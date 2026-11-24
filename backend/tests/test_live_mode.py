"""Live-mode lockdown and config validation (task 24, Requirements 11.1 to 11.5)."""

from __future__ import annotations

import asyncio
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr

from backend.app.api.routes import AppServices
from backend.app.main import ConfigError, Settings, build_in_memory_services, create_app
from backend.app.services.africastalking_client import AfricasTalkingSettings
from backend.app.services.incident_store import SYSTEM_INCIDENT_ID

READ_KEY = "distinct-read-key-7f3a91"
ALERT_KEY = "distinct-alert-key-52bc"
SMS_SECRET = "distinct-sms-secret-9d1e"
AT_KEY = "distinct-at-key-44aa"
NUMBER = "+254711000111"
ALERT = {"service_name": "auth-db", "error_code": "DB_POOL_EXHAUSTED", "summary": "pool at 100%"}

REQUIRED = (
    "ALERT_WEBHOOK_SECRET",
    "API_READ_SECRET",
    "AFRICASTALKING_USERNAME",
    "AFRICASTALKING_API_KEY",
    "AFRICASTALKING_WEBHOOK_SECRET",
    "ONCALL_PHONE_NUMBER",
)
FULL_ENV = {
    "DRY_RUN": "false",
    "USE_IN_MEMORY": "true",
    "ALERT_WEBHOOK_SECRET": ALERT_KEY,
    "API_READ_SECRET": READ_KEY,
    "AFRICASTALKING_USERNAME": "distinct-user",
    "AFRICASTALKING_API_KEY": AT_KEY,
    "AFRICASTALKING_WEBHOOK_SECRET": SMS_SECRET,
    "ONCALL_PHONE_NUMBER": NUMBER,
}


def live_env(**overrides: str) -> dict[str, str]:
    env = {**FULL_ENV, **overrides}
    return {k: v for k, v in env.items() if v != "<absent>"}


def live_settings(**env: str) -> Settings:
    return Settings.from_env({**live_env(**env), "FRONTEND_DIR": ""}).model_copy(update={"frontend_dir": None})


# --- validation table --------------------------------------------------------


@pytest.mark.parametrize("missing", REQUIRED)
def test_live_requires_each_variable(missing: str) -> None:
    cfg = Settings.from_env(live_env(**{missing: "<absent>"}))
    with pytest.raises(ConfigError) as exc:
        cfg.validate_for_runtime()
    assert missing in str(exc.value)


def test_live_all_present_ok() -> None:
    Settings.from_env(live_env()).validate_for_runtime()


@pytest.mark.parametrize("number", ["0700123456", "254711000111", "+25471", "abc"])
def test_local_format_number_rejected(number: str) -> None:
    for dry in ("false", "true"):
        cfg = Settings.from_env(live_env(ONCALL_PHONE_NUMBER=number, DRY_RUN=dry))
        with pytest.raises(ConfigError) as exc:
            cfg.validate_for_runtime()
        assert "ONCALL_PHONE_NUMBER" in str(exc.value)
        assert number not in str(exc.value)


def test_dry_run_needs_nothing() -> None:
    Settings.from_env({"DRY_RUN": "true"}).validate_for_runtime()
    Settings.from_env({}).validate_for_runtime()


def test_error_has_names_not_values() -> None:
    cfg = Settings.from_env(live_env(**{"ALERT_WEBHOOK_SECRET": "<absent>", "ONCALL_PHONE_NUMBER": "0700123456"}))
    with pytest.raises(ConfigError) as exc:
        cfg.validate_for_runtime()
    text = str(exc.value)
    assert "ALERT_WEBHOOK_SECRET" in text and "ONCALL_PHONE_NUMBER" in text
    for value in (READ_KEY, SMS_SECRET, AT_KEY, "0700123456"):
        assert value not in text
    assert isinstance(exc.value, ValueError)


def test_read_secret_not_printable() -> None:
    cfg = Settings.from_env(live_env())
    assert READ_KEY not in repr(cfg) and READ_KEY not in str(cfg)
    svc = build_in_memory_services(cfg)
    assert READ_KEY not in repr(svc)


def test_startup_line_masks_sender() -> None:
    line = Settings.from_env(live_env()).startup_line()
    assert "dry_run=false" in line and "africastalking" in line
    assert NUMBER not in line and "+254" in line


# --- startup -------------------------------------------------------------------


def test_create_app_raises_for_incomplete_live_settings() -> None:
    with pytest.raises(ConfigError):
        create_app(None, Settings.from_env(live_env(API_READ_SECRET="<absent>")))


def test_lifespan_revalidates() -> None:
    cfg = live_settings()
    app = create_app(build_in_memory_services(cfg), cfg)
    object.__setattr__(cfg, "api_read_secret", SecretStr(""))  # config drifts after create_app
    with pytest.raises(ConfigError):
        with TestClient(app):
            pass


def test_live_registers_no_demo_routes_and_never_reseeds() -> None:
    calls: list[int] = []

    async def reseed() -> int:
        calls.append(1)
        return 1

    cfg = live_settings()
    svc = build_in_memory_services(cfg)
    import dataclasses

    svc = dataclasses.replace(svc, reseed=reseed)
    app = create_app(svc, cfg)
    assert not [r for r in app.routes if getattr(r, "path", "").startswith("/api/demo")]
    with TestClient(app) as c:
        assert c.post("/api/demo/reseed").status_code in (404, 405)
    assert calls == []


# --- read API matrix -------------------------------------------------------------


@pytest.fixture()
def live() -> Iterator[tuple[TestClient, AppServices]]:
    cfg = live_settings()
    svc = build_in_memory_services(cfg)
    with TestClient(create_app(svc, cfg)) as c:
        yield c, svc


def _audit_payload_text(svc: AppServices) -> str:
    records = asyncio.run(svc.audit.records(SYSTEM_INCIDENT_ID))
    return " ".join(f"{r.event_type} {r.payload}" for r in records)


def _alert(c: TestClient) -> Any:
    return c.post("/webhooks/alerts", json=ALERT, headers={"Authorization": f"Bearer {ALERT_KEY}"})


def test_live_alert_response_has_no_token(live: tuple[TestClient, AppServices]) -> None:
    c, _ = live
    resp = _alert(c)
    assert resp.status_code == 202
    assert "token" not in resp.text.lower()


def test_dry_run_alert_response_has_no_token() -> None:
    cfg = Settings(frontend_dir=None)
    with TestClient(create_app(build_in_memory_services(cfg), cfg)) as c:
        resp = c.post("/webhooks/alerts", json=ALERT)
        assert resp.status_code == 202
        assert "token" not in resp.text.lower()


@pytest.mark.parametrize("header", [None, "Bearer wrong-key", "Basic abc", "Bearer "])
def test_live_read_apis_reject_bad_key(live: tuple[TestClient, AppServices], header: str | None) -> None:
    c, svc = live
    incident_id = _alert(c).json()["incident_id"]
    headers = {} if header is None else {"Authorization": header}
    for path in ("/api/incidents", f"/api/incidents/{incident_id}/audit"):
        resp = c.get(path, headers=headers)
        assert resp.status_code == 401
        assert resp.headers["WWW-Authenticate"] == "Bearer"
    text = _audit_payload_text(svc)
    assert "SECURITY_VIOLATION" in text
    for secret in (READ_KEY, "wrong-key", ALERT_KEY, SMS_SECRET, AT_KEY):
        assert secret not in text


def test_live_read_apis_accept_correct_key(live: tuple[TestClient, AppServices]) -> None:
    c, _ = live
    incident_id = _alert(c).json()["incident_id"]
    headers = {"Authorization": f"Bearer {READ_KEY}"}
    listing = c.get("/api/incidents", headers=headers)
    assert listing.status_code == 200 and len(listing.json()) == 1
    assert c.get(f"/api/incidents/{incident_id}/audit", headers=headers).status_code == 200
    assert "token" not in listing.text.lower()


def test_dry_run_read_apis_open() -> None:
    cfg = Settings(frontend_dir=None)
    with TestClient(create_app(build_in_memory_services(cfg), cfg)) as c:
        assert c.get("/api/incidents").status_code == 200


def test_live_health_and_ready_need_no_read_key(live: tuple[TestClient, AppServices]) -> None:
    c, _ = live
    assert c.get("/healthz").status_code == 200
    assert c.get("/readyz").status_code in (200, 503)
    assert c.post("/webhooks/alerts", json=ALERT).status_code == 401  # own auth still applies


def test_read_api_fails_closed_when_secret_unset() -> None:
    cfg = Settings.from_env(live_env())
    svc = build_in_memory_services(cfg)
    import dataclasses

    svc = dataclasses.replace(svc, api_read_secret=SecretStr(""))
    with TestClient(create_app(svc, cfg.model_copy(update={"frontend_dir": None}))) as c:
        assert c.get("/api/incidents", headers={"Authorization": "Bearer "}).status_code == 401
        assert c.get("/api/incidents", headers={"Authorization": "Bearer x"}).status_code == 401


# --- UI --------------------------------------------------------------------------


def test_index_html_banner_and_read_key() -> None:
    html = (Path(__file__).resolve().parents[2] / "frontend" / "index.html").read_text(encoding="utf-8")
    assert 'fetch("/readyz")' in html
    assert "dry_run" in html and "innerHTML" not in html
    assert "READ KEY NEEDED" in html


def test_env_example_documents_every_setting() -> None:
    root = Path(__file__).resolve().parents[2]
    example = (root / ".env.example").read_text(encoding="utf-8")
    compose = (root / "docker-compose.yml").read_text(encoding="utf-8")
    for name in (*REQUIRED, "DRY_RUN", "TRIAGE_TIMEOUT_SECONDS", "EXECUTING_TIMEOUT_SECONDS", "PAGE_MAX_ATTEMPTS",
                 "TOKEN_COOLDOWN_SECONDS", "MAX_ALERT_BODY_BYTES", "DEDUP_AUDIT_SAMPLE",
                 "TELEMETRY_MAX_CONCURRENCY", "PAGE_RATE_PER_MINUTE", "PAGE_FAILURE_READY_THRESHOLD"):
        assert f"\n{name}=" in "\n" + example
    assert "API_READ_SECRET: ${API_READ_SECRET" in compose


_ = AfricasTalkingSettings
