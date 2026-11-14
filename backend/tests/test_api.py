"""Smoke tests for the FastAPI gateway (in-memory adapters, no Postgres/Redis)."""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any, cast
from uuid import UUID

import pytest
from fastapi.testclient import TestClient
from twilio.request_validator import RequestValidator  # type: ignore[import-untyped]

from backend.app.api.routes import AppServices
from backend.app.main import Settings, build_in_memory_services, create_app
from backend.app.services.guardrails import verify_chain
from backend.app.services.incident_store import SYSTEM_INCIDENT_ID
from backend.app.services.twilio_client import TwilioSmsAdapter

AUTH_TOKEN = "test-auth-token"
SMS_URL = "http://testserver/webhooks/twilio/sms"
ALERT = {"service_name": "auth-db", "error_code": "DB_POOL_EXHAUSTED", "summary": "pool at 100%"}


@pytest.fixture()
def services() -> AppServices:
    return build_in_memory_services(Settings(use_in_memory=True, twilio_auth_token=AUTH_TOKEN))


@pytest.fixture()
def client(services: AppServices) -> Iterator[TestClient]:
    with TestClient(create_app(services, Settings(frontend_dir=None))) as c:
        yield c


def _outbox(services: AppServices) -> list[str]:
    return [m.text for m in cast(TwilioSmsAdapter, services.sms).outbox]


def _sms(client: TestClient, body: str, *, sign: bool = True) -> Any:
    params = {"Body": body, "From": "+15550001111"}
    sig = RequestValidator(AUTH_TOKEN).compute_signature(SMS_URL, params) if sign else "bogus"
    return client.post("/webhooks/twilio/sms", data=params, headers={"X-Twilio-Signature": sig})


def _states(client: TestClient) -> dict[str, str]:
    return {i["token"]: i["state"] for i in client.get("/api/incidents").json()}


def test_invalid_alert_returns_422_and_runs_nothing(client: TestClient, services: AppServices) -> None:
    assert client.post("/webhooks/alerts", json={"service_name": "auth-db"}).status_code == 422
    assert client.post("/webhooks/alerts", json={**ALERT, "service_name": "bad name!"}).status_code == 422
    assert client.get("/api/incidents").json() == []
    assert _outbox(services) == []


def test_new_alert_then_duplicate(client: TestClient, services: AppServices) -> None:
    first = client.post("/webhooks/alerts", json=ALERT)
    assert first.status_code == 202
    token = first.json()["token"]
    incident_id = first.json()["incident_id"]
    assert len(token) == 2 and token == token.upper() and token.isalnum()
    assert _states(client) == {token: "AWAITING_APPROVAL"}
    assert len(_outbox(services)) == 1 and _outbox(services)[0].startswith(f"INC-{token} ")

    dup = client.post("/webhooks/alerts", json=ALERT)
    assert dup.status_code == 200 and dup.json()["status"] == "DEDUPLICATED"
    assert len(_outbox(services)) == 1  # no second agent run

    audit = client.get(f"/api/incidents/{incident_id}/audit").json()
    events = [r["event_type"] for r in audit["records"]]
    assert audit["chain_valid"] is True
    assert "INCIDENT_CREATED" in events and "ALERT_DEDUPLICATED" in events and "PAGER_SENT" in events


def test_invalid_signature_is_rejected_and_audited(client: TestClient, services: AppServices) -> None:
    token = client.post("/webhooks/alerts", json=ALERT).json()["token"]
    assert _sms(client, f"{token}-1", sign=False).status_code == 403
    assert _states(client) == {token: "AWAITING_APPROVAL"}
    system = [r.event_type for r in _run(services.audit.records(SYSTEM_INCIDENT_ID))]
    assert system == ["SECURITY_VIOLATION"]


def test_valid_reply_resumes_and_resolves(client: TestClient, services: AppServices) -> None:
    token = client.post("/webhooks/alerts", json=ALERT).json()["token"]
    assert _sms(client, f" {token.lower()}-1 ").status_code == 200
    assert _states(client) == {token: "RESOLVED"}
    assert _outbox(services)[-1] == f"INC-{token} RESOLVED"
    incident_id = UUID(client.get("/api/incidents").json()[0]["incident_id"])
    assert verify_chain(_run(services.audit.records(incident_id))).valid
    # Terminal state released the dedup lock: same fingerprint starts a fresh incident.
    assert client.post("/webhooks/alerts", json=ALERT).status_code == 202
    # A second reply to the now-resolved token mutates nothing.
    before = _run(services.audit.records(incident_id))
    assert _sms(client, f"{token}-1").status_code == 200
    assert "no longer active" in _outbox(services)[-1]
    assert _run(services.audit.records(incident_id)) == before


def test_unknown_token_replies_inactive_without_mutation(client: TestClient, services: AppServices) -> None:
    assert _sms(client, "ZZ-2").status_code == 200
    assert _outbox(services) == ["INC-ZZ no longer active. No action taken."]
    assert client.get("/api/incidents").json() == []


def test_audit_unknown_incident_404(client: TestClient) -> None:
    assert client.get(f"/api/incidents/{UUID(int=5)}/audit").status_code == 404


@pytest.fixture()
def demo_client(services: AppServices) -> Iterator[TestClient]:
    with TestClient(create_app(services, Settings(frontend_dir=None, dry_run=True))) as c:
        yield c


def test_demo_reply_resolves_and_outbox_shows_pager_text(demo_client: TestClient) -> None:
    token = demo_client.post("/webhooks/alerts", json=ALERT).json()["token"]
    outbox = demo_client.get("/api/demo/outbox").json()
    assert outbox[0]["text"].startswith(f"INC-{token} ") and len(outbox[0]["text"]) <= 160
    assert demo_client.post("/api/demo/reply", json={"token": token, "choice": 1}).status_code == 202
    assert _states(demo_client) == {token: "RESOLVED"}
    assert demo_client.get("/api/demo/outbox").json()[0]["text"] == f"INC-{token} RESOLVED"
    assert demo_client.post("/api/demo/reply", json={"token": token, "choice": 3}).status_code == 422


def test_demo_routes_disabled_when_not_dry_run(client: TestClient, services: AppServices) -> None:
    # Not registered when Settings.dry_run is false.
    # (405 when the static UI mount at "/" answers instead of the API.)
    assert client.post("/api/demo/reply", json={"token": "AB", "choice": 1}).status_code in (404, 405)
    assert client.get("/api/demo/outbox").status_code == 404
    # Registered but the SMS adapter is not in dry-run: still 404 (defence in depth).
    live = AppServices(
        graph=services.graph,
        dedup=services.dedup,
        sms=_LiveSms(),
        incidents=services.incidents,
        audit=services.audit,
    )
    with TestClient(create_app(live, Settings(frontend_dir=None, dry_run=True))) as c:
        assert c.post("/api/demo/reply", json={"token": "AB", "choice": 1}).status_code == 404
        assert c.get("/api/demo/outbox").status_code == 404


class _LiveSms:
    async def send(self, text: str) -> None:
        return None


def _run(coro: Any) -> Any:
    import asyncio

    return asyncio.run(coro)


# ---------------------------------------------------------------------------
# Optional ALERT_WEBHOOK_SECRET (task 6.4)
# ---------------------------------------------------------------------------

SECRET = "s3cret-token"


@pytest.fixture()
def secured() -> Iterator[tuple[TestClient, AppServices]]:
    cfg = Settings(use_in_memory=True, twilio_auth_token=AUTH_TOKEN, alert_webhook_secret=SECRET)
    svc = build_in_memory_services(cfg)
    with TestClient(create_app(svc, Settings(frontend_dir=None, alert_webhook_secret=SECRET))) as c:
        yield c, svc


@pytest.mark.parametrize(
    "headers",
    [{}, {"Authorization": "Bearer wrong"}, {"Authorization": SECRET}, {"Authorization": "Basic " + SECRET}],
)
def test_alert_secret_rejects_missing_or_wrong_token(
    secured: tuple[TestClient, AppServices], headers: dict[str, str]
) -> None:
    client, services = secured
    assert client.post("/webhooks/alerts", json=ALERT, headers=headers).status_code == 401
    # Rejected before body parsing: even an invalid body gets 401, not 422.
    assert client.post("/webhooks/alerts", content=b"{not json", headers=headers).status_code == 401
    assert client.get("/api/incidents").json() == []
    assert _outbox(services) == []
    system = [r.event_type for r in _run(services.audit.records(SYSTEM_INCIDENT_ID))]
    assert system == ["SECURITY_VIOLATION"] * 2


def test_alert_secret_accepts_correct_token(secured: tuple[TestClient, AppServices]) -> None:
    client, services = secured
    ok = client.post("/webhooks/alerts", json=ALERT, headers={"Authorization": f"Bearer {SECRET}"})
    assert ok.status_code == 202
    assert len(_outbox(services)) == 1
    bad_body = client.post(
        "/webhooks/alerts", json={"service_name": "x"}, headers={"Authorization": f"Bearer {SECRET}"}
    )
    assert bad_body.status_code == 422


def test_alert_secret_unset_leaves_endpoint_open(client: TestClient) -> None:
    assert client.post("/webhooks/alerts", json=ALERT).status_code == 202


def test_settings_reads_alert_webhook_secret() -> None:
    assert Settings.from_env({"ALERT_WEBHOOK_SECRET": " abc "}).alert_webhook_secret == "abc"
    assert Settings.from_env({}).alert_webhook_secret == ""
