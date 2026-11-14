"""Smoke tests for the FastAPI gateway (in-memory adapters, no Postgres/Redis)."""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any, cast
from uuid import UUID

import itertools
import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr

from backend.app.api.routes import AppServices
from backend.app.main import Settings, build_in_memory_services, create_app
from backend.app.services.guardrails import verify_chain
from backend.app.services.incident_store import SYSTEM_INCIDENT_ID
from backend.app.services.africastalking_client import AfricasTalkingSettings, AfricasTalkingSmsAdapter

WH_SECRET = "test-webhook-secret"
ONCALL = "+254711000111"
SHORTCODE = "20880"
SMS_PATH = "/webhooks/africastalking/sms"


def _at_settings(**overrides: Any) -> AfricasTalkingSettings:
    base: dict[str, Any] = {
        "webhook_secret": SecretStr(WH_SECRET),
        "to_number": ONCALL,
        "shortcode": SHORTCODE,
    }
    return AfricasTalkingSettings(**{**base, **overrides})

ALERT = {"service_name": "auth-db", "error_code": "DB_POOL_EXHAUSTED", "summary": "pool at 100%"}


@pytest.fixture()
def services() -> AppServices:
    return build_in_memory_services(Settings(use_in_memory=True, africastalking=_at_settings()))


@pytest.fixture()
def client(services: AppServices) -> Iterator[TestClient]:
    with TestClient(create_app(services, Settings(frontend_dir=None))) as c:
        yield c


def _outbox(services: AppServices) -> list[str]:
    return [m.text for m in cast(AfricasTalkingSmsAdapter, services.sms).outbox]


_msg_counter = itertools.count(1)


def _sms(
    client: TestClient,
    body: str,
    *,
    secret: str | None = WH_SECRET,
    sender: str = ONCALL,
    to: str = SHORTCODE,
    msg_id: str | None = None,
    query_secret: bool = False,
) -> Any:
    form = {
        "from": sender,
        "to": to,
        "text": body,
        "date": "2025-01-01 00:00:00",
        "id": msg_id if msg_id is not None else f"ATXid_{next(_msg_counter)}",
        "linkId": "link-1",
    }
    headers = {} if secret is None or query_secret else {"X-Webhook-Secret": secret}
    url = f"{SMS_PATH}?secret={secret}" if query_secret and secret is not None else SMS_PATH
    return client.post(url, data=form, headers=headers)


def _token_of(client: TestClient, incident_id: str | UUID) -> str:
    repo = client.app.state.services.incidents  # type: ignore[attr-defined]
    record = _run(repo.get(UUID(str(incident_id))))
    assert record is not None
    return str(record.token)


def _new_token(client: TestClient) -> str:
    """Raise an alert and read the reply token from the repository (it is not in the response)."""
    resp = client.post("/webhooks/alerts", json=ALERT)
    assert resp.status_code == 202
    return _token_of(client, resp.json()["incident_id"])


def _states(client: TestClient) -> dict[str, str]:
    repo = client.app.state.services.incidents  # type: ignore[attr-defined]
    tokens = {r.incident_id: r.token for r in _run(repo.list_recent())}
    return {tokens[UUID(i["incident_id"])]: i["state"] for i in client.get("/api/incidents").json()}


def test_invalid_alert_returns_422_and_runs_nothing(client: TestClient, services: AppServices) -> None:
    assert client.post("/webhooks/alerts", json={"service_name": "auth-db"}).status_code == 422
    assert client.post("/webhooks/alerts", json={**ALERT, "service_name": "bad name!"}).status_code == 422
    assert client.get("/api/incidents").json() == []
    assert _outbox(services) == []


def test_new_alert_then_duplicate(client: TestClient, services: AppServices) -> None:
    first = client.post("/webhooks/alerts", json=ALERT)
    assert first.status_code == 202
    assert set(first.json()) == {"incident_id"}  # reply token is never returned to the alert source
    incident_id = first.json()["incident_id"]
    token = _token_of(client, incident_id)
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


def _violations(services: AppServices) -> list[dict[str, Any]]:
    return [
        dict(r.payload) for r in _run(services.audit.records(SYSTEM_INCIDENT_ID)) if r.event_type == "SECURITY_VIOLATION"
    ]


@pytest.mark.parametrize("secret", ["wrong", "", None])
def test_bad_or_missing_secret_is_rejected_and_audited(
    client: TestClient, services: AppServices, secret: str | None
) -> None:
    token = _new_token(client)
    before = len(_outbox(services))
    assert _sms(client, f"{token}-1", secret=secret).status_code == 403
    assert _states(client) == {token: "AWAITING_APPROVAL"}
    assert len(_outbox(services)) == before
    violations = _violations(services)
    assert len(violations) == 1 and violations[0]["reason"] == "invalid_secret"
    assert WH_SECRET not in str(violations) and "sender" not in violations[0]


def test_wrong_sender_is_rejected_and_audited_with_masked_number(
    client: TestClient, services: AppServices
) -> None:
    token = _new_token(client)
    assert _sms(client, f"{token}-1", sender="+254722999888").status_code == 403
    assert _sms(client, f"{token}-1", sender="not-a-number").status_code == 403
    assert _states(client) == {token: "AWAITING_APPROVAL"}
    violations = _violations(services)
    assert [v["reason"] for v in violations] == ["unauthorized_sender"] * 2
    assert violations[0]["sender"] == "***9888" and "254722999888" not in str(violations)


def test_wrong_shortcode_is_rejected(client: TestClient, services: AppServices) -> None:
    token = _new_token(client)
    assert _sms(client, f"{token}-1", to="99999").status_code == 403
    assert _sms(client, f"{token}-1", to="").status_code == 403
    assert _states(client) == {token: "AWAITING_APPROVAL"}
    assert [v["reason"] for v in _violations(services)] == ["shortcode_mismatch"] * 2


def test_secret_unset_rejects_everything() -> None:
    svc = build_in_memory_services(Settings(use_in_memory=True, africastalking=_at_settings(webhook_secret=SecretStr(""))))
    with TestClient(create_app(svc, Settings(frontend_dir=None))) as c:
        token = _new_token(c)
        assert _sms(c, f"{token}-1", secret="").status_code == 403
        assert _sms(c, f"{token}-1", secret=WH_SECRET).status_code == 403
        assert _states(c) == {token: "AWAITING_APPROVAL"}
        assert [v["reason"] for v in _violations(svc)] == ["secret_not_configured"] * 2


def test_secret_in_query_parameter_and_unconfigured_shortcode(client: TestClient) -> None:
    token = _new_token(client)
    assert _sms(client, f"{token}-2", query_secret=True).status_code == 200
    assert _states(client) == {token: "RESOLVED"}


def test_duplicate_message_id_is_ignored(client: TestClient, services: AppServices) -> None:
    token = _new_token(client)
    first = _sms(client, f"{token}-1", msg_id="ATXid_dup")
    assert first.status_code == 200 and first.json() == {"status": "ok"}
    incident_id = UUID(client.get("/api/incidents").json()[0]["incident_id"])
    audit_before = _run(services.audit.records(incident_id))
    outbox_before = _outbox(services)
    again = _sms(client, f"{token}-1", msg_id="ATXid_dup")
    assert again.status_code == 200 and again.json() == {}
    assert _run(services.audit.records(incident_id)) == audit_before
    assert _outbox(services) == outbox_before  # no "no longer active" SMS either


def test_missing_message_id_is_rejected(client: TestClient) -> None:
    token = _new_token(client)
    assert _sms(client, f"{token}-1", msg_id="").status_code == 400
    assert _states(client) == {token: "AWAITING_APPROVAL"}


def test_valid_reply_resumes_and_resolves(client: TestClient, services: AppServices) -> None:
    token = _new_token(client)
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
    token = _new_token(demo_client)
    outbox = demo_client.get("/api/demo/outbox").json()
    assert outbox[0]["text"].startswith(f"INC-{token} ") and len(outbox[0]["text"]) <= 160
    assert demo_client.post("/api/demo/reply", json={"token": token, "choice": 1}).status_code == 202
    assert _states(demo_client) == {token: "RESOLVED"}
    assert demo_client.get("/api/demo/outbox").json()[0]["text"] == f"INC-{token} RESOLVED"
    assert demo_client.post("/api/demo/reply", json={"token": token, "choice": 3}).status_code == 422


def test_demo_reply_by_incident_id_and_outbox_incident_id(demo_client: TestClient) -> None:
    incident_id = demo_client.post("/webhooks/alerts", json=ALERT).json()["incident_id"]
    entry = demo_client.get("/api/demo/outbox").json()[0]
    assert entry["incident_id"] == incident_id
    resp = demo_client.post("/api/demo/reply", json={"incident_id": incident_id, "choice": 2})
    assert resp.status_code == 202
    assert [i["state"] for i in demo_client.get("/api/incidents").json()] == ["RESOLVED"]
    newest = demo_client.get("/api/demo/outbox").json()[0]
    assert newest["incident_id"] == incident_id
    assert "token" not in newest and "token" not in resp.json()
    # Unknown incident, and both/neither selector, are rejected.
    assert demo_client.post("/api/demo/reply", json={"incident_id": str(UUID(int=9)), "choice": 1}).status_code == 404
    assert demo_client.post("/api/demo/reply", json={"choice": 1}).status_code == 422
    both = {"incident_id": incident_id, "token": "AB", "choice": 1}
    assert demo_client.post("/api/demo/reply", json=both).status_code == 422


def _contains_token(value: Any, token: str) -> bool:
    if isinstance(value, dict):
        return any(k == "token" or _contains_token(v, token) for k, v in value.items())
    if isinstance(value, list):
        return any(_contains_token(v, token) for v in value)
    if isinstance(value, str):
        return f"INC-{token}" in value or f"{token}-1" in value or f"{token}-2" in value
    return False


def test_public_api_does_not_expose_reply_token(client: TestClient, services: AppServices) -> None:
    accepted = client.post("/webhooks/alerts", json=ALERT).json()
    assert "token" not in accepted and set(accepted) == {"incident_id"}
    token, incident_id = _token_of(client, accepted["incident_id"]), UUID(accepted["incident_id"])
    listing = client.get("/api/incidents").json()
    assert listing and all("token" not in i for i in listing)
    assert token not in str(listing).replace(accepted["incident_id"], "")
    # Plant a nested payload carrying the token in key and string forms.
    _run(
        services.audit.append_event(
            incident_id,
            "CUSTOM",
            {"token": token, "nested": {"token": token, "items": [f"INC-{token} Reply {token}-1 or {token}-2"]}},
        )
    )
    stored = _run(services.audit.records(incident_id))
    assert _contains_token([r.payload for r in stored], token)  # stored data keeps it
    audit = client.get(f"/api/incidents/{incident_id}/audit").json()
    assert audit["chain_valid"] is True
    assert not _contains_token([r["payload"] for r in audit["records"]], token)
    assert len(audit["records"]) == len(stored)
    assert [r["hash"] for r in audit["records"]] == [r.hash for r in stored]


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
    cfg = Settings(use_in_memory=True, africastalking=_at_settings(), alert_webhook_secret=SECRET)
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


def test_africastalking_form_fields_and_unauthorized_sender_audit(client: TestClient, services: AppServices) -> None:
    token = _new_token(client)
    body = {
        "from": "+254722999888",
        "to": SHORTCODE,
        "text": f"{token}-1",
        "date": "2025-01-01 00:00:00",
        "id": "ATXid_fields",
        "linkId": "link-9",
    }
    resp = client.post(SMS_PATH, data=body, headers={"X-Webhook-Secret": WH_SECRET})
    assert resp.status_code == 403
    assert _states(client) == {token: "AWAITING_APPROVAL"}
    events = [r for r in _run(services.audit.records(SYSTEM_INCIDENT_ID)) if r.event_type == "SECURITY_VIOLATION"]
    assert len(events) == 1 and events[0].payload["reason"] == "unauthorized_sender"
    # Same field names from the on-call sender are accepted.
    ok = client.post(SMS_PATH, data={**body, "from": ONCALL}, headers={"X-Webhook-Secret": WH_SECRET})
    assert ok.status_code == 200
    assert _states(client) == {token: "RESOLVED"}


def test_alert_response_and_public_api_never_carry_token(client: TestClient) -> None:
    resp = client.post("/webhooks/alerts", json=ALERT)
    token = _token_of(client, resp.json()["incident_id"])
    assert "token" not in resp.json() and token not in resp.text.replace(resp.json()["incident_id"], "")


# ---------------------------------------------------------------------------
# GET /healthz (task 10.1, Req 7.1)
# ---------------------------------------------------------------------------


def test_healthz_ok_unauthenticated_even_with_secrets(secured: tuple[TestClient, AppServices]) -> None:
    client, _ = secured
    resp = client.get("/healthz")
    assert resp.status_code == 200 and resp.json() == {"status": "ok"}


@pytest.mark.parametrize("dry_run", [True, False])
def test_healthz_registered_regardless_of_dry_run(services: AppServices, dry_run: bool) -> None:
    with TestClient(create_app(services, Settings(frontend_dir=None, dry_run=dry_run))) as c:
        assert c.get("/healthz").json() == {"status": "ok"}


def test_healthz_not_shadowed_by_static_mount(services: AppServices, tmp_path: Any) -> None:
    (tmp_path / "index.html").write_text("<html>ui</html>")
    with TestClient(create_app(services, Settings(frontend_dir=tmp_path))) as c:
        assert c.get("/").text == "<html>ui</html>"
        assert c.get("/healthz").json() == {"status": "ok"}


def test_healthz_503_without_leaking_details_when_ping_fails(services: AppServices) -> None:
    async def boom() -> None:
        raise RuntimeError("postgres://user:secret@db/pagemaster refused")

    import dataclasses

    failing = dataclasses.replace(services, ping=boom)
    with TestClient(create_app(failing, Settings(frontend_dir=None))) as c:
        resp = c.get("/healthz")
    assert resp.status_code == 503
    assert resp.json() == {"status": "unavailable"}
    assert "secret" not in resp.text


def test_healthz_200_when_ping_succeeds(services: AppServices) -> None:
    import dataclasses

    async def fine() -> None:
        return None

    with TestClient(create_app(dataclasses.replace(services, ping=fine), Settings(frontend_dir=None))) as c:
        assert c.get("/healthz").status_code == 200
