"""Alert body limit and dedup audit cap (Req 10.4, 10.5, task 21)."""

from __future__ import annotations

import json
from dataclasses import replace
from typing import Any

import pytest
from fastapi.testclient import TestClient

from backend.app.api.routes import AppServices
from backend.app.main import Settings, create_app
from backend.app.services.guardrails import verify_chain
from backend.app.services.incident_store import SYSTEM_INCIDENT_ID
from backend.tests.test_expiry import make_services

LIMIT = 65_536
SECRET = "alert-secret"
ALERT = {"service_name": "auth-db", "error_code": "REPLICATION_LAG", "summary": "lag"}


class _IdleGraph:
    async def ainvoke(self, input: Any, config: Any = None) -> Any:
        return {}


def _app(services: AppServices) -> Any:
    return create_app(services, Settings(use_in_memory=True, dry_run=True, reaper_interval_seconds=60.0))


def _body_of_size(size: int) -> bytes:
    """A valid alert JSON padded (via an ignored extra field) to exactly ``size`` bytes."""
    base = json.dumps({**ALERT, "pad": ""}).encode()
    return json.dumps({**ALERT, "pad": "x" * (size - len(base))}).encode()


async def _asgi_post(
    app: Any, chunks: list[bytes], headers: list[tuple[bytes, bytes]]
) -> tuple[int, bytes, int]:
    """Drive the app directly; returns (status, body, number of request chunks consumed)."""
    consumed = 0
    sent: list[dict[str, Any]] = []
    remaining = list(chunks)

    async def receive() -> dict[str, Any]:
        nonlocal consumed
        if not remaining:
            return {"type": "http.disconnect"}
        consumed += 1
        data = remaining.pop(0)
        return {"type": "http.request", "body": data, "more_body": bool(remaining)}

    async def send(message: dict[str, Any]) -> None:
        sent.append(message)

    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "POST",
        "path": "/webhooks/alerts",
        "raw_path": b"/webhooks/alerts",
        "query_string": b"",
        "root_path": "",
        "scheme": "http",
        "headers": headers,
        "client": ("127.0.0.1", 1),
        "server": ("test", 80),
        "state": {},
    }
    await app(scope, receive, send)
    status = next(m["status"] for m in sent if m["type"] == "http.response.start")
    body = b"".join(m.get("body", b"") for m in sent if m["type"] == "http.response.body")
    return status, body, consumed


def test_body_one_over_limit_is_413_via_client_and_exactly_at_limit_is_accepted() -> None:
    services, _, _ = make_services()
    with TestClient(_app(services)) as client:
        over = client.post("/webhooks/alerts", content=_body_of_size(LIMIT + 1))
        assert over.status_code == 413
        assert over.json() == {"detail": "payload too large"}
        assert client.post("/webhooks/alerts", content=_body_of_size(LIMIT)).status_code == 202


@pytest.mark.asyncio
async def test_content_length_over_limit_is_413_without_reading_the_body() -> None:
    services, _, _ = make_services()
    chunks = [b"x" * 8192 for _ in range(10)]  # 80 KB
    headers = [(b"content-length", str(sum(map(len, chunks))).encode())]
    status, body, consumed = await _asgi_post(_app(services), chunks, headers)
    assert status == 413
    assert consumed == 0
    assert b"xxxx" not in body  # no echo of the input
    assert json.loads(body) == {"detail": "payload too large"}


@pytest.mark.asyncio
async def test_stream_without_content_length_is_aborted_early() -> None:
    services, _, _ = make_services()
    chunks = [b"x" * 8192 for _ in range(100)]  # 800 KB; the limit is crossed in chunk 9
    status, body, consumed = await _asgi_post(_app(services), chunks, [])
    assert status == 413
    assert consumed == LIMIT // 8192 + 1  # stopped at the first chunk over the limit
    assert consumed < len(chunks)
    assert b"xxxx" not in body


@pytest.mark.asyncio
async def test_understated_content_length_cannot_bypass_the_stream_limit() -> None:
    services, _, _ = make_services()
    chunks = [b"x" * 8192 for _ in range(100)]
    status, _, consumed = await _asgi_post(_app(services), chunks, [(b"content-length", b"10")])
    assert status == 413
    assert consumed < len(chunks)


@pytest.mark.parametrize("value", ["abc", "-1", "1.5", "", "1 2", "+5"])
def test_invalid_content_length_is_400(value: str) -> None:
    import asyncio

    services, _, _ = make_services()
    status, _, consumed = asyncio.run(_asgi_post(_app(services), [b"{}"], [(b"content-length", value.encode())]))
    assert status == 400
    assert consumed == 0


def test_unauthorized_request_gets_401_before_any_body_handling() -> None:
    import asyncio

    services, _, _ = make_services()
    services = replace(services, alert_webhook_secret=SECRET)
    app = _app(services)
    chunks = [b"x" * 8192 for _ in range(20)]
    for headers in (
        [(b"content-length", str(8192 * 20).encode())],  # oversized
        [(b"content-length", b"bogus")],  # malformed
        [],  # no length at all
    ):
        status, _, consumed = asyncio.run(_asgi_post(app, list(chunks), headers))
        assert status == 401
        assert consumed == 0
    authorized = [(b"authorization", f"Bearer {SECRET}".encode()), (b"content-length", str(8192 * 20).encode())]
    status, _, consumed = asyncio.run(_asgi_post(app, list(chunks), authorized))
    assert status == 413


@pytest.mark.asyncio
async def test_duplicate_flood_is_bounded_and_chain_verifies() -> None:
    services, _, _ = make_services()
    sample = 20
    services = replace(services, dedup_audit_sample=sample, graph=_IdleGraph())  # incident stays TRIAGING
    app = _app(services)
    with TestClient(app) as client:
        first = client.post("/webhooks/alerts", json=ALERT)
        assert first.status_code == 202
        incident_id = first.json()["incident_id"]
        for _ in range(1000):
            r = client.post("/webhooks/alerts", json=ALERT)
            assert r.status_code == 200
            assert r.json() == {"status": "DEDUPLICATED", "incident_id": incident_id}
    row = await services.incidents.get(__import__("uuid").UUID(incident_id))
    assert row is not None and row.duplicate_count == 1000
    chain = await services.audit.records(row.incident_id)
    sampled = [r for r in chain if r.event_type == "ALERT_DEDUPLICATED"]
    summaries = [r for r in chain if r.event_type == "ALERT_DEDUPLICATED_SUMMARY"]
    assert len(sampled) == sample
    assert [r.payload["duplicates"] for r in summaries] == [sample + 100 * k for k in range(1, 10)]
    assert len(sampled) + len(summaries) <= sample + 1000 // 100 + 1
    assert verify_chain(chain).valid
    assert not any(r.incident_id == SYSTEM_INCIDENT_ID for r in chain)


def test_settings_defaults_overrides_and_minimums() -> None:
    assert Settings.from_env({}).max_alert_body_bytes == 65536
    assert Settings.from_env({}).dedup_audit_sample == 20
    assert Settings.from_env({"MAX_ALERT_BODY_BYTES": "1024"}).max_alert_body_bytes == 1024
    assert Settings.from_env({"MAX_ALERT_BODY_BYTES": "0"}).max_alert_body_bytes == 1
    assert Settings.from_env({"DEDUP_AUDIT_SAMPLE": "5"}).dedup_audit_sample == 5
    assert Settings.from_env({"DEDUP_AUDIT_SAMPLE": "0"}).dedup_audit_sample == 1
    assert Settings.from_env({"DEDUP_AUDIT_SAMPLE": "x"}).dedup_audit_sample == 20


@pytest.mark.asyncio
async def test_duplicate_counter_on_terminal_or_missing_incident_does_not_break() -> None:
    from uuid import uuid4

    from backend.tests.test_expiry import add_incident

    services, _, _ = make_services()
    incident = await add_incident(services, "AWAITING_APPROVAL")
    await services.incidents.set_state(incident.incident_id, "FAILED")
    assert await services.incidents.increment_duplicate_count(incident.incident_id) == 1
    assert await services.incidents.increment_duplicate_count(uuid4()) is None
