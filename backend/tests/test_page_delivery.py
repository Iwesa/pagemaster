"""Reliable page delivery (Req 8.1 to 8.4, task 17)."""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import replace
from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient
from langgraph.checkpoint.memory import MemorySaver
from pydantic import SecretStr

from backend.app.agents.graph import build_graph
from backend.app.agents.ports import Ports
from backend.app.api.routes import AppServices
from backend.app.main import Settings, build_in_memory_services, create_app
from backend.app.services.africastalking_client import (
    AfricasTalkingSettings,
    AfricasTalkingSmsAdapter,
    SmsSendError,
)
from backend.app.services.health_state import HealthState
from backend.app.services.llm_summarizer import DisabledSummarizer
from backend.app.services.retrying_sms import RetryingSmsPort, backoff_delay
from backend.app.services.telemetry_adapters import SimulatedRunbooks, StaticTelemetry

ALERT = {"service_name": "auth-db", "error_code": "DB_POOL_EXHAUSTED", "summary": "pool at 100%"}
ONCALL = "+254711000111"
OK_BODY = {"SMSMessageData": {"Recipients": [{"statusCode": 101, "status": "Sent"}]}}


class FakeSleep:
    def __init__(self) -> None:
        self.delays: list[float] = []

    async def __call__(self, delay: float) -> None:
        self.delays.append(delay)


class FailingSmsPort:
    """In-memory SmsPort that fails ``failures`` times, then records messages."""

    def __init__(self, failures: int, error: Exception | None = None) -> None:
        self.failures = failures
        self.error = error if error is not None else SmsSendError("boom", retryable=True)
        self.calls = 0
        self.sent: list[str] = []

    async def send(self, text: str) -> None:
        self.calls += 1
        if self.calls <= self.failures:
            raise self.error
        self.sent.append(text)


def _services(sms: Any) -> AppServices:
    base = build_in_memory_services(Settings(use_in_memory=True))
    ports = Ports(
        telemetry=StaticTelemetry(),
        sms=sms,
        audit=base.audit,
        runbooks=SimulatedRunbooks(),
        summarizer=DisabledSummarizer(),
    )
    return replace(base, graph=build_graph(ports, MemorySaver()), health=HealthState())


def _http_port(handler: Any, sleep: FakeSleep, max_attempts: int = 3) -> tuple[RetryingSmsPort, list[int]]:
    calls: list[int] = []

    def wrapped(request: httpx.Request) -> httpx.Response:
        calls.append(1)
        return handler(len(calls), request)  # type: ignore[no-any-return]

    adapter = AfricasTalkingSmsAdapter(
        AfricasTalkingSettings(dry_run=False, username="u", api_key=SecretStr("k"), to_number=ONCALL),
        transport=httpx.MockTransport(wrapped),
    )
    return RetryingSmsPort(adapter, max_attempts=max_attempts, sleep=sleep, rand=lambda: 0.0), calls


@pytest.fixture()
def run() -> Iterator[Any]:
    """Return ``run(sms) -> (client, services)`` and tear the clients down afterwards."""
    clients: list[TestClient] = []

    def start(sms: Any) -> tuple[TestClient, AppServices]:
        services = _services(sms)
        client = TestClient(create_app(services, Settings(frontend_dir=None)))
        client.__enter__()
        clients.append(client)
        return client, services

    yield start
    for c in clients:
        c.__exit__(None, None, None)


def _events(client: TestClient, incident_id: str) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = client.get(f"/api/incidents/{incident_id}/audit").json()["records"]
    return records


def _state(client: TestClient, incident_id: str) -> str:
    rows = client.get("/api/incidents").json()
    return next(str(r["state"]) for r in rows if r["incident_id"] == incident_id)


def _page_events(client: TestClient, incident_id: str) -> list[str]:
    return [r["event_type"] for r in _events(client, incident_id) if r["event_type"].startswith("PAGER_")]


def test_three_retryable_failures_fail_the_incident_and_refire_returns_202(run: Any) -> None:
    sleep = FakeSleep()
    port, calls = _http_port(lambda n, r: httpx.Response(500, text="down"), sleep)
    client, services = run(port)

    first = client.post("/webhooks/alerts", json=ALERT)
    assert first.status_code == 202
    incident_id = first.json()["incident_id"]

    assert len(calls) == 3
    assert sleep.delays == [1.0, 2.0]
    assert _state(client, incident_id) == "FAILED"
    assert _page_events(client, incident_id) == ["PAGER_FAILED"]
    failed = next(r for r in _events(client, incident_id) if r["event_type"] == "PAGER_FAILED")
    assert failed["payload"] == {"reason": "pager_undeliverable"}
    last = _events(client, incident_id)[-1]
    assert last["event_type"] == "INCIDENT_FAILED" and last["payload"]["reason"] == "pager_undeliverable"
    assert services.health.consecutive_page_failures == 1
    assert services.health.last_failure_at is not None

    again = client.post("/webhooks/alerts", json=ALERT)
    assert again.status_code == 202
    assert again.json()["incident_id"] != incident_id
    assert services.health.consecutive_page_failures == 2


def test_failing_once_then_succeeding_sends_one_page(run: Any) -> None:
    sleep = FakeSleep()

    def handler(n: int, request: httpx.Request) -> httpx.Response:
        return httpx.Response(500) if n == 1 else httpx.Response(201, json=OK_BODY)

    port, calls = _http_port(handler, sleep)
    client, services = run(port)
    services.health.record_page_failure()  # a success must reset the counter

    incident_id = client.post("/webhooks/alerts", json=ALERT).json()["incident_id"]

    assert len(calls) == 2 and len(sleep.delays) == 1
    assert _state(client, incident_id) == "AWAITING_APPROVAL"
    assert _page_events(client, incident_id) == ["PAGER_SENT"]
    assert services.health.consecutive_page_failures == 0


def test_non_retryable_401_is_not_retried(run: Any) -> None:
    sleep = FakeSleep()
    port, calls = _http_port(lambda n, r: httpx.Response(401, text="bad key"), sleep)
    client, _ = run(port)

    incident_id = client.post("/webhooks/alerts", json=ALERT).json()["incident_id"]

    assert len(calls) == 1 and sleep.delays == []
    assert _state(client, incident_id) == "FAILED"
    assert _page_events(client, incident_id) == ["PAGER_FAILED"]


def test_invalid_number_recipient_status_is_not_retried(run: Any) -> None:
    body = {"SMSMessageData": {"Recipients": [{"statusCode": 403, "status": "InvalidPhoneNumber"}]}}
    port, calls = _http_port(lambda n, r: httpx.Response(201, json=body), FakeSleep())
    client, _ = run(port)
    incident_id = client.post("/webhooks/alerts", json=ALERT).json()["incident_id"]
    assert len(calls) == 1
    assert _state(client, incident_id) == "FAILED"


@pytest.mark.parametrize(
    ("response", "retryable"),
    [
        (httpx.Response(500), True),
        (httpx.Response(503), True),
        (httpx.Response(429), True),
        (httpx.Response(408), True),
        (httpx.Response(400), False),
        (httpx.Response(401), False),
        (httpx.Response(403), False),
        (httpx.Response(201, json={"SMSMessageData": {"Recipients": [{"statusCode": 502, "status": "x"}]}}), True),
        (httpx.Response(201, json={"SMSMessageData": {"Recipients": [{"statusCode": 405, "status": "x"}]}}), False),
    ],
)
async def test_error_classification(response: httpx.Response, retryable: bool) -> None:
    adapter = AfricasTalkingSmsAdapter(
        AfricasTalkingSettings(dry_run=False, username="u", api_key=SecretStr("k"), to_number=ONCALL),
        transport=httpx.MockTransport(lambda r: response),
    )
    with pytest.raises(SmsSendError) as info:
        await adapter.send("INC-7A auth-db: x. 7A-1:a 7A-2:b")
    assert info.value.retryable is retryable
    await adapter.aclose()


async def test_transport_error_is_retryable() -> None:
    def boom(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("down")

    adapter = AfricasTalkingSmsAdapter(
        AfricasTalkingSettings(dry_run=False, username="u", api_key=SecretStr("k"), to_number=ONCALL),
        transport=httpx.MockTransport(boom),
    )
    with pytest.raises(SmsSendError) as info:
        await adapter.send("INC-7A auth-db: x. 7A-1:a 7A-2:b")
    assert info.value.retryable is True
    await adapter.aclose()


def test_in_memory_failing_port_wrapped_recovers(run: Any) -> None:
    inner = FailingSmsPort(failures=2)
    sleep = FakeSleep()
    client, _ = run(RetryingSmsPort(inner, max_attempts=3, sleep=sleep, rand=lambda: 0.0))
    incident_id = client.post("/webhooks/alerts", json=ALERT).json()["incident_id"]
    assert inner.calls == 3 and len(inner.sent) == 1
    assert sleep.delays == [1.0, 2.0]
    assert _state(client, incident_id) == "AWAITING_APPROVAL"
    assert _page_events(client, incident_id) == ["PAGER_SENT"]


def test_unwrapped_port_failure_still_fails_without_interrupt(run: Any) -> None:
    inner = FailingSmsPort(failures=99, error=RuntimeError("secret +254700000000"))
    client, _ = run(inner)
    incident_id = client.post("/webhooks/alerts", json=ALERT).json()["incident_id"]
    assert inner.calls == 1
    assert _state(client, incident_id) == "FAILED"
    assert _page_events(client, incident_id) == ["PAGER_FAILED"]
    dumped = str(_events(client, incident_id))
    assert "254700000000" not in dumped and "secret" not in dumped.replace("pager_undeliverable", "")


def test_backoff_schedule_and_jitter() -> None:
    assert [backoff_delay(i, 0.0) for i in range(3)] == [1.0, 2.0, 4.0]
    assert backoff_delay(1, 1.0) == pytest.approx(2.5)


async def test_four_attempts_sleep_one_two_four() -> None:
    sleep = FakeSleep()
    inner = FailingSmsPort(failures=99)
    port = RetryingSmsPort(inner, max_attempts=4, sleep=sleep, rand=lambda: 0.0)
    with pytest.raises(SmsSendError):
        await port.send("x")
    assert sleep.delays == [1.0, 2.0, 4.0] and inner.calls == 4


def test_max_attempts_must_be_positive() -> None:
    with pytest.raises(ValueError):
        RetryingSmsPort(FailingSmsPort(0), max_attempts=0)


def test_health_state_counts_and_resets() -> None:
    health = HealthState()
    health.record_page_failure()
    health.record_page_failure()
    assert health.consecutive_page_failures == 2
    health.record_page_success()
    assert health.consecutive_page_failures == 0 and health.last_failure_at is not None


def test_page_max_attempts_setting() -> None:
    assert Settings.from_env({}).page_max_attempts == 3
    assert Settings.from_env({"PAGE_MAX_ATTEMPTS": "5"}).page_max_attempts == 5
    assert Settings.from_env({"PAGE_MAX_ATTEMPTS": "0"}).page_max_attempts == 1
    assert Settings.from_env({"PAGE_MAX_ATTEMPTS": "abc"}).page_max_attempts == 3
