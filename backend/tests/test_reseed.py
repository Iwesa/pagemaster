"""Task 6.3: DEGRADED on empty window, reseed_recent_logs, POST /api/demo/reseed.

Requirements: 2.4, 2.5.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import replace
from datetime import UTC, datetime
from typing import Any, cast

import pytest
from fastapi.testclient import TestClient
from langgraph.checkpoint.memory import MemorySaver

from backend.app.agents.graph import build_graph
from backend.app.agents.ports import Ports
from backend.app.api.routes import AppServices
from backend.app.main import Settings, build_in_memory_services, create_app
from backend.tests.test_api import live_settings
from backend.app.mcp.server import (
    NO_RECENT_LOGS_REASON,
    Confidence,
    IncidentContext,
    TelemetryStore,
    reseed_recent_logs,
)
from backend.app.services.dedup import InMemoryDedupStore
from backend.app.services.incident_store import InMemoryAuditStore, InMemoryIncidentRepository
from backend.app.services.llm_summarizer import DisabledSummarizer
from backend.app.services.telemetry_adapters import DatabaseTelemetry, SimulatedRunbooks
from backend.app.services.africastalking_client import AfricasTalkingSettings, AfricasTalkingSmsAdapter

LOG_ROW: dict[str, Any] = {
    "service_name": "auth-db",
    "level": "ERROR",
    "error_code": "DB_POOL_EXHAUSTED",
    "message": "too many clients",
    "stack_trace": None,
    "logged_at": datetime(2025, 1, 1, tzinfo=UTC),
}
EDGE_ROW: dict[str, Any] = {"service_name": "auth-db", "depends_on": None, "tier": "data"}
BOOK_ROW: dict[str, Any] = {
    "action_id": "RB-AUTHDB-RESET-POOL",
    "service_name": "auth-db",
    "title": "Reset connection pool",
    "description": "d",
}


class _Txn:
    async def __aenter__(self) -> None:
        return None

    async def __aexit__(self, *exc: object) -> None:
        return None


class _FakeConn:
    def __init__(self, logs: list[dict[str, Any]]) -> None:
        self.logs = logs
        self.executed: list[str] = []

    def transaction(self) -> _Txn:
        return _Txn()

    async def execute(self, sql: str, *args: object) -> str:
        self.executed.append(sql)
        return "SET"

    async def fetch(self, sql: str, *args: object) -> list[dict[str, Any]]:
        if "v_recent_logs" in sql:
            return self.logs
        return [EDGE_ROW] if "v_service_topology" in sql else [BOOK_ROW]


class _Acquire:
    def __init__(self, conn: _FakeConn) -> None:
        self.conn = conn

    async def __aenter__(self) -> _FakeConn:
        return self.conn

    async def __aexit__(self, *exc: object) -> None:
        return None


class _FakePool:
    def __init__(self, logs: list[dict[str, Any]]) -> None:
        self.conn = _FakeConn(logs)
        self.reseed_calls: list[tuple[str, tuple[object, ...]]] = []

    def acquire(self) -> _Acquire:
        return _Acquire(self.conn)

    async def execute(self, sql: str, *args: object, timeout: float | None = None) -> str:
        self.reseed_calls.append((sql, args))
        return "UPDATE 17"


def _store(logs: list[dict[str, Any]]) -> tuple[TelemetryStore, _FakeConn]:
    store = TelemetryStore("postgresql://unused")
    pool = _FakePool(logs)
    store._pool = cast(Any, pool)
    return store, pool.conn


async def test_empty_recent_logs_is_degraded_with_reason() -> None:
    store, conn = _store([])
    ctx = await store.get_incident_context("auth-db")
    assert ctx.confidence is Confidence.DEGRADED
    assert ctx.degraded_reason == "no recent logs in window" == NO_RECENT_LOGS_REASON
    assert ctx.recent_logs == [] and [r.action_id for r in ctx.runbooks] == ["RB-AUTHDB-RESET-POOL"]
    assert conn.executed == ["SET TRANSACTION READ ONLY"]


async def test_non_empty_recent_logs_stays_high() -> None:
    store, _ = _store([LOG_ROW])
    ctx = await store.get_incident_context("auth-db")
    assert ctx.confidence is Confidence.HIGH and ctx.degraded_reason is None


async def test_degraded_empty_window_reaches_the_pager() -> None:
    store, _ = _store([])
    incidents = InMemoryIncidentRepository()
    audit = InMemoryAuditStore(incidents)
    sms = AfricasTalkingSmsAdapter(AfricasTalkingSettings(dry_run=True))
    telemetry = DatabaseTelemetry(store)
    ports = Ports(
        telemetry=telemetry,
        sms=sms,
        audit=audit,
        runbooks=SimulatedRunbooks(telemetry),
        summarizer=DisabledSummarizer(),
    )
    graph = build_graph(ports, MemorySaver())
    from uuid import uuid4

    iid = uuid4()
    await incidents.create(
        incident_id=iid, token="AB", service_name="auth-db", error_code="E1", raw_alert={}
    )
    await graph.ainvoke(
        {
            "incident_id": str(iid),
            "token": "AB",
            "service_name": "auth-db",
            "error_code": "E1",
            "alert_summary": "pool at 100%",
            "audit_records": [],
        },
        {"configurable": {"thread_id": str(iid)}},
    )
    assert sms.outbox and "[DEGRADED]" in sms.outbox[0].text
    assert sms.outbox[0].text.startswith("INC-AB ") and len(sms.outbox[0].text) <= 160


async def test_reseed_recent_logs_uses_fixed_parameterized_sql() -> None:
    pool = _FakePool([])
    assert await reseed_recent_logs(cast(Any, pool)) == 17
    sql, args = pool.reseed_calls[0]
    assert sql.startswith("UPDATE service_logs") and "$1" in sql
    assert args == (["auth-db", "payment-gateway", "ledger-worker"],)


def test_incident_context_model_default_unchanged() -> None:
    assert IncidentContext(service_name="x", confidence=Confidence.HIGH).degraded_reason is None


# ----------------------------- POST /api/demo/reseed -----------------------------


@pytest.fixture()
def services() -> AppServices:
    return build_in_memory_services(Settings(use_in_memory=True))


@pytest.fixture()
def demo_client(services: AppServices) -> Iterator[TestClient]:
    with TestClient(create_app(services, Settings(frontend_dir=None, dry_run=True))) as c:
        yield c


def test_reseed_noop_ok_in_memory(demo_client: TestClient) -> None:
    res = demo_client.post("/api/demo/reseed")
    assert res.status_code == 200 and res.json() == {"status": "ok", "rows_refreshed": 0}


def test_reseed_calls_injected_reseeder(services: AppServices) -> None:
    calls: list[int] = []

    async def reseed() -> int:
        calls.append(1)
        return 5

    with TestClient(create_app(replace(services, reseed=reseed), Settings(frontend_dir=None, dry_run=True))) as c:
        assert c.post("/api/demo/reseed").json()["rows_refreshed"] == 5
    assert calls == [1]


def test_reseed_failure_is_503(services: AppServices) -> None:
    async def boom() -> int:
        raise OSError("db down")

    with TestClient(create_app(replace(services, reseed=boom), Settings(frontend_dir=None, dry_run=True))) as c:
        assert c.post("/api/demo/reseed").status_code == 503


class _LiveSms:
    async def send(self, text: str) -> None:
        return None


def test_reseed_disabled_when_not_dry_run(services: AppServices) -> None:
    calls: list[int] = []

    async def reseed() -> int:
        calls.append(1)
        return 1

    svc = replace(services, reseed=reseed)
    with TestClient(create_app(svc, live_settings())) as c:
        assert c.post("/api/demo/reseed").status_code in (404, 405)
    live = replace(svc, sms=_LiveSms())
    with TestClient(create_app(live, Settings(frontend_dir=None, dry_run=True))) as c:
        assert c.post("/api/demo/reseed").status_code == 404
    assert calls == []

