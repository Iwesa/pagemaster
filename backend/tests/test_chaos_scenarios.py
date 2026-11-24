"""Named chaos scenarios from the external review (task 27, Req 12.1), in memory.

Each scenario is an ``async def scenario_*`` that drives ``create_app`` over an ASGI client with
in-memory services and asserts the outcome the review demanded. The scenario tests run them
as they are; the ``test_meta_*`` tests break the code under test (no reaper, no token cooldown)
and require the same scenario to fail, so a deleted safeguard cannot go unnoticed.

Where each scenario is covered in finer detail (this module adds the end-to-end view only):

=====================  =====================================================================
crash recovery         ``test_lifecycle_sweep.py``, ``test_expiry.py``
page failure           ``test_page_delivery.py``
double reply           ``test_forgiving_replies.py``
duplicate storm        ``test_request_limits.py``
dependency outage      ``test_readiness.py``
alert storm            ``test_overload.py``
=====================  =====================================================================

The real-stack variants (crash by killing the process, proxy-simulated Postgres/Redis outage,
60-alert storm against Postgres and Redis) live in ``test_real_stack.py``.
"""

from __future__ import annotations

import asyncio
import re
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from dataclasses import replace
from pathlib import Path
from typing import Any
from uuid import UUID

import asyncpg  # type: ignore[import-untyped]
import httpx
import pytest
import redis.exceptions as redis_exc
from langgraph.checkpoint.memory import MemorySaver

from backend.app.agents.graph import build_graph
from backend.app.agents.ports import Ports
from backend.app.api.routes import AppServices
from backend.app.main import Settings, build_in_memory_services, create_app
from backend.app.mcp.server import RunbookOption
from backend.app.services.guardrails import verify_chain
from backend.app.services.incident_store import InMemoryIncidentRepository
from backend.app.services.lifecycle import Lifecycle
from backend.app.services.page_rate import CoalescingPageGate, PageRateLimiter
from backend.app.services.telemetry_adapters import SimulatedRunbooks
from backend.tests.test_expiry import (
    SERVICE,
    add_incident,
    make_services,
    outbox,
    reply,
    state_of,
)
from backend.tests.test_overload import FakeClock, ProbeTelemetry
from backend.tests.test_page_delivery import ALERT as PAGE_ALERT
from backend.tests.test_page_delivery import FakeSleep, _http_port, _services
from backend.tests.test_page_options import ALERT as OPTIONS_ALERT
from backend.tests.test_page_options import ALL_RUNBOOKS, _Runbooks, _Telemetry
from backend.tests.test_readiness import Flaky
from backend.tests.test_request_limits import _IdleGraph

TIMEOUT = 30  # in-flight timeout used by the crash scenario (any value >= 10 is valid in production)


@asynccontextmanager
async def _client(services: AppServices) -> AsyncIterator[httpx.AsyncClient]:
    app = create_app(services, Settings(frontend_dir=None, dry_run=True))
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as client:
        yield client


def _alert(service: str, code: str) -> dict[str, str]:
    return {"service_name": service, "error_code": code, "summary": "chaos"}


# ---------------------------------------------------------------------------
# 1. Crash recovery (task 16)
# ---------------------------------------------------------------------------


async def scenario_crash_recovery() -> None:
    """A worker died mid-triage and mid-execution. The reaper frees both, alerts flow again."""
    services, clock, graph = make_services()
    services = replace(services, triage_timeout_seconds=TIMEOUT, executing_timeout_seconds=TIMEOUT)
    triaging = await add_incident(services, "TRIAGING", token="AA", code="E1")
    executing = await add_incident(services, "EXECUTING", token="BB", code="E2")
    async with _client(services) as client:
        # While the orphans own their fingerprints a re-fired alert is swallowed as a duplicate.
        swallowed = await client.post("/webhooks/alerts", json=_alert(SERVICE, "E1"))
        assert swallowed.status_code == 200

        clock.advance(TIMEOUT + 1)
        await services.lifecycle.tick()  # one reaper iteration

        assert await state_of(services, triaging.incident_id) == "FAILED"
        assert await state_of(services, executing.incident_id) == "FAILED"
        assert graph.calls == []  # remediation was never re-run
        assert sorted(outbox(services)) == ["INC-AA FAILED. Re-send the alert.", "INC-BB FAILED. Re-send the alert."]
        for code, old in (("E1", triaging), ("E2", executing)):
            refired = await client.post("/webhooks/alerts", json=_alert(SERVICE, code))
            assert refired.status_code == 202
            assert refired.json()["incident_id"] != str(old.incident_id)


async def test_crash_recovery() -> None:
    await scenario_crash_recovery()


# ---------------------------------------------------------------------------
# 2. Page failure (task 17)
# ---------------------------------------------------------------------------


async def scenario_page_failure() -> None:
    """The SMS provider answers 500 on every attempt: FAILED, lock released, re-fire accepted."""
    sleep = FakeSleep()
    port, calls = _http_port(lambda n, r: httpx.Response(500, text="down"), sleep)
    services = _services(port)
    async with _client(services) as client:
        first = await client.post("/webhooks/alerts", json=PAGE_ALERT)
        assert first.status_code == 202
        first_id = UUID(first.json()["incident_id"])
        assert len(calls) == 3 and sleep.delays == [1.0, 2.0]  # three attempts, backoff between them
        assert await state_of(services, first_id) == "FAILED"
        events = [r.event_type for r in await services.audit.records(first_id)]
        assert events.count("PAGER_FAILED") == 1 and "PAGER_SENT" not in events
        assert services.health.consecutive_page_failures == 1

        again = await client.post("/webhooks/alerts", json=PAGE_ALERT)
        assert again.status_code == 202 and again.json()["incident_id"] != str(first_id)


async def test_page_failure() -> None:
    await scenario_page_failure()


# ---------------------------------------------------------------------------
# 3. Double reply (task 19)
# ---------------------------------------------------------------------------


async def scenario_double_reply() -> None:
    """Five replies race for one approval: one execution, four 'already handled' answers."""
    runbooks = _Runbooks(ALL_RUNBOOKS)
    base = build_in_memory_services(Settings(use_in_memory=True))
    ports = Ports(telemetry=_Telemetry(ALL_RUNBOOKS), sms=base.sms, audit=base.audit, runbooks=runbooks)
    services = replace(base, graph=build_graph(ports, MemorySaver()))
    async with _client(services) as client:
        resp = await client.post("/webhooks/alerts", json=OPTIONS_ALERT)
        assert resp.status_code == 202
        incident_id = UUID(resp.json()["incident_id"])
    incident = await services.incidents.get(incident_id)
    assert incident is not None and incident.state == "AWAITING_APPROVAL"

    await asyncio.gather(*(reply(services, f"{incident.token}-1") for _ in range(5)))

    assert runbooks.executed == ["RB-ONE"]
    assert await state_of(services, incident_id) == "RESOLVED"
    losers = [t for t in outbox(services) if "already handled" in t]
    assert len(losers) == 4
    assert all(re.fullmatch(rf"INC-{incident.token} already handled \((EXECUTING|RESOLVED)\)\.", t) for t in losers)
    assert not any("not awaiting approval" in t for t in outbox(services))


async def test_double_reply() -> None:
    await scenario_double_reply()


# ---------------------------------------------------------------------------
# 4. Duplicate storm (task 21)
# ---------------------------------------------------------------------------

STORM_DUPLICATES = 1000
AUDIT_SAMPLE = 20


async def scenario_duplicate_storm() -> None:
    """1000 duplicates: one incident, a capped number of audit rows, a valid hash chain."""
    services, _, _ = make_services()
    services = replace(services, dedup_audit_sample=AUDIT_SAMPLE, graph=_IdleGraph())
    async with _client(services) as client:
        first = await client.post("/webhooks/alerts", json=OPTIONS_ALERT)
        assert first.status_code == 202
        incident_id = first.json()["incident_id"]
        for _ in range(STORM_DUPLICATES):
            dup = await client.post("/webhooks/alerts", json=OPTIONS_ALERT)
            assert dup.status_code == 200 and dup.json()["incident_id"] == incident_id
        view = (await client.get(f"/api/incidents/{incident_id}/audit")).json()
    row = await services.incidents.get(UUID(incident_id))
    assert row is not None and row.duplicate_count == STORM_DUPLICATES  # the count stays exact
    kinds = [r["event_type"] for r in view["records"]]
    dedup_rows = sum(k.startswith("ALERT_DEDUPLICATED") for k in kinds)
    assert AUDIT_SAMPLE <= dedup_rows <= AUDIT_SAMPLE + STORM_DUPLICATES // 100 + 1
    assert view["chain_valid"] and verify_chain(await services.audit.records(row.incident_id)).valid
    assert len(await services.incidents.list_recent()) == 1


async def test_duplicate_storm() -> None:
    await scenario_duplicate_storm()


# ---------------------------------------------------------------------------
# 5. Dependency outage (task 23)
# ---------------------------------------------------------------------------


async def scenario_dependency_outage() -> None:
    """Redis, then Postgres, fail mid-flight: 503 + Retry-After, no residue, recovery without restart."""
    base = build_in_memory_services(Settings(use_in_memory=True))
    dedup = Flaky(base.dedup, {"acquire"})
    repo = Flaky(base.incidents, {"create"})
    redis_down = False

    async def ping_redis() -> None:
        if redis_down:
            raise redis_exc.ConnectionError("down")

    async def ping_postgres() -> None:
        if repo.exc is not None:
            raise asyncpg.PostgresConnectionError("down")

    services = replace(
        base,
        dedup=dedup,  # type: ignore[arg-type]
        incidents=repo,  # type: ignore[arg-type]
        ping_redis=ping_redis,
        ping_postgres=ping_postgres,
    )
    body = _alert("auth-db", "OUTAGE")
    async with _client(services) as client:
        assert (await client.get("/readyz")).status_code == 200

        redis_down, dedup.exc = True, redis_exc.ConnectionError("down")
        resp = await client.post("/webhooks/alerts", json=body)
        assert resp.status_code == 503 and resp.headers["Retry-After"] == "5"
        assert resp.json() == {"detail": "dependency unavailable"}
        ready = await client.get("/readyz")
        assert ready.status_code == 503 and ready.json()["checks"]["redis"]["ok"] is False
        assert (await client.get("/healthz")).status_code == 200  # liveness never depends on them
        redis_down, dedup.exc = False, None

        repo.exc = asyncpg.InterfaceError("pool is closed")
        resp = await client.post("/webhooks/alerts", json=body)
        assert resp.status_code == 503 and resp.headers["Retry-After"] == "5"
        ready = await client.get("/readyz")
        assert ready.status_code == 503 and ready.json()["checks"]["postgres"]["ok"] is False
        assert await base.incidents.list_recent() == []  # nothing half-created
        repo.exc = None

        assert (await client.get("/readyz")).status_code == 200
        # The lock taken during the failed attempt was released, so this is a new incident.
        assert (await client.post("/webhooks/alerts", json=body)).status_code == 202


async def test_dependency_outage() -> None:
    await scenario_dependency_outage()


# ---------------------------------------------------------------------------
# 6. Alert storm (task 22)
# ---------------------------------------------------------------------------

STORM_ALERTS = 60
STORM_CONCURRENCY = 4
STORM_PAGE_RATE = 6
STORM_SERVICES = ("auth-db", "payment-gateway", "ledger-worker")


class _StormTelemetry(ProbeTelemetry):
    """Real semaphore and timeout logic of the MCP adapter; every service has one runbook."""

    async def _call(self, service_name: str) -> Any:
        ctx = await super()._call(service_name)
        option = RunbookOption(action_id=f"RB-{service_name}", service_name=service_name, title="Restart", description="")
        return ctx.model_copy(update={"runbooks": [option]})


async def scenario_alert_storm() -> None:
    """60 distinct alerts at once: bounded telemetry, bounded pages, nothing left undefined."""
    clock = FakeClock()
    telemetry = _StormTelemetry(max_concurrency=STORM_CONCURRENCY)
    base = build_in_memory_services(Settings(use_in_memory=True))
    gate = CoalescingPageGate(base.sms, PageRateLimiter(STORM_PAGE_RATE, clock), clock=clock)
    ports = Ports(telemetry=telemetry, sms=base.sms, audit=base.audit, runbooks=SimulatedRunbooks(), page_gate=gate)
    services = replace(base, graph=build_graph(ports, MemorySaver()), page_gate=gate)
    async with _client(services) as client:

        async def fire(i: int) -> int:
            clock.now += 0.05  # 60 alerts over 3 s
            body = _alert(STORM_SERVICES[i % 3], f"S{i}")
            return (await client.post("/webhooks/alerts", json=body)).status_code

        assert await asyncio.gather(*(fire(i) for i in range(STORM_ALERTS))) == [202] * STORM_ALERTS
        await services.lifecycle.tick()  # flushes the coalesced summary page

    assert telemetry.calls == STORM_ALERTS and telemetry.peak <= STORM_CONCURRENCY
    incidents = await services.incidents.list_recent()
    assert len(incidents) == STORM_ALERTS
    assert {i.state for i in incidents} == {"AWAITING_APPROVAL"}  # defined, none stuck in TRIAGING
    texts = outbox(services)
    individual = [t for t in texts if t.startswith("INC-")]
    summaries = [t for t in texts if t.startswith("ALERTS:")]
    assert len(individual) == STORM_PAGE_RATE and len(summaries) == 1
    assert summaries[0].startswith(f"ALERTS: {STORM_ALERTS - STORM_PAGE_RATE} more")
    assert not any("DEGRADED" in t for t in texts)  # queueing alone never degrades a triage
    for incident in incidents:
        assert verify_chain(await services.audit.records(incident.incident_id)).valid


async def test_alert_storm() -> None:
    await scenario_alert_storm()


# ---------------------------------------------------------------------------
# 7. Token cooldown (task 20), the second safeguard the meta tests remove
# ---------------------------------------------------------------------------


async def scenario_token_cooldown() -> None:
    """A finished incident's token is not reissued during the cooldown."""
    services, clock, _ = make_services()
    services = replace(services, token_alphabet="A")  # a single token, "AA"
    done = await add_incident(services, "TRIAGING", token="AA", service="old")
    await services.incidents.set_state(done.incident_id, "RESOLVED")
    async with _client(services) as client:
        assert (await client.post("/webhooks/alerts", json=_alert("svc-new", "E1"))).status_code == 503
        clock.advance(services.token_cooldown_seconds)
        assert (await client.post("/webhooks/alerts", json=_alert("svc-new", "E2"))).status_code == 202


async def test_token_cooldown() -> None:
    await scenario_token_cooldown()


# ---------------------------------------------------------------------------
# CI files (Req 12.3): the workflow itself cannot run locally, so pin what it must contain
# ---------------------------------------------------------------------------

ROOT = Path(__file__).resolve().parents[2]


def test_smoke_script_is_strict_posix_sh_without_jq() -> None:
    raw = (ROOT / "scripts" / "smoke_compose.sh").read_bytes()
    text = raw.decode("ascii")
    assert b"\r" not in raw and text.startswith("#!/bin/sh\n")
    assert "set -eu" in text and "| jq" not in text
    assert "[[" not in text and "pipefail" not in text  # no bash-only syntax
    for needle in ("/readyz", "/webhooks/alerts", "/api/demo/outbox", "/api/demo/reply", "RESOLVED", "ALERT_WEBHOOK_SECRET"):
        assert needle in text


def test_workflow_runs_the_documented_commands() -> None:
    workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    for needle in (
        "postgres:16-alpine",
        "redis:7-alpine",
        "TEST_DATABASE_URL",
        "TEST_REDIS_URL",
        "pip install -r backend/requirements.txt",
        "mypy --strict backend/app",
        "pytest backend/tests -q",
        "docker build -f backend/Dockerfile -t pagemaster-backend .",
        "docker compose up -d --wait",
        "scripts/smoke_compose.sh",
        "docker compose down -v",
    ):
        assert needle in workflow, needle
    assert workflow.index("if: always()") > workflow.index("smoke_compose.sh")  # teardown runs last


# ---------------------------------------------------------------------------
# Meta tests: the suite must notice a deleted safeguard (Req 12, task 27 acceptance)
# ---------------------------------------------------------------------------


async def _noop(*args: Any, **kwargs: Any) -> int:
    return 0


@pytest.mark.parametrize("method", ["tick", "sweep_inflight"])
async def test_meta_crash_scenario_fails_when_the_reaper_does_not_sweep(
    monkeypatch: pytest.MonkeyPatch, method: str
) -> None:
    monkeypatch.setattr(Lifecycle, method, _noop)
    with pytest.raises(AssertionError):
        await scenario_crash_recovery()


async def test_meta_cooldown_scenario_fails_when_the_cooldown_is_disabled(monkeypatch: pytest.MonkeyPatch) -> None:
    original: Callable[..., Awaitable[frozenset[str]]] = InMemoryIncidentRepository.busy_tokens

    async def no_cooldown(self: InMemoryIncidentRepository, cooldown_seconds: float) -> frozenset[str]:
        return await original(self, 0)  # only active incidents hold a token

    monkeypatch.setattr(InMemoryIncidentRepository, "busy_tokens", no_cooldown)
    with pytest.raises(AssertionError):
        await scenario_token_cooldown()
