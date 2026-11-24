"""Overload control (Req 10.1, 10.2, 10.3, task 22).

* telemetry concurrency: a semaphore bounds lookups, one MCP session is reused and respawned;
* triage reuses the context it fetched (no second call), the Tripwire still re-queries fresh;
* page rate: sliding-window limiter, coalesced summary pages, incidents stay well defined.
"""

from __future__ import annotations

import asyncio
import os
import signal
from dataclasses import replace
from pathlib import Path
from typing import Any
from uuid import uuid4

import httpx
import pytest
from langgraph.checkpoint.memory import MemorySaver
from langgraph.types import Command

from backend.app.agents import graph as graph_module
from backend.app.agents.graph import IncidentState, build_graph
from backend.app.agents.ports import Ports, TelemetryContext
from backend.app.api.routes import AppServices
from backend.app.main import Settings, build_in_memory_services, create_app
from backend.app.mcp.server import Confidence, IncidentContext
from backend.app.services.guardrails import PAGER_MAX_CHARS, gsm7_septets
from backend.app.services.page_rate import (
    CoalescingPageGate,
    PageRateLimiter,
    format_summary,
)
from backend.app.services.mcp_client import McpSubprocessTelemetry
from backend.app.services.sms_common import PagerInvariantError, validate_outbound
from backend.app.services.telemetry_adapters import SimulatedRunbooks, StaticTelemetry
from backend.tests.test_workflow import RUNBOOKS, FakeAudit, FakeRunbooks, FakeSms

REPO_ROOT = Path(__file__).resolve().parents[2]
STUB = Path(__file__).with_name("stub_mcp_server.py")


class FakeClock:
    def __init__(self, now: float = 1000.0) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now


# ---------------------------------------------------------------------------
# Telemetry concurrency (Req 10.1)
# ---------------------------------------------------------------------------


def _ctx(service: str) -> IncidentContext:
    return IncidentContext(service_name=service, confidence=Confidence.HIGH)


class ProbeTelemetry(McpSubprocessTelemetry):
    """Real semaphore and timeout logic; the MCP round trip is replaced by a timed fake."""

    def __init__(self, *, max_concurrency: int, timeout: float = 5.0, delay: float = 0.02) -> None:
        super().__init__("unused", max_concurrency=max_concurrency, timeout=timeout)
        self.delay = delay
        self.live = 0
        self.peak = 0
        self.calls = 0

    async def _call(self, service_name: str) -> IncidentContext:
        self.calls += 1
        self.live += 1
        self.peak = max(self.peak, self.live)
        try:
            await asyncio.sleep(self.delay)
        finally:
            self.live -= 1
        return _ctx(service_name)


async def test_peak_telemetry_concurrency_never_exceeds_the_limit_under_60_triages() -> None:
    telemetry = ProbeTelemetry(max_concurrency=4)
    runbooks = FakeRunbooks()
    ports = Ports(telemetry=telemetry, sms=FakeSms(), audit=FakeAudit(), runbooks=runbooks)
    graph = build_graph(ports, MemorySaver())

    async def triage(n: int) -> dict[str, Any]:
        state: IncidentState = {
            "incident_id": str(uuid4()),
            "token": "ABCDEFGHIJ"[n // 10] + "ABCDEFGHIJ"[n % 10],
            "service_name": "auth-db",
            "error_code": "E",
            "alert_summary": "x",
            "audit_records": [],
        }
        result: dict[str, Any] = await graph.ainvoke(
            state, {"configurable": {"thread_id": state["incident_id"]}}
        )
        return result

    results = await asyncio.gather(*(triage(n) for n in range(60)))
    assert telemetry.peak == 4  # the limit is reached but never exceeded
    assert telemetry.calls == 60
    assert all(r["confidence"] == "HIGH" for r in results)  # queueing did not degrade a triage
    assert all(r["status"] == "NO_ACTION" for r in results)  # probe context has no runbooks


async def test_semaphore_wait_is_not_charged_to_the_per_call_timeout() -> None:
    # 20 calls x 0.05 s over 2 slots = 0.5 s of queueing, far above the 0.2 s per-call timeout.
    telemetry = ProbeTelemetry(max_concurrency=2, timeout=0.2, delay=0.05)
    results = await asyncio.gather(*(telemetry.get_incident_context("auth-db") for _ in range(20)))
    assert all(r.confidence == "HIGH" for r in results)
    assert telemetry.peak == 2


async def test_per_call_timeout_still_degrades_a_slow_call() -> None:
    telemetry = ProbeTelemetry(max_concurrency=2, timeout=0.05, delay=0.5)
    assert (await telemetry.get_incident_context("auth-db")).confidence == "DEGRADED"


def test_max_concurrency_must_be_positive() -> None:
    with pytest.raises(ValueError):
        McpSubprocessTelemetry("dsn", max_concurrency=0)


def _spawned(log: Path) -> list[int]:
    return [int(x) for x in log.read_text().split()] if log.exists() else []


def _stub(log: Path, **kw: Any) -> McpSubprocessTelemetry:
    return McpSubprocessTelemetry(
        "unused",
        cwd=REPO_ROOT,
        server_args=[str(STUB)],
        extra_env={"STUB_SPAWN_LOG": str(log)},
        **kw,
    )


async def test_one_mcp_session_is_reused_and_respawned_after_the_subprocess_dies(tmp_path: Path) -> None:
    log = tmp_path / "spawns.txt"
    telemetry = _stub(log, timeout=20.0, max_concurrency=4)
    try:
        first = await telemetry.get_incident_context("auth-db")
        assert first.confidence == "HIGH" and first.runbooks[0].action_id == "RB-STUB"
        # Sequential and concurrent calls share the one subprocess.
        burst = await asyncio.gather(*(telemetry.get_incident_context("auth-db") for _ in range(12)))
        assert all(c.confidence == "HIGH" for c in burst)
        assert len(_spawned(log)) == 1

        os.kill(_spawned(log)[0], signal.SIGTERM)  # simulated death
        await asyncio.sleep(0.5)
        after = await telemetry.get_incident_context("auth-db")
        assert after.confidence == "HIGH"  # respawned, not degraded
        pids = _spawned(log)
        assert len(pids) == 2 and pids[0] != pids[1]
        assert (await telemetry.get_incident_context("auth-db")).confidence == "HIGH"
        assert len(_spawned(log)) == 2

        # A call racing the death (no pause) is retried once on a fresh session, not degraded.
        os.kill(_spawned(log)[1], signal.SIGTERM)
        assert (await telemetry.get_incident_context("auth-db")).confidence == "HIGH"
        assert len(_spawned(log)) == 3
    finally:
        await telemetry.aclose()
    assert not telemetry._tasks  # owner task finished: the subprocess was torn down
    assert (await telemetry.get_incident_context("auth-db")).confidence == "DEGRADED"  # closed
    assert len(_spawned(log)) == 3  # and nothing was respawned after aclose


async def test_spawn_failure_degrades_and_aclose_is_idempotent(tmp_path: Path) -> None:
    telemetry = McpSubprocessTelemetry("unused", cwd=tmp_path / "missing", timeout=10.0)
    assert (await telemetry.get_incident_context("auth-db")).confidence == "DEGRADED"
    await telemetry.aclose()
    await telemetry.aclose()


# ---------------------------------------------------------------------------
# Triage reuses its context; the Tripwire stays fresh (Req 10.2, Property 9)
# ---------------------------------------------------------------------------


class CountingTelemetry:
    def __init__(self, ctx: TelemetryContext | None) -> None:
        self._ctx = ctx
        self.calls = 0

    async def get_incident_context(self, service_name: str) -> TelemetryContext:
        self.calls += 1
        if self._ctx is None:
            raise RuntimeError("telemetry down")
        return self._ctx


def _start(token: str = "7A") -> tuple[IncidentState, Any]:
    incident_id = str(uuid4())
    state: IncidentState = {
        "incident_id": incident_id,
        "token": token,
        "service_name": "auth-db",
        "error_code": "E",
        "alert_summary": "pool",
        "audit_records": [],
    }
    return state, {"configurable": {"thread_id": incident_id}}


@pytest.mark.parametrize(
    "ctx",
    [
        TelemetryContext(confidence="DEGRADED", root_cause="", runbooks=()),
        TelemetryContext(confidence="HIGH", root_cause="x", runbooks=()),
        None,  # the call raised
    ],
    ids=["degraded", "high-without-runbooks", "raised"],
)
async def test_triage_makes_exactly_one_telemetry_call_and_no_runbook_lookup(
    ctx: TelemetryContext | None,
) -> None:
    telemetry = CountingTelemetry(ctx)
    runbooks = FakeRunbooks()  # would offer two runbooks if (wrongly) consulted at triage
    graph = build_graph(
        Ports(telemetry=telemetry, sms=FakeSms(), audit=FakeAudit(), runbooks=runbooks), MemorySaver()
    )
    state, config = _start()
    result = await graph.ainvoke(state, config)
    assert telemetry.calls == 1
    assert runbooks.lookups == 0
    assert result["runbooks"] == [] and result["status"] == "NO_ACTION"


async def test_tripwire_requeries_runbooks_fresh_even_though_triage_reused_its_context() -> None:
    telemetry = CountingTelemetry(TelemetryContext(root_cause="pool", runbooks=RUNBOOKS))
    runbooks = FakeRunbooks()
    graph = build_graph(
        Ports(telemetry=telemetry, sms=FakeSms(), audit=FakeAudit(), runbooks=runbooks), MemorySaver()
    )
    state, config = _start()
    paged = await graph.ainvoke(state, config)
    assert paged["status"] == "AWAITING_APPROVAL" and runbooks.lookups == 0

    runbooks.approved = ()  # revoked after triage: the cached triage context must not authorize
    done = await graph.ainvoke(Command(resume={"choice": "1"}), config)
    assert runbooks.lookups == 1  # exactly one fresh query at execution time
    assert done["status"] == "BLOCKED_BY_TRIPWIRE" and runbooks.executed == []
    assert telemetry.calls == 1


def test_graph_overall_telemetry_bound_exceeds_the_per_call_timeout() -> None:
    assert graph_module.TELEMETRY_OVERALL_TIMEOUT_SECONDS > 5.0


# ---------------------------------------------------------------------------
# Rate limiter and summary text (Req 10.3)
# ---------------------------------------------------------------------------


def test_rate_limiter_admits_the_rate_then_refuses_until_the_window_slides() -> None:
    clock = FakeClock(0.0)
    limiter = PageRateLimiter(6, clock)
    assert [limiter.try_acquire() for _ in range(8)] == [True] * 6 + [False] * 2
    clock.now = 59.9
    assert not limiter.try_acquire()
    clock.now = 60.0  # the first six are exactly 60 s old: out of the window
    assert [limiter.try_acquire() for _ in range(7)] == [True] * 6 + [False]


def test_rate_limiter_has_no_burst_plus_refill_double_allowance() -> None:
    clock = FakeClock(0.0)
    limiter = PageRateLimiter(6, clock)
    sent = 0
    for second in range(0, 60):  # one attempt per second for a minute, bursting at t=0
        clock.now = float(second)
        for _ in range(6 if second == 0 else 1):
            sent += limiter.try_acquire()
    assert sent == 6  # a plain token bucket would have admitted about 12


def test_rate_limiter_minimum_is_one() -> None:
    with pytest.raises(ValueError):
        PageRateLimiter(0)
    limiter = PageRateLimiter(1, FakeClock())
    assert limiter.try_acquire() and not limiter.try_acquire()


def test_summary_text_has_the_documented_form_and_passes_validate_outbound() -> None:
    text = format_summary({"auth-db": 5, "payment-gateway": 2})
    assert text == "ALERTS: 7 more (auth-db x5, payment-gateway x2) see dashboard"
    assert validate_outbound(text) == text
    with_codes = format_summary({"auth-db": 2}, ["AB", "C9"])
    assert with_codes == "ALERTS: 2 more (auth-db x2) codes AB C9 see dashboard"
    assert validate_outbound(with_codes) == with_codes


def test_summary_stays_within_160_septets_and_folds_the_rest_into_other() -> None:
    counts = {f"svc-{i:02d}": 100 - i for i in range(40)}
    text = format_summary(counts, [f"{i % 36:X}{i // 36:X}" for i in range(60)])
    assert gsm7_septets(text) <= PAGER_MAX_CHARS
    assert "other x" in text and text.startswith("ALERTS: ")
    assert " codes " not in text  # the codes did not fit, so they are left out entirely
    assert validate_outbound(text) == text


async def test_service_names_the_sanitiser_would_redact_are_folded_into_other() -> None:
    clock = FakeClock(0.0)
    sms = RecordingSms()
    gate = CoalescingPageGate(sms, PageRateLimiter(1, clock), clock=clock)
    await gate.admit(token="AA", service_name="auth-db", actionable=True)  # the one individual page
    secretish = "service-number-000-x"  # long token-like name: redacted by the sanitiser
    for name in (secretish, secretish, "auth-db"):
        await gate.admit(token="AB", service_name=name, actionable=False)
    assert await gate.flush()
    assert sms.sent == ["ALERTS: 3 more (other x2, auth-db x1) see dashboard"]


def test_only_the_exact_summary_form_is_exempt_from_the_inc_prefix_rule() -> None:
    ok = "ALERTS: 7 more (auth-db x5) see dashboard"
    assert validate_outbound(ok) == ok
    assert validate_outbound("ALERTS: 7 more see dashboard")
    for bad in (
        ok + ".",
        ok.lower(),
        ok + " now",
        "ALERTS: many more see dashboard",
        "ALERTS: 7 more (auth-db) see dashboard",
        "ALERTS: 7 more (auth db x5) see dashboard",
        "Hello ALERTS: 7 more see dashboard",
        "ALERTS: 7 more codes ab see dashboard",
        "ALERTS: 7 more (" + "a" * 25 + " x1) see dashboard",
    ):
        with pytest.raises(PagerInvariantError):
            validate_outbound(bad)


class RecordingSms:
    def __init__(self, fail: int = 0) -> None:
        self.sent: list[str] = []
        self.fail = fail

    async def send(self, text: str) -> None:
        if self.fail > 0:
            self.fail -= 1
            raise RuntimeError("provider down")
        self.sent.append(validate_outbound(text))


async def test_gate_sends_at_most_one_summary_per_interval_and_retries_a_failed_one() -> None:
    clock = FakeClock(0.0)
    sms = RecordingSms(fail=1)
    gate = CoalescingPageGate(sms, PageRateLimiter(2, clock), clock=clock)
    decisions = [
        await gate.admit(token=f"A{i}", service_name="auth-db", actionable=True) for i in range(5)
    ]
    assert decisions == ["SEND", "SEND", "COALESCED", "COALESCED", "COALESCED"]
    assert not await gate.flush() and sms.sent == []  # provider failed: entries are kept
    assert gate.pending == 3
    assert not await gate.flush()  # not again within the interval
    clock.now = 61.0
    assert await gate.flush()
    assert sms.sent == ["ALERTS: 3 more (auth-db x3) codes A2 A3 A4 see dashboard"]
    clock.now = 200.0
    assert not await gate.flush()  # nothing pending


# ---------------------------------------------------------------------------
# 60 alerts in 3 s (Req 10.3), in-memory stack
# ---------------------------------------------------------------------------

SERVICES = ("auth-db", "payment-gateway", "ledger-worker")


def _storm_services(rate: int, clock: FakeClock) -> tuple[AppServices, CoalescingPageGate]:
    base = build_in_memory_services(Settings(use_in_memory=True))
    gate = CoalescingPageGate(base.sms, PageRateLimiter(rate, clock), clock=clock)
    ports = Ports(
        telemetry=StaticTelemetry(),
        sms=base.sms,
        audit=base.audit,
        runbooks=SimulatedRunbooks(),
        page_gate=gate,
    )
    return replace(base, graph=build_graph(ports, MemorySaver()), page_gate=gate), gate


def _outbox(services: AppServices) -> list[str]:
    return [m.text for m in services.sms.outbox]  # type: ignore[attr-defined]


async def test_alert_storm_pages_at_most_the_rate_then_one_summary_and_every_incident_is_defined() -> None:
    clock = FakeClock()
    services, gate = _storm_services(6, clock)
    app = create_app(services, Settings(frontend_dir=None))
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t") as client:

        async def fire(i: int) -> int:
            clock.now += 0.05  # 60 alerts over 3 s
            body = {"service_name": SERVICES[i % 3], "error_code": f"E{i}", "summary": "storm"}
            return (await client.post("/webhooks/alerts", json=body)).status_code

        statuses = await asyncio.gather(*(fire(i) for i in range(60)))
        assert statuses == [202] * 60
        incidents = (await client.get("/api/incidents")).json()
        assert len(incidents) == 60
        assert {i["state"] for i in incidents} == {"AWAITING_APPROVAL"}

        sent = coalesced = 0
        for inc in incidents:
            audit = (await client.get(f"/api/incidents/{inc['incident_id']}/audit")).json()
            types = [r["event_type"] for r in audit["records"]]
            assert audit["chain_valid"]
            assert types.count("PAGER_SENT") + types.count("PAGER_COALESCED") == 1
            sent += types.count("PAGER_SENT")
            coalesced += types.count("PAGER_COALESCED")
            for r in audit["records"]:
                if r["event_type"] == "PAGER_COALESCED":
                    assert r["payload"] == {"reason": "rate_limited"}  # reason only
        assert (sent, coalesced) == (6, 54)
        assert len(_outbox(services)) == 6 and all(t.startswith("INC-") for t in _outbox(services))

        await services.lifecycle.tick()  # the reaper tick flushes the summary
        summaries = [t for t in _outbox(services) if t.startswith("ALERTS:")]
        assert len(summaries) == 1
        assert summaries[0].startswith("ALERTS: 54 more (")
        assert gsm7_septets(summaries[0]) <= PAGER_MAX_CHARS
        assert " x18" in summaries[0] and " codes " not in summaries[0]  # 54 codes do not fit

        await services.lifecycle.tick()  # not due again within the minute
        assert len([t for t in _outbox(services) if t.startswith("ALERTS:")]) == 1
        assert gate.pending == 0


async def test_a_coalesced_page_does_not_reset_the_consecutive_failure_count() -> None:
    clock = FakeClock()
    services, _ = _storm_services(1, clock)
    app = create_app(services, Settings(frontend_dir=None))
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t") as client:
        await client.post("/webhooks/alerts", json={"service_name": "auth-db", "error_code": "E1"})
        services.health.record_page_failure()
        services.health.record_page_failure()
        r = await client.post("/webhooks/alerts", json={"service_name": "auth-db", "error_code": "E2"})
        assert r.status_code == 202
        assert services.health.consecutive_page_failures == 2  # the withheld page proved nothing


def test_settings_parse_the_overload_variables() -> None:
    default = Settings.from_env({})
    assert (default.telemetry_max_concurrency, default.page_rate_per_minute) == (4, 6)
    custom = Settings.from_env({"TELEMETRY_MAX_CONCURRENCY": "2", "PAGE_RATE_PER_MINUTE": "10"})
    assert (custom.telemetry_max_concurrency, custom.page_rate_per_minute) == (2, 10)
    low = Settings.from_env({"TELEMETRY_MAX_CONCURRENCY": "0", "PAGE_RATE_PER_MINUTE": "-3"})
    assert (low.telemetry_max_concurrency, low.page_rate_per_minute) == (1, 1)
    bad = Settings.from_env({"TELEMETRY_MAX_CONCURRENCY": "x", "PAGE_RATE_PER_MINUTE": ""})
    assert (bad.telemetry_max_concurrency, bad.page_rate_per_minute) == (4, 6)

