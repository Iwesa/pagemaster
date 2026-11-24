"""Stateful Hypothesis test of the incident lifecycle (task 27, Req 12.2).

A ``RuleBasedStateMachine`` drives the real app (``create_app`` over an ASGI client), the real
in-memory repository, audit store, dedup store, ``Lifecycle`` and the real LangGraph graph, with
a fake clock and a fake SMS port. Rules: alert (new or duplicate), reply (valid or noise), crash
(the next graph run is silently lost, as if the worker died), page failure (the next SMS send
fails), reaper tick, and clock advances (which drive expiry and the in-flight timeouts).

Invariants checked after every step:

* ``RESOLVED`` incidents have all four resolution gates true.
* At most one approval resume (execution) per incident, and no more remediation steps than resumes.
* Terminal states are absorbing.
* The dedup lock is held by every active incident and by no terminal one; one active incident
  per fingerprint.
* Reply tokens are unique among active incidents.
* After a reaper tick nothing is older than its timeout (``AWAITING_APPROVAL`` < TTL, ``TRIAGING``
  and ``EXECUTING`` < their timeouts), so every incident is terminal within the maximum timeout
  plus two ticks. The machine's teardown asserts that directly by advancing past every timeout.

The dedup store's TTL is set far beyond the fake clock so lock expiry (a separate Redis feature)
does not mask a leaked lock.
"""

from __future__ import annotations

import asyncio
from collections import Counter
from collections.abc import Coroutine
from dataclasses import replace
from typing import Any
from uuid import UUID, uuid4

import httpx
import pytest
from fastapi import BackgroundTasks
from hypothesis import HealthCheck, Phase, settings
from hypothesis import strategies as st
from hypothesis.stateful import (
    Bundle,
    RuleBasedStateMachine,
    invariant,
    rule,
    run_state_machine_as_test,
)
from langgraph.checkpoint.memory import MemorySaver
from langgraph.types import Command

from backend.app.agents.graph import build_graph
from backend.app.agents.ports import Ports
from backend.app.api.routes import AppServices, _handle_reply
from backend.app.main import Settings, build_in_memory_services, create_app
from backend.app.services.dedup import Acquired, InMemoryDedupStore
from backend.app.services.incident_store import (
    ACTIVE_STATUSES,
    TERMINAL_STATUSES,
    InMemoryAuditStore,
    InMemoryIncidentRepository,
)
from backend.app.services.lifecycle import Lifecycle
from backend.app.services.telemetry_adapters import SimulatedRunbooks, StaticTelemetry
from backend.tests.test_expiry import Clock

SERVICES = ("auth-db", "payment-gateway", "ledger-worker")
CODES = ("E1", "E2")
APPROVAL_TTL = 900
TRIAGE_TIMEOUT = 120
EXECUTING_TIMEOUT = 120
MAX_TIMEOUT = max(APPROVAL_TTL, TRIAGE_TIMEOUT, EXECUTING_TIMEOUT)
ADVANCES = (30, 119, 121, 901)
NOISE = ("hello", "", "ZZ-1", "AB-1 thanks", "approve AB-1", "7A-3")
ALL_GATES = ("tripwire_check_passed", "simulated_step_executed", "confirmation_sms_sent", "audit_record_committed")


class ChaosGraph:
    """Wraps the real graph. ``crash_next`` loses the next run (no state change, no side effect)."""

    def __init__(self, inner: Any) -> None:
        self.inner = inner
        self.crash_next = False
        self.resumes: Counter[str] = Counter()  # approval resumes per incident (thread) id

    async def ainvoke(self, input: Any, config: Any = None) -> Any:
        if isinstance(input, Command):
            self.resumes[config["configurable"]["thread_id"]] += 1
        if self.crash_next:
            self.crash_next = False
            return {}  # the worker died: the caller sees no result, the incident row is untouched
        return await self.inner.ainvoke(input, config)

    def __getattr__(self, name: str) -> Any:  # aget_state for checkpoint resume
        return getattr(self.inner, name)


class FlakySms:
    """The graph's SMS port. ``fail_next`` makes the next sends raise."""

    def __init__(self) -> None:
        self.fail_next = 0
        self.sent: list[str] = []

    async def send(self, text: str) -> None:
        if self.fail_next > 0:
            self.fail_next -= 1
            raise RuntimeError("provider down")
        self.sent.append(text)


class CountingRunbooks(SimulatedRunbooks):
    def __init__(self) -> None:
        super().__init__()
        self.executions = 0

    async def execute(self, *, target_host: str, action_id: str, token: str) -> bool:
        self.executions += 1
        return await super().execute(target_host=target_host, action_id=action_id, token=token)



class LifecycleMachine(RuleBasedStateMachine):
    incident_ids = Bundle("incident_ids")

    def __init__(self) -> None:
        super().__init__()
        self.loop = asyncio.new_event_loop()
        self.clock = Clock()
        self.sms = FlakySms()
        self.runbooks = CountingRunbooks()
        self.repo = InMemoryIncidentRepository(self.clock)
        audit = InMemoryAuditStore(self.repo)
        ports = Ports(telemetry=StaticTelemetry(), sms=self.sms, audit=audit, runbooks=self.runbooks)
        self.graph = ChaosGraph(build_graph(ports, MemorySaver()))
        base = build_in_memory_services(Settings(use_in_memory=True))
        self.services: AppServices = replace(
            base,
            graph=self.graph,
            incidents=self.repo,
            audit=audit,
            dedup=InMemoryDedupStore(ttl_seconds=10**9),
            clock=self.clock,
            approval_ttl_seconds=APPROVAL_TTL,
            triage_timeout_seconds=TRIAGE_TIMEOUT,
            executing_timeout_seconds=EXECUTING_TIMEOUT,
            inflight_stale_seconds=TRIAGE_TIMEOUT,
            triage_wait_seconds=0.0,  # replies never wait for triage: no real sleeping
        )
        app = create_app(self.services, Settings(frontend_dir=None, dry_run=True))
        self.client = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t")
        self.terminal_seen: dict[UUID, str] = {}

    def _run(self, coro: Coroutine[Any, Any, Any]) -> Any:
        return self.loop.run_until_complete(coro)

    # -- rules ------------------------------------------------------------------------------

    @rule(target=incident_ids, service=st.sampled_from(SERVICES), code=st.sampled_from(CODES))
    def alert(self, service: str, code: str) -> UUID:
        """A new alert, or a duplicate of one whose incident is still active."""
        resp = self._run(
            self.client.post("/webhooks/alerts", json={"service_name": service, "error_code": code, "summary": "x"})
        )
        assert resp.status_code in (200, 202), resp.text
        return UUID(resp.json()["incident_id"])

    @rule(incident=incident_ids, choice=st.sampled_from(("1", "2")))
    def reply_valid(self, incident: UUID, choice: str) -> None:
        """A well-formed reply for a known incident, whatever state it is in by now."""
        row = self._run(self.repo.get(incident))
        assert row is not None
        self._reply(f"{row.token}-{choice}")

    @rule(body=st.sampled_from(NOISE))
    def reply_noise(self, body: str) -> None:
        self._reply(body)

    def _reply(self, body: str) -> None:
        async def go() -> None:
            background = BackgroundTasks()
            await _handle_reply(self.services, background, body)
            await background()

        self._run(go())

    @rule()
    def crash(self) -> None:
        """The next graph run (triage or approval resume) is lost, like a killed worker."""
        self.graph.crash_next = True

    @rule()
    def page_failure(self) -> None:
        """The next SMS the graph sends (the page, or a confirmation) fails."""
        self.sms.fail_next += 1

    @rule()
    def tick(self) -> None:
        self._run(self.services.lifecycle.tick())
        self._check_bounded_staleness()

    @rule(seconds=st.sampled_from(ADVANCES))
    def advance(self, seconds: int) -> None:
        self.clock.advance(seconds)

    # -- invariants -------------------------------------------------------------------------

    def _rows(self) -> list[Any]:
        return list(self._run(self.repo.list_recent(limit=100_000)))

    @invariant()
    def resolved_needs_all_four_gates(self) -> None:
        for row in self._rows():
            if row.state == "RESOLVED":
                gates = self.repo._gates.get(row.incident_id, {})
                assert all(gates.get(name) is True for name in ALL_GATES), (row.incident_id, gates)

    @invariant()
    def at_most_one_execution_per_incident(self) -> None:
        assert all(count <= 1 for count in self.graph.resumes.values()), dict(self.graph.resumes)
        assert self.runbooks.executions <= sum(self.graph.resumes.values())

    @invariant()
    def terminal_states_are_absorbing(self) -> None:
        for row in self._rows():
            before = self.terminal_seen.get(row.incident_id)
            assert before is None or row.state == before, (row.incident_id, before, row.state)
            if row.state in TERMINAL_STATUSES:
                self.terminal_seen[row.incident_id] = row.state

    @invariant()
    def tokens_are_unique_among_active_incidents(self) -> None:
        tokens = [r.token for r in self._rows() if r.state in ACTIVE_STATUSES]
        assert len(tokens) == len(set(tokens)), tokens

    @invariant()
    def lock_is_held_exactly_while_active(self) -> None:
        holders = self._run(self._holders())
        active_by_fingerprint: dict[tuple[str, str], list[UUID]] = {}
        for row in self._rows():
            held_by = holders[(row.service_name, row.error_code)]
            if row.state in ACTIVE_STATUSES:
                active_by_fingerprint.setdefault((row.service_name, row.error_code), []).append(row.incident_id)
                assert held_by == row.incident_id, f"active {row.state} incident does not hold its lock"
            else:
                assert held_by != row.incident_id, f"{row.state} incident still holds its lock"
        assert all(len(ids) == 1 for ids in active_by_fingerprint.values())

    async def _holders(self) -> dict[tuple[str, str], UUID | None]:
        """Who holds each fingerprint, probed through the public port (probe lock released at once)."""
        result: dict[tuple[str, str], UUID | None] = {}
        for service in SERVICES:
            for code in CODES:
                probe = uuid4()
                outcome = await self.services.dedup.acquire(service, code, probe)
                if isinstance(outcome, Acquired):
                    await self.services.dedup.release(service, code, probe)
                    result[(service, code)] = None
                else:
                    result[(service, code)] = outcome.incident_id
        return result

    def _check_bounded_staleness(self) -> None:
        now = self.clock()
        limits = {"AWAITING_APPROVAL": APPROVAL_TTL, "TRIAGING": TRIAGE_TIMEOUT, "EXECUTING": EXECUTING_TIMEOUT}
        for row in self._rows():
            limit = limits.get(row.state)
            if limit is not None:
                age = (now - row.updated_at).total_seconds()
                assert age < limit, f"{row.state} incident survived a tick at age {age}s (limit {limit}s)"

    # -- termination ------------------------------------------------------------------------

    def teardown(self) -> None:
        try:
            self.graph.crash_next = False
            self.sms.fail_next = 0
            for _ in range(2):  # a resumed triage may need a second window to reach a terminal state
                self.clock.advance(MAX_TIMEOUT + 1)
                self._run(self.services.lifecycle.tick())
            stuck = [(r.incident_id, r.state) for r in self._rows() if r.state not in TERMINAL_STATUSES]
            assert not stuck, f"non-terminal after the maximum timeout and two ticks: {stuck}"
            self.lock_is_held_exactly_while_active()
            self._run(self.client.aclose())
        finally:
            self.loop.close()


STATEFUL_SETTINGS = settings(max_examples=200, stateful_step_count=30, deadline=None)
LifecycleMachine.TestCase.settings = STATEFUL_SETTINGS
TestLifecycleStateMachine = LifecycleMachine.TestCase


# ---------------------------------------------------------------------------
# Meta: the machine must notice a lifecycle without its sweeps
# ---------------------------------------------------------------------------


async def _noop(*args: Any, **kwargs: Any) -> int:
    return 0


@pytest.mark.parametrize("method", ["tick", "reap_once", "sweep_inflight"])
def test_meta_state_machine_fails_without_the_reaper_sweeps(monkeypatch: pytest.MonkeyPatch, method: str) -> None:
    monkeypatch.setattr(Lifecycle, method, _noop)
    quick = settings(
        max_examples=60,
        stateful_step_count=30,
        deadline=None,
        database=None,
        phases=(Phase.generate,),
        report_multiple_bugs=False,
        suppress_health_check=list(HealthCheck),
    )
    with pytest.raises(AssertionError):
        run_state_machine_as_test(LifecycleMachine, settings=quick)
