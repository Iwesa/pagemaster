"""Periodic in-flight sweep, failure/expiry notifications and EXPIRED replies (Req 6.8 to 6.11)."""

from __future__ import annotations

from dataclasses import replace
from typing import Any
from uuid import UUID

import pytest

from backend.app.api.routes import AppServices
from backend.app.main import Settings, _parse_timeout_seconds
from backend.app.services.sms_common import validate_outbound
from backend.tests.test_expiry import (
    TTL,
    RecordingGraph,
    add_incident,
    events_of,
    fingerprint_free,
    make_services,
    outbox,
    reply,
    state_of,
)

TIMEOUT = 120


class _Snapshot:
    def __init__(self, values: dict[str, Any], next_: tuple[str, ...]) -> None:
        self.values = values
        self.next = next_


class CheckpointGraph(RecordingGraph):
    """A graph with an ``aget_state`` view; ``resume`` calls are ``ainvoke(None, ...)``."""

    def __init__(self, snapshot: _Snapshot, result: Any = None, error: Exception | None = None) -> None:
        super().__init__()
        self.snapshot = snapshot
        self.result = result
        self.error = error

    async def aget_state(self, config: Any) -> _Snapshot:
        return self.snapshot

    async def ainvoke(self, input: Any, config: Any = None) -> Any:
        self.calls.append(input)
        if self.error is not None:
            raise self.error
        return self.result


def _with(services: AppServices, **changes: Any) -> AppServices:
    return replace(services, triage_timeout_seconds=TIMEOUT, executing_timeout_seconds=TIMEOUT, **changes)


def test_timeout_settings_parse_and_clamp() -> None:
    assert _parse_timeout_seconds("X", None) == 120
    assert _parse_timeout_seconds("X", "300") == 300
    assert _parse_timeout_seconds("X", "3") == 10
    assert _parse_timeout_seconds("X", "abc") == 120
    cfg = Settings.from_env({"TRIAGE_TIMEOUT_SECONDS": "5", "EXECUTING_TIMEOUT_SECONDS": "45"})
    assert (cfg.triage_timeout_seconds, cfg.executing_timeout_seconds) == (10, 45)
    assert Settings.from_env({}).triage_timeout_seconds == 120


async def test_stale_triaging_without_checkpoint_fails_and_notifies() -> None:
    services, clock, graph = make_services()
    services = _with(services)
    incident = await add_incident(services, "TRIAGING")
    clock.advance(TIMEOUT + 1)
    assert await services.lifecycle.sweep_inflight() == 1
    assert await state_of(services, incident.incident_id) == "FAILED"
    records = await services.audit.records(incident.incident_id)
    failed = [r for r in records if r.event_type == "INCIDENT_FAILED"]
    assert [r.payload for r in failed] == [{"reason": "recovered_after_crash"}]
    assert await fingerprint_free(services)  # a re-fired alert is accepted again
    assert outbox(services) == ["INC-7A FAILED. Re-send the alert."]
    validate_outbound(outbox(services)[0])
    assert graph.calls == []


async def test_fresh_inflight_incidents_are_untouched() -> None:
    services, clock, _ = make_services()
    services = _with(services)
    triaging = await add_incident(services, "TRIAGING", token="AA", code="E1")
    executing = await add_incident(services, "EXECUTING", token="BB", code="E2")
    clock.advance(TIMEOUT - 1)
    assert await services.lifecycle.sweep_inflight() == 0
    assert await state_of(services, triaging.incident_id) == "TRIAGING"
    assert await state_of(services, executing.incident_id) == "EXECUTING"
    assert outbox(services) == []


async def test_stale_executing_fails_without_rerunning_remediation() -> None:
    services, clock, graph = make_services()
    services = _with(services)
    incident = await add_incident(services, "EXECUTING")
    clock.advance(TIMEOUT + 1)
    assert await services.lifecycle.sweep_inflight() == 1
    assert await state_of(services, incident.incident_id) == "FAILED"
    failed = [r for r in await services.audit.records(incident.incident_id) if r.event_type == "INCIDENT_FAILED"]
    assert [r.payload for r in failed] == [{"reason": "execution_timeout"}]
    assert graph.calls == []  # never resumed
    assert await fingerprint_free(services)
    assert outbox(services) == ["INC-7A FAILED. Re-send the alert."]


async def test_stale_triaging_resumes_from_checkpoint() -> None:
    services, clock, _ = make_services()
    graph = CheckpointGraph(
        _Snapshot({"incident_id": "x"}, ("dispatch_pager",)), result={"status": "AWAITING_APPROVAL"}
    )
    services = _with(services, graph=graph)
    incident = await add_incident(services, "TRIAGING")
    clock.advance(TIMEOUT + 1)
    assert await services.lifecycle.sweep_inflight() == 0
    assert graph.calls == [None]  # resume = ainvoke(None, thread config)
    assert await state_of(services, incident.incident_id) == "AWAITING_APPROVAL"
    assert outbox(services) == []
    assert "INCIDENT_FAILED" not in await events_of(services, incident.incident_id)


async def test_resume_error_or_empty_checkpoint_fails_incident() -> None:
    for graph in (
        CheckpointGraph(_Snapshot({"a": 1}, ("n",)), error=RuntimeError("boom")),
        CheckpointGraph(_Snapshot({}, ())),
    ):
        services, clock, _ = make_services()
        services = _with(services, graph=graph)
        incident = await add_incident(services, "TRIAGING")
        clock.advance(TIMEOUT + 1)
        assert await services.lifecycle.sweep_inflight() == 1
        assert await state_of(services, incident.incident_id) == "FAILED"
        assert outbox(services) == ["INC-7A FAILED. Re-send the alert."]


async def test_reaper_tick_runs_expiry_and_sweep() -> None:
    services, clock, _ = make_services()
    services = _with(services)
    awaiting = await add_incident(services, "AWAITING_APPROVAL", token="AA", code="E1")
    executing = await add_incident(services, "EXECUTING", token="BB", code="E2")
    clock.advance(TTL + 1)
    await services.lifecycle.tick()
    assert await state_of(services, awaiting.incident_id) == "EXPIRED"
    assert await state_of(services, executing.incident_id) == "FAILED"
    assert sorted(outbox(services)) == ["INC-AA EXPIRED. No action taken.", "INC-BB FAILED. Re-send the alert."]
    assert await services.lifecycle.sweep_inflight() == 0  # idempotent


async def test_reply_to_expired_incident_answers_and_mutates_nothing() -> None:
    services, clock, graph = make_services()
    incident = await add_incident(services, "AWAITING_APPROVAL")
    clock.advance(TTL + 1)
    assert await services.lifecycle.reap_once() == 1
    before = await services.audit.records(incident.incident_id)
    sent_before = len(outbox(services))
    await reply(services, "7A-1")
    assert outbox(services)[sent_before:] == ["INC-7A expired. No action taken."]
    validate_outbound(outbox(services)[-1])
    assert await state_of(services, incident.incident_id) == "EXPIRED"
    assert await services.audit.records(incident.incident_id) == before
    assert graph.calls == []


async def test_reply_to_unknown_token_still_says_no_longer_active() -> None:
    services, _, _ = make_services()
    await reply(services, "ZZ-1")
    assert outbox(services) == ["INC-ZZ no longer active. No action taken."]


async def test_reply_wins_race_against_sweep() -> None:
    """A reply that claimed AWAITING_APPROVAL -> EXECUTING refreshes updated_at: the sweep leaves it."""
    services, clock, graph = make_services()
    services = _with(services)
    incident = await add_incident(services, "AWAITING_APPROVAL")
    clock.advance(TTL - 1)
    await reply(services, "7A-1")
    assert graph.calls and await state_of(services, incident.incident_id) == "RESOLVED"
    clock.advance(TIMEOUT + 1)
    assert await services.lifecycle.sweep_inflight() == 0
    assert await state_of(services, incident.incident_id) == "RESOLVED"


async def test_sweep_loses_cas_when_state_moves_first() -> None:
    services, clock, _ = make_services()
    services = _with(services)
    incident = await add_incident(services, "TRIAGING")
    clock.advance(TIMEOUT + 1)
    claimed = await services.incidents.renew_stale_triaging(TIMEOUT)
    assert [c.incident_id for c in claimed] == [incident.incident_id]
    # The graph reaches the approval gate between the claim and the failure CAS.
    assert await services.incidents.compare_and_set_state(incident.incident_id, "TRIAGING", "AWAITING_APPROVAL")
    assert not await services.incidents.compare_and_set_state(incident.incident_id, "TRIAGING", "FAILED")
    assert await state_of(services, incident.incident_id) == "AWAITING_APPROVAL"


async def test_reconcile_orphans_notifies_failed() -> None:
    services, clock, _ = make_services()
    services = _with(services, inflight_stale_seconds=60)
    incident: Any = await add_incident(services, "EXECUTING")
    clock.advance(61)
    assert await services.lifecycle.reconcile_orphans() == 1
    assert await state_of(services, UUID(str(incident.incident_id))) == "FAILED"
    assert outbox(services) == ["INC-7A FAILED. Re-send the alert."]


@pytest.mark.parametrize("state", ["TRIAGING", "EXECUTING"])
async def test_failure_audit_payload_has_no_token(state: Any) -> None:
    services, clock, _ = make_services()
    services = _with(services)
    incident = await add_incident(services, state)
    clock.advance(TIMEOUT + 1)
    await services.lifecycle.sweep_inflight()
    payloads = [r.payload for r in await services.audit.records(incident.incident_id)]
    assert all("7A" not in str(p) and "token" not in p for p in payloads)
