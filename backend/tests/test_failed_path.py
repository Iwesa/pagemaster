"""FAILED lifecycle (Req 5.6) and ``record_resolution`` on the in-memory adapters."""

from __future__ import annotations

from dataclasses import replace
from typing import Any
from uuid import UUID, uuid4

import pytest

from backend.app.api.routes import AppServices, _run_workflow
from backend.app.main import Settings, build_in_memory_services
from backend.app.services.dedup import Acquired, Duplicate
from backend.app.services.guardrails import ResolutionGates
from backend.app.services.incident_store import (
    ACTIVE_STATUSES,
    TERMINAL_STATUSES,
    IncidentRecord,
)

SERVICE = "auth-db"
CODE = "E1"
ALL_TRUE = {
    "tripwire_check_passed": True,
    "simulated_step_executed": True,
    "confirmation_sms_sent": True,
    "audit_record_committed": True,
}


class StubGraph:
    """Returns a canned result or raises; stands in for the compiled LangGraph."""

    def __init__(self, result: Any = None, error: Exception | None = None) -> None:
        self._result = result
        self._error = error

    async def ainvoke(self, input: Any, config: Any = None) -> Any:
        if self._error is not None:
            raise self._error
        return self._result


async def run_stub(result: Any = None, error: Exception | None = None) -> tuple[AppServices, IncidentRecord]:
    """Create an active incident holding the fingerprint, then run ``_run_workflow`` on it."""
    base = build_in_memory_services(Settings(use_in_memory=True))
    services = replace(base, graph=StubGraph(result, error))
    incident_id = uuid4()
    assert isinstance(await services.dedup.acquire(SERVICE, CODE, incident_id), Acquired)
    incident = await services.incidents.create(
        incident_id=incident_id, token="7A", service_name=SERVICE, error_code=CODE, raw_alert={}
    )
    await services.audit.append_event(incident_id, "INCIDENT_CREATED", {})
    await _run_workflow(services, incident, {})
    return services, incident


async def fingerprint_free(services: AppServices) -> bool:
    probe = await services.dedup.acquire(SERVICE, CODE, uuid4())
    return not isinstance(probe, Duplicate)


async def test_executor_partial_failure_moves_to_failed_and_frees_lock() -> None:
    gates = {**ALL_TRUE, "confirmation_sms_sent": False}
    services, incident = await run_stub({"status": "EXECUTING", "gates": gates})
    row = await services.incidents.get(incident.incident_id)
    assert row is not None and row.state == "FAILED"
    events = [r.event_type for r in await services.audit.records(incident.incident_id)]
    assert events[-1] == "INCIDENT_FAILED"
    assert await fingerprint_free(services)


async def test_unhandled_exception_moves_to_failed_and_frees_lock() -> None:
    services, incident = await run_stub(error=RuntimeError("boom"))
    row = await services.incidents.get(incident.incident_id)
    assert row is not None and row.state == "FAILED"
    events = [r.event_type for r in await services.audit.records(incident.incident_id)]
    assert events[-1] == "WORKFLOW_ERROR"
    assert await fingerprint_free(services)


async def test_resolved_with_missing_gate_is_never_written() -> None:
    gates = {**ALL_TRUE, "audit_record_committed": None}
    services, incident = await run_stub({"status": "RESOLVED", "gates": gates})
    row = await services.incidents.get(incident.incident_id)
    assert row is not None and row.state == "FAILED"


async def test_resolved_with_all_gates_is_recorded_and_frees_lock() -> None:
    services, incident = await run_stub({"status": "RESOLVED", "gates": ALL_TRUE})
    row = await services.incidents.get(incident.incident_id)
    assert row is not None and row.state == "RESOLVED"
    assert await fingerprint_free(services)


async def test_failed_incident_frees_fingerprint_for_a_new_incident() -> None:
    services, incident = await run_stub(error=RuntimeError("boom"))
    again = await services.incidents.create(
        incident_id=uuid4(), token="7A", service_name=SERVICE, error_code=CODE, raw_alert={}
    )
    assert again.incident_id != incident.incident_id


async def test_in_memory_record_resolution_rejects_resolved_without_all_gates() -> None:
    repo = build_in_memory_services(Settings(use_in_memory=True)).incidents
    incident_id: UUID = uuid4()
    await repo.create(incident_id=incident_id, token="B3", service_name=SERVICE, error_code=CODE, raw_alert={})
    with pytest.raises(ValueError):
        await repo.record_resolution(incident_id, "RESOLVED", ResolutionGates(tripwire_check_passed=True))
    # Gates persist across calls (COALESCE semantics): earlier True flags survive later None.
    await repo.record_resolution(incident_id, "EXECUTING", ResolutionGates(tripwire_check_passed=True))
    full = ResolutionGates(
        simulated_step_executed=True, confirmation_sms_sent=True, audit_record_committed=True
    )
    assert await repo.record_resolution(incident_id, "RESOLVED", full)
    assert await repo.record_resolution(uuid4(), "FAILED", None) is False


def test_failed_is_terminal_not_active() -> None:
    assert "FAILED" in TERMINAL_STATUSES and "FAILED" not in ACTIVE_STATUSES
