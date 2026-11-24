"""Background workflow execution: run/resume the graph and sync incident state and dedup lock.

Imported by the alert webhook, the reply handler and ``AppServices`` (reaper resume).
``AppServices`` is only referenced for typing, so there is no import cycle.

Requirements: 3.5, 5.4, 5.5, 5.6, 6.8, 8.4.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any, Final, cast
from uuid import UUID

from langchain_core.runnables import RunnableConfig

from backend.app.agents.graph import REASON_PAGER_UNDELIVERABLE
from backend.app.services.dedup import release_on_terminal
from backend.app.services.guardrails import ResolutionGates, can_resolve
from backend.app.services.incident_store import ALL_STATUSES, IncidentRecord, IncidentStatus

if TYPE_CHECKING:
    from backend.app.api.app_services import AppServices

__all__ = [
    "EVENT_INCIDENT_FAILED",
    "EVENT_INCIDENT_NO_ACTION",
    "EVENT_WORKFLOW_ERROR",
    "REASON_NO_APPROVED_RUNBOOK",
    "fail_incident",
    "resume_triage",
    "run_workflow",
]

logger = logging.getLogger("pagemaster.api")

EVENT_WORKFLOW_ERROR: Final[str] = "WORKFLOW_ERROR"
EVENT_INCIDENT_FAILED: Final[str] = "INCIDENT_FAILED"
EVENT_INCIDENT_NO_ACTION: Final[str] = "INCIDENT_NO_ACTION"
REASON_NO_APPROVED_RUNBOOK: Final[str] = "no_approved_runbook"


def _thread_config(incident_id: UUID) -> RunnableConfig:
    return {"configurable": {"thread_id": str(incident_id)}}


async def run_workflow(services: AppServices, incident: IncidentRecord, graph_input: Any) -> None:
    """Run or resume the graph, then sync incident state and dedup lock. Never raises."""
    try:
        result = await services.graph.ainvoke(graph_input, _thread_config(incident.incident_id))
        await _apply_result(services, incident, result)
    except Exception:
        logger.exception("workflow failed for incident %s", incident.incident_id)
        await fail_incident(services, incident, "workflow_exception", None)


async def _apply_result(services: AppServices, incident: IncidentRecord, result: Any) -> None:
    """Sync the incident row and dedup lock with a graph result."""
    status = result.get("status") if isinstance(result, dict) else None
    if not (isinstance(status, str) and status in ALL_STATUSES):
        return
    gates = _gates_from_result(result)
    new_status = cast(IncidentStatus, status)
    coalesced = isinstance(result, dict) and result.get("pager_coalesced") is True
    if new_status == "AWAITING_APPROVAL" and not coalesced:  # the page went out (Req 8.4)
        services.health.record_page_success()  # a withheld page (Req 10.3) proves nothing
    elif new_status == "FAILED":
        reason = result.get("failure_reason") if isinstance(result, dict) else None
        if reason == REASON_PAGER_UNDELIVERABLE:
            services.health.record_page_failure()
        await fail_incident(
            services, incident, reason if isinstance(reason, str) else "workflow_failed", gates
        )
        return
    # The graph ends in EXECUTING only when the executor ran but a gate is false.
    # RESOLVED is never written unless all four gates are true (Req 5.4, 5.5, 5.6).
    if new_status == "EXECUTING" or (new_status == "RESOLVED" and not can_resolve(gates)):
        await fail_incident(services, incident, "remediation_incomplete", gates)
        return
    option_count: int | None = None
    if new_status in ("AWAITING_APPROVAL", "NO_ACTION"):
        raw_count = result.get("option_count") if isinstance(result, dict) else None
        option_count = raw_count if isinstance(raw_count, int) and not isinstance(raw_count, bool) else None
        if new_status == "NO_ACTION":
            option_count = 0
    if new_status == "NO_ACTION":  # Req 3.5: audit before the state is terminal; no secrets in payload
        try:
            await services.audit.append_event(
                incident.incident_id, EVENT_INCIDENT_NO_ACTION, {"reason": REASON_NO_APPROVED_RUNBOOK}
            )
        except Exception:
            logger.exception("could not audit NO_ACTION for %s", incident.incident_id)
    await services.incidents.record_resolution(incident.incident_id, new_status, gates, option_count)
    await release_on_terminal(
        services.dedup, new_status, incident.service_name, incident.error_code, incident.incident_id
    )


async def resume_triage(services: AppServices, incident_id: UUID) -> bool:
    """Resume a stale TRIAGING incident from its checkpoint (Req 6.8).

    False when there is nothing to resume (no checkpoint, finished graph, row no longer
    TRIAGING). Exceptions from the graph propagate so the caller can fail the incident.
    """
    incident = await services.incidents.get(incident_id)
    if incident is None or incident.state != "TRIAGING":
        return False
    config = _thread_config(incident_id)
    get_state = getattr(services.graph, "aget_state", None)
    if get_state is None:
        return False
    snapshot = await get_state(config)
    if not getattr(snapshot, "values", None) or not getattr(snapshot, "next", ()):
        return False
    result = await services.graph.ainvoke(None, config)
    await _apply_result(services, incident, result)
    return True


def _gates_from_result(result: object) -> ResolutionGates:
    raw = result.get("gates") if isinstance(result, dict) else None
    if not isinstance(raw, dict):
        return ResolutionGates()
    return ResolutionGates.model_validate(
        {k: v for k, v in raw.items() if k in ResolutionGates.model_fields and isinstance(v, bool | None)}
    )


async def fail_incident(
    services: AppServices, incident: IncidentRecord, reason: str, gates: ResolutionGates | None
) -> None:
    """Req 5.6: audit, move to FAILED and free the fingerprint. Each step is isolated."""
    try:
        await services.audit.append_event(
            incident.incident_id,
            EVENT_WORKFLOW_ERROR if reason == "workflow_exception" else EVENT_INCIDENT_FAILED,
            {"token": incident.token, "reason": reason},
        )
    except Exception:
        logger.exception("could not record failure for %s", incident.incident_id)
    try:
        await services.incidents.record_resolution(incident.incident_id, "FAILED", gates)
    except Exception:
        logger.exception("could not mark %s FAILED", incident.incident_id)
    try:
        await release_on_terminal(
            services.dedup, "FAILED", incident.service_name, incident.error_code, incident.incident_id
        )
    except Exception:
        logger.exception("could not release lock for %s", incident.incident_id)
