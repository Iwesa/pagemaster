"""LangGraph incident state machine for Pagemaster.

Flow::

    triage_worker -> supervisor_formatter -> dispatch_pager
        -> human_approval_gate (interrupt) -> tripwire_guard
        -> remediation_executor -> END          (tripwire passed)
                                -> END          (BLOCKED_BY_TRIPWIRE)

Domain code only: all I/O goes through the typed ports in
:mod:`backend.app.agents.ports`. ``AsyncPostgresSaver`` is imported lazily in
:func:`compile_with_postgres`; tests pass a ``MemorySaver`` to
:func:`build_graph`.

Requirements: 2.1, 2.3, 3.1, 3.3, 4.1, 4.4, 5.1-5.5.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any, Final, Literal, TypedDict
from uuid import UUID

from langgraph.checkpoint.base import BaseCheckpointSaver
from langgraph.graph import END, START, StateGraph
from langgraph.graph.state import CompiledStateGraph
from langgraph.types import interrupt

from backend.app.agents.ports import Ports, Runbook
from backend.app.services.guardrails import (
    AuditEvent,
    AuditLogger,
    AuditRecord,
    ResolutionGates,
    TripwireValidator,
    can_resolve,
    format_pager_payload,
    sanitize_pager_text,
)

logger = logging.getLogger("pagemaster.agents.graph")

TELEMETRY_TIMEOUT_SECONDS: Final[float] = 5.0
RUNBOOK_LOOKUP_TIMEOUT_SECONDS: Final[float] = 5.0
REASON_LOOKUP_FAILED: Final[str] = "runbook_lookup_failed"

IncidentStatus = Literal["TRIAGING", "AWAITING_APPROVAL", "EXECUTING", "RESOLVED", "BLOCKED_BY_TRIPWIRE"]
Confidence = Literal["HIGH", "DEGRADED"]

# Extra audit events emitted by the graph (free-form ``event_type`` strings).
EVENT_PAGER_SENT: Final[str] = "PAGER_SENT"
EVENT_APPROVAL_RECEIVED: Final[str] = "APPROVAL_RECEIVED"
EVENT_REMEDIATION_EXECUTED: Final[str] = "REMEDIATION_EXECUTED"
EVENT_REMEDIATION_FAILED: Final[str] = "REMEDIATION_FAILED"
EVENT_INCIDENT_RESOLVED: Final[str] = "INCIDENT_RESOLVED"
UNKNOWN_ACTION: Final[str] = "UNKNOWN"


class IncidentState(TypedDict, total=False):
    """Checkpointed graph state. Values are JSON-friendly for any checkpointer."""

    # Inputs (set when the run starts).
    incident_id: str  # UUID text
    token: str  # 2 uppercase alphanumerics
    service_name: str
    error_code: str
    alert_summary: str
    # Progress.
    status: IncidentStatus
    confidence: Confidence
    root_cause: str
    runbooks: list[dict[str, str]]  # Runbook.model_dump()
    pager_text: str
    choice: Literal["1", "2"] | None
    action_id: str
    target_host: str
    gates: dict[str, bool | None]  # ResolutionGates fields
    audit_records: list[dict[str, Any]]  # AuditRecord.model_dump(mode="json")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class _Audit:
    """Appends to the incident's hash chain and persists each record via the port."""

    def __init__(self, state: IncidentState, ports: Ports) -> None:
        records = [AuditRecord.model_validate(r) for r in state.get("audit_records", [])]
        self._logger = AuditLogger(UUID(state["incident_id"]), records)
        self._ports = ports

    async def emit(self, event: str, payload: dict[str, Any] | None = None) -> bool:
        """Append and persist. Returns True iff the record was durably committed."""
        record = self._logger.append(event, payload)
        try:
            await self._ports.audit.commit(record)
        except Exception:
            logger.exception("audit commit failed for %s", event)
            return False
        return True

    def dump(self) -> list[dict[str, Any]]:
        return [r.model_dump(mode="json") for r in self._logger.records]


def _runbooks(state: IncidentState) -> list[Runbook]:
    return [Runbook.model_validate(r) for r in state.get("runbooks", [])]


async def _safe_send(ports: Ports, text: str) -> bool:
    try:
        await ports.sms.send(text)
    except Exception:
        logger.exception("sms send failed")
        return False
    return True


# ---------------------------------------------------------------------------
# Graph factory
# ---------------------------------------------------------------------------


def build_graph(
    ports: Ports, checkpointer: BaseCheckpointSaver[Any]
) -> CompiledStateGraph[IncidentState, None, IncidentState, IncidentState]:
    """Build and compile the incident graph with injected ports and checkpointer."""

    async def triage_worker(state: IncidentState) -> dict[str, Any]:
        service = state["service_name"]
        confidence: Confidence = "HIGH"
        root_cause = state.get("alert_summary", "")
        runbooks: list[Runbook] = []
        try:
            ctx = await asyncio.wait_for(
                ports.telemetry.get_incident_context(service), TELEMETRY_TIMEOUT_SECONDS
            )
            confidence = ctx.confidence
            # DEGRADED telemetry carries no real cause: keep the alert's own summary.
            if confidence == "HIGH":
                root_cause = ctx.root_cause or root_cause
            else:
                root_cause = root_cause or ctx.root_cause
            runbooks = list(ctx.runbooks)
        except Exception:  # includes TimeoutError; Req 2.3: never crash the workflow
            logger.warning("telemetry unavailable for %s; degrading", service)
            confidence = "DEGRADED"
        if not runbooks:
            try:
                runbooks = list(await ports.runbooks.list_approved(service))
            except Exception:
                logger.warning("runbook lookup failed for %s", service)
        return {
            "status": "TRIAGING",
            "confidence": confidence,
            "root_cause": root_cause,
            "runbooks": [r.model_dump() for r in runbooks],
        }

    async def supervisor_formatter(state: IncidentState) -> dict[str, Any]:
        service = state["service_name"]
        root_cause = state.get("root_cause", "")
        summary = root_cause
        if ports.summarizer is not None:
            try:
                summary = await ports.summarizer.summarize(service, root_cause)
            except Exception:
                logger.warning("summarizer failed; using deterministic summary")
        if state.get("confidence") == "DEGRADED":
            summary = f"[DEGRADED] {summary}"
        books = _runbooks(state)
        payload = format_pager_payload(
            state["token"],
            service,
            summary,
            books[0].title if len(books) > 0 else None,
            books[1].title if len(books) > 1 else None,
        )
        audit = _Audit(state, ports)
        if payload.audit_event is not None:  # Req 3.3
            await audit.emit(
                payload.audit_event, {"reasons": [str(r) for r in payload.reasons]}
            )
        return {"pager_text": payload.text, "audit_records": audit.dump()}

    async def dispatch_pager(state: IncidentState) -> dict[str, Any]:
        audit = _Audit(state, ports)
        sent = await _safe_send(ports, state["pager_text"])
        await audit.emit(EVENT_PAGER_SENT, {"token": state["token"], "sent": sent})
        # Req 4.1: transition to AWAITING_APPROVAL; checkpoint is written by the saver.
        return {"status": "AWAITING_APPROVAL", "audit_records": audit.dump()}

    async def human_approval_gate(state: IncidentState) -> dict[str, Any]:
        resume: object = interrupt({"status": "AWAITING_APPROVAL", "token": state["token"]})
        raw = resume.get("choice") if isinstance(resume, dict) else None
        choice: Literal["1", "2"] | None = "1" if raw == "1" else "2" if raw == "2" else None
        runbooks = _runbooks(state)
        selected = runbooks[int(choice) - 1] if choice and int(choice) <= len(runbooks) else None
        audit = _Audit(state, ports)
        await audit.emit(
            EVENT_APPROVAL_RECEIVED,
            {"token": state["token"], "choice": choice or "invalid"},
        )
        return {
            "status": "EXECUTING",
            "choice": choice,
            "action_id": selected.action_id if selected else UNKNOWN_ACTION,
            "target_host": "",  # set by tripwire_guard from a fresh runbook lookup
            "audit_records": audit.dump(),
        }

    async def tripwire_guard(state: IncidentState) -> dict[str, Any]:
        # Authorization is re-queried now (no TOCTOU): state only maps the reply
        # digit to an action id; approval and target host come from the fresh record.
        service = state["service_name"]
        action_id = state.get("action_id", UNKNOWN_ACTION)
        audit = _Audit(state, ports)
        update: dict[str, Any] = {}
        try:
            fresh = list(
                await asyncio.wait_for(
                    ports.runbooks.list_approved(service), RUNBOOK_LOOKUP_TIMEOUT_SECONDS
                )
            )
        except Exception:  # includes TimeoutError: fail closed
            logger.warning("runbook lookup failed for %s at execution time", service)
            await audit.emit(
                AuditEvent.TRIPWIRE_BLOCKED,
                {"action_id": action_id, "token": state["token"], "reason": REASON_LOOKUP_FAILED},
            )
            passed = False
        else:
            matches = [r for r in fresh if r.action_id == action_id]
            chosen = next((r for r in matches if r.target_host == service), None) or (
                matches[0] if matches else None
            )
            result = TripwireValidator(r.action_id for r in fresh).validate(
                # No fresh record => not approved; use the service so the reason is
                # action_not_approved rather than a bogus host mismatch.
                target_host=chosen.target_host if chosen is not None else service,
                service_name=service,
                action_id=action_id,
                token=state["token"],
            )
            await audit.emit(result.audit_event(), result.audit_payload())
            passed = result.passed
            if passed and chosen is not None:
                update["target_host"] = chosen.target_host
        gates = ResolutionGates(tripwire_check_passed=passed)
        update["gates"] = gates.model_dump()
        if not passed:
            update["status"] = "BLOCKED_BY_TRIPWIRE"
            await _safe_send(  # alert operator; no execution follows
                ports, sanitize_pager_text(f"INC-{state['token']} BLOCKED_BY_TRIPWIRE")
            )
        update["audit_records"] = audit.dump()
        return update

    async def remediation_executor(state: IncidentState) -> dict[str, Any]:
        token = state["token"]
        audit = _Audit(state, ports)
        executed = False
        try:
            executed = await ports.runbooks.execute(
                target_host=state["target_host"], action_id=state["action_id"], token=token
            )
        except Exception:
            logger.exception("remediation step failed")
        sms_sent = False
        committed = False
        if executed:
            await audit.emit(
                EVENT_REMEDIATION_EXECUTED,
                {"action_id": state["action_id"], "target_host": state["target_host"]},
            )
            sms_sent = await _safe_send(ports, f"INC-{token} RESOLVED")
            committed = await audit.emit(EVENT_INCIDENT_RESOLVED, {"token": token})
        else:
            await audit.emit(EVENT_REMEDIATION_FAILED, {"action_id": state["action_id"]})
        gates = ResolutionGates(
            tripwire_check_passed=True,
            simulated_step_executed=executed,
            confirmation_sms_sent=sms_sent,
            audit_record_committed=committed,
        )
        status: IncidentStatus = "RESOLVED" if can_resolve(gates) else "EXECUTING"
        return {"status": status, "gates": gates.model_dump(), "audit_records": audit.dump()}

    def route_after_tripwire(state: IncidentState) -> Literal["remediation_executor", "__end__"]:
        gates = state.get("gates", {})
        return "remediation_executor" if gates.get("tripwire_check_passed") is True else "__end__"

    builder: StateGraph[IncidentState, None, IncidentState, IncidentState] = StateGraph(
        IncidentState
    )
    builder.add_node("triage_worker", triage_worker)
    builder.add_node("supervisor_formatter", supervisor_formatter)
    builder.add_node("dispatch_pager", dispatch_pager)
    builder.add_node("human_approval_gate", human_approval_gate)
    builder.add_node("tripwire_guard", tripwire_guard)
    builder.add_node("remediation_executor", remediation_executor)
    builder.add_edge(START, "triage_worker")
    builder.add_edge("triage_worker", "supervisor_formatter")
    builder.add_edge("supervisor_formatter", "dispatch_pager")
    builder.add_edge("dispatch_pager", "human_approval_gate")
    builder.add_edge("human_approval_gate", "tripwire_guard")
    builder.add_conditional_edges("tripwire_guard", route_after_tripwire)
    builder.add_edge("remediation_executor", END)
    return builder.compile(checkpointer=checkpointer)


@asynccontextmanager
async def compile_with_postgres(
    conn_string: str, ports: Ports
) -> AsyncIterator[CompiledStateGraph[IncidentState, None, IncidentState, IncidentState]]:
    """Compile the graph with an ``AsyncPostgresSaver`` (Req 4.1 durable checkpoints)."""
    from langgraph.checkpoint.postgres.aio import AsyncPostgresSaver  # lazy: keeps imports light

    async with AsyncPostgresSaver.from_conn_string(conn_string) as saver:
        await saver.setup()
        yield build_graph(ports, saver)
