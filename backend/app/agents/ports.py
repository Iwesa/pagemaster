"""Typed port interfaces for the incident graph (hexagonal boundary).

Adapters (MCP client, Africa's Talking/mock SMS, Postgres audit store, runbook store)
live outside ``backend/app/agents/`` and are injected via ``build_graph``.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Literal, Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict

from backend.app.services.guardrails import AuditRecord


class Runbook(BaseModel):
    """An approved remediation option (a row of ``v_approved_runbooks``)."""

    model_config = ConfigDict(frozen=True, strict=True)

    action_id: str
    title: str
    target_host: str


class TelemetryContext(BaseModel):
    """Result of read-only triage telemetry (Req 2.1)."""

    model_config = ConfigDict(frozen=True, strict=True)

    confidence: Literal["HIGH", "DEGRADED"] = "HIGH"
    root_cause: str
    runbooks: tuple[Runbook, ...] = ()


@runtime_checkable
class TelemetryPort(Protocol):
    """Read-only telemetry. May raise or time out; the graph degrades (Req 2.3)."""

    async def get_incident_context(self, service_name: str) -> TelemetryContext: ...


@runtime_checkable
class SummarizerPort(Protocol):
    """Optional LLM boundary; output is always clamped by ``format_pager_payload``."""

    async def summarize(self, service_name: str, root_cause: str) -> str: ...


@runtime_checkable
class SmsPort(Protocol):
    """Outbound pager/confirmation SMS."""

    async def send(self, text: str) -> None: ...


PageDecision = Literal["SEND", "COALESCED"]


@runtime_checkable
class PageGate(Protocol):
    """Page rate gate (Req 10.3). Decides whether an incident's own page may go out now.

    ``"SEND"``: the caller sends the individual page. ``"COALESCED"``: the gate has taken
    ownership of the incident (it will appear in a later summary page) and the caller must
    not send an individual page. Each call is decided exactly once.
    """

    async def admit(self, *, token: str, service_name: str, actionable: bool) -> PageDecision: ...


@runtime_checkable
class AuditPort(Protocol):
    """Durably persists one hash-chained audit record. Raises on failure."""

    async def commit(self, record: AuditRecord) -> None: ...


@runtime_checkable
class RunbookPort(Protocol):
    """Approved runbooks and (simulated) remediation execution."""

    async def list_approved(self, service_name: str) -> Sequence[Runbook]: ...

    async def execute(self, *, target_host: str, action_id: str, token: str) -> bool: ...


@dataclass(frozen=True, slots=True)
class Ports:
    """Bundle of injected adapters."""

    telemetry: TelemetryPort
    sms: SmsPort
    audit: AuditPort
    runbooks: RunbookPort
    summarizer: SummarizerPort | None = None
    page_gate: PageGate | None = None
