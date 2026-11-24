"""Services injected into the HTTP layer (``app.state.services``) and the FastAPI dependency for them.

Requirements: 1.1, 1.2, 1.3, 4.2, 4.3, 4.5.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import datetime
from typing import Annotated, Any, Final, Protocol
from uuid import UUID

from fastapi import Depends, Request
from langchain_core.runnables import RunnableConfig
from pydantic import SecretStr

from backend.app.agents.ports import SmsPort
from backend.app.api.workflow import resume_triage
from backend.app.config import DEFAULT_DEDUP_AUDIT_SAMPLE, DEFAULT_MAX_ALERT_BODY_BYTES
from backend.app.services.dedup import DedupStore
from backend.app.services.health_state import HealthState
from backend.app.services.hint_limiter import HintLimiter, HintRateLimiter
from backend.app.services.incident_store import (
    DEFAULT_TOKEN_COOLDOWN_SECONDS,
    TOKEN_ALPHABET,
    AuditStore,
    IncidentRepository,
)
from backend.app.services.leader_lock import ReconcileLock
from backend.app.services.lifecycle import DEFAULT_APPROVAL_TTL_SECONDS, Lifecycle, utc_now
from backend.app.services.page_rate import CoalescingPageGate
from backend.app.services.readiness import (
    DEFAULT_PAGE_FAILURE_READY_THRESHOLD,
    OutageLog,
    ReaperHeartbeat,
)
from backend.app.services.seen_ids import InMemorySeenIdStore, SeenIdStore

__all__ = [
    "DEFAULT_DEDUP_AUDIT_SAMPLE",
    "DEFAULT_MAX_ALERT_BODY_BYTES",
    "AppServices",
    "Services",
    "WorkflowGraph",
    "get_services",
]



class WorkflowGraph(Protocol):
    """The slice of a compiled LangGraph used by the API."""

    async def ainvoke(self, input: Any, config: RunnableConfig | None = None) -> Any: ...


@dataclass(frozen=True, slots=True)
class AppServices:
    """Adapters injected into the HTTP layer."""

    graph: WorkflowGraph
    dedup: DedupStore
    sms: SmsPort
    incidents: IncidentRepository
    audit: AuditStore
    #: Shared secret for the Africa's Talking webhook. Empty = reject everything (fail closed).
    africastalking_webhook_secret: str = ""
    #: The only sender (E.164, ``ONCALL_PHONE_NUMBER``) whose replies are accepted.
    oncall_phone_number: str = ""
    #: When non-empty, inbound ``to`` must equal it.
    africastalking_shortcode: str = ""
    seen_ids: SeenIdStore = field(default_factory=InMemorySeenIdStore)
    alert_webhook_secret: str = ""
    #: Bearer key for the read APIs when not in dry run (``API_READ_SECRET``). Empty = reject (fail closed).
    api_read_secret: SecretStr = SecretStr("")
    #: Legacy opt-in: also accept the webhook secret as ``?secret=`` (default header-only).
    allow_query_secret: bool = False
    #: Refreshes demo telemetry rows (returns rows touched). ``None`` = nothing to refresh.
    reseed: Callable[[], Awaitable[int]] | None = None
    #: Cheap dependency probes for ``/readyz``; raise on failure. ``None`` = in-memory mode (always ok).
    ping_postgres: Callable[[], Awaitable[None]] | None = None
    ping_redis: Callable[[], Awaitable[None]] | None = None
    #: ``/readyz`` pager check fails at this many consecutive page failures (``PAGE_FAILURE_READY_THRESHOLD``).
    page_failure_ready_threshold: int = DEFAULT_PAGE_FAILURE_READY_THRESHOLD
    #: Reaper liveness for ``/readyz`` (touched by ``Lifecycle.run_reaper``).
    reaper: ReaperHeartbeat = field(default_factory=ReaperHeartbeat)
    #: Once-per-outage logging state for the 503 handlers.
    outages: OutageLog = field(default_factory=OutageLog)
    #: Seconds an incident may wait in ``AWAITING_APPROVAL`` before it expires.
    approval_ttl_seconds: int = DEFAULT_APPROVAL_TTL_SECONDS
    #: Age (seconds) after which TRIAGING/EXECUTING incidents count as orphaned (Req 6.4).
    inflight_stale_seconds: int = 60
    #: Max seconds in TRIAGING / EXECUTING before the reaper recovers or fails the incident (Req 6.8).
    triage_timeout_seconds: int = 120
    executing_timeout_seconds: int = 120
    #: A token stays unavailable this long after its incident became terminal (Req 9.1).
    token_cooldown_seconds: int = DEFAULT_TOKEN_COOLDOWN_SECONDS
    #: Characters a 2-character token is drawn from (injectable so tests can exhaust it).
    token_alphabet: str = TOKEN_ALPHABET
    #: Largest accepted ``POST /webhooks/alerts`` body in bytes (Req 10.4).
    max_alert_body_bytes: int = DEFAULT_MAX_ALERT_BODY_BYTES
    #: ``ALERT_DEDUPLICATED`` rows written per incident before only summaries (Req 10.5).
    dedup_audit_sample: int = DEFAULT_DEDUP_AUDIT_SAMPLE
    #: Optional leader lock for startup reconciliation (``None`` = single process, no lock).
    reconcile_lock: ReconcileLock | None = None
    #: Time source for expiry checks (injectable for tests).
    clock: Callable[[], datetime] = utc_now
    #: Consecutive page-delivery failures (Req 8.4); exposed by /readyz in a later task.
    health: HealthState = field(default_factory=HealthState)
    #: One unparseable-reply hint per sender per 60 s (Req 4.10).
    hint_limiter: HintLimiter = field(default_factory=HintRateLimiter)
    #: Rate gate for individual pages; the reaper tick flushes its summary page (Req 10.3).
    page_gate: CoalescingPageGate | None = None
    #: Max seconds a reply waits for a TRIAGING incident to reach approval (Req 6.12).
    triage_wait_seconds: float = 2.0
    #: Sleep used while waiting (injectable for tests).
    sleep: Callable[[float], Awaitable[None]] = asyncio.sleep

    @property
    def lifecycle(self) -> Lifecycle:
        return Lifecycle(
            incidents=self.incidents,
            audit=self.audit,
            dedup=self.dedup,
            sms=self.sms,
            approval_ttl_seconds=self.approval_ttl_seconds,
            clock=self.clock,
            inflight_stale_seconds=self.inflight_stale_seconds,
            triage_timeout_seconds=self.triage_timeout_seconds,
            executing_timeout_seconds=self.executing_timeout_seconds,
            resume_triage=self._resume,
            flush_pages=self.page_gate.flush if self.page_gate is not None else None,
            heartbeat=self.reaper,
        )

    async def _resume(self, incident_id: UUID) -> bool:
        return await resume_triage(self, incident_id)


def get_services(request: Request) -> AppServices:
    services: AppServices = request.app.state.services
    return services


Services = Annotated[AppServices, Depends(get_services)]
