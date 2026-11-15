"""FastAPI routes: alert ingestion, Africa's Talking SMS webhook, and read APIs.

Everything the routes need (graph, dedup store, SMS adapter, repositories) is
injected through :class:`AppServices` stored on ``app.state.services``.

Requirements: 1.1, 1.2, 1.3, 4.2, 4.3, 4.5.
"""

from __future__ import annotations

import asyncio
import hmac
import logging
import re
from collections.abc import Awaitable, Callable, Iterable
from dataclasses import dataclass, field
from datetime import datetime
from typing import Annotated, Any, Final, Literal, Protocol, cast
from urllib.parse import parse_qsl
from uuid import UUID, uuid4

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request, Response
from fastapi.exceptions import RequestValidationError
from langchain_core.runnables import RunnableConfig
from langgraph.types import Command
from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from backend.app.agents.ports import SmsPort
from backend.app.services.africastalking_client import (
    AfricasTalkingSmsAdapter,
    canonicalize_e164,
    extract_webhook_secret,
)
from backend.app.services.sms_common import OutboxMessage
from backend.app.services.leader_lock import ReconcileLock
from backend.app.services.seen_ids import InMemorySeenIdStore, SeenIdStore
from backend.app.services.dedup import DedupStore, Duplicate, release_on_terminal
from backend.app.services.lifecycle import DEFAULT_APPROVAL_TTL_SECONDS, Lifecycle, utc_now
from backend.app.services.guardrails import (
    AuditEvent,
    AuditRecord,
    ResolutionGates,
    can_resolve,
    parse_sms_reply,
    verify_chain,
)
from backend.app.services.incident_store import (
    ALL_STATUSES,
    SYSTEM_INCIDENT_ID,
    ActiveFingerprintError,
    AuditStore,
    IncidentRecord,
    IncidentRepository,
    IncidentStatus,
    TokenCollisionError,
    generate_token,
)

logger = logging.getLogger("pagemaster.api")

EVENT_ALERT_DEDUPLICATED: Final[str] = "ALERT_DEDUPLICATED"
EVENT_WORKFLOW_ERROR: Final[str] = "WORKFLOW_ERROR"
EVENT_INCIDENT_FAILED: Final[str] = "INCIDENT_FAILED"
MAX_TOKEN_ATTEMPTS: Final[int] = 20
MAX_SMS_BODY_BYTES: Final[int] = 16_384
MAX_MESSAGE_ID_CHARS: Final[int] = 128

router = APIRouter()


# ---------------------------------------------------------------------------
# Injected services
# ---------------------------------------------------------------------------


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
    #: Legacy opt-in: also accept the webhook secret as ``?secret=`` (default header-only).
    allow_query_secret: bool = False
    #: Refreshes demo telemetry rows (returns rows touched). ``None`` = nothing to refresh.
    reseed: Callable[[], Awaitable[int]] | None = None
    #: Cheap dependency probe for ``/healthz``; raises on failure. ``None`` = always ready.
    ping: Callable[[], Awaitable[None]] | None = None
    #: Seconds an incident may wait in ``AWAITING_APPROVAL`` before it expires.
    approval_ttl_seconds: int = DEFAULT_APPROVAL_TTL_SECONDS
    #: Age (seconds) after which TRIAGING/EXECUTING incidents count as orphaned (Req 6.4).
    inflight_stale_seconds: int = 60
    #: Optional leader lock for startup reconciliation (``None`` = single process, no lock).
    reconcile_lock: ReconcileLock | None = None
    #: Time source for expiry checks (injectable for tests).
    clock: Callable[[], datetime] = utc_now

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
        )


def get_services(request: Request) -> AppServices:
    services: AppServices = request.app.state.services
    return services


Services = Annotated[AppServices, Depends(get_services)]


# ---------------------------------------------------------------------------
# Schemas (Pydantic v2)
# ---------------------------------------------------------------------------


class AlertPayload(BaseModel):
    """Inbound monitoring alert (Req 1.1, 1.3)."""

    model_config = ConfigDict(extra="ignore")

    service_name: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
    error_code: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]*$")
    summary: str = Field(default="", max_length=500)
    severity: Literal["low", "medium", "high", "critical"] | None = None
    source: str | None = Field(default=None, max_length=64)


class AlertAccepted(BaseModel):
    incident_id: UUID


class AlertDeduplicated(BaseModel):
    status: Literal["DEDUPLICATED"] = "DEDUPLICATED"
    incident_id: UUID


class IncidentView(BaseModel):
    incident_id: UUID
    service_name: str
    error_code: str
    state: IncidentStatus
    created_at: str
    updated_at: str


class AuditView(BaseModel):
    incident_id: UUID
    chain_valid: bool
    records: list[AuditRecord]


# ---------------------------------------------------------------------------
# Workflow execution (background)
# ---------------------------------------------------------------------------


def _thread_config(incident_id: UUID) -> RunnableConfig:
    return {"configurable": {"thread_id": str(incident_id)}}


async def _run_workflow(services: AppServices, incident: IncidentRecord, graph_input: Any) -> None:
    """Run or resume the graph, then sync incident state and dedup lock. Never raises."""
    try:
        result = await services.graph.ainvoke(graph_input, _thread_config(incident.incident_id))
        status = result.get("status") if isinstance(result, dict) else None
        if not (isinstance(status, str) and status in ALL_STATUSES):
            return
        gates = _gates_from_result(result)
        new_status = cast(IncidentStatus, status)
        # The graph ends in EXECUTING only when the executor ran but a gate is false.
        # RESOLVED is never written unless all four gates are true (Req 5.4, 5.5, 5.6).
        if new_status == "EXECUTING" or (new_status == "RESOLVED" and not can_resolve(gates)):
            await _fail_incident(services, incident, "remediation_incomplete", gates)
            return
        await services.incidents.record_resolution(incident.incident_id, new_status, gates)
        await release_on_terminal(
            services.dedup, new_status, incident.service_name, incident.error_code, incident.incident_id
        )
    except Exception:
        logger.exception("workflow failed for incident %s", incident.incident_id)
        await _fail_incident(services, incident, "workflow_exception", None)


def _gates_from_result(result: object) -> ResolutionGates:
    raw = result.get("gates") if isinstance(result, dict) else None
    if not isinstance(raw, dict):
        return ResolutionGates()
    return ResolutionGates.model_validate(
        {k: v for k, v in raw.items() if k in ResolutionGates.model_fields and isinstance(v, bool | None)}
    )


async def _fail_incident(
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


# ---------------------------------------------------------------------------
# GET /healthz (unauthenticated, registered regardless of DRY_RUN)
# ---------------------------------------------------------------------------

HEALTH_PING_TIMEOUT_SECONDS: Final[float] = 2.0


class HealthStatus(BaseModel):
    status: Literal["ok", "unavailable"]


@router.get("/healthz", response_model=HealthStatus)
async def healthz(request: Request, response: Response) -> HealthStatus:
    """Readiness-lite probe. Never leaks error details; any probe failure is a bare 503."""
    services: AppServices | None = getattr(request.app.state, "services", None)
    if services is None:  # lifespan has not finished wiring adapters yet
        response.status_code = 503
        return HealthStatus(status="unavailable")
    if services.ping is not None:
        try:
            await asyncio.wait_for(services.ping(), timeout=HEALTH_PING_TIMEOUT_SECONDS)
        except Exception:
            logger.warning("health probe failed")
            response.status_code = 503
            return HealthStatus(status="unavailable")
    return HealthStatus(status="ok")


# ---------------------------------------------------------------------------
# POST /webhooks/alerts
# ---------------------------------------------------------------------------


async def _record_duplicate(services: AppServices, holder: UUID, payload: AlertPayload) -> None:
    occurrence = payload.model_dump(mode="json", exclude_none=True)
    if await services.audit.append_event(holder, EVENT_ALERT_DEDUPLICATED, occurrence) is None:
        logger.warning("dedup holder %s has no incident record", holder)


def _bearer_valid(secret: str, header: str) -> bool:
    scheme, _, supplied = header.partition(" ")
    if scheme.lower() != "bearer" or not supplied:
        return False
    return hmac.compare_digest(supplied.strip().encode("utf-8"), secret.encode("utf-8"))


async def _authorize_alert(request: Request, services: AppServices) -> None:
    """Optional shared-secret check. No secret configured means open (unchanged behaviour)."""
    if not services.alert_webhook_secret:
        return
    header = request.headers.get("Authorization", "")
    if _bearer_valid(services.alert_webhook_secret, header):
        return
    await services.audit.append_event(
        SYSTEM_INCIDENT_ID,
        AuditEvent.SECURITY_VIOLATION,
        {"reason": "invalid_alert_token", "path": request.url.path, "token_present": bool(header)},
    )
    raise HTTPException(status_code=401, detail="unauthorized", headers={"WWW-Authenticate": "Bearer"})


@router.post(
    "/webhooks/alerts",
    status_code=202,
    response_model=AlertAccepted | AlertDeduplicated,
    responses={200: {"model": AlertDeduplicated}},
)
async def receive_alert(
    request: Request,
    background: BackgroundTasks,
    response: Response,
    services: Services,
) -> AlertAccepted | AlertDeduplicated:
    # Authenticate before the body is read, parsed or validated.
    await _authorize_alert(request, services)
    try:
        payload = AlertPayload.model_validate_json(await request.body())
    except ValidationError as exc:
        raise RequestValidationError(exc.errors(include_url=False, include_context=False, include_input=False)) from exc
    incident_id = uuid4()
    acquired = await services.dedup.acquire(payload.service_name, payload.error_code, incident_id)
    if isinstance(acquired, Duplicate):
        await _record_duplicate(services, acquired.incident_id, payload)
        response.status_code = 200
        return AlertDeduplicated(incident_id=acquired.incident_id)

    async def release() -> None:
        await services.dedup.release(payload.service_name, payload.error_code, incident_id)

    incident: IncidentRecord | None = None
    try:
        for _ in range(MAX_TOKEN_ATTEMPTS):
            try:
                incident = await services.incidents.create(
                    incident_id=incident_id,
                    token=generate_token(),
                    service_name=payload.service_name,
                    error_code=payload.error_code,
                    raw_alert=payload.model_dump(mode="json", exclude_none=True),
                )
                break
            except TokenCollisionError:
                continue
            except ActiveFingerprintError as exc:
                # Lock had expired but the incident is still active: treat as duplicate.
                await release()
                await _record_duplicate(services, exc.incident_id, payload)
                response.status_code = 200
                return AlertDeduplicated(incident_id=exc.incident_id)
        if incident is None:
            await release()
            raise HTTPException(status_code=503, detail="no free incident token")
        await services.audit.append_event(
            incident.incident_id,
            AuditEvent.INCIDENT_CREATED,
            {"service_name": incident.service_name, "error_code": incident.error_code, "token": incident.token},
        )
        chain = await services.audit.records(incident.incident_id)
    except HTTPException:
        raise
    except BaseException:
        await release()
        raise

    graph_input: dict[str, Any] = {
        "incident_id": str(incident.incident_id),
        "token": incident.token,
        "service_name": incident.service_name,
        "error_code": incident.error_code,
        "alert_summary": payload.summary,
        "audit_records": [r.model_dump(mode="json") for r in chain],
    }
    background.add_task(_run_workflow, services, incident, graph_input)
    return AlertAccepted(incident_id=incident.incident_id)


# ---------------------------------------------------------------------------
# POST /webhooks/africastalking/sms
# ---------------------------------------------------------------------------


def _digits(raw: str) -> str:
    return "".join(ch for ch in raw if "0" <= ch <= "9")


def _mask_sender(raw: str) -> str:
    digits = _digits(raw)
    return f"***{digits[-4:]}" if len(digits) > 4 else "***"


def secret_violation(expected_secret: str, supplied_secrets: Iterable[str]) -> str | None:
    """Shared-secret check. Unconfigured secret fails closed."""
    expected = expected_secret.encode("utf-8")
    if not expected:
        return "secret_not_configured"
    # Evaluate every candidate (no short-circuit) to keep timing independent of which matched.
    results = [hmac.compare_digest(s.encode("utf-8"), expected) for s in supplied_secrets if s]
    return None if any(results) else "invalid_secret"


def authorize_inbound_sms(
    *,
    expected_secret: str,
    supplied_secrets: Iterable[str],
    sender: str,
    to: str,
    oncall_phone_number: str,
    shortcode: str,
) -> str | None:
    """Pure inbound-SMS authorization. Return a violation reason, or ``None`` when allowed.

    Order: shared secret (unconfigured fails closed), canonical E.164 sender equal to the
    on-call number, then the destination shortcode when one is configured. Message-id
    idempotency is applied afterwards by the route (it needs the seen-id store).
    """
    secret_reason = secret_violation(expected_secret, supplied_secrets)
    if secret_reason is not None:
        return secret_reason
    sender_e164 = canonicalize_e164(sender)
    oncall_e164 = canonicalize_e164(oncall_phone_number)
    if sender_e164 is None or oncall_e164 is None or sender_e164 != oncall_e164:
        return "unauthorized_sender"
    code = _digits(shortcode)
    if shortcode.strip() and (not code or _digits(to) != code):
        return "shortcode_mismatch"
    return None

async def _reject_sms(
    request: Request,
    services: AppServices,
    reason: str,
    sender: str | None,
    *,
    query_secret_disabled: bool = False,
) -> None:
    payload: dict[str, Any] = {"reason": reason, "path": request.url.path}
    if query_secret_disabled:
        payload["query_secret_disabled"] = True
    if sender is not None:
        payload["sender"] = _mask_sender(sender)
    try:
        await services.audit.append_event(SYSTEM_INCIDENT_ID, AuditEvent.SECURITY_VIOLATION, payload)
    except Exception:
        logger.exception("could not audit sms rejection")
    raise HTTPException(status_code=403, detail="forbidden")


async def _notify(services: AppServices, text: str) -> None:
    try:
        await services.sms.send(text)
    except Exception:
        logger.exception("informational sms failed")


class SmsAck(BaseModel):
    """JSON acknowledgement. Redelivered ids get an empty one."""

    status: Literal["ok"] | None = None


@router.post("/webhooks/africastalking/sms", response_model=SmsAck, response_model_exclude_none=True)
async def africastalking_sms(request: Request, background: BackgroundTasks, services: Services) -> SmsAck:
    raw = await request.body()
    if len(raw) > MAX_SMS_BODY_BYTES:
        raise HTTPException(status_code=413, detail="payload too large")

    # (1) Shared secret first: no body field is interpreted before it is accepted.
    # Only the first available source is compared (header, bearer, then opt-in query).
    query_secret = request.query_params.get("secret")
    selected = extract_webhook_secret(
        request.headers.get("X-Webhook-Secret"),
        request.headers.get("Authorization"),
        query_secret,
        allow_query=services.allow_query_secret,
    )
    supplied: tuple[str, ...] = (selected,) if selected else ()
    reason = secret_violation(services.africastalking_webhook_secret, supplied)
    if reason is not None:
        ignored = bool(query_secret) and not services.allow_query_secret
        await _reject_sms(request, services, reason, None, query_secret_disabled=ignored)

    form = dict(parse_qsl(raw.decode("utf-8", errors="replace"), keep_blank_values=True))
    sender = form.get("from", "")

    # (2) sender == ONCALL_PHONE_NUMBER and (3) optional shortcode match.
    violation = authorize_inbound_sms(
        expected_secret=services.africastalking_webhook_secret,
        supplied_secrets=supplied,
        sender=sender,
        to=form.get("to", ""),
        oncall_phone_number=services.oncall_phone_number,
        shortcode=services.africastalking_shortcode,
    )
    if violation is not None:
        await _reject_sms(request, services, violation, sender)

    # (4) Idempotency: an unseen id is claimed atomically; a redelivery changes nothing.
    message_id = form.get("id", "").strip()
    if not message_id or len(message_id) > MAX_MESSAGE_ID_CHARS:
        raise HTTPException(status_code=400, detail="missing or invalid message id")
    if not await services.seen_ids.claim(message_id):
        return SmsAck()

    await _handle_reply(services, background, form.get("text", ""))
    return SmsAck(status="ok")


async def _handle_reply(services: AppServices, background: BackgroundTasks, body: str) -> None:
    """Parse an SMS reply body and resume the workflow. Shared by the webhook and demo route.

    Callers are responsible for authenticating the request first.
    """
    reply = parse_sms_reply(body)
    if reply is None:
        return  # not an action code: ignore, no mutation

    # Req 6.1, 6.2, 6.7: the store clock decides expiry, before any graph resume.
    outcome = await services.incidents.expire_if_stale(reply.token, services.approval_ttl_seconds)
    if outcome.expired_now:
        await services.lifecycle.handle_expiry(outcome, reply.token)  # audit + unlock + SMS
        return
    incident = (
        await services.incidents.get_active_by_token(reply.token) if outcome.found else None
    )
    if incident is None:  # Req 4.5: unknown, expired or resolved
        await _notify(services, f"INC-{reply.token} no longer active. No action taken.")
        return
    claimed = await services.incidents.compare_and_set_state(
        incident.incident_id, "AWAITING_APPROVAL", "EXECUTING"
    )
    if not claimed:  # still triaging, or another reply already won
        await _notify(services, f"INC-{reply.token} is not awaiting approval. No action taken.")
        return

    # Req 4.4: resume the suspended graph with the selected action.
    background.add_task(_run_workflow, services, incident, Command(resume={"choice": reply.choice}))


# ---------------------------------------------------------------------------
# Read APIs
# ---------------------------------------------------------------------------


@router.get("/api/incidents", response_model=list[IncidentView])
async def list_incidents(services: Services) -> list[IncidentView]:
    rows = await services.incidents.list_recent()
    return [
        IncidentView(
            incident_id=r.incident_id,
            service_name=r.service_name,
            error_code=r.error_code,
            state=r.state,
            created_at=r.created_at.isoformat(),
            updated_at=r.updated_at.isoformat(),
        )
        for r in rows
        if r.incident_id != SYSTEM_INCIDENT_ID
    ]


# ---------------------------------------------------------------------------
# DRY_RUN-only demo routes (registered by create_app only when DRY_RUN=true)
# ---------------------------------------------------------------------------

demo_router = APIRouter(prefix="/api/demo")


class DemoReply(BaseModel):
    """Reply by ``incident_id`` (preferred) or, for backward compatibility, ``token``."""

    model_config = ConfigDict(extra="forbid")

    incident_id: UUID | None = None
    token: str | None = Field(default=None, pattern=r"^[A-Za-z0-9]{2}$")
    choice: Literal[1, 2]

    @model_validator(mode="after")
    def _exactly_one_target(self) -> DemoReply:
        if (self.incident_id is None) == (self.token is None):
            raise ValueError("provide exactly one of incident_id or token")
        return self


class DemoOutboxMessage(BaseModel):
    text: str
    sent_at: str
    #: Incident this pager message belongs to, when it can be determined.
    incident_id: UUID | None = None


def _dry_run_adapter(services: AppServices) -> AfricasTalkingSmsAdapter:
    """Return the dry-run SMS adapter, or 404 so live mode never exposes demo features."""
    sms = services.sms
    if not isinstance(sms, AfricasTalkingSmsAdapter) or not sms.dry_run:
        raise HTTPException(status_code=404, detail="not found")
    return sms


@demo_router.post("/reply", status_code=202)
async def demo_reply(payload: DemoReply, background: BackgroundTasks, services: Services) -> dict[str, str]:
    """Simulate an SMS reply without an SMS gateway. Same parse/resume path as the webhook."""
    _dry_run_adapter(services)
    token = payload.token
    if payload.incident_id is not None:
        incident = await services.incidents.get(payload.incident_id)
        if incident is None or incident.incident_id == SYSTEM_INCIDENT_ID:
            raise HTTPException(status_code=404, detail="incident not found")
        token = incident.token
    await _handle_reply(services, background, f"{token}-{payload.choice}")
    return {"status": "accepted"}


_OUTBOX_TOKEN_RE: Final[re.Pattern[str]] = re.compile(r"^INC-([A-Z0-9]{2})(?: |$)", re.ASCII)


async def _outbox_incident_ids(services: AppServices, messages: list[OutboxMessage]) -> list[UUID | None]:
    """Map each pager text to the newest incident with its token created before it was sent."""
    rows = [r for r in await services.incidents.list_recent() if r.incident_id != SYSTEM_INCIDENT_ID]
    result: list[UUID | None] = []
    for m in messages:
        match = _OUTBOX_TOKEN_RE.match(m.text)
        candidates = (
            [r for r in rows if r.token == match.group(1) and r.created_at <= m.sent_at] if match else []
        )
        result.append(max(candidates, key=lambda r: r.created_at).incident_id if candidates else None)
    return result


@demo_router.get("/outbox", response_model=list[DemoOutboxMessage])
async def demo_outbox(services: Services, limit: int = 20) -> list[DemoOutboxMessage]:
    """Latest dry-run pager messages, newest first."""
    sms = _dry_run_adapter(services)
    capped = max(1, min(limit, 100))
    messages = list(reversed(sms.outbox[-capped:]))
    ids = await _outbox_incident_ids(services, messages)
    return [
        DemoOutboxMessage(text=m.text, sent_at=m.sent_at.isoformat(), incident_id=i)
        for m, i in zip(messages, ids, strict=True)
    ]


class DemoReseedResult(BaseModel):
    status: Literal["ok"] = "ok"
    rows_refreshed: int = 0


@demo_router.post("/reseed", response_model=DemoReseedResult)
async def demo_reseed(services: Services) -> DemoReseedResult:
    """Move the demo logs back inside the 15-minute window. No-op without a database."""
    _dry_run_adapter(services)
    if services.reseed is None:
        return DemoReseedResult()
    try:
        rows = await services.reseed()
    except Exception:
        logger.exception("demo reseed failed")
        raise HTTPException(status_code=503, detail="reseed failed") from None
    return DemoReseedResult(rows_refreshed=rows)


@router.get("/api/incidents/{incident_id}/audit", response_model=AuditView)
async def incident_audit(incident_id: UUID, services: Services) -> AuditView:
    if incident_id == SYSTEM_INCIDENT_ID or await services.incidents.get(incident_id) is None:
        raise HTTPException(status_code=404, detail="incident not found")
    incident = await services.incidents.get(incident_id)
    records = await services.audit.records(incident_id)
    # Validate the real stored chain; only the response copy is redacted.
    chain_valid = verify_chain(records).valid
    token = incident.token if incident is not None else ""
    public = [r.model_copy(update={"payload": _redact(r.payload, token)}) for r in records]
    return AuditView(incident_id=incident_id, chain_valid=chain_valid, records=public)


_GENERIC_TOKEN_RE: Final[re.Pattern[str]] = re.compile(r"INC-[A-Za-z0-9]{2}(?![A-Za-z0-9])")
REDACTED: Final[str] = "[redacted]"


def _redact_text(text: str, token: str) -> str:
    out = _GENERIC_TOKEN_RE.sub(f"INC-{REDACTED}", text)
    if token:
        out = re.sub(rf"(?<![A-Za-z0-9]){re.escape(token)}-([12])(?![0-9])", rf"{REDACTED}-\1", out, flags=re.I)
    return out


def _redact(value: Any, token: str) -> Any:
    """Copy of ``value`` without ``token`` keys or reply-token occurrences in strings."""
    if isinstance(value, dict):
        return {k: _redact(v, token) for k, v in value.items() if str(k).lower() != "token"}
    if isinstance(value, list | tuple):
        return [_redact(v, token) for v in value]
    if isinstance(value, str):
        return _redact_text(value, token)
    return value
