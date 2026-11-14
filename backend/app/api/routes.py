"""FastAPI routes: alert ingestion, Twilio SMS webhook, and read APIs.

Everything the routes need (graph, dedup store, SMS adapter, repositories) is
injected through :class:`AppServices` stored on ``app.state.services``.

Requirements: 1.1, 1.2, 1.3, 4.2, 4.3, 4.5.
"""

from __future__ import annotations

import hmac
import logging
from dataclasses import dataclass
from typing import Annotated, Any, Final, Literal, Protocol, cast
from urllib.parse import parse_qsl
from uuid import UUID, uuid4

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request, Response
from fastapi.exceptions import RequestValidationError
from langchain_core.runnables import RunnableConfig
from langgraph.types import Command
from starlette.datastructures import ImmutableMultiDict
from pydantic import BaseModel, ConfigDict, Field, ValidationError
from twilio.request_validator import RequestValidator  # type: ignore[import-untyped]

from backend.app.agents.ports import SmsPort
from backend.app.services.dedup import DedupStore, Duplicate, release_on_terminal
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
from backend.app.services.twilio_client import TwilioSmsAdapter

logger = logging.getLogger("pagemaster.api")

EVENT_ALERT_DEDUPLICATED: Final[str] = "ALERT_DEDUPLICATED"
EVENT_WORKFLOW_ERROR: Final[str] = "WORKFLOW_ERROR"
EVENT_INCIDENT_FAILED: Final[str] = "INCIDENT_FAILED"
MAX_TOKEN_ATTEMPTS: Final[int] = 20
MAX_SMS_BODY_BYTES: Final[int] = 16_384
EMPTY_TWIML: Final[str] = '<?xml version="1.0" encoding="UTF-8"?><Response></Response>'

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
    twilio_auth_token: str = ""
    public_base_url: str | None = None
    alert_webhook_secret: str = ""


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
    token: str = Field(pattern=r"^[A-Z0-9]{2}$")


class AlertDeduplicated(BaseModel):
    status: Literal["DEDUPLICATED"] = "DEDUPLICATED"
    incident_id: UUID


class IncidentView(BaseModel):
    incident_id: UUID
    token: str
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
    return AlertAccepted(incident_id=incident.incident_id, token=incident.token)


# ---------------------------------------------------------------------------
# POST /webhooks/twilio/sms
# ---------------------------------------------------------------------------


def _external_url(request: Request, services: AppServices) -> str:
    """URL Twilio signed. ``PUBLIC_BASE_URL`` overrides it behind proxies/tunnels."""
    if services.public_base_url:
        url = services.public_base_url.rstrip("/") + request.url.path
        return f"{url}?{request.url.query}" if request.url.query else url
    return str(request.url)


def _signature_valid(services: AppServices, url: str, params: ImmutableMultiDict[str, str], signature: str) -> bool:
    if not services.twilio_auth_token or not signature:
        return False  # fail closed when unconfigured
    validator = RequestValidator(services.twilio_auth_token)
    return bool(validator.validate(url, params, signature))


def _twiml() -> Response:
    return Response(content=EMPTY_TWIML, media_type="application/xml")


async def _notify(services: AppServices, text: str) -> None:
    try:
        await services.sms.send(text)
    except Exception:
        logger.exception("informational sms failed")


@router.post("/webhooks/twilio/sms", response_class=Response)
async def twilio_sms(request: Request, background: BackgroundTasks, services: Services) -> Response:
    raw = await request.body()
    if len(raw) > MAX_SMS_BODY_BYTES:
        raise HTTPException(status_code=413, detail="payload too large")

    # Req 4.2: authenticate first. The form is only decoded to compute the HMAC;
    # nothing in it is interpreted until the signature has been accepted.
    params: ImmutableMultiDict[str, str] = ImmutableMultiDict(
        parse_qsl(raw.decode("utf-8", errors="replace"), keep_blank_values=True)
    )
    signature = request.headers.get("X-Twilio-Signature", "")
    if not _signature_valid(services, _external_url(request, services), params, signature):
        await services.audit.append_event(
            SYSTEM_INCIDENT_ID,
            AuditEvent.SECURITY_VIOLATION,
            {"reason": "invalid_twilio_signature", "path": request.url.path, "signature_present": bool(signature)},
        )
        raise HTTPException(status_code=403, detail="invalid signature")

    await _handle_reply(services, background, params.get("Body", ""))
    return _twiml()


async def _handle_reply(services: AppServices, background: BackgroundTasks, body: str) -> None:
    """Parse an SMS reply body and resume the workflow. Shared by the webhook and demo route.

    Callers are responsible for authenticating the request first.
    """
    reply = parse_sms_reply(body)
    if reply is None:
        return  # not an action code: ignore, no mutation

    incident = await services.incidents.get_active_by_token(reply.token)
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
            token=r.token,
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
    model_config = ConfigDict(extra="forbid")

    token: str = Field(pattern=r"^[A-Za-z0-9]{2}$")
    choice: Literal[1, 2]


class DemoOutboxMessage(BaseModel):
    text: str
    sent_at: str


def _dry_run_adapter(services: AppServices) -> TwilioSmsAdapter:
    """Return the dry-run SMS adapter, or 404 so live mode never exposes demo features."""
    sms = services.sms
    if not isinstance(sms, TwilioSmsAdapter) or not sms.dry_run:
        raise HTTPException(status_code=404, detail="not found")
    return sms


@demo_router.post("/reply", status_code=202)
async def demo_reply(payload: DemoReply, background: BackgroundTasks, services: Services) -> dict[str, str]:
    """Simulate an SMS reply without Twilio. Same parse/resume path as the webhook."""
    _dry_run_adapter(services)
    await _handle_reply(services, background, f"{payload.token}-{payload.choice}")
    return {"status": "accepted"}


@demo_router.get("/outbox", response_model=list[DemoOutboxMessage])
async def demo_outbox(services: Services, limit: int = 20) -> list[DemoOutboxMessage]:
    """Latest dry-run pager messages, newest first."""
    sms = _dry_run_adapter(services)
    capped = max(1, min(limit, 100))
    return [
        DemoOutboxMessage(text=m.text, sent_at=m.sent_at.isoformat())
        for m in reversed(sms.outbox[-capped:])
    ]


@router.get("/api/incidents/{incident_id}/audit", response_model=AuditView)
async def incident_audit(incident_id: UUID, services: Services) -> AuditView:
    if incident_id == SYSTEM_INCIDENT_ID or await services.incidents.get(incident_id) is None:
        raise HTTPException(status_code=404, detail="incident not found")
    records = await services.audit.records(incident_id)
    return AuditView(
        incident_id=incident_id, chain_valid=verify_chain(records).valid, records=records
    )
