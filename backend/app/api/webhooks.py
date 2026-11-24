"""Inbound webhooks: monitoring alerts and the Africa's Talking SMS reply callback.

Holds the shared-secret, E.164 sender and shortcode checks, bounded body reading, alert
deduplication/audit and message-id idempotency. Reply handling lives in ``replies``.

Requirements: 1.1, 1.2, 1.3, 4.2, 4.3, 4.5, 10.4, 10.5.
"""

from __future__ import annotations

import hmac
import logging
from collections.abc import Iterable
from typing import Any, Final, Literal
from urllib.parse import parse_qsl
from uuid import UUID, uuid4

from fastapi import APIRouter, BackgroundTasks, HTTPException, Request, Response
from fastapi.exceptions import RequestValidationError
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from backend.app.api.app_services import AppServices, Services
from backend.app.api.auth import bearer_valid
from backend.app.api.replies import handle_reply
from backend.app.api.workflow import fail_incident, run_workflow
from backend.app.services.africastalking_client import canonicalize_e164, extract_webhook_secret
from backend.app.services.dedup import Duplicate
from backend.app.services.guardrails import AuditEvent
from backend.app.services.incident_store import (
    SYSTEM_INCIDENT_ID,
    ActiveFingerprintError,
    IncidentRecord,
    TokenCollisionError,
    TokenExhaustedError,
    generate_token,
)
from backend.app.services.readiness import dependency_kind
from backend.app.services.sms_common import mask_phone

__all__ = [
    "DEDUP_SUMMARY_EVERY",
    "EVENT_ALERT_DEDUPLICATED",
    "EVENT_ALERT_DEDUPLICATED_SUMMARY",
    "EVENT_TOKEN_EXHAUSTED",
    "MAX_MESSAGE_ID_CHARS",
    "MAX_SMS_BODY_BYTES",
    "MAX_TOKEN_ATTEMPTS",
    "REASON_NO_FREE_TOKEN",
    "TOKEN_RETRY_AFTER_SECONDS",
    "AlertAccepted",
    "AlertDeduplicated",
    "AlertPayload",
    "SmsAck",
    "africastalking_sms",
    "authorize_inbound_sms",
    "receive_alert",
    "router",
    "secret_violation",
]

logger = logging.getLogger("pagemaster.api")

EVENT_ALERT_DEDUPLICATED: Final[str] = "ALERT_DEDUPLICATED"
EVENT_ALERT_DEDUPLICATED_SUMMARY: Final[str] = "ALERT_DEDUPLICATED_SUMMARY"
#: After the sampled rows, one summary row per this many further duplicates.
DEDUP_SUMMARY_EVERY: Final[int] = 100
#: Insert attempts after a lost token race (the unique index decides); exhaustion is exact, not retried.
MAX_TOKEN_ATTEMPTS: Final[int] = 5
EVENT_TOKEN_EXHAUSTED: Final[str] = "TOKEN_EXHAUSTED"
REASON_NO_FREE_TOKEN: Final[str] = "no_free_token"
TOKEN_RETRY_AFTER_SECONDS: Final[int] = 30
MAX_SMS_BODY_BYTES: Final[int] = 16_384
MAX_MESSAGE_ID_CHARS: Final[int] = 128

router = APIRouter()


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


# ---------------------------------------------------------------------------
# POST /webhooks/alerts
# ---------------------------------------------------------------------------


async def _record_duplicate(services: AppServices, holder: UUID, payload: AlertPayload) -> None:
    """Count the duplicate, then audit a bounded sample plus periodic summaries (Req 10.5).

    The first ``dedup_audit_sample`` duplicates per incident get one ``ALERT_DEDUPLICATED`` row each;
    after that one ``ALERT_DEDUPLICATED_SUMMARY`` row is appended per ``DEDUP_SUMMARY_EVERY`` more.
    """
    count = await services.incidents.increment_duplicate_count(holder)
    if count is None:
        logger.warning("dedup holder %s has no incident record", holder)
        return
    sample = max(1, services.dedup_audit_sample)
    if count <= sample:
        occurrence = payload.model_dump(mode="json", exclude_none=True)
        await services.audit.append_event(holder, EVENT_ALERT_DEDUPLICATED, occurrence)
    elif (count - sample) % DEDUP_SUMMARY_EVERY == 0:
        await services.audit.append_event(holder, EVENT_ALERT_DEDUPLICATED_SUMMARY, {"duplicates": count})


async def _read_alert_body(request: Request, limit: int) -> bytes:
    """Read the alert body, never buffering more than ``limit`` bytes (Req 10.4).

    A declared ``Content-Length`` over the limit is rejected before any read. The stream is
    limited as well, because the header can be absent or wrong.
    """
    declared = request.headers.get("Content-Length")
    if declared is not None:
        text = declared.strip()
        if not (text.isascii() and text.isdigit()):
            raise HTTPException(status_code=400, detail="invalid Content-Length")
        if int(text) > limit:
            raise HTTPException(status_code=413, detail="payload too large")
    chunks: list[bytes] = []
    total = 0
    async for chunk in request.stream():
        total += len(chunk)
        if total > limit:
            raise HTTPException(status_code=413, detail="payload too large")
        chunks.append(chunk)
    return b"".join(chunks)


async def _authorize_alert(request: Request, services: AppServices) -> None:
    """Optional shared-secret check. No secret configured means open (unchanged behaviour)."""
    if not services.alert_webhook_secret:
        return
    header = request.headers.get("Authorization", "")
    if bearer_valid(services.alert_webhook_secret, header):
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
        payload = AlertPayload.model_validate_json(await _read_alert_body(request, services.max_alert_body_bytes))
    except ValidationError as exc:
        raise RequestValidationError(exc.errors(include_url=False, include_context=False, include_input=False)) from exc
    incident_id = uuid4()
    acquired = await services.dedup.acquire(payload.service_name, payload.error_code, incident_id)
    if isinstance(acquired, Duplicate):
        await _record_duplicate(services, acquired.incident_id, payload)
        response.status_code = 200
        return AlertDeduplicated(incident_id=acquired.incident_id)

    async def release() -> None:
        """Best effort: a failing release (outage) must not mask the original error; the TTL frees it."""
        try:
            await services.dedup.release(payload.service_name, payload.error_code, incident_id)
        except Exception:
            logger.warning("could not release dedup lock for %s", incident_id)

    incident: IncidentRecord | None = None
    try:
        for _ in range(MAX_TOKEN_ATTEMPTS):
            busy = await services.incidents.busy_tokens(services.token_cooldown_seconds)
            try:
                token = generate_token(busy, services.token_alphabet)
            except TokenExhaustedError:
                break
            try:
                incident = await services.incidents.create(
                    incident_id=incident_id,
                    token=token,
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
            await services.audit.append_event(
                SYSTEM_INCIDENT_ID, EVENT_TOKEN_EXHAUSTED, {"reason": REASON_NO_FREE_TOKEN}
            )
            raise HTTPException(
                status_code=503,
                detail="no free incident token",
                headers={"Retry-After": str(TOKEN_RETRY_AFTER_SECONDS)},
            )
        await services.audit.append_event(
            incident.incident_id,
            AuditEvent.INCIDENT_CREATED,
            {"service_name": incident.service_name, "error_code": incident.error_code, "token": incident.token},
        )
        chain = await services.audit.records(incident.incident_id)
    except HTTPException:
        raise
    except BaseException:
        if incident is not None:
            # The row exists but the request failed before the workflow started: do not leave a
            # TRIAGING incident behind (it would shadow re-fired alerts until the reaper runs).
            await fail_incident(services, incident, "alert_setup_failed", None)
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
    background.add_task(run_workflow, services, incident, graph_input)
    return AlertAccepted(incident_id=incident.incident_id)


# ---------------------------------------------------------------------------
# POST /webhooks/africastalking/sms
# ---------------------------------------------------------------------------


def _digits(raw: str) -> str:
    return "".join(ch for ch in raw if "0" <= ch <= "9")


def _mask_sender(raw: str) -> str:
    return mask_phone(raw, prefix=0, tail=4)


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

    try:
        await handle_reply(services, background, form.get("text", ""), sender=canonicalize_e164(sender) or sender)
    except Exception as exc:
        if dependency_kind(exc) is not None:  # 503 follows: let the provider's redelivery be processed
            try:
                await services.seen_ids.forget(message_id)
            except Exception:
                logger.warning("could not release message id claim")
        raise
    return SmsAck(status="ok")
