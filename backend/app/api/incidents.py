"""Read APIs: incident list and redacted audit trail, behind the read-access dependency.

Requirements: 11.2.
"""

from __future__ import annotations

import logging
import re
from typing import Any, Final
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel

from backend.app.api.app_services import Services
from backend.app.api.auth import bearer_valid
from backend.app.services.guardrails import AuditEvent, AuditRecord, verify_chain
from backend.app.services.incident_store import SYSTEM_INCIDENT_ID, IncidentStatus

__all__ = [
    "REDACTED",
    "AuditView",
    "IncidentView",
    "incident_audit",
    "list_incidents",
    "require_read_access",
    "router",
]

logger = logging.getLogger("pagemaster.api")

router = APIRouter()


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


async def require_read_access(request: Request, services: Services) -> None:
    """Req 11.2: outside dry run the read APIs need ``Authorization: Bearer <API_READ_SECRET>``.

    Constant-time comparison on bytes; an unset secret rejects everything. A failure is audited on
    the system incident with a reason only (never the supplied or configured key).
    """
    if bool(getattr(request.app.state, "dry_run", False)):
        return
    secret = services.api_read_secret.get_secret_value()
    header = request.headers.get("Authorization", "")
    if secret and bearer_valid(secret, header):
        return
    reason = "read_key_not_configured" if not secret else ("read_key_missing" if not header else "invalid_read_key")
    try:
        await services.audit.append_event(SYSTEM_INCIDENT_ID, AuditEvent.SECURITY_VIOLATION, {"reason": reason})
    except Exception:
        logger.exception("could not audit read api rejection")
    raise HTTPException(status_code=401, detail="unauthorized", headers={"WWW-Authenticate": "Bearer"})


ReadAccess = [Depends(require_read_access)]


@router.get("/api/incidents", response_model=list[IncidentView], dependencies=ReadAccess)
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


@router.get("/api/incidents/{incident_id}/audit", response_model=AuditView, dependencies=ReadAccess)
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
