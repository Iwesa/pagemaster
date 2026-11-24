"""DRY_RUN-only demo routes: simulated SMS replies, dry-run outbox and telemetry reseed.

The router is included only when ``DRY_RUN=true``; each handler also 404s unless the SMS
adapter is in dry-run mode, so live mode never exposes demo features.
"""

from __future__ import annotations

import logging
import re
from typing import Final, Literal
from uuid import UUID

from fastapi import APIRouter, BackgroundTasks, HTTPException
from pydantic import BaseModel, ConfigDict, Field, model_validator

from backend.app.api.app_services import AppServices, Services
from backend.app.api.replies import handle_reply
from backend.app.services.africastalking_client import AfricasTalkingSmsAdapter
from backend.app.services.incident_store import SYSTEM_INCIDENT_ID
from backend.app.services.sms_common import OutboxMessage

__all__ = [
    "DemoOutboxMessage",
    "DemoReply",
    "DemoReseedResult",
    "demo_outbox",
    "demo_reply",
    "demo_reseed",
    "demo_router",
]

logger = logging.getLogger("pagemaster.api")

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
    await handle_reply(services, background, f"{token}-{payload.choice}")
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
