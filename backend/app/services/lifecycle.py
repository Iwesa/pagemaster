"""Incident lifecycle: approval expiry, the reaper, and startup reconciliation.

Every non-terminal state needs an exit (Req 6):

* ``AWAITING_APPROVAL`` older than ``APPROVAL_TTL_SECONDS`` becomes ``EXPIRED``.
* ``TRIAGING`` / ``EXECUTING`` incidents found at startup are orphans of a dead process
  and become ``FAILED``.

Each transition is a compare-and-set on the observed state, so a concurrent valid reply
and an expiry can never both win. Neither path ever resumes the graph, so no
infrastructure mutation can follow. The audit event and lock release run after the CAS.

Requirements: 6.1 to 6.5.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Final

from backend.app.agents.ports import SmsPort
from backend.app.services.dedup import DedupStore, release_on_terminal
from backend.app.services.incident_store import AuditStore, IncidentRecord, IncidentRepository

logger = logging.getLogger("pagemaster.lifecycle")

EVENT_INCIDENT_EXPIRED: Final[str] = "INCIDENT_EXPIRED"
EVENT_INCIDENT_RECONCILED: Final[str] = "INCIDENT_RECONCILED"
DEFAULT_APPROVAL_TTL_SECONDS: Final[int] = 900
DEFAULT_REAPER_INTERVAL_SECONDS: Final[float] = 30.0


def utc_now() -> datetime:
    return datetime.now(UTC)


def approval_expired(incident: IncidentRecord, now: datetime, ttl_seconds: int) -> bool:
    """True when an ``AWAITING_APPROVAL`` incident is older than the TTL.

    ``updated_at`` is the time of the last state transition; the only writer of the
    ``AWAITING_APPROVAL`` state is the transition into it, so it is when approval started.
    """
    return incident.state == "AWAITING_APPROVAL" and now - incident.updated_at > timedelta(seconds=ttl_seconds)


@dataclass(frozen=True, slots=True)
class Lifecycle:
    """Expiry and reconciliation over the persistence/dedup/SMS ports."""

    incidents: IncidentRepository
    audit: AuditStore
    dedup: DedupStore
    sms: SmsPort
    approval_ttl_seconds: int = DEFAULT_APPROVAL_TTL_SECONDS
    clock: Callable[[], datetime] = utc_now

    async def expire(self, incident: IncidentRecord) -> bool:
        """Move ``AWAITING_APPROVAL`` to ``EXPIRED``. False if another writer won the race."""
        if not await self.incidents.compare_and_set_state(incident.incident_id, "AWAITING_APPROVAL", "EXPIRED"):
            return False
        await self._finish(incident, "EXPIRED", EVENT_INCIDENT_EXPIRED, {"ttl_seconds": self.approval_ttl_seconds})
        try:
            await self.sms.send(f"INC-{incident.token} no longer active. No action taken.")
        except Exception:
            logger.exception("expiry sms failed for %s", incident.incident_id)
        return True

    async def reap_once(self) -> int:
        """Expire every ``AWAITING_APPROVAL`` incident past the TTL. Returns how many expired."""
        cutoff = self.clock() - timedelta(seconds=self.approval_ttl_seconds)
        stale = await self.incidents.list_by_states(["AWAITING_APPROVAL"], updated_before=cutoff)
        expired = 0
        for incident in stale:
            try:
                expired += await self.expire(incident)
            except Exception:
                logger.exception("could not expire incident %s", incident.incident_id)
        return expired

    async def run_reaper(self, interval_seconds: float) -> None:
        """Loop until cancelled. A failing iteration is logged and the loop continues."""
        while True:
            try:
                await self.reap_once()
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.exception("reaper iteration failed")
            await asyncio.sleep(interval_seconds)

    async def reconcile_orphans(self) -> int:
        """Startup: ``TRIAGING``/``EXECUTING`` incidents lost their task, so mark them ``FAILED``.

        ``AWAITING_APPROVAL`` incidents have durable checkpoints and are left alone.
        """
        orphans = await self.incidents.list_by_states(["TRIAGING", "EXECUTING"])
        reconciled = 0
        for incident in orphans:
            try:
                if not await self.incidents.compare_and_set_state(incident.incident_id, incident.state, "FAILED"):
                    continue
                await self._finish(
                    incident, "FAILED", EVENT_INCIDENT_RECONCILED, {"reason": "orphaned", "from_state": incident.state}
                )
                reconciled += 1
            except Exception:
                logger.exception("could not reconcile incident %s", incident.incident_id)
        return reconciled

    async def _finish(self, incident: IncidentRecord, status: str, event: str, payload: dict[str, object]) -> None:
        """Audit and free the fingerprint after the state change. Steps are isolated."""
        try:
            await self.audit.append_event(incident.incident_id, event, payload)
        except Exception:
            logger.exception("could not audit %s for %s", event, incident.incident_id)
        try:
            await release_on_terminal(
                self.dedup, status, incident.service_name, incident.error_code, incident.incident_id
            )
        except Exception:
            logger.exception("could not release lock for %s", incident.incident_id)
