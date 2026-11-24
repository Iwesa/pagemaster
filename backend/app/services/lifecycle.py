"""Incident lifecycle: approval expiry, the reaper, and startup reconciliation.

Every non-terminal state needs an exit (Req 6):

* ``AWAITING_APPROVAL`` older than ``APPROVAL_TTL_SECONDS`` becomes ``EXPIRED``.
* ``TRIAGING`` / ``EXECUTING`` incidents older than ``inflight_stale_seconds`` found at
  startup are orphans of a dead process and become ``FAILED`` (one worker at a time, under
  an optional leader lock).

Each transition is a compare-and-set on the observed state, so a concurrent valid reply
and an expiry can never both win. Neither path ever resumes the graph, so no
infrastructure mutation can follow. The audit event and lock release run after the CAS.

Requirements: 6.1 to 6.5.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Final
from uuid import UUID

from backend.app.agents.ports import SmsPort
from backend.app.services.dedup import DedupStore, release_on_terminal
from backend.app.services.incident_store import (
    AuditStore,
    ExpiryOutcome,
    IncidentRepository,
    ReclaimedIncident,
)
from backend.app.services.leader_lock import WORKER_ID, ReconcileLock
from backend.app.services.readiness import ReaperHeartbeat

logger = logging.getLogger("pagemaster.lifecycle")

EVENT_INCIDENT_FAILED: Final[str] = "INCIDENT_FAILED"
REASON_STALE: Final[str] = "stale_inflight_reconciled"
REASON_RECOVERED_AFTER_CRASH: Final[str] = "recovered_after_crash"
REASON_EXECUTION_TIMEOUT: Final[str] = "execution_timeout"
DEFAULT_INFLIGHT_TIMEOUT_SECONDS: Final[int] = 120

EVENT_INCIDENT_EXPIRED: Final[str] = "INCIDENT_EXPIRED"
EVENT_INCIDENT_RECONCILED: Final[str] = "INCIDENT_RECONCILED"
DEFAULT_APPROVAL_TTL_SECONDS: Final[int] = 900
DEFAULT_REAPER_INTERVAL_SECONDS: Final[float] = 30.0


def utc_now() -> datetime:
    return datetime.now(UTC)


@dataclass(frozen=True, slots=True)
class Lifecycle:
    """Expiry and reconciliation over the persistence/dedup/SMS ports."""

    incidents: IncidentRepository
    audit: AuditStore
    dedup: DedupStore
    sms: SmsPort
    approval_ttl_seconds: int = DEFAULT_APPROVAL_TTL_SECONDS
    clock: Callable[[], datetime] = utc_now
    inflight_stale_seconds: int = 60
    triage_timeout_seconds: int = DEFAULT_INFLIGHT_TIMEOUT_SECONDS
    executing_timeout_seconds: int = DEFAULT_INFLIGHT_TIMEOUT_SECONDS
    #: Resume a stale TRIAGING incident from its checkpoint. True = resumed and state synced.
    resume_triage: Callable[[UUID], Awaitable[bool]] | None = None
    #: Sends the coalesced summary page when one is due (Req 10.3). Runs once per tick.
    flush_pages: Callable[[], Awaitable[object]] | None = None
    #: Touched by ``run_reaper`` every iteration so ``/readyz`` can tell the reaper is alive.
    heartbeat: ReaperHeartbeat | None = None

    async def handle_expiry(self, outcome: ExpiryOutcome, token: str) -> bool:
        """Run the expiry side effects for an incident the store just moved to ``EXPIRED``.

        Returns False (and does nothing) unless ``outcome.expired_now``, so exactly one
        caller per incident audits, releases the lock and notifies.
        """
        if not outcome.expired_now or outcome.incident_id is None:
            return False
        await self._apply_expiry(
            outcome.incident_id, token, outcome.service_name or "", outcome.error_code or ""
        )
        return True

    async def _apply_expiry(self, incident_id: UUID, token: str, service_name: str, error_code: str) -> None:
        """Audit (no token in payload), release the fingerprint lock, send the informational SMS."""
        await self._finish(
            incident_id, service_name, error_code, "EXPIRED", EVENT_INCIDENT_EXPIRED,
            {"ttl_seconds": self.approval_ttl_seconds},
        )
        try:
            await self.sms.send(f"INC-{token} EXPIRED. No action taken.")
        except Exception:
            logger.exception("expiry sms failed for %s", incident_id)

    async def reap_once(self) -> int:
        """Expire every ``AWAITING_APPROVAL`` incident past the TTL (store clock). Returns the count."""
        stale = await self.incidents.expire_stale_awaiting(self.approval_ttl_seconds)
        for item in stale:
            try:
                await self._apply_expiry(item.incident_id, item.token, item.service_name, item.error_code)
            except Exception:
                logger.exception("could not finish expiry of incident %s", item.incident_id)
        return len(stale)

    async def sweep_inflight(self) -> int:
        """Recover or fail ``TRIAGING``/``EXECUTING`` rows past their timeout (store clock).

        ``TRIAGING``: claim (refresh ``updated_at``), try to resume from the checkpoint, and on
        no checkpoint or any error compare-and-set ``TRIAGING`` -> ``FAILED``. ``EXECUTING``:
        compare-and-set to ``FAILED``; the remediation step is never re-run. Returns the number
        of incidents moved to ``FAILED``.
        """
        failed = 0
        for item in await self.incidents.renew_stale_triaging(self.triage_timeout_seconds):
            try:
                if await self._try_resume(item.incident_id):
                    continue
                if not await self.incidents.compare_and_set_state(item.incident_id, "TRIAGING", "FAILED"):
                    continue  # a concurrent writer moved it on; nothing to clean up
                await self._apply_failure(item, REASON_RECOVERED_AFTER_CRASH)
                failed += 1
            except Exception:
                logger.exception("could not recover triaging incident %s", item.incident_id)
        for item in await self.incidents.fail_stale_state("EXECUTING", self.executing_timeout_seconds):
            try:
                await self._apply_failure(item, REASON_EXECUTION_TIMEOUT)
                failed += 1
            except Exception:
                logger.exception("could not finish failure of incident %s", item.incident_id)
        return failed

    async def _try_resume(self, incident_id: UUID) -> bool:
        if self.resume_triage is None:
            return False
        try:
            return await asyncio.wait_for(self.resume_triage(incident_id), timeout=self.triage_timeout_seconds)
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("resume from checkpoint failed for %s", incident_id)
            return False

    async def _apply_failure(self, item: ReclaimedIncident, reason: str) -> None:
        """Audit (no token/phone in payload), release the lock, tell the on-call engineer."""
        await self._finish(
            item.incident_id, item.service_name, item.error_code, "FAILED", EVENT_INCIDENT_FAILED,
            {"reason": reason},
        )
        try:
            await self.sms.send(f"INC-{item.token} FAILED. Re-send the alert.")
        except Exception:
            logger.exception("failure sms failed for %s", item.incident_id)

    async def tick(self) -> None:
        """One reaper iteration: approval expiry, in-flight sweep, summary page. Steps are isolated."""
        try:
            await self.reap_once()
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("approval expiry sweep failed")
        try:
            await self.sweep_inflight()
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("in-flight sweep failed")
        if self.flush_pages is not None:
            try:
                await self.flush_pages()
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.exception("coalesced page flush failed")

    async def run_reaper(self, interval_seconds: float) -> None:
        """Loop until cancelled. A failing iteration is logged and the loop continues."""
        while True:
            if self.heartbeat is not None:
                self.heartbeat.beat()
            try:
                await self.tick()
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.exception("reaper iteration failed")
            if self.heartbeat is not None:
                self.heartbeat.beat()  # a slow tick must not look like a dead reaper
            await asyncio.sleep(interval_seconds)

    async def reconcile_orphans(self) -> int:
        """Fail stale ``TRIAGING``/``EXECUTING`` incidents (age >= ``inflight_stale_seconds``).

        Fresh in-flight incidents may belong to a live worker and are untouched, as are
        ``AWAITING_APPROVAL`` incidents (durable checkpoints). For each reclaimed incident the
        dedup lock is released and an ``INCIDENT_FAILED`` audit event is appended; the steps are
        isolated per incident so one failure never skips the rest.
        """
        reclaimed = await self.incidents.reconcile_stale_inflight(self.inflight_stale_seconds)
        for item in reclaimed:
            try:
                await self.audit.append_event(item.incident_id, EVENT_INCIDENT_FAILED, {"reason": REASON_STALE})
            except Exception:
                logger.exception("could not audit reconcile for %s", item.incident_id)
            try:
                await release_on_terminal(self.dedup, "FAILED", item.service_name, item.error_code, item.incident_id)
            except Exception:
                logger.exception("could not release lock for %s", item.incident_id)
            try:
                await self.sms.send(f"INC-{item.token} FAILED. Re-send the alert.")
            except Exception:
                logger.exception("failure sms failed for %s", item.incident_id)
        return len(reclaimed)

    async def startup_reconcile(self, lock: ReconcileLock | None, worker_id: str = WORKER_ID) -> int | None:
        """Run ``reconcile_orphans`` under the optional leader lock.

        Returns the reclaimed count, or ``None`` when another worker holds the lock (skipped).
        """
        if lock is None:
            return await self.reconcile_orphans()
        if not await lock.acquire(worker_id):
            logger.info("reconcile lock held by another worker; skipping startup reconciliation")
            return None
        try:
            return await self.reconcile_orphans()
        finally:
            try:
                await lock.release(worker_id)
            except Exception:
                logger.exception("could not release reconcile lock")

    async def _finish(
        self, incident_id: UUID, service_name: str, error_code: str, status: str, event: str, payload: dict[str, object]
    ) -> None:
        """Audit and free the fingerprint after the state change. Steps are isolated."""
        try:
            await self.audit.append_event(incident_id, event, payload)
        except Exception:
            logger.exception("could not audit %s for %s", event, incident_id)
        try:
            await release_on_terminal(
                self.dedup, status, service_name, error_code, incident_id
            )
        except Exception:
            logger.exception("could not release lock for %s", incident_id)
