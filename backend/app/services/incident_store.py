"""Incident repository and audit store ports with in-memory implementations.

These are the persistence ports used by the HTTP layer. ``USE_IN_MEMORY=true``
wires the in-memory versions (no Postgres/Redis); production wires the
asyncpg-backed versions in :mod:`backend.app.services.postgres_store`.

Audit chains
------------
``AuditStore.commit`` implements ``AuditPort`` for the graph. Both the graph and
the HTTP layer (dedup occurrences, security violations) append to the same
incident, so the store is the single authority on chain order: it **re-chains**
every appended event onto the stored head (``seq``, ``prev_hash`` and ``hash``
are recomputed). The stored chain therefore always passes ``verify_chain``,
even when two writers interleave.

Requirements: 1.1, 1.2, 4.2, 4.3, 4.5.
"""

from __future__ import annotations

import secrets
import string
from collections.abc import Callable, Collection, Mapping
from datetime import UTC, datetime, timedelta
from typing import Any, Final, Literal, Protocol, runtime_checkable
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from backend.app.services.guardrails import (
    GENESIS_HASH,
    AuditRecord,
    ResolutionGates,
    can_resolve,
    compute_audit_hash,
)

IncidentStatus = Literal[
    "TRIAGING",
    "AWAITING_APPROVAL",
    "EXECUTING",
    "RESOLVED",
    "BLOCKED_BY_TRIPWIRE",
    "FAILED",
    "EXPIRED",
    "NO_ACTION",
]

InflightStatus = Literal["TRIAGING", "EXECUTING"]

ACTIVE_STATUSES: Final[frozenset[str]] = frozenset({"TRIAGING", "AWAITING_APPROVAL", "EXECUTING"})
TERMINAL_STATUSES: Final[frozenset[str]] = frozenset(
    {"RESOLVED", "BLOCKED_BY_TRIPWIRE", "FAILED", "EXPIRED", "NO_ACTION"}
)
ALL_STATUSES: Final[frozenset[str]] = ACTIVE_STATUSES | TERMINAL_STATUSES

#: Pseudo-incident that owns audit events with no incident (e.g. forged webhooks).
SYSTEM_INCIDENT_ID: Final[UUID] = UUID(int=0)

TOKEN_ALPHABET: Final[str] = string.ascii_uppercase + string.digits
DEFAULT_TOKEN_COOLDOWN_SECONDS: Final[int] = 3600


class TokenExhaustedError(Exception):
    """Every token is held by an active incident or is still cooling down (Req 9.2)."""


def token_space(alphabet: str = TOKEN_ALPHABET) -> list[str]:
    """Every 2-character token over ``alphabet`` (36 x 36 = 1296 by default)."""
    return [a + b for a in alphabet for b in alphabet]


def generate_token(busy: Collection[str] = (), alphabet: str = TOKEN_ALPHABET) -> str:
    """Draw uniformly from the tokens not in ``busy``.

    Raises :class:`TokenExhaustedError` when none is free, so exhaustion is exact
    instead of being guessed from failed random draws.
    """
    taken = set(busy)
    free = [token for token in token_space(alphabet) if token not in taken]
    if not free:
        raise TokenExhaustedError
    return secrets.choice(free)


class TokenCollisionError(Exception):
    """The token is already used by an active incident."""


class ActiveFingerprintError(Exception):
    """An active incident already exists for the ``(service_name, error_code)`` fingerprint."""

    def __init__(self, incident_id: UUID) -> None:
        super().__init__(f"active incident {incident_id} holds this fingerprint")
        self.incident_id = incident_id


class IncidentRecord(BaseModel):
    """One row of ``incidents``."""

    model_config = ConfigDict(frozen=True)

    incident_id: UUID
    token: str = Field(pattern=r"^[A-Z0-9]{2}$")
    service_name: str
    error_code: str
    state: IncidentStatus = "TRIAGING"
    raw_alert: dict[str, Any] = Field(default_factory=dict)
    #: Reply options on the page (0..2), recorded with the state change that follows the
    #: page; ``None`` until then (and for rows written before the column existed).
    option_count: int | None = Field(default=None, ge=0, le=2)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    #: When the incident last entered a terminal state; ``None`` while active (Req 9.1).
    terminal_at: datetime | None = None
    #: Alerts deduplicated onto this incident (Req 10.5); audit rows are sampled, this is exact.
    duplicate_count: int = Field(default=0, ge=0)


class ReclaimedIncident(BaseModel):
    """An in-flight incident failed by stale-lease reconciliation."""

    model_config = ConfigDict(frozen=True)

    incident_id: UUID
    token: str
    service_name: str
    error_code: str


class ExpiryOutcome(BaseModel):
    """Result of the point-of-use expiry check (:meth:`IncidentRepository.expire_if_stale`).

    ``found`` is False when no *active* incident holds the token (unknown, already
    terminal, or just expired by a concurrent caller). ``is_expired`` is the store
    clock's verdict (``updated_at <= now - ttl``) for any active state; only an
    ``AWAITING_APPROVAL`` row that is expired is transitioned, with ``expired_now``
    True for exactly one caller.
    """

    model_config = ConfigDict(frozen=True)

    found: bool
    incident_id: UUID | None = None
    state_before: IncidentStatus | None = None
    expired_now: bool = False
    is_expired: bool = False
    service_name: str | None = None
    error_code: str | None = None


@runtime_checkable
class IncidentRepository(Protocol):
    """Port for incident persistence."""

    async def create(
        self,
        *,
        incident_id: UUID,
        token: str,
        service_name: str,
        error_code: str,
        raw_alert: Mapping[str, Any],
    ) -> IncidentRecord:
        """Insert a ``TRIAGING`` incident.

        Raises ``TokenCollisionError`` or ``ActiveFingerprintError`` on conflict.
        """
        ...

    async def get(self, incident_id: UUID) -> IncidentRecord | None: ...

    async def get_active_by_token(self, token: str) -> IncidentRecord | None:
        """The active (non-terminal) incident holding ``token``, if any."""
        ...

    async def list_recent(self, limit: int = 100) -> list[IncidentRecord]:
        """Newest first. Excludes the system pseudo-incident."""
        ...

    async def set_state(self, incident_id: UUID, new: IncidentStatus) -> bool:
        """Unconditionally set the state. False if the incident does not exist."""
        ...

    async def compare_and_set_state(
        self, incident_id: UUID, expected: IncidentStatus, new: IncidentStatus
    ) -> bool:
        """Atomically move ``expected`` -> ``new``. False if the state differed."""
        ...

    async def list_by_states(
        self,
        states: Collection[IncidentStatus],
        *,
        updated_before: datetime | None = None,
        limit: int = 1000,
    ) -> list[IncidentRecord]:
        """Incidents in any of ``states`` (oldest first), optionally with ``updated_at < updated_before``.

        ``updated_at`` is the time of the last state transition, so for ``AWAITING_APPROVAL``
        it is when approval started. Excludes the system pseudo-incident.
        """
        ...

    async def reconcile_stale_inflight(self, stale_seconds: int) -> list[ReclaimedIncident]:
        """Atomically fail ``TRIAGING``/``EXECUTING`` rows with ``updated_at <= now - stale_seconds``.

        Fresher in-flight rows (possibly owned by a live worker) are untouched.
        """
        ...

    async def expire_stale_awaiting(self, ttl_seconds: float) -> list[ReclaimedIncident]:
        """Atomically expire ``AWAITING_APPROVAL`` rows with ``updated_at <= now - ttl_seconds``.

        "now" is the store's clock (database ``now()`` in Postgres).
        """
        ...

    async def fail_stale_state(
        self, state: InflightStatus, timeout_seconds: float
    ) -> list[ReclaimedIncident]:
        """Compare-and-set ``state`` -> ``FAILED`` for rows with ``updated_at <= now - timeout_seconds``.

        Store clock. Rows whose state changed concurrently are untouched.
        """
        ...

    async def renew_stale_triaging(self, timeout_seconds: float) -> list[ReclaimedIncident]:
        """Claim stale ``TRIAGING`` rows by refreshing ``updated_at`` (state unchanged).

        Returns only the rows this caller claimed, so one worker per tick attempts recovery.
        """
        ...

    async def latest_by_token(self, token: str) -> IncidentRecord | None:
        """The newest incident (any state, system row excluded) that used ``token``."""
        ...

    async def busy_tokens(self, cooldown_seconds: float) -> frozenset[str]:
        """Tokens that cannot be issued (Req 9.1).

        Held by an active incident, or held by an incident that became terminal less
        than ``cooldown_seconds`` ago (store clock).
        """
        ...

    async def expire_if_stale(self, token: str, ttl_seconds: float) -> ExpiryOutcome:
        """Point-of-use expiry check for the active incident holding ``token``.

        Expiry is decided by the store clock. An expired ``AWAITING_APPROVAL`` row is
        moved to ``EXPIRED`` atomically, so concurrent callers see ``expired_now``
        True at most once.
        """
        ...

    async def increment_duplicate_count(self, incident_id: UUID) -> int | None:
        """Atomically add one to the incident's duplicate counter and return the new value.

        Independent of the incident's state (a concurrently terminal incident is counted
        too). ``None`` if the incident does not exist.
        """
        ...

    async def record_resolution(
        self,
        incident_id: UUID,
        status: IncidentStatus,
        gates: ResolutionGates | None,
        option_count: int | None = None,
    ) -> bool:
        """Persist ``status``, the four gate flags and ``option_count`` in one atomic write.

        ``option_count`` ``None`` keeps the stored value.

        ``None`` flags keep the stored value. ``RESOLVED`` is only accepted when
        every flag is true (``ValueError`` in memory, ``CheckViolationError`` in
        Postgres). False if the incident does not exist.
        """
        ...


@runtime_checkable
class AuditStore(Protocol):
    """Port for the append-only, hash-chained audit trail. Also satisfies ``AuditPort``."""

    async def commit(self, record: AuditRecord) -> None:
        """``AuditPort``: persist the event carried by ``record`` (re-chained onto the head)."""
        ...

    async def append_event(
        self, incident_id: UUID, event_type: str, payload: Mapping[str, Any] | None = None
    ) -> AuditRecord | None:
        """Append one event. Returns ``None`` if the incident does not exist."""
        ...

    async def records(self, incident_id: UUID) -> list[AuditRecord]:
        """The incident's chain ordered by ``seq`` (empty if none)."""
        ...


def rechain(
    chain: list[AuditRecord], incident_id: UUID, event_type: str, payload: Mapping[str, Any]
) -> AuditRecord:
    """Build the next record for ``chain`` (does not mutate it)."""
    prev = chain[-1].hash if chain else GENESIS_HASH
    seq = len(chain)
    body: dict[str, Any] = dict(payload)
    return AuditRecord(
        incident_id=incident_id,
        seq=seq,
        event_type=event_type,
        payload=body,
        prev_hash=prev,
        hash=compute_audit_hash(prev, incident_id, seq, event_type, body),
    )


class InMemoryIncidentRepository:
    """Single-process repository enforcing the same uniqueness rules as the SQL indexes."""

    def __init__(self, clock: Callable[[], datetime] | None = None) -> None:
        self._clock: Callable[[], datetime] = clock if clock is not None else (lambda: datetime.now(UTC))
        self._rows: dict[UUID, IncidentRecord] = {}
        self._gates: dict[UUID, dict[str, bool | None]] = {}

    async def create(
        self,
        *,
        incident_id: UUID,
        token: str,
        service_name: str,
        error_code: str,
        raw_alert: Mapping[str, Any],
    ) -> IncidentRecord:
        for row in self._rows.values():
            if row.state not in ACTIVE_STATUSES:
                continue
            if row.token == token:
                raise TokenCollisionError(token)
            if row.service_name == service_name and row.error_code == error_code:
                raise ActiveFingerprintError(row.incident_id)
        record = IncidentRecord(
            incident_id=incident_id,
            token=token,
            service_name=service_name,
            error_code=error_code,
            raw_alert=dict(raw_alert),
            created_at=self._clock(),
            updated_at=self._clock(),
        )
        self._rows[incident_id] = record
        return record

    async def get(self, incident_id: UUID) -> IncidentRecord | None:
        return self._rows.get(incident_id)

    async def get_active_by_token(self, token: str) -> IncidentRecord | None:
        for row in self._rows.values():
            if row.token == token and row.state in ACTIVE_STATUSES:
                return row
        return None

    async def list_recent(self, limit: int = 100) -> list[IncidentRecord]:
        rows = sorted(self._rows.values(), key=lambda r: r.created_at, reverse=True)
        return rows[:limit]

    async def list_by_states(
        self,
        states: Collection[IncidentStatus],
        *,
        updated_before: datetime | None = None,
        limit: int = 1000,
    ) -> list[IncidentRecord]:
        wanted = set(states)
        rows = [
            r
            for r in self._rows.values()
            if r.state in wanted
            and r.incident_id != SYSTEM_INCIDENT_ID
            and (updated_before is None or r.updated_at < updated_before)
        ]
        return sorted(rows, key=lambda r: r.updated_at)[:limit]

    @staticmethod
    def _transition(new: IncidentStatus, now: datetime) -> dict[str, Any]:
        """Fields written by a state change; ``terminal_at`` is set with the state (Req 9.1)."""
        update: dict[str, Any] = {"state": new, "updated_at": now}
        if new in TERMINAL_STATUSES:
            update["terminal_at"] = now
        return update

    async def busy_tokens(self, cooldown_seconds: float) -> frozenset[str]:
        cutoff = self._clock() - timedelta(seconds=cooldown_seconds)
        return frozenset(
            row.token
            for row in self._rows.values()
            if row.state in ACTIVE_STATUSES or (row.terminal_at is not None and row.terminal_at > cutoff)
        )

    async def set_state(self, incident_id: UUID, new: IncidentStatus) -> bool:
        row = self._rows.get(incident_id)
        if row is None:
            return False
        self._rows[incident_id] = row.model_copy(update=self._transition(new, self._clock()))
        return True

    async def compare_and_set_state(
        self, incident_id: UUID, expected: IncidentStatus, new: IncidentStatus
    ) -> bool:
        # No await between check and write: atomic on the event loop.
        row = self._rows.get(incident_id)
        if row is None or row.state != expected:
            return False
        self._rows[incident_id] = row.model_copy(update=self._transition(new, self._clock()))
        return True

    async def reconcile_stale_inflight(self, stale_seconds: int) -> list[ReclaimedIncident]:
        # No await between scan and write: atomic on the event loop.
        now = self._clock()
        cutoff = now - timedelta(seconds=stale_seconds)
        reclaimed: list[ReclaimedIncident] = []
        for incident_id, row in list(self._rows.items()):
            if row.state in ("TRIAGING", "EXECUTING") and row.updated_at <= cutoff:
                self._rows[incident_id] = row.model_copy(update=self._transition("FAILED", now))
                reclaimed.append(
                    ReclaimedIncident(
                        incident_id=incident_id,
                        token=row.token,
                        service_name=row.service_name,
                        error_code=row.error_code,
                    )
                )
        return reclaimed

    async def expire_stale_awaiting(self, ttl_seconds: float) -> list[ReclaimedIncident]:
        # No await between scan and write: atomic on the event loop.
        now = self._clock()
        cutoff = now - timedelta(seconds=ttl_seconds)
        expired: list[ReclaimedIncident] = []
        for incident_id, row in list(self._rows.items()):
            if row.state == "AWAITING_APPROVAL" and row.updated_at <= cutoff:
                self._rows[incident_id] = row.model_copy(update=self._transition("EXPIRED", now))
                expired.append(
                    ReclaimedIncident(
                        incident_id=incident_id,
                        token=row.token,
                        service_name=row.service_name,
                        error_code=row.error_code,
                    )
                )
        return expired

    @staticmethod
    def _reclaimed(row: IncidentRecord) -> ReclaimedIncident:
        return ReclaimedIncident(
            incident_id=row.incident_id,
            token=row.token,
            service_name=row.service_name,
            error_code=row.error_code,
        )

    async def fail_stale_state(
        self, state: InflightStatus, timeout_seconds: float
    ) -> list[ReclaimedIncident]:
        # No await between scan and write: atomic on the event loop.
        now = self._clock()
        cutoff = now - timedelta(seconds=timeout_seconds)
        failed: list[ReclaimedIncident] = []
        for incident_id, row in list(self._rows.items()):
            if row.state == state and row.updated_at <= cutoff and incident_id != SYSTEM_INCIDENT_ID:
                self._rows[incident_id] = row.model_copy(update=self._transition("FAILED", now))
                failed.append(self._reclaimed(row))
        return failed

    async def renew_stale_triaging(self, timeout_seconds: float) -> list[ReclaimedIncident]:
        now = self._clock()
        cutoff = now - timedelta(seconds=timeout_seconds)
        claimed: list[ReclaimedIncident] = []
        for incident_id, row in list(self._rows.items()):
            if row.state == "TRIAGING" and row.updated_at <= cutoff and incident_id != SYSTEM_INCIDENT_ID:
                self._rows[incident_id] = row.model_copy(update={"updated_at": now})
                claimed.append(self._reclaimed(row))
        return claimed

    async def latest_by_token(self, token: str) -> IncidentRecord | None:
        rows = [r for r in self._rows.values() if r.token == token and r.incident_id != SYSTEM_INCIDENT_ID]
        return max(rows, key=lambda r: r.created_at, default=None)

    async def expire_if_stale(self, token: str, ttl_seconds: float) -> ExpiryOutcome:
        # No await between read and write: atomic on the event loop.
        row = next(
            (r for r in self._rows.values() if r.token == token and r.state in ACTIVE_STATUSES), None
        )
        if row is None:
            return ExpiryOutcome(found=False)
        now = self._clock()
        is_expired = row.updated_at <= now - timedelta(seconds=ttl_seconds)
        expired_now = is_expired and row.state == "AWAITING_APPROVAL"
        if expired_now:
            self._rows[row.incident_id] = row.model_copy(update=self._transition("EXPIRED", now))
        return ExpiryOutcome(
            found=True,
            incident_id=row.incident_id,
            state_before=row.state,
            expired_now=expired_now,
            is_expired=is_expired,
            service_name=row.service_name,
            error_code=row.error_code,
        )

    async def increment_duplicate_count(self, incident_id: UUID) -> int | None:
        # No await between read and write: atomic on the event loop.
        row = self._rows.get(incident_id)
        if row is None:
            return None
        updated = row.model_copy(update={"duplicate_count": row.duplicate_count + 1})
        self._rows[incident_id] = updated
        return updated.duplicate_count

    async def record_resolution(
        self,
        incident_id: UUID,
        status: IncidentStatus,
        gates: ResolutionGates | None,
        option_count: int | None = None,
    ) -> bool:
        row = self._rows.get(incident_id)
        if row is None:
            return False
        merged = {
            name: (new if new is not None else self._gates.get(incident_id, {}).get(name))
            for name, new in (gates or ResolutionGates()).model_dump().items()
        }
        if status == "RESOLVED" and not can_resolve(ResolutionGates.model_validate(merged)):
            raise ValueError("RESOLVED requires all four resolution gates to be true")
        self._gates[incident_id] = merged
        update = self._transition(status, self._clock())
        if option_count is not None:
            update["option_count"] = option_count
        self._rows[incident_id] = row.model_copy(update=update)
        return True


class InMemoryAuditStore:
    """Single-process audit store. ``known`` incidents are looked up in ``repository``."""

    def __init__(self, repository: IncidentRepository | None = None) -> None:
        self._repository = repository
        self._chains: dict[UUID, list[AuditRecord]] = {}

    async def commit(self, record: AuditRecord) -> None:
        await self.append_event(record.incident_id, record.event_type, record.payload)

    async def append_event(
        self, incident_id: UUID, event_type: str, payload: Mapping[str, Any] | None = None
    ) -> AuditRecord | None:
        if incident_id != SYSTEM_INCIDENT_ID and self._repository is not None:
            if await self._repository.get(incident_id) is None:
                return None
        chain = self._chains.setdefault(incident_id, [])
        record = rechain(chain, incident_id, event_type, payload or {})
        chain.append(record)
        return record

    async def records(self, incident_id: UUID) -> list[AuditRecord]:
        return list(self._chains.get(incident_id, ()))
