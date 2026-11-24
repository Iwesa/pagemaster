"""asyncpg-backed ``IncidentRepository`` and ``AuditStore``.

Uses fixed, parameterised SQL against ``incidents`` and ``audit_trail`` only.
Audit appends run in one transaction that locks the incident row
(``SELECT ... FOR UPDATE``) so concurrent writers serialise and the chain
stays contiguous. Events without an incident (forged webhooks) attach to a
sentinel ``_system`` incident created by :func:`ensure_system_incident`.

Requirements: 1.1, 1.2, 4.2, 4.3, 4.5.
"""

from __future__ import annotations

import json
from collections.abc import Collection, Mapping
from datetime import datetime
from typing import Any, Final, cast
from uuid import UUID

import asyncpg  # type: ignore[import-untyped]

from backend.app.services.guardrails import AuditRecord, ResolutionGates
from backend.app.services.incident_store import (
    SYSTEM_INCIDENT_ID,
    TERMINAL_STATUSES,
    ActiveFingerprintError,
    ExpiryOutcome,
    IncidentRecord,
    IncidentStatus,
    InflightStatus,
    ReclaimedIncident,
    TokenCollisionError,
    rechain,
)

SYSTEM_SERVICE_NAME: Final[str] = "_system"

_COLUMNS: Final[str] = (
    "incident_id, token, service_name, error_code, state, raw_alert, "
    "option_count, created_at, updated_at, terminal_at, duplicate_count"
)

_TERMINAL_LIST: Final[str] = ", ".join(f"'{s}'" for s in sorted(TERMINAL_STATUSES))


def _terminal_at_for(state_param: str) -> str:
    """SQL fragment stamping ``terminal_at`` (store clock) when ``state_param`` is terminal."""
    return f"terminal_at = CASE WHEN {state_param}::text IN ({_TERMINAL_LIST}) THEN now() ELSE terminal_at END"


_SQL_INSERT: Final[str] = (
    "INSERT INTO incidents (incident_id, token, service_name, error_code, state, raw_alert) "
    f"VALUES ($1, $2, $3, $4, 'TRIAGING', $5::jsonb) RETURNING {_COLUMNS}"
)
_SQL_GET: Final[str] = f"SELECT {_COLUMNS} FROM incidents WHERE incident_id = $1"
_SQL_BY_TOKEN: Final[str] = (
    f"SELECT {_COLUMNS} FROM incidents WHERE token = $1 "
    "AND state IN ('TRIAGING', 'AWAITING_APPROVAL', 'EXECUTING')"
)
_SQL_ACTIVE_BY_FINGERPRINT: Final[str] = (
    "SELECT incident_id FROM incidents WHERE service_name = $1 AND error_code = $2 "
    "AND state IN ('TRIAGING', 'AWAITING_APPROVAL', 'EXECUTING')"
)
_SQL_LIST: Final[str] = (
    f"SELECT {_COLUMNS} FROM incidents WHERE incident_id <> $1 ORDER BY created_at DESC LIMIT $2"
)
_SQL_LIST_BY_STATES: Final[str] = (
    f"SELECT {_COLUMNS} FROM incidents WHERE state = ANY($1::text[]) AND incident_id <> $2 "
    "AND ($3::timestamptz IS NULL OR updated_at < $3) ORDER BY updated_at LIMIT $4"
)
_SQL_SET_STATE: Final[str] = (
    f"UPDATE incidents SET state = $2, updated_at = now(), {_terminal_at_for('$2')} WHERE incident_id = $1"
)
_SQL_RECORD_RESOLUTION: Final[str] = (
    "UPDATE incidents SET state = $2, "
    "tripwire_check_passed = COALESCE($3, tripwire_check_passed), "
    "simulated_step_executed = COALESCE($4, simulated_step_executed), "
    "confirmation_sms_sent = COALESCE($5, confirmation_sms_sent), "
    "audit_record_committed = COALESCE($6, audit_record_committed), "
    "option_count = COALESCE($7::smallint, option_count), "
    f"updated_at = now(), {_terminal_at_for('$2')} WHERE incident_id = $1"
)
_SQL_CAS_STATE: Final[str] = (
    f"UPDATE incidents SET state = $3, updated_at = now(), {_terminal_at_for('$3')} "
    "WHERE incident_id = $1 AND state = $2"
)
_SQL_RECONCILE_STALE: Final[str] = (
    "UPDATE incidents SET state = 'FAILED', updated_at = now(), terminal_at = now() "
    "WHERE state IN ('TRIAGING', 'EXECUTING') "
    "AND updated_at <= now() - make_interval(secs => $1::double precision) "
    "RETURNING incident_id, token, service_name, error_code"
)
_SQL_EXPIRE_STALE_AWAITING: Final[str] = (
    "UPDATE incidents SET state = 'EXPIRED', updated_at = now(), terminal_at = now() "
    "WHERE state = 'AWAITING_APPROVAL' "
    "AND updated_at <= now() - make_interval(secs => $1::double precision) "
    "RETURNING incident_id, token, service_name, error_code"
)
_SQL_FAIL_STALE_STATE: Final[str] = (
    "UPDATE incidents SET state = 'FAILED', updated_at = now(), terminal_at = now() "
    "WHERE state = $1 AND incident_id <> $3 "
    "AND updated_at <= now() - make_interval(secs => $2::double precision) "
    "RETURNING incident_id, token, service_name, error_code"
)
_SQL_RENEW_STALE_TRIAGING: Final[str] = (
    "UPDATE incidents SET updated_at = now() "
    "WHERE state = 'TRIAGING' AND incident_id <> $2 "
    "AND updated_at <= now() - make_interval(secs => $1::double precision) "
    "RETURNING incident_id, token, service_name, error_code"
)
_SQL_LATEST_BY_TOKEN: Final[str] = (
    f"SELECT {_COLUMNS} FROM incidents WHERE token = $1 AND incident_id <> $2 "
    "ORDER BY created_at DESC LIMIT 1"
)
_SQL_EXPIRE_IF_STALE: Final[str] = (
    "WITH cur AS ("
    "SELECT incident_id, state, service_name, error_code, "
    "(updated_at <= now() - make_interval(secs => $2::double precision)) AS is_expired "
    "FROM incidents WHERE token = $1 "
    "AND state IN ('TRIAGING', 'AWAITING_APPROVAL', 'EXECUTING') FOR UPDATE), "
    "upd AS ("
    "UPDATE incidents i SET state = 'EXPIRED', updated_at = now(), terminal_at = now() FROM cur "
    "WHERE i.incident_id = cur.incident_id AND cur.state = 'AWAITING_APPROVAL' AND cur.is_expired "
    "RETURNING i.incident_id) "
    "SELECT cur.incident_id, cur.state, cur.service_name, cur.error_code, cur.is_expired, "
    "(upd.incident_id IS NOT NULL) AS expired_now "
    "FROM cur LEFT JOIN upd ON upd.incident_id = cur.incident_id"
)
# Tokens that cannot be issued: active, or terminal for less than the cooldown (Req 9.1).
_SQL_BUSY_TOKENS: Final[str] = (
    f"SELECT token FROM incidents WHERE state NOT IN ({_TERMINAL_LIST}) "
    "OR terminal_at > now() - make_interval(secs => $1::double precision)"
)
# One atomic statement; deliberately not filtered by state so a concurrently terminal incident still counts.
_SQL_INCREMENT_DUPLICATES: Final[str] = (
    "UPDATE incidents SET duplicate_count = COALESCE(duplicate_count, 0) + 1 "
    "WHERE incident_id = $1 RETURNING duplicate_count"
)
_SQL_LOCK: Final[str] = "SELECT 1 FROM incidents WHERE incident_id = $1 FOR UPDATE"
_SQL_CHAIN: Final[str] = (
    "SELECT incident_id, seq, event_type, payload, prev_hash, hash "
    "FROM audit_trail WHERE incident_id = $1 ORDER BY seq"
)
_SQL_INSERT_AUDIT: Final[str] = (
    "INSERT INTO audit_trail (incident_id, seq, event_type, payload, prev_hash, hash) "
    "VALUES ($1, $2, $3, $4::jsonb, $5, $6)"
)
_SQL_ENSURE_SYSTEM: Final[str] = (
    "INSERT INTO incidents (incident_id, token, service_name, error_code, state, "
    "tripwire_check_passed, simulated_step_executed, confirmation_sms_sent, audit_record_committed) "
    "VALUES ($1, '00', $2, 'SYSTEM', 'RESOLVED', TRUE, TRUE, TRUE, TRUE) "
    "ON CONFLICT (incident_id) DO NOTHING"
)
MCP_READER_ROLE: Final[str] = "mcp_reader"
_SQL_ROLE_EXISTS: Final[str] = "SELECT 1 FROM pg_roles WHERE rolname = $1"
# The server quotes the secret (%L); the secret is never concatenated client-side.
_SQL_ROLE_PASSWORD_STMT: Final[str] = "SELECT format('ALTER ROLE %I PASSWORD %L', $1::text, $2::text)"


def _json_dict(value: object) -> dict[str, Any]:
    """asyncpg returns JSONB as ``str`` unless a codec is registered."""
    if isinstance(value, str):
        loaded: object = json.loads(value)
        return cast("dict[str, Any]", loaded) if isinstance(loaded, dict) else {}
    return dict(cast("Mapping[str, Any]", value)) if isinstance(value, Mapping) else {}


def _to_incident(row: asyncpg.Record) -> IncidentRecord:
    return IncidentRecord(
        incident_id=row["incident_id"],
        token=str(row["token"]).strip(),
        service_name=row["service_name"],
        error_code=row["error_code"],
        state=row["state"],
        raw_alert=_json_dict(row["raw_alert"]),
        option_count=row["option_count"],
        created_at=row["created_at"],
        updated_at=row["updated_at"],
        terminal_at=row["terminal_at"],
        duplicate_count=row["duplicate_count"] or 0,
    )


def _to_audit(row: asyncpg.Record) -> AuditRecord:
    return AuditRecord(
        incident_id=row["incident_id"],
        seq=row["seq"],
        event_type=row["event_type"],
        payload=_json_dict(row["payload"]),
        prev_hash=str(row["prev_hash"]).strip(),
        hash=str(row["hash"]).strip(),
    )


async def ensure_system_incident(pool: asyncpg.Pool) -> None:
    """Create the sentinel incident that owns incident-less audit events."""
    async with pool.acquire() as conn:
        await conn.execute(_SQL_ENSURE_SYSTEM, SYSTEM_INCIDENT_ID, SYSTEM_SERVICE_NAME)


async def sync_mcp_reader_password(pool: asyncpg.Pool, password: str | None) -> bool:
    """Set the ``mcp_reader`` role password from ``MCP_READER_PASSWORD``.

    Returns True when applied. Skips silently (False) if the password is unset
    or the role does not exist. The statement is built server-side with
    ``format(%I, %L)`` so the value is always correctly quoted.
    """
    if not password:
        return False
    async with pool.acquire() as conn:
        if await conn.fetchval(_SQL_ROLE_EXISTS, MCP_READER_ROLE) is None:
            return False
        statement = await conn.fetchval(_SQL_ROLE_PASSWORD_STMT, MCP_READER_ROLE, password)
        if not isinstance(statement, str):
            return False
        await conn.execute(statement)
    return True


class PostgresIncidentRepository:
    def __init__(self, pool: asyncpg.Pool) -> None:
        self._pool = pool

    async def create(
        self,
        *,
        incident_id: UUID,
        token: str,
        service_name: str,
        error_code: str,
        raw_alert: Mapping[str, Any],
    ) -> IncidentRecord:
        async with self._pool.acquire() as conn:
            try:
                row = await conn.fetchrow(
                    _SQL_INSERT, incident_id, token, service_name, error_code, json.dumps(dict(raw_alert))
                )
            except asyncpg.UniqueViolationError as exc:
                if exc.constraint_name == "uq_incidents_active_token":
                    raise TokenCollisionError(token) from exc
                holder = await conn.fetchval(_SQL_ACTIVE_BY_FINGERPRINT, service_name, error_code)
                if holder is None:
                    raise  # primary-key or other conflict: surface it
                raise ActiveFingerprintError(holder) from exc
        if row is None:
            raise RuntimeError("incident insert returned no row")
        return _to_incident(row)

    async def get(self, incident_id: UUID) -> IncidentRecord | None:
        async with self._pool.acquire() as conn:
            row = await conn.fetchrow(_SQL_GET, incident_id)
        return None if row is None else _to_incident(row)

    async def get_active_by_token(self, token: str) -> IncidentRecord | None:
        async with self._pool.acquire() as conn:
            row = await conn.fetchrow(_SQL_BY_TOKEN, token)
        return None if row is None else _to_incident(row)

    async def list_recent(self, limit: int = 100) -> list[IncidentRecord]:
        async with self._pool.acquire() as conn:
            rows = await conn.fetch(_SQL_LIST, SYSTEM_INCIDENT_ID, limit)
        return [_to_incident(r) for r in rows]

    async def list_by_states(
        self,
        states: Collection[IncidentStatus],
        *,
        updated_before: datetime | None = None,
        limit: int = 1000,
    ) -> list[IncidentRecord]:
        async with self._pool.acquire() as conn:
            rows = await conn.fetch(_SQL_LIST_BY_STATES, list(states), SYSTEM_INCIDENT_ID, updated_before, limit)
        return [_to_incident(r) for r in rows]

    async def set_state(self, incident_id: UUID, new: IncidentStatus) -> bool:
        async with self._pool.acquire() as conn:
            status = await conn.execute(_SQL_SET_STATE, incident_id, new)
        return bool(status.endswith(" 1"))

    async def reconcile_stale_inflight(self, stale_seconds: int) -> list[ReclaimedIncident]:
        async with self._pool.acquire() as conn:
            rows = await conn.fetch(_SQL_RECONCILE_STALE, float(stale_seconds))
        return [
            ReclaimedIncident(
                incident_id=r["incident_id"],
                token=str(r["token"]).strip(),
                service_name=r["service_name"],
                error_code=r["error_code"],
            )
            for r in rows
        ]

    async def expire_stale_awaiting(self, ttl_seconds: float) -> list[ReclaimedIncident]:
        async with self._pool.acquire() as conn:
            rows = await conn.fetch(_SQL_EXPIRE_STALE_AWAITING, float(ttl_seconds))
        return [
            ReclaimedIncident(
                incident_id=r["incident_id"],
                token=str(r["token"]).strip(),
                service_name=r["service_name"],
                error_code=r["error_code"],
            )
            for r in rows
        ]

    @staticmethod
    def _reclaimed(rows: list[asyncpg.Record]) -> list[ReclaimedIncident]:
        return [
            ReclaimedIncident(
                incident_id=r["incident_id"],
                token=str(r["token"]).strip(),
                service_name=r["service_name"],
                error_code=r["error_code"],
            )
            for r in rows
        ]

    async def fail_stale_state(
        self, state: InflightStatus, timeout_seconds: float
    ) -> list[ReclaimedIncident]:
        async with self._pool.acquire() as conn:
            rows = await conn.fetch(_SQL_FAIL_STALE_STATE, state, float(timeout_seconds), SYSTEM_INCIDENT_ID)
        return self._reclaimed(rows)

    async def renew_stale_triaging(self, timeout_seconds: float) -> list[ReclaimedIncident]:
        async with self._pool.acquire() as conn:
            rows = await conn.fetch(_SQL_RENEW_STALE_TRIAGING, float(timeout_seconds), SYSTEM_INCIDENT_ID)
        return self._reclaimed(rows)

    async def latest_by_token(self, token: str) -> IncidentRecord | None:
        async with self._pool.acquire() as conn:
            row = await conn.fetchrow(_SQL_LATEST_BY_TOKEN, token, SYSTEM_INCIDENT_ID)
        return None if row is None else _to_incident(row)

    async def busy_tokens(self, cooldown_seconds: float) -> frozenset[str]:
        async with self._pool.acquire() as conn:
            rows = await conn.fetch(_SQL_BUSY_TOKENS, float(cooldown_seconds))
        return frozenset(str(r["token"]).strip() for r in rows)

    async def increment_duplicate_count(self, incident_id: UUID) -> int | None:
        async with self._pool.acquire() as conn:
            value = await conn.fetchval(_SQL_INCREMENT_DUPLICATES, incident_id)
        return None if value is None else int(value)

    async def expire_if_stale(self, token: str, ttl_seconds: float) -> ExpiryOutcome:
        async with self._pool.acquire() as conn:
            row = await conn.fetchrow(_SQL_EXPIRE_IF_STALE, token, float(ttl_seconds))
        if row is None:
            return ExpiryOutcome(found=False)
        return ExpiryOutcome(
            found=True,
            incident_id=row["incident_id"],
            state_before=row["state"],
            expired_now=bool(row["expired_now"]),
            is_expired=bool(row["is_expired"]),
            service_name=row["service_name"],
            error_code=row["error_code"],
        )

    async def record_resolution(
        self,
        incident_id: UUID,
        status: IncidentStatus,
        gates: ResolutionGates | None,
        option_count: int | None = None,
    ) -> bool:
        g = gates or ResolutionGates()
        async with self._pool.acquire() as conn:
            result = await conn.execute(
                _SQL_RECORD_RESOLUTION,
                incident_id,
                status,
                g.tripwire_check_passed,
                g.simulated_step_executed,
                g.confirmation_sms_sent,
                g.audit_record_committed,
                option_count,
            )
        return bool(result.endswith(" 1"))

    async def compare_and_set_state(
        self, incident_id: UUID, expected: IncidentStatus, new: IncidentStatus
    ) -> bool:
        async with self._pool.acquire() as conn:
            status = await conn.execute(_SQL_CAS_STATE, incident_id, expected, new)
        return bool(status.endswith(" 1"))


class PostgresAuditStore:
    def __init__(self, pool: asyncpg.Pool) -> None:
        self._pool = pool

    async def commit(self, record: AuditRecord) -> None:
        if await self.append_event(record.incident_id, record.event_type, record.payload) is None:
            raise LookupError(f"incident {record.incident_id} not found")

    async def append_event(
        self, incident_id: UUID, event_type: str, payload: Mapping[str, Any] | None = None
    ) -> AuditRecord | None:
        async with self._pool.acquire() as conn, conn.transaction():
            if await conn.fetchval(_SQL_LOCK, incident_id) is None:
                return None
            chain = [_to_audit(r) for r in await conn.fetch(_SQL_CHAIN, incident_id)]
            record = rechain(chain, incident_id, event_type, payload or {})
            await conn.execute(
                _SQL_INSERT_AUDIT,
                incident_id,
                record.seq,
                record.event_type,
                json.dumps(record.payload),
                record.prev_hash,
                record.hash,
            )
            return record

    async def records(self, incident_id: UUID) -> list[AuditRecord]:
        async with self._pool.acquire() as conn:
            rows = await conn.fetch(_SQL_CHAIN, incident_id)
        return [_to_audit(r) for r in rows]
