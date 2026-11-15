"""Postgres integration tests (skipped unless ``TEST_DATABASE_URL`` is set).

``TEST_DATABASE_URL`` must point at a server where the user may ``CREATE DATABASE``.
Each test module run loads ``database/init_mock_logs.sql`` into a throwaway
database (the role/GRANT section is skipped because it names the production
database and cluster-wide roles) and drops it afterwards.
"""

from __future__ import annotations

import os
from collections.abc import AsyncIterator, Callable
from datetime import UTC, datetime
from functools import partial
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit
from uuid import UUID, uuid4

import asyncpg  # type: ignore[import-untyped]
import pytest
import pytest_asyncio

from backend.app.services.dedup import Acquired, Duplicate, InMemoryDedupStore
from backend.app.services.guardrails import ResolutionGates
from backend.app.services.lifecycle import Lifecycle
from backend.app.services.incident_store import ActiveFingerprintError
from backend.app.services.incident_store import SYSTEM_INCIDENT_ID, IncidentStatus
from backend.app.services.postgres_store import (
    PostgresAuditStore,
    PostgresIncidentRepository,
    ensure_system_incident,
)

TEST_DATABASE_URL = os.environ.get("TEST_DATABASE_URL")

pytestmark = pytest.mark.skipif(not TEST_DATABASE_URL, reason="TEST_DATABASE_URL is not set")

SQL_PATH = Path(__file__).resolve().parents[2] / "database" / "init_mock_logs.sql"
_ROLE_START = "-- Restricted MCP reader role"
_SEED_START = "-- Seed data"
ALL_TRUE = ResolutionGates(
    tripwire_check_passed=True,
    simulated_step_executed=True,
    confirmation_sms_sent=True,
    audit_record_committed=True,
)


def _schema_sql() -> str:
    text = SQL_PATH.read_text(encoding="utf-8-sig")  # file starts with a UTF-8 BOM
    start = text.index(_ROLE_START)
    # Cut back to the start of the comment banner line above the marker.
    start = text.rindex("-- ----", 0, start)
    end = text.index(_SEED_START)
    end = text.rindex("-- ----", 0, end)
    return text[:start] + text[end:]


def _with_db(url: str, name: str) -> str:
    parts = urlsplit(url)
    return urlunsplit(parts._replace(path=f"/{name}"))


@pytest_asyncio.fixture()
async def pool() -> AsyncIterator[asyncpg.Pool]:
    assert TEST_DATABASE_URL is not None
    name = f"pm_test_{uuid4().hex[:12]}"
    admin = await asyncpg.connect(TEST_DATABASE_URL)
    try:
        await admin.execute(f'CREATE DATABASE "{name}"')
        scratch = await asyncpg.connect(_with_db(TEST_DATABASE_URL, name))
        try:
            await scratch.execute(_schema_sql())
        finally:
            await scratch.close()
        pool = await asyncpg.create_pool(_with_db(TEST_DATABASE_URL, name), min_size=1, max_size=4)
        try:
            yield pool
        finally:
            await pool.close()
    finally:
        await admin.execute(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)')
        await admin.close()


async def _new(repo: PostgresIncidentRepository, token: str, code: str = "E1") -> UUID:
    incident_id = uuid4()
    await repo.create(
        incident_id=incident_id, token=token, service_name="auth-db", error_code=code, raw_alert={}
    )
    return incident_id


async def test_seed_contains_only_terminal_incidents(pool: asyncpg.Pool) -> None:
    states = {r["state"] for r in await pool.fetch("SELECT state FROM incidents")}
    assert states == {"RESOLVED", "BLOCKED_BY_TRIPWIRE"}
    assert await pool.fetchval("SELECT count(*) FROM service_logs") > 0


async def test_check_constraint_rejects_resolved_without_gates(pool: asyncpg.Pool) -> None:
    repo = PostgresIncidentRepository(pool)
    incident_id = await _new(repo, "A1")
    with pytest.raises(asyncpg.CheckViolationError):
        await repo.set_state(incident_id, "RESOLVED")
    with pytest.raises(asyncpg.CheckViolationError):
        await repo.record_resolution(
            incident_id, "RESOLVED", ResolutionGates(tripwire_check_passed=True)
        )
    row = await repo.get(incident_id)
    assert row is not None and row.state == "TRIAGING"  # failed write left no partial state


async def test_record_resolution_with_all_gates_succeeds(pool: asyncpg.Pool) -> None:
    repo = PostgresIncidentRepository(pool)
    incident_id = await _new(repo, "A2")
    assert await repo.record_resolution(incident_id, "RESOLVED", ALL_TRUE)
    row = await pool.fetchrow(
        "SELECT state, tripwire_check_passed, simulated_step_executed, confirmation_sms_sent, "
        "audit_record_committed FROM incidents WHERE incident_id = $1",
        incident_id,
    )
    assert row is not None and tuple(row.values()) == ("RESOLVED", True, True, True, True)
    assert await repo.record_resolution(uuid4(), "FAILED", None) is False


async def test_record_resolution_keeps_flags_when_none(pool: asyncpg.Pool) -> None:
    repo = PostgresIncidentRepository(pool)
    incident_id = await _new(repo, "A3")
    await repo.record_resolution(incident_id, "EXECUTING", ResolutionGates(tripwire_check_passed=True))
    await repo.record_resolution(incident_id, "FAILED", ResolutionGates(simulated_step_executed=False))
    row = await pool.fetchrow(
        "SELECT tripwire_check_passed, simulated_step_executed FROM incidents WHERE incident_id = $1",
        incident_id,
    )
    assert row is not None and tuple(row.values()) == (True, False)


async def test_failed_frees_the_fingerprint_and_token(pool: asyncpg.Pool) -> None:
    repo = PostgresIncidentRepository(pool)
    first = await _new(repo, "A4", "E9")
    with pytest.raises(ActiveFingerprintError):
        await _new(repo, "A5", "E9")
    assert await repo.record_resolution(first, "FAILED", ResolutionGates(tripwire_check_passed=True))
    second = await _new(repo, "A4", "E9")  # same fingerprint and token are reusable
    assert second != first
    audit = PostgresAuditStore(pool)
    assert await audit.append_event(first, "INCIDENT_FAILED", {"reason": "test"}) is not None


async def test_ensure_system_incident_satisfies_check_constraint(pool: asyncpg.Pool) -> None:
    select = (
        "SELECT state, tripwire_check_passed, simulated_step_executed, confirmation_sms_sent, "
        "audit_record_committed FROM incidents WHERE incident_id = $1"
    )
    try:
        await ensure_system_incident(pool)
    except asyncpg.CheckViolationError as exc:  # pragma: no cover - regression guard
        pytest.fail(f"system incident violated the RESOLVED gate CHECK: {exc}")
    row = await pool.fetchrow(select, SYSTEM_INCIDENT_ID)
    assert row is not None and tuple(row.values()) == ("RESOLVED", True, True, True, True)

    await ensure_system_incident(pool)  # idempotent
    assert await pool.fetchval("SELECT count(*) FROM incidents WHERE incident_id = $1", SYSTEM_INCIDENT_ID) == 1
    row = await pool.fetchrow(select, SYSTEM_INCIDENT_ID)
    assert row is not None and tuple(row.values()) == ("RESOLVED", True, True, True, True)


async def test_reconcile_stale_inflight_uses_db_clock_and_cutoff(pool: asyncpg.Pool) -> None:
    repo = PostgresIncidentRepository(pool)
    stale = await _new(repo, "S1", "E1")
    fresh = await _new(repo, "S2", "E2")
    approval = await _new(repo, "S3", "E3")
    executing = await _new(repo, "S4", "E4")
    await repo.set_state(approval, "AWAITING_APPROVAL")
    await repo.set_state(executing, "EXECUTING")
    await pool.execute(
        "UPDATE incidents SET updated_at = now() - interval '120 seconds' WHERE incident_id = ANY($1::uuid[])",
        [stale, executing, approval],
    )

    reclaimed = await repo.reconcile_stale_inflight(60)

    assert {r.incident_id for r in reclaimed} == {stale, executing}
    by_id = {r.incident_id: r for r in reclaimed}
    assert (by_id[stale].token, by_id[stale].service_name, by_id[stale].error_code) == ("S1", "auth-db", "E1")
    states = {r["incident_id"]: r["state"] for r in await pool.fetch("SELECT incident_id, state FROM incidents")}
    assert states[stale] == "FAILED" and states[executing] == "FAILED"
    assert states[fresh] == "TRIAGING" and states[approval] == "AWAITING_APPROVAL"
    assert await repo.reconcile_stale_inflight(60) == []
    # the fingerprint is free again
    await _new(repo, "S5", "E1")


async def _awaiting(repo: PostgresIncidentRepository, token: str, code: str) -> UUID:
    incident_id = await _new(repo, token, code)
    await repo.set_state(incident_id, "AWAITING_APPROVAL")
    return incident_id


async def test_expire_stale_awaiting_follows_db_clock(pool: asyncpg.Pool) -> None:
    repo = PostgresIncidentRepository(pool)  # no Python clock involved
    stale = await _awaiting(repo, "X1", "E1")
    fresh = await _awaiting(repo, "X2", "E2")
    triaging = await _new(repo, "X3", "E3")
    await pool.execute(
        "UPDATE incidents SET updated_at = now() - interval '120 seconds' WHERE incident_id = ANY($1::uuid[])",
        [stale, triaging],
    )

    expired = await repo.expire_stale_awaiting(60)

    assert [(r.incident_id, r.token, r.service_name, r.error_code) for r in expired] == [
        (stale, "X1", "auth-db", "E1")
    ]
    states = {r["incident_id"]: r["state"] for r in await pool.fetch("SELECT incident_id, state FROM incidents")}
    assert states[stale] == "EXPIRED" and states[fresh] == "AWAITING_APPROVAL"
    assert states[triaging] == "TRIAGING"
    assert await repo.expire_stale_awaiting(60) == []


async def test_expire_if_stale_uses_db_now(pool: asyncpg.Pool) -> None:
    repo = PostgresIncidentRepository(pool)
    iid = await _awaiting(repo, "Y1", "E1")

    out = await repo.expire_if_stale("Y1", 60)
    assert out.found and not out.is_expired and not out.expired_now

    await pool.execute(
        "UPDATE incidents SET updated_at = now() - interval '61 seconds' WHERE incident_id = $1", iid
    )
    out = await repo.expire_if_stale("Y1", 60)
    assert out.found and out.is_expired and out.expired_now and out.incident_id == iid
    assert out.state_before == "AWAITING_APPROVAL" and out.service_name == "auth-db"
    assert await pool.fetchval("SELECT state FROM incidents WHERE incident_id = $1", iid) == "EXPIRED"
    assert (await repo.expire_if_stale("Y1", 60)).found is False


async def test_expire_if_stale_leaves_non_awaiting_and_unknown(pool: asyncpg.Pool) -> None:
    repo = PostgresIncidentRepository(pool)
    iid = await _new(repo, "Z1", "E1")
    await pool.execute("UPDATE incidents SET updated_at = now() - interval '1 hour' WHERE incident_id = $1", iid)

    out = await repo.expire_if_stale("Z1", 60)

    assert out.found and out.is_expired and not out.expired_now and out.state_before == "TRIAGING"
    assert await pool.fetchval("SELECT state FROM incidents WHERE incident_id = $1", iid) == "TRIAGING"
    assert (await repo.expire_if_stale("NO", 60)).found is False


async def test_expire_if_stale_double_call_race(pool: asyncpg.Pool) -> None:
    import asyncio

    repo = PostgresIncidentRepository(pool)
    iid = await _awaiting(repo, "R1", "E1")
    await pool.execute("UPDATE incidents SET updated_at = now() - interval '5 minutes' WHERE incident_id = $1", iid)

    outcomes = await asyncio.gather(*(repo.expire_if_stale("R1", 60) for _ in range(3)))

    assert sum(o.expired_now for o in outcomes) == 1
    assert await pool.fetchval("SELECT state FROM incidents WHERE incident_id = $1", iid) == "EXPIRED"


# ---------------------------------------------------------------------------
# Task 15.2: boot reconciliation and DB-clock expiry through Lifecycle
# ---------------------------------------------------------------------------


def _fixed(moment: datetime) -> datetime:
    return moment


class _NullSms:
    async def send(self, text: str) -> None:
        return None


def _lifecycle(
    pool: asyncpg.Pool,
    *,
    clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    stale: int = 60,
    ttl: int = 60,
    dedup: InMemoryDedupStore | None = None,
) -> Lifecycle:
    return Lifecycle(
        incidents=PostgresIncidentRepository(pool),
        audit=PostgresAuditStore(pool),
        dedup=dedup if dedup is not None else InMemoryDedupStore(),
        sms=_NullSms(),
        approval_ttl_seconds=ttl,
        clock=clock,
        inflight_stale_seconds=stale,
    )


async def _backdate(pool: asyncpg.Pool, incident_id: UUID, seconds: int) -> None:
    await pool.execute(
        "UPDATE incidents SET updated_at = now() - make_interval(secs => $2::double precision) "
        "WHERE incident_id = $1",
        incident_id,
        float(seconds),
    )


async def _state(pool: asyncpg.Pool, incident_id: UUID) -> str:
    value = await pool.fetchval("SELECT state FROM incidents WHERE incident_id = $1", incident_id)
    assert isinstance(value, str)
    return value


async def test_boot_reconciliation_through_lifecycle_fails_only_stale_and_frees_fingerprints(
    pool: asyncpg.Pool,
) -> None:
    repo = PostgresIncidentRepository(pool)
    dedup = InMemoryDedupStore()
    lifecycle = _lifecycle(pool, stale=60, dedup=dedup)
    rows: dict[str, tuple[UUID, str]] = {}
    inflight: tuple[tuple[str, str, str, IncidentStatus], ...] = (
        ("stale_triaging", "B1", "C1", "TRIAGING"),
        ("stale_executing", "B2", "C2", "EXECUTING"),
        ("fresh_triaging", "B3", "C3", "TRIAGING"),
        ("fresh_executing", "B4", "C4", "EXECUTING"),
    )
    for label, token, code, state in inflight:
        incident_id = await _new(repo, token, code)
        assert isinstance(await dedup.acquire("auth-db", code, incident_id), Acquired)
        if state != "TRIAGING":
            await repo.set_state(incident_id, state)
        rows[label] = (incident_id, code)
    for label in ("stale_triaging", "stale_executing"):
        await _backdate(pool, rows[label][0], 120)
    for label in ("fresh_triaging", "fresh_executing"):
        await _backdate(pool, rows[label][0], 5)

    assert await lifecycle.startup_reconcile(None) == 2

    assert await _state(pool, rows["stale_triaging"][0]) == "FAILED"
    assert await _state(pool, rows["stale_executing"][0]) == "FAILED"
    assert await _state(pool, rows["fresh_triaging"][0]) == "TRIAGING"
    assert await _state(pool, rows["fresh_executing"][0]) == "EXECUTING"
    for label in ("stale_triaging", "stale_executing"):
        incident_id, code = rows[label]
        events = await lifecycle.audit.records(incident_id)
        failed = [e for e in events if e.event_type == "INCIDENT_FAILED"]
        assert len(failed) == 1
        assert failed[0].payload == {"reason": "stale_inflight_reconciled"}
        # dedup lock released and the SQL fingerprint is reusable by a fresh incident
        probe = uuid4()
        assert isinstance(await dedup.acquire("auth-db", code, probe), Acquired)
        replacement = await _new(repo, f"N{code}", code)
        assert replacement != incident_id and await _state(pool, replacement) == "TRIAGING"
    for label in ("fresh_triaging", "fresh_executing"):
        assert isinstance(await dedup.acquire("auth-db", rows[label][1], uuid4()), Duplicate)
    assert await lifecycle.startup_reconcile(None) == 0  # idempotent


async def test_awaiting_expiry_follows_sql_updated_at_regardless_of_app_clock_skew(
    pool: asyncpg.Pool,
) -> None:
    repo = PostgresIncidentRepository(pool)
    far_past = datetime(1970, 1, 1, tzinfo=UTC)
    far_future = datetime(2999, 1, 1, tzinfo=UTC)
    outcomes: dict[str, dict[str, str]] = {}
    for name, skewed_now in (("past", far_past), ("future", far_future)):
        lifecycle = _lifecycle(pool, clock=partial(_fixed, skewed_now), ttl=60)
        ids = {
            "stale": await _awaiting(repo, f"{name[0].upper()}1", f"K{name}1"),
            "boundary_fresh": await _awaiting(repo, f"{name[0].upper()}2", f"K{name}2"),
            "fresh": await _awaiting(repo, f"{name[0].upper()}3", f"K{name}3"),
        }
        await _backdate(pool, ids["stale"], 3600)
        await _backdate(pool, ids["boundary_fresh"], 30)

        assert await lifecycle.reap_once() == 1

        outcomes[name] = {label: await _state(pool, iid) for label, iid in ids.items()}
    assert outcomes["past"] == outcomes["future"] == {
        "stale": "EXPIRED",
        "boundary_fresh": "AWAITING_APPROVAL",
        "fresh": "AWAITING_APPROVAL",
    }


async def test_reply_time_expiry_ignores_skewed_app_clock(pool: asyncpg.Pool) -> None:
    repo = PostgresIncidentRepository(pool)
    stale = await _awaiting(repo, "Q1", "KQ1")
    fresh = await _awaiting(repo, "Q2", "KQ2")
    await _backdate(pool, stale, 3600)
    # The point check takes only (token, ttl): a skewed app clock cannot influence it.
    skewed = _lifecycle(pool, clock=lambda: datetime(2999, 1, 1, tzinfo=UTC), ttl=60)
    stale_out = await skewed.incidents.expire_if_stale("Q1", skewed.approval_ttl_seconds)
    fresh_out = await skewed.incidents.expire_if_stale("Q2", skewed.approval_ttl_seconds)
    assert stale_out.expired_now and not fresh_out.is_expired
    assert await _state(pool, stale) == "EXPIRED" and await _state(pool, fresh) == "AWAITING_APPROVAL"
