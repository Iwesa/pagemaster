"""Postgres integration tests (skipped unless ``TEST_DATABASE_URL`` is set).

``TEST_DATABASE_URL`` must point at a server where the user may ``CREATE DATABASE``.
Each test loads ``database/10_schema.sql`` and ``30_demo_seed.sql`` into a throwaway
database (``20_roles.sql`` creates cluster-wide roles and has its own tests) and drops it
afterwards.
"""

from __future__ import annotations

import os
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
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

DB_DIR = Path(__file__).resolve().parents[2] / "database"
_PRODUCTION_DB_NAME = "pagemaster"
ALL_TRUE = ResolutionGates(
    tripwire_check_passed=True,
    simulated_step_executed=True,
    confirmation_sms_sent=True,
    audit_record_committed=True,
)


def _sql(name: str) -> str:
    return (DB_DIR / name).read_text(encoding="utf-8-sig")


def _schema_sql() -> str:
    """Schema plus demo seed; roles (20_roles.sql) are cluster-wide and tested separately."""
    return _sql("10_schema.sql") + "\n" + _sql("30_demo_seed.sql")


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


# --- Task 16: periodic in-flight sweep (Req 6.8 to 6.11), database clock ---------------------


class _RecordingSms:
    def __init__(self) -> None:
        self.sent: list[str] = []

    async def send(self, text: str) -> None:
        self.sent.append(text)


async def test_fail_stale_state_is_cas_on_state_and_db_clock(pool: asyncpg.Pool) -> None:
    repo = PostgresIncidentRepository(pool)
    stale_exec = await _new(repo, "S1", "KS1")
    fresh_exec = await _new(repo, "S2", "KS2")
    stale_triage = await _new(repo, "S3", "KS3")
    for iid in (stale_exec, fresh_exec):
        await repo.set_state(iid, "EXECUTING")
    await _backdate(pool, stale_exec, 3600)
    await _backdate(pool, stale_triage, 3600)
    failed = await repo.fail_stale_state("EXECUTING", 120)
    assert [r.incident_id for r in failed] == [stale_exec]
    assert await _state(pool, stale_exec) == "FAILED"
    assert await _state(pool, fresh_exec) == "EXECUTING"
    assert await _state(pool, stale_triage) == "TRIAGING"  # other state untouched
    assert await repo.fail_stale_state("EXECUTING", 120) == []  # second call loses the CAS


async def test_renew_stale_triaging_claims_each_row_once(pool: asyncpg.Pool) -> None:
    repo = PostgresIncidentRepository(pool)
    stale = await _new(repo, "R1", "KR1")
    fresh = await _new(repo, "R2", "KR2")
    await _backdate(pool, stale, 3600)
    first = await repo.renew_stale_triaging(120)
    second = await repo.renew_stale_triaging(120)
    assert [r.incident_id for r in first] == [stale] and second == []
    assert await _state(pool, stale) == "TRIAGING" and await _state(pool, fresh) == "TRIAGING"


async def test_latest_by_token_returns_expired_row(pool: asyncpg.Pool) -> None:
    repo = PostgresIncidentRepository(pool)
    iid = await _new(repo, "L1", "KL1")
    await repo.set_state(iid, "EXPIRED")
    latest = await repo.latest_by_token("L1")
    assert latest is not None and latest.incident_id == iid and latest.state == "EXPIRED"
    assert await repo.latest_by_token("ZZ") is None


async def test_sweep_inflight_fails_notifies_and_frees_locks(pool: asyncpg.Pool) -> None:
    repo = PostgresIncidentRepository(pool)
    dedup = InMemoryDedupStore()
    sms = _RecordingSms()
    lifecycle = Lifecycle(
        incidents=repo,
        audit=PostgresAuditStore(pool),
        dedup=dedup,
        sms=sms,
        triage_timeout_seconds=120,
        executing_timeout_seconds=120,
    )
    triage = await _new(repo, "W1", "KW1")
    execing = await _new(repo, "W2", "KW2")
    await repo.set_state(execing, "EXECUTING")
    for iid, code in ((triage, "KW1"), (execing, "KW2")):
        assert isinstance(await dedup.acquire("auth-db", code, iid), Acquired)
        await _backdate(pool, iid, 3600)
    assert await lifecycle.sweep_inflight() == 2
    assert await _state(pool, triage) == "FAILED" and await _state(pool, execing) == "FAILED"
    assert sorted(sms.sent) == ["INC-W1 FAILED. Re-send the alert.", "INC-W2 FAILED. Re-send the alert."]
    for code in ("KW1", "KW2"):
        assert isinstance(await dedup.acquire("auth-db", code, uuid4()), Acquired)


async def test_no_action_is_terminal_frees_fingerprint_and_stores_option_count(pool: asyncpg.Pool) -> None:
    repo = PostgresIncidentRepository(pool)
    first = await _new(repo, "N1", "E7")
    assert (await repo.get(first)) is not None and (await repo.get(first)).option_count is None  # type: ignore[union-attr]
    assert await repo.record_resolution(first, "NO_ACTION", None, 0)
    row = await repo.get(first)
    assert row is not None and row.state == "NO_ACTION" and row.option_count == 0
    assert await repo.get_active_by_token("N1") is None
    second = await _new(repo, "N1", "E7")  # NO_ACTION is outside the active partial unique indexes
    assert second != first


async def test_option_count_is_kept_when_none_and_range_checked(pool: asyncpg.Pool) -> None:
    repo = PostgresIncidentRepository(pool)
    incident_id = await _new(repo, "N2", "E8")
    assert await repo.record_resolution(incident_id, "AWAITING_APPROVAL", None, 1)
    assert await repo.record_resolution(incident_id, "EXECUTING", None)  # None keeps the value
    row = await repo.get(incident_id)
    assert row is not None and row.option_count == 1
    with pytest.raises(asyncpg.CheckViolationError):
        await repo.record_resolution(incident_id, "FAILED", None, 3)

# ---------------------------------------------------------------------------
# Token cooldown (Req 9.1, 9.2, task 20)
# ---------------------------------------------------------------------------


async def _terminal_at(pool: asyncpg.Pool, incident_id: UUID) -> datetime | None:
    value = await pool.fetchval("SELECT terminal_at FROM incidents WHERE incident_id = $1", incident_id)
    assert value is None or isinstance(value, datetime)
    return value


async def test_terminal_at_is_set_with_the_state_change_on_every_path(pool: asyncpg.Pool) -> None:
    repo = PostgresIncidentRepository(pool)
    set_state = await _new(repo, "T1", "K1")
    cas = await _new(repo, "T2", "K2")
    resolved = await _new(repo, "T3", "K3")
    failed = await _new(repo, "T4", "K4")
    expired = await _awaiting(repo, "T5", "K5")
    active = await _new(repo, "T6", "K6")
    for incident_id in (set_state, cas, resolved, failed, expired, active):
        assert await _terminal_at(pool, incident_id) is None  # NULL while active
    await repo.set_state(set_state, "NO_ACTION")
    assert await repo.compare_and_set_state(cas, "TRIAGING", "BLOCKED_BY_TRIPWIRE")
    assert await repo.record_resolution(resolved, "RESOLVED", ALL_TRUE)
    await repo.set_state(active, "AWAITING_APPROVAL")  # non-terminal change leaves it NULL
    await pool.execute("UPDATE incidents SET updated_at = now() - interval '1 hour' WHERE incident_id = ANY($1::uuid[])", [failed, expired])
    assert [r.incident_id for r in await repo.fail_stale_state("TRIAGING", 60)] == [failed]
    assert [r.incident_id for r in await repo.expire_stale_awaiting(60)] == [expired]
    for incident_id in (set_state, cas, resolved, failed, expired):
        stamped = await pool.fetchval(
            "SELECT terminal_at = updated_at FROM incidents WHERE incident_id = $1", incident_id
        )
        assert stamped is True  # same now() as the state change
    assert await _terminal_at(pool, active) is None


async def test_reconcile_and_expire_if_stale_stamp_terminal_at(pool: asyncpg.Pool) -> None:
    repo = PostgresIncidentRepository(pool)
    orphan = await _new(repo, "U1", "K1")
    awaiting = await _awaiting(repo, "U2", "K2")
    await pool.execute(
        "UPDATE incidents SET updated_at = now() - interval '1 hour' WHERE incident_id = ANY($1::uuid[])",
        [orphan, awaiting],
    )
    assert [r.incident_id for r in await repo.reconcile_stale_inflight(60)] == [orphan]
    assert (await repo.expire_if_stale("U2", 60)).expired_now
    assert await _terminal_at(pool, orphan) is not None
    assert await _terminal_at(pool, awaiting) is not None


async def test_busy_tokens_cover_active_and_cooling_then_free_on_db_clock(pool: asyncpg.Pool) -> None:
    repo = PostgresIncidentRepository(pool)
    await _new(repo, "B1", "K1")
    cooling = await _new(repo, "B2", "K2")
    cooled = await _new(repo, "B3", "K3")
    await repo.set_state(cooling, "FAILED")
    await repo.set_state(cooled, "EXPIRED")
    await pool.execute(
        "UPDATE incidents SET terminal_at = now() - interval '2 hours' WHERE incident_id = $1", cooled
    )
    busy = await repo.busy_tokens(3600)
    assert {"B1", "B2"} <= busy and "B3" not in busy
    assert "B2" not in await repo.busy_tokens(0)  # cooldown 0 frees terminal tokens at once
    assert "B1" in await repo.busy_tokens(0)  # but never an active one
    assert "B3" in await repo.busy_tokens(3 * 3600)


async def test_busy_tokens_ignore_seed_rows_without_cooldown_and_system_row(pool: asyncpg.Pool) -> None:
    from backend.app.services.postgres_store import ensure_system_incident

    await ensure_system_incident(pool)
    repo = PostgresIncidentRepository(pool)
    busy = await repo.busy_tokens(3600)
    assert "00" not in busy  # the system pseudo-incident never blocks a token
    assert "Z1" not in busy  # seeded RESOLVED 110 minutes ago


async def test_token_race_is_decided_by_the_unique_index(pool: asyncpg.Pool) -> None:
    from backend.app.services.incident_store import TokenCollisionError

    repo = PostgresIncidentRepository(pool)
    await _new(repo, "R9", "K1")
    with pytest.raises(TokenCollisionError):
        await _new(repo, "R9", "K2")


async def test_duplicate_counter_is_atomic_and_audit_rows_are_capped(pool: asyncpg.Pool) -> None:
    import asyncio

    from backend.app.api.routes import AlertPayload, AppServices, _record_duplicate
    from backend.app.services.guardrails import verify_chain

    repo = PostgresIncidentRepository(pool)
    audit = PostgresAuditStore(pool)
    incident_id = await _new(repo, "D1", "KD1")
    await audit.append_event(incident_id, "INCIDENT_CREATED", {})
    row = await repo.get(incident_id)
    assert row is not None and row.duplicate_count == 0
    assert await repo.increment_duplicate_count(uuid4()) is None

    # Concurrent increments never lose an update and each caller sees a distinct value.
    seen = await asyncio.gather(*(repo.increment_duplicate_count(incident_id) for _ in range(25)))
    assert sorted(v for v in seen if v is not None) == list(range(1, 26))
    await repo.set_state(incident_id, "FAILED")  # terminal incidents still count
    assert await repo.increment_duplicate_count(incident_id) == 26

    other = await _new(repo, "D2", "KD2")
    await audit.append_event(other, "INCIDENT_CREATED", {})
    services = AppServices(
        graph=None,  # type: ignore[arg-type]
        dedup=InMemoryDedupStore(),
        sms=_NullSms(),
        incidents=repo,
        audit=audit,
        dedup_audit_sample=5,
    )
    payload = AlertPayload(service_name="auth-db", error_code="KD2")
    for _ in range(300):
        await _record_duplicate(services, other, payload)
    chain = await audit.records(other)
    kinds = [r.event_type for r in chain]
    assert kinds.count("ALERT_DEDUPLICATED") == 5
    assert [r.payload["duplicates"] for r in chain if r.event_type == "ALERT_DEDUPLICATED_SUMMARY"] == [105, 205]
    assert verify_chain(chain).valid
    final = await repo.get(other)
    assert final is not None and final.duplicate_count == 300


# ---------------------------------------------------------------------------
# Task 26: database scripts are idempotent, database-name agnostic and split
# ---------------------------------------------------------------------------


@asynccontextmanager
async def _scratch_db() -> AsyncIterator[tuple[str, asyncpg.Connection]]:
    """A connection to a fresh, empty, randomly named database (dropped afterwards)."""
    assert TEST_DATABASE_URL is not None
    name = f"pm_scripts_{uuid4().hex[:12]}"
    admin = await asyncpg.connect(TEST_DATABASE_URL)
    try:
        await admin.execute(f'CREATE DATABASE "{name}"')
        conn = await asyncpg.connect(_with_db(TEST_DATABASE_URL, name))
        try:
            yield name, conn
        finally:
            await conn.close()
    finally:
        await admin.execute(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)')
        await admin.close()


async def _can_manage_roles(conn: asyncpg.Connection) -> bool:
    row = await conn.fetchrow(
        "SELECT rolsuper OR rolcreaterole AS ok FROM pg_roles WHERE rolname = current_user"
    )
    return bool(row is not None and row["ok"])


async def test_scripts_apply_twice_in_a_row_in_a_differently_named_database() -> None:
    async with _scratch_db() as (name, conn):
        assert await conn.fetchval("SELECT current_database()") != _PRODUCTION_DB_NAME
        roles = await _can_manage_roles(conn)
        files = ["10_schema.sql"] + (["20_roles.sql"] if roles else []) + ["30_demo_seed.sql"]
        for _ in range(2):
            for name in files:
                await conn.execute(_sql(name))
            await conn.execute(_sql("migrations/001_hardening_columns.sql"))
        counts = await conn.fetchrow(
            "SELECT (SELECT count(*) FROM approved_runbooks) AS runbooks, "
            "(SELECT count(*) FROM incidents) AS incidents, "
            "(SELECT count(*) FROM audit_trail) AS audit, "
            "(SELECT count(*) FROM service_logs) AS logs"
        )
        assert counts is not None
        assert (counts["runbooks"], counts["incidents"], counts["audit"], counts["logs"]) == (6, 2, 3, 17)
        if roles:
            assert await conn.fetchval(
                "SELECT has_database_privilege('mcp_reader', current_database(), 'CONNECT')"
            )
            assert await conn.fetchval(
                "SELECT has_table_privilege('mcp_reader', 'v_recent_logs', 'SELECT')"
            )
            assert not await conn.fetchval(
                "SELECT has_table_privilege('mcp_reader', 'incidents', 'SELECT')"
            )


async def test_seed_is_absent_when_demo_seed_is_not_applied() -> None:
    async with _scratch_db() as (name, conn):
        await conn.execute(_sql("10_schema.sql"))
        pool = await asyncpg.create_pool(_with_db(TEST_DATABASE_URL or "", name), min_size=1, max_size=1)
        try:
            await ensure_system_incident(pool)
        finally:
            await pool.close()
        ids = {r["incident_id"] for r in await conn.fetch("SELECT incident_id FROM incidents")}
        assert ids <= {SYSTEM_INCIDENT_ID}
        assert await conn.fetchval("SELECT count(*) FROM service_logs") == 0
        assert await conn.fetchval("SELECT count(*) FROM approved_runbooks") == 0
        assert await conn.fetchval("SELECT count(*) FROM audit_trail") == 0
