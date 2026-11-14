"""Postgres integration tests (skipped unless ``TEST_DATABASE_URL`` is set).

``TEST_DATABASE_URL`` must point at a server where the user may ``CREATE DATABASE``.
Each test module run loads ``database/init_mock_logs.sql`` into a throwaway
database (the role/GRANT section is skipped because it names the production
database and cluster-wide roles) and drops it afterwards.
"""

from __future__ import annotations

import os
from collections.abc import AsyncIterator
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit
from uuid import UUID, uuid4

import asyncpg  # type: ignore[import-untyped]
import pytest
import pytest_asyncio

from backend.app.services.guardrails import ResolutionGates
from backend.app.services.incident_store import ActiveFingerprintError
from backend.app.services.incident_store import SYSTEM_INCIDENT_ID
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
