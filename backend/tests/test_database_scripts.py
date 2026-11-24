"""Static checks of the database scripts and their wiring (no Postgres needed).

Requirements: 7.6 (idempotent scripts), 11.2 (live mode contains no demo data).
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
DB = ROOT / "database"
SCHEMA = DB / "10_schema.sql"
ROLES = DB / "20_roles.sql"
SEED = DB / "30_demo_seed.sql"
MIGRATION = DB / "migrations" / "001_hardening_columns.sql"
INIT_SH = DB / "docker-entrypoint" / "00_init.sh"
APPLY_SH = ROOT / "scripts" / "apply_schema.sh"
ALL_SQL = (SCHEMA, ROLES, SEED, MIGRATION)


def _code(path: Path) -> str:
    """File text with ``--`` comments removed."""
    text = path.read_text(encoding="utf-8-sig")
    return "\n".join(re.sub(r"--.*$", "", line) for line in text.splitlines())


def _statements(path: Path) -> list[str]:
    return [s.strip() for s in _code(path).split(";") if s.strip()]


@pytest.mark.parametrize("path", [*ALL_SQL, INIT_SH, APPLY_SH], ids=lambda p: p.name)
def test_files_exist_are_ascii_and_use_lf(path: Path) -> None:
    raw = path.read_bytes()
    raw.decode("ascii")  # no BOM and no non-ASCII, so any loader encoding works
    assert b"\r" not in raw


def test_old_monolithic_script_is_gone() -> None:
    assert not (DB / "init_mock_logs.sql").exists()


@pytest.mark.parametrize("path", [SCHEMA, SEED])
def test_schema_and_seed_do_not_name_the_database(path: Path) -> None:
    assert "pagemaster" not in _code(path).lower()


def test_roles_script_does_not_hardcode_the_database_name() -> None:
    code = _code(ROLES)
    assert not re.search(r"\bDATABASE\s+\"?pagemaster\b", code, re.IGNORECASE)
    assert code.count("current_database()") >= 3
    assert "IF NOT EXISTS (SELECT FROM pg_roles" in code


@pytest.mark.parametrize("path", [SCHEMA, ROLES, SEED, MIGRATION], ids=lambda p: p.name)
def test_ddl_is_idempotent(path: Path) -> None:
    code = _code(path)
    assert not re.search(r"\bCREATE\s+(UNIQUE\s+)?(TABLE|INDEX)\s+(?!IF\s+NOT\s+EXISTS)", code, re.I)
    assert not re.search(r"\bCREATE\s+(VIEW|FUNCTION)\b", code, re.I)  # must be CREATE OR REPLACE
    for trigger in re.findall(r"\bCREATE\s+TRIGGER\s+(\w+)", code, re.I):
        assert re.search(rf"DROP\s+TRIGGER\s+IF\s+EXISTS\s+{trigger}\b", code, re.I)
    assert not re.search(r"\bCREATE\s+ROLE\b", code, re.I) or "IF NOT EXISTS (SELECT FROM pg_roles" in code


@pytest.mark.parametrize("path", [SCHEMA, ROLES, SEED, MIGRATION], ids=lambda p: p.name)
def test_every_insert_is_guarded(path: Path) -> None:
    for statement in _statements(path):
        if re.search(r"\bINSERT\s+INTO\b", statement, re.I):
            assert re.search(r"ON\s+CONFLICT|NOT\s+EXISTS", statement, re.I), statement[:80]


def test_schema_keeps_the_hardening_constraints() -> None:
    code = _code(SCHEMA)
    for needle in (
        "resolved_requires_all_gates",
        "option_count",
        "terminal_at",
        "duplicate_count",
        "uq_incidents_active_token",
        "uq_incidents_active_fingerprint",
        "'FAILED', 'EXPIRED', 'NO_ACTION'",
        "trg_audit_trail_no_update_delete",
        "trg_audit_trail_no_truncate",
        "v_recent_logs",
        "v_service_topology",
        "v_approved_runbooks",
    ):
        assert needle in code, needle


def test_schema_has_no_demo_data_and_seed_holds_the_hash_vector_rows() -> None:
    schema = _code(SCHEMA)
    assert not re.search(r"\bINSERT\b", schema, re.I)
    seed = _code(SEED)
    assert "00000000-0000-4000-8000-0000000000a4" in seed
    assert "INCIDENT_CREATED" in seed and "TRIPWIRE_PASSED" in seed and "TRIPWIRE_BLOCKED" in seed


def test_compose_mounts_the_split_scripts_and_gates_the_seed_on_dry_run() -> None:
    compose = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    for name in ("10_schema.sql", "20_roles.sql", "30_demo_seed.sql", "00_init.sh"):
        assert name in compose, name
    assert "init_mock_logs" not in compose
    assert "DEMO_SEED: ${DRY_RUN:-true}" in compose
    # Only the wrapper sits in the initdb directory; the SQL files must not run unconditionally.
    for line in compose.splitlines():
        if "30_demo_seed.sql" in line:
            assert "/docker-entrypoint-initdb.d/" not in line


def test_init_wrapper_applies_in_order_and_seeds_only_on_demo_seed() -> None:
    sh = INIT_SH.read_text(encoding="utf-8")
    assert sh.startswith("#!/bin/sh")
    assert "psql -v ON_ERROR_STOP=1" in sh and '-U "$POSTGRES_USER"' in sh and '-d "$POSTGRES_DB"' in sh
    assert sh.index("10_schema.sql") < sh.index("20_roles.sql") < sh.index("30_demo_seed.sql")
    assert "DEMO_SEED" in sh


def test_apply_script_is_posix_strict_and_has_no_database_name() -> None:
    sh = APPLY_SH.read_text(encoding="utf-8")
    assert sh.startswith("#!/bin/sh") and "set -eu" in sh
    assert "--demo" in sh and "Usage:" in sh and "DATABASE_URL" in sh
    assert "pagemaster" not in sh.replace("Pagemaster", "").lower()
    assert sh.index("10_schema.sql") < sh.index("20_roles.sql") < sh.index("30_demo_seed.sql")
