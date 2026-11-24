"""Token cooldown and exact exhaustion (Req 9.1, 9.2, task 20)."""

from __future__ import annotations

from dataclasses import replace
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient

from backend.app.main import Settings, create_app
from backend.app.services.dedup import Acquired
from backend.app.services.incident_store import (
    SYSTEM_INCIDENT_ID,
    TERMINAL_STATUSES,
    TOKEN_ALPHABET,
    IncidentStatus,
    InMemoryIncidentRepository,
    TokenExhaustedError,
    generate_token,
    token_space,
)
from backend.tests.test_expiry import Clock, add_incident, make_services

COOLDOWN = 3600


async def _create(repo: InMemoryIncidentRepository, token: str, code: str) -> UUID:
    incident_id = uuid4()
    await repo.create(
        incident_id=incident_id, token=token, service_name="svc", error_code=code, raw_alert={}
    )
    return incident_id


def test_token_space_is_36_by_36_and_two_characters() -> None:
    space = token_space()
    assert len(space) == 1296 == len(set(space))
    assert all(len(t) == 2 and set(t) <= set(TOKEN_ALPHABET) for t in space)


def test_generate_token_draws_only_from_free_tokens() -> None:
    busy = set(token_space("AB")) - {"BA"}
    assert {generate_token(busy, "AB") for _ in range(20)} == {"BA"}
    with pytest.raises(TokenExhaustedError):
        generate_token(token_space("AB"), "AB")


@pytest.mark.asyncio
async def test_token_is_busy_while_active_and_during_cooldown_then_free() -> None:
    clock = Clock()
    repo = InMemoryIncidentRepository(clock)
    incident_id = await _create(repo, "AB", "E1")
    assert await repo.busy_tokens(COOLDOWN) == {"AB"}  # active
    await repo.set_state(incident_id, "RESOLVED")
    clock.advance(COOLDOWN - 1)
    assert await repo.busy_tokens(COOLDOWN) == {"AB"}  # cooling down
    clock.advance(1)
    assert await repo.busy_tokens(COOLDOWN) == frozenset()  # exactly the cooldown ago: free
    assert await repo.busy_tokens(0) == frozenset()


@pytest.mark.asyncio
@pytest.mark.parametrize("state", sorted(TERMINAL_STATUSES))
async def test_every_terminal_state_stamps_terminal_at(state: IncidentStatus) -> None:
    clock = Clock()
    repo = InMemoryIncidentRepository(clock)
    incident_id = await _create(repo, "AB", "E1")
    assert (row0 := await repo.get(incident_id)) is not None and row0.terminal_at is None
    clock.advance(5)
    await repo.compare_and_set_state(incident_id, "TRIAGING", state)
    row = await repo.get(incident_id)
    assert row is not None and row.terminal_at == clock.now


@pytest.mark.asyncio
async def test_sweeps_stamp_terminal_at_with_the_state_change() -> None:
    clock = Clock()
    repo = InMemoryIncidentRepository(clock)
    stale = await _create(repo, "AA", "E1")
    awaiting = await _create(repo, "BB", "E2")
    executing = await _create(repo, "CC", "E3")
    await repo.set_state(awaiting, "AWAITING_APPROVAL")
    await repo.set_state(executing, "EXECUTING")
    clock.advance(500)
    await repo.reconcile_stale_inflight(60)
    await repo.expire_stale_awaiting(60)
    for incident_id in (stale, awaiting, executing):
        row = await repo.get(incident_id)
        assert row is not None and row.state in TERMINAL_STATUSES and row.terminal_at == clock.now
    assert await repo.busy_tokens(COOLDOWN) == {"AA", "BB", "CC"}


@pytest.mark.asyncio
async def test_exhaustion_is_exact_with_every_token_busy() -> None:
    repo = InMemoryIncidentRepository(Clock())
    space = token_space("AB")  # AA AB BA BB
    for i, token in enumerate(space):
        busy = await repo.busy_tokens(COOLDOWN)
        assert generate_token(busy, "AB") not in busy
        await _create(repo, token, f"E{i}")
    with pytest.raises(TokenExhaustedError):
        generate_token(await repo.busy_tokens(COOLDOWN), "AB")


def _alert(code: str) -> dict[str, str]:
    return {"service_name": "svc-new", "error_code": code, "summary": "boom"}


@pytest.mark.asyncio
async def test_exhausted_alert_returns_503_creates_nothing_and_frees_lock() -> None:
    services, clock, _ = make_services()
    services = replace(services, token_alphabet="A")  # only token "AA"
    await add_incident(services, "AWAITING_APPROVAL", token="AA")
    app = create_app(services, Settings(use_in_memory=True, dry_run=True, reaper_interval_seconds=60.0))
    with TestClient(app) as client:
        response = client.post("/webhooks/alerts", json=_alert("E9"))
    assert response.status_code == 503
    assert response.headers["Retry-After"] == "30"
    assert len(await services.incidents.list_recent()) == 1  # nothing created
    assert isinstance(await services.dedup.acquire("svc-new", "E9", uuid4()), Acquired)  # lock freed
    chain = await services.audit.records(SYSTEM_INCIDENT_ID)
    exhausted = [r for r in chain if r.event_type == "TOKEN_EXHAUSTED"]
    assert [r.payload for r in exhausted] == [{"reason": "no_free_token"}]


@pytest.mark.asyncio
async def test_cooling_token_blocks_alert_until_cooldown_elapses() -> None:
    services, clock, _ = make_services()
    services = replace(services, token_alphabet="A")
    done = await add_incident(services, "TRIAGING", token="AA", service="old")
    await services.incidents.set_state(done.incident_id, "RESOLVED")
    app = create_app(services, Settings(use_in_memory=True, dry_run=True, reaper_interval_seconds=60.0))
    with TestClient(app) as client:
        assert client.post("/webhooks/alerts", json=_alert("E1")).status_code == 503
        clock.advance(COOLDOWN)
        assert client.post("/webhooks/alerts", json=_alert("E2")).status_code == 202


def test_zero_cooldown_reuses_a_terminal_token_immediately() -> None:
    import asyncio

    services, _, _ = make_services()
    services = replace(services, token_alphabet="A", token_cooldown_seconds=0)
    done = asyncio.run(add_incident(services, "RESOLVED", token="AA", service="old"))
    assert done.token == "AA"
    app = create_app(services, Settings(use_in_memory=True, dry_run=True, reaper_interval_seconds=60.0))
    with TestClient(app) as client:
        assert client.post("/webhooks/alerts", json=_alert("E1")).status_code == 202


def test_settings_token_cooldown_default_override_and_minimum() -> None:
    assert Settings.from_env({}).token_cooldown_seconds == 3600
    assert Settings.from_env({"TOKEN_COOLDOWN_SECONDS": "120"}).token_cooldown_seconds == 120
    assert Settings.from_env({"TOKEN_COOLDOWN_SECONDS": "0"}).token_cooldown_seconds == 0
    assert Settings.from_env({"TOKEN_COOLDOWN_SECONDS": "-5"}).token_cooldown_seconds == 0
    assert Settings.from_env({"TOKEN_COOLDOWN_SECONDS": "x"}).token_cooldown_seconds == 3600
