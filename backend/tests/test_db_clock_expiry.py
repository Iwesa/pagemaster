"""In-memory ``expire_stale_awaiting`` / ``expire_if_stale`` semantics (Req 6.1, 6.2, 6.7)."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

from backend.app.services.incident_store import InMemoryIncidentRepository, IncidentStatus

T0 = datetime(2025, 1, 1, tzinfo=UTC)
TTL = 60.0


class Clock:
    def __init__(self) -> None:
        self.now = T0

    def __call__(self) -> datetime:
        return self.now


async def _seed(repo: InMemoryIncidentRepository, token: str, state: IncidentStatus, code: str) -> UUID:
    incident_id = uuid4()
    await repo.create(
        incident_id=incident_id, token=token, service_name="svc", error_code=code, raw_alert={}
    )
    if state != "TRIAGING":
        await repo.set_state(incident_id, state)
    return incident_id


async def test_fresh_not_expired() -> None:
    clock = Clock()
    repo = InMemoryIncidentRepository(clock)
    iid = await _seed(repo, "A1", "AWAITING_APPROVAL", "E1")
    clock.now = T0 + timedelta(seconds=59)

    out = await repo.expire_if_stale("A1", TTL)

    assert out.found and out.incident_id == iid
    assert not out.is_expired and not out.expired_now and out.state_before == "AWAITING_APPROVAL"
    row = await repo.get(iid)
    assert row is not None and row.state == "AWAITING_APPROVAL"
    assert await repo.expire_stale_awaiting(TTL) == []


async def test_boundary_equality_counts_as_expired() -> None:
    clock = Clock()
    repo = InMemoryIncidentRepository(clock)
    iid = await _seed(repo, "B1", "AWAITING_APPROVAL", "E1")
    clock.now = T0 + timedelta(seconds=60)

    out = await repo.expire_if_stale("B1", TTL)

    assert out.expired_now and out.is_expired
    assert (out.service_name, out.error_code) == ("svc", "E1")
    row = await repo.get(iid)
    assert row is not None and row.state == "EXPIRED"


async def test_stale_expires_exactly_once_under_concurrency() -> None:
    clock = Clock()
    repo = InMemoryIncidentRepository(clock)
    await _seed(repo, "C1", "AWAITING_APPROVAL", "E1")
    clock.now = T0 + timedelta(seconds=120)

    a, b = await asyncio.gather(repo.expire_if_stale("C1", TTL), repo.expire_if_stale("C1", TTL))

    assert sorted([a.expired_now, b.expired_now]) == [False, True]
    assert sum(o.found for o in (a, b)) == 1  # the loser no longer sees an active row


async def test_sweep_expires_only_stale_awaiting_exactly_once() -> None:
    clock = Clock()
    repo = InMemoryIncidentRepository(clock)
    stale = await _seed(repo, "D1", "AWAITING_APPROVAL", "E1")
    triaging = await _seed(repo, "D2", "TRIAGING", "E2")
    executing = await _seed(repo, "D3", "EXECUTING", "E3")
    clock.now = T0 + timedelta(seconds=30)
    fresh = await _seed(repo, "D4", "AWAITING_APPROVAL", "E4")
    clock.now = T0 + timedelta(seconds=70)

    first, second = await asyncio.gather(repo.expire_stale_awaiting(TTL), repo.expire_stale_awaiting(TTL))

    assert [r.incident_id for r in first + second] == [stale]
    states = {i: (await repo.get(i)).state for i in (stale, triaging, executing, fresh)}  # type: ignore[union-attr]
    assert states == {
        stale: "EXPIRED",
        triaging: "TRIAGING",
        executing: "EXECUTING",
        fresh: "AWAITING_APPROVAL",
    }


async def test_non_awaiting_states_untouched_by_point_check() -> None:
    clock = Clock()
    repo = InMemoryIncidentRepository(clock)
    t = await _seed(repo, "E1", "TRIAGING", "E1")
    e = await _seed(repo, "E2", "EXECUTING", "E2")
    clock.now = T0 + timedelta(hours=1)

    for token, iid, state in (("E1", t, "TRIAGING"), ("E2", e, "EXECUTING")):
        out = await repo.expire_if_stale(token, TTL)
        assert out.found and out.state_before == state and not out.expired_now
        row = await repo.get(iid)
        assert row is not None and row.state == state


async def test_unknown_or_terminal_token_not_found() -> None:
    clock = Clock()
    repo = InMemoryIncidentRepository(clock)
    iid = await _seed(repo, "F1", "AWAITING_APPROVAL", "E1")
    await repo.set_state(iid, "FAILED")
    clock.now = T0 + timedelta(hours=1)

    assert (await repo.expire_if_stale("ZZ", TTL)).found is False
    assert (await repo.expire_if_stale("F1", TTL)).found is False
    row = await repo.get(iid)
    assert row is not None and row.state == "FAILED"
