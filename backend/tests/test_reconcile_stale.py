"""In-memory ``reconcile_stale_inflight`` (Req 6.4)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4

from backend.app.services.incident_store import (
    InMemoryIncidentRepository,
    IncidentStatus,
    ReclaimedIncident,
)

T0 = datetime(2025, 1, 1, tzinfo=UTC)


class Clock:
    def __init__(self) -> None:
        self.now = T0

    def __call__(self) -> datetime:
        return self.now


async def _seed(
    repo: InMemoryIncidentRepository, clock: Clock, token: str, state: IncidentStatus, code: str
) -> object:
    incident_id = uuid4()
    await repo.create(
        incident_id=incident_id, token=token, service_name="svc", error_code=code, raw_alert={}
    )
    if state != "TRIAGING":
        await repo.set_state(incident_id, state)
    return incident_id


async def test_fresh_inflight_untouched_and_stale_failed() -> None:
    clock = Clock()
    repo = InMemoryIncidentRepository(clock)
    stale_t = await _seed(repo, clock, "A1", "TRIAGING", "E1")
    stale_e = await _seed(repo, clock, "A2", "EXECUTING", "E2")
    clock.now = T0 + timedelta(seconds=100)
    fresh_t = await _seed(repo, clock, "A3", "TRIAGING", "E3")
    fresh_e = await _seed(repo, clock, "A4", "EXECUTING", "E4")
    clock.now = T0 + timedelta(seconds=130)

    reclaimed = await repo.reconcile_stale_inflight(60)

    assert {r.incident_id for r in reclaimed} == {stale_t, stale_e}
    for iid in (stale_t, stale_e):
        row = await repo.get(iid)  # type: ignore[arg-type]
        assert row is not None and row.state == "FAILED" and row.updated_at == clock.now
    for iid, state in ((fresh_t, "TRIAGING"), (fresh_e, "EXECUTING")):
        row = await repo.get(iid)  # type: ignore[arg-type]
        assert row is not None and row.state == state


async def test_other_states_untouched() -> None:
    clock = Clock()
    repo = InMemoryIncidentRepository(clock)
    states: list[IncidentStatus] = ["AWAITING_APPROVAL", "FAILED", "EXPIRED", "BLOCKED_BY_TRIPWIRE"]
    ids = [await _seed(repo, clock, f"B{i}", s, f"E{i}") for i, s in enumerate(states)]
    clock.now = T0 + timedelta(hours=1)
    assert await repo.reconcile_stale_inflight(10) == []
    for iid, s in zip(ids, states, strict=True):
        row = await repo.get(iid)  # type: ignore[arg-type]
        assert row is not None and row.state == s and row.updated_at == T0


async def test_boundary_exactly_at_cutoff_is_included() -> None:
    clock = Clock()
    repo = InMemoryIncidentRepository(clock)
    at = await _seed(repo, clock, "C1", "TRIAGING", "E1")
    clock.now = T0 + timedelta(seconds=60)
    just_fresh = await _seed(repo, clock, "C2", "TRIAGING", "E2")
    clock.now = T0 + timedelta(seconds=60)
    reclaimed = await repo.reconcile_stale_inflight(60)
    assert [r.incident_id for r in reclaimed] == [at]
    row = await repo.get(just_fresh)  # type: ignore[arg-type]
    assert row is not None and row.state == "TRIAGING"


async def test_returned_fields_and_idempotence() -> None:
    clock = Clock()
    repo = InMemoryIncidentRepository(clock)
    iid = uuid4()
    await repo.create(incident_id=iid, token="Z9", service_name="auth-db", error_code="E42", raw_alert={})
    clock.now = T0 + timedelta(seconds=11)
    assert await repo.reconcile_stale_inflight(10) == [
        ReclaimedIncident(incident_id=iid, token="Z9", service_name="auth-db", error_code="E42")
    ]
    assert await repo.reconcile_stale_inflight(10) == []
