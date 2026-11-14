"""Approval expiry, the reaper and startup reconciliation (Req 6, Property 10)."""

from __future__ import annotations

import asyncio
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID, uuid4

from fastapi import BackgroundTasks
from fastapi.testclient import TestClient

from backend.app.api.routes import AppServices, _handle_reply
from backend.app.main import Settings, build_in_memory_services, create_app
from backend.app.services.africastalking_client import AfricasTalkingSmsAdapter
from backend.app.services.dedup import Acquired, Duplicate
from backend.app.services.incident_store import (
    TERMINAL_STATUSES,
    InMemoryAuditStore,
    InMemoryIncidentRepository,
    IncidentRecord,
    IncidentStatus,
)

SERVICE = "auth-db"
CODE = "E1"
TTL = 900
ALL_TRUE = {
    "tripwire_check_passed": True,
    "simulated_step_executed": True,
    "confirmation_sms_sent": True,
    "audit_record_committed": True,
}


class Clock:
    def __init__(self) -> None:
        self.now = datetime(2025, 1, 1, tzinfo=UTC)

    def __call__(self) -> datetime:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += timedelta(seconds=seconds)


class RecordingGraph:
    """Stands in for the compiled graph; ``calls`` is every resume (= infrastructure mutation)."""

    def __init__(self) -> None:
        self.calls: list[Any] = []

    async def ainvoke(self, input: Any, config: Any = None) -> Any:
        self.calls.append(input)
        return {"status": "RESOLVED", "gates": ALL_TRUE}


def make_services() -> tuple[AppServices, Clock, RecordingGraph]:
    clock = Clock()
    graph = RecordingGraph()
    base = build_in_memory_services(Settings(use_in_memory=True))
    repo = InMemoryIncidentRepository(clock)
    services = replace(
        base,
        graph=graph,
        incidents=repo,
        audit=InMemoryAuditStore(repo),
        approval_ttl_seconds=TTL,
        clock=clock,
    )
    return services, clock, graph


async def add_incident(
    services: AppServices,
    state: IncidentStatus,
    *,
    token: str = "7A",
    service: str = SERVICE,
    code: str = CODE,
) -> IncidentRecord:
    incident_id = uuid4()
    assert isinstance(await services.dedup.acquire(service, code, incident_id), Acquired)
    incident = await services.incidents.create(
        incident_id=incident_id, token=token, service_name=service, error_code=code, raw_alert={}
    )
    await services.audit.append_event(incident_id, "INCIDENT_CREATED", {})
    if state != "TRIAGING":
        await services.incidents.set_state(incident_id, state)
    return incident


async def reply(services: AppServices, body: str) -> None:
    background = BackgroundTasks()
    await _handle_reply(services, background, body)
    await background()


def outbox(services: AppServices) -> list[str]:
    sms = services.sms
    assert isinstance(sms, AfricasTalkingSmsAdapter)
    return [m.text for m in sms.outbox]


async def state_of(services: AppServices, incident_id: UUID) -> str:
    row = await services.incidents.get(incident_id)
    assert row is not None
    return row.state


async def events_of(services: AppServices, incident_id: UUID) -> list[str]:
    return [r.event_type for r in await services.audit.records(incident_id)]


async def fingerprint_free(services: AppServices) -> bool:
    probe_id = uuid4()
    probe = await services.dedup.acquire(SERVICE, CODE, probe_id)
    if isinstance(probe, Duplicate):
        return False
    await services.dedup.release(SERVICE, CODE, probe_id)
    return True


def test_expired_is_terminal() -> None:
    assert "EXPIRED" in TERMINAL_STATUSES


async def test_reply_after_ttl_expires_without_mutation() -> None:
    services, clock, graph = make_services()
    incident = await add_incident(services, "AWAITING_APPROVAL")
    clock.advance(TTL + 1)
    await reply(services, "7A-1")
    assert await state_of(services, incident.incident_id) == "EXPIRED"
    assert graph.calls == []
    assert (await events_of(services, incident.incident_id))[-1] == "INCIDENT_EXPIRED"
    assert await fingerprint_free(services)
    assert outbox(services) == ["INC-7A no longer active. No action taken."]


async def test_reply_within_ttl_resolves() -> None:
    services, clock, graph = make_services()
    incident = await add_incident(services, "AWAITING_APPROVAL")
    clock.advance(TTL - 1)
    await reply(services, "7A-1")
    assert len(graph.calls) == 1
    assert await state_of(services, incident.incident_id) == "RESOLVED"


async def test_second_reply_after_expiry_is_inactive() -> None:
    services, clock, graph = make_services()
    incident = await add_incident(services, "AWAITING_APPROVAL")
    clock.advance(TTL + 1)
    await reply(services, "7A-1")
    await reply(services, "7A-1")
    assert graph.calls == []
    assert await state_of(services, incident.incident_id) == "EXPIRED"
    assert (await events_of(services, incident.incident_id)).count("INCIDENT_EXPIRED") == 1


async def test_expired_frees_fingerprint_for_a_new_incident() -> None:
    services, clock, _ = make_services()
    first = await add_incident(services, "AWAITING_APPROVAL")
    clock.advance(TTL + 1)
    await reply(services, "7A-2")
    second = await add_incident(services, "TRIAGING", token="9Z")
    assert second.incident_id != first.incident_id
    assert await state_of(services, second.incident_id) == "TRIAGING"


async def test_reaper_expires_stale_and_spares_fresh() -> None:
    services, clock, graph = make_services()
    stale = await add_incident(services, "AWAITING_APPROVAL", token="AA", service="svc-a")
    clock.advance(TTL - 10)
    fresh = await add_incident(services, "AWAITING_APPROVAL", token="BB", service="svc-b")
    triaging = await add_incident(services, "TRIAGING", token="CC", service="svc-c")
    clock.advance(20)
    assert await services.lifecycle.reap_once() == 1
    assert await state_of(services, stale.incident_id) == "EXPIRED"
    assert await state_of(services, fresh.incident_id) == "AWAITING_APPROVAL"
    assert await state_of(services, triaging.incident_id) == "TRIAGING"
    assert "INCIDENT_EXPIRED" in await events_of(services, stale.incident_id)
    assert graph.calls == []
    probe = await services.dedup.acquire("svc-a", CODE, uuid4())
    assert isinstance(probe, Acquired)


async def test_reaper_survives_an_iteration_failure() -> None:
    services, clock, _ = make_services()
    incident = await add_incident(services, "AWAITING_APPROVAL")
    clock.advance(TTL + 1)
    real = services.incidents.list_by_states
    attempts = 0

    async def flaky(*args: Any, **kwargs: Any) -> list[IncidentRecord]:
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise RuntimeError("db down")
        return await real(*args, **kwargs)

    repo = services.incidents
    assert isinstance(repo, InMemoryIncidentRepository)
    repo.list_by_states = flaky  # type: ignore[method-assign]
    task = asyncio.create_task(services.lifecycle.run_reaper(0.01))
    try:
        for _ in range(200):
            if await state_of(services, incident.incident_id) == "EXPIRED":
                break
            await asyncio.sleep(0.01)
    finally:
        task.cancel()
    assert attempts >= 2
    assert await state_of(services, incident.incident_id) == "EXPIRED"


async def test_reconcile_fails_orphans_and_spares_awaiting_approval() -> None:
    services, _, graph = make_services()
    triaging = await add_incident(services, "TRIAGING", token="AA", service="svc-a")
    executing = await add_incident(services, "EXECUTING", token="BB", service="svc-b")
    awaiting = await add_incident(services, "AWAITING_APPROVAL", token="CC", service="svc-c")
    assert await services.lifecycle.reconcile_orphans() == 2
    for orphan, svc in ((triaging, "svc-a"), (executing, "svc-b")):
        assert await state_of(services, orphan.incident_id) == "FAILED"
        assert "INCIDENT_RECONCILED" in await events_of(services, orphan.incident_id)
        assert isinstance(await services.dedup.acquire(svc, CODE, uuid4()), Acquired)
    assert await state_of(services, awaiting.incident_id) == "AWAITING_APPROVAL"
    assert "INCIDENT_RECONCILED" not in await events_of(services, awaiting.incident_id)
    assert isinstance(await services.dedup.acquire("svc-c", CODE, uuid4()), Duplicate)
    assert graph.calls == []


def test_lifespan_reconciles_on_startup_and_stops_reaper() -> None:
    services, _, _ = make_services()
    app = create_app(services, Settings(use_in_memory=True, dry_run=True, reaper_interval_seconds=0.05))

    async def seed() -> UUID:
        return (await add_incident(services, "EXECUTING")).incident_id

    incident_id = asyncio.run(seed())
    with TestClient(app):
        assert asyncio.run(state_of(services, incident_id)) == "FAILED"
