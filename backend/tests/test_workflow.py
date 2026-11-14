"""Integration tests: deduplication, HITL interrupt/resume, Tripwire, RESOLVED gating.

Uses ``MemorySaver`` and in-memory/fake ports; no Postgres, Redis, or network.
"""

from __future__ import annotations

from collections.abc import Iterator, Sequence
from typing import Any, cast
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient
from langgraph.checkpoint.memory import MemorySaver
from langgraph.types import Command

from backend.app.agents.graph import IncidentState, build_graph
from backend.app.agents.ports import Ports, Runbook, TelemetryContext
from backend.app.api.routes import AppServices
from backend.app.main import Settings, build_in_memory_services, create_app
from backend.app.services.guardrails import AuditRecord, verify_chain
from backend.app.services.incident_store import InMemoryAuditStore
from backend.app.services.twilio_client import TwilioSmsAdapter

SERVICE = "auth-db"
TOKEN = "7A"
RUNBOOKS = (
    Runbook(action_id="RB-AUTHDB-RESET-POOL", title="Reset pool", target_host=SERVICE),
    Runbook(action_id="RB-AUTHDB-FAILOVER", title="Failover", target_host=SERVICE),
)


class FakeTelemetry:
    def __init__(self, runbooks: Sequence[Runbook] = RUNBOOKS) -> None:
        self._runbooks = tuple(runbooks)

    async def get_incident_context(self, service_name: str) -> TelemetryContext:
        return TelemetryContext(root_cause="pool exhausted", runbooks=self._runbooks)


class FakeSms:
    def __init__(self, fail_on_suffix: str | None = None) -> None:
        self.sent: list[str] = []
        self._fail_on_suffix = fail_on_suffix

    async def send(self, text: str) -> None:
        if self._fail_on_suffix and text.endswith(self._fail_on_suffix):
            raise RuntimeError("sms provider down")
        self.sent.append(text)


class FakeAudit:
    """Wraps the real in-memory chain store; can fail on a chosen event type."""

    def __init__(self, fail_event: str | None = None) -> None:
        self.store = InMemoryAuditStore()
        self._fail_event = fail_event

    async def commit(self, record: AuditRecord) -> None:
        if record.event_type == self._fail_event:
            raise RuntimeError("audit store unavailable")
        await self.store.commit(record)


class FakeRunbooks:
    def __init__(self, succeed: bool = True) -> None:
        self.executed: list[tuple[str, str]] = []
        self._succeed = succeed

    async def list_approved(self, service_name: str) -> Sequence[Runbook]:
        return RUNBOOKS

    async def execute(self, *, target_host: str, action_id: str, token: str) -> bool:
        self.executed.append((target_host, action_id))
        return self._succeed


class Rig:
    def __init__(
        self,
        *,
        telemetry: FakeTelemetry | None = None,
        sms: FakeSms | None = None,
        audit: FakeAudit | None = None,
        runbooks: FakeRunbooks | None = None,
    ) -> None:
        self.sms = sms or FakeSms()
        self.audit = audit or FakeAudit()
        self.runbooks = runbooks or FakeRunbooks()
        ports = Ports(
            telemetry=telemetry or FakeTelemetry(),
            sms=self.sms,
            audit=self.audit,
            runbooks=self.runbooks,
        )
        self.graph = build_graph(ports, MemorySaver())
        self.incident_id = uuid4()
        self.config: Any = {"configurable": {"thread_id": str(self.incident_id)}}

    def start_input(self) -> IncidentState:
        return {
            "incident_id": str(self.incident_id),
            "token": TOKEN,
            "service_name": SERVICE,
            "error_code": "DB_POOL_EXHAUSTED",
            "alert_summary": "pool at 100%",
            "audit_records": [],
        }

    async def start(self) -> Any:
        return await self.graph.ainvoke(self.start_input(), self.config)

    async def resume(self, choice: str) -> Any:
        return await self.graph.ainvoke(Command(resume={"choice": choice}), self.config)

    async def chain(self) -> list[AuditRecord]:
        return await self.audit.store.records(self.incident_id)


# ---------------------------------------------------------------------------
# HITL interrupt / resume (Req 4.3)
# ---------------------------------------------------------------------------


async def test_graph_pauses_at_approval_gate_then_resumes_and_resolves() -> None:
    rig = Rig()
    paused = await rig.start()
    snapshot = await rig.graph.aget_state(rig.config)
    assert snapshot.next == ("human_approval_gate",)
    assert paused["status"] == "AWAITING_APPROVAL"
    assert len(rig.sms.sent) == 1 and rig.sms.sent[0].startswith(f"INC-{TOKEN} ")
    assert len(rig.sms.sent[0]) <= 160
    assert rig.runbooks.executed == []  # nothing runs before approval

    done = await rig.resume("1")
    assert done["status"] == "RESOLVED"
    assert rig.runbooks.executed == [(SERVICE, "RB-AUTHDB-RESET-POOL")]
    assert rig.sms.sent[-1] == f"INC-{TOKEN} RESOLVED"
    assert done["gates"] == {
        "tripwire_check_passed": True,
        "simulated_step_executed": True,
        "confirmation_sms_sent": True,
        "audit_record_committed": True,
    }
    assert (await rig.graph.aget_state(rig.config)).next == ()
    assert verify_chain(await rig.chain()).valid


async def test_choice_2_selects_second_runbook() -> None:
    rig = Rig()
    await rig.start()
    done = await rig.resume("2")
    assert done["status"] == "RESOLVED"
    assert rig.runbooks.executed == [(SERVICE, "RB-AUTHDB-FAILOVER")]


async def test_resume_survives_new_graph_instance_sharing_checkpointer() -> None:
    saver = MemorySaver()
    audit, sms, runbooks = FakeAudit(), FakeSms(), FakeRunbooks()

    def make() -> Any:
        return build_graph(
            Ports(telemetry=FakeTelemetry(), sms=sms, audit=audit, runbooks=runbooks), saver
        )

    incident_id = uuid4()
    config: Any = {"configurable": {"thread_id": str(incident_id)}}
    first = make()
    await first.ainvoke(
        {
            "incident_id": str(incident_id),
            "token": TOKEN,
            "service_name": SERVICE,
            "error_code": "E",
            "alert_summary": "x",
            "audit_records": [],
        },
        config,
    )
    done = await make().ainvoke(Command(resume={"choice": "1"}), config)  # "restarted" process
    assert done["status"] == "RESOLVED"
    assert len(sms.sent) == 2


# ---------------------------------------------------------------------------
# Tripwire blocking (Req 5.2)
# ---------------------------------------------------------------------------


async def test_tripwire_blocks_runbook_targeting_another_host() -> None:
    wrong_host = (Runbook(action_id="RB-AUTHDB-RESET-POOL", title="t", target_host="payment-gateway"),)
    rig = Rig(telemetry=FakeTelemetry(wrong_host))
    await rig.start()
    done = await rig.resume("1")
    assert done["status"] == "BLOCKED_BY_TRIPWIRE"
    assert rig.runbooks.executed == []
    assert not any(m.endswith("RESOLVED") for m in rig.sms.sent)
    assert done["gates"]["tripwire_check_passed"] is False
    assert done["gates"].get("simulated_step_executed") is None
    events = [r.event_type for r in await rig.chain()]
    assert "TRIPWIRE_BLOCKED" in events and "REMEDIATION_EXECUTED" not in events
    assert verify_chain(await rig.chain()).valid


@pytest.mark.parametrize("choice", ["3", "0", "", "x"])
async def test_invalid_choice_is_blocked_and_executes_nothing(choice: str) -> None:
    rig = Rig()
    await rig.start()
    done = await rig.resume(choice)
    assert done["status"] == "BLOCKED_BY_TRIPWIRE"
    assert rig.runbooks.executed == []


async def test_choice_beyond_runbook_list_is_blocked() -> None:
    rig = Rig(telemetry=FakeTelemetry(RUNBOOKS[:1]))
    await rig.start()
    done = await rig.resume("2")
    assert done["status"] == "BLOCKED_BY_TRIPWIRE"
    assert rig.runbooks.executed == []


# ---------------------------------------------------------------------------
# RESOLVED gating: all four flags, atomic (Req 5.3-5.5)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("name", "rig_kwargs", "expected_gates"),
    [
        (
            "step not executed",
            lambda: {"runbooks": FakeRunbooks(succeed=False)},
            (True, False, False, False),
        ),
        (
            "confirmation sms fails",
            lambda: {"sms": FakeSms(fail_on_suffix="RESOLVED")},
            (True, True, False, True),
        ),
        (
            "audit commit fails",
            lambda: {"audit": FakeAudit(fail_event="INCIDENT_RESOLVED")},
            (True, True, True, False),
        ),
    ],
)
async def test_resolved_withheld_unless_all_four_gates_true(
    name: str, rig_kwargs: Any, expected_gates: tuple[bool, bool, bool, bool]
) -> None:
    rig = Rig(**rig_kwargs())
    await rig.start()
    done = await rig.resume("1")
    assert done["status"] == "EXECUTING", name
    gates = done["gates"]
    assert (
        gates["tripwire_check_passed"],
        gates["simulated_step_executed"],
        gates["confirmation_sms_sent"],
        gates["audit_record_committed"],
    ) == expected_gates


async def test_api_never_persists_resolved_when_a_gate_fails() -> None:
    sms = TwilioSmsAdapter()
    base = build_in_memory_services(Settings(use_in_memory=True))
    ports = Ports(
        telemetry=FakeTelemetry(),
        sms=sms,
        audit=base.audit,
        runbooks=FakeRunbooks(succeed=False),
    )
    services = AppServices(
        graph=build_graph(ports, MemorySaver()),
        dedup=base.dedup,
        sms=sms,
        incidents=base.incidents,
        audit=base.audit,
    )
    with TestClient(create_app(services, Settings(frontend_dir=None, dry_run=True))) as client:
        token = client.post(
            "/webhooks/alerts", json={"service_name": SERVICE, "error_code": "E1"}
        ).json()["token"]
        assert client.post("/api/demo/reply", json={"token": token, "choice": 1}).status_code == 202
        states = {i["token"]: i["state"] for i in client.get("/api/incidents").json()}
        assert states == {token: "FAILED"}  # Req 5.6: never RESOLVED, and the lock is freed


# ---------------------------------------------------------------------------
# End-to-end deduplication through the HTTP gateway (Req 1.2)
# ---------------------------------------------------------------------------


@pytest.fixture()
def api() -> Iterator[tuple[TestClient, AppServices]]:
    services = build_in_memory_services(Settings(use_in_memory=True, twilio_auth_token="t"))
    with TestClient(create_app(services, Settings(frontend_dir=None, dry_run=True))) as client:
        yield client, services


def test_duplicate_alerts_start_exactly_one_agent_run(api: tuple[TestClient, AppServices]) -> None:
    client, services = api
    alert = {"service_name": SERVICE, "error_code": "DB_POOL_EXHAUSTED", "summary": "pool"}
    first = client.post("/webhooks/alerts", json=alert)
    assert first.status_code == 202
    incident_id = first.json()["incident_id"]

    for _ in range(5):
        dup = client.post("/webhooks/alerts", json=alert)
        assert dup.status_code == 200
        assert dup.json() == {"status": "DEDUPLICATED", "incident_id": incident_id}

    outbox = cast(TwilioSmsAdapter, services.sms).outbox
    assert len(outbox) == 1  # one pager => one graph run
    assert len(client.get("/api/incidents").json()) == 1
    records = client.get(f"/api/incidents/{incident_id}/audit").json()["records"]
    events = [r["event_type"] for r in records]
    assert events.count("ALERT_DEDUPLICATED") == 5 and events.count("INCIDENT_CREATED") == 1


def test_different_fingerprints_each_start_a_run(api: tuple[TestClient, AppServices]) -> None:
    client, services = api
    a = client.post("/webhooks/alerts", json={"service_name": SERVICE, "error_code": "E1"})
    b = client.post("/webhooks/alerts", json={"service_name": SERVICE, "error_code": "E2"})
    assert a.status_code == b.status_code == 202
    assert len(cast(TwilioSmsAdapter, services.sms).outbox) == 2


def test_fingerprint_is_released_after_resolution(api: tuple[TestClient, AppServices]) -> None:
    client, _ = api
    alert = {"service_name": SERVICE, "error_code": "E1"}
    token = client.post("/webhooks/alerts", json=alert).json()["token"]
    client.post("/api/demo/reply", json={"token": token, "choice": 1})
    again = client.post("/webhooks/alerts", json=alert)
    assert again.status_code == 202
    assert isinstance(UUID(again.json()["incident_id"]), UUID)
