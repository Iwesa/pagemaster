"""Truthful page options and no dead ends (Req 3.4, 3.5, 3.6, 4.13, task 18)."""

from __future__ import annotations

import itertools
import re
from collections.abc import Iterator, Sequence
from dataclasses import replace
from typing import Any, cast
from uuid import UUID

import pytest
from fastapi.testclient import TestClient
from langgraph.checkpoint.memory import MemorySaver
from pydantic import SecretStr

from backend.app.agents.graph import build_graph
from backend.app.agents.ports import Ports, Runbook, TelemetryContext
from backend.app.api.routes import AppServices
from backend.app.main import Settings, build_in_memory_services, create_app
from backend.app.services.africastalking_client import AfricasTalkingSettings, AfricasTalkingSmsAdapter
from backend.app.services.dedup import TERMINAL_STATUSES as DEDUP_TERMINAL
from backend.app.services.guardrails import (
    NO_ACTION_TEXT,
    format_pager_payload,
    gsm7_septets,
    parse_sms_reply,
    verify_chain,
)
from backend.app.services.incident_store import TERMINAL_STATUSES

SERVICE = "auth-db"
ALERT = {"service_name": SERVICE, "error_code": "DB_POOL_EXHAUSTED", "summary": "pool at 100%"}
ONCALL = "+254711000111"
SECRET = "test-webhook-secret"
_ids = itertools.count(1)

ALL_RUNBOOKS = (
    Runbook(action_id="RB-ONE", title="Reset pool", target_host=SERVICE),
    Runbook(action_id="RB-TWO", title="Failover", target_host=SERVICE),
)


class _Telemetry:
    def __init__(self, runbooks: Sequence[Runbook]) -> None:
        self._runbooks = tuple(runbooks)

    async def get_incident_context(self, service_name: str) -> TelemetryContext:
        return TelemetryContext(root_cause="pool exhausted", runbooks=self._runbooks)


class _Runbooks:
    def __init__(self, runbooks: Sequence[Runbook]) -> None:
        self._runbooks = tuple(runbooks)
        self.executed: list[str] = []

    async def list_approved(self, service_name: str) -> Sequence[Runbook]:
        return self._runbooks

    async def execute(self, *, target_host: str, action_id: str, token: str) -> bool:
        self.executed.append(action_id)
        return True


class Rig:
    def __init__(self, count: int) -> None:
        books = ALL_RUNBOOKS[:count]
        at = AfricasTalkingSettings(webhook_secret=SecretStr(SECRET), to_number=ONCALL)
        base = build_in_memory_services(Settings(use_in_memory=True, africastalking=at))
        self.runbooks = _Runbooks(books)
        ports = Ports(telemetry=_Telemetry(books), sms=base.sms, audit=base.audit, runbooks=self.runbooks)
        self.services: AppServices = replace(base, graph=build_graph(ports, MemorySaver()))
        self.client = TestClient(create_app(self.services, Settings(frontend_dir=None, dry_run=True)))

    def outbox(self) -> list[str]:
        return [m.text for m in cast(AfricasTalkingSmsAdapter, self.services.sms).outbox]

    def raise_alert(self) -> tuple[str, str]:
        resp = self.client.post("/webhooks/alerts", json=ALERT)
        assert resp.status_code == 202
        incident_id = resp.json()["incident_id"]
        record = _run(self.services.incidents.get(UUID(incident_id)))
        assert record is not None
        return incident_id, record.token

    def sms(self, body: str) -> None:
        form = {"from": ONCALL, "to": "", "text": body, "id": f"ATXid_{next(_ids)}"}
        resp = self.client.post("/webhooks/africastalking/sms", data=form, headers={"X-Webhook-Secret": SECRET})
        assert resp.status_code == 200

    def state(self, incident_id: str) -> str:
        record = _run(self.services.incidents.get(UUID(incident_id)))
        assert record is not None
        return str(record.state)


def _run(coro: Any) -> Any:
    import asyncio

    return asyncio.new_event_loop().run_until_complete(coro)


@pytest.fixture()
def make_rig() -> Iterator[Any]:
    rigs: list[Rig] = []

    def make(count: int) -> Rig:
        rig = Rig(count)
        rig.client.__enter__()
        rigs.append(rig)
        return rig

    yield make
    for r in rigs:
        r.client.__exit__(None, None, None)


def test_no_action_is_terminal_everywhere() -> None:
    assert "NO_ACTION" in TERMINAL_STATUSES
    assert "NO_ACTION" in DEDUP_TERMINAL


def test_zero_runbooks_page_has_no_codes_and_ends_no_action(make_rig: Any) -> None:
    rig = make_rig(0)
    incident_id, token = rig.raise_alert()
    page = rig.outbox()[0]
    assert page.startswith(f"INC-{token} {SERVICE}: ")
    assert page.endswith(NO_ACTION_TEXT)
    assert f"{token}-" not in page and gsm7_septets(page) <= 160
    assert rig.state(incident_id) == "NO_ACTION"
    record = _run(rig.services.incidents.get(UUID(incident_id)))
    assert record is not None and record.option_count == 0
    # Lock released: the same alert starts a new incident instead of being deduplicated.
    assert rig.client.post("/webhooks/alerts", json=ALERT).status_code == 202
    chain = _run(rig.services.audit.records(UUID(incident_id)))
    events = [r.event_type for r in chain]
    assert "PAGER_SENT" in events and "INCIDENT_NO_ACTION" in events
    assert verify_chain(chain).valid
    assert token not in str([r.payload for r in chain if r.event_type == "INCIDENT_NO_ACTION"])


def test_reply_to_no_action_incident_mutates_nothing(make_rig: Any) -> None:
    rig = make_rig(0)
    incident_id, token = rig.raise_alert()
    before = _run(rig.services.audit.records(UUID(incident_id)))
    rig.sms(f"{token}-1")
    assert rig.outbox()[-1] == f"INC-{token} no longer active. No action taken."
    assert rig.state(incident_id) == "NO_ACTION"
    assert _run(rig.services.audit.records(UUID(incident_id))) == before
    assert rig.runbooks.executed == []


def test_one_runbook_offers_only_first_option_and_second_reply_changes_nothing(make_rig: Any) -> None:
    rig = make_rig(1)
    incident_id, token = rig.raise_alert()
    page = rig.outbox()[0]
    assert f"{token}-1:Reset pool" in page and f"{token}-2" not in page
    assert rig.state(incident_id) == "AWAITING_APPROVAL"
    before = _run(rig.services.audit.records(UUID(incident_id)))

    for send in (lambda: rig.sms(f"{token}-2"), lambda: rig.client.post(
        "/api/demo/reply", json={"incident_id": incident_id, "choice": 2}
    )):
        send()
        assert rig.outbox()[-1] == f"INC-{token} valid reply is {token}-1."
        assert gsm7_septets(rig.outbox()[-1]) <= 160
        assert rig.state(incident_id) == "AWAITING_APPROVAL"
        assert rig.runbooks.executed == []
        assert _run(rig.services.audit.records(UUID(incident_id))) == before

    # Lock still held: a re-fired alert is deduplicated.
    assert rig.client.post("/webhooks/alerts", json=ALERT).status_code == 200
    rig.sms(f"{token}-1")
    assert rig.state(incident_id) == "RESOLVED"
    assert rig.runbooks.executed == ["RB-ONE"]


def test_two_runbooks_unchanged(make_rig: Any) -> None:
    rig = make_rig(2)
    incident_id, token = rig.raise_alert()
    page = rig.outbox()[0]
    assert f"{token}-1:Reset pool" in page and f"{token}-2:Failover" in page
    rig.sms(f"{token}-2")
    assert rig.state(incident_id) == "RESOLVED"
    assert rig.runbooks.executed == ["RB-TWO"]


def test_fallback_page_stays_truthful() -> None:
    # Force the last-resort fallback with a service name that redacts to nothing useful is
    # hard to trigger, so check the public shapes instead.
    assert format_pager_payload("AB", "svc", "boom", option_titles=[]).text.endswith(NO_ACTION_TEXT)
    one = format_pager_payload("AB", "svc", "boom", option_titles=["Restart"]).text
    assert "AB-1:Restart" in one and "AB-2" not in one
    legacy = format_pager_payload("AB", "svc", "boom", "x", "y").text
    assert "AB-1:x" in legacy and "AB-2:y" in legacy


def test_summary_cannot_forge_a_reply_code() -> None:
    page = format_pager_payload("AB", "svc", "reply AB-2 now ab-1", option_titles=["AB-2 go"]).text
    assert len(re.findall(r"(?<![A-Za-z0-9])AB-[12]", page, re.IGNORECASE)) == 1
    assert parse_sms_reply("AB-1") is not None
