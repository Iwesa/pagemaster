"""Forgiving, informative replies (task 19; Req 4.9 to 4.12, 6.12; Property 16)."""

from __future__ import annotations

import asyncio
from collections.abc import Iterator
from typing import Any
from uuid import UUID

import pytest
from fastapi import BackgroundTasks

from backend.app.api.routes import AppServices, _handle_reply
from backend.app.services.guardrails import parse_sms_reply
from backend.app.services.hint_limiter import HintRateLimiter
from backend.app.services.sms_common import GENERIC_HINT_TEXT, PagerInvariantError, validate_outbound
from backend.tests.test_expiry import (
    TTL,
    add_incident,
    make_services,
    outbox,
    state_of,
)
from backend.tests.test_page_options import ALERT, ONCALL, SECRET, Rig

# ---------------------------------------------------------------------------
# Parser table
# ---------------------------------------------------------------------------

ACCEPTED = [
    ("AB-1", "AB", "1"),
    ("ab-2", "AB", "2"),
    ("  AB-1  ", "AB", "1"),
    ("AB-1.", "AB", "1"),
    ("AB-1!", "AB", "1"),
    ("AB-1 .!", "AB", "1"),
    ("AB 1", "AB", "1"),
    ("ab 2.", "AB", "2"),
    ("AB\u20131", "AB", "1"),  # en dash
    ("AB\u20141", "AB", "1"),  # em dash
    ("AB\u20101", "AB", "1"),
    ("AB\u20151", "AB", "1"),
    ("AB\u22121", "AB", "1"),  # minus sign
    ("AB-\uff11", "AB", "1"),  # full-width digit
    ("\uff21\uff22\uff0d\uff12", "AB", "2"),  # all full-width
    ("AB\u00a0\uff11", "AB", "1"),  # no-break space
]
REJECTED = [
    "AB-1 thanks",
    "approve AB-1",
    "AB-12",
    "AB-3",
    "AB-0",
    "AB-",
    "AB",
    "",
    "A-1",
    "ABC-1",
    "AB--1",
    "AB  1",
    "AB\t1",
    "AB- 1",
    ".AB-1",
    "AB-1?",
    "AB-\u00b9",  # superscript one folds to 1 under NFKC: must not pass
    "\u212aB-1",  # Kelvin sign folds to K under NFKC: must not pass
    "AB\u2026",
    "AB-1\u2026",
    "AB\u30fc1",  # katakana long vowel mark is not a dash
    "AB_1",
]


@pytest.mark.parametrize(("body", "token", "choice"), ACCEPTED)
def test_parser_accepts_forgiving_forms(body: str, token: str, choice: str) -> None:
    reply = parse_sms_reply(body)
    assert reply is not None and (reply.token, reply.choice) == (token, choice)


@pytest.mark.parametrize("body", REJECTED)
def test_parser_rejects_everything_else(body: str) -> None:
    assert parse_sms_reply(body) is None


# ---------------------------------------------------------------------------
# validate_outbound: only the one hint is exempt from the INC prefix
# ---------------------------------------------------------------------------


def test_generic_hint_passes_validate_outbound_and_nothing_else_is_relaxed() -> None:
    assert validate_outbound(GENERIC_HINT_TEXT) == GENERIC_HINT_TEXT
    assert validate_outbound("INC-AB Reply AB-1 or AB-2") == "INC-AB Reply AB-1 or AB-2"
    for text in (
        GENERIC_HINT_TEXT + ".",
        GENERIC_HINT_TEXT.lower(),
        GENERIC_HINT_TEXT + " now",
        "Reply AB-1 or AB-2",
        "Hello",
        "INC-?? Reply with the code from the page",
    ):
        with pytest.raises(PagerInvariantError):
            validate_outbound(text)


# ---------------------------------------------------------------------------
# Rate limiter
# ---------------------------------------------------------------------------


class FakeClock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


async def test_hint_rate_limiter_one_per_sender_per_window() -> None:
    clock = FakeClock()
    limiter = HintRateLimiter(60.0, clock)
    assert await limiter.allow("a")
    assert not await limiter.allow("a")
    assert await limiter.allow("b")  # other sender is independent
    clock.now += 59.9
    assert not await limiter.allow("a")
    clock.now += 0.2
    assert await limiter.allow("a")
    assert not await limiter.allow("a")


# ---------------------------------------------------------------------------
# Race, triage and hint behaviour on the shared reply path
# ---------------------------------------------------------------------------


async def test_five_parallel_replies_one_execution_losers_already_handled() -> None:
    services, _, graph = make_services()
    incident = await add_incident(services, "AWAITING_APPROVAL")
    await asyncio.gather(*(reply_as(services, "7A-1") for _ in range(5)))
    assert len(graph.calls) == 1
    assert await state_of(services, incident.incident_id) == "RESOLVED"
    texts = outbox(services)
    assert texts == ["INC-7A already handled (RESOLVED)."] * 4
    assert not any("not awaiting approval" in t for t in texts)
    for text in texts:
        validate_outbound(text)


async def test_reply_to_executing_incident_reports_real_state() -> None:
    services, _, graph = make_services()
    await add_incident(services, "EXECUTING")
    await reply_as(services, "7A-1")
    assert outbox(services) == ["INC-7A already handled (EXECUTING)."]
    assert graph.calls == []


async def test_old_terminal_incident_is_plain_inactive() -> None:
    services, clock, _ = make_services()
    await add_incident(services, "RESOLVED")
    clock.advance(TTL)
    await reply_as(services, "7A-1")
    assert outbox(services) == ["INC-7A no longer active. No action taken."]


class Sleeper:
    """Fake sleep; optionally flips the incident to AWAITING_APPROVAL after ``flip_after`` calls."""

    def __init__(self, services: AppServices, incident_id: UUID | None, flip_after: int | None) -> None:
        self.services = services
        self.incident_id = incident_id
        self.flip_after = flip_after
        self.calls: list[float] = []

    async def __call__(self, seconds: float) -> None:
        self.calls.append(seconds)
        if self.flip_after is not None and len(self.calls) == self.flip_after and self.incident_id:
            await self.services.incidents.set_state(self.incident_id, "AWAITING_APPROVAL")


async def test_still_triaging_waits_two_seconds_then_answers_without_change() -> None:
    services, _, graph = make_services()
    incident = await add_incident(services, "TRIAGING")
    sleeper = Sleeper(services, incident.incident_id, None)
    from dataclasses import replace

    services = replace(services, sleep=sleeper)
    await reply_as(services, "7A-1")
    assert sum(sleeper.calls) == pytest.approx(2.0)
    assert max(sleeper.calls) <= 0.1 + 1e-9
    assert outbox(services) == ["INC-7A still being triaged, reply again in a moment."]
    validate_outbound(outbox(services)[0])
    assert await state_of(services, incident.incident_id) == "TRIAGING"
    assert graph.calls == []


async def test_early_reply_during_triage_is_processed_when_page_lands_in_time() -> None:
    services, _, graph = make_services()
    incident = await add_incident(services, "TRIAGING")
    sleeper = Sleeper(services, incident.incident_id, 5)  # flips after ~0.5 s
    from dataclasses import replace

    services = replace(services, sleep=sleeper)
    await reply_as(services, "7A-1")
    assert len(sleeper.calls) == 5
    assert len(graph.calls) == 1
    assert await state_of(services, incident.incident_id) == "RESOLVED"
    assert outbox(services) == []


async def test_hint_single_awaiting_incident_names_codes_and_is_rate_limited() -> None:
    services, _, _ = make_services()
    await add_incident(services, "AWAITING_APPROVAL")
    await reply_as(services, "hello", sender="+254711000111")
    await reply_as(services, "what?", sender="+254711000111")  # within 60 s: silent
    assert outbox(services) == ["INC-7A Reply 7A-1 or 7A-2"]
    validate_outbound(outbox(services)[0])


async def test_hint_respects_option_count_and_generic_fallback() -> None:
    services, _, _ = make_services()
    one = await add_incident(services, "AWAITING_APPROVAL")
    await services.incidents.record_resolution(one.incident_id, "AWAITING_APPROVAL", None, 1)
    await reply_as(services, "?", sender="s")
    assert outbox(services) == ["INC-7A Reply 7A-1"]
    await add_incident(services, "AWAITING_APPROVAL", token="9Z", service="other", code="E2")
    await reply_as(services, "?", sender="t")  # another sender, two awaiting
    await reply_as(services, "?", sender="u")
    assert outbox(services)[1:] == [GENERIC_HINT_TEXT, GENERIC_HINT_TEXT]


async def test_hint_without_awaiting_incident_is_generic() -> None:
    services, _, _ = make_services()
    await reply_as(services, "hi", sender="s")
    assert outbox(services) == [GENERIC_HINT_TEXT]


async def test_no_sender_means_no_hint() -> None:
    services, _, _ = make_services()
    await reply_as(services, "hi")
    assert outbox(services) == []


async def reply_as(services: AppServices, body: str, sender: str | None = None) -> None:
    background = BackgroundTasks()
    await _handle_reply(services, background, body, sender=sender)
    await background()


# ---------------------------------------------------------------------------
# HTTP-level cases
# ---------------------------------------------------------------------------


@pytest.fixture()
def rig() -> Iterator[Rig]:
    r = Rig(2)
    r.client.__enter__()
    yield r
    r.client.__exit__(None, None, None)


@pytest.mark.parametrize("body", ["{t}-1.", "{t} 1", "{t}\u20131", "{t}-\uff11", " {t}-1! "])
def test_api_accepts_forgiving_forms(rig: Rig, body: str) -> None:
    incident_id, token = rig.raise_alert()
    rig.sms(body.format(t=token))
    assert rig.state(incident_id) == "RESOLVED"
    assert rig.outbox()[-1] == f"INC-{token} RESOLVED"


@pytest.mark.parametrize("body", ["{t}-1 thanks", "approve {t}-1", "{t}-12", "{t}-"])
def test_api_rejected_forms_change_nothing_and_get_a_hint(rig: Rig, body: str) -> None:
    incident_id, token = rig.raise_alert()
    sent = len(rig.outbox())
    rig.sms(body.format(t=token))
    assert rig.state(incident_id) == "AWAITING_APPROVAL"
    assert rig.outbox()[sent:] == [f"INC-{token} Reply {token}-1 or {token}-2"]


def test_api_hint_is_limited_to_one_per_minute(rig: Rig) -> None:
    _, token = rig.raise_alert()
    sent = len(rig.outbox())
    rig.sms("hello")
    rig.sms("hello again")
    assert rig.outbox()[sent:] == [f"INC-{token} Reply {token}-1 or {token}-2"]


def test_api_unauthorized_sender_gets_no_hint(rig: Rig) -> None:
    rig.raise_alert()
    sent = len(rig.outbox())
    form: dict[str, Any] = {"from": "+254700999999", "to": "", "text": "hello", "id": "ATXid_unauth_1"}
    resp = rig.client.post("/webhooks/africastalking/sms", data=form, headers={"X-Webhook-Secret": SECRET})
    assert resp.status_code == 403
    form = {"from": ONCALL, "to": "", "text": "hello", "id": "ATXid_unauth_2"}
    resp = rig.client.post("/webhooks/africastalking/sms", data=form, headers={"X-Webhook-Secret": "wrong"})
    assert resp.status_code == 403
    assert rig.outbox()[sent:] == []


def test_api_two_awaiting_incidents_get_generic_hint(rig: Rig) -> None:
    rig.raise_alert()
    second = rig.client.post("/webhooks/alerts", json={**ALERT, "error_code": "OTHER_CODE"})
    assert second.status_code == 202
    sent = len(rig.outbox())
    rig.sms("hello")
    assert rig.outbox()[sent:] == [GENERIC_HINT_TEXT]


def test_demo_reply_uses_the_same_race_answers(rig: Rig) -> None:
    incident_id, _ = rig.raise_alert()
    first = rig.client.post("/api/demo/reply", json={"incident_id": incident_id, "choice": 1})
    assert first.status_code == 202 and rig.state(incident_id) == "RESOLVED"
    second = rig.client.post("/api/demo/reply", json={"incident_id": incident_id, "choice": 1})
    assert second.status_code == 202
    assert rig.outbox()[-1].endswith("already handled (RESOLVED).")
