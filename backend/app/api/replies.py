"""SMS reply handling shared by the Africa's Talking webhook and the DRY_RUN demo route.

Requirements: 3.6, 4.4, 4.5, 4.10, 4.11, 4.12, 6.1, 6.2, 6.7, 6.10, 6.12.
"""

from __future__ import annotations

import logging
from typing import Final

from fastapi import BackgroundTasks
from langgraph.types import Command

from backend.app.api.app_services import AppServices
from backend.app.api.workflow import run_workflow
from backend.app.services.guardrails import MAX_PAGE_OPTIONS, parse_sms_reply
from backend.app.services.incident_store import IncidentRecord
from backend.app.services.sms_common import GENERIC_HINT_TEXT

__all__ = [
    "ALREADY_HANDLED_WINDOW_SECONDS",
    "TRIAGE_POLL_SECONDS",
    "handle_reply",
]

logger = logging.getLogger("pagemaster.api")

TRIAGE_POLL_SECONDS: Final[float] = 0.1
#: Terminal states reachable through an approval reply; a reply arriving this soon after one
#: is the loser of a race (Req 4.11), later ones get the plain "no longer active" answer.
ALREADY_HANDLED_WINDOW_SECONDS: Final[float] = 30.0
_REPLY_TERMINAL_STATES: Final[frozenset[str]] = frozenset({"RESOLVED", "BLOCKED_BY_TRIPWIRE", "FAILED"})


async def _notify(services: AppServices, text: str) -> None:
    try:
        await services.sms.send(text)
    except Exception:
        logger.exception("informational sms failed")


async def _wait_for_triage(services: AppServices, incident: IncidentRecord) -> IncidentRecord:
    """Req 6.12: give a ``TRIAGING`` incident up to ``triage_wait_seconds`` to reach approval.

    Polls the repository every ``TRIAGE_POLL_SECONDS``; returns the latest row (possibly still
    ``TRIAGING``). The waiting budget is the sum of the requested sleeps, so tests can inject
    ``services.sleep`` and run instantly.
    """
    waited = 0.0
    current = incident
    while current.state == "TRIAGING" and waited < services.triage_wait_seconds:
        step = min(TRIAGE_POLL_SECONDS, services.triage_wait_seconds - waited)
        await services.sleep(step)
        waited += step
        refreshed = await services.incidents.get(incident.incident_id)
        if refreshed is None:
            break
        current = refreshed
    return current


async def _send_hint(services: AppServices, sender: str) -> None:
    """Req 4.10: tell the authorized sender what to reply, at most once per window."""
    if not await services.hint_limiter.allow(sender):
        return
    awaiting = await services.incidents.list_by_states(["AWAITING_APPROVAL"], limit=2)
    if len(awaiting) == 1:
        only = awaiting[0]
        count = only.option_count if only.option_count is not None else MAX_PAGE_OPTIONS
        if count >= 1:
            codes = " or ".join(f"{only.token}-{n}" for n in range(1, min(count, MAX_PAGE_OPTIONS) + 1))
            await _notify(services, f"INC-{only.token} Reply {codes}")
            return
    await _notify(services, GENERIC_HINT_TEXT)


async def handle_reply(
    services: AppServices, background: BackgroundTasks, body: str, sender: str | None = None
) -> None:
    """Parse an SMS reply body and resume the workflow. Shared by the webhook and demo route.

    Callers are responsible for authenticating the request first. ``sender`` is the
    already-authorized sender; only then is a hint sent for unparseable text.
    """
    reply = parse_sms_reply(body)
    if reply is None:
        if sender is not None:  # Req 4.10: authorized sender only
            await _send_hint(services, sender)
        return  # not an action code: no mutation

    # Req 6.1, 6.2, 6.7: the store clock decides expiry, before any graph resume.
    outcome = await services.incidents.expire_if_stale(reply.token, services.approval_ttl_seconds)
    if outcome.expired_now:
        await services.lifecycle.handle_expiry(outcome, reply.token)  # audit + unlock + SMS
        return
    incident = (
        await services.incidents.get_active_by_token(reply.token) if outcome.found else None
    )
    if incident is None:  # Req 4.5: unknown, expired or resolved
        latest = await services.incidents.latest_by_token(reply.token)
        if latest is not None and latest.state == "EXPIRED":  # Req 6.10: answer only, mutate nothing
            await _notify(services, f"INC-{reply.token} expired. No action taken.")
            return
        if latest is not None and latest.state in _REPLY_TERMINAL_STATES:
            age = (services.clock() - latest.updated_at).total_seconds()
            if age <= ALREADY_HANDLED_WINDOW_SECONDS:  # Req 4.11: lost the race to another reply
                await _notify(services, f"INC-{reply.token} already handled ({latest.state}).")
                return
        await _notify(services, f"INC-{reply.token} no longer active. No action taken.")
        return
    if incident.state == "TRIAGING":  # Req 6.12: do not drop an early reply
        incident = await _wait_for_triage(services, incident)
        if incident.state == "TRIAGING":  # Req 4.12: answer only
            await _notify(services, f"INC-{reply.token} still being triaged, reply again in a moment.")
            return
    if incident.state != "AWAITING_APPROVAL":  # EXECUTING or already terminal: another reply won
        await _notify(services, f"INC-{reply.token} already handled ({incident.state}).")
        return
    if incident.option_count is not None and int(reply.choice) > incident.option_count:
        codes = " or ".join(f"{reply.token}-{n}" for n in range(1, incident.option_count + 1))
        valid = f"valid reply is {codes}." if codes else "no reply options."
        await _notify(services, f"INC-{reply.token} {valid}")  # Req 3.6: no such option; no change
        return
    claimed = await services.incidents.compare_and_set_state(
        incident.incident_id, "AWAITING_APPROVAL", "EXECUTING"
    )
    if not claimed:  # another reply (or the reaper) won between the read and the claim
        current = await services.incidents.get(incident.incident_id)
        state = current.state if current is not None else "UNKNOWN"
        await _notify(services, f"INC-{reply.token} already handled ({state}).")
        return

    # Req 4.4: resume the suspended graph with the selected action.
    background.add_task(run_workflow, services, incident, Command(resume={"choice": reply.choice}))
