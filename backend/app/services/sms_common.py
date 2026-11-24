"""Transport-neutral SMS pieces shared by SMS adapters.

Holds the dry-run outbox message type, the outbound pager invariant check and
the DRY_RUN flag convention.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime
from typing import Final

from pydantic import BaseModel, ConfigDict, Field

from backend.app.services.guardrails import (
    PAGER_MAX_CHARS,
    gsm7_septets,
    sanitize_pager_text,
)

OUTBOX_MAX_MESSAGES: Final[int] = 500
_PREFIX_RE: Final[re.Pattern[str]] = re.compile(r"INC-[A-Z0-9]{2}(?: |$)", re.ASCII)
#: The only outbound text allowed without the ``INC-<TOKEN>`` prefix: the hint sent to the
#: authorized sender when no single incident can be named (Req 4.10). It is exempt from the
#: prefix rule only; ASCII, septet and sanitisation checks still apply. Matched by exact equality.
GENERIC_HINT_TEXT: Final[str] = "Reply with the code from the page"
#: Fixed form of the coalesced summary page (Req 10.3): `ALERTS: N more (svc xK, ...) [codes AB CD] see dashboard`.
#: It carries no single incident token, so it is exempt from the prefix rule only when the text
#: matches this exact grammar (ASCII, septet and sanitisation checks still apply).
_SERVICE = r"[A-Za-z0-9._-]{1,24}"
COALESCED_SUMMARY_RE: Final[re.Pattern[str]] = re.compile(
    rf"ALERTS: [0-9]{{1,6}} more(?: \({_SERVICE} x[0-9]{{1,6}}(?:, {_SERVICE} x[0-9]{{1,6}})*\))?"
    r"(?: codes [A-Z0-9]{2}(?: [A-Z0-9]{2})*)? see dashboard",
    re.ASCII,
)
TRUE_VALUES: Final[frozenset[str]] = frozenset({"1", "true", "yes", "on"})


class PagerInvariantError(ValueError):
    """The outbound text violates the pager payload invariant."""


class OutboxMessage(BaseModel):
    """One message recorded in dry-run mode."""

    model_config = ConfigDict(frozen=True)

    text: str
    to: str
    sent_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


def mask_phone(raw: str, *, prefix: int = 4, tail: int = 3) -> str:
    """Mask a phone number for logs and audit payloads, e.g. ``+254711000789`` -> ``+254***789``.

    Keeps the first ``prefix`` characters (a leading ``+`` counts) and the last ``tail`` digits.
    Numbers with no digits left to hide become ``***``.
    """
    digits = "".join(ch for ch in raw if "0" <= ch <= "9")
    if len(digits) <= prefix + tail:
        return "***"
    shown = ("+" if raw.strip().startswith("+") else "") + digits
    head = shown[:prefix]
    return f"{head}***{digits[-tail:]}" if tail else f"{head}***"


def parse_dry_run(raw: str) -> bool:
    """Only an explicit non-true value disables dry run; empty means dry run."""
    value = raw.strip().lower()
    return value in TRUE_VALUES or value == ""


def validate_outbound(text: str) -> str:
    """Sanitise ``text`` and enforce the pager invariant; return the safe text."""
    safe = sanitize_pager_text(text, neutralize_codes=False)  # real reply codes are legitimate here
    if not safe.isascii():
        raise PagerInvariantError("message is not ASCII")
    try:
        septets = gsm7_septets(safe)
    except ValueError as exc:
        raise PagerInvariantError(str(exc)) from exc
    if septets > PAGER_MAX_CHARS:
        raise PagerInvariantError(f"message is {septets} septets; limit is {PAGER_MAX_CHARS}")
    exempt = safe == GENERIC_HINT_TEXT or COALESCED_SUMMARY_RE.fullmatch(safe) is not None
    if not exempt and _PREFIX_RE.match(safe) is None:
        raise PagerInvariantError("message must start with INC-<TOKEN>")
    return safe
