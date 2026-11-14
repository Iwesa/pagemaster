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
TRUE_VALUES: Final[frozenset[str]] = frozenset({"1", "true", "yes", "on"})


class PagerInvariantError(ValueError):
    """The outbound text violates the pager payload invariant."""


class OutboxMessage(BaseModel):
    """One message recorded in dry-run mode."""

    model_config = ConfigDict(frozen=True)

    text: str
    to: str
    sent_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


def parse_dry_run(raw: str) -> bool:
    """Only an explicit non-true value disables dry run; empty means dry run."""
    value = raw.strip().lower()
    return value in TRUE_VALUES or value == ""


def validate_outbound(text: str) -> str:
    """Sanitise ``text`` and enforce the pager invariant; return the safe text."""
    safe = sanitize_pager_text(text)
    if not safe.isascii():
        raise PagerInvariantError("message is not ASCII")
    try:
        septets = gsm7_septets(safe)
    except ValueError as exc:
        raise PagerInvariantError(str(exc)) from exc
    if septets > PAGER_MAX_CHARS:
        raise PagerInvariantError(f"message is {septets} septets; limit is {PAGER_MAX_CHARS}")
    if _PREFIX_RE.match(safe) is None:
        raise PagerInvariantError("message must start with INC-<TOKEN>")
    return safe
