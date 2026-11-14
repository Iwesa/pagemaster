"""SMS adapter implementing ``SmsPort`` (Req 4.1).

Live mode dispatches through the Twilio SDK (async HTTP client). With
``DRY_RUN=true`` nothing touches the network: messages are appended to an
in-memory outbox that the UI and tests can read.

Every outbound message is re-checked here (defence in depth, on top of
``format_pager_payload``): sanitised, ASCII, ``<= 160`` chars, ``INC-<TOKEN>``
prefix. A message that still violates the invariant is rejected, never sent.
"""

from __future__ import annotations

import logging
import os
import re
from collections import deque
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Final

from pydantic import BaseModel, ConfigDict, Field, SecretStr
from twilio.http.async_http_client import AsyncTwilioHttpClient  # type: ignore[import-untyped]
from twilio.rest import Client  # type: ignore[import-untyped]

from backend.app.services.guardrails import PAGER_MAX_CHARS, sanitize_pager_text

logger = logging.getLogger(__name__)

OUTBOX_MAX_MESSAGES: Final[int] = 500
_PREFIX_RE: Final[re.Pattern[str]] = re.compile(r"INC-[A-Z0-9]{2}(?: |$)", re.ASCII)
_TRUE_VALUES: Final[frozenset[str]] = frozenset({"1", "true", "yes", "on"})


class PagerInvariantError(ValueError):
    """The outbound text violates the pager payload invariant."""


class TwilioConfigError(RuntimeError):
    """Live mode was requested without the required Twilio settings."""


class TwilioSettings(BaseModel):
    """Twilio configuration. ``dry_run`` defaults to True (safe by default)."""

    model_config = ConfigDict(frozen=True)

    dry_run: bool = True
    account_sid: str = ""
    auth_token: SecretStr = SecretStr("")
    from_number: str = ""
    to_number: str = ""

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> TwilioSettings:
        """Read ``DRY_RUN`` and ``TWILIO_*`` variables. Only an explicit false disables dry run."""
        source = os.environ if env is None else env
        raw = source.get("DRY_RUN", "true").strip().lower()
        return cls(
            dry_run=raw in _TRUE_VALUES or raw == "",
            account_sid=source.get("TWILIO_ACCOUNT_SID", ""),
            auth_token=SecretStr(source.get("TWILIO_AUTH_TOKEN", "")),
            from_number=source.get("TWILIO_FROM_NUMBER", ""),
            to_number=source.get("ONCALL_PHONE_NUMBER", ""),
        )

    def require_live(self) -> None:
        """Raise ``TwilioConfigError`` if any live-mode setting is missing."""
        missing = [
            name
            for name, value in (
                ("TWILIO_ACCOUNT_SID", self.account_sid),
                ("TWILIO_AUTH_TOKEN", self.auth_token.get_secret_value()),
                ("TWILIO_FROM_NUMBER", self.from_number),
                ("ONCALL_PHONE_NUMBER", self.to_number),
            )
            if not value
        ]
        if missing:
            raise TwilioConfigError(f"live SMS requires: {', '.join(missing)}")


class OutboxMessage(BaseModel):
    """One message recorded in dry-run mode."""

    model_config = ConfigDict(frozen=True)

    text: str
    to: str
    sent_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


def validate_outbound(text: str) -> str:
    """Sanitise ``text`` and enforce the pager invariant; return the safe text."""
    safe = sanitize_pager_text(text)
    if len(safe) > PAGER_MAX_CHARS:
        raise PagerInvariantError(f"message is {len(safe)} chars; limit is {PAGER_MAX_CHARS}")
    if not safe.isascii():
        raise PagerInvariantError("message is not ASCII")
    if _PREFIX_RE.match(safe) is None:
        raise PagerInvariantError("message must start with INC-<TOKEN>")
    return safe


class TwilioSmsAdapter:
    """``SmsPort`` implementation with live and ``DRY_RUN`` modes."""

    def __init__(self, settings: TwilioSettings | None = None) -> None:
        self._settings = settings if settings is not None else TwilioSettings.from_env()
        self._outbox: deque[OutboxMessage] = deque(maxlen=OUTBOX_MAX_MESSAGES)
        self._http: AsyncTwilioHttpClient | None = None
        self._client: Client | None = None
        if not self._settings.dry_run:
            self._settings.require_live()
            self._http = AsyncTwilioHttpClient()
            self._client = Client(
                self._settings.account_sid,
                self._settings.auth_token.get_secret_value(),
                http_client=self._http,
            )

    @property
    def dry_run(self) -> bool:
        return self._settings.dry_run

    @property
    def outbox(self) -> tuple[OutboxMessage, ...]:
        """Snapshot of recorded messages, oldest first (dry run only)."""
        return tuple(self._outbox)

    def clear_outbox(self) -> None:
        self._outbox.clear()

    async def send(self, text: str) -> None:
        safe = validate_outbound(text)
        if self._client is None:
            self._outbox.append(OutboxMessage(text=safe, to=self._settings.to_number))
            logger.info("DRY_RUN sms recorded (%d chars)", len(safe))
            return
        await self._client.messages.create_async(
            to=self._settings.to_number,
            from_=self._settings.from_number,
            body=safe,
        )

    async def aclose(self) -> None:
        """Close the live HTTP session, if any."""
        if self._http is not None:
            await self._http.close()
