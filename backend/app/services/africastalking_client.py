"""Africa's Talking SMS adapter implementing ``SmsPort`` (Req 4.1).

Live mode POSTs to the Africa's Talking messaging REST API through
``httpx.AsyncClient``. With ``DRY_RUN=true`` nothing touches the network:
messages are appended to a bounded in-memory outbox.

A non-2xx response or any recipient whose ``statusCode`` is not a success code
raises ``SmsSendError``, so callers (e.g. the remediation executor's
``confirmation_sms_sent`` gate) observe the failure. The API key is a
``SecretStr`` and is never logged.
"""

from __future__ import annotations

import logging
import os
import re
from collections import deque
from collections.abc import Mapping
from typing import Any, Final

import httpx
from pydantic import BaseModel, ConfigDict, SecretStr

from backend.app.services.sms_common import (
    OUTBOX_MAX_MESSAGES,
    OutboxMessage,
    PagerInvariantError,
    parse_dry_run,
    validate_outbound,
)

logger = logging.getLogger(__name__)

__all__ = [
    "AfricasTalkingConfigError",
    "AfricasTalkingSettings",
    "AfricasTalkingSmsAdapter",
    "OutboxMessage",
    "PagerInvariantError",
    "SmsSendError",
    "canonicalize_e164",
    "extract_webhook_secret",
]

PRODUCTION_URL: Final[str] = "https://api.africastalking.com/version1/messaging"
SANDBOX_URL: Final[str] = "https://api.sandbox.africastalking.com/version1/messaging"
# 100 Processed, 101 Sent, 102 Queued are accepted outcomes.
_OK_STATUS_CODES: Final[frozenset[int]] = frozenset({100, 101, 102})
_TRUE_VALUES: Final[frozenset[str]] = frozenset({"1", "true", "yes", "on"})
_E164_STRIP_RE: Final[re.Pattern[str]] = re.compile(r"[\s\-()]")
_E164_DIGITS_RE: Final[re.Pattern[str]] = re.compile(r"[0-9]{8,15}", re.ASCII)
_HTTP_TIMEOUT_SECONDS: Final[float] = 10.0


class AfricasTalkingConfigError(RuntimeError):
    """Live mode was requested without the required Africa's Talking settings."""


class SmsSendError(RuntimeError):
    """Africa's Talking rejected the message or the request failed.

    ``retryable`` is True for transient failures (transport errors, timeouts, HTTP 5xx, 408,
    429, provider-side recipient codes >= 500) and False for errors a retry cannot fix
    (authentication, invalid number, insufficient balance). It defaults to True so existing
    ``SmsSendError("...")`` callers are unchanged.
    """

    def __init__(self, message: str = "", *, retryable: bool = True) -> None:
        super().__init__(message)
        self.retryable = retryable


def _http_status_retryable(status: int) -> bool:
    return status >= 500 or status in (408, 429)


_BEARER_PREFIX: Final[str] = "bearer "


def extract_webhook_secret(
    x_webhook_secret: str | None,
    authorization: str | None,
    query_secret: str | None,
    *,
    allow_query: bool,
) -> str | None:
    """Pick the callback secret from the first available source, never falling through.

    Order: ``X-Webhook-Secret`` header, ``Authorization: Bearer <secret>`` (scheme
    case-insensitive, exactly one space, non-empty token), then ``?secret=`` only when
    ``allow_query`` is true. An empty value counts as absent. The first available source
    wins even if it is wrong, so a bad header is never rescued by a lower-priority source.
    """
    if x_webhook_secret:
        return x_webhook_secret
    if authorization and authorization[: len(_BEARER_PREFIX)].lower() == _BEARER_PREFIX:
        token = authorization[len(_BEARER_PREFIX) :]
        if token and not token[0].isspace():
            return token
    if allow_query and query_secret:
        return query_secret
    return None


def canonicalize_e164(raw: str) -> str | None:
    """Return ``+<digits>`` for a plausible E.164 number, else ``None``.

    Strips spaces, dashes and parentheses; accepts a leading ``+`` or ``00``;
    requires 8-15 ASCII digits.
    """
    cleaned = _E164_STRIP_RE.sub("", raw)
    if cleaned.startswith("+"):
        digits = cleaned[1:]
    elif cleaned.startswith("00"):
        digits = cleaned[2:]
    else:
        return None
    if _E164_DIGITS_RE.fullmatch(digits) is None:
        return None
    return f"+{digits}"


class AfricasTalkingSettings(BaseModel):
    """Africa's Talking configuration. ``dry_run`` defaults to True (safe by default)."""

    model_config = ConfigDict(frozen=True)

    dry_run: bool = True
    username: str = ""
    api_key: SecretStr = SecretStr("")
    shortcode: str = ""
    to_number: str = ""
    webhook_secret: SecretStr = SecretStr("")
    sandbox: bool = False

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> AfricasTalkingSettings:
        """Read ``DRY_RUN`` and ``AFRICASTALKING_*`` variables."""
        source = os.environ if env is None else env
        username = source.get("AFRICASTALKING_USERNAME", "").strip()
        sandbox_flag = source.get("AFRICASTALKING_SANDBOX", "").strip().lower() in _TRUE_VALUES
        return cls(
            dry_run=parse_dry_run(source.get("DRY_RUN", "true")),
            username=username,
            api_key=SecretStr(source.get("AFRICASTALKING_API_KEY", "")),
            shortcode=source.get("AFRICASTALKING_SHORTCODE", "").strip(),
            to_number=source.get("ONCALL_PHONE_NUMBER", ""),
            webhook_secret=SecretStr(source.get("AFRICASTALKING_WEBHOOK_SECRET", "")),
            sandbox=username.lower() == "sandbox" or sandbox_flag,
        )

    @property
    def endpoint(self) -> str:
        return SANDBOX_URL if self.sandbox else PRODUCTION_URL

    def require_live(self) -> None:
        """Raise ``AfricasTalkingConfigError`` if any live-mode setting is missing."""
        missing = [
            name
            for name, value in (
                ("AFRICASTALKING_USERNAME", self.username),
                ("AFRICASTALKING_API_KEY", self.api_key.get_secret_value()),
                ("ONCALL_PHONE_NUMBER", self.to_number),
            )
            if not value
        ]
        if missing:
            raise AfricasTalkingConfigError(f"live SMS requires: {', '.join(missing)}")


class AfricasTalkingSmsAdapter:
    """``SmsPort`` implementation with live and ``DRY_RUN`` modes."""

    def __init__(
        self,
        settings: AfricasTalkingSettings | None = None,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self._settings = settings if settings is not None else AfricasTalkingSettings.from_env()
        self._outbox: deque[OutboxMessage] = deque(maxlen=OUTBOX_MAX_MESSAGES)
        self._http: httpx.AsyncClient | None = None
        if not self._settings.dry_run:
            self._settings.require_live()
            self._http = httpx.AsyncClient(transport=transport, timeout=_HTTP_TIMEOUT_SECONDS)

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
        if self._http is None:
            self._outbox.append(OutboxMessage(text=safe, to=self._settings.to_number))
            logger.info("DRY_RUN sms recorded (%d chars)", len(safe))
            return
        form = {
            "username": self._settings.username,
            "to": self._settings.to_number,
            "message": safe,
        }
        if self._settings.shortcode:
            form["from"] = self._settings.shortcode
        headers = {
            "apiKey": self._settings.api_key.get_secret_value(),
            "Accept": "application/json",
            "Content-Type": "application/x-www-form-urlencoded",
        }
        try:
            response = await self._http.post(self._settings.endpoint, data=form, headers=headers)
        except httpx.HTTPError as exc:
            raise SmsSendError(f"africastalking request failed: {type(exc).__name__}") from exc
        if not response.is_success:
            raise SmsSendError(
                f"africastalking returned HTTP {response.status_code}",
                retryable=_http_status_retryable(response.status_code),
            )
        self._check_recipients(response)

    @staticmethod
    def _check_recipients(response: httpx.Response) -> None:
        try:
            body: Any = response.json()
            recipients = body["SMSMessageData"]["Recipients"]
        except (ValueError, KeyError, TypeError) as exc:
            raise SmsSendError("africastalking response was malformed", retryable=False) from exc
        if not isinstance(recipients, list) or not recipients:
            raise SmsSendError("africastalking reported no recipients")
        for recipient in recipients:
            code = recipient.get("statusCode") if isinstance(recipient, dict) else None
            if code not in _OK_STATUS_CODES:
                status = recipient.get("status", "unknown") if isinstance(recipient, dict) else "?"
                raise SmsSendError(
                    f"africastalking recipient failed: {code} {status}",
                    retryable=isinstance(code, int) and code >= 500,
                )

    async def aclose(self) -> None:
        """Close the live HTTP client, if any."""
        if self._http is not None:
            await self._http.aclose()
