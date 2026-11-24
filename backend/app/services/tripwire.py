"""SMS reply grammar, tripwire validation and RESOLVED gating.

Holds the ``<TOKEN>-1|2`` reply grammar (``parse_sms_reply``), the ``TripwireValidator``
(target host and approved action re-check at execution time) and ``ResolutionGates``
(``can_resolve``). Depends on :mod:`audit_chain` for ``AuditEvent`` only.
"""

from __future__ import annotations

import re
import unicodedata
from collections.abc import Collection, Iterable, Mapping
from typing import Any, Final, Literal

from pydantic import BaseModel, ConfigDict

from backend.app.services.audit_chain import AuditEvent

__all__ = [
    "ResolutionGates",
    "SmsReply",
    "TripwireResult",
    "TripwireValidator",
    "TripwireViolationError",
    "can_resolve",
    "normalize_sms_reply",
    "parse_sms_reply",
]

_SMS_REPLY_RE: Final[re.Pattern[str]] = re.compile(r"([A-Za-z0-9]{2})[- ]([12])", re.ASCII)
_REPLY_TRAILING_RE: Final[re.Pattern[str]] = re.compile(r"[\s.!]+\Z")
#: Dash variants (U+2010..U+2015, U+2212) folded to ``-``. NFKC leaves them untouched.
_REPLY_DASHES: Final[Mapping[int, str]] = {
    **{cp: "-" for cp in range(0x2010, 0x2016)},
    0x2212: "-",
}
_FULLWIDTH_FIRST: Final[int] = 0xFF01
_FULLWIDTH_LAST: Final[int] = 0xFF5E


def _reply_char_allowed(ch: str) -> bool:
    """Only ASCII, full-width forms (U+FF01..U+FF5E), the dash set and whitespace may enter NFKC.

    NFKC also folds characters such as superscript digits or the Kelvin sign into
    ASCII letters and digits; those must not be accepted as ``<TOKEN>-<N>``.
    """
    code = ord(ch)
    return (
        code < 0x80
        or _FULLWIDTH_FIRST <= code <= _FULLWIDTH_LAST
        or code in _REPLY_DASHES
        or ch.isspace()
    )


def normalize_sms_reply(body: str) -> str | None:
    """Canonical form of a reply body, or ``None`` when it holds a disallowed character.

    NFKC, dash variants to ``-``, then leading whitespace and trailing ``.``, ``!`` and
    whitespace are dropped.
    """
    if not all(_reply_char_allowed(ch) for ch in body):
        return None
    text = unicodedata.normalize("NFKC", body).translate(_REPLY_DASHES)
    return _REPLY_TRAILING_RE.sub("", text.lstrip())


class SmsReply(BaseModel):
    """A parsed ``<TOKEN>-1`` / ``<TOKEN>-2`` reply."""

    model_config = ConfigDict(frozen=True, strict=True)

    token: str
    choice: Literal["1", "2"]

    @property
    def action_code(self) -> str:
        return f"{self.token}-{self.choice}"


def parse_sms_reply(body: str, known_tokens: Collection[str] | None = None) -> SmsReply | None:
    """Parse an SMS body; return ``None`` unless it normalises to exactly ``<TOKEN>-1|2``.

    The body is normalised first (:func:`normalize_sms_reply`: NFKC, dash variants,
    trailing ``.``/``!``/whitespace); a single space may replace the dash. Any other
    leading or trailing text is rejected. The token is normalised to
    uppercase. When ``known_tokens`` is given, the token must be in it
    (compared case-insensitively). With ``None`` only the format is checked,
    so the caller can still answer "incident no longer active" (Req 4.5).
    """
    normalized = normalize_sms_reply(body)
    match = None if normalized is None else _SMS_REPLY_RE.fullmatch(normalized)
    if match is None:
        return None
    token = match.group(1).upper()
    if known_tokens is not None and token not in {t.upper() for t in known_tokens}:
        return None
    choice: Literal["1", "2"] = "1" if match.group(2) == "1" else "2"
    return SmsReply(token=token, choice=choice)


class TripwireResult(BaseModel):
    """Outcome of a tripwire check. ``reason`` values mirror the audit payloads."""

    model_config = ConfigDict(frozen=True, strict=True)

    passed: bool
    reason: Literal["ok", "target_host_mismatch", "action_not_approved"]
    target_host: str
    action_id: str
    token: str | None = None

    def audit_event(self) -> AuditEvent:
        return AuditEvent.TRIPWIRE_PASSED if self.passed else AuditEvent.TRIPWIRE_BLOCKED

    def audit_payload(self) -> dict[str, Any]:
        payload: dict[str, Any] = {"target_host": self.target_host, "action_id": self.action_id}
        if self.token is not None:
            payload["token"] = self.token
        if not self.passed:
            payload["reason"] = self.reason
        return payload


class TripwireViolationError(Exception):
    """Raised by :meth:`TripwireValidator.ensure` when a tripwire check does not pass."""

    def __init__(self, result: TripwireResult) -> None:
        super().__init__(f"tripwire blocked: {result.reason}")
        self.result = result


class TripwireValidator:
    """Passes iff ``target_host == service_name`` and ``action_id`` is approved."""

    def __init__(self, approved_action_ids: Iterable[str]) -> None:
        self._approved: frozenset[str] = frozenset(approved_action_ids)

    @property
    def approved_action_ids(self) -> frozenset[str]:
        return self._approved

    def validate(
        self,
        *,
        target_host: str,
        service_name: str,
        action_id: str,
        token: str | None = None,
    ) -> TripwireResult:
        if target_host != service_name:
            reason: Literal["ok", "target_host_mismatch", "action_not_approved"] = (
                "target_host_mismatch"
            )
        elif action_id not in self._approved:
            reason = "action_not_approved"
        else:
            reason = "ok"
        return TripwireResult(
            passed=reason == "ok",
            reason=reason,
            target_host=target_host,
            action_id=action_id,
            token=token,
        )

    def ensure(
        self,
        *,
        target_host: str,
        service_name: str,
        action_id: str,
        token: str | None = None,
    ) -> TripwireResult:
        """Like :meth:`validate` but raise :class:`TripwireViolationError` when blocked."""
        result = self.validate(
            target_host=target_host, service_name=service_name, action_id=action_id, token=token
        )
        if not result.passed:
            raise TripwireViolationError(result)
        return result


class ResolutionGates(BaseModel):
    """The four gating flags. ``None`` means "never evaluated" and blocks RESOLVED."""

    model_config = ConfigDict(frozen=True, strict=True, extra="forbid")

    tripwire_check_passed: bool | None = None
    simulated_step_executed: bool | None = None
    confirmation_sms_sent: bool | None = None
    audit_record_committed: bool | None = None


def can_resolve(gates: ResolutionGates) -> bool:
    """True only when all four gating flags are exactly ``True``."""
    return (
        gates.tripwire_check_passed is True
        and gates.simulated_step_executed is True
        and gates.confirmation_sms_sent is True
        and gates.audit_record_committed is True
    )
