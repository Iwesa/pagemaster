"""Deterministic guardrails for Pagemaster.

Pure domain code: only the standard library and Pydantic v2 are imported, so the
agents and the API layer can both depend on it without crossing hexagonal
boundaries.

Covers:
  * Req 3.1-3.3 / Property 1: ``sanitize_pager_text`` and ``format_pager_payload``.
  * Req 4.4 / Property 3:     ``parse_sms_reply``.
  * Req 5.1-5.2 / Property 4: ``TripwireValidator``.
  * Req 5.3 / Property 5:     ``AuditLogger``, ``compute_audit_hash``, ``verify_chain``.
  * Req 5.4-5.5 / Property 5: ``ResolutionGates`` and ``can_resolve``.

Audit hash contract (must match ``database/init_mock_logs.sql``)::

    hash = hex(sha256(utf8(
        prev_hash '|' incident_id '|' seq '|' event_type '|' payload_text)))

* ``prev_hash`` is the previous record's hash, or 64 ``'0'`` characters for the
  first record (``seq == 0``) of an incident.
* ``incident_id`` is the lowercase hyphenated UUID text (``uuid::text``).
* ``seq`` is the decimal integer; sequences start at 0 and increase by 1.
* ``payload_text`` is PostgreSQL's ``jsonb::text`` rendering: object keys sorted
  by (byte length, bytes), ``": "`` after keys, ``", "`` between items, no
  escaping of non-ASCII characters. See :func:`jsonb_text`. Floats are rendered
  as Postgres ``numeric`` text (plain decimal, no exponent); NaN/Infinity raise.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import math
import re
from collections import Counter
from collections.abc import Collection, Iterable, Mapping, Sequence
from decimal import Decimal
from enum import StrEnum
from typing import Any, Final, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

PAGER_MAX_CHARS: Final[int] = 160
GENESIS_HASH: Final[str] = "0" * 64
REDACTION: Final[str] = "***"
_MAX_SERVICE_CHARS: Final[int] = 32
_TOKEN_RE: Final[re.Pattern[str]] = re.compile(r"[A-Z0-9]{2}", re.ASCII)


class AuditEvent(StrEnum):
    """Well-known audit ``event_type`` values."""

    INCIDENT_CREATED = "INCIDENT_CREATED"
    GUARDRAIL_CLAMPED = "GUARDRAIL_CLAMPED"
    SECURITY_VIOLATION = "SECURITY_VIOLATION"
    TRIPWIRE_PASSED = "TRIPWIRE_PASSED"
    TRIPWIRE_BLOCKED = "TRIPWIRE_BLOCKED"


# ---------------------------------------------------------------------------
# Sanitisation (Req 3.2, 3.3)
# ---------------------------------------------------------------------------

_BEARER_RE: Final[re.Pattern[str]] = re.compile(r"bearer(?:\s+\S+|\s*$)", re.IGNORECASE)
_JWT_RE: Final[re.Pattern[str]] = re.compile(r"eyJ[A-Za-z0-9_\-]*(?:\.[A-Za-z0-9_\-]*)*")
_EMAIL_RE: Final[re.Pattern[str]] = re.compile(r"[^\s@]+@[^\s@]+")
# Loose IPv6 candidate: a run of hex digits, '.' and ':' containing at least one ':',
# optionally followed by a zone id (``%eth0``). Candidates are only redacted when
# ``ipaddress`` confirms a real IPv6 address, so ``12:30:45`` and ``ab:cd:ef`` survive.
_IPV6_CANDIDATE_RE: Final[re.Pattern[str]] = re.compile(
    r"[0-9A-Fa-f:.]*:[0-9A-Fa-f:.]*(?:%[0-9A-Za-z_.\-]+)?"
)
_IPV4_RE: Final[re.Pattern[str]] = re.compile(r"\d{1,3}(?:\.\d{1,3}){3}")
_SECRET_CANDIDATE_RE: Final[re.Pattern[str]] = re.compile(r"[A-Za-z0-9+/=_\-]{20,}")
_WS_RE: Final[re.Pattern[str]] = re.compile(r"\s+", re.ASCII)


def _valid_ipv6_span(candidate: str) -> tuple[int, int] | None:
    """Return the (start, end) of the first real IPv6 address inside ``candidate``.

    Leading/trailing ``:`` and ``.`` (sentence punctuation) are trimmed, fewest first.
    """
    n = len(candidate)
    starts = [0]
    while starts[-1] < n and candidate[starts[-1]] in ":.":
        starts.append(starts[-1] + 1)
    ends = [n]
    while ends[-1] > 0 and candidate[ends[-1] - 1] in ":.":
        ends.append(ends[-1] - 1)
    for start in starts:
        for end in ends:
            part = candidate[start:end]
            if end <= start or ":" not in part:
                continue
            try:
                ipaddress.IPv6Address(part)
            except ValueError:
                continue
            return start, end
    return None


def _redact_ipv6(text: str) -> tuple[str, int]:
    count = 0

    def _sub(match: re.Match[str]) -> str:
        nonlocal count
        cand = match.group(0)
        span = _valid_ipv6_span(cand)
        if span is None:
            return cand
        count += 1
        return cand[: span[0]] + REDACTION + cand[span[1] :]

    return _IPV6_CANDIDATE_RE.sub(_sub, text), count


def _shannon_entropy(value: str) -> float:
    counts = Counter(value)
    total = len(value)
    return -sum((n / total) * math.log2(n / total) for n in counts.values())


def _looks_like_secret(candidate: str) -> bool:
    entropy = _shannon_entropy(candidate)
    has_digit = any(c.isdigit() for c in candidate)
    has_alpha = any(c.isalpha() for c in candidate)
    if len(candidate) >= 32 and entropy >= 4.0:
        return True
    return has_digit and has_alpha and entropy >= 3.5


def _redact_secret_candidate(match: re.Match[str]) -> str:
    return REDACTION if _looks_like_secret(match.group(0)) else match.group(0)


class ClampReason(StrEnum):
    """Why a pager payload was modified (reported with ``GUARDRAIL_CLAMPED``)."""

    REDACTED = "REDACTED"
    NON_ASCII = "NON_ASCII"
    TRANSLITERATED = "TRANSLITERATED"
    TRUNCATED = "TRUNCATED"


# ---------------------------------------------------------------------------
# GSM 03.38 (GSM-7) septet accounting and UCS-2 prevention (Req 3.1)
# ---------------------------------------------------------------------------

# Default alphabet (1 septet each). The ESC slot (0x1B) is not a character.
_GSM7_BASIC: Final[frozenset[str]] = frozenset(
    "@\u00a3$\u00a5\u00e8\u00e9\u00f9\u00ec\u00f2\u00c7\n\u00d8\u00f8\r\u00c5\u00e5"
    "\u0394_\u03a6\u0393\u039b\u03a9\u03a0\u03a8\u03a3\u0398\u039e"
    "\u00c6\u00e6\u00df\u00c9 !\"#\u00a4%&'()*+,-./0123456789:;<=>?"
    "\u00a1ABCDEFGHIJKLMNOPQRSTUVWXYZ\u00c4\u00d6\u00d1\u00dc\u00a7"
    "\u00bfabcdefghijklmnopqrstuvwxyz\u00e4\u00f6\u00f1\u00fc\u00e0"
)
# Extension table (ESC + char = 2 septets).
_GSM7_EXTENSION: Final[frozenset[str]] = frozenset("\f^{}\\[~]|\u20ac")

_TRANSLITERATIONS: Final[Mapping[str, str]] = {
    "`": "'",
    "\u00b4": "'",
    "\u2018": "'",
    "\u2019": "'",
    "\u201a": ",",
    "\u201b": "'",
    "\u2032": "'",
    "\u201c": '"',
    "\u201d": '"',
    "\u201e": '"',
    "\u201f": '"',
    "\u2033": '"',
    "\u00ab": '"',
    "\u00bb": '"',
    "\u2010": "-",
    "\u2011": "-",
    "\u2012": "-",
    "\u2013": "-",
    "\u2014": "-",
    "\u2015": "-",
    "\u2212": "-",
    "\u2026": "...",
    "\u20ac": "EUR",
    "\u00a0": " ",
    "\u2022": "*",
    "\u00d7": "x",
}


def gsm7_septet_cost(ch: str) -> int:
    """Septets for one character: 1 (basic) or 2 (extension).

    Raises:
        ValueError: if ``ch`` is not in the GSM 03.38 alphabets (it would force UCS-2).
    """
    if ch in _GSM7_BASIC:
        return 1
    if ch in _GSM7_EXTENSION:
        return 2
    raise ValueError(f"character U+{ord(ch):04X} is not encodable in GSM-7")


def gsm7_septets(text: str) -> int:
    """Number of GSM-7 septets needed for ``text`` (extension characters cost 2).

    Raises:
        ValueError: if any character is outside the GSM 03.38 alphabets.
    """
    return sum(gsm7_septet_cost(ch) for ch in text)


def clamp_to_septets(text: str, limit: int = PAGER_MAX_CHARS) -> str:
    """Longest prefix of ``text`` costing at most ``limit`` septets.

    Never splits a 2-septet extension character: it is kept whole or dropped.
    """
    used = 0
    for index, ch in enumerate(text):
        used += gsm7_septet_cost(ch)
        if used > limit:
            return text[:index]
    return text


def transliterate_gsm7(text: str) -> tuple[str, bool, bool]:
    """Fold ``text`` to printable ASCII that is also encodable in GSM-7.

    Returns ``(text, transliterated, replaced)``: ``transliterated`` is true when
    a known mapping applied (backtick, smart quotes/dashes, ellipsis, euro...),
    ``replaced`` when an unmappable non-ASCII character became ``?``. Control
    characters become spaces; whitespace is not collapsed here.
    """
    out: list[str] = []
    transliterated = False
    replaced = False
    for ch in text:
        mapped = _TRANSLITERATIONS.get(ch)
        code = ord(ch)
        if mapped is not None:
            out.append(mapped)
            transliterated = True
        elif code > 127:
            out.append("?")
            replaced = True
        elif code < 32 or code == 127:
            out.append(" ")
        else:
            out.append(ch)
    return "".join(out), transliterated, replaced


def to_gsm7_safe(text: str) -> str:
    """ASCII-only, GSM-7 encodable rendering of ``text`` (no UCS-2 fallback possible)."""
    return _WS_RE.sub(" ", transliterate_gsm7(text)[0]).strip()


def _ascii_clean(text: str) -> tuple[str, bool, bool]:
    """Transliterate/replace non-GSM text and collapse spaces.

    Returns ``(text, non_ascii_replaced, transliterated)``.
    """
    folded, transliterated, replaced = transliterate_gsm7(text)
    return _WS_RE.sub(" ", folded).strip(), replaced, transliterated


def _redact(text: str) -> tuple[str, int]:
    """Apply every redaction rule; return (text, number_of_redactions)."""
    total = 0
    for pattern in (_BEARER_RE, _JWT_RE, _EMAIL_RE):
        text, n = pattern.subn(REDACTION, text)
        total += n
    text, n = _redact_ipv6(text)
    total += n
    text, n = _IPV4_RE.subn(REDACTION, text)
    total += n
    redacted: list[str] = []

    def _count(match: re.Match[str]) -> str:
        replaced = _redact_secret_candidate(match)
        if replaced != match.group(0):
            redacted.append(replaced)
        return replaced

    text = _SECRET_CANDIDATE_RE.sub(_count, text)
    return text, total + len(redacted)


class SanitizeResult(BaseModel):
    """Outcome of :func:`sanitize_with_report`."""

    model_config = ConfigDict(frozen=True, strict=True)

    text: str
    redactions: int = Field(ge=0)
    non_ascii_replaced: bool
    transliterated: bool = False


def sanitize_with_report(text: str) -> SanitizeResult:
    """Sanitise ``text`` and report whether anything was redacted/replaced."""
    cleaned, non_ascii, translit = _ascii_clean(text)
    redacted, count = _redact(cleaned)
    return SanitizeResult(
        text=redacted,
        redactions=count,
        non_ascii_replaced=non_ascii,
        transliterated=translit,
    )


def sanitize_pager_text(text: str) -> str:
    """Return ASCII text with emails, IPv4/IPv6, bearer tokens and secrets removed."""
    return sanitize_with_report(text).text


# ---------------------------------------------------------------------------
# Pager payload (Req 3.1-3.3)
# ---------------------------------------------------------------------------


def _validate_token(token: str) -> str:
    if _TOKEN_RE.fullmatch(token) is None:
        raise ValueError("token must be exactly 2 uppercase alphanumeric characters")
    return token


def _truncate(text: str, limit: int) -> str:
    """Truncate to at most ``limit`` septets, ending in ``...`` when room allows."""
    if limit <= 0:
        return ""
    if gsm7_septets(text) <= limit:
        return text
    if limit <= 3:
        return clamp_to_septets(text, limit)
    return clamp_to_septets(text, limit - 3).rstrip() + "..."


class PagerPayload(BaseModel):
    """A guaranteed-safe pager message plus clamp metadata."""

    model_config = ConfigDict(frozen=True, strict=True)

    text: str
    clamped: bool
    reasons: tuple[ClampReason, ...] = ()

    @property
    def audit_event(self) -> AuditEvent | None:
        """``GUARDRAIL_CLAMPED`` when the payload was modified, else ``None``."""
        return AuditEvent.GUARDRAIL_CLAMPED if self.clamped else None


TITLE_MAX_SEPTETS: Final[int] = 16
_TITLE_CAPS: Final[tuple[int, ...]] = (TITLE_MAX_SEPTETS, 12, 8, 4)
_MIN_SUMMARY_SEPTETS: Final[int] = 12


def _shorten_title(title: str, limit: int) -> str:
    """Cap ``title`` at ``limit`` septets, preferring a word boundary."""
    if gsm7_septets(title) <= limit:
        return title
    cut = clamp_to_septets(title, limit)
    if len(cut) < len(title) and title[len(cut)] != " " and " " in cut:
        cut = cut[: cut.rindex(" ")]
    return cut.rstrip(" :.-")


def short_title(
    raw: str | None, option: int, limit: int = TITLE_MAX_SEPTETS, *, _reasons: set[ClampReason] | None = None
) -> str:
    """Short pager title for reply option ``option`` (1 or 2).

    Runs ``raw`` through the same PII/ASCII/GSM-7 pipeline as the summary, then
    caps it at ``limit`` septets. Falls back to ``Option <n>`` when ``raw`` is
    missing or empty after sanitisation.
    """
    fallback = f"Option {option}"
    if raw is None:
        return _shorten_title(fallback, limit)
    report = sanitize_with_report(raw)
    if _reasons is not None:
        if report.redactions:
            _reasons.add(ClampReason.REDACTED)
        if report.non_ascii_replaced:
            _reasons.add(ClampReason.NON_ASCII)
        if report.transliterated:
            _reasons.add(ClampReason.TRANSLITERATED)
    text = _shorten_title(report.text, limit)
    if not text.strip("?*. -"):
        text = fallback
    return _shorten_title(text, limit) or fallback[:limit]


def format_pager_payload(
    token: str,
    service_name: str,
    summary: str,
    title1: str | None = None,
    title2: str | None = None,
) -> PagerPayload:
    """Build ``INC-<TOKEN> <service>: <summary>. <TOKEN>-1:<t1> <TOKEN>-2:<t2>``.

    ``title1``/``title2`` are the runbook titles for options 1 and 2 (generic
    ``Option n`` when missing). The result is pure ASCII, at most 160 GSM-7
    septets, and free of emails, IP addresses, bearer tokens and high-entropy
    secrets. The summary is truncated first, then the titles shrink; neither
    reply code is ever dropped. ``clamped`` is true when the summary/service had
    to be redacted, ASCII-folded or truncated (title shortening alone is by
    design and does not count), so the caller can record a ``GUARDRAIL_CLAMPED``
    audit event (Req 3.3).

    Raises:
        ValueError: if ``token`` is not 2 uppercase alphanumeric characters.
    """
    _validate_token(token)
    reasons: set[ClampReason] = set()

    def _clean(value: str) -> str:
        report = sanitize_with_report(value)
        if report.redactions:
            reasons.add(ClampReason.REDACTED)
        if report.non_ascii_replaced:
            reasons.add(ClampReason.NON_ASCII)
        if report.transliterated:
            reasons.add(ClampReason.TRANSLITERATED)
        return report.text

    service = _clean(service_name)
    if len(service) > _MAX_SERVICE_CHARS or gsm7_septets(service) > _MAX_SERVICE_CHARS:
        service = clamp_to_septets(service[:_MAX_SERVICE_CHARS], _MAX_SERVICE_CHARS)
        reasons.add(ClampReason.TRUNCATED)
    service = service.rstrip(":. ") or "unknown"
    # The ": " separator can complete a match (e.g. "0@" + ":" -> "0@:"); redact with it.
    contextual, count = _redact(f"{service}: ")
    if count:
        reasons.add(ClampReason.REDACTED)
        service = contextual.rstrip(":. ") or "unknown"

    prefix = f"INC-{token} {service}: "
    suffix = ""
    budget = 0
    for cap in _TITLE_CAPS:
        t1 = short_title(title1, 1, cap, _reasons=reasons)
        t2 = short_title(title2, 2, cap, _reasons=reasons)
        suffix = f". {token}-1:{t1} {token}-2:{t2}"
        budget = PAGER_MAX_CHARS - gsm7_septets(prefix) - gsm7_septets(suffix)
        if budget >= _MIN_SUMMARY_SEPTETS:
            break

    body = _clean(summary) or "alert"
    for _ in range(3):
        if gsm7_septets(body) > budget:
            body = _truncate(body, budget)
            reasons.add(ClampReason.TRUNCATED)
        again, count = _redact(body)
        if count == 0:
            break
        reasons.add(ClampReason.REDACTED)
        body = again
    else:
        body = ""
    body = body.rstrip(". ") or "alert"
    if _redact(f"{prefix}{body}{suffix}")[1] > 0:
        # Joining body and suffix can form a new match (e.g. "0@" + ". 00-1" -> "0@.").
        # Redact the body with the separator as context instead of dropping the titles.
        body = _redact(f"{body}. ")[0].rstrip(". ") or "alert"
        reasons.add(ClampReason.REDACTED)

    text = f"{prefix}{body}{suffix}"
    if gsm7_septets(text) > PAGER_MAX_CHARS or not text.isascii() or _redact(text)[1] > 0:
        # Last-resort deterministic fallback; cannot violate the invariant.
        reasons.add(ClampReason.TRUNCATED)
        text = f"INC-{token} Reply {token}-1 or {token}-2"

    return PagerPayload(
        text=text,
        clamped=bool(reasons),
        reasons=tuple(sorted(reasons)),
    )


# ---------------------------------------------------------------------------
# SMS reply parsing (Req 4.4)
# ---------------------------------------------------------------------------

_SMS_REPLY_RE: Final[re.Pattern[str]] = re.compile(r"([A-Za-z0-9]{2})-([12])", re.ASCII)


class SmsReply(BaseModel):
    """A parsed ``<TOKEN>-1`` / ``<TOKEN>-2`` reply."""

    model_config = ConfigDict(frozen=True, strict=True)

    token: str
    choice: Literal["1", "2"]

    @property
    def action_code(self) -> str:
        return f"{self.token}-{self.choice}"


def parse_sms_reply(body: str, known_tokens: Collection[str] | None = None) -> SmsReply | None:
    """Parse an SMS body; return ``None`` unless it is exactly ``<TOKEN>-1|2``.

    Case and surrounding whitespace are tolerated; the token is normalised to
    uppercase. When ``known_tokens`` is given, the token must be in it
    (compared case-insensitively). With ``None`` only the format is checked,
    so the caller can still answer "incident no longer active" (Req 4.5).
    """
    match = _SMS_REPLY_RE.fullmatch(body.strip())
    if match is None:
        return None
    token = match.group(1).upper()
    if known_tokens is not None and token not in {t.upper() for t in known_tokens}:
        return None
    choice: Literal["1", "2"] = "1" if match.group(2) == "1" else "2"
    return SmsReply(token=token, choice=choice)


# ---------------------------------------------------------------------------
# Tripwire (Req 5.1, 5.2)
# ---------------------------------------------------------------------------


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


# ---------------------------------------------------------------------------
# Hash-chained audit log (Req 5.3, Property 5)
# ---------------------------------------------------------------------------

type JsonValue = None | bool | int | str | list[JsonValue] | dict[str, JsonValue]


def _jsonb_key_order(key: str) -> tuple[int, bytes]:
    raw = key.encode("utf-8")
    return (len(raw), raw)


def jsonb_text(value: object) -> str:
    """Render ``value`` exactly like PostgreSQL ``jsonb::text``.

    Supports ``None``, ``bool``, ``int``, ``float``, ``str``, lists and dicts
    with string keys.

    Floats: the JSON text of a Python float is ``repr(value)`` (shortest
    round-trip). Postgres parses that text as ``numeric``, which keeps the digits
    and scale as written but never prints an exponent and has no negative zero.
    So ``Decimal(repr(x))`` formatted with ``"f"`` matches: ``1.5 -> 1.5``,
    ``2.0 -> 2.0``, ``1e-07 -> 0.0000001``, ``1e16 -> 10000000000000000``,
    ``-0.0 -> 0.0``. NaN and +/-Infinity are not valid JSON and raise ``ValueError``.
    """
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("NaN and Infinity cannot be represented in jsonb")
        number = Decimal(repr(value))
        rendered = format(number, "f")
        return rendered[1:] if number.is_zero() and rendered.startswith("-") else rendered
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False)
    if isinstance(value, Sequence):
        return "[" + ", ".join(jsonb_text(v) for v in value) + "]"
    if isinstance(value, Mapping):
        items: list[str] = []
        for key in sorted(value, key=_jsonb_key_order):
            if not isinstance(key, str):
                raise TypeError("jsonb object keys must be strings")
            items.append(f"{json.dumps(key, ensure_ascii=False)}: {jsonb_text(value[key])}")
        return "{" + ", ".join(items) + "}"
    raise TypeError(f"unsupported payload type for audit hashing: {type(value).__name__}")


def compute_audit_hash(
    prev_hash: str,
    incident_id: UUID,
    seq: int,
    event_type: str,
    payload: Mapping[str, Any],
) -> str:
    """SHA-256 hex digest of ``prev_hash|incident_id|seq|event_type|payload::text``."""
    material = f"{prev_hash}|{incident_id}|{seq}|{event_type}|{jsonb_text(payload)}"
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


class AuditRecord(BaseModel):
    """One row of ``audit_trail``."""

    model_config = ConfigDict(frozen=True)

    incident_id: UUID
    seq: int = Field(ge=0)
    event_type: str
    payload: dict[str, Any] = Field(default_factory=dict)
    prev_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    hash: str = Field(pattern=r"^[0-9a-f]{64}$")


class ChainVerification(BaseModel):
    """Result of :func:`verify_chain`; ``broken_at`` is the first bad ``seq`` index."""

    model_config = ConfigDict(frozen=True)

    valid: bool
    broken_at: int | None = None


def verify_chain(records: Sequence[AuditRecord]) -> ChainVerification:
    """Verify a single incident's chain, ordered by ``seq``.

    Checks the genesis ``prev_hash``, contiguous ``seq`` from 0, a single
    ``incident_id``, ``prev_hash`` linkage, and each record's recomputed hash.
    ``broken_at`` is the list index of the first failing record.
    """
    prev = GENESIS_HASH
    for index, rec in enumerate(records):
        expected = compute_audit_hash(prev, rec.incident_id, rec.seq, rec.event_type, rec.payload)
        if (
            rec.seq != index
            or rec.incident_id != records[0].incident_id
            or rec.prev_hash != prev
            or rec.hash != expected
        ):
            return ChainVerification(valid=False, broken_at=index)
        prev = rec.hash
    return ChainVerification(valid=True)


class AuditLogger:
    """In-memory builder for one incident's hash chain.

    Persistence is the caller's concern (an adapter inserts each returned
    :class:`AuditRecord`). Resume an existing chain by passing its records.
    """

    def __init__(self, incident_id: UUID, records: Sequence[AuditRecord] = ()) -> None:
        self._incident_id = incident_id
        self._records: list[AuditRecord] = list(records)
        if any(r.incident_id != incident_id for r in self._records):
            raise ValueError("records belong to a different incident")
        if not verify_chain(self._records).valid:
            raise ValueError("existing audit chain failed verification")

    @property
    def records(self) -> tuple[AuditRecord, ...]:
        return tuple(self._records)

    @property
    def head_hash(self) -> str:
        return self._records[-1].hash if self._records else GENESIS_HASH

    def append(self, event_type: str, payload: Mapping[str, Any] | None = None) -> AuditRecord:
        body: dict[str, Any] = dict(payload or {})
        seq = len(self._records)
        prev = self.head_hash
        record = AuditRecord(
            incident_id=self._incident_id,
            seq=seq,
            event_type=str(event_type),
            payload=body,
            prev_hash=prev,
            hash=compute_audit_hash(prev, self._incident_id, seq, str(event_type), body),
        )
        self._records.append(record)
        return record

    def verify(self) -> ChainVerification:
        return verify_chain(self._records)


# ---------------------------------------------------------------------------
# RESOLVED gating (Req 5.4, 5.5)
# ---------------------------------------------------------------------------


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
