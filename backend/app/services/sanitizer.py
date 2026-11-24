"""Pager text sanitiser and payload formatter.

Redacts PII and secrets (emails, IPv4/IPv6, bearer tokens, JWTs, ``key=value`` secrets,
long hex/base64, provider token formats), neutralises reply-code lookalikes and builds the
guaranteed-safe ASCII, <= 160 septet pager message (``format_pager_payload``).
Depends on :mod:`gsm7` and :mod:`audit_chain` (for ``AuditEvent``) only.
"""

from __future__ import annotations

import ipaddress
import math
import re
from collections import Counter
from collections.abc import Sequence
from enum import StrEnum
from typing import Final

from pydantic import BaseModel, ConfigDict, Field

from backend.app.services.audit_chain import AuditEvent
from backend.app.services.gsm7 import (
    _WS_RE,
    PAGER_MAX_CHARS,
    clamp_to_septets,
    gsm7_septets,
    transliterate_gsm7,
)

__all__ = [
    "MAX_PAGE_OPTIONS",
    "NO_ACTION_TEXT",
    "REDACTION",
    "TITLE_MAX_SEPTETS",
    "ClampReason",
    "PagerPayload",
    "SanitizeResult",
    "format_pager_payload",
    "neutralize_reply_codes",
    "sanitize_pager_text",
    "sanitize_with_report",
    "short_title",
]

REDACTION: Final[str] = "***"
_MAX_SERVICE_CHARS: Final[int] = 32
#: A service name starting with 1 or 2 would complete ``INC-AB 1...`` into a reply lookalike.
_LEADING_DIGIT_RE: Final[re.Pattern[str]] = re.compile(r"[12]")
_TOKEN_RE: Final[re.Pattern[str]] = re.compile(r"[A-Z0-9]{2}", re.ASCII)

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
_UUID_RE: Final[re.Pattern[str]] = re.compile(
    r"[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}"
)
# ``key=value`` / ``key: value`` secrets (Req 3.7). The key may carry a closing quote (JSON
# style); the value is quoted, or runs to the next whitespace, comma, semicolon or quote. A scheme
# word (``Basic``, ``Digest``...) before the credential is part of the value.
_SECRET_KEYS: Final[str] = (
    r"password|passwd|pwd|secret|token|api[_\-]?key|authorization|auth|credentials?|"
    r"client[_\-]secret|access[_\-]key|private[_\-]key"
)
_KV_VALUE: Final[str] = r"""(?:"[^"]*"|'[^']*'|[^\s,;"']+)"""
_KV_RE: Final[re.Pattern[str]] = re.compile(
    rf"""(?:{_SECRET_KEYS})["']?\s*[:=]\s*"""
    rf"""(?:(?:basic|digest|negotiate|token|apikey)\s+(?={_KV_VALUE}))?{_KV_VALUE}""",
    re.IGNORECASE,
)
# Provider token formats. Prefix-anchored, so no boundary is needed except for ``sk-``, which
# also ends words such as ``task-`` and ``desk_``.
_TOKEN_FORMAT_RES: Final[tuple[re.Pattern[str], ...]] = (
    re.compile(r"(?<![A-Za-z0-9])sk[-_][A-Za-z0-9_\-]{8,}"),
    re.compile(r"(?:gh[pousr]_|github_pat_)[A-Za-z0-9_]{8,}"),
    re.compile(r"xox[abprs]-[A-Za-z0-9\-]+"),
    re.compile(r"(?:AKIA|ASIA)[A-Z0-9]{16}"),
    re.compile(r"AIza[0-9A-Za-z_\-]{30,}"),
)
#: Long hex digests/keys. Low-entropy runs (``aaaa...``) are padding, not secrets.
_HEX_RE: Final[re.Pattern[str]] = re.compile(r"[0-9A-Fa-f]{32,}")
_HEX_MIN_ENTROPY: Final[float] = 3.0


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
    candidate = match.group(0)
    # UUIDs (8-4-4-4-12 hex) are identifiers, not secrets: leave them alone, also with a
    # short prefix such as ``req-`` attached.
    if _UUID_RE.search(candidate) and len(_UUID_RE.sub("", candidate)) < 20:
        return candidate
    return REDACTION if _looks_like_secret(candidate) else candidate


class ClampReason(StrEnum):
    """Why a pager payload was modified (reported with ``GUARDRAIL_CLAMPED``)."""

    REDACTED = "REDACTED"
    NON_ASCII = "NON_ASCII"
    TRANSLITERATED = "TRANSLITERATED"
    TRUNCATED = "TRUNCATED"
    CODE_NEUTRALIZED = "CODE_NEUTRALIZED"


def _ascii_clean(text: str) -> tuple[str, bool, bool]:
    """Transliterate/replace non-GSM text and collapse spaces.

    Returns ``(text, non_ascii_replaced, transliterated)``.
    """
    folded, transliterated, replaced = transliterate_gsm7(text)
    return _WS_RE.sub(" ", folded).strip(), replaced, transliterated


def _redact_kv(text: str) -> tuple[str, int]:
    count = 0

    def _sub(match: re.Match[str]) -> str:
        nonlocal count
        if not match.group(0).endswith(REDACTION):  # an already redacted value is not news
            count += 1
        return REDACTION

    return _KV_RE.sub(_sub, text), count


def _redact(text: str, *, kv: bool = True) -> tuple[str, int]:
    """Apply every redaction rule; return (text, number_of_redactions).

    ``kv=False`` skips the ``key: value`` rule. It is for checks over an assembled page,
    where ``<service>: <summary>`` (for example ``auth: db down``) is layout, not a secret.
    """
    total = 0
    text, n = _BEARER_RE.subn(REDACTION, text)
    total += n
    if kv:  # before the JWT rule: a JWT run may otherwise swallow the key of a following pair
        text, n = _redact_kv(text)
        total += n
    text, n = _JWT_RE.subn(REDACTION, text)
    total += n
    text, n = _EMAIL_RE.subn(REDACTION, text)
    total += n
    text, n = _redact_ipv6(text)
    total += n
    text, n = _IPV4_RE.subn(REDACTION, text)
    total += n
    for token_re in _TOKEN_FORMAT_RES:
        text, n = token_re.subn(REDACTION, text)
        total += n
    hex_hits = 0

    def _hex(match: re.Match[str]) -> str:
        nonlocal hex_hits
        if _shannon_entropy(match.group(0)) < _HEX_MIN_ENTROPY:
            return match.group(0)
        hex_hits += 1
        return REDACTION

    text = _HEX_RE.sub(_hex, text)
    total += hex_hits
    redacted: list[str] = []

    def _count(match: re.Match[str]) -> str:
        replaced = _redact_secret_candidate(match)
        if replaced != match.group(0):
            redacted.append(replaced)
        return replaced

    text = _SECRET_CANDIDATE_RE.sub(_count, text)
    return text, total + len(redacted)


# ---------------------------------------------------------------------------
# Reply-code injection (Req 3.8)
# ---------------------------------------------------------------------------

#: Anything ``parse_sms_reply`` could take for a reply once it is on its own: two alphanumerics,
#: ``-`` or a space, then ``1`` or ``2``. There is no boundary on either side on purpose:
#: ``web-1`` is rewritten because the window ``eb-1`` is a valid reply, and ``ab-12`` is rewritten
#: so truncating text after the digit can never create a code.
_CODE_LOOKALIKE_RE: Final[re.Pattern[str]] = re.compile(
    r"([A-Za-z0-9]{2})[- ](?=[12])", re.ASCII
)


def neutralize_reply_codes(text: str) -> tuple[str, bool]:
    """Rewrite every reply-code lookalike in ASCII ``text`` so it cannot be replied verbatim.

    ``AB-1`` / ``ab 2`` become ``AB_1`` / ``ab_2``. Run on untrusted text (alert summary, log
    line, LLM output, service name, runbook title) before the real ``<TOKEN>-N`` options are
    appended, so those are the only codes on the page (Req 3.8). Returns ``(text, changed)``.
    """
    out, count = _CODE_LOOKALIKE_RE.subn(r"\1_", text)
    return out, count > 0


class SanitizeResult(BaseModel):
    """Outcome of :func:`sanitize_with_report`."""

    model_config = ConfigDict(frozen=True, strict=True)

    text: str
    redactions: int = Field(ge=0)
    non_ascii_replaced: bool
    transliterated: bool = False
    neutralized: bool = False


def sanitize_with_report(text: str, *, neutralize_codes: bool = True) -> SanitizeResult:
    """Sanitise ``text`` and report whether anything was redacted/replaced.

    Pipeline: transliterate to ASCII, redact secrets and PII, neutralise reply-code lookalikes.
    Redaction runs here, before any truncation by the callers.
    """
    cleaned, non_ascii, translit = _ascii_clean(text)
    redacted, count = _redact(cleaned)
    neutralized = False
    if neutralize_codes:
        redacted, neutralized = neutralize_reply_codes(redacted)
    return SanitizeResult(
        text=redacted,
        redactions=count,
        non_ascii_replaced=non_ascii,
        transliterated=translit,
        neutralized=neutralized,
    )


def sanitize_pager_text(text: str, *, neutralize_codes: bool = True) -> str:
    """ASCII text with secrets, emails, IPs and bearer tokens removed and no reply-code lookalikes.

    ``neutralize_codes=False`` keeps names such as ``db-1`` intact (used only to test whether a
    name survives redaction).
    """
    return sanitize_with_report(text, neutralize_codes=neutralize_codes).text


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
_OPTION_LETTERS: Final[str] = "AB"
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
    fallback = f"Option {_OPTION_LETTERS[(option - 1) % 2]}"  # not "Option 1": "on 1" is a reply lookalike
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
        if report.neutralized:
            _reasons.add(ClampReason.CODE_NEUTRALIZED)
    text = _shorten_title(report.text, limit)
    if not text.strip("?*. -"):
        text = fallback
    return _shorten_title(text, limit) or fallback[:limit]


MAX_PAGE_OPTIONS: Final[int] = 2
NO_ACTION_TEXT: Final[str] = "No approved action. Manual response needed."


def _option_suffix(token: str, titles: Sequence[str | None], cap: int, reasons: set[ClampReason]) -> str:
    """Page tail: ``. <TOKEN>-1:<t1> <TOKEN>-2:<t2>`` per option, or the no-action notice.

    ``short_title`` sanitises each title, including reply-code neutralisation, before the real
    ``<TOKEN>-N:`` entry is put in front of it.
    """
    if not titles:
        return f". {NO_ACTION_TEXT}"
    # A title ending in two alphanumerics, a space and a token that starts with 1 or 2 would read as
    # a reply (``11 1`` in ``...:11 10-2``). Only then is ``,`` used between the options instead.
    parts = [f"{token}-{n}:{short_title(raw, n, cap, _reasons=reasons)}" for n, raw in enumerate(titles, 1)]
    options = parts[0]
    for part in parts[1:]:
        tail = options[-2:]
        joins_badly = token[0] in "12" and len(tail) == 2 and tail.isalnum() and tail.isascii()
        options += ("," if joins_badly else " ") + part
    return f". {options}"


def format_pager_payload(
    token: str,
    service_name: str,
    summary: str,
    title1: str | None = None,
    title2: str | None = None,
    *,
    option_titles: Sequence[str | None] | None = None,
) -> PagerPayload:
    """Build ``INC-<TOKEN> <service>: <summary>. <TOKEN>-1:<t1> <TOKEN>-2:<t2>``.

    The number of reply options is explicit. With ``option_titles`` there is one
    ``<TOKEN>-N:<title>`` option per entry (at most 2; extra entries are ignored)
    and an empty sequence means no approved action: the page then ends with
    ``No approved action. Manual response needed.`` and carries no reply code
    (Req 3.4-3.6). Without ``option_titles`` the legacy two-option form is built
    from ``title1``/``title2`` (generic ``Option A``/``Option B`` when missing).

    The result is pure ASCII, at most 160 GSM-7
    septets, and free of emails, IP addresses, bearer tokens and high-entropy
    secrets. The summary is truncated first, then the titles shrink; no
    offered reply code is ever dropped. ``clamped`` is true when the summary/service had
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
        if report.neutralized:
            reasons.add(ClampReason.CODE_NEUTRALIZED)
        return report.text

    service = _clean(service_name)
    if _LEADING_DIGIT_RE.match(service):
        # ``INC-AB 1: ...`` would read as the reply ``AB 1``.
        service = f"#{service}"
    if len(service) > _MAX_SERVICE_CHARS or gsm7_septets(service) > _MAX_SERVICE_CHARS:
        service = clamp_to_septets(service[:_MAX_SERVICE_CHARS], _MAX_SERVICE_CHARS)
        reasons.add(ClampReason.TRUNCATED)
    service = service.rstrip(":. ") or "unknown"
    # The ": " separator can complete a match (e.g. "0@" + ":" -> "0@:"); redact with it.
    contextual, count = _redact(f"{service}: ", kv=False)
    if count:
        reasons.add(ClampReason.REDACTED)
        service = contextual.rstrip(":. ") or "unknown"

    raw_titles: list[str | None] = (
        [title1, title2] if option_titles is None else list(option_titles[:MAX_PAGE_OPTIONS])
    )
    prefix = f"INC-{token} {service}: "
    suffix = ""
    budget = 0
    for cap in _TITLE_CAPS:
        suffix = _option_suffix(token, raw_titles, cap, reasons)
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
        if not raw_titles:
            text = f"INC-{token} {NO_ACTION_TEXT}"
        elif len(raw_titles) == 1:
            text = f"INC-{token} Reply: {token}-1"
        else:
            text = f"INC-{token} Reply: {token}-1, {token}-2"

    return PagerPayload(
        text=text,
        clamped=bool(reasons),
        reasons=tuple(sorted(reasons)),
    )
