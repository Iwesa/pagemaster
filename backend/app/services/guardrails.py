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

Audit hash contract (must match ``database/30_demo_seed.sql`` (seed) and ``10_schema.sql``)::

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
import unicodedata
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
#: A service name starting with 1 or 2 would complete ``INC-AB 1...`` into a reply lookalike.
_LEADING_DIGIT_RE: Final[re.Pattern[str]] = re.compile(r"[12]")
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


#: Invisible characters removed outright (zero-width space/joiners, word joiner, BOM, soft hyphen).
_DROPPED: Final[frozenset[str]] = frozenset("\u200b\u200c\u200d\u2060\ufeff\u00ad")
#: Letters with no NFKD decomposition into base letter plus mark.
_LETTER_FOLDS: Final[Mapping[str, str]] = {
    "\u00df": "ss",
    "\u00e6": "ae",
    "\u00c6": "AE",
    "\u00f8": "o",
    "\u00d8": "O",
    "\u0153": "oe",
    "\u0152": "OE",
    "\u0142": "l",
    "\u0141": "L",
    "\u0111": "d",
    "\u0110": "D",
    "\u0131": "i",
}


def _fold_non_ascii(ch: str) -> str | None:
    """ASCII rendering of one non-ASCII character, or ``None`` when it has none.

    Order: explicit table (smart quotes, dashes, ellipsis, euro...), whitespace, letter folds,
    then NFKD with the combining marks removed (``e`` + acute -> ``e``, full-width ``A`` -> ``A``).
    """
    mapped = _TRANSLITERATIONS.get(ch) or _LETTER_FOLDS.get(ch)
    if mapped is not None:
        return mapped
    if ch.isspace():
        return " "
    base = "".join(c for c in unicodedata.normalize("NFKD", ch) if not unicodedata.combining(c))
    if base and all(" " <= c <= "~" for c in base):
        return base
    return None


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
    in_run = False  # inside a run of unmappable characters (they share one ``?``)
    for ch in text:
        code = ord(ch)
        if code < 128:
            in_run = False
            if ch in _TRANSLITERATIONS:
                out.append(_TRANSLITERATIONS[ch])
                transliterated = True
            elif code < 32 or code == 127:
                out.append(" ")
            else:
                out.append(ch)
            continue
        if ch in _DROPPED or unicodedata.combining(ch):
            transliterated = True  # invisible: no output and no effect on the current run
            continue
        folded = _fold_non_ascii(ch)
        if folded is not None:
            out.append(folded)
            transliterated = True
            in_run = False
        elif not in_run:
            out.append("?")
            replaced = True
            in_run = True
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


# ---------------------------------------------------------------------------
# SMS reply parsing (Req 4.4)
# ---------------------------------------------------------------------------

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
