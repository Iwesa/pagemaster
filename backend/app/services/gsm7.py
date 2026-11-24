"""GSM 03.38 (GSM-7) septet accounting, ASCII transliteration and UCS-2 prevention.

Standalone domain module (stdlib only). ``PAGER_MAX_CHARS`` is the 160-septet pager limit;
extension characters (``^{}\\[~]|`` and the euro sign) cost 2 septets.
"""

from __future__ import annotations

import re
import unicodedata
from collections.abc import Mapping
from typing import Final

__all__ = [
    "PAGER_MAX_CHARS",
    "clamp_to_septets",
    "gsm7_septet_cost",
    "gsm7_septets",
    "to_gsm7_safe",
    "transliterate_gsm7",
]

PAGER_MAX_CHARS: Final[int] = 160
_WS_RE: Final[re.Pattern[str]] = re.compile(r"\s+", re.ASCII)

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
