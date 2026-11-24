"""Page rate limiting and coalesced summary pages (Req 10.3).

``PageRateLimiter`` admits at most ``PAGE_RATE_PER_MINUTE`` individual pages in ANY 60 s window.
A classic token bucket with capacity ``rate`` and refill ``rate / 60`` per second would allow up
to ``2 * rate`` pages inside one window (a full burst plus a minute of refill), so the limiter
keeps the timestamps of the admitted pages instead: a page is admitted only while fewer than
``rate`` admissions happened in the last 60 s. The clock is injectable.

``CoalescingPageGate`` implements the domain ``PageGate`` port on top of it. A request over the
limit is recorded (per service, plus the reply token when the incident has options) and left
for ``flush``, which sends at most one summary page per ``summary_interval`` seconds::

    ALERTS: 54 more (auth-db x40, payment-gateway x14) codes AB CD see dashboard

The reply tokens are listed only when the whole text fits in 160 GSM-7 septets; otherwise the
coalesced incidents simply expire through the approval TTL. State is in memory and per worker.
"""

from __future__ import annotations

import asyncio
import logging
import re
import time
from collections import deque
from collections.abc import Callable, Mapping, Sequence
from typing import Final

from backend.app.agents.ports import PageDecision, SmsPort
from backend.app.services.guardrails import PAGER_MAX_CHARS, gsm7_septets, sanitize_pager_text
from backend.app.services.sms_common import PagerInvariantError, validate_outbound

logger = logging.getLogger("pagemaster.page_rate")

DEFAULT_PAGE_RATE_PER_MINUTE: Final[int] = 6
RATE_WINDOW_SECONDS: Final[float] = 60.0
SUMMARY_INTERVAL_SECONDS: Final[float] = 60.0
#: Bounds on in-memory pending state during a long storm.
MAX_PENDING_SERVICES: Final[int] = 100
MAX_PENDING_CODES: Final[int] = 100
SERVICE_NAME_MAX_CHARS: Final[int] = 24
OTHER_SERVICES: Final[str] = "other"
_UNSAFE_NAME_RE: Final[re.Pattern[str]] = re.compile(r"[^A-Za-z0-9._-]")


class PageRateLimiter:
    """Sliding-window limiter: at most ``rate`` admissions in any 60 s window."""

    def __init__(
        self,
        rate_per_minute: int = DEFAULT_PAGE_RATE_PER_MINUTE,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if rate_per_minute < 1:
            raise ValueError("rate_per_minute must be >= 1")
        self.rate = rate_per_minute
        self._clock = clock
        self._admitted: deque[float] = deque()

    def try_acquire(self) -> bool:
        """Admit one page now, or refuse. Synchronous, so check-and-record is atomic."""
        now = self._clock()
        while self._admitted and now - self._admitted[0] >= RATE_WINDOW_SECONDS:
            self._admitted.popleft()
        if len(self._admitted) >= self.rate:
            return False
        self._admitted.append(now)
        return True


def _compose(total: int, parts: Sequence[str], codes: Sequence[str]) -> str:
    text = f"ALERTS: {total} more"
    if parts:
        text += f" ({', '.join(parts)})"
    if codes:
        text += f" codes {' '.join(codes)}"
    return text + " see dashboard"


def format_summary(
    counts: Mapping[str, int], codes: Sequence[str] = (), *, codes_complete: bool = True
) -> str:
    """Build the coalesced summary text (at most 160 septets).

    Services are listed by descending count; those that do not fit are folded into
    ``other xM``. Reply codes are appended only when every code fits (and none was dropped).
    """
    total = sum(counts.values())
    ranked = sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))
    parts = [f"{name} x{n}" for name, n in ranked]
    shown = parts
    for keep in range(len(parts), -1, -1):
        hidden = sum(n for _, n in ranked[keep:])
        shown = parts[:keep] + ([f"{OTHER_SERVICES} x{hidden}"] if hidden else [])
        if gsm7_septets(_compose(total, shown, ())) <= PAGER_MAX_CHARS:
            break
    if codes and codes_complete:
        with_codes = _compose(total, shown, codes)
        if gsm7_septets(with_codes) <= PAGER_MAX_CHARS:
            return with_codes
    return _compose(total, shown, ())


def _safe_name(service_name: str) -> str:
    """A name that survives the outbound sanitiser unchanged, else ``other`` (the sanitiser
    redacts long token-like strings, which would make the whole summary unsendable)."""
    name = _UNSAFE_NAME_RE.sub("_", service_name)[:SERVICE_NAME_MAX_CHARS] or "unknown"
    return name if sanitize_pager_text(name) == name else OTHER_SERVICES


class CoalescingPageGate:
    """``PageGate`` that rate-limits individual pages and flushes one summary page per minute."""

    def __init__(
        self,
        sms: SmsPort,
        limiter: PageRateLimiter,
        *,
        clock: Callable[[], float] = time.monotonic,
        summary_interval: float = SUMMARY_INTERVAL_SECONDS,
    ) -> None:
        self._sms = sms
        self._limiter = limiter
        self._clock = clock
        self._interval = summary_interval
        self._counts: dict[str, int] = {}
        self._codes: list[str] = []
        self._codes_complete = True
        self._last_attempt: float | None = None
        self._flush_lock = asyncio.Lock()
        self.admitted_total = 0
        self.coalesced_total = 0
        self.summaries_sent = 0

    @property
    def pending(self) -> int:
        return sum(self._counts.values())

    async def admit(self, *, token: str, service_name: str, actionable: bool) -> PageDecision:
        if self._limiter.try_acquire():
            self.admitted_total += 1
            return "SEND"
        self.coalesced_total += 1
        self._record(_safe_name(service_name), token if actionable else None)
        return "COALESCED"

    def _record(self, name: str, code: str | None) -> None:
        if name not in self._counts and len(self._counts) >= MAX_PENDING_SERVICES:
            name = OTHER_SERVICES
        self._counts[name] = self._counts.get(name, 0) + 1
        if code is not None:
            if len(self._codes) < MAX_PENDING_CODES:
                self._codes.append(code)
            else:
                self._codes_complete = False

    async def flush(self) -> bool:
        """Send one summary page for the pending incidents if one is due. Returns True if sent.

        Called from the reaper tick. At most one attempt per ``summary_interval``; a failed
        send keeps the entries for the next attempt. Never raises (except cancellation).
        """
        async with self._flush_lock:
            if not self._counts:
                return False
            now = self._clock()
            if self._last_attempt is not None and now - self._last_attempt < self._interval:
                return False
            self._last_attempt = now
            counts, codes, complete = self._counts, self._codes, self._codes_complete
            self._counts, self._codes, self._codes_complete = {}, [], True
            text = self._text(counts, codes, complete)
            try:
                await self._sms.send(text)
            except asyncio.CancelledError:
                self._restore(counts, codes, complete)
                raise
            except Exception:
                logger.warning("summary page undeliverable; %d coalesced incidents wait", sum(counts.values()))
                self._restore(counts, codes, complete)
                return False
            self.summaries_sent += 1
            return True

    @staticmethod
    def _text(counts: Mapping[str, int], codes: Sequence[str], complete: bool) -> str:
        """The summary, degraded step by step until it passes the outbound invariant."""
        for candidate in (
            format_summary(counts, codes, codes_complete=complete),
            format_summary(counts),
            format_summary({OTHER_SERVICES: sum(counts.values())}),
        ):
            try:
                return validate_outbound(candidate)
            except PagerInvariantError:
                continue
        return validate_outbound(f"ALERTS: {sum(counts.values())} more see dashboard")

    def _restore(self, counts: dict[str, int], codes: list[str], complete: bool) -> None:
        for name, n in counts.items():
            self._counts[name] = self._counts.get(name, 0) + n
        room = MAX_PENDING_CODES - len(self._codes)
        self._codes.extend(codes[: max(room, 0)])
        self._codes_complete = self._codes_complete and complete and len(codes) <= max(room, 0)
