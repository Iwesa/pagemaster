"""Rate limit for the "unparseable reply" hint (Req 4.10): one hint per sender per window."""

from __future__ import annotations

import time
from collections.abc import Callable
from typing import Final, Protocol

HINT_WINDOW_SECONDS: Final[float] = 60.0
_PRUNE_ABOVE: Final[int] = 1024


class HintLimiter(Protocol):
    """Port. A Redis-backed implementation can replace the in-memory one."""

    async def allow(self, key: str) -> bool:
        """True (and the slot is consumed) when ``key`` may receive a hint now."""
        ...


class HintRateLimiter:
    """In-memory limiter: at most one hint per key per ``window_seconds``."""

    def __init__(
        self,
        window_seconds: float = HINT_WINDOW_SECONDS,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._window = window_seconds
        self._clock = clock
        self._last: dict[str, float] = {}

    async def allow(self, key: str) -> bool:
        # No await between read and write: atomic on the event loop.
        now = self._clock()
        last = self._last.get(key)
        if last is not None and now - last < self._window:
            return False
        if len(self._last) >= _PRUNE_ABOVE:
            self._last = {k: t for k, t in self._last.items() if now - t < self._window}
        self._last[key] = now
        return True
