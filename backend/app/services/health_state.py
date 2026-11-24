"""Process-local delivery health (Req 8.4). Task 23 exposes it through ``/readyz``."""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime


def _utc_now() -> datetime:
    return datetime.now(UTC)


class HealthState:
    """Counts consecutive page failures; a successful page resets the count.

    Single event loop, no awaits inside the methods, so updates are atomic.
    """

    def __init__(self, clock: Callable[[], datetime] = _utc_now) -> None:
        self._clock = clock
        self.consecutive_page_failures: int = 0
        self.last_failure_at: datetime | None = None

    def record_page_failure(self) -> None:
        self.consecutive_page_failures += 1
        self.last_failure_at = self._clock()

    def record_page_success(self) -> None:
        self.consecutive_page_failures = 0
