"""Dependency-outage classification, once-per-outage logging and readiness checks (task 23).

Requirements: 7.1, 7.4, 7.5.

* :func:`dependency_kind` recognises asyncpg / Redis / network failures so the API layer can
  answer ``503`` instead of ``500``. It never exposes exception text.
* :class:`OutageLog` logs a dependency outage once, until a request succeeds again.
* :class:`ReaperHeartbeat` is touched by ``Lifecycle.run_reaper`` every iteration.
* :func:`run_readiness` runs the per-dependency probes concurrently, each with its own timeout.
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Awaitable, Callable
from typing import Final, Literal

import asyncpg  # type: ignore[import-untyped]
import redis.exceptions as redis_exceptions
from pydantic import BaseModel, ConfigDict, Field

from backend.app.config import DEFAULT_PAGE_FAILURE_READY_THRESHOLD as DEFAULT_PAGE_FAILURE_READY_THRESHOLD  # re-export
from backend.app.services.health_state import HealthState

logger = logging.getLogger("pagemaster.readiness")

DEPENDENCY_UNAVAILABLE_DETAIL: Final[str] = "dependency unavailable"
RETRY_AFTER_SECONDS: Final[int] = 5
READY_CHECK_TIMEOUT_SECONDS: Final[float] = 2.0
#: The reaper is considered dead after this many missed intervals.
REAPER_DEAD_AFTER_INTERVALS: Final[float] = 3.0

#: Exception classes that mean "a dependency is unreachable". ``OSError`` covers
#: ``ConnectionError`` and ``TimeoutError`` (``asyncio.TimeoutError`` is ``TimeoutError``).
DEPENDENCY_EXCEPTIONS: Final[tuple[type[Exception], ...]] = (
    asyncpg.PostgresConnectionError,
    asyncpg.InterfaceError,
    redis_exceptions.ConnectionError,
    redis_exceptions.TimeoutError,
    OSError,
    asyncio.TimeoutError,
)

DependencyKind = Literal["postgres", "redis", "network"]


def dependency_kind(exc: BaseException) -> DependencyKind | None:
    """Which dependency ``exc`` points at, or ``None`` when it is not a connectivity failure."""
    if isinstance(exc, asyncpg.PostgresConnectionError | asyncpg.InterfaceError):
        return "postgres"
    if isinstance(exc, redis_exceptions.ConnectionError | redis_exceptions.TimeoutError):
        return "redis"
    if isinstance(exc, OSError | asyncio.TimeoutError):
        return "network"
    return None


class OutageLog:
    """Log each kind of dependency outage once, until :meth:`recovered` is called."""

    def __init__(self) -> None:
        self._open: set[str] = set()

    def failed(self, kind: str) -> bool:
        """Record a failure. True (and logs) only for the first failure of this outage."""
        if kind in self._open:
            return False
        self._open.add(kind)
        logger.warning("dependency outage started: %s unavailable; answering 503", kind)
        return True

    def recovered(self) -> None:
        if self._open:
            logger.warning("dependency outage ended: %s", ", ".join(sorted(self._open)))
            self._open.clear()

    @property
    def active(self) -> bool:
        return bool(self._open)


class ReaperHeartbeat:
    """Liveness of the background reaper. Not configured (tests) means "not applicable"."""

    def __init__(self, clock: Callable[[], float] = time.monotonic) -> None:
        self._clock = clock
        self.interval_seconds: float | None = None
        self.last_tick_at: float | None = None

    def configure(self, interval_seconds: float) -> None:
        """A reaper is about to run; the grace period starts now."""
        self.interval_seconds = interval_seconds
        self.last_tick_at = self._clock()

    def beat(self) -> None:
        self.last_tick_at = self._clock()

    def alive(self) -> bool:
        if self.interval_seconds is None:
            return True  # no reaper configured
        if self.last_tick_at is None:
            return False
        return self._clock() - self.last_tick_at <= REAPER_DEAD_AFTER_INTERVALS * self.interval_seconds


# ---------------------------------------------------------------------------
# /readyz body
# ---------------------------------------------------------------------------


class CheckResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    ok: bool
    mode: Literal["in_memory"] | None = None


class PagerCheck(BaseModel):
    model_config = ConfigDict(extra="forbid")

    ok: bool
    consecutive_failures: int = Field(ge=0)


class ReadinessChecks(BaseModel):
    model_config = ConfigDict(extra="forbid")

    postgres: CheckResult
    redis: CheckResult
    reaper: CheckResult
    pager: PagerCheck


class ReadinessReport(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: Literal["ok", "unavailable"]
    dry_run: bool
    channel: Literal["africastalking"] = "africastalking"
    checks: ReadinessChecks


Probe = Callable[[], Awaitable[None]]


async def _probe(probe: Probe | None, timeout: float) -> CheckResult:
    """Run one dependency probe. ``None`` = in-memory mode. Never raises, never keeps error text."""
    if probe is None:
        return CheckResult(ok=True, mode="in_memory")
    try:
        await asyncio.wait_for(probe(), timeout=timeout)
    except Exception:
        return CheckResult(ok=False)
    return CheckResult(ok=True)


async def run_readiness(
    *,
    ping_postgres: Probe | None,
    ping_redis: Probe | None,
    heartbeat: ReaperHeartbeat,
    health: HealthState,
    page_failure_threshold: int,
    dry_run: bool,
    timeout: float = READY_CHECK_TIMEOUT_SECONDS,
) -> ReadinessReport:
    """Run the Postgres and Redis probes concurrently (each bounded by ``timeout``)."""
    postgres, redis = await asyncio.gather(_probe(ping_postgres, timeout), _probe(ping_redis, timeout))
    failures = health.consecutive_page_failures
    checks = ReadinessChecks(
        postgres=postgres,
        redis=redis,
        reaper=CheckResult(ok=heartbeat.alive()),
        pager=PagerCheck(ok=failures < max(1, page_failure_threshold), consecutive_failures=failures),
    )
    ok = all((checks.postgres.ok, checks.redis.ok, checks.reaper.ok, checks.pager.ok))
    return ReadinessReport(status="ok" if ok else "unavailable", dry_run=dry_run, checks=checks)
