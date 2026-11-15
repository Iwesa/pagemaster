"""Short-TTL leader lock so only one worker runs startup reconciliation (Req 6.4).

``SET pagemaster:reconcile_lock <worker_id> NX EX 30`` acquires; release is a
compare-and-delete so a worker never frees a lock another worker now holds.
The lock is optional: in-memory (single process) mode runs without one.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from typing import TYPE_CHECKING, Final, Protocol, runtime_checkable
from uuid import uuid4

if TYPE_CHECKING:
    from redis.asyncio import Redis

RECONCILE_LOCK_KEY: Final[str] = "pagemaster:reconcile_lock"
RECONCILE_LOCK_TTL_SECONDS: Final[int] = 30

#: Identity of this process, generated once.
WORKER_ID: Final[str] = uuid4().hex

_RELEASE_LUA: Final[str] = (
    "if redis.call('GET', KEYS[1]) == ARGV[1] then "
    "return redis.call('DEL', KEYS[1]) else return 0 end"
)


@runtime_checkable
class ReconcileLock(Protocol):
    """Port for the startup-reconcile leader lock."""

    async def acquire(self, worker_id: str) -> bool:
        """Atomically take the lock for ``worker_id``. False if another worker holds it."""
        ...

    async def release(self, worker_id: str) -> bool:
        """Free the lock if ``worker_id`` still holds it. True if freed."""
        ...


class RedisReconcileLock:
    """``redis.asyncio`` adapter."""

    def __init__(self, client: Redis, ttl_seconds: int = RECONCILE_LOCK_TTL_SECONDS) -> None:
        if ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be positive")
        self._client = client
        self._ttl = ttl_seconds

    async def acquire(self, worker_id: str) -> bool:
        return bool(await self._client.set(RECONCILE_LOCK_KEY, worker_id, nx=True, ex=self._ttl))

    async def release(self, worker_id: str) -> bool:
        return bool(await self._client.eval(_RELEASE_LUA, 1, RECONCILE_LOCK_KEY, worker_id))


class InMemoryReconcileLock:
    """Redis-free fake with the same NX/EX and compare-and-delete semantics."""

    def __init__(
        self,
        ttl_seconds: int = RECONCILE_LOCK_TTL_SECONDS,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be positive")
        self._ttl = ttl_seconds
        self._clock = clock
        self._holder: tuple[str, float] | None = None

    def _live_holder(self) -> str | None:
        if self._holder is None:
            return None
        holder, expires_at = self._holder
        if self._clock() >= expires_at:
            self._holder = None
            return None
        return holder

    async def acquire(self, worker_id: str) -> bool:
        if self._live_holder() is not None:
            return False
        self._holder = (worker_id, self._clock() + self._ttl)
        return True

    async def release(self, worker_id: str) -> bool:
        if self._live_holder() != worker_id:
            return False
        self._holder = None
        return True
