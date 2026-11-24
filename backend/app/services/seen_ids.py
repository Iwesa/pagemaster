"""Atomic seen-message-id store for inbound SMS idempotency (Req 4.5).

``claim`` records a message id and reports whether this call was the first
to see it. The Redis adapter uses a single atomic ``SET key 1 NX EX 86400``;
``InMemorySeenIdStore`` has the same semantics for tests and in-memory mode.
Mirrors ``DedupStore`` in ``dedup.py``.
"""

from __future__ import annotations

import hashlib
import time
from collections.abc import Callable
from typing import TYPE_CHECKING, Final, Protocol, runtime_checkable

if TYPE_CHECKING:
    from redis.asyncio import Redis

SEEN_ID_TTL_SECONDS: Final[int] = 86_400
SEEN_KEY_PREFIX: Final[str] = "sms:seen:"


def seen_key(message_id: str) -> str:
    """Redis key for a message id (hashed so arbitrary ids stay bounded)."""
    return SEEN_KEY_PREFIX + hashlib.sha256(message_id.encode("utf-8")).hexdigest()


@runtime_checkable
class SeenIdStore(Protocol):
    """Port for atomic message-id idempotency."""

    async def claim(self, message_id: str) -> bool:
        """Atomically record ``message_id``. True if first seen, False if a redelivery."""
        ...

    async def forget(self, message_id: str) -> None:
        """Undo a claim (best effort) so a provider redelivery is processed after an outage."""
        ...


class RedisSeenIdStore:
    """``redis.asyncio`` adapter using ``SET key 1 NX EX ttl``."""

    def __init__(self, client: Redis, ttl_seconds: int = SEEN_ID_TTL_SECONDS) -> None:
        if ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be positive")
        self._client = client
        self._ttl = ttl_seconds

    async def claim(self, message_id: str) -> bool:
        return bool(await self._client.set(seen_key(message_id), "1", nx=True, ex=self._ttl))

    async def forget(self, message_id: str) -> None:
        await self._client.delete(seen_key(message_id))


class InMemorySeenIdStore:
    """Redis-free fake with the same NX/EX semantics. Single-process only."""

    def __init__(
        self,
        ttl_seconds: int = SEEN_ID_TTL_SECONDS,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be positive")
        self._ttl = ttl_seconds
        self._clock = clock
        self._seen: dict[str, float] = {}

    async def claim(self, message_id: str) -> bool:
        now = self._clock()
        if self._seen and len(self._seen) % 256 == 0:  # amortised pruning
            self._seen = {k: exp for k, exp in self._seen.items() if exp > now}
        key = seen_key(message_id)
        expires_at = self._seen.get(key)
        if expires_at is not None and expires_at > now:
            return False
        self._seen[key] = now + self._ttl
        return True

    async def forget(self, message_id: str) -> None:
        self._seen.pop(seen_key(message_id), None)
