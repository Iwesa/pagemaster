"""Atomic incident deduplication (Req 1.2).

The fingerprint of an alert is ``sha256(service_name NUL error_code)``. The
lock key is ``incident:lock:{fingerprint}`` and is written with a single
atomic ``SET key incident_id NX EX 300``. The first alert acquires the lock;
later alerts inside the TTL window see the existing ``incident_id``.

``DedupStore`` is the port. ``RedisDedupStore`` is the production adapter and
``InMemoryDedupStore`` is a faithful fake for tests and demos without Redis.
"""

from __future__ import annotations

import hashlib
import time
from collections.abc import Callable
from typing import TYPE_CHECKING, Final, Literal, Protocol, runtime_checkable
from uuid import UUID

from pydantic import BaseModel, ConfigDict

if TYPE_CHECKING:
    from redis.asyncio import Redis

DEDUP_TTL_SECONDS: Final[int] = 300
LOCK_KEY_PREFIX: Final[str] = "incident:lock:"

# Terminal states that free the fingerprint before the TTL expires.
TERMINAL_STATUSES: Final[frozenset[str]] = frozenset(
    {"RESOLVED", "BLOCKED_BY_TRIPWIRE", "FAILED", "EXPIRED", "NO_ACTION"}
)

_MAX_ACQUIRE_ATTEMPTS: Final[int] = 3

# Delete the key only if it still belongs to the caller's incident.
_RELEASE_LUA: Final[str] = (
    "if redis.call('GET', KEYS[1]) == ARGV[1] then "
    "return redis.call('DEL', KEYS[1]) else return 0 end"
)


class DedupError(RuntimeError):
    """The dedup backend returned an inconsistent result."""


class Acquired(BaseModel):
    """This alert owns the fingerprint; start a new agent run."""

    model_config = ConfigDict(frozen=True, strict=True)

    kind: Literal["acquired"] = "acquired"
    fingerprint: str
    incident_id: UUID


class Duplicate(BaseModel):
    """An active incident already holds the fingerprint; suppress this alert."""

    model_config = ConfigDict(frozen=True, strict=True)

    kind: Literal["duplicate"] = "duplicate"
    fingerprint: str
    incident_id: UUID


DedupResult = Acquired | Duplicate


def compute_fingerprint(service_name: str, error_code: str) -> str:
    """Stable SHA-256 hex fingerprint of ``(service_name, error_code)``."""
    digest = hashlib.sha256()
    digest.update(service_name.encode("utf-8"))
    digest.update(b"\x00")  # separator so ("a", "bc") != ("ab", "c")
    digest.update(error_code.encode("utf-8"))
    return digest.hexdigest()


def lock_key(fingerprint: str) -> str:
    """Redis key for a fingerprint."""
    return f"{LOCK_KEY_PREFIX}{fingerprint}"


@runtime_checkable
class DedupStore(Protocol):
    """Port for atomic fingerprint locking."""

    async def acquire(self, service_name: str, error_code: str, incident_id: UUID) -> DedupResult:
        """Atomically claim the fingerprint for ``incident_id`` or report the holder."""
        ...

    async def release(self, service_name: str, error_code: str, incident_id: UUID) -> bool:
        """Free the fingerprint if ``incident_id`` still holds it. True if freed."""
        ...


class RedisDedupStore:
    """``redis.asyncio`` adapter using ``SET key value NX EX ttl``."""

    def __init__(self, client: Redis, ttl_seconds: int = DEDUP_TTL_SECONDS) -> None:
        if ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be positive")
        self._client = client
        self._ttl = ttl_seconds

    async def acquire(self, service_name: str, error_code: str, incident_id: UUID) -> DedupResult:
        fingerprint = compute_fingerprint(service_name, error_code)
        key = lock_key(fingerprint)
        for _ in range(_MAX_ACQUIRE_ATTEMPTS):
            if await self._client.set(key, str(incident_id), nx=True, ex=self._ttl):
                return Acquired(fingerprint=fingerprint, incident_id=incident_id)
            existing = await self._client.get(key)
            if existing is not None:
                text = existing.decode("ascii") if isinstance(existing, bytes) else str(existing)
                try:
                    holder = UUID(text)
                except ValueError as exc:
                    raise DedupError(f"lock {key} holds a non-UUID value") from exc
                return Duplicate(fingerprint=fingerprint, incident_id=holder)
            # Key expired or was released between SET and GET: try again.
        raise DedupError(f"could not acquire or read lock {key}")

    async def release(self, service_name: str, error_code: str, incident_id: UUID) -> bool:
        key = lock_key(compute_fingerprint(service_name, error_code))
        deleted = await self._client.eval(_RELEASE_LUA, 1, key, str(incident_id))
        return bool(deleted)


class InMemoryDedupStore:
    """Redis-free fake with the same NX/EX semantics. Single-process only."""

    def __init__(
        self,
        ttl_seconds: int = DEDUP_TTL_SECONDS,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be positive")
        self._ttl = ttl_seconds
        self._clock = clock
        self._locks: dict[str, tuple[UUID, float]] = {}

    def _live_holder(self, key: str) -> UUID | None:
        entry = self._locks.get(key)
        if entry is None:
            return None
        holder, expires_at = entry
        if self._clock() >= expires_at:
            del self._locks[key]
            return None
        return holder

    async def acquire(self, service_name: str, error_code: str, incident_id: UUID) -> DedupResult:
        fingerprint = compute_fingerprint(service_name, error_code)
        key = lock_key(fingerprint)
        holder = self._live_holder(key)
        if holder is not None:
            return Duplicate(fingerprint=fingerprint, incident_id=holder)
        self._locks[key] = (incident_id, self._clock() + self._ttl)
        return Acquired(fingerprint=fingerprint, incident_id=incident_id)

    async def release(self, service_name: str, error_code: str, incident_id: UUID) -> bool:
        key = lock_key(compute_fingerprint(service_name, error_code))
        if self._live_holder(key) != incident_id:
            return False
        del self._locks[key]
        return True


async def release_on_terminal(
    store: DedupStore,
    status: str,
    service_name: str,
    error_code: str,
    incident_id: UUID,
) -> bool:
    """Release the fingerprint when ``status`` is ``RESOLVED``, ``BLOCKED_BY_TRIPWIRE``, ``FAILED``, ``EXPIRED`` or ``NO_ACTION``.

    Any other status leaves the lock in place and returns False.
    """
    if status not in TERMINAL_STATUSES:
        return False
    return await store.release(service_name, error_code, incident_id)
