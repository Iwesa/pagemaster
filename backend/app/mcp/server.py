"""Read-only FastMCP telemetry server for Pagemaster.

Exposes ``get_incident_context(service_name)``. Every query runs inside a
transaction that issues ``SET TRANSACTION READ ONLY`` and only touches the
allowlisted views ``v_recent_logs``, ``v_service_topology`` and
``v_approved_runbooks``. SQL is fixed and parameterized; ``service_name`` is
validated before use. If the database is unreachable or slow (> 5 s) the tool
returns a ``DEGRADED`` result instead of raising.

Run with ``python -m backend.app.mcp.server`` (env ``MCP_READER_DATABASE_URL``,
falling back to ``DATABASE_URL``).

Requirements: 2.1, 2.2, 2.3.
"""

from __future__ import annotations

import asyncio
import logging
import os
import re
import sys
from collections.abc import AsyncIterator, Mapping
from contextlib import asynccontextmanager
from datetime import datetime
from enum import StrEnum
from typing import Final

import asyncpg  # type: ignore[import-untyped]
from mcp.server.fastmcp import FastMCP
from pydantic import BaseModel, ConfigDict, Field

# stdio transport owns stdout; all logging goes to stderr.
logging.basicConfig(stream=sys.stderr, level=logging.INFO)
logger = logging.getLogger("pagemaster.mcp")

QUERY_TIMEOUT_SECONDS: Final[float] = 5.0
MAX_LOG_ROWS: Final[int] = 20
MAX_ROWS: Final[int] = 50

_SERVICE_NAME_RE: Final[re.Pattern[str]] = re.compile(r"[a-z0-9][a-z0-9-]{0,62}")

# Fixed, allowlisted SQL. Each statement touches exactly one allowlisted view.
_SQL_RECENT_LOGS: Final[str] = (
    "SELECT service_name, level, error_code, message, stack_trace, logged_at "
    "FROM v_recent_logs WHERE service_name = $1 "
    "ORDER BY logged_at DESC LIMIT 20"
)
_SQL_TOPOLOGY: Final[str] = (
    "SELECT service_name, depends_on, tier FROM v_service_topology "
    "WHERE service_name = $1 OR depends_on = $1 LIMIT 50"
)
_SQL_RUNBOOKS: Final[str] = (
    "SELECT action_id, service_name, title, description "
    "FROM v_approved_runbooks WHERE service_name = $1 "
    "ORDER BY action_id LIMIT 50"
)


class Confidence(StrEnum):
    """Confidence of the returned context."""

    HIGH = "HIGH"
    DEGRADED = "DEGRADED"


class LogEntry(BaseModel):
    model_config = ConfigDict(frozen=True)

    service_name: str
    level: str
    error_code: str | None = None
    message: str
    stack_trace: str | None = None
    logged_at: datetime


class TopologyEdge(BaseModel):
    model_config = ConfigDict(frozen=True)

    service_name: str
    depends_on: str | None = None
    tier: str


class RunbookOption(BaseModel):
    model_config = ConfigDict(frozen=True)

    action_id: str
    service_name: str
    title: str
    description: str


class IncidentContext(BaseModel):
    """Result of ``get_incident_context``."""

    model_config = ConfigDict(frozen=True)

    service_name: str
    confidence: Confidence
    recent_logs: list[LogEntry] = Field(default_factory=list)
    topology: list[TopologyEdge] = Field(default_factory=list)
    runbooks: list[RunbookOption] = Field(default_factory=list)
    degraded_reason: str | None = None


def validate_service_name(service_name: str) -> bool:
    """Return True if ``service_name`` is a safe, lowercase slug."""
    return _SERVICE_NAME_RE.fullmatch(service_name) is not None


def _degraded(service_name: str, reason: str) -> IncidentContext:
    return IncidentContext(
        service_name=service_name,
        confidence=Confidence.DEGRADED,
        degraded_reason=reason,
    )


class TelemetryStore:
    """Lazily-created read-only asyncpg pool plus the fixed context query."""

    def __init__(self, dsn: str | None) -> None:
        self._dsn = dsn
        self._pool: asyncpg.Pool | None = None
        self._lock = asyncio.Lock()

    async def _get_pool(self) -> asyncpg.Pool:
        if self._pool is not None:
            return self._pool
        async with self._lock:
            if self._pool is None:
                self._pool = await asyncpg.create_pool(
                    dsn=self._dsn,
                    min_size=1,
                    max_size=4,
                    timeout=QUERY_TIMEOUT_SECONDS,
                    command_timeout=QUERY_TIMEOUT_SECONDS,
                    server_settings={"default_transaction_read_only": "on"},
                )
            assert self._pool is not None
            return self._pool

    async def close(self) -> None:
        pool, self._pool = self._pool, None
        if pool is not None:
            await pool.close()

    async def _fetch(self, service_name: str) -> IncidentContext:
        pool = await self._get_pool()
        async with pool.acquire() as conn:
            async with conn.transaction():
                await conn.execute("SET TRANSACTION READ ONLY")
                logs = await conn.fetch(_SQL_RECENT_LOGS, service_name)
                edges = await conn.fetch(_SQL_TOPOLOGY, service_name)
                books = await conn.fetch(_SQL_RUNBOOKS, service_name)
        return IncidentContext(
            service_name=service_name,
            confidence=Confidence.HIGH,
            recent_logs=[LogEntry(**dict(r)) for r in logs],
            topology=[TopologyEdge(**dict(r)) for r in edges],
            runbooks=[RunbookOption(**dict(r)) for r in books],
        )

    async def get_incident_context(self, service_name: str) -> IncidentContext:
        if not validate_service_name(service_name):
            return _degraded(service_name[:64], "invalid service_name")
        if not self._dsn:
            return _degraded(service_name, "DATABASE_URL not configured")
        try:
            async with asyncio.timeout(QUERY_TIMEOUT_SECONDS):
                return await self._fetch(service_name)
        except TimeoutError:
            logger.warning("telemetry query timed out for %s", service_name)
            return _degraded(service_name, "database timeout")
        except (OSError, asyncpg.PostgresError, asyncpg.InterfaceError, ValueError) as exc:
            logger.warning("telemetry query failed for %s: %s", service_name, type(exc).__name__)
            return _degraded(service_name, "database unavailable")


def resolve_dsn(env: Mapping[str, str] | None = None) -> str | None:
    """Prefer the restricted ``MCP_READER_DATABASE_URL`` role over ``DATABASE_URL``."""
    source = os.environ if env is None else env
    return source.get("MCP_READER_DATABASE_URL") or source.get("DATABASE_URL") or None


_store = TelemetryStore(resolve_dsn())


@asynccontextmanager
async def _lifespan(_server: FastMCP) -> AsyncIterator[None]:
    try:
        yield
    finally:
        await _store.close()


mcp = FastMCP("pagemaster-telemetry", lifespan=_lifespan)


@mcp.tool()
async def get_incident_context(service_name: str) -> IncidentContext:
    """Return recent WARN+ logs, dependency topology and approved runbooks for a service.

    Read-only. On database failure returns confidence=DEGRADED with empty data.
    """
    return await _store.get_incident_context(service_name)


if __name__ == "__main__":
    mcp.run()
