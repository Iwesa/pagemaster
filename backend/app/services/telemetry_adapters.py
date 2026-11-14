"""Adapters for ``TelemetryPort`` and ``RunbookPort``.

* ``StaticTelemetry``: seeded context for dry-run/in-memory mode (no database).
* ``DatabaseTelemetry``: wraps the read-only MCP ``TelemetryStore`` (fixed SQL over
  the allowlisted views inside ``SET TRANSACTION READ ONLY``).
* ``SimulatedRunbooks``: lists approved runbooks and *simulates* execution. No
  shell or SQL is ever executed (Req 5.3).

Requirements: 2.1, 2.3, 5.3.
"""

from __future__ import annotations

import logging
from collections.abc import Mapping, Sequence
from typing import Final, Protocol

from backend.app.agents.ports import Runbook, TelemetryContext
from backend.app.mcp.server import Confidence, IncidentContext

logger = logging.getLogger("pagemaster.telemetry")

#: Mirrors the seed rows of ``approved_runbooks`` in ``database/init_mock_logs.sql``.
SEED_RUNBOOKS: Final[Mapping[str, tuple[tuple[str, str], ...]]] = {
    "auth-db": (
        ("RB-AUTHDB-RESET-POOL", "Reset connection pool"),
        ("RB-AUTHDB-FAILOVER", "Failover to replica"),
    ),
    "payment-gateway": (
        ("RB-PAYGW-DRAIN-UPSTREAM", "Drain failing upstream"),
        ("RB-PAYGW-RESTART", "Rolling restart"),
    ),
    "ledger-worker": (
        ("RB-LEDGER-REPLAY-DLQ", "Replay dead-letter queue"),
        ("RB-LEDGER-RESTART", "Restart ledger workers"),
    ),
}


def _seed(service_name: str) -> tuple[Runbook, ...]:
    return tuple(
        Runbook(action_id=action_id, title=title, target_host=service_name)
        for action_id, title in SEED_RUNBOOKS.get(service_name, ())
    )


class StaticTelemetry:
    """``TelemetryPort`` returning seeded runbooks; unknown services are ``DEGRADED``."""

    async def get_incident_context(self, service_name: str) -> TelemetryContext:
        runbooks = _seed(service_name)
        return TelemetryContext(
            confidence="HIGH" if runbooks else "DEGRADED",
            root_cause=f"{service_name} reporting elevated errors (dry-run telemetry)",
            runbooks=runbooks,
        )


class _ContextSource(Protocol):
    async def get_incident_context(self, service_name: str) -> IncidentContext: ...


def to_telemetry_context(ctx: IncidentContext) -> TelemetryContext:
    """Map an MCP ``IncidentContext`` onto the domain ``TelemetryContext``."""
    top = ctx.recent_logs[0] if ctx.recent_logs else None
    cause = ctx.degraded_reason or ""
    if top is not None:
        cause = f"{top.error_code or top.level}: {top.message}"
    return TelemetryContext(
        confidence="HIGH" if ctx.confidence is Confidence.HIGH else "DEGRADED",
        root_cause=cause,
        runbooks=tuple(
            Runbook(action_id=r.action_id, title=r.title, target_host=r.service_name)
            for r in ctx.runbooks
        ),
    )


class DatabaseTelemetry:
    """``TelemetryPort`` and ``RunbookPort.list_approved`` over the read-only telemetry store."""

    def __init__(self, source: _ContextSource) -> None:
        self._source = source

    async def get_incident_context(self, service_name: str) -> TelemetryContext:
        return to_telemetry_context(await self._source.get_incident_context(service_name))

    async def list_approved(self, service_name: str) -> Sequence[Runbook]:
        return (await self.get_incident_context(service_name)).runbooks


class _RunbookLister(Protocol):
    async def list_approved(self, service_name: str) -> Sequence[Runbook]: ...


class SimulatedRunbooks:
    """``RunbookPort`` with simulated execution. ``lister`` supplies approved runbooks."""

    def __init__(self, lister: _RunbookLister | None = None) -> None:
        self._lister = lister

    async def list_approved(self, service_name: str) -> Sequence[Runbook]:
        if self._lister is not None:
            return await self._lister.list_approved(service_name)
        return _seed(service_name)

    async def execute(self, *, target_host: str, action_id: str, token: str) -> bool:
        logger.info("simulated remediation %s on %s for INC-%s", action_id, target_host, token)
        return True
