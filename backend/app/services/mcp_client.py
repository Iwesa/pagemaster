"""``TelemetryPort`` over the real MCP protocol (stdio subprocess).

``McpSubprocessTelemetry`` spawns ``python -m backend.app.mcp.server`` for each
call, invokes the ``get_incident_context`` tool and parses the JSON result. The
subprocess receives only ``MCP_READER_DATABASE_URL`` (the restricted
``mcp_reader`` role), never the superuser ``DATABASE_URL``. Any failure or a
5 s overall timeout yields a ``DEGRADED`` context (Req 2.3).

Requirements: 2.1, 2.2, 2.3.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any, Final

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from backend.app.agents.ports import Runbook, TelemetryContext
from backend.app.mcp.server import IncidentContext
from backend.app.services.telemetry_adapters import to_telemetry_context

logger = logging.getLogger("pagemaster.mcp_client")

MCP_CALL_TIMEOUT_SECONDS: Final[float] = 5.0
_TOOL_NAME: Final[str] = "get_incident_context"
_REPO_ROOT: Final[Path] = Path(__file__).resolve().parents[3]
_PASSTHROUGH_ENV: Final[tuple[str, ...]] = (
    "PATH",
    "SYSTEMROOT",
    "HOME",
    "USERPROFILE",
    "TEMP",
    "TMP",
    "PYTHONPATH",
    "LANG",
)


def _degraded(service_name: str, reason: str) -> TelemetryContext:
    logger.debug("degraded context for %s: %s", service_name, reason)
    # Empty root_cause lets triage keep the alert's own summary.
    return TelemetryContext(confidence="DEGRADED", root_cause="", runbooks=())


def parse_tool_result(result: Any) -> IncidentContext:
    """Parse a ``CallToolResult`` into an ``IncidentContext`` (raises ``ValueError``)."""
    if getattr(result, "isError", False):
        raise ValueError("tool returned an error")
    structured = getattr(result, "structuredContent", None)
    if isinstance(structured, dict):
        return IncidentContext.model_validate(structured)
    for block in getattr(result, "content", None) or ():
        text = getattr(block, "text", None)
        if isinstance(text, str):
            return IncidentContext.model_validate(json.loads(text))
    raise ValueError("tool result has no JSON content")


class McpSubprocessTelemetry:
    """``TelemetryPort`` + ``RunbookPort.list_approved`` over a stdio MCP subprocess."""

    def __init__(
        self,
        reader_dsn: str,
        *,
        timeout: float = MCP_CALL_TIMEOUT_SECONDS,
        cwd: Path | None = None,
    ) -> None:
        self._dsn = reader_dsn
        self._timeout = timeout
        self._cwd = cwd if cwd is not None else _REPO_ROOT

    def _params(self) -> StdioServerParameters:
        env = {k: os.environ[k] for k in _PASSTHROUGH_ENV if k in os.environ}
        env["MCP_READER_DATABASE_URL"] = self._dsn
        return StdioServerParameters(
            command=sys.executable,
            args=["-m", "backend.app.mcp.server"],
            env=env,
            cwd=self._cwd,
        )

    async def _call(self, service_name: str) -> IncidentContext:
        async with stdio_client(self._params()) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                result = await session.call_tool(_TOOL_NAME, {"service_name": service_name})
        return parse_tool_result(result)

    async def get_incident_context(self, service_name: str) -> TelemetryContext:
        try:
            async with asyncio.timeout(self._timeout):
                ctx = await self._call(service_name)
        except Exception as exc:  # incl. TimeoutError, spawn/protocol/parse errors (Req 2.3)
            logger.warning("mcp telemetry failed for %s: %s", service_name, type(exc).__name__)
            return _degraded(service_name, "unavailable")
        return to_telemetry_context(ctx)

    async def list_approved(self, service_name: str) -> Sequence[Runbook]:
        return (await self.get_incident_context(service_name)).runbooks
