"""Tiny stdio MCP server used by ``test_overload.py`` (no database, starts fast).

Appends its pid to the file named by ``STUB_SPAWN_LOG`` at start-up so tests can count spawns.
The tool ``get_incident_context`` returns a valid ``IncidentContext`` JSON with one runbook.
"""

from __future__ import annotations

import os
from typing import Any

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("stub-telemetry")

_LOG = os.environ.get("STUB_SPAWN_LOG")
if _LOG:
    with open(_LOG, "a", encoding="ascii") as fh:
        fh.write(f"{os.getpid()}\n")


@mcp.tool()
def get_incident_context(service_name: str) -> dict[str, Any]:
    return (
        {
            "service_name": service_name,
            "confidence": "HIGH",
            "recent_logs": [],
            "topology": [],
            "runbooks": [
                {
                    "action_id": "RB-STUB",
                    "service_name": service_name,
                    "title": "Stub action",
                    "description": "stub",
                }
            ],
        }
    )


if __name__ == "__main__":
    mcp.run()
