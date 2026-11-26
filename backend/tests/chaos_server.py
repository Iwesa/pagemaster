"""Test launcher for the real-stack chaos tests: ``python -m backend.tests.chaos_server``.

Runs the production ``backend.app.main:app`` under uvicorn on ``$PORT`` (127.0.0.1). With
``CHAOS_HANG_TRIAGE=1`` the database telemetry never answers, which parks every new incident in
``TRIAGING`` for the 60 s triage bound, so a test can kill the process while work is in flight.
Nothing else is changed: settings come from the environment exactly as in the container.
"""

from __future__ import annotations

import asyncio
import os
import sys
from collections.abc import Sequence

import uvicorn

from backend.app.agents.ports import Runbook, TelemetryContext
from backend.app.services import telemetry_adapters


async def _hang_context(self: object, service_name: str) -> TelemetryContext:
    await asyncio.sleep(3600)
    raise AssertionError("unreachable")


async def _hang_runbooks(self: object, service_name: str) -> Sequence[Runbook]:
    await asyncio.sleep(3600)
    raise AssertionError("unreachable")


def main() -> None:
    if os.environ.get("CHAOS_HANG_TRIAGE") == "1":
        telemetry_adapters.DatabaseTelemetry.get_incident_context = _hang_context  # type: ignore[method-assign]
        telemetry_adapters.DatabaseTelemetry.list_approved = _hang_runbooks  # type: ignore[method-assign]
    uvicorn.run(
        "backend.app.main:app",
        host="127.0.0.1",
        port=int(os.environ["PORT"]),
        log_level="warning",
        # Windows: uvicorn's "asyncio"/"auto" loops are ProactorEventLoop (the event loop policy is
        # ignored), which psycopg's async driver (AsyncPostgresSaver) cannot use.
        loop="asyncio:SelectorEventLoop" if sys.platform == "win32" else "auto",
    )


if __name__ == "__main__":
    main()
