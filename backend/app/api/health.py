"""Unauthenticated liveness and readiness probes (registered regardless of DRY_RUN).

The frontend is a ``StaticFiles`` mount created in ``main.py``, not a route here.

Requirements: 7.1, 7.5.
"""

from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, Request, Response
from pydantic import BaseModel

from backend.app.api.app_services import AppServices
from backend.app.services.readiness import (
    CheckResult,
    PagerCheck,
    ReadinessChecks,
    ReadinessReport,
    run_readiness,
)

__all__ = ["HealthStatus", "healthz", "readyz", "router"]

router = APIRouter()


class HealthStatus(BaseModel):
    status: Literal["ok", "unavailable"]


@router.get("/healthz", response_model=HealthStatus)
async def healthz() -> HealthStatus:
    """Liveness only (Req 7.1): 200 while the process serves requests. Checks no dependency."""
    return HealthStatus(status="ok")


@router.get("/readyz", response_model=ReadinessReport, response_model_exclude_none=True)
async def readyz(request: Request, response: Response) -> ReadinessReport:
    """Readiness (Req 7.5): per-check JSON, 503 when any check fails. Never carries error text."""
    services: AppServices | None = getattr(request.app.state, "services", None)
    dry_run = bool(getattr(request.app.state, "dry_run", False))
    if services is None:  # lifespan has not finished wiring adapters yet
        response.status_code = 503
        down = CheckResult(ok=False)
        return ReadinessReport(
            status="unavailable",
            dry_run=dry_run,
            checks=ReadinessChecks(
                postgres=down, redis=down, reaper=down, pager=PagerCheck(ok=False, consecutive_failures=0)
            ),
        )
    report = await run_readiness(
        ping_postgres=services.ping_postgres,
        ping_redis=services.ping_redis,
        heartbeat=services.reaper,
        health=services.health,
        page_failure_threshold=services.page_failure_ready_threshold,
        dry_run=dry_run,
    )
    if report.checks.postgres.ok and report.checks.redis.ok:
        services.outages.recovered()
    if report.status != "ok":
        response.status_code = 503
    return report
