"""FastAPI application factory, lifespan and module-level ``app``.

* ``create_app(services=...)`` builds an app around injected adapters (tests).
* ``create_app()`` wires adapters in the lifespan from the environment.

Configuration (env table, ``Settings``, ``ConfigError``) lives in ``backend.app.config``; adapter
wiring (``build_in_memory_services``, ``build_real_services``) in ``backend.app.container``. Both are
re-exported here so ``from backend.app.main import Settings, create_app, ...`` keeps working.

Requirements: 1.1, 4.1, 4.2, 11.1 to 11.5.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import AsyncExitStack, asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

from backend.app.api.routes import AppServices, demo_router, router
from backend.app.config import (
    DEFAULT_INFLIGHT_STALE_SECONDS,
    DEFAULT_INFLIGHT_TIMEOUT_SECONDS,
    DEFAULT_PAGE_MAX_ATTEMPTS,
    MIN_INFLIGHT_STALE_SECONDS,
    MIN_INFLIGHT_TIMEOUT_SECONDS,
    ConfigError,
    Settings,
    _parse_inflight_stale_seconds,
    _parse_min_seconds,
    _parse_timeout_seconds,
)
from backend.app.container import ServiceContainer, build_in_memory_services, build_real_services
from backend.app.services.readiness import (
    DEPENDENCY_EXCEPTIONS,
    DEPENDENCY_UNAVAILABLE_DETAIL,
    RETRY_AFTER_SECONDS,
    OutageLog,
    dependency_kind,
)

__all__ = [
    "DEFAULT_INFLIGHT_STALE_SECONDS",
    "DEFAULT_INFLIGHT_TIMEOUT_SECONDS",
    "DEFAULT_PAGE_MAX_ATTEMPTS",
    "MIN_INFLIGHT_STALE_SECONDS",
    "MIN_INFLIGHT_TIMEOUT_SECONDS",
    "AppServices",
    "ConfigError",
    "ServiceContainer",
    "Settings",
    "_parse_inflight_stale_seconds",
    "_parse_min_seconds",
    "_parse_timeout_seconds",
    "app",
    "build_in_memory_services",
    "build_real_services",
    "create_app",
]

logger = logging.getLogger("pagemaster.main")


def _default_frontend_dir() -> Path:
    return Path(__file__).resolve().parents[2] / "frontend"


def _install_dependency_handlers(app: FastAPI) -> None:
    """Map dependency connectivity errors to 503 + ``Retry-After`` and log once per outage (Req 7.4)."""
    fallback = OutageLog()  # used before the lifespan has wired services

    def outages() -> OutageLog:
        services: ServiceContainer | None = getattr(app.state, "services", None)
        return services.outages if services is not None else fallback

    async def dependency_unavailable(request: Request, exc: Exception) -> JSONResponse:
        outages().failed(dependency_kind(exc) or "network")  # never logs exception text
        return JSONResponse(
            status_code=503,
            content={"detail": DEPENDENCY_UNAVAILABLE_DETAIL},
            headers={"Retry-After": str(RETRY_AFTER_SECONDS)},
        )

    for exc_type in DEPENDENCY_EXCEPTIONS:
        app.add_exception_handler(exc_type, dependency_unavailable)

    @app.middleware("http")
    async def end_outage_on_success(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        response = await call_next(request)
        if response.status_code in (200, 202) and request.url.path.startswith("/webhooks/"):
            outages().recovered()  # a webhook that touched the dependencies worked again
        return response


def create_app(
    services: ServiceContainer | None = None,
    settings: Settings | None = None,
) -> FastAPI:
    """Create the app. Pass ``services`` to inject adapters (skips env wiring)."""
    cfg = settings if settings is not None else Settings.from_env()
    cfg.validate_for_runtime()  # fail before anything is wired (Req 11.1, 11.4)
    if not cfg.dry_run and not cfg.alert_webhook_secret:
        logger.warning("ALERT_WEBHOOK_SECRET is not set: POST /webhooks/alerts is unauthenticated")
    if cfg.public_base_url and "?" in cfg.public_base_url:
        logger.warning(
            "PUBLIC_BASE_URL contains a query string; secrets in URLs leak into proxy logs. "
            "Send the webhook secret in the X-Webhook-Secret header instead"
        )
    if cfg.allow_query_secret:
        logger.warning(
            "ALLOW_QUERY_SECRET is enabled: the webhook secret may be sent as ?secret=, "
            "which leaks into proxy and access logs. Prefer the X-Webhook-Secret header"
        )

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        cfg.validate_for_runtime()
        logger.info(cfg.startup_line())
        async with AsyncExitStack() as stack:
            if services is not None:
                app.state.services = services
            elif cfg.use_in_memory:
                app.state.services = build_in_memory_services(cfg)
            else:
                app.state.services = await build_real_services(cfg, stack)
            lifecycle = app.state.services.lifecycle
            # Req 6.4: stale TRIAGING/EXECUTING incidents fail before we serve traffic.
            # One worker reconciles at a time (optional Redis leader lock); the lock is
            # released inside startup_reconcile once the run finishes.
            try:
                count = await lifecycle.startup_reconcile(app.state.services.reconcile_lock)
                if count:
                    logger.warning("reconciled %d stale in-flight incidents to FAILED", count)
            except Exception:
                logger.exception("startup reconciliation failed")
            app.state.services.reaper.configure(cfg.reaper_interval_seconds)
            reaper = asyncio.create_task(lifecycle.run_reaper(cfg.reaper_interval_seconds), name="approval-reaper")
            try:
                yield
            finally:
                reaper.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await reaper

    app = FastAPI(title="Pagemaster", lifespan=lifespan)
    app.state.dry_run = cfg.dry_run
    _install_dependency_handlers(app)
    if services is not None:
        app.state.services = services  # also usable without running the lifespan
    app.include_router(router)
    if cfg.dry_run:  # demo routes simulate SMS replies: never registered in live mode
        app.include_router(demo_router)

    frontend = cfg.frontend_dir if cfg.frontend_dir is not None else _default_frontend_dir()
    if frontend.is_dir():  # mounted last so API routes take precedence
        app.mount("/", StaticFiles(directory=frontend, html=True), name="frontend")
    return app


app = create_app()
