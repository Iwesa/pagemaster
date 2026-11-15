"""FastAPI application factory and production/dry-run wiring.

* ``create_app(services=...)`` builds an app around injected adapters (tests).
* ``create_app()`` wires adapters in the lifespan from the environment:

  ===================== ==========================================================
  ``USE_IN_MEMORY``     ``true``: in-memory repo/audit/dedup, ``MemorySaver``,
                        seeded telemetry. No Postgres or Redis needed.
  ``DATABASE_URL``      Postgres for incidents, audit trail and LangGraph checkpoints.
  ``MCP_READER_DATABASE_URL`` read-only role used for telemetry views.
  ``MCP_TRANSPORT``     ``stdio`` (default, spawns the MCP server) or ``inprocess``.
  ``GEMINI_API_KEY`` /  optional LLM summarizer keys (Gemini preferred); absent = deterministic.
  ``OPENAI_API_KEY``
  ``REDIS_URL``         Redis for the dedup lock.
  ``AFRICASTALKING_*``  username, API key, shortcode, webhook secret (``X-Webhook-Secret``
                        header or ``Authorization: Bearer``; unset rejects all inbound SMS), plus
                        ``ONCALL_PHONE_NUMBER`` (the only accepted reply sender).
  ``PUBLIC_BASE_URL``   no longer used for signatures; kept for compatibility. A warning
                        is logged at startup if it contains a ``?`` query string.
  ``ALLOW_QUERY_SECRET`` ``true``/``1``/``yes`` (case-insensitive) permits the legacy
                        ``?secret=`` webhook auth; default false (header-only). Warns when on.
  ``ALERT_WEBHOOK_SECRET`` optional; when set, ``POST /webhooks/alerts`` requires
                        ``Authorization: Bearer <secret>`` (401 otherwise).
  ``FRONTEND_DIR``      static UI directory (default ``<repo>/frontend``).
  ``APPROVAL_TTL_SECONDS`` seconds an incident may await approval before it expires (900).
  ``REAPER_INTERVAL_SECONDS`` how often the background reaper looks for expired approvals (30).
  ``INFLIGHT_STALE_SECONDS`` age before a TRIAGING/EXECUTING incident is reconciled to FAILED
                        at startup (60, minimum 10; bad values fall back to 60).
  ``DRY_RUN``           default true; registers ``/api/demo/*`` (simulated replies, outbox).
  ===================== ==========================================================

Requirements: 1.1, 4.1, 4.2.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os
from collections.abc import AsyncIterator, Mapping
from contextlib import AsyncExitStack, asynccontextmanager
from pathlib import Path
from typing import Final

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field

from backend.app.agents.graph import build_graph, compile_with_postgres
from backend.app.agents.ports import Ports
from backend.app.api.routes import AppServices, demo_router, router
from backend.app.services.africastalking_client import (
    AfricasTalkingSettings,
    AfricasTalkingSmsAdapter,
)
from backend.app.services.dedup import InMemoryDedupStore
from backend.app.services.seen_ids import InMemorySeenIdStore
from backend.app.services.llm_summarizer import DisabledSummarizer, LlmSummarizer
from backend.app.services.incident_store import InMemoryAuditStore, InMemoryIncidentRepository
from backend.app.services.mcp_client import McpSubprocessTelemetry
from backend.app.services.telemetry_adapters import (
    DatabaseTelemetry,
    SimulatedRunbooks,
    StaticTelemetry,
)

logger = logging.getLogger("pagemaster.main")
_TRUE_VALUES: Final[frozenset[str]] = frozenset({"1", "true", "yes", "on"})


_QUERY_SECRET_TRUE_VALUES: Final[frozenset[str]] = frozenset({"1", "true", "yes"})

MIN_INFLIGHT_STALE_SECONDS: Final[int] = 10
DEFAULT_INFLIGHT_STALE_SECONDS: Final[int] = 60


def _parse_inflight_stale_seconds(raw: str | None) -> int:
    """Parse ``INFLIGHT_STALE_SECONDS``: clamp to the minimum, fall back on bad input."""
    if raw is None:
        return DEFAULT_INFLIGHT_STALE_SECONDS
    try:
        value = int(raw.strip())
    except ValueError:
        logger.warning(
            "invalid INFLIGHT_STALE_SECONDS; using default %d", DEFAULT_INFLIGHT_STALE_SECONDS
        )
        return DEFAULT_INFLIGHT_STALE_SECONDS
    if value < MIN_INFLIGHT_STALE_SECONDS:
        logger.warning(
            "INFLIGHT_STALE_SECONDS below minimum; clamped to %d", MIN_INFLIGHT_STALE_SECONDS
        )
        return MIN_INFLIGHT_STALE_SECONDS
    return value


class Settings(BaseModel):
    """Environment-driven configuration."""

    model_config = ConfigDict(frozen=True)

    use_in_memory: bool = False
    database_url: str = ""
    mcp_reader_database_url: str = ""
    mcp_transport: str = "stdio"  # "stdio" (real MCP subprocess) or "inprocess" (fallback)
    gemini_api_key: str = ""
    openai_api_key: str = ""
    redis_url: str = "redis://localhost:6379/0"
    africastalking: AfricasTalkingSettings = AfricasTalkingSettings()
    public_base_url: str | None = None  # unused by SMS auth; kept for compatibility
    alert_webhook_secret: str = ""  # optional; when set, POST /webhooks/alerts needs a Bearer token
    frontend_dir: Path | None = None
    approval_ttl_seconds: int = Field(default=900, gt=0)
    reaper_interval_seconds: float = Field(default=30.0, gt=0)
    inflight_stale_seconds: int = Field(default=60, ge=MIN_INFLIGHT_STALE_SECONDS)
    allow_query_secret: bool = False  # legacy opt-in for ?secret= on the SMS webhook
    dry_run: bool = False  # enables the demo routes; from_env defaults to True like AfricasTalkingSettings

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> Settings:
        source = os.environ if env is None else env
        frontend = source.get("FRONTEND_DIR")
        return cls(
            use_in_memory=source.get("USE_IN_MEMORY", "false").strip().lower() in _TRUE_VALUES,
            database_url=source.get("DATABASE_URL", ""),
            mcp_reader_database_url=source.get("MCP_READER_DATABASE_URL", ""),
            mcp_transport=source.get("MCP_TRANSPORT", "stdio").strip().lower() or "stdio",
            gemini_api_key=source.get("GEMINI_API_KEY", "").strip(),
            openai_api_key=source.get("OPENAI_API_KEY", "").strip(),
            redis_url=source.get("REDIS_URL", "redis://localhost:6379/0"),
            africastalking=AfricasTalkingSettings.from_env(source),
            public_base_url=source.get("PUBLIC_BASE_URL") or None,
            alert_webhook_secret=source.get("ALERT_WEBHOOK_SECRET", "").strip(),
            frontend_dir=Path(frontend) if frontend else None,
            approval_ttl_seconds=int(source.get("APPROVAL_TTL_SECONDS", "900") or "900"),
            reaper_interval_seconds=float(source.get("REAPER_INTERVAL_SECONDS", "30") or "30"),
            inflight_stale_seconds=_parse_inflight_stale_seconds(source.get("INFLIGHT_STALE_SECONDS")),
            allow_query_secret=source.get("ALLOW_QUERY_SECRET", "").strip().lower()
            in _QUERY_SECRET_TRUE_VALUES,
            dry_run=source.get("DRY_RUN", "true").strip().lower() in (_TRUE_VALUES | {""}),
        )


def build_in_memory_services(settings: Settings) -> AppServices:
    """Adapters that need no external infrastructure (tests, dry-run demo)."""
    from langgraph.checkpoint.memory import MemorySaver

    incidents = InMemoryIncidentRepository()
    audit = InMemoryAuditStore(incidents)
    sms = AfricasTalkingSmsAdapter(settings.africastalking.model_copy(update={"dry_run": True}))
    ports = Ports(
        telemetry=StaticTelemetry(),
        sms=sms,
        audit=audit,
        runbooks=SimulatedRunbooks(),
        summarizer=DisabledSummarizer(),
    )
    async def reseed_noop() -> int:  # static telemetry has no logs to age out
        return 0

    return AppServices(
        graph=build_graph(ports, MemorySaver()),
        dedup=InMemoryDedupStore(),
        sms=sms,
        incidents=incidents,
        audit=audit,
        africastalking_webhook_secret=settings.africastalking.webhook_secret.get_secret_value(),
        oncall_phone_number=settings.africastalking.to_number,
        africastalking_shortcode=settings.africastalking.shortcode,
        seen_ids=InMemorySeenIdStore(),
        alert_webhook_secret=settings.alert_webhook_secret,
        allow_query_secret=settings.allow_query_secret,
        reseed=reseed_noop,
        approval_ttl_seconds=settings.approval_ttl_seconds,
        inflight_stale_seconds=settings.inflight_stale_seconds,
    )


async def build_real_services(settings: Settings, stack: AsyncExitStack) -> AppServices:
    """Postgres + Redis wiring. Resources are registered on ``stack`` for shutdown."""
    import asyncpg  # type: ignore[import-untyped]
    from redis.asyncio import Redis

    from backend.app.mcp.server import TelemetryStore, reseed_recent_logs
    from backend.app.services.dedup import RedisDedupStore
    from backend.app.services.leader_lock import RedisReconcileLock
    from backend.app.services.seen_ids import RedisSeenIdStore
    from backend.app.services.postgres_store import (
        PostgresAuditStore,
        PostgresIncidentRepository,
        ensure_system_incident,
        sync_mcp_reader_password,
    )

    if not settings.database_url:
        raise RuntimeError("DATABASE_URL is required unless USE_IN_MEMORY=true")

    pool = await asyncpg.create_pool(dsn=settings.database_url, min_size=1, max_size=5)
    if pool is None:
        raise RuntimeError("could not create database pool")
    stack.push_async_callback(pool.close)
    await ensure_system_incident(pool)
    try:
        await sync_mcp_reader_password(pool, os.environ.get("MCP_READER_PASSWORD"))
    except asyncpg.PostgresError:
        logger.warning("could not sync mcp_reader password (insufficient privilege?)")

    # Admin/app pool (not mcp_reader) refreshes demo logs; never inside the MCP read-only txn.
    async def reseed() -> int:
        return await reseed_recent_logs(pool)

    if settings.dry_run:
        try:
            logger.info("reseeded %d demo log rows", await reseed())
        except (asyncpg.PostgresError, OSError, TimeoutError):
            logger.warning("startup demo log reseed failed")

    redis = Redis.from_url(settings.redis_url)
    stack.push_async_callback(redis.aclose)

    sms = AfricasTalkingSmsAdapter(settings.africastalking.model_copy(update={"dry_run": settings.dry_run}))
    stack.push_async_callback(sms.aclose)

    telemetry: DatabaseTelemetry | McpSubprocessTelemetry
    if settings.mcp_transport == "inprocess":
        telemetry_store = TelemetryStore(settings.mcp_reader_database_url or None)
        stack.push_async_callback(telemetry_store.close)
        telemetry = DatabaseTelemetry(telemetry_store)
    else:
        telemetry = McpSubprocessTelemetry(
            settings.mcp_reader_database_url or settings.database_url
        )

    summarizer = LlmSummarizer(
        gemini_api_key=settings.gemini_api_key, openai_api_key=settings.openai_api_key
    )
    stack.push_async_callback(summarizer.aclose)

    async def ping() -> None:
        await pool.fetchval("SELECT 1")
        await redis.ping()

    incidents = PostgresIncidentRepository(pool)
    audit = PostgresAuditStore(pool)
    ports = Ports(
        telemetry=telemetry,
        sms=sms,
        audit=audit,
        runbooks=SimulatedRunbooks(telemetry),
        summarizer=summarizer,
    )
    graph = await stack.enter_async_context(compile_with_postgres(settings.database_url, ports))
    return AppServices(
        graph=graph,
        dedup=RedisDedupStore(redis),
        sms=sms,
        incidents=incidents,
        audit=audit,
        africastalking_webhook_secret=settings.africastalking.webhook_secret.get_secret_value(),
        oncall_phone_number=settings.africastalking.to_number,
        africastalking_shortcode=settings.africastalking.shortcode,
        seen_ids=RedisSeenIdStore(redis),
        alert_webhook_secret=settings.alert_webhook_secret,
        allow_query_secret=settings.allow_query_secret,
        reseed=reseed,
        ping=ping,
        reconcile_lock=RedisReconcileLock(redis),
        approval_ttl_seconds=settings.approval_ttl_seconds,
        inflight_stale_seconds=settings.inflight_stale_seconds,
    )


def _default_frontend_dir() -> Path:
    return Path(__file__).resolve().parents[2] / "frontend"


def create_app(
    services: AppServices | None = None,
    settings: Settings | None = None,
) -> FastAPI:
    """Create the app. Pass ``services`` to inject adapters (skips env wiring)."""
    cfg = settings if settings is not None else Settings.from_env()
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
            reaper = asyncio.create_task(lifecycle.run_reaper(cfg.reaper_interval_seconds), name="approval-reaper")
            try:
                yield
            finally:
                reaper.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await reaper

    app = FastAPI(title="Pagemaster", lifespan=lifespan)
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
