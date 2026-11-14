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
  ``TWILIO_AUTH_TOKEN`` verifies ``X-Twilio-Signature`` (missing token rejects all).
  ``PUBLIC_BASE_URL``   externally visible base URL Twilio signs (proxies/tunnels).
  ``ALERT_WEBHOOK_SECRET`` optional; when set, ``POST /webhooks/alerts`` requires
                        ``Authorization: Bearer <secret>`` (401 otherwise).
  ``FRONTEND_DIR``      static UI directory (default ``<repo>/frontend``).
  ``DRY_RUN``           default true; registers ``/api/demo/*`` (simulated replies, outbox).
  ===================== ==========================================================

Requirements: 1.1, 4.1, 4.2.
"""

from __future__ import annotations

import logging
import os
from collections.abc import AsyncIterator, Mapping
from contextlib import AsyncExitStack, asynccontextmanager
from pathlib import Path
from typing import Final

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict

from backend.app.agents.graph import build_graph, compile_with_postgres
from backend.app.agents.ports import Ports
from backend.app.api.routes import AppServices, demo_router, router
from backend.app.services.dedup import InMemoryDedupStore
from backend.app.services.llm_summarizer import DisabledSummarizer, LlmSummarizer
from backend.app.services.incident_store import InMemoryAuditStore, InMemoryIncidentRepository
from backend.app.services.mcp_client import McpSubprocessTelemetry
from backend.app.services.telemetry_adapters import (
    DatabaseTelemetry,
    SimulatedRunbooks,
    StaticTelemetry,
)
from backend.app.services.twilio_client import TwilioSmsAdapter

logger = logging.getLogger("pagemaster.main")
_TRUE_VALUES: Final[frozenset[str]] = frozenset({"1", "true", "yes", "on"})


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
    twilio_auth_token: str = ""
    public_base_url: str | None = None
    alert_webhook_secret: str = ""  # optional; when set, POST /webhooks/alerts needs a Bearer token
    frontend_dir: Path | None = None
    dry_run: bool = False  # enables the demo routes; from_env defaults to True like TwilioSettings

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
            twilio_auth_token=source.get("TWILIO_AUTH_TOKEN", ""),
            public_base_url=source.get("PUBLIC_BASE_URL") or None,
            alert_webhook_secret=source.get("ALERT_WEBHOOK_SECRET", "").strip(),
            frontend_dir=Path(frontend) if frontend else None,
            dry_run=source.get("DRY_RUN", "true").strip().lower() in (_TRUE_VALUES | {""}),
        )


def build_in_memory_services(settings: Settings) -> AppServices:
    """Adapters that need no external infrastructure (tests, dry-run demo)."""
    from langgraph.checkpoint.memory import MemorySaver

    incidents = InMemoryIncidentRepository()
    audit = InMemoryAuditStore(incidents)
    sms = TwilioSmsAdapter()
    ports = Ports(
        telemetry=StaticTelemetry(),
        sms=sms,
        audit=audit,
        runbooks=SimulatedRunbooks(),
        summarizer=DisabledSummarizer(),
    )
    return AppServices(
        graph=build_graph(ports, MemorySaver()),
        dedup=InMemoryDedupStore(),
        sms=sms,
        incidents=incidents,
        audit=audit,
        twilio_auth_token=settings.twilio_auth_token,
        public_base_url=settings.public_base_url,
        alert_webhook_secret=settings.alert_webhook_secret,
    )


async def build_real_services(settings: Settings, stack: AsyncExitStack) -> AppServices:
    """Postgres + Redis wiring. Resources are registered on ``stack`` for shutdown."""
    import asyncpg  # type: ignore[import-untyped]
    from redis.asyncio import Redis

    from backend.app.mcp.server import TelemetryStore
    from backend.app.services.dedup import RedisDedupStore
    from backend.app.services.postgres_store import (
        PostgresAuditStore,
        PostgresIncidentRepository,
        ensure_system_incident,
    )

    if not settings.database_url:
        raise RuntimeError("DATABASE_URL is required unless USE_IN_MEMORY=true")

    pool = await asyncpg.create_pool(dsn=settings.database_url, min_size=1, max_size=5)
    if pool is None:
        raise RuntimeError("could not create database pool")
    stack.push_async_callback(pool.close)
    await ensure_system_incident(pool)

    redis = Redis.from_url(settings.redis_url)
    stack.push_async_callback(redis.aclose)

    sms = TwilioSmsAdapter()
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
        twilio_auth_token=settings.twilio_auth_token,
        public_base_url=settings.public_base_url,
        alert_webhook_secret=settings.alert_webhook_secret,
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

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        if services is not None:
            app.state.services = services
            yield
            return
        async with AsyncExitStack() as stack:
            if cfg.use_in_memory:
                app.state.services = build_in_memory_services(cfg)
            else:
                app.state.services = await build_real_services(cfg, stack)
            yield

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
