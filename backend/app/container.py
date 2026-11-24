"""Service container wiring: ``build_in_memory_services`` and ``build_real_services``.

``ServiceContainer`` is the canonical bundle of adapters, an alias of ``AppServices`` (defined in
``backend.app.api.app_services`` so the HTTP layer never imports this module). Import graph:
``config`` <- ``api.app_services`` <- ``container`` <- ``main``.

Requirements: 1.1, 4.1, 4.2, 11.1 to 11.5.
"""

from __future__ import annotations

import logging
import os
from contextlib import AsyncExitStack

from backend.app.agents.graph import build_graph, compile_with_postgres
from backend.app.agents.ports import Ports
from backend.app.api.app_services import AppServices
from backend.app.config import Settings
from backend.app.services.africastalking_client import AfricasTalkingSmsAdapter
from backend.app.services.dedup import InMemoryDedupStore
from backend.app.services.incident_store import InMemoryAuditStore, InMemoryIncidentRepository
from backend.app.services.llm_summarizer import DisabledSummarizer, LlmSummarizer
from backend.app.services.mcp_client import McpSubprocessTelemetry
from backend.app.services.page_rate import CoalescingPageGate, PageRateLimiter
from backend.app.services.retrying_sms import RetryingSmsPort
from backend.app.services.seen_ids import InMemorySeenIdStore
from backend.app.services.telemetry_adapters import DatabaseTelemetry, SimulatedRunbooks, StaticTelemetry

__all__ = ["ServiceContainer", "build_in_memory_services", "build_real_services"]

logger = logging.getLogger("pagemaster.container")

ServiceContainer = AppServices


def build_in_memory_services(settings: Settings) -> ServiceContainer:
    """Adapters that need no external infrastructure (tests, dry-run demo)."""
    from langgraph.checkpoint.memory import MemorySaver

    incidents = InMemoryIncidentRepository()
    audit = InMemoryAuditStore(incidents)
    sms = AfricasTalkingSmsAdapter(settings.africastalking.model_copy(update={"dry_run": True}))
    paging = RetryingSmsPort(sms, max_attempts=settings.page_max_attempts)
    page_gate = CoalescingPageGate(paging, PageRateLimiter(settings.page_rate_per_minute))
    ports = Ports(
        telemetry=StaticTelemetry(),
        sms=paging,
        audit=audit,
        runbooks=SimulatedRunbooks(),
        summarizer=DisabledSummarizer(),
        page_gate=page_gate,
    )

    async def reseed_noop() -> int:  # static telemetry has no logs to age out
        return 0

    return AppServices(
        graph=build_graph(ports, MemorySaver()),
        page_gate=page_gate,
        dedup=InMemoryDedupStore(),
        sms=sms,
        incidents=incidents,
        audit=audit,
        africastalking_webhook_secret=settings.africastalking.webhook_secret.get_secret_value(),
        oncall_phone_number=settings.africastalking.to_number,
        africastalking_shortcode=settings.africastalking.shortcode,
        seen_ids=InMemorySeenIdStore(),
        alert_webhook_secret=settings.alert_webhook_secret,
        api_read_secret=settings.api_read_secret,
        allow_query_secret=settings.allow_query_secret,
        reseed=reseed_noop,
        approval_ttl_seconds=settings.approval_ttl_seconds,
        inflight_stale_seconds=settings.inflight_stale_seconds,
        triage_timeout_seconds=settings.triage_timeout_seconds,
        executing_timeout_seconds=settings.executing_timeout_seconds,
        token_cooldown_seconds=settings.token_cooldown_seconds,
        max_alert_body_bytes=settings.max_alert_body_bytes,
        dedup_audit_sample=settings.dedup_audit_sample,
        page_failure_ready_threshold=settings.page_failure_ready_threshold,
    )


async def build_real_services(settings: Settings, stack: AsyncExitStack) -> ServiceContainer:
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
        mcp_telemetry = McpSubprocessTelemetry(
            settings.mcp_reader_database_url or settings.database_url,
            max_concurrency=settings.telemetry_max_concurrency,
        )
        stack.push_async_callback(mcp_telemetry.aclose)  # stop the long-lived subprocess
        telemetry = mcp_telemetry

    summarizer = LlmSummarizer(
        gemini_api_key=settings.gemini_api_key, openai_api_key=settings.openai_api_key
    )
    stack.push_async_callback(summarizer.aclose)

    async def ping_postgres() -> None:
        await pool.fetchval("SELECT 1")

    async def ping_redis() -> None:
        await redis.ping()

    incidents = PostgresIncidentRepository(pool)
    audit = PostgresAuditStore(pool)
    paging = RetryingSmsPort(sms, max_attempts=settings.page_max_attempts)
    page_gate = CoalescingPageGate(paging, PageRateLimiter(settings.page_rate_per_minute))
    ports = Ports(
        telemetry=telemetry,
        sms=paging,
        audit=audit,
        runbooks=SimulatedRunbooks(telemetry),
        summarizer=summarizer,
        page_gate=page_gate,
    )
    graph = await stack.enter_async_context(compile_with_postgres(settings.database_url, ports))
    return AppServices(
        graph=graph,
        page_gate=page_gate,
        dedup=RedisDedupStore(redis),
        sms=sms,
        incidents=incidents,
        audit=audit,
        africastalking_webhook_secret=settings.africastalking.webhook_secret.get_secret_value(),
        oncall_phone_number=settings.africastalking.to_number,
        africastalking_shortcode=settings.africastalking.shortcode,
        seen_ids=RedisSeenIdStore(redis),
        alert_webhook_secret=settings.alert_webhook_secret,
        api_read_secret=settings.api_read_secret,
        allow_query_secret=settings.allow_query_secret,
        reseed=reseed if settings.dry_run else None,  # live mode never reseeds demo logs (Req 11.2)
        ping_postgres=ping_postgres,
        ping_redis=ping_redis,
        page_failure_ready_threshold=settings.page_failure_ready_threshold,
        reconcile_lock=RedisReconcileLock(redis),
        approval_ttl_seconds=settings.approval_ttl_seconds,
        inflight_stale_seconds=settings.inflight_stale_seconds,
        triage_timeout_seconds=settings.triage_timeout_seconds,
        executing_timeout_seconds=settings.executing_timeout_seconds,
        token_cooldown_seconds=settings.token_cooldown_seconds,
        max_alert_body_bytes=settings.max_alert_body_bytes,
        dedup_audit_sample=settings.dedup_audit_sample,
    )
