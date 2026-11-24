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
  ``API_READ_SECRET``   required when ``DRY_RUN=false``: ``GET /api/incidents`` and ``/api/incidents/{id}/audit``
                        need ``Authorization: Bearer <API_READ_SECRET>`` (401 otherwise). Dry run stays open.
  ``FRONTEND_DIR``      static UI directory (default ``<repo>/frontend``).
  ``APPROVAL_TTL_SECONDS`` seconds an incident may await approval before it expires (900).
  ``REAPER_INTERVAL_SECONDS`` how often the background reaper looks for expired approvals (30).
  ``INFLIGHT_STALE_SECONDS`` age before a TRIAGING/EXECUTING incident is reconciled to FAILED
                        at startup (60, minimum 10; bad values fall back to 60).
  ``TRIAGE_TIMEOUT_SECONDS`` / ``EXECUTING_TIMEOUT_SECONDS`` age after which the reaper recovers
                        (TRIAGING, from its checkpoint) or fails an in-flight incident
                        (120, minimum 10; bad values fall back to 120).
  ``PAGE_MAX_ATTEMPTS`` total attempts to send a page before it is declared undeliverable
                        (default 3, minimum 1; backoff 1 s, 2 s, 4 s plus jitter; non-retryable
                        provider errors are not retried).
  ``TOKEN_COOLDOWN_SECONDS`` seconds a token stays unavailable after its incident became
                        terminal (default 3600, minimum 0).
  ``MAX_ALERT_BODY_BYTES`` largest accepted ``POST /webhooks/alerts`` body (default 65536;
                        larger gets 413).
  ``DEDUP_AUDIT_SAMPLE`` ``ALERT_DEDUPLICATED`` audit rows kept per incident before only
                        summary rows (default 20, minimum 1).
  ``TELEMETRY_MAX_CONCURRENCY`` concurrent telemetry lookups (default 4, minimum 1). One long-lived MCP
                        subprocess/session per worker serves them and respawns when it dies.
  ``PAGE_RATE_PER_MINUTE`` individual pages allowed in any 60 s window (default 6, minimum 1). Over the
                        limit incidents are still triaged and one summary page per minute is sent.
  ``PAGE_FAILURE_READY_THRESHOLD`` consecutive failed pages at which ``/readyz`` reports the pager
                        check as failing (default 3, minimum 1; bad values fall back to 3).
  ``DRY_RUN``           default true; registers ``/api/demo/*`` (simulated replies, outbox). When false the
                        app refuses to start unless ``ALERT_WEBHOOK_SECRET``, ``API_READ_SECRET``, the
                        Africa's Talking username, API key and webhook secret, and ``ONCALL_PHONE_NUMBER``
                        are set (``Settings.validate_for_runtime``). ``ONCALL_PHONE_NUMBER`` must always be
                        E.164 when set.
  ===================== ==========================================================

Requirements: 1.1, 4.1, 4.2, 11.1 to 11.5.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os
from collections.abc import AsyncIterator, Awaitable, Callable, Mapping
from contextlib import AsyncExitStack, asynccontextmanager
from pathlib import Path
from typing import Final

from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field, SecretStr

from backend.app.agents.graph import build_graph, compile_with_postgres
from backend.app.agents.ports import Ports
from backend.app.api.routes import (
    DEFAULT_DEDUP_AUDIT_SAMPLE,
    DEFAULT_MAX_ALERT_BODY_BYTES,
    AppServices,
    demo_router,
    router,
)
from backend.app.services.africastalking_client import (
    AfricasTalkingSettings,
    AfricasTalkingSmsAdapter,
    canonicalize_e164,
)
from backend.app.services.dedup import InMemoryDedupStore
from backend.app.services.readiness import (
    DEFAULT_PAGE_FAILURE_READY_THRESHOLD,
    DEPENDENCY_EXCEPTIONS,
    DEPENDENCY_UNAVAILABLE_DETAIL,
    RETRY_AFTER_SECONDS,
    OutageLog,
    dependency_kind,
)
from backend.app.services.retrying_sms import RetryingSmsPort
from backend.app.services.seen_ids import InMemorySeenIdStore
from backend.app.services.sms_common import mask_phone
from backend.app.services.llm_summarizer import DisabledSummarizer, LlmSummarizer
from backend.app.services.incident_store import (
    DEFAULT_TOKEN_COOLDOWN_SECONDS,
    InMemoryAuditStore,
    InMemoryIncidentRepository,
)
from backend.app.services.mcp_client import (
    DEFAULT_TELEMETRY_MAX_CONCURRENCY,
    McpSubprocessTelemetry,
)
from backend.app.services.page_rate import (
    DEFAULT_PAGE_RATE_PER_MINUTE,
    CoalescingPageGate,
    PageRateLimiter,
)
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


def _parse_min_seconds(name: str, raw: str | None, default: int, minimum: int) -> int:
    """Parse an integer seconds setting: clamp to ``minimum``, fall back to ``default`` on bad input."""
    if raw is None:
        return default
    try:
        value = int(raw.strip())
    except ValueError:
        logger.warning("invalid %s; using default %d", name, default)
        return default
    if value < minimum:
        logger.warning("%s below minimum; clamped to %d", name, minimum)
        return minimum
    return value


def _parse_inflight_stale_seconds(raw: str | None) -> int:
    """Parse ``INFLIGHT_STALE_SECONDS``: clamp to the minimum, fall back on bad input."""
    return _parse_min_seconds(
        "INFLIGHT_STALE_SECONDS", raw, DEFAULT_INFLIGHT_STALE_SECONDS, MIN_INFLIGHT_STALE_SECONDS
    )


MIN_INFLIGHT_TIMEOUT_SECONDS: Final[int] = 10
DEFAULT_INFLIGHT_TIMEOUT_SECONDS: Final[int] = 120


def _parse_timeout_seconds(name: str, raw: str | None) -> int:
    """Parse ``TRIAGE_TIMEOUT_SECONDS`` / ``EXECUTING_TIMEOUT_SECONDS`` (default 120, minimum 10)."""
    return _parse_min_seconds(name, raw, DEFAULT_INFLIGHT_TIMEOUT_SECONDS, MIN_INFLIGHT_TIMEOUT_SECONDS)



DEFAULT_PAGE_MAX_ATTEMPTS: Final[int] = 3


class ConfigError(ValueError):
    """Invalid or incomplete configuration. The message names variables, never their values."""


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
    api_read_secret: SecretStr = SecretStr("")  # required when dry_run is false (read APIs)
    frontend_dir: Path | None = None
    approval_ttl_seconds: int = Field(default=900, gt=0)
    reaper_interval_seconds: float = Field(default=30.0, gt=0)
    inflight_stale_seconds: int = Field(default=60, ge=MIN_INFLIGHT_STALE_SECONDS)
    triage_timeout_seconds: int = Field(default=120, ge=MIN_INFLIGHT_TIMEOUT_SECONDS)
    executing_timeout_seconds: int = Field(default=120, ge=MIN_INFLIGHT_TIMEOUT_SECONDS)
    token_cooldown_seconds: int = Field(default=DEFAULT_TOKEN_COOLDOWN_SECONDS, ge=0)
    page_max_attempts: int = Field(default=DEFAULT_PAGE_MAX_ATTEMPTS, ge=1)
    max_alert_body_bytes: int = Field(default=DEFAULT_MAX_ALERT_BODY_BYTES, ge=1)
    dedup_audit_sample: int = Field(default=DEFAULT_DEDUP_AUDIT_SAMPLE, ge=1)
    telemetry_max_concurrency: int = Field(default=DEFAULT_TELEMETRY_MAX_CONCURRENCY, ge=1)
    page_rate_per_minute: int = Field(default=DEFAULT_PAGE_RATE_PER_MINUTE, ge=1)
    page_failure_ready_threshold: int = Field(default=DEFAULT_PAGE_FAILURE_READY_THRESHOLD, ge=1)
    allow_query_secret: bool = False  # legacy opt-in for ?secret= on the SMS webhook
    dry_run: bool = True  # enables the demo routes; safe default, same as AfricasTalkingSettings

    def validate_for_runtime(self) -> None:
        """Refuse unsafe configuration (Req 11.1, 11.4). Raises ``ConfigError`` naming variables only.

        Always: ``ONCALL_PHONE_NUMBER``, when set, must canonicalize as E.164. When ``dry_run`` is
        false: the alert secret, the read secret and the full Africa's Talking channel are required.
        All problems are collected into one error; values are never included.
        """
        at = self.africastalking
        missing: list[str] = []
        invalid: list[str] = []
        if not self.dry_run:
            required = (
                ("ALERT_WEBHOOK_SECRET", self.alert_webhook_secret),
                ("API_READ_SECRET", self.api_read_secret.get_secret_value()),
                ("AFRICASTALKING_USERNAME", at.username),
                ("AFRICASTALKING_API_KEY", at.api_key.get_secret_value()),
                ("AFRICASTALKING_WEBHOOK_SECRET", at.webhook_secret.get_secret_value()),
                ("ONCALL_PHONE_NUMBER", at.to_number),
            )
            missing = [name for name, value in required if not value.strip()]
        if at.to_number.strip() and canonicalize_e164(at.to_number.strip()) is None:
            invalid.append("ONCALL_PHONE_NUMBER")
        if missing or invalid:
            parts: list[str] = []
            if missing:
                parts.append("missing: " + ", ".join(missing))
            if invalid:
                parts.append("invalid (expected E.164 such as +254700123456): " + ", ".join(invalid))
            raise ConfigError("invalid configuration; " + "; ".join(parts))

    def startup_line(self) -> str:
        """The single startup INFO line: channel, dry-run flag and masked authorized sender."""
        sender = canonicalize_e164(self.africastalking.to_number.strip())
        masked = mask_phone(sender) if sender else "unset"
        return f"pagemaster starting: sms_channel=africastalking dry_run={str(self.dry_run).lower()} authorized_sender={masked}"

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
            api_read_secret=SecretStr(source.get("API_READ_SECRET", "").strip()),
            frontend_dir=Path(frontend) if frontend else None,
            approval_ttl_seconds=int(source.get("APPROVAL_TTL_SECONDS", "900") or "900"),
            reaper_interval_seconds=float(source.get("REAPER_INTERVAL_SECONDS", "30") or "30"),
            inflight_stale_seconds=_parse_inflight_stale_seconds(source.get("INFLIGHT_STALE_SECONDS")),
            triage_timeout_seconds=_parse_timeout_seconds(
                "TRIAGE_TIMEOUT_SECONDS", source.get("TRIAGE_TIMEOUT_SECONDS")
            ),
            executing_timeout_seconds=_parse_timeout_seconds(
                "EXECUTING_TIMEOUT_SECONDS", source.get("EXECUTING_TIMEOUT_SECONDS")
            ),
            token_cooldown_seconds=_parse_min_seconds(
                "TOKEN_COOLDOWN_SECONDS",
                source.get("TOKEN_COOLDOWN_SECONDS"),
                DEFAULT_TOKEN_COOLDOWN_SECONDS,
                0,
            ),
            page_max_attempts=_parse_min_seconds(
                "PAGE_MAX_ATTEMPTS",
                source.get("PAGE_MAX_ATTEMPTS"),
                DEFAULT_PAGE_MAX_ATTEMPTS,
                1,
            ),
            max_alert_body_bytes=_parse_min_seconds(
                "MAX_ALERT_BODY_BYTES",
                source.get("MAX_ALERT_BODY_BYTES"),
                DEFAULT_MAX_ALERT_BODY_BYTES,
                1,
            ),
            dedup_audit_sample=_parse_min_seconds(
                "DEDUP_AUDIT_SAMPLE", source.get("DEDUP_AUDIT_SAMPLE"), DEFAULT_DEDUP_AUDIT_SAMPLE, 1
            ),
            telemetry_max_concurrency=_parse_min_seconds(
                "TELEMETRY_MAX_CONCURRENCY",
                source.get("TELEMETRY_MAX_CONCURRENCY"),
                DEFAULT_TELEMETRY_MAX_CONCURRENCY,
                1,
            ),
            page_rate_per_minute=_parse_min_seconds(
                "PAGE_RATE_PER_MINUTE",
                source.get("PAGE_RATE_PER_MINUTE"),
                DEFAULT_PAGE_RATE_PER_MINUTE,
                1,
            ),
            page_failure_ready_threshold=_parse_min_seconds(
                "PAGE_FAILURE_READY_THRESHOLD",
                source.get("PAGE_FAILURE_READY_THRESHOLD"),
                DEFAULT_PAGE_FAILURE_READY_THRESHOLD,
                1,
            ),
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


def _default_frontend_dir() -> Path:
    return Path(__file__).resolve().parents[2] / "frontend"


def _install_dependency_handlers(app: FastAPI) -> None:
    """Map dependency connectivity errors to 503 + ``Retry-After`` and log once per outage (Req 7.4)."""
    fallback = OutageLog()  # used before the lifespan has wired services

    def outages() -> OutageLog:
        services: AppServices | None = getattr(app.state, "services", None)
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
    services: AppServices | None = None,
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
