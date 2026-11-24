"""Environment configuration: ``Settings``, ``ConfigError`` and the env parsing helpers.

Pure configuration: no FastAPI, asyncpg or redis imports. Consumed by ``container`` and ``main``.

Variables read by ``Settings.from_env``:

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

Requirements: 11.1 to 11.5.
"""

from __future__ import annotations

import logging
import os
from collections.abc import Mapping
from pathlib import Path
from typing import Final

from pydantic import BaseModel, ConfigDict, Field, SecretStr

from backend.app.services.africastalking_client import AfricasTalkingSettings, canonicalize_e164
from backend.app.services.incident_store import DEFAULT_TOKEN_COOLDOWN_SECONDS
from backend.app.services.page_rate import DEFAULT_PAGE_RATE_PER_MINUTE
from backend.app.services.sms_common import mask_phone

# Historical logger name: tests and operators filter parse warnings on ``pagemaster.main``.
logger = logging.getLogger("pagemaster.main")

# Defaults owned here so config stays free of asyncpg/redis/mcp imports. The modules that used
# to define them (api.app_services, services.readiness, services.mcp_client) import them from here.
DEFAULT_MAX_ALERT_BODY_BYTES: Final[int] = 65_536
DEFAULT_DEDUP_AUDIT_SAMPLE: Final[int] = 20
DEFAULT_PAGE_FAILURE_READY_THRESHOLD: Final[int] = 3
DEFAULT_TELEMETRY_MAX_CONCURRENCY: Final[int] = 4

_TRUE_VALUES: Final[frozenset[str]] = frozenset({"1", "true", "yes", "on"})
_QUERY_SECRET_TRUE_VALUES: Final[frozenset[str]] = frozenset({"1", "true", "yes"})

MIN_INFLIGHT_STALE_SECONDS: Final[int] = 10
DEFAULT_INFLIGHT_STALE_SECONDS: Final[int] = 60
MIN_INFLIGHT_TIMEOUT_SECONDS: Final[int] = 10
DEFAULT_INFLIGHT_TIMEOUT_SECONDS: Final[int] = 120
DEFAULT_PAGE_MAX_ATTEMPTS: Final[int] = 3


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


def _parse_timeout_seconds(name: str, raw: str | None) -> int:
    """Parse ``TRIAGE_TIMEOUT_SECONDS`` / ``EXECUTING_TIMEOUT_SECONDS`` (default 120, minimum 10)."""
    return _parse_min_seconds(name, raw, DEFAULT_INFLIGHT_TIMEOUT_SECONDS, MIN_INFLIGHT_TIMEOUT_SECONDS)


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
