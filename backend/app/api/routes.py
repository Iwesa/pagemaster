"""Assembly point for the HTTP API plus a compatibility facade for its public helpers.

Handlers live in ``health``, ``webhooks``, ``incidents`` and ``demo``; shared logic in
``replies``, ``workflow`` and ``app_services``. Sub-modules never import this module.
Everything the app and tests import from ``backend.app.api.routes`` is re-exported here.

Requirements: 1.1, 1.2, 1.3, 4.2, 4.3, 4.5.
"""

from __future__ import annotations

from fastapi import APIRouter

from backend.app.api import demo, health, incidents, webhooks
from backend.app.api.app_services import (
    DEFAULT_DEDUP_AUDIT_SAMPLE,
    DEFAULT_MAX_ALERT_BODY_BYTES,
    AppServices,
    Services,
    WorkflowGraph,
    get_services,
)
from backend.app.api.demo import (
    DemoOutboxMessage,
    DemoReply,
    DemoReseedResult,
    demo_outbox,
    demo_reply,
    demo_reseed,
    demo_router,
)
from backend.app.api.health import HealthStatus, healthz, readyz
from backend.app.api.incidents import (
    REDACTED,
    AuditView,
    IncidentView,
    incident_audit,
    list_incidents,
    require_read_access,
)
from backend.app.api.replies import (
    ALREADY_HANDLED_WINDOW_SECONDS,
    TRIAGE_POLL_SECONDS,
    handle_reply,
)
from backend.app.api.webhooks import (
    DEDUP_SUMMARY_EVERY,
    EVENT_ALERT_DEDUPLICATED,
    EVENT_ALERT_DEDUPLICATED_SUMMARY,
    EVENT_TOKEN_EXHAUSTED,
    MAX_MESSAGE_ID_CHARS,
    MAX_SMS_BODY_BYTES,
    MAX_TOKEN_ATTEMPTS,
    REASON_NO_FREE_TOKEN,
    TOKEN_RETRY_AFTER_SECONDS,
    AlertAccepted,
    AlertDeduplicated,
    AlertPayload,
    SmsAck,
    _record_duplicate,
    africastalking_sms,
    authorize_inbound_sms,
    receive_alert,
    secret_violation,
)
from backend.app.api.workflow import (
    EVENT_INCIDENT_FAILED,
    EVENT_INCIDENT_NO_ACTION,
    EVENT_WORKFLOW_ERROR,
    REASON_NO_APPROVED_RUNBOOK,
    fail_incident,
    resume_triage,
    run_workflow,
)

# Underscore aliases kept for existing importers (tests).
_handle_reply = handle_reply
_run_workflow = run_workflow
_fail_incident = fail_incident
_resume_triage = resume_triage

__all__ = [
    "ALREADY_HANDLED_WINDOW_SECONDS",
    "DEDUP_SUMMARY_EVERY",
    "DEFAULT_DEDUP_AUDIT_SAMPLE",
    "DEFAULT_MAX_ALERT_BODY_BYTES",
    "EVENT_ALERT_DEDUPLICATED",
    "EVENT_ALERT_DEDUPLICATED_SUMMARY",
    "EVENT_INCIDENT_FAILED",
    "EVENT_INCIDENT_NO_ACTION",
    "EVENT_TOKEN_EXHAUSTED",
    "EVENT_WORKFLOW_ERROR",
    "MAX_MESSAGE_ID_CHARS",
    "MAX_SMS_BODY_BYTES",
    "MAX_TOKEN_ATTEMPTS",
    "REASON_NO_APPROVED_RUNBOOK",
    "REASON_NO_FREE_TOKEN",
    "REDACTED",
    "TOKEN_RETRY_AFTER_SECONDS",
    "TRIAGE_POLL_SECONDS",
    "AlertAccepted",
    "AlertDeduplicated",
    "AlertPayload",
    "AppServices",
    "AuditView",
    "DemoOutboxMessage",
    "DemoReply",
    "DemoReseedResult",
    "HealthStatus",
    "IncidentView",
    "Services",
    "SmsAck",
    "WorkflowGraph",
    "_fail_incident",
    "_handle_reply",
    "_record_duplicate",
    "_resume_triage",
    "_run_workflow",
    "africastalking_sms",
    "authorize_inbound_sms",
    "build_router",
    "demo_outbox",
    "demo_reply",
    "demo_reseed",
    "demo_router",
    "get_services",
    "healthz",
    "incident_audit",
    "list_incidents",
    "readyz",
    "receive_alert",
    "require_read_access",
    "router",
    "secret_violation",
]


def build_router(*, dry_run: bool = False) -> APIRouter:
    """Return one router with the health, webhook and read-API routes.

    The ``/api/demo/*`` routes are added only when ``dry_run`` is true, so live mode never
    registers them. Include the result before any ``StaticFiles`` mount at ``/``.
    """
    root = APIRouter()
    root.include_router(health.router)
    root.include_router(webhooks.router)
    root.include_router(incidents.router)
    if dry_run:
        root.include_router(demo.demo_router)
    return root


#: Always-on routes (no demo). ``main.create_app`` includes ``demo_router`` only when DRY_RUN=true.
router = build_router(dry_run=False)
