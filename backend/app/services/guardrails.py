"""Backwards-compatible facade over the focused guardrail modules.

The implementation lives in:

* :mod:`backend.app.services.gsm7`: GSM 03.38 septet accounting, transliteration, clamping.
* :mod:`backend.app.services.sanitizer`: PII/secret redaction, reply-code neutralisation,
  ``format_pager_payload``.
* :mod:`backend.app.services.tripwire`: reply grammar, ``TripwireValidator``, ``ResolutionGates``.
* :mod:`backend.app.services.audit_chain`: ``AuditLogger``, ``compute_audit_hash``, ``jsonb_text``.

Dependencies flow one way: ``gsm7`` and ``audit_chain`` are leaves, ``sanitizer`` and
``tripwire`` import from them, and this module only re-exports.
"""

from __future__ import annotations

from backend.app.services.audit_chain import (
    GENESIS_HASH,
    AuditEvent,
    AuditLogger,
    AuditRecord,
    ChainVerification,
    JsonValue,
    compute_audit_hash,
    jsonb_text,
    verify_chain,
)
from backend.app.services.gsm7 import (
    _GSM7_BASIC,
    _GSM7_EXTENSION,
    PAGER_MAX_CHARS,
    clamp_to_septets,
    gsm7_septet_cost,
    gsm7_septets,
    to_gsm7_safe,
    transliterate_gsm7,
)
from backend.app.services.sanitizer import (
    MAX_PAGE_OPTIONS,
    NO_ACTION_TEXT,
    REDACTION,
    TITLE_MAX_SEPTETS,
    ClampReason,
    PagerPayload,
    SanitizeResult,
    format_pager_payload,
    neutralize_reply_codes,
    sanitize_pager_text,
    sanitize_with_report,
    short_title,
)
from backend.app.services.tripwire import (
    ResolutionGates,
    SmsReply,
    TripwireResult,
    TripwireValidator,
    TripwireViolationError,
    can_resolve,
    normalize_sms_reply,
    parse_sms_reply,
)

__all__ = [
    "GENESIS_HASH",
    "MAX_PAGE_OPTIONS",
    "NO_ACTION_TEXT",
    "PAGER_MAX_CHARS",
    "REDACTION",
    "TITLE_MAX_SEPTETS",
    "AuditEvent",
    "AuditLogger",
    "AuditRecord",
    "ChainVerification",
    "ClampReason",
    "JsonValue",
    "PagerPayload",
    "ResolutionGates",
    "SanitizeResult",
    "SmsReply",
    "TripwireResult",
    "TripwireValidator",
    "TripwireViolationError",
    "can_resolve",
    "clamp_to_septets",
    "compute_audit_hash",
    "format_pager_payload",
    "gsm7_septet_cost",
    "gsm7_septets",
    "jsonb_text",
    "neutralize_reply_codes",
    "normalize_sms_reply",
    "parse_sms_reply",
    "sanitize_pager_text",
    "sanitize_with_report",
    "short_title",
    "to_gsm7_safe",
    "transliterate_gsm7",
    "verify_chain",
]

# Private names that tests import from this module.
_PRIVATE_REEXPORTS = (_GSM7_BASIC, _GSM7_EXTENSION)
