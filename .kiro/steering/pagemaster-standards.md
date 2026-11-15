---
inclusion: always
---
# Pagemaster Engineering & Guardrail Standards

- **Architecture:** Strict hexagonal boundaries. Domain state machines (`backend/app/agents/`) must never import FastAPI or Twilio SDKs directly; interact via typed port interfaces.
- **Determinism & Safety:** Never allow unconstrained shell or SQL execution. All MCP database tools must enforce `SET TRANSACTION READ ONLY` and query allowlisted views only.
- **Pager Payload Invariant:** Every outbound pager message MUST be ASCII, cost <= 160 GSM-7 septets (extension characters `^{}\[~]|€` count as 2; no UCS-2 fallback), contain a valid `INC-<TOKEN>` prefix with both reply options and their short titles, and strip emails, IPv4/IPv6 addresses, and bearer tokens.
- **Testing Discipline:** Every correctness property in `design.md` must have a corresponding `hypothesis` property-based test in `backend/tests/test_properties.py` with `@settings(max_examples=200)`.
- **Code Hygiene:** Python 3.13+, strict type annotations (`mypy --strict` compatible), Pydantic v2 models for all state and webhook payloads, async I/O throughout.
- **SMS Transport & Authorization:** SMS goes through Africa's Talking behind the `SmsPort` protocol (adapters live in `backend/app/services/`, never in `backend/app/agents/`). Inbound replies require the webhook shared secret, an E.164 sender equal to `ONCALL_PHONE_NUMBER`, a matching shortcode when configured, and message-`id` idempotency. Reply tokens must never be returned by public APIs or audit payloads.
- **Webhook Authentication (header-only):** The Africa's Talking secret is read from `X-Webhook-Secret`, then `Authorization: Bearer`. `?secret=` is ignored unless `ALLOW_QUERY_SECRET=true`, because URLs leak into proxy and access logs. Compare with `hmac.compare_digest` and fail closed (empty or missing configured secret rejects everything).
- **Tripwire:** Authorization data must be re-queried at execution time (no TOCTOU). Never authorize from state cached during triage.
- **Lifecycle:** Every non-terminal state needs an exit. Approvals expire after `APPROVAL_TTL_SECONDS` (`EXPIRED`), orphaned `TRIAGING`/`EXECUTING` incidents are reconciled to `FAILED` on startup, and every terminal state releases the fingerprint lock. Startup reconciliation fails only stale in-flight incidents (older than `INFLIGHT_STALE_SECONDS`), so it is safe with multiple workers. Expiry is evaluated with the database clock, not the application clock.
