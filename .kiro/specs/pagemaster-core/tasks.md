# Implementation Plan: Pagemaster Core

- [x] 1. Initialize repository structure, Docker stack, and PostgreSQL schema
  - [x] 1.1 Create `docker-compose.yml`, `backend/Dockerfile`, `backend/requirements.txt` (`fastapi`, `uvicorn`, `langgraph`, `langgraph-checkpoint-postgres`, `mcp`, `asyncpg`, `redis`, `twilio`, `pydantic`, `pytest`, `hypothesis`), and `LICENSE` (MIT).
    - _Requirements: 1.1, 4.1_
  - [x] 1.2 Create `database/init_mock_logs.sql` defining tables (`incidents`, `service_logs`, `approved_runbooks`, `audit_trail`), read-only views (`v_recent_logs`, `v_service_topology`, `v_approved_runbooks`), a restricted `mcp_reader` DB role, and realistic seed incident logs for `auth-db`, `payment-gateway`, and `ledger-worker`.
    - _Requirements: 2.2, 5.2_

- [x] 2. Build read-only FastMCP telemetry server and deterministic guardrails
  - [x] 2.1 Implement `backend/app/mcp/server.py` using `FastMCP` exposing `get_incident_context(service_name)` over a read-only `asyncpg` pool with a 5-second timeout and graceful fallback.
    - _Requirements: 2.1, 2.2, 2.3_
  - [x] 2.2 Implement `backend/app/services/guardrails.py` containing `sanitize_pager_text`, `format_pager_payload` (enforcing `<= 160` ASCII chars), `parse_sms_reply`, `TripwireValidator`, and SHA-256 hash-chained `AuditLogger`.
    - _Requirements: 3.1, 3.2, 3.3, 4.4, 5.1, 5.2, 5.3_

- [x] 3. Implement LangGraph supervisor-worker state machine with Postgres HITL checkpointing
  - [x] 3.1 Implement `backend/app/agents/graph.py` defining `IncidentState`, `triage_worker`, `supervisor_formatter`, `human_approval_gate` (using `langgraph.types.interrupt`), `tripwire_guard`, and `remediation_executor` compiled with `AsyncPostgresSaver`.
    - _Requirements: 2.1, 3.1, 4.1, 4.4, 5.1, 5.3_

- [x] 4. Build FastAPI webhook gateway, Redis deduplication, and Twilio SMS adapter
  - [x] 4.1 Implement `backend/app/services/dedup.py` using Redis `SET ... NX EX 300` for atomic incident fingerprinting and `backend/app/services/twilio_client.py` supporting both live Twilio dispatch and `DRY_RUN` mode.
    - _Requirements: 1.2, 4.1_
  - [x] 4.2 Implement `backend/app/main.py` and `backend/app/api/routes.py` with `POST /webhooks/alerts`, `POST /webhooks/twilio/sms` (with `RequestValidator` signature verification), `GET /api/incidents`, and `GET /api/incidents/{id}/audit`.
    - _Requirements: 1.1, 1.2, 1.3, 4.2, 4.3, 4.5_

- [x] 5. Build Retro LCD Pager Simulator UI and Property-Based Test Suite
  - [x] 5.1 Create `frontend/index.html` styled as a 1990s Motorola Advisor two-way pager with live incident polling, simulated alert triggers, and one-click SMS reply buttons (`<TOKEN>-1` / `<TOKEN>-2`) for demo resilience.
    - _Requirements: 1.1, 4.1, 4.4_
  - [x] 5.2 Implement `backend/tests/test_properties.py` covering Properties 1ΓÇô5 using `hypothesis` (`@settings(max_examples=200)`) and integration tests in `backend/tests/test_workflow.py` verifying end-to-end deduplication, HITL interrupt/resume, and Tripwire blocking.
    - _Requirements: 1.2, 3.2, 4.3, 4.5, 5.2, 5.3_

# Hardening (round 2)

- [x] 6. Fix PostgreSQL startup gate crash, BOM encoding, and fresh telemetry confidence
  - [x] 6.1 Update `_SQL_ENSURE_SYSTEM` in `backend/app/services/postgres_store.py` to insert `TRUE` for `tripwire_check_passed`, `simulated_step_executed`, `confirmation_sms_sent`, and `audit_record_committed`, and sync `mcp_reader` password from `MCP_READER_PASSWORD` during startup initialization.
  - [x] 6.2 Update `backend/tests/test_postgres_integration.py` to read `database/init_mock_logs.sql` using `encoding="utf-8-sig"` and add `test_ensure_system_incident_satisfies_check_constraint`.
  - [x] 6.3 Update `TelemetryStore._fetch` in `backend/app/mcp/server.py` to return `Confidence.DEGRADED` (`degraded_reason="no recent logs in window"`) when `recent_logs` is empty, and add `reseed_recent_logs()` invoked on startup in `DRY_RUN=true` mode (plus `POST /api/demo/reseed`) so demo logs never age out of the 15-minute `v_recent_logs` window.

- [x] 7. Enforce GSM-7 single-SMS septet budget, runbook action titles, and prompt escaping
  - [x] 7.1 Implement GSM 03.38 (GSM-7) septet counting (`gsm7_septets`) and UCS-2 prevention in `backend/app/services/guardrails.py` (transliterating backticks/smart quotes, accounting for 2-septet extension characters `^{}\\[~]|€`, and clamping `gsm7_septets(text) <= 160`).
  - [x] 7.2 Update `format_pager_payload` and `supervisor_formatter` (`backend/app/agents/graph.py`) to include short titles for options `1` and `2` (`INC-<TOKEN> <service>: <summary>. <TOKEN>-1:<t1> <TOKEN>-2:<t2>`) within the 160-septet budget.
  - [x] 7.3 Escape XML delimiter tags (`</logs>`, `<logs>`) in `backend/app/services/llm_summarizer.py` before interpolating untrusted log text into LLM prompts.
  - [x] 7.4 Extend `backend/tests/test_properties.py` with Hypothesis properties verifying `gsm7_septets(payload.text) <= 160`, zero UCS-2 fallback characters, and presence of both action titles.

- [x] 8. Migrate SMS transport to Africa's Talking and lock down reply authorization
  - [x] 8.1 Implement `AfricasTalkingSmsAdapter` and `AfricasTalkingSettings` in `backend/app/services/africastalking_client.py` using `httpx.AsyncClient` (supporting sandbox vs. production endpoints, `AFRICASTALKING_USERNAME`, `AFRICASTALKING_API_KEY`, `AFRICASTALKING_SHORTCODE`, `ONCALL_PHONE_NUMBER`, and `DRY_RUN` outbox).
  - [x] 8.2 Replace `/webhooks/twilio/sms` in `backend/app/api/routes.py` with `POST /webhooks/africastalking/sms` validating `AFRICASTALKING_WEBHOOK_SECRET`, canonical E.164 sender match (`from == ONCALL_PHONE_NUMBER`), optional shortcode `to` match, and AT message `id` idempotency; log `SECURITY_VIOLATION` and return `403` on unauthorized senders.
  - [x] 8.3 Remove `token` from `IncidentView` (`GET /api/incidents`) and strip `token` from audit record payloads returned by `GET /api/incidents/{incident_id}/audit`.
  - [x] 8.4 Update `backend/tests/test_api.py` and `frontend/index.html` for Africa's Talking webhook payloads, unauthorized sender `403` rejection, and token redaction.

- [x] 9. Implement non-circular TOCTOU Tripwire, incident approval expiry, and crash reconciliation
  - [x] 9.1 Update `tripwire_guard` in `backend/app/agents/graph.py` to query `ports.runbooks.list_approved(state["service_name"])` dynamically at execution time rather than trusting cached triage state, verifying `action_id` is currently approved for `service_name`.
  - [x] 9.2 Add `EXPIRED` to `IncidentStatus` and `TERMINAL_STATUSES` (and the `incidents` SQL `CHECK` constraint in `database/init_mock_logs.sql`), add `APPROVAL_TTL_SECONDS` expiration checks on reply and via a lifespan background reaper, and reconcile orphaned `TRIAGING`/`EXECUTING` incidents to `FAILED` on startup.
  - [x] 9.3 Add unit, workflow, and Hypothesis property tests in `backend/tests/test_workflow.py` and `backend/tests/test_properties.py` covering TOCTOU runbook revocation, approval expiration, and startup crash recovery.

- [x] 10. Harden Docker Compose, healthchecks, and dependency pinning
  - [x] 10.1 Add `GET /healthz` to `backend/app/api/routes.py` and a `healthcheck` block to `backend` in `docker-compose.yml`.
  - [x] 10.2 Bind Postgres and Redis ports in `docker-compose.yml` to `127.0.0.1`, configure Redis password authentication, replace `TWILIO_*` env vars with `AFRICASTALKING_*` and `APPROVAL_TTL_SECONDS`, and pin dependency versions in `backend/requirements.txt` (including `mcp>=1.2,<2`).

- [x] 11. Post-review hardening (round 1, completed before the round 2 tasks 6-10)
  - [x] 11.1 Fix PostgreSQL persistence and incident lifecycle: add `IncidentRepository.record_resolution(incident_id, status, gates)` (in-memory and `postgres_store.py`) that persists the four `ResolutionGates` flags atomically with the state so `resolved_requires_all_gates` holds; use it from `_run_workflow` in `routes.py`. Add `FAILED` to `IncidentStatus` and `TERMINAL_STATUSES`, exclude it from `uq_incidents_active_fingerprint`, move failed runs (executor gate failure, unhandled `_run_workflow` exception) to `FAILED`, and release the Redis lock. Change `database/init_mock_logs.sql` to seed only terminal incidents (`RESOLVED`, `BLOCKED_BY_TRIPWIRE`). Add a Postgres integration test file that is skipped when no `TEST_DATABASE_URL` is set.
    - _Requirements: 1.2, 4.4, 5.2, 5.3, 5.4, 5.5_
  - [x] 11.2 Harden `guardrails.py`: replace the loose IPv6 regex with candidate extraction validated by `ipaddress.ip_address()` so timestamps such as `12:30:45` survive, and make `jsonb_text` handle floats (normalize to Decimal strings matching Postgres jsonb output) instead of raising `TypeError`. Add property tests.
    - _Requirements: 3.2, 3.3, 5.3_
  - [x] 11.3 Make triage use real MCP and wire the summarizer: `mcp/server.py` reads `MCP_READER_DATABASE_URL` before `DATABASE_URL`; add an `McpSubprocessTelemetry` adapter (`mcp.client.stdio.stdio_client` and `ClientSession` spawning `python -m backend.app.mcp.server`) used by `build_real_services`; add an `LlmSummarizer` adapter (Gemini or OpenAI when an API key is set, clean fallback otherwise) wired into `Ports`, with output still clamped by `format_pager_payload`.
    - _Requirements: 2.1, 2.2, 2.3, 3.1, 3.3_
  - [x] 11.4 API, compose and UI hardening: optional `ALERT_WEBHOOK_SECRET` bearer check on `POST /webhooks/alerts`; expose `PUBLIC_BASE_URL`, `USE_IN_MEMORY`, `ALERT_WEBHOOK_SECRET` in `docker-compose.yml`; add a NEXT button to `frontend/index.html` that cycles through `AWAITING_APPROVAL` incidents and binds `-1`/`-2` to the selected page; add a `.gitignore` covering `__pycache__/`, `.pytest_cache/`, `.mypy_cache/`, `.hypothesis/`; run `pytest backend/tests/ -v` and `mypy --strict backend/app` and fix failures.
    - _Requirements: 1.1, 1.3, 4.1, 4.4_

  # Multi-Worker, DB-Clock Expiry & Webhook Auth Hardening

- [x] 12. Make startup reconciliation multi-worker safe with a stale-lease cutoff
  - [x] 12.1 Add `inflight_stale_seconds: int = 60` (read from `INFLIGHT_STALE_SECONDS`, minimum `10`) to `Settings` in `backend/app/main.py`.
  - [x] 12.2 Update `reconcile_stale_inflight` in `backend/app/services/postgres_store.py` to atomically transition only stale rows via `UPDATE incidents SET state = 'FAILED', updated_at = now() WHERE state IN ('TRIAGING', 'EXECUTING') AND updated_at <= now() - make_interval(secs => $1) RETURNING incident_id, token, service_name, error_code`, and mirror the cutoff in `InMemoryIncidentRepository` (`backend/app/services/incident_store.py`).
  - [x] 12.3 Update startup reconciliation in `backend/app/services/lifecycle.py` and `backend/app/main.py` to acquire an optional short-TTL Redis leader lock (`SET pagemaster:reconcile_lock <worker_id> NX EX 30`), release the `(service_name, error_code)` dedup lock for each reclaimed incident, and append an `INCIDENT_FAILED` audit record (`{"reason": "stale_inflight_reconciled"}`).

- [x] 13. Evaluate incident approval expiry strictly against PostgreSQL database time
  - [x] 13.1 Replace Python `datetime.now()` vs. `updated_at` comparisons in `backend/app/services/postgres_store.py` with SQL-side `updated_at <= now() - make_interval(secs => $1)` checks in both `expire_stale_awaiting(ttl_seconds)` and point-of-use `expire_if_stale(token, ttl_seconds)`, and compute `is_expired` inside SQL `SELECT` queries.
  - [x] 13.2 Update `backend/app/services/lifecycle.py` and `backend/app/api/routes.py` so `POST /webhooks/africastalking/sms` and `POST /api/demo/reply` call `expire_if_stale` atomically before resuming LangGraph, freeing the dedup lock and appending `INCIDENT_EXPIRED` when expired.

- [x] 14. Enforce header-based authentication on Africa's Talking callbacks by default
  - [x] 14.1 Add `allow_query_secret: bool = False` (from `ALLOW_QUERY_SECRET`) to `Settings` in `backend/app/main.py`, and log a startup warning if `PUBLIC_BASE_URL` contains a `?` query string.
  - [x] 14.2 Update `POST /webhooks/africastalking/sms` in `backend/app/api/routes.py` (and helpers in `backend/app/services/africastalking_client.py`) to read `X-Webhook-Secret` first, then `Authorization: Bearer <secret>`, and ignore `?secret=` unless `ALLOW_QUERY_SECRET=true`; validate with `hmac.compare_digest` and return `403 Forbidden` with a `SECURITY_VIOLATION` audit record on mismatch.
  - [x] 14.3 Add `INFLIGHT_STALE_SECONDS=60` and `ALLOW_QUERY_SECRET=false` to `docker-compose.yml` and update `.kiro/steering/pagemaster-standards.md` and `README.md` to document header-only webhook authentication.

- [x] 15. Switch `.kiro/settings/mcp.json` to `MCP_READER_DATABASE_URL` and add regression tests
  - [x] 15.1 Update `.kiro/settings/mcp.json` so `pagemaster-telemetry` sets `MCP_READER_DATABASE_URL` instead of `DATABASE_URL`.
  - [x] 15.2 Add tests in `backend/tests/test_expiry.py` and `backend/tests/test_postgres_integration.py` verifying that fresh `TRIAGING`/`EXECUTING` incidents younger than `INFLIGHT_STALE_SECONDS` are untouched on worker boot, stale ones transition to `FAILED` and free their dedup lock, and SQL-backdated `AWAITING_APPROVAL` rows expire using DB `now()` regardless of app clock skew.
  - [x] 15.3 Add tests in `backend/tests/test_africastalking_client.py` and `backend/tests/test_api.py` verifying `?secret=` returns `403` when `ALLOW_QUERY_SECRET=false` while `X-Webhook-Secret` and `Authorization: Bearer` headers are accepted.
