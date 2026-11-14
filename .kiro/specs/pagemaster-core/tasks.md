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
  - [x] 5.2 Implement `backend/tests/test_properties.py` covering Properties 1–5 using `hypothesis` (`@settings(max_examples=200)`) and integration tests in `backend/tests/test_workflow.py` verifying end-to-end deduplication, HITL interrupt/resume, and Tripwire blocking.
    - _Requirements: 1.2, 3.2, 4.3, 4.5, 5.2, 5.3_
- [x] 6. Post-review hardening
  - [x] 6.1 Fix PostgreSQL persistence and incident lifecycle: add `IncidentRepository.record_resolution(incident_id, status, gates)` (in-memory and `postgres_store.py`) that persists the four `ResolutionGates` flags atomically with the state so `resolved_requires_all_gates` holds; use it from `_run_workflow` in `routes.py`. Add `FAILED` to `IncidentStatus` and `TERMINAL_STATUSES`, exclude it from `uq_incidents_active_fingerprint`, move failed runs (executor gate failure, unhandled `_run_workflow` exception) to `FAILED`, and release the Redis lock. Change `database/init_mock_logs.sql` to seed only terminal incidents (`RESOLVED`, `BLOCKED_BY_TRIPWIRE`). Add a Postgres integration test file that is skipped when no `TEST_DATABASE_URL` is set.
    - _Requirements: 1.2, 4.4, 5.2, 5.3, 5.4, 5.5_
  - [x] 6.2 Harden `guardrails.py`: replace the loose IPv6 regex with candidate extraction validated by `ipaddress.ip_address()` so timestamps such as `12:30:45` survive, and make `jsonb_text` handle floats (normalize to Decimal strings matching Postgres jsonb output) instead of raising `TypeError`. Add property tests.
    - _Requirements: 3.2, 3.3, 5.3_
  - [x] 6.3 Make triage use real MCP and wire the summarizer: `mcp/server.py` reads `MCP_READER_DATABASE_URL` before `DATABASE_URL`; add an `McpSubprocessTelemetry` adapter (`mcp.client.stdio.stdio_client` and `ClientSession` spawning `python -m backend.app.mcp.server`) used by `build_real_services`; add an `LlmSummarizer` adapter (Gemini or OpenAI when an API key is set, clean fallback otherwise) wired into `Ports`, with output still clamped by `format_pager_payload`.
    - _Requirements: 2.1, 2.2, 2.3, 3.1, 3.3_
  - [x] 6.4 API, compose and UI hardening: optional `ALERT_WEBHOOK_SECRET` bearer check on `POST /webhooks/alerts`; expose `PUBLIC_BASE_URL`, `USE_IN_MEMORY`, `ALERT_WEBHOOK_SECRET` in `docker-compose.yml`; add a NEXT button to `frontend/index.html` that cycles through `AWAITING_APPROVAL` incidents and binds `-1`/`-2` to the selected page; add a `.gitignore` covering `__pycache__/`, `.pytest_cache/`, `.mypy_cache/`, `.hypothesis/`; run `pytest backend/tests/ -v` and `mypy --strict backend/app` and fix failures.
    - _Requirements: 1.1, 1.3, 4.1, 4.4_
