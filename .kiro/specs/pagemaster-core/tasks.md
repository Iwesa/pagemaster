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

# Hardening (round 4: external review)

Notes for tasks 16 to 27 (apply to every one of them):
- Adapted to this build (Africa's Talking only, `Lifecycle` reaper and reconciliation already exist from tasks 9, 12, 13). A finding about a Telegram channel does not apply here (see the end of `requirements.md`).
- Do not change behaviour outside the task. Keep the hexagonal rule: `backend/app/agents/` imports no FastAPI, asyncpg, Redis, httpx or SMS SDKs.
- New settings go in `Settings` with a documented env var, in `docker-compose.yml`, in a root `.env.example`, and in the README table. Secrets use `SecretStr`. All SQL stays parameterized.
- Every behaviour change needs a test, and a Hypothesis property (`@settings(max_examples=200, deadline=None)`) where an invariant exists.
- Done means `mypy --strict backend/app` is clean and `pytest backend/tests/ -v` passes. Run the suite without `TEST_DATABASE_URL`, and again with `TEST_DATABASE_URL` and `TEST_REDIS_URL` set when real Postgres and Redis are available.
- Audit every state change with the hash-chained audit store. Never put secrets, tokens, or phone numbers in audit payloads.
- Order: 16 to 20 (lifecycle and replies), 21 to 23 (overload and outages), 24 and 25 (exposure), 26 and 27 (scripts, chaos suite, CI). Task 17 needs 16, 22 needs 17, 23 reads state from 17 and 22, 27 exercises everything.

- [x] 16. Total incident lifecycle: periodic recovery, notifications, expiry replies
  - Requirements: 6.8, 6.9, 6.10, 6.11. Review findings C1, C3.
  - Today `Lifecycle` expires stale `AWAITING_APPROVAL` incidents and reconciles stale `TRIAGING`/`EXECUTING` ones only at startup (`INFLIGHT_STALE_SECONDS`). A worker that hangs mid-triage after boot is never cleaned up, and nobody is told when an incident fails or expires.
  - Add settings `TRIAGE_TIMEOUT_SECONDS` and `EXECUTING_TIMEOUT_SECONDS` (default 120, minimum 10). Extend the reaper loop (`Lifecycle.run_reaper`) to sweep stale `TRIAGING` and `EXECUTING` rows every tick, using the database clock like `reconcile_stale_inflight`.
  - Stale `TRIAGING`: first try to resume the graph from its checkpoint (thread id = incident id); if there is no checkpoint or the resume raises, mark `FAILED` (`reason=recovered_after_crash`), release the lock, audit, send `INC-<TOKEN> FAILED. Re-send the alert.`
  - Stale `EXECUTING`: `FAILED` (`reason=execution_timeout`), same cleanup, never re-run the remediation step.
  - Expiry (`handle_expiry`) now sends `INC-<TOKEN> EXPIRED. No action taken.`; a reply to an `EXPIRED` incident answers `INC-<TOKEN> expired. No action taken.` and mutates nothing.
  - Every transition is a compare-and-set on state so a late reply and the reaper cannot both win (reuse the existing repository methods; add one for the new sweeps).
  - Acceptance: a `TRIAGING` row older than the timeout is resolved or `FAILED` within one tick and a re-fired alert returns 202; an `EXECUTING` row older than the timeout becomes `FAILED` without re-execution; a reply racing the reaper never yields both an execution and `EXPIRED`.
  - Tests: unit tests with the injectable clock, in-memory and Postgres repository tests, a property test that no incident stays non-terminal past the maximum timeout, a real-stack test that kills the app process mid-triage (skipped without the env vars).
- [x] 17. Reliable page delivery
  - Requirements: 8.1, 8.2, 8.3, 8.4. Review finding C2. Depends on 16.
  - Today a failed SMS still moves the incident to `AWAITING_APPROVAL` with `PAGER_SENT {sent:false}`.
  - Add a `RetryingSmsPort` adapter in `backend/app/services/` that wraps the Africa's Talking adapter: retry retryable errors (`PAGE_MAX_ATTEMPTS`, default 3; backoff 1 s, 2 s, 4 s with jitter; injectable sleep) and fail fast on non-retryable ones (authentication, invalid number). Keep `agents/` free of infrastructure imports.
  - `dispatch_pager` in `backend/app/agents/graph.py` handles a final failure through the `SmsPort` contract: audit `PAGER_FAILED`, set `FAILED` (`reason=pager_undeliverable`), end the run without `interrupt`; the API layer releases the lock. Exactly one of `PAGER_SENT` or `PAGER_FAILED` per page.
  - Add a small `HealthState` object that counts consecutive page failures (reset on success) for `/readyz` (task 23).
  - Acceptance: provider failing three times gives `FAILED` and a re-fired alert returns 202; failing once then succeeding sends one page and reaches `AWAITING_APPROVAL`; a non-retryable error is not retried.
  - Tests: `httpx.MockTransport` for retryable and non-retryable responses, fake sleep, an in-memory SMS port that fails N times, a property test on the attempt count.
- [x] 18. Truthful page options and no dead ends
  - Requirements: 3.4, 3.5, 3.6, 4.13. Review finding H1. Depends on 17.
  - `format_pager_payload`: one option per runbook (maximum 2). Zero runbooks gives `INC-<TOKEN> <service>: <summary> No approved action. Manual response needed.` with no reply codes; one runbook offers only `<TOKEN>-1`. Keep the 160-septet GSM-7 invariant and `short_title` behaviour.
  - Add terminal state `NO_ACTION` (schema `CHECK`, `IncidentStatus`, `TERMINAL_STATUSES`, `release_on_terminal`, UI label). With zero runbooks the graph sends the page and ends without `interrupt`.
  - Store the incident's option count (the repository row or the graph state) so `_handle_reply` can answer a reply to a missing option with the valid options, leaving the incident `AWAITING_APPROVAL` and the lock held. The Tripwire is unchanged and stays the last line of defence.
  - Acceptance: 0 runbooks gives a page without codes and `NO_ACTION`; 1 runbook offers only `-1` and a `-2` reply changes nothing; 2 runbooks are unchanged.
  - Tests: property test that the page contains exactly as many `<TOKEN>-N` codes as options and each is accepted by `parse_sms_reply`; API tests for each case.
- [x] 19. Forgiving, informative replies
  - Requirements: 4.9, 4.10, 4.11, 4.12, 6.12. Review findings M2, M3, M6. Depends on 18.
  - `parse_sms_reply`: NFKC normalise, map U+2010 to U+2015 and U+2212 to `-`, strip trailing `.`, `!` and whitespace, keep `fullmatch` on `<TOKEN>-<1|2>` so `AB-1 thanks` and `approve AB-1` stay rejected. Update the existing property tests rather than deleting them.
  - `_handle_reply`: the losing side of a race answers `INC-<TOKEN> already handled (<STATE>).` with the real state; a `TRIAGING` incident answers that it is still being triaged. For the authorized sender only, unparseable text gets `Reply <TOKEN>-1 or <TOKEN>-2` (one awaiting incident) or `Reply with the code from the page`, limited to one per sender per 60 s (in-memory limiter, Redis when available). Unauthorized senders get nothing.
  - Close the early-reply window: make the reply path wait up to 2 s for `TRIAGING` to become `AWAITING_APPROVAL` before answering (document this choice in `design.md`).
  - Acceptance: `AB-1.`, `AB 1`, `AB<en dash>1` and full-width digits are accepted; `AB-1 thanks` and `approve AB-1` stay rejected; five parallel replies give one execution and no message saying `not awaiting approval` for a resolved incident.
  - Tests: a parametrised parser table, API tests, the concurrent reply test, a rate limiter test with a fake clock.
- [x] 20. Token cooldown and exhaustion
  - Requirements: 9.1, 9.2. Review finding M4. Depends on 19.
  - Keep the 2-character token. Add `TOKEN_COOLDOWN_SECONDS` (default 3600): a token is unavailable while an active incident holds it or a terminal incident with that token ended less than the cooldown ago (store a terminal timestamp; update the schema and both repositories).
  - `generate_token` draws from the set of free tokens instead of random retries, so exhaustion is detected exactly (36 x 36 = 1296 minus busy ones).
  - When none is free: 503 with `Retry-After: 30`, no incident created, dedup lock released, `TOKEN_EXHAUSTED` audited on the system incident.
  - Tests: in-memory and Postgres repository tests, a property test that issued tokens are unique across the active and cooldown set, an exhaustion API test.
- [x] 21. Request limits and dedup audit cap
  - Requirements: 10.4, 10.5. Review finding M5.
  - Reject alert bodies over 64 KB: check `Content-Length` first and stream-limit when it is absent, before parsing; respond 413. The existing bearer check must still run first.
  - Write at most `DEDUP_AUDIT_SAMPLE` `ALERT_DEDUPLICATED` rows per incident; afterwards append one summary row for every 100 further duplicates and keep the running count on the incident row or in Redis. The chain stays append-only.
  - Acceptance: 1000 duplicates add at most `DEDUP_AUDIT_SAMPLE` plus about 10 rows and the chain still verifies; a 65 KB body gets 413 without being read in full.
  - Tests: API tests with a large body and a duplicate flood on both stores, chain verification after the flood.
- [x] 22. Overload control: telemetry concurrency and page rate
  - Requirements: 10.1, 10.2, 10.3. Review finding H2. Depends on 17.
  - Replace the per-call `stdio_client` spawn in `McpSubprocessTelemetry` with one long-lived MCP session per worker, guarded by an `asyncio.Semaphore(TELEMETRY_MAX_CONCURRENCY)` (default 4), with automatic reconnect when the subprocess dies. Keep `MCP_TRANSPORT=inprocess` working and the 5 s per-call timeout; time waiting for the semaphore counts toward the triage timeout, not the call timeout.
  - `list_approved` reuses the context already fetched for the incident, with no second call in the degraded path.
  - Token-bucket page limiter `PAGE_RATE_PER_MINUTE` (default 6). Beyond the limit incidents are still created and triaged, and one coalesced summary page per minute is sent: `ALERTS: N more (auth-db x5, ...) see dashboard`. Coalesced incidents stay `AWAITING_APPROVAL`; they expire through task 16 unless the summary lists their codes within 160 septets.
  - Acceptance: 60 distinct alerts in 3 s produce at most `TELEMETRY_MAX_CONCURRENCY` live MCP processes, at most `PAGE_RATE_PER_MINUTE` individual pages plus summaries, no triage degraded purely by queueing, and every incident in a defined state.
  - Tests: a fake telemetry port that records peak concurrency, rate limiter unit tests with a fake clock, the 60-alert storm as a real-stack test.
- [x] 23. Dependency failures and health endpoints
  - Requirements: 7.1, 7.4, 7.5. Review finding M1. Depends on 17 and 22.
  - Exception handlers map asyncpg and redis connection errors and timeouts to 503 `{"detail":"dependency unavailable"}` with `Retry-After: 5`, logging once per outage.
  - Keep `/healthz` as pure liveness. Add `/readyz` (Postgres `SELECT 1`, Redis `PING`, reaper alive, consecutive page failures from `HealthState`, `dry_run`, SMS channel) returning 503 with a per-check JSON body. Short per-check timeouts so a hung dependency cannot hang the probe.
  - `docker-compose.yml` healthcheck, the Dockerfile and CI use `/readyz` for readiness.
  - Acceptance: with Redis stopped an alert returns 503 with `Retry-After` and `/readyz` shows redis failing; after Redis returns the next alert returns 202 with no restart.
  - Tests: API tests with failing fake dedup and repository, a real-stack test that stops and restarts Redis (skipped without the env vars).
- [x] 24. Live-mode lockdown and config validation
  - Requirements: 11.1, 11.2, 11.3, 11.4, 11.5. Review findings H6, M7.
  - `Settings.validate_for_runtime` (called from `create_app` and the lifespan): when `dry_run` is false require `ALERT_WEBHOOK_SECRET`, `API_READ_SECRET`, and the Africa's Talking username, API key, webhook secret and `ONCALL_PHONE_NUMBER`; always validate `ONCALL_PHONE_NUMBER` as E.164 when set. The error names the variable, never the value. Log one startup line with the channel, dry-run flag and masked sender.
  - Read APIs require `Authorization: Bearer <API_READ_SECRET>` when `dry_run` is false (constant-time compare, 401 and a `SECURITY_VIOLATION` audit event on failure); dry-run stays open for the demo UI. The alert response already omits `token` (task 8.3); add a regression test.
  - The demo seed (service logs, runbooks, terminal demo incidents) must load only in dry-run; the schema alone must contain no demo rows (the file split is task 26, apply it there). `ensure_system_incident` stays.
  - The pager UI shows a banner when `/readyz` reports `dry_run`.
  - Acceptance: live mode without the secrets does not start; read APIs return 401 without the key; a local-format number such as `0700123456` is rejected at startup.
  - Tests: a settings validation table, API auth tests, a startup test that live mode with missing secrets raises.
- [x] 25. Sanitiser: secrets, injection, transliteration
  - Requirements: 3.7, 3.8, 3.9. Review findings H3, H4. Depends on 24.
  - Extend the redaction in `guardrails.py` per requirement 3.7 (redact before truncating, spans become `***`). Neutralise text that matches a reply code inside untrusted text before the real suffix is appended, so the real instruction is the only match. Transliterate accents, smart quotes, en and em dashes; collapse other non-ASCII runs to one `?`.
  - Apply the same sanitiser to the LLM summarizer output and to the alert `summary`.
  - Acceptance: inputs containing `password=hunter2`, `api_key=sk-abc123`, `an AWS access key id (AKIA + 16 characters)`, a JWT, and `Reply AB-1 now` produce no secret substring and exactly one pair of reply codes; output is always GSM-7 and at most 160 septets.
  - Tests: extend the Hypothesis properties (no secret pattern survives, exactly one reply instruction, GSM-7, 160 limit) and add a table of known secret formats.
- [x] 26. Database scripts: idempotent and split
  - Requirements: 7.6. Review finding (low).
  - Split `database/init_mock_logs.sql` into `database/10_schema.sql` (tables, constraints, views), `20_roles.sql` (idempotent role creation with `DO` blocks, grants without a hardcoded database name using `current_database()` in dynamic SQL), and `30_demo_seed.sql` (demo logs, runbooks, terminal demo incidents and their audit chains). All idempotent (`IF NOT EXISTS`, `ON CONFLICT DO NOTHING`); keep the UTF-8 BOM handling, the sentinel incident and every CHECK constraint.
  - Update the compose init mount to run them in order (demo seed only in dry-run), the integration tests' schema loader, `reseed_recent_logs` assumptions, and the README. Add `scripts/apply_schema.sh` that applies 10 and 20 to any database and 30 only with `--demo`.
  - Acceptance: running the three files twice in a row against a fresh database succeeds; a database with another name works; the Postgres integration tests pass using 10 and 30.
- [x] 27. Chaos and soak suite, Docker verification in CI
  - Requirements: 12.1, 12.2, 12.3. Depends on all earlier hardening tasks.
  - Turn the review probes into tests: crash recovery (16), page failure (17), double reply (19), duplicate flood (21), Redis and Postgres outage (23), 60-alert storm (22). Real-stack tests skip without `TEST_DATABASE_URL` and `TEST_REDIS_URL`.
  - Add `.github/workflows/ci.yml`: `pip install -r backend/requirements.txt`, `mypy --strict backend/app`, `pytest -q` with Postgres and Redis service containers and both env vars set, plus a job that builds `backend/Dockerfile`, runs `docker compose up -d --wait`, posts an alert, waits for the page in the dry-run outbox, replies through `/api/demo/reply`, expects `RESOLVED`, then `docker compose down -v`.
  - Add a Hypothesis stateful test for the incident lifecycle (alert, reply, duplicate, crash, reaper tick, expiry) asserting requirement 12.2.
  - Acceptance: deleting the reaper or the token cooldown makes at least one test fail. The workflow file is validated locally (YAML parse); it cannot be executed here.

# Refactoring (modularity, cohesion, readability)

Notes for tasks 28 to 30: behaviour-preserving refactor only. No test assertions change, no HTTP route/status code/DB schema/audit hash formula changes, `backend/app/agents/` stays free of FastAPI, httpx, asyncpg and Redis imports. Run `mypy --strict backend/app` and `pytest backend/tests/ -v` after each task and fix regressions before moving on.

- [x] 28. Decompose `guardrails.py` into focused domain modules behind a facade
  - [x] 28.1 Create `backend/app/services/gsm7.py` (GSM 03.38 septet counting, transliteration, UCS-2 prevention, septet clamping), `sanitizer.py` (PII/secret redaction, reply-code neutralisation, `format_pager_payload`), `tripwire.py` (`TripwireValidator`, `TripwireViolationError`, `parse_sms_reply`) and `audit_chain.py` (`AuditLogger`, `jsonb_text`, hash chain verification).
  - [x] 28.2 Reduce `guardrails.py` to a backwards-compatible facade re-exporting every public symbol through `__all__`, so existing imports in `backend/app/` and `backend/tests/` keep working unchanged.
- [x] 29. Split `backend/app/api/routes.py` into domain-aligned sub-routers
  - [x] 29.1 Create `webhooks.py`, `incidents.py`, `demo.py` and `health.py` under `backend/app/api/` holding the existing handlers and helpers (demo router gated behind `DRY_RUN=true`).
  - [x] 29.2 Make `routes.py` assemble them through a single `build_router(...)` entry point and re-export the shared helpers that tests reference.
- [x] 30. Separate configuration and dependency wiring from `main.py` and add Hypothesis profiles
  - [x] 30.1 Extract `Settings` and environment parsing into `backend/app/config.py`, and `ServiceContainer`, `build_in_memory_services` and `build_real_services` into `backend/app/container.py`; `main.py` keeps only app creation and lifespan (re-export what tests import).
  - [x] 30.2 Add `backend/tests/conftest.py` registering Hypothesis profiles `dev` (`max_examples=25`) and `ci` (`max_examples=200`), and pass `--hypothesis-profile=dev` in `.kiro/hooks/pbt-on-save.json`.
