# Pagemaster

Two-way incident response over SMS, reviving 1990s Motorola Advisor paging for modern cloud DevOps. A monitoring alert comes in, an agent triages it using read-only Model Context Protocol (MCP) telemetry, and a sanitized single-SMS pager message (at most 160 GSM-7 septets, with a short title for each reply option) goes to the on-call engineer. Nothing touches infrastructure until the engineer replies `<TOKEN>-1` or `<TOKEN>-2`. A deterministic Tripwire check then validates the target host and approved runbook before remediation runs.

## How It Works

1. **Atomic Ingestion & Deduplication:** `POST /webhooks/alerts` validates the payload, deduplicates it in Redis by `(service_name, error_code)` (`SET ... NX EX 300`), and starts a LangGraph run (`202 Accepted`). Duplicate active alerts return `200 OK` (`DEDUPLICATED`).
2. **Read-Only MCP Triage:** The triage worker queries recent error logs, service topology, and approved runbooks through a FastMCP server over `stdio`. If MCP is unreachable or exceeds 5 seconds, triage degrades gracefully with `confidence="DEGRADED"`.
3. **Supervisor Compression & PII Clamp:** The supervisor summarizes the root cause (via Gemini or OpenAI when an API key is configured, otherwise a deterministic fallback). `format_pager_payload` clamps the output to `<= 160` GSM-7 septets (ASCII only, no UCS-2 fallback), prefixes `INC-<TOKEN>`, and strips emails, IPv4/IPv6 addresses, JWTs, and bearer tokens.
4. **Durable Human-in-the-Loop Gate:** The LangGraph workflow suspends via `interrupt()` in `AWAITING_APPROVAL`, persisting its checkpoint in PostgreSQL. An approval that is not answered within `APPROVAL_TTL_SECONDS` becomes `EXPIRED`, and stale `TRIAGING`/`EXECUTING` incidents (not updated for `INFLIGHT_STALE_SECONDS`) are moved to `FAILED` on startup. Reconciliation leaves fresh in-flight incidents alone, so it is safe with multiple workers, and expiry is evaluated with the database clock.
5. **Authenticated Two-Way SMS Reply:** Africa's Talking posts the engineer's reply to `POST /webhooks/africastalking/sms`. The shared secret (`X-Webhook-Secret` header or `Authorization: Bearer`; `?secret=` is ignored unless `ALLOW_QUERY_SECRET=true`), the E.164 sender (must equal `ONCALL_PHONE_NUMBER`), the optional shortcode and the message `id` (idempotency) are all checked before any state change (`403 Forbidden` and a `SECURITY_VIOLATION` audit record on failure).
6. **Deterministic Tripwire Isolation:** `TripwireValidator` verifies that `target_host == incident.service_name` and that `action_id` is currently approved, re-querying the runbooks at execution time so a revocation after triage is honoured. Any mismatch trips the circuit breaker (`BLOCKED_BY_TRIPWIRE`) and aborts execution.
7. **Four-Gate Resolution & Tamper-Evident Audit:** An incident transitions to `RESOLVED` only when `tripwire_check_passed`, `simulated_step_executed`, `confirmation_sms_sent`, and `audit_record_committed` are all `true`. Failed runs transition to `FAILED` and release the deduplication lock. Every state transition is appended to a SHA-256 hash-chained audit trail.

## Kiro Implementation & Property-Based Testing

Pagemaster was built using Kiro's spec-driven workflow, steering guardrails, and automated agent hooks under `.kiro/`:

* **Spec-Driven Development (`.kiro/specs/pagemaster-core/`):** Formalized EARS acceptance criteria (`requirements.md`), hexagonal component boundaries and correctness invariants (`design.md`), and wave-ordered execution tasks (`tasks.md`).
* **Steering Policies (`.kiro/steering/pagemaster-standards.md`):** Always-on rules enforcing zero framework/SDK imports inside `backend/app/agents/`, strict `mypy --strict` typing, `READ ONLY` SQL transactions, and `<= 160` GSM-7 septet pager invariants.
* **Agent Hooks (`.kiro/hooks/pbt-on-save.json`):** A `PostFileSave` hook that automatically executes the Hypothesis property-based test suite whenever agent, MCP, or guardrail modules are modified.
* **What Property-Based Testing Caught:** Running 200-example Hypothesis fuzzing (`backend/tests/test_properties.py`) uncovered and verified critical edge cases that standard unit tests missed:
  * **Log Timestamp vs. IPv6 False Positives:** Ensuring colon-delimited timestamps (`12:30:45`) and MAC-like IDs survive sanitization while genuine IPv6 addresses (`::1`, `2001:db8::...`, `fe80::...`) and multi-part JWTs are stripped without exceeding the 160-character budget.
  * **Postgres `jsonb::text` Hash Parity:** Matching PostgreSQL's exact key-ordering (`(byte_length, bytes)`) and float serialization rules in Python so SHA-256 audit chains verify identically across Python and SQL.
  * **Non-Tail Audit Deletion & Lock Release:** Verifying that tampering with or deleting any intermediate audit record invalidates the chain, and that partial execution failures transition to `FAILED` and release the Redis fingerprint lock rather than deadlocking future alerts.

## Safety Guardrails

* **Hexagonal Architecture:** `backend/app/agents/` imports no FastAPI, SMS-provider, `asyncpg`, `httpx`, or Redis libraries; all external I/O flows through typed `Protocol` ports.
* **Least-Privilege MCP Database Role:** MCP telemetry queries run inside `SET TRANSACTION READ ONLY` transactions as the restricted `mcp_reader` role with `SELECT` access limited to `v_recent_logs`, `v_service_topology`, and `v_approved_runbooks`.
* **Defense-in-Depth Outbound Check:** Both `format_pager_payload` and `AfricasTalkingSmsAdapter.send` independently enforce the 160-septet GSM-7 and `INC-<TOKEN>` invariants before dispatch.
* **Webhook Authentication:** Shared-secret and E.164 sender allowlist on `/webhooks/africastalking/sms` (the reply token is never returned by the public API), and optional `ALERT_WEBHOOK_SECRET` bearer-token verification on `/webhooks/alerts`.

## Repository Layout

```text
.kiro/                  Specs (requirements, design, tasks), steering rules, and PostFileSave PBT hook
backend/app/agents/     LangGraph state machine and hexagonal port interfaces
backend/app/services/   Guardrails, Redis dedup, Africa's Talking adapter, stores, MCP stdio client, LLM summarizer
backend/app/mcp/        FastMCP read-only telemetry server
backend/app/api/        FastAPI webhook and read/demo routes
backend/tests/          Pytest integration and Hypothesis property-based test suites
database/               PostgreSQL scripts: 10_schema.sql, 20_roles.sql, 30_demo_seed.sql, migrations/
frontend/index.html     1990s Motorola Advisor retro LCD pager simulator

## Run with Docker

```
docker compose up --build
```

Open http://localhost:8000. With `DRY_RUN=true` (the default) no SMS is sent. The pager UI can trigger alerts and reply with `-1` / `-2` through demo endpoints that exist only in dry-run mode.

## Configuration

Copy `.env.example` to `.env` and fill in the values (`.env` is git-ignored).

**Live mode (`DRY_RUN=false`)** refuses to start unless `ALERT_WEBHOOK_SECRET`, `API_READ_SECRET`, `AFRICASTALKING_USERNAME`, `AFRICASTALKING_API_KEY`, `AFRICASTALKING_WEBHOOK_SECRET` and `ONCALL_PHONE_NUMBER` are set. The error lists variable names only. `ONCALL_PHONE_NUMBER` must be E.164 (`+254700123456`); a local format such as `0700123456` is rejected at startup. Live mode registers no demo routes and never loads demo seed data.

| Variable | Purpose | Default |
|---|---|---|
| `DRY_RUN` | Use the in-memory SMS outbox instead of Africa's Talking | `true` |
| `USE_IN_MEMORY` | In-memory stores and checkpointer, no Postgres or Redis | `false` |
| `MCP_TRANSPORT` | `stdio` (subprocess MCP server) or `inprocess` | `stdio` |
| `MCP_READER_DATABASE_URL` | DSN for the `mcp_reader` role | set in compose |
| `ALERT_WEBHOOK_SECRET` | Bearer token required on `/webhooks/alerts` | empty (off) |
| `API_READ_SECRET` | Bearer key for `GET /api/incidents` and `/api/incidents/{id}/audit`. Required when `DRY_RUN=false` (401 + `SECURITY_VIOLATION` audit without it); dry run stays open | empty |
| `GEMINI_API_KEY`, `OPENAI_API_KEY` | Enable the LLM summarizer | empty |
| `AFRICASTALKING_USERNAME`, `AFRICASTALKING_API_KEY` | Africa's Talking credentials (username `sandbox` selects the sandbox endpoint) | empty |
| `AFRICASTALKING_SHORTCODE` | Sender shortcode. When set, inbound `to` must match it | empty |
| `AFRICASTALKING_WEBHOOK_SECRET` | Shared secret for the inbound SMS webhook. Empty rejects all inbound SMS | empty |
| `ONCALL_PHONE_NUMBER` | On-call number in E.164. Pages go here and only replies from it are accepted | empty |
| `APPROVAL_TTL_SECONDS` | Seconds before a pending approval expires (`EXPIRED`) | `900` |
| `REAPER_INTERVAL_SECONDS` | Interval of the sweep that expires approvals | `30` |
| `INFLIGHT_STALE_SECONDS` | Startup reconciliation fails only `TRIAGING`/`EXECUTING` incidents not updated for this long (minimum 10), so a booting worker does not kill another worker's live runs | `60` |
| `TRIAGE_TIMEOUT_SECONDS` | The reaper resumes a `TRIAGING` incident older than this from its checkpoint, or marks it `FAILED` (`recovered_after_crash`) and texts `INC-<TOKEN> FAILED. Re-send the alert.` (minimum 10) | `120` |
| `EXECUTING_TIMEOUT_SECONDS` | The reaper marks an `EXECUTING` incident older than this `FAILED` (`execution_timeout`) without re-running remediation (minimum 10) | `120` |
| `TOKEN_COOLDOWN_SECONDS` | A 2-character incident token is not reissued while an active incident holds it, or until this many seconds after its incident reached a terminal state (store clock). When every token is busy, `POST /webhooks/alerts` returns `503` with `Retry-After: 30`, creates no incident and audits `TOKEN_EXHAUSTED` (minimum 0) | `3600` |
| `MAX_ALERT_BODY_BYTES` | Largest accepted `POST /webhooks/alerts` body. A larger `Content-Length` gets `413` without reading the body; a body without one is read in chunks and aborted with `413` once it exceeds the limit. The bearer check (`401`) runs first; a malformed `Content-Length` gets `400` (minimum 1) | `65536` |
| `DEDUP_AUDIT_SAMPLE` | `ALERT_DEDUPLICATED` audit rows kept per incident. Later duplicates are only counted (`incidents.duplicate_count`) and one `ALERT_DEDUPLICATED_SUMMARY` row (`{"duplicates": n}`) is appended per 100 more. The API still answers `200 DEDUPLICATED` (minimum 1) | `20` |

| `TELEMETRY_MAX_CONCURRENCY` | Telemetry lookups in flight at once. One long-lived MCP subprocess and session per worker serves them (respawned when it dies or a call hits a transport error); extra triages wait for a slot, and that wait counts toward the triage timeout, not the 5 s per-call timeout (minimum 1) | `4` |
| `PAGE_RATE_PER_MINUTE` | Individual pages allowed in any 60 s window. Over the limit, incidents are still created, triaged and left `AWAITING_APPROVAL` (audited `PAGER_COALESCED`), and at most one summary page per minute is sent: `ALERTS: N more (auth-db x5, ...) see dashboard`, with reply codes only when they fit in 160 septets; otherwise those incidents expire through `APPROVAL_TTL_SECONDS`. The limit is per worker (minimum 1) | `6` |
| `PAGE_FAILURE_READY_THRESHOLD` | Consecutive failed pages at which `/readyz` reports the `pager` check as failing (minimum 1) | `3` |
| `PAGE_MAX_ATTEMPTS` | Total attempts to send a page. Retryable provider errors (HTTP 5xx, 408, 429, transport errors, timeouts) back off 1 s, 2 s, 4 s with jitter; authentication and invalid-number errors are not retried. If every attempt fails the incident is audited `PAGER_FAILED`, ends `FAILED` (`pager_undeliverable`) and releases its fingerprint (minimum 1) | `3` |
| `ALLOW_QUERY_SECRET` | Also accept the webhook secret from the `?secret=` query parameter. Less secure: URLs appear in proxy and access logs | `false` |
| `REDIS_PASSWORD` | Redis `requirepass`; embedded in the backend `REDIS_URL` | `pagemaster_redis_dev` |
| `POSTGRES_PASSWORD`, `MCP_READER_PASSWORD` | Postgres and `mcp_reader` role passwords (`20_roles.sql` creates `mcp_reader` with the default `mcp_reader_dev`; the backend syncs `MCP_READER_PASSWORD` at startup) | `pagemaster_dev`, `mcp_reader_dev` |

## Database scripts

The scripts in `database/` are idempotent and contain no database name:

| File | Content |
|---|---|
| `10_schema.sql` | Tables, constraints, indexes, audit triggers, read-only views |
| `20_roles.sql` | `mcp_reader` role and grants (uses `current_database()`) |
| `30_demo_seed.sql` | Demo logs, runbooks, terminal demo incidents and audit chains. Demo only |

On first boot, compose runs `database/docker-entrypoint/00_init.sh`, which applies 10 and 20 and applies 30 only when `DEMO_SEED=true` (compose sets it from `DRY_RUN`, default `true`). Live mode therefore starts with no demo data. To apply the scripts to any other database:

```
DATABASE_URL=postgresql://user:pass@host:5432/dbname scripts/apply_schema.sh          # schema and roles
DATABASE_URL=postgresql://user:pass@host:5432/dbname scripts/apply_schema.sh --demo   # plus demo seed
```

`PG*` environment variables work when `DATABASE_URL` is unset. The connecting role must be allowed to create roles.

**Existing databases** created from the old `init_mock_logs.sql` lack `incidents.option_count`, `terminal_at`, `duplicate_count` and the `FAILED`/`EXPIRED`/`NO_ACTION` states in the `state` CHECK. Run `psql -v ON_ERROR_STOP=1 -f database/migrations/001_hardening_columns.sql` once (idempotent), then `10_schema.sql` and `20_roles.sql`. Compose only runs init scripts on an empty volume.

## Liveness and readiness
- `GET /healthz` is liveness only: it answers `200` while the process is up and checks no dependency. Use it to decide whether to restart the container.
- `GET /readyz` is readiness: `200` when every check passes, otherwise `503`, with a per-check body (never any error text):
  `{"status": "ok"|"unavailable", "dry_run": bool, "channel": "africastalking", "checks": {"postgres": {"ok": bool}, "redis": {"ok": bool}, "reaper": {"ok": bool}, "pager": {"ok": bool, "consecutive_failures": int}}}`.
  Postgres (`SELECT 1`) and Redis (`PING`) are probed concurrently with a 2 s limit each, so a hung dependency cannot hang the probe; with `USE_IN_MEMORY=true` they report `"mode": "in_memory"`. `reaper` fails when the background sweep has not ticked for 3 x `REAPER_INTERVAL_SECONDS`. `pager` fails at `PAGE_FAILURE_READY_THRESHOLD` consecutive failed pages. The Docker healthcheck (compose and `backend/Dockerfile`) uses `/readyz`.
- While Postgres or Redis is unreachable, API requests that need them answer `503 {"detail": "dependency unavailable"}` with `Retry-After: 5` instead of `500`. The outage is logged once, not per request, and the service recovers without a restart.
## Africa's Talking SMS

Inbound replies arrive at `POST /webhooks/africastalking/sms` as form fields `from`, `to`, `text`, `date`, `id` and `linkId`. The secret is read from the `X-Webhook-Secret` header, then from `Authorization: Bearer <secret>`, and compared in constant time (`hmac.compare_digest`). Requests without a valid secret are rejected (fail closed). The `?secret=` query parameter is ignored unless `ALLOW_QUERY_SECRET=true`. The alert response never contains the reply token; it only appears in the pager SMS.

To configure the callback in the Africa's Talking dashboard, open SMS, then SMS Callback URLs, then incoming messages, and enter `https://<your-host>/webhooks/africastalking/sms`. The server must be reachable from the internet, for example through a tunnel.

The dashboard callback URL cannot attach custom headers. With the default `ALLOW_QUERY_SECRET=false` you therefore have two options:

1. **Recommended:** route the callback through a reverse proxy or API gateway that injects the header. For example, with nginx:

   ```nginx
   location /webhooks/africastalking/sms {
       proxy_set_header X-Webhook-Secret "<AFRICASTALKING_WEBHOOK_SECRET>";
       proxy_pass http://backend:8000;
   }
   ```

   Anyone who can reach the proxy can then post to this endpoint without the secret, so the E.164 sender check is the remaining control. Restrict the location to Africa's Talking source IPs where possible.
2. **Explicit opt-in:** set `ALLOW_QUERY_SECRET=true` and use `https://<your-host>/webhooks/africastalking/sms?secret=<AFRICASTALKING_WEBHOOK_SECRET>`. This is less secure: the secret can appear in proxy and access logs. Rotate it regularly.

Sandbox: with `AFRICASTALKING_USERNAME=sandbox` the app uses the sandbox endpoint. Sandbox messages go to the simulator, not to a real phone, and you can send replies from the simulator to the callback URL.

The compose file publishes Postgres (5432) and Redis (6379) on `127.0.0.1` only; the backend port 8000 is published on all interfaces. It contains development passwords for Postgres, Redis and `mcp_reader`. Change them for anything beyond local use.

## Tests

```
pip install -r backend/requirements.txt
pytest backend/tests/ -v
mypy --strict backend/app
```

The suite runs without Postgres or Redis (the real-stack tests skip). The Hypothesis property tests cover the properties in `.kiro/specs/pagemaster-core/design.md`. `test_lifecycle_state_machine.py` is a stateful Hypothesis test of the incident lifecycle (about 30 s), and `test_chaos_scenarios.py` holds one named scenario per review probe (crash recovery, page failure, double reply, duplicate storm, dependency outage, alert storm) plus meta tests that fail when the reaper sweep or the token cooldown is removed.

### Real-stack tests

The tests that need real servers skip unless both variables are set. `TEST_DATABASE_URL` must belong to a role that may `CREATE DATABASE` (each test creates and drops a scratch database):

```
docker compose up -d postgres redis
export TEST_DATABASE_URL=postgresql://pagemaster:pagemaster_dev@127.0.0.1:5432/postgres
export TEST_REDIS_URL=redis://:pagemaster_redis_dev@127.0.0.1:6379/0
pytest backend/tests -v
```

(PowerShell: `$env:TEST_DATABASE_URL = "..."`.) `test_postgres_integration.py` and `test_real_stack.py` then run. The latter starts the app as a subprocess, kills it mid-triage and checks recovery, runs a 60-alert storm, and cuts and restores Postgres and Redis through a TCP proxy. Use the compose passwords of your `.env` if you changed them.

### CI

`.github/workflows/ci.yml` runs `mypy --strict backend/app` and `pytest backend/tests -q` against Postgres and Redis service containers, then builds `backend/Dockerfile`, starts the compose stack and runs `scripts/smoke_compose.sh` (alert, page in the dry-run outbox, reply through `/api/demo/reply`, `RESOLVED`). Run the smoke test locally against a started stack with `sh scripts/smoke_compose.sh` (`BASE_URL` and `ALERT_WEBHOOK_SECRET` are honoured).

## Status

The in-memory paths are tested. The Postgres checkpointer, Redis adapter, live Africa's Talking sending and the Docker image have not been exercised end to end.

## License

MIT