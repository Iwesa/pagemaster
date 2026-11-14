# Pagemaster

Two-way incident response over SMS, reviving 1990s Motorola Advisor paging for modern cloud DevOps. A monitoring alert comes in, an agent triages it using read-only Model Context Protocol (MCP) telemetry, and a sanitized single-SMS pager message (at most 160 GSM-7 septets, with a short title for each reply option) goes to the on-call engineer. Nothing touches infrastructure until the engineer replies `<TOKEN>-1` or `<TOKEN>-2`. A deterministic Tripwire check then validates the target host and approved runbook before remediation runs.

## How It Works

1. **Atomic Ingestion & Deduplication:** `POST /webhooks/alerts` validates the payload, deduplicates it in Redis by `(service_name, error_code)` (`SET ... NX EX 300`), and starts a LangGraph run (`202 Accepted`). Duplicate active alerts return `200 OK` (`DEDUPLICATED`).
2. **Read-Only MCP Triage:** The triage worker queries recent error logs, service topology, and approved runbooks through a FastMCP server over `stdio`. If MCP is unreachable or exceeds 5 seconds, triage degrades gracefully with `confidence="DEGRADED"`.
3. **Supervisor Compression & PII Clamp:** The supervisor summarizes the root cause (via Gemini or OpenAI when an API key is configured, otherwise a deterministic fallback). `format_pager_payload` clamps the output to `<= 160` GSM-7 septets (ASCII only, no UCS-2 fallback), prefixes `INC-<TOKEN>`, and strips emails, IPv4/IPv6 addresses, JWTs, and bearer tokens.
4. **Durable Human-in-the-Loop Gate:** The LangGraph workflow suspends via `interrupt()` in `AWAITING_APPROVAL`, persisting its checkpoint in PostgreSQL. An approval that is not answered within `APPROVAL_TTL_SECONDS` becomes `EXPIRED`, and orphaned `TRIAGING`/`EXECUTING` incidents are moved to `FAILED` on startup.
5. **Authenticated Two-Way SMS Reply:** Africa's Talking posts the engineer's reply to `POST /webhooks/africastalking/sms`. The shared secret (`X-Webhook-Secret` header or `?secret=`), the E.164 sender (must equal `ONCALL_PHONE_NUMBER`), the optional shortcode and the message `id` (idempotency) are all checked before any state change (`403 Forbidden` and a `SECURITY_VIOLATION` audit record on failure).
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
database/               PostgreSQL schema, read-only views, roles, and seed data
frontend/index.html     1990s Motorola Advisor retro LCD pager simulator

## Run with Docker

```
docker compose up --build
```

Open http://localhost:8000. With `DRY_RUN=true` (the default) no SMS is sent. The pager UI can trigger alerts and reply with `-1` / `-2` through demo endpoints that exist only in dry-run mode.

## Configuration

| Variable | Purpose | Default |
|---|---|---|
| `DRY_RUN` | Use the in-memory SMS outbox instead of Africa's Talking | `true` |
| `USE_IN_MEMORY` | In-memory stores and checkpointer, no Postgres or Redis | `false` |
| `MCP_TRANSPORT` | `stdio` (subprocess MCP server) or `inprocess` | `stdio` |
| `MCP_READER_DATABASE_URL` | DSN for the `mcp_reader` role | set in compose |
| `ALERT_WEBHOOK_SECRET` | Bearer token required on `/webhooks/alerts` | empty (off) |
| `GEMINI_API_KEY`, `OPENAI_API_KEY` | Enable the LLM summarizer | empty |
| `AFRICASTALKING_USERNAME`, `AFRICASTALKING_API_KEY` | Africa's Talking credentials (username `sandbox` selects the sandbox endpoint) | empty |
| `AFRICASTALKING_SHORTCODE` | Sender shortcode. When set, inbound `to` must match it | empty |
| `AFRICASTALKING_WEBHOOK_SECRET` | Shared secret for the inbound SMS webhook. Empty rejects all inbound SMS | empty |
| `ONCALL_PHONE_NUMBER` | On-call number in E.164. Pages go here and only replies from it are accepted | empty |
| `APPROVAL_TTL_SECONDS` | Seconds before a pending approval expires (`EXPIRED`) | `900` |
| `REAPER_INTERVAL_SECONDS` | Interval of the sweep that expires approvals | `30` |
| `REDIS_PASSWORD` | Redis `requirepass`; embedded in the backend `REDIS_URL` | `pagemaster_redis_dev` |
| `POSTGRES_PASSWORD`, `MCP_READER_PASSWORD` | Postgres and `mcp_reader` role passwords (the latter must match `database/init_mock_logs.sql`) | `pagemaster_dev`, `mcp_reader_dev` |

## Africa's Talking SMS

Inbound replies arrive at `POST /webhooks/africastalking/sms` as form fields `from`, `to`, `text`, `date`, `id` and `linkId`. Send the secret in the `X-Webhook-Secret` header or the `?secret=` query parameter. The alert response never contains the reply token; it only appears in the pager SMS.

To configure the callback in the Africa's Talking dashboard, open SMS, then SMS Callback URLs, then incoming messages, and enter `https://<your-host>/webhooks/africastalking/sms?secret=<AFRICASTALKING_WEBHOOK_SECRET>`. The dashboard cannot set custom headers, so use the query parameter. The server must be reachable from the internet, for example through a tunnel.

Sandbox: with `AFRICASTALKING_USERNAME=sandbox` the app uses the sandbox endpoint. Sandbox messages go to the simulator, not to a real phone, and you can send replies from the simulator to the callback URL.

The compose file publishes Postgres (5432) and Redis (6379) on `127.0.0.1` only; the backend port 8000 is published on all interfaces. It contains development passwords for Postgres, Redis and `mcp_reader`. Change them for anything beyond local use.

## Tests

```
pip install -r backend/requirements.txt
pytest backend/tests/ -v
mypy --strict backend/app
```

The suite runs without Postgres or Redis. The Hypothesis property tests cover the properties in `.kiro/specs/pagemaster-core/design.md`. To run the Postgres integration tests, set `TEST_DATABASE_URL` to a server where the user can create databases.

## Status

The in-memory paths are tested. The Postgres checkpointer, Redis adapter, live Africa's Talking sending and the Docker image have not been exercised end to end.

## License

MIT