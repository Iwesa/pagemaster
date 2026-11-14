# Pagemaster

**Kiroween 2026 Submission — Category: Resurrection**  
**Demo Video:** [Watch the 3-minute walkthrough on YouTube](#) *(replace with your YouTube URL)*

Two-way incident response over SMS, reviving 1990s Motorola Advisor paging for modern cloud DevOps. A monitoring alert comes in, an agent triages it using read-only Model Context Protocol (MCP) telemetry, and a sanitized pager message of at most 160 ASCII characters goes to the on-call engineer. Nothing touches infrastructure until the engineer replies `<TOKEN>-1` or `<TOKEN>-2`. A deterministic Tripwire check then validates the target host and approved runbook before remediation runs.

## How It Works

1. **Atomic Ingestion & Deduplication:** `POST /webhooks/alerts` validates the payload, deduplicates it in Redis by `(service_name, error_code)` (`SET ... NX EX 300`), and starts a LangGraph run (`202 Accepted`). Duplicate active alerts return `200 OK` (`DEDUPLICATED`).
2. **Read-Only MCP Triage:** The triage worker queries recent error logs, service topology, and approved runbooks through a FastMCP server over `stdio`. If MCP is unreachable or exceeds 5 seconds, triage degrades gracefully with `confidence="DEGRADED"`.
3. **Supervisor Compression & PII Clamp:** The supervisor summarizes the root cause (via Gemini or OpenAI when an API key is configured, otherwise a deterministic fallback). `format_pager_payload` clamps the output to `<= 160` printable ASCII characters, prefixes `INC-<TOKEN>`, and strips emails, IPv4/IPv6 addresses, JWTs, and bearer tokens.
4. **Durable Human-in-the-Loop Gate:** The LangGraph workflow suspends via `interrupt()` in `AWAITING_APPROVAL`, persisting its checkpoint in PostgreSQL.
5. **Authenticated Two-Way SMS Reply:** Twilio posts the engineer's reply to `POST /webhooks/twilio/sms`. `X-Twilio-Signature` is verified before the request body is parsed (`403 Forbidden` and a `SECURITY_VIOLATION` audit record on failure).
6. **Deterministic Tripwire Isolation:** `TripwireValidator` verifies that `target_host == incident.service_name` and `action_id` exists in `v_approved_runbooks`. Any mismatch trips the circuit breaker (`BLOCKED_BY_TRIPWIRE`) and aborts execution.
7. **Four-Gate Resolution & Tamper-Evident Audit:** An incident transitions to `RESOLVED` only when `tripwire_check_passed`, `simulated_step_executed`, `confirmation_sms_sent`, and `audit_record_committed` are all `true`. Failed runs transition to `FAILED` and release the deduplication lock. Every state transition is appended to a SHA-256 hash-chained audit trail.

## Kiro Implementation & Property-Based Testing

Pagemaster was built using Kiro's spec-driven workflow, steering guardrails, and automated agent hooks under `.kiro/`:

* **Spec-Driven Development (`.kiro/specs/pagemaster-core/`):** Formalized EARS acceptance criteria (`requirements.md`), hexagonal component boundaries and correctness invariants (`design.md`), and wave-ordered execution tasks (`tasks.md`).
* **Steering Policies (`.kiro/steering/pagemaster-standards.md`):** Always-on rules enforcing zero framework/SDK imports inside `backend/app/agents/`, strict `mypy --strict` typing, `READ ONLY` SQL transactions, and `<= 160` ASCII pager invariants.
* **Agent Hooks (`.kiro/hooks/pbt-on-save.json`):** A `PostFileSave` hook that automatically executes the Hypothesis property-based test suite whenever agent, MCP, or guardrail modules are modified.
* **What Property-Based Testing Caught:** Running 200-example Hypothesis fuzzing (`backend/tests/test_properties.py`) uncovered and verified critical edge cases that standard unit tests missed:
  * **Log Timestamp vs. IPv6 False Positives:** Ensuring colon-delimited timestamps (`12:30:45`) and MAC-like IDs survive sanitization while genuine IPv6 addresses (`::1`, `2001:db8::...`, `fe80::...`) and multi-part JWTs are stripped without exceeding the 160-character budget.
  * **Postgres `jsonb::text` Hash Parity:** Matching PostgreSQL's exact key-ordering (`(byte_length, bytes)`) and float serialization rules in Python so SHA-256 audit chains verify identically across Python and SQL.
  * **Non-Tail Audit Deletion & Lock Release:** Verifying that tampering with or deleting any intermediate audit record invalidates the chain, and that partial execution failures transition to `FAILED` and release the Redis fingerprint lock rather than deadlocking future alerts.

## Safety Guardrails

* **Hexagonal Architecture:** `backend/app/agents/` imports no FastAPI, Twilio, `asyncpg`, or Redis libraries; all external I/O flows through typed `Protocol` ports.
* **Least-Privilege MCP Database Role:** MCP telemetry queries run inside `SET TRANSACTION READ ONLY` transactions as the restricted `mcp_reader` role with `SELECT` access limited to `v_recent_logs`, `v_service_topology`, and `v_approved_runbooks`.
* **Defense-in-Depth Outbound Check:** Both `format_pager_payload` and `TwilioSmsAdapter.send` independently enforce the 160-character ASCII and `INC-<TOKEN>` invariants before dispatch.
* **Webhook Authentication:** HMAC signature validation on `/webhooks/twilio/sms` and optional `ALERT_WEBHOOK_SECRET` bearer-token verification on `/webhooks/alerts`.

## Repository Layout

```text
.kiro/                  Specs (requirements, design, tasks), steering rules, and PostFileSave PBT hook
backend/app/agents/     LangGraph state machine and hexagonal port interfaces
backend/app/services/   Guardrails, Redis dedup, Twilio adapter, stores, MCP stdio client, LLM summarizer
backend/app/mcp/        FastMCP read-only telemetry server
backend/app/api/        FastAPI webhook and read/demo routes
backend/tests/          Pytest integration and Hypothesis property-based test suites
database/               PostgreSQL schema, read-only views, roles, and seed data
frontend/index.html     1990s Motorola Advisor retro LCD pager simulator
