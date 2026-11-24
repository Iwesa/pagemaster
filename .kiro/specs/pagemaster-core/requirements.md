# Requirements Document: Pagemaster Incident Response System

## Introduction
Pagemaster is an event-driven, two-way incident response system that triages cloud infrastructure alerts via a read-only Model Context Protocol (MCP) telemetry server, dispatches compressed single-SMS pager alerts (at most 160 GSM-7 septets) via Africa's Talking SMS, and executes verified remediation playbooks only after deterministic human-in-the-loop (HITL) SMS approval.

## Requirements

### Requirement 1: Alert Ingestion & Atomic Deduplication
**User Story:** As an on-call Site Reliability Engineer, I want incoming server alerts deduplicated atomically so that cascading failures do not flood my pager with duplicate messages.

#### Acceptance Criteria
1. WHEN a monitoring source submits a valid JSON alert payload to `POST /webhooks/alerts` THE SYSTEM SHALL validate the schema, persist a raw incident record, and return HTTP `202 Accepted` with an `incident_id`. The record SHALL hold a 2-character alphanumeric reply `token`, which SHALL NOT be returned to the alert source.
2. IF an alert with an identical `(service_name, error_code)` fingerprint arrives WHILE an active incident for that fingerprint is in `TRIAGING`, `AWAITING_APPROVAL`, or `EXECUTING` state THEN THE SYSTEM SHALL suppress duplicate agent execution, append the occurrence to the existing incident's audit log, and return HTTP `200 OK` with status `DEDUPLICATED`.
3. IF an incoming alert payload fails Pydantic schema validation THEN THE SYSTEM SHALL reject the request with HTTP `422 Unprocessable Entity` without invoking any LLM agent.

### Requirement 2: Read-Only MCP Telemetry Triage
**User Story:** As a Triage Agent, I want scoped read-only access to recent stack traces and service dependencies via MCP so that I can diagnose root causes without risking production data mutation.

#### Acceptance Criteria
1. WHEN an incident transitions to `TRIAGING` THE SYSTEM SHALL invoke the Triage Worker Agent connected to the `pagemaster-telemetry` MCP server to retrieve the last 15 minutes of error logs and service topology for the affected service.
2. WHILE executing any MCP database query THE SYSTEM SHALL enforce a PostgreSQL `READ ONLY` transaction and restrict queries to whitelisted views (`v_recent_logs`, `v_service_topology`, `v_approved_runbooks`).
3. IF the MCP server is unreachable or times out after 5 seconds THEN THE SYSTEM SHALL fall back to the raw alert payload metadata and mark the triage confidence as `DEGRADED` rather than crashing the workflow.
4. IF the MCP server returns zero rows from `v_recent_logs` for the affected service THEN THE SYSTEM SHALL mark the triage confidence as `DEGRADED` with reason `no recent logs in window`.
5. WHILE `DRY_RUN=true` THE SYSTEM SHALL refresh the demo log rows at startup and on `POST /api/demo/reseed` so that demo logs remain inside the 15-minute `v_recent_logs` window.

### Requirement 3: Supervisor Pager Compression & PII Guardrail
**User Story:** As an on-call engineer carrying a 160-character pager/SMS endpoint, I want concise, sanitized alerts with explicit numeric reply options so that I can assess severity and authorize action immediately.

#### Acceptance Criteria
1. WHEN the Triage Worker produces a root-cause diagnosis THE SYSTEM SHALL pass it to the Supervisor Agent to format a pager payload containing `INC-<TOKEN>`, service name, root cause summary, and two valid action codes each followed by a short runbook title, in the form `INC-<TOKEN> <service>: <summary>. <TOKEN>-1:<title1> <TOKEN>-2:<title2>`, so that the engineer knows what each reply will run.
2. THE SYSTEM SHALL guarantee that every generated pager payload is ASCII, costs at most 160 GSM 03.38 (GSM-7) septets so that it fits one SMS segment, never forces UCS-2 encoding, and contains zero raw IP addresses, email addresses, or API secrets. Characters in the GSM extension table (`^ { } \ [ ~ ] | €`) SHALL count as 2 septets, and characters outside GSM-7 (such as backticks and smart quotes) SHALL be transliterated or removed.
3. IF the Supervisor Agent's initial output exceeds 160 septets or triggers the PII regex/entropy filter THEN THE SYSTEM SHALL deterministically truncate and sanitize the summary before dispatch and record a `GUARDRAIL_CLAMPED` audit event.
4. THE SYSTEM SHALL list only reply options that exist: one `<TOKEN>-N` code and title per approved runbook, never more than two.
5. WHERE an incident has no approved runbook THE SYSTEM SHALL send `INC-<TOKEN> <service>: <summary> No approved action. Manual response needed.` without reply codes and SHALL move the incident to the terminal state `NO_ACTION` and release its fingerprint lock.
6. THE SYSTEM SHALL keep the 160-septet GSM-7 guarantee for every page variant, including the no-runbook and single-runbook pages.
7. THE SYSTEM SHALL also redact `key=value` and `key: value` secrets (password, passwd, secret, token, api_key, apikey, authorization), `sk-`, `ghp_`, and `xox` tokens, AWS access key ids, JWTs, and hexadecimal or base64 strings of 32 or more characters, and SHALL redact before truncating.
8. THE SYSTEM SHALL ensure that the pattern `[A-Z0-9]{2}-[12]` appears in a page only as the real reply instruction, neutralizing any such text that comes from an alert summary, a log line, or LLM output.
9. THE SYSTEM SHALL transliterate common non-ASCII characters (accents, smart quotes, en and em dashes) and replace any other run of non-ASCII characters with a single `?`, for alert summaries and LLM output alike.

### Requirement 4: Two-Way SMS Dispatch & Durable Human Approval Gate
**User Story:** As an on-call engineer, I want the system to pause before touching infrastructure until I reply with my incident action code via SMS.

#### Acceptance Criteria
1. WHEN a pager payload passes Supervisor validation THE SYSTEM SHALL dispatch the SMS via Africa's Talking (or local mock transport in `DRY_RUN=true` mode), persist the LangGraph checkpoint in PostgreSQL, and transition the incident state to `AWAITING_APPROVAL`.
2. WHEN Africa's Talking posts a reply to `POST /webhooks/africastalking/sms` THE SYSTEM SHALL verify the shared secret `AFRICASTALKING_WEBHOOK_SECRET` (constant-time comparison) before parsing the message body. The secret SHALL be read from the `X-Webhook-Secret` header, then from `Authorization: Bearer <secret>`; a `?secret=` query parameter SHALL be ignored unless `ALLOW_QUERY_SECRET=true`.
3. IF the webhook secret is invalid THEN THE SYSTEM SHALL reject the request with HTTP `403 Forbidden` and log a `SECURITY_VIOLATION` audit event.
4. IF the sender (`from`) of a reply, after canonicalization to E.164, does not equal `ONCALL_PHONE_NUMBER`, or the destination (`to`) does not equal the configured shortcode when one is set, THEN THE SYSTEM SHALL reject the request with HTTP `403 Forbidden`, log a `SECURITY_VIOLATION` audit event, and perform zero state changes.
5. WHEN Africa's Talking redelivers a reply with a message `id` that was already processed THE SYSTEM SHALL ignore the duplicate and perform zero additional state changes.
6. THE SYSTEM SHALL NOT expose an incident's reply `token` through `GET /api/incidents` or through audit payloads returned by `GET /api/incidents/{incident_id}/audit`.
7. WHEN a verified SMS body matches `<TOKEN>-1` or `<TOKEN>-2` for an incident in `AWAITING_APPROVAL` state THE SYSTEM SHALL resume the suspended LangGraph workflow with the selected action.
8. IF an SMS reply references an expired, unknown, or already-resolved `<TOKEN>` THEN THE SYSTEM SHALL reply with an informational SMS stating the incident is no longer active and perform zero infrastructure mutations.
9. THE SYSTEM SHALL normalize an inbound reply with Unicode NFKC, map the dash variants U+2010 to U+2015 and U+2212 to `-`, and ignore trailing `.`, `!`, and whitespace, before matching `<TOKEN>-<1|2>` against the full text. Any other leading or trailing text SHALL still be rejected.
10. WHEN the authorized sender sends text that does not parse THE SYSTEM SHALL answer `Reply <TOKEN>-1 or <TOKEN>-2` for the single awaiting incident, or `Reply with the code from the page` when several are awaiting, limited to one such answer per sender per 60 seconds. Unauthorized senders SHALL receive no reply.
11. WHEN a reply loses the approval race THE SYSTEM SHALL answer `INC-<TOKEN> already handled (<STATE>).` using the incident's real state.
12. WHEN a reply arrives while the incident is `TRIAGING` THE SYSTEM SHALL answer that the incident is still being triaged and SHALL NOT change state.
13. WHEN a reply names an option that does not exist for the incident THE SYSTEM SHALL answer with the valid options, keep the incident `AWAITING_APPROVAL`, and keep its fingerprint lock, without reaching the Tripwire.

### Requirement 5: Tripwire Verification & Audited Execution
**User Story:** As a security-conscious engineering lead, I want a deterministic Tripwire check before any remediation runs so that an agent cannot target an unauthorized host or execute unapproved commands.

#### Acceptance Criteria
1. WHEN the Execution Agent prepares a remediation action after human approval THE SYSTEM SHALL pass the target host, action ID, and incident token through a deterministic `TripwireValidator`.
2. IF the target host does not match the original incident's `service_name` OR the action ID is not currently approved for that `service_name` (the approved runbook source being queried again at execution time, not the list cached during triage) THEN THE SYSTEM SHALL trip the circuit breaker, transition the incident to `BLOCKED_BY_TRIPWIRE`, alert the operator, and abort execution.
3. WHEN the Tripwire check passes THE SYSTEM SHALL execute the simulated remediation step, send a confirmation SMS (`INC-<TOKEN> RESOLVED`), and commit an immutable hash-chained audit record.
4. THE SYSTEM SHALL transition an incident to `RESOLVED` only WHEN `tripwire_check_passed`, `simulated_step_executed`, `confirmation_sms_sent`, and `audit_record_committed` are all true, and SHALL apply that transition atomically.
5. IF any of `tripwire_check_passed`, `simulated_step_executed`, `confirmation_sms_sent`, or `audit_record_committed` is false or was never evaluated THEN THE SYSTEM SHALL NOT transition the incident to `RESOLVED`.
6. IF remediation or the workflow fails (the executor leaves any gating flag false, or the workflow raises an unhandled error) THEN THE SYSTEM SHALL append an audit event, transition the incident to `FAILED`, and release the fingerprint lock so a new alert for the same `(service_name, error_code)` starts a fresh incident.

### Requirement 6: Approval Expiry & Crash Reconciliation
**User Story:** As an on-call engineer, I want stale or orphaned incidents to close themselves so that a lost reply or a crashed process never blocks future alerts or allows a late approval.

#### Acceptance Criteria
1. WHEN an incident has been in `AWAITING_APPROVAL` for longer than `APPROVAL_TTL_SECONDS` THE SYSTEM SHALL transition it to `EXPIRED`, append an audit event, and release the fingerprint lock.
2. IF a reply arrives for an incident whose approval window has elapsed THEN THE SYSTEM SHALL treat it as expired, perform zero infrastructure mutations, and reply that the incident is no longer active.
3. WHILE the application is running THE SYSTEM SHALL run a background reaper that applies criterion 1 periodically.
4. WHEN the application starts THE SYSTEM SHALL transition every `TRIAGING` or `EXECUTING` incident whose `updated_at` is older than `INFLIGHT_STALE_SECONDS` (default 60, minimum 10) to `FAILED`, append an `INCIDENT_FAILED` audit event with reason `stale_inflight_reconciled`, and release its fingerprint lock. Fresh in-flight incidents (possibly owned by another live worker) SHALL NOT be touched.
5. THE SYSTEM SHALL treat `EXPIRED` as a terminal state that is excluded from the active-fingerprint and active-token uniqueness constraints.
6. WHERE a Redis leader lock is available THE SYSTEM SHALL take `pagemaster:reconcile_lock` (`NX`, 30 second TTL) before reconciling so that concurrently booting workers do not reconcile at the same time.
7. THE SYSTEM SHALL evaluate approval expiry against the PostgreSQL clock (`now()`), not the application clock, when a PostgreSQL repository is used, and SHALL expire a stale incident atomically before any LangGraph resume.
8. WHILE the application is running THE SYSTEM SHALL periodically move every incident that has been in `TRIAGING` for longer than `TRIAGE_TIMEOUT_SECONDS` (default 120) or in `EXECUTING` for longer than `EXECUTING_TIMEOUT_SECONDS` (default 120) to a terminal state with an audit event and a released fingerprint lock. A stale `TRIAGING` incident SHALL first be resumed from its checkpoint when one exists and SHALL become `FAILED` (reason `recovered_after_crash`) otherwise. A stale `EXECUTING` incident SHALL become `FAILED` (reason `execution_timeout`) and its remediation step SHALL NOT be re-run.
9. WHEN the system moves an incident to `FAILED` or `EXPIRED` by reconciliation or by the reaper THE SYSTEM SHALL send the on-call engineer `INC-<TOKEN> FAILED. Re-send the alert.` or `INC-<TOKEN> EXPIRED. No action taken.` respectively.
10. WHEN a reply arrives for an `EXPIRED` incident THE SYSTEM SHALL answer `INC-<TOKEN> expired. No action taken.` and SHALL NOT mutate any state.
11. THE SYSTEM SHALL apply every reaper and reconciliation transition as a compare-and-set on the incident state, so that a concurrent reply and a reaper cannot both succeed.
12. THE SYSTEM SHALL NOT drop a reply that arrives after the page was sent but before the incident state is `AWAITING_APPROVAL`.

### Requirement 7: Operability
**User Story:** As an operator, I want health checks and a locked-down default deployment so that the stack is safe to run outside a laptop.

#### Acceptance Criteria
1. THE SYSTEM SHALL expose `GET /healthz` returning HTTP `200` while the process is alive (liveness only, no dependency checks).
2. THE SYSTEM SHALL bind published Postgres and Redis ports to `127.0.0.1` only and require a password for Redis.
3. THE SYSTEM SHALL pin dependency versions in `backend/requirements.txt`.
4. WHEN Redis or PostgreSQL is unreachable THE SYSTEM SHALL answer API requests with HTTP `503` and `Retry-After: 5` instead of HTTP `500`, and SHALL log the outage once rather than once per request.
5. THE SYSTEM SHALL provide `GET /readyz`, which checks PostgreSQL, Redis, the background reaper, and the consecutive failed-page count, returns `503` with a per-check JSON body when any check fails, and reports `dry_run`. Docker healthchecks and CI SHALL use `/readyz` for readiness and `/healthz` for liveness only.
6. THE SYSTEM SHALL keep the database schema, roles, and demo seed in separate idempotent files (`database/10_schema.sql`, `20_roles.sql`, `30_demo_seed.sql`) that can be applied repeatedly and to any database name.

### Requirement 8: Page Delivery Reliability
**User Story:** As an on-call engineer, I want a failed page to be visible and retried so that a provider outage never leaves an incident silently waiting for a human who was never paged.

#### Acceptance Criteria
1. WHEN sending the page fails with a retryable error THE SYSTEM SHALL retry up to `PAGE_MAX_ATTEMPTS` (default 3) times with exponential backoff and jitter, and SHALL NOT retry non-retryable provider errors such as authentication failure or an invalid number.
2. IF every attempt fails THEN THE SYSTEM SHALL audit `PAGER_FAILED`, transition the incident to `FAILED` with reason `pager_undeliverable`, release its fingerprint lock, and SHALL NOT enter `AWAITING_APPROVAL`, so that a re-fired alert starts a new incident.
3. WHEN the page is sent THE SYSTEM SHALL audit exactly one `PAGER_SENT` and no `PAGER_FAILED` for that page.
4. THE SYSTEM SHALL track consecutive page failures and report the count through `/readyz`.

### Requirement 9: Token Safety
**User Story:** As an on-call engineer, I want a reply code never to be reused soon after it was issued so that a delayed reply cannot approve a different incident.

#### Acceptance Criteria
1. THE SYSTEM SHALL NOT issue a reply token that is held by an active incident or that belonged to an incident which became terminal less than `TOKEN_COOLDOWN_SECONDS` (default 3600) ago.
2. IF no token is free THEN THE SYSTEM SHALL answer `POST /webhooks/alerts` with HTTP `503` and `Retry-After`, create no incident, release the deduplication lock, and audit `TOKEN_EXHAUSTED` on the system incident.

### Requirement 10: Overload Control
**User Story:** As an operator, I want an alert storm to degrade predictably instead of exhausting the host or paging the engineer into numbness.

#### Acceptance Criteria
1. THE SYSTEM SHALL limit concurrent telemetry lookups to `TELEMETRY_MAX_CONCURRENCY` (default 4) and SHALL reuse one MCP session per worker instead of spawning one subprocess per lookup, reconnecting when it dies.
2. THE SYSTEM SHALL NOT perform a second telemetry call to obtain runbooks when the first call degraded.
3. THE SYSTEM SHALL send at most `PAGE_RATE_PER_MINUTE` (default 6) individual pages per minute, and for incidents beyond that limit SHALL still create and triage them and send one coalesced summary page per minute.
4. THE SYSTEM SHALL record at most `DEDUP_AUDIT_SAMPLE` (default 20) `ALERT_DEDUPLICATED` audit rows per incident, and afterwards append one summary row per 100 further duplicates, keeping the hash chain append-only.
5. THE SYSTEM SHALL reject an alert body larger than 64 KB with HTTP `413` before reading it fully.

### Requirement 11: Live-Mode Exposure Control
**User Story:** As a security-conscious operator, I want live mode to refuse unsafe configuration and to expose nothing without credentials.

#### Acceptance Criteria
1. WHEN `DRY_RUN=false` THE SYSTEM SHALL refuse to start unless `ALERT_WEBHOOK_SECRET`, `API_READ_SECRET`, and a fully configured Africa's Talking channel (username, API key, webhook secret, `ONCALL_PHONE_NUMBER`) are present, and the error SHALL name the missing variable but never print a value.
2. WHEN `DRY_RUN=false` THE SYSTEM SHALL require `Authorization: Bearer <API_READ_SECRET>` (constant-time comparison) on `GET /api/incidents` and `GET /api/incidents/{incident_id}/audit`, answer `401` with an audit event otherwise, and SHALL NOT contain demo data. While `DRY_RUN=true` the read APIs stay open for the demo UI.
3. THE SYSTEM SHALL NOT include the approval token in the alert response in any mode (see Requirement 4, criterion 6).
4. THE SYSTEM SHALL validate `ONCALL_PHONE_NUMBER` as E.164 at startup and refuse to start otherwise.
5. THE SYSTEM SHALL log one startup line with the SMS channel, the dry-run flag, and the masked authorized sender, and `/readyz` SHALL report `dry_run`.

### Requirement 12: Verification
**User Story:** As a maintainer, I want the failure scenarios found in review to stay covered by automated tests and CI.

#### Acceptance Criteria
1. THE SYSTEM SHALL ship automated tests for crash recovery, page failure, double reply, duplicate storm, dependency outage, and alert storm, with real-stack variants that skip when `TEST_DATABASE_URL` and `TEST_REDIS_URL` are unset.
2. THE SYSTEM SHALL ship a Hypothesis stateful test of the incident lifecycle asserting that every incident reaches a terminal state, `RESOLVED` requires all four gates, at most one execution happens per incident, and a lock is released on every terminal transition.
3. CI SHALL build the Docker image and run a compose smoke test (alert, reply through `/api/demo/reply`, `RESOLVED`).

### Not applicable to this build
A review finding (H5, Telegram group chats) concerns a Telegram channel that this build does not have. The equivalent control here is the E.164 sender and shortcode allowlist in Requirement 4, criteria 4 and 5. If a Telegram channel is added, it SHALL authorize on both the message sender id and the chat id and SHALL ignore group chats by default.