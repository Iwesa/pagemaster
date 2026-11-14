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

### Requirement 4: Two-Way SMS Dispatch & Durable Human Approval Gate
**User Story:** As an on-call engineer, I want the system to pause before touching infrastructure until I reply with my incident action code via SMS.

#### Acceptance Criteria
1. WHEN a pager payload passes Supervisor validation THE SYSTEM SHALL dispatch the SMS via Africa's Talking (or local mock transport in `DRY_RUN=true` mode), persist the LangGraph checkpoint in PostgreSQL, and transition the incident state to `AWAITING_APPROVAL`.
2. WHEN Africa's Talking posts a reply to `POST /webhooks/africastalking/sms` THE SYSTEM SHALL verify the shared secret `AFRICASTALKING_WEBHOOK_SECRET` (constant-time comparison) before parsing the message body.
3. IF the webhook secret is invalid THEN THE SYSTEM SHALL reject the request with HTTP `403 Forbidden` and log a `SECURITY_VIOLATION` audit event.
4. IF the sender (`from`) of a reply, after canonicalization to E.164, does not equal `ONCALL_PHONE_NUMBER`, or the destination (`to`) does not equal the configured shortcode when one is set, THEN THE SYSTEM SHALL reject the request with HTTP `403 Forbidden`, log a `SECURITY_VIOLATION` audit event, and perform zero state changes.
5. WHEN Africa's Talking redelivers a reply with a message `id` that was already processed THE SYSTEM SHALL ignore the duplicate and perform zero additional state changes.
6. THE SYSTEM SHALL NOT expose an incident's reply `token` through `GET /api/incidents` or through audit payloads returned by `GET /api/incidents/{incident_id}/audit`.
7. WHEN a verified SMS body matches `<TOKEN>-1` or `<TOKEN>-2` for an incident in `AWAITING_APPROVAL` state THE SYSTEM SHALL resume the suspended LangGraph workflow with the selected action.
8. IF an SMS reply references an expired, unknown, or already-resolved `<TOKEN>` THEN THE SYSTEM SHALL reply with an informational SMS stating the incident is no longer active and perform zero infrastructure mutations.

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
4. WHEN the application starts THE SYSTEM SHALL transition every orphaned `TRIAGING` or `EXECUTING` incident to `FAILED`, append an audit event, and release its fingerprint lock.
5. THE SYSTEM SHALL treat `EXPIRED` as a terminal state that is excluded from the active-fingerprint and active-token uniqueness constraints.

### Requirement 7: Operability
**User Story:** As an operator, I want health checks and a locked-down default deployment so that the stack is safe to run outside a laptop.

#### Acceptance Criteria
1. THE SYSTEM SHALL expose `GET /healthz` returning HTTP `200` when the service is ready, and the `backend` container SHALL declare a Docker healthcheck that uses it.
2. THE SYSTEM SHALL bind published Postgres and Redis ports to `127.0.0.1` only and require a password for Redis.
3. THE SYSTEM SHALL pin dependency versions in `backend/requirements.txt`.
