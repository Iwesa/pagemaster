-- Pagemaster DEMO seed: runbooks, service logs, terminal demo incidents and hash-chained audit rows.
-- Demo mode only (DRY_RUN=true). Never apply to a live database (Req 11.2).
-- Idempotent: every INSERT is guarded by ON CONFLICT DO NOTHING or WHERE NOT EXISTS.
-- Timestamps are relative to now(); reseed_recent_logs() keeps logs inside the 15-minute window.
-- Run after 10_schema.sql.

BEGIN;

INSERT INTO approved_runbooks (action_id, service_name, title, description) VALUES
    ('RB-AUTHDB-RESET-POOL',    'auth-db',         'Reset connection pool',   'Terminate idle-in-transaction sessions and recycle the pgbouncer pool.'),
    ('RB-AUTHDB-FAILOVER',      'auth-db',         'Failover to replica',     'Promote the standby replica and repoint the primary DNS record.'),
    ('RB-PAYGW-RESTART',        'payment-gateway', 'Rolling restart',         'Rolling restart of payment-gateway pods, one at a time.'),
    ('RB-PAYGW-DRAIN-UPSTREAM', 'payment-gateway', 'Drain failing upstream',  'Remove the failing upstream from the load balancer rotation.'),
    ('RB-LEDGER-RESTART',       'ledger-worker',   'Restart ledger workers',  'Restart ledger-worker consumers after draining in-flight batches.'),
    ('RB-LEDGER-REPLAY-DLQ',    'ledger-worker',   'Replay dead-letter queue','Replay the dead-letter queue into the main ledger topic.')
ON CONFLICT (action_id) DO NOTHING;

-- A row is skipped when the same service and message already exist (logged_at is shifted by reseed).
INSERT INTO service_logs (service_name, level, error_code, message, stack_trace, logged_at)
SELECT v.service_name, v.level, v.error_code, v.message, v.stack_trace, v.logged_at
FROM (VALUES
    -- auth-db: connection pool exhaustion
    ('auth-db', 'INFO',  NULL::text,      'checkpoint complete: wrote 412 buffers (2.5%)', NULL::text, now() - INTERVAL '40 minutes'),
    ('auth-db', 'ERROR', 'DB_POOL_EXHAUSTED', 'FATAL: remaining connection slots are reserved for non-replication superuser connections (old, outside window)', NULL, now() - INTERVAL '20 minutes'),
    ('auth-db', 'WARN',  'DB_POOL_EXHAUSTED', 'pgbouncer: pool auth_main at 95/100 server connections', NULL, now() - INTERVAL '12 minutes'),
    ('auth-db', 'ERROR', 'DB_POOL_EXHAUSTED', 'FATAL: sorry, too many clients already',
        E'psycopg.OperationalError: connection failed: too many clients already\n  File "auth/session.py", line 88, in acquire\n  File "auth/pool.py", line 41, in get_conn', now() - INTERVAL '9 minutes'),
    ('auth-db', 'ERROR', 'DB_POOL_EXHAUSTED', 'idle in transaction sessions: 71 (oldest 842s) from client 10.20.4.17', NULL, now() - INTERVAL '6 minutes'),
    ('auth-db', 'FATAL', 'DB_POOL_EXHAUSTED', 'FATAL: too many connections for role "auth_svc"',
        E'psycopg.OperationalError: FATAL: too many connections for role "auth_svc"\n  File "auth/login.py", line 120, in verify_credentials', now() - INTERVAL '2 minutes'),

    -- payment-gateway: upstream timeouts caused by auth-db
    ('payment-gateway', 'INFO',  NULL,               'health check ok', NULL, now() - INTERVAL '30 minutes'),
    ('payment-gateway', 'WARN',  'UPSTREAM_TIMEOUT', 'auth-db token validation latency 4800ms (p99 threshold 800ms)', NULL, now() - INTERVAL '11 minutes'),
    ('payment-gateway', 'ERROR', 'UPSTREAM_TIMEOUT', 'POST /v1/charge failed: upstream auth timeout after 5000ms',
        E'httpx.ReadTimeout: timed out\n  File "gateway/auth_client.py", line 57, in validate_token\n  File "gateway/handlers/charge.py", line 33, in post_charge', now() - INTERVAL '8 minutes'),
    ('payment-gateway', 'ERROR', 'UPSTREAM_TIMEOUT', 'charge failed for user ops@example.com: upstream auth timeout (bearer eyJhbGciOiJIUzI1NiJ9.mock.sig)', NULL, now() - INTERVAL '5 minutes'),
    ('payment-gateway', 'FATAL', 'UPSTREAM_TIMEOUT', 'circuit breaker OPEN for dependency auth-db, rejecting 100% of /v1/charge',
        E'gateway.errors.CircuitOpen: auth-db\n  File "gateway/breaker.py", line 76, in call', now() - INTERVAL '1 minute'),

    -- ledger-worker: consumer lag / poison message
    ('ledger-worker', 'INFO',  NULL,                'batch 88213 committed (500 entries)', NULL, now() - INTERVAL '25 minutes'),
    ('ledger-worker', 'WARN',  'LEDGER_CONSUMER_LAG', 'consumer lag on topic ledger.entries: 12400 messages', NULL, now() - INTERVAL '13 minutes'),
    ('ledger-worker', 'ERROR', 'LEDGER_CONSUMER_LAG', 'failed to apply entry 7f3a: could not obtain auth-db connection',
        E'sqlalchemy.exc.OperationalError: too many clients already\n  File "ledger/apply.py", line 102, in apply_entry\n  File "ledger/worker.py", line 64, in run_batch', now() - INTERVAL '7 minutes'),
    ('ledger-worker', 'ERROR', 'LEDGER_CONSUMER_LAG', 'batch 88219 retry 3/3 exhausted, routing to dead-letter queue', NULL, now() - INTERVAL '4 minutes'),
    ('ledger-worker', 'FATAL', 'LEDGER_CONSUMER_LAG', 'consumer lag on topic ledger.entries: 58300 messages, worker heartbeat lost',
        E'ledger.errors.HeartbeatLost: worker-2\n  File "ledger/heartbeat.py", line 29, in beat', now() - INTERVAL '30 seconds')
) AS v (service_name, level, error_code, message, stack_trace, logged_at)
WHERE NOT EXISTS (
    SELECT 1 FROM service_logs s
    WHERE s.service_name = v.service_name AND s.message = v.message
);

-- Seed only terminal incidents. Active ones would hold the dedup fingerprint without a LangGraph
-- checkpoint, so demo alerts would be DEDUPLICATED and could never be resumed.
INSERT INTO incidents (incident_id, token, service_name, error_code, state, raw_alert,
                       tripwire_check_passed, simulated_step_executed, confirmation_sms_sent, audit_record_committed,
                       created_at, updated_at, terminal_at) VALUES
    ('00000000-0000-4000-8000-0000000000a4', 'Z1', 'auth-db',         'REPLICATION_LAG',     'RESOLVED',
        '{"source":"mock-monitor","severity":"high"}',     TRUE,  TRUE,  TRUE,  TRUE,  now() - INTERVAL '2 hours', now() - INTERVAL '110 minutes', now() - INTERVAL '110 minutes'),
    ('00000000-0000-4000-8000-0000000000a5', 'Q4', 'payment-gateway', 'DISK_FULL',           'BLOCKED_BY_TRIPWIRE',
        '{"source":"mock-monitor","severity":"high"}',     FALSE, FALSE, FALSE, FALSE, now() - INTERVAL '1 hour', now() - INTERVAL '58 minutes', now() - INTERVAL '58 minutes')
ON CONFLICT (incident_id) DO NOTHING;

-- Hash-chained audit trail for the resolved incident Z1.
INSERT INTO audit_trail (incident_id, seq, event_type, payload, prev_hash, hash, created_at)
WITH chain AS (
    SELECT
        '00000000-0000-4000-8000-0000000000a4'::uuid AS incident_id,
        0 AS seq, 'INCIDENT_CREATED' AS event_type,
        '{"service_name":"auth-db"}'::jsonb AS payload,
        repeat('0', 64) AS prev_hash,
        now() - INTERVAL '2 hours' AS created_at
), c0 AS (
    SELECT *, encode(sha256(convert_to(
        prev_hash || '|' || incident_id::text || '|' || seq || '|' || event_type || '|' || payload::text, 'UTF8')), 'hex') AS hash
    FROM chain
), n1 AS (
    SELECT incident_id, 1 AS seq, 'TRIPWIRE_PASSED' AS event_type,
           '{"action_id":"RB-AUTHDB-RESET-POOL"}'::jsonb AS payload,
           hash AS prev_hash, now() - INTERVAL '112 minutes' AS created_at
    FROM c0
), c1 AS (
    SELECT *, encode(sha256(convert_to(
        prev_hash || '|' || incident_id::text || '|' || seq || '|' || event_type || '|' || payload::text, 'UTF8')), 'hex') AS hash
    FROM n1
)
SELECT incident_id, seq, event_type, payload, prev_hash, hash, created_at FROM c0
UNION ALL
SELECT incident_id, seq, event_type, payload, prev_hash, hash, created_at FROM c1
ON CONFLICT DO NOTHING;

-- Blocked incident: record the tripwire event.
INSERT INTO audit_trail (incident_id, seq, event_type, payload, prev_hash, hash, created_at)
SELECT incident_id, 0, 'TRIPWIRE_BLOCKED', p, repeat('0', 64),
       encode(sha256(convert_to(repeat('0', 64) || '|' || incident_id::text || '|0|TRIPWIRE_BLOCKED|' || p::text, 'UTF8')), 'hex'),
       now() - INTERVAL '58 minutes'
FROM (SELECT '00000000-0000-4000-8000-0000000000a5'::uuid AS incident_id,
             '{"reason":"target_host_mismatch","target_host":"auth-db"}'::jsonb AS p) s
ON CONFLICT DO NOTHING;

COMMIT;
