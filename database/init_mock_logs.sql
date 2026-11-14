-- Pagemaster mock telemetry + incident schema.
-- Runs once via /docker-entrypoint-initdb.d as the `pagemaster` superuser.
-- Requirements: 2.2 (read-only, whitelisted views), 5.2 (approved runbooks), 5.3-5.5 (audit, RESOLVED gating).

BEGIN;

-- ---------------------------------------------------------------------------
-- Tables
-- ---------------------------------------------------------------------------

CREATE TABLE incidents (
    incident_id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    token                   CHAR(2) NOT NULL CHECK (token ~ '^[A-Z0-9]{2}$'),
    service_name            TEXT NOT NULL,
    error_code              TEXT NOT NULL,
    fingerprint             TEXT GENERATED ALWAYS AS (service_name || ':' || error_code) STORED,
    state                   TEXT NOT NULL DEFAULT 'TRIAGING'
        CHECK (state IN ('TRIAGING', 'AWAITING_APPROVAL', 'EXECUTING', 'RESOLVED', 'BLOCKED_BY_TRIPWIRE', 'FAILED')),
    raw_alert               JSONB NOT NULL DEFAULT '{}'::jsonb,
    tripwire_check_passed   BOOLEAN NOT NULL DEFAULT FALSE,
    simulated_step_executed BOOLEAN NOT NULL DEFAULT FALSE,
    confirmation_sms_sent   BOOLEAN NOT NULL DEFAULT FALSE,
    audit_record_committed  BOOLEAN NOT NULL DEFAULT FALSE,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- Req 5.4 / 5.5: RESOLVED requires all four gating flags.
    CONSTRAINT resolved_requires_all_gates CHECK (
        state <> 'RESOLVED'
        OR (tripwire_check_passed
            AND simulated_step_executed
            AND confirmation_sms_sent
            AND audit_record_committed)
    )
);

-- Token must be unique among active incidents; fingerprint dedup (Req 1.2) is one active incident each.
-- Terminal states (RESOLVED, BLOCKED_BY_TRIPWIRE, FAILED) are excluded so they free the fingerprint (Req 5.6).
CREATE UNIQUE INDEX uq_incidents_active_token
    ON incidents (token) WHERE state IN ('TRIAGING', 'AWAITING_APPROVAL', 'EXECUTING');
CREATE UNIQUE INDEX uq_incidents_active_fingerprint
    ON incidents (fingerprint) WHERE state IN ('TRIAGING', 'AWAITING_APPROVAL', 'EXECUTING');
CREATE INDEX ix_incidents_token ON incidents (token);

CREATE TABLE service_logs (
    log_id       BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    service_name TEXT NOT NULL,
    level        TEXT NOT NULL CHECK (level IN ('DEBUG', 'INFO', 'WARN', 'ERROR', 'FATAL')),
    error_code   TEXT,
    message      TEXT NOT NULL,
    stack_trace  TEXT,
    logged_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX ix_service_logs_service_time ON service_logs (service_name, logged_at DESC);

CREATE TABLE approved_runbooks (
    action_id    TEXT PRIMARY KEY,
    service_name TEXT NOT NULL,
    title        TEXT NOT NULL,
    description  TEXT NOT NULL,
    is_active    BOOLEAN NOT NULL DEFAULT TRUE
);

-- Hash-chained, append-only audit log (Property 5). hash = hex SHA-256 over
-- prev_hash|incident_id|seq|event_type|payload::text. The first record of each
-- incident chain uses prev_hash = 64 zeros.
CREATE TABLE audit_trail (
    audit_id    BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    incident_id UUID NOT NULL REFERENCES incidents (incident_id),
    seq         INTEGER NOT NULL CHECK (seq >= 0),
    event_type  TEXT NOT NULL,
    payload     JSONB NOT NULL DEFAULT '{}'::jsonb,
    prev_hash   CHAR(64) NOT NULL CHECK (prev_hash ~ '^[0-9a-f]{64}$'),
    hash        CHAR(64) NOT NULL CHECK (hash ~ '^[0-9a-f]{64}$'),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (incident_id, seq),
    UNIQUE (hash)
);

CREATE FUNCTION audit_trail_immutable() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'audit_trail is append-only';
END;
$$;

CREATE TRIGGER trg_audit_trail_no_update_delete
    BEFORE UPDATE OR DELETE ON audit_trail
    FOR EACH ROW EXECUTE FUNCTION audit_trail_immutable();
CREATE TRIGGER trg_audit_trail_no_truncate
    BEFORE TRUNCATE ON audit_trail
    FOR EACH STATEMENT EXECUTE FUNCTION audit_trail_immutable();

-- ---------------------------------------------------------------------------
-- Whitelisted read-only views (Req 2.2)
-- ---------------------------------------------------------------------------

CREATE VIEW v_recent_logs AS
SELECT log_id, service_name, level, error_code, message, stack_trace, logged_at
FROM service_logs
WHERE logged_at >= now() - INTERVAL '15 minutes'
  AND level IN ('WARN', 'ERROR', 'FATAL');

CREATE VIEW v_service_topology AS
SELECT service_name, depends_on, tier
FROM (VALUES
    ('payment-gateway', 'auth-db',        'edge'),
    ('payment-gateway', 'ledger-worker',  'edge'),
    ('ledger-worker',   'auth-db',        'core'),
    ('auth-db',         NULL::text,       'data')
) AS t (service_name, depends_on, tier);

CREATE VIEW v_approved_runbooks AS
SELECT action_id, service_name, title, description
FROM approved_runbooks
WHERE is_active;

-- ---------------------------------------------------------------------------
-- Restricted MCP reader role: SELECT on the three views only.
-- Password must match MCP_READER_PASSWORD default in docker-compose.yml.
-- ---------------------------------------------------------------------------

CREATE ROLE mcp_reader WITH LOGIN PASSWORD 'mcp_reader_dev'
    NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOINHERIT;

ALTER ROLE mcp_reader SET default_transaction_read_only = on;
ALTER ROLE mcp_reader SET statement_timeout = '5s';

REVOKE ALL ON ALL TABLES IN SCHEMA public FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM mcp_reader;
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
REVOKE ALL ON DATABASE pagemaster FROM PUBLIC;

GRANT CONNECT ON DATABASE pagemaster TO mcp_reader;
GRANT USAGE ON SCHEMA public TO mcp_reader;
GRANT SELECT ON v_recent_logs, v_service_topology, v_approved_runbooks TO mcp_reader;

-- Keep the application owner able to connect after revoking PUBLIC.
GRANT CONNECT ON DATABASE pagemaster TO pagemaster;

-- ---------------------------------------------------------------------------
-- Seed data (timestamps relative to now())
-- ---------------------------------------------------------------------------

INSERT INTO approved_runbooks (action_id, service_name, title, description) VALUES
    ('RB-AUTHDB-RESET-POOL',    'auth-db',         'Reset connection pool',   'Terminate idle-in-transaction sessions and recycle the pgbouncer pool.'),
    ('RB-AUTHDB-FAILOVER',      'auth-db',         'Failover to replica',     'Promote the standby replica and repoint the primary DNS record.'),
    ('RB-PAYGW-RESTART',        'payment-gateway', 'Rolling restart',         'Rolling restart of payment-gateway pods, one at a time.'),
    ('RB-PAYGW-DRAIN-UPSTREAM', 'payment-gateway', 'Drain failing upstream',  'Remove the failing upstream from the load balancer rotation.'),
    ('RB-LEDGER-RESTART',       'ledger-worker',   'Restart ledger workers',  'Restart ledger-worker consumers after draining in-flight batches.'),
    ('RB-LEDGER-REPLAY-DLQ',    'ledger-worker',   'Replay dead-letter queue','Replay the dead-letter queue into the main ledger topic.');

INSERT INTO service_logs (service_name, level, error_code, message, stack_trace, logged_at) VALUES
    -- auth-db: connection pool exhaustion
    ('auth-db', 'INFO',  NULL,            'checkpoint complete: wrote 412 buffers (2.5%)', NULL, now() - INTERVAL '40 minutes'),
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
        E'ledger.errors.HeartbeatLost: worker-2\n  File "ledger/heartbeat.py", line 29, in beat', now() - INTERVAL '30 seconds');

-- Seed only terminal incidents. Active ones would hold the dedup fingerprint without a LangGraph
-- checkpoint, so demo alerts would be DEDUPLICATED and could never be resumed.
INSERT INTO incidents (incident_id, token, service_name, error_code, state, raw_alert,
                       tripwire_check_passed, simulated_step_executed, confirmation_sms_sent, audit_record_committed,
                       created_at, updated_at) VALUES
    ('00000000-0000-4000-8000-0000000000a4', 'Z1', 'auth-db',         'REPLICATION_LAG',     'RESOLVED',
        '{"source":"mock-monitor","severity":"high"}',     TRUE,  TRUE,  TRUE,  TRUE,  now() - INTERVAL '2 hours', now() - INTERVAL '110 minutes'),
    ('00000000-0000-4000-8000-0000000000a5', 'Q4', 'payment-gateway', 'DISK_FULL',           'BLOCKED_BY_TRIPWIRE',
        '{"source":"mock-monitor","severity":"high"}',     FALSE, FALSE, FALSE, FALSE, now() - INTERVAL '1 hour', now() - INTERVAL '58 minutes');

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
SELECT incident_id, seq, event_type, payload, prev_hash, hash, created_at FROM c1;

-- Blocked incident: record the tripwire event.
INSERT INTO audit_trail (incident_id, seq, event_type, payload, prev_hash, hash, created_at)
SELECT incident_id, 0, 'TRIPWIRE_BLOCKED', p, repeat('0', 64),
       encode(sha256(convert_to(repeat('0', 64) || '|' || incident_id::text || '|0|TRIPWIRE_BLOCKED|' || p::text, 'UTF8')), 'hex'),
       now() - INTERVAL '58 minutes'
FROM (SELECT '00000000-0000-4000-8000-0000000000a5'::uuid AS incident_id,
             '{"reason":"target_host_mismatch","target_host":"auth-db"}'::jsonb AS p) s;

COMMIT;
