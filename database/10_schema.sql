-- Pagemaster schema: tables, constraints, indexes, triggers and read-only views.
-- Idempotent: safe to run any number of times, in any database (no database name appears here).
-- Order: 10_schema.sql, 20_roles.sql, then optionally 30_demo_seed.sql (demo mode only).
-- Existing databases created before the hardening columns need
-- database/migrations/001_hardening_columns.sql first.
-- Requirements: 2.2 (read-only, whitelisted views), 5.2 (approved runbooks), 5.3-5.5 (audit, RESOLVED gating), 7.6.

BEGIN;

-- ---------------------------------------------------------------------------
-- Tables
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS incidents (
    incident_id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    token                   CHAR(2) NOT NULL CHECK (token ~ '^[A-Z0-9]{2}$'),
    service_name            TEXT NOT NULL,
    error_code              TEXT NOT NULL,
    fingerprint             TEXT GENERATED ALWAYS AS (service_name || ':' || error_code) STORED,
    state                   TEXT NOT NULL DEFAULT 'TRIAGING'
        CHECK (state IN ('TRIAGING', 'AWAITING_APPROVAL', 'EXECUTING', 'RESOLVED', 'BLOCKED_BY_TRIPWIRE', 'FAILED', 'EXPIRED', 'NO_ACTION')),
    raw_alert               JSONB NOT NULL DEFAULT '{}'::jsonb,
    -- Number of reply options on the page (0..2); NULL until the page is sent (Req 3.5).
    option_count            SMALLINT CHECK (option_count BETWEEN 0 AND 2),
    tripwire_check_passed   BOOLEAN NOT NULL DEFAULT FALSE,
    simulated_step_executed BOOLEAN NOT NULL DEFAULT FALSE,
    confirmation_sms_sent   BOOLEAN NOT NULL DEFAULT FALSE,
    audit_record_committed  BOOLEAN NOT NULL DEFAULT FALSE,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- When the incident last entered a terminal state (store clock); NULL while active (Req 9.1).
    -- A token stays unavailable for TOKEN_COOLDOWN_SECONDS after this moment.
    terminal_at             TIMESTAMPTZ,
    -- Alerts deduplicated onto this incident (Req 10.5); audit rows are sampled, this count is exact.
    duplicate_count         INTEGER NOT NULL DEFAULT 0 CHECK (duplicate_count >= 0),
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
-- Terminal states (RESOLVED, BLOCKED_BY_TRIPWIRE, FAILED, EXPIRED, NO_ACTION) are excluded so they free the fingerprint (Req 5.6).
CREATE UNIQUE INDEX IF NOT EXISTS uq_incidents_active_token
    ON incidents (token) WHERE state IN ('TRIAGING', 'AWAITING_APPROVAL', 'EXECUTING');
CREATE UNIQUE INDEX IF NOT EXISTS uq_incidents_active_fingerprint
    ON incidents (fingerprint) WHERE state IN ('TRIAGING', 'AWAITING_APPROVAL', 'EXECUTING');
CREATE INDEX IF NOT EXISTS ix_incidents_token ON incidents (token);
CREATE INDEX IF NOT EXISTS ix_incidents_terminal_at ON incidents (terminal_at) WHERE terminal_at IS NOT NULL;

CREATE TABLE IF NOT EXISTS service_logs (
    log_id       BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    service_name TEXT NOT NULL,
    level        TEXT NOT NULL CHECK (level IN ('DEBUG', 'INFO', 'WARN', 'ERROR', 'FATAL')),
    error_code   TEXT,
    message      TEXT NOT NULL,
    stack_trace  TEXT,
    logged_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS ix_service_logs_service_time ON service_logs (service_name, logged_at DESC);

CREATE TABLE IF NOT EXISTS approved_runbooks (
    action_id    TEXT PRIMARY KEY,
    service_name TEXT NOT NULL,
    title        TEXT NOT NULL,
    description  TEXT NOT NULL,
    is_active    BOOLEAN NOT NULL DEFAULT TRUE
);

-- Hash-chained, append-only audit log (Property 5). hash = hex SHA-256 over
-- prev_hash|incident_id|seq|event_type|payload::text. The first record of each
-- incident chain uses prev_hash = 64 zeros.
CREATE TABLE IF NOT EXISTS audit_trail (
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

CREATE OR REPLACE FUNCTION audit_trail_immutable() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'audit_trail is append-only';
END;
$$;

DROP TRIGGER IF EXISTS trg_audit_trail_no_update_delete ON audit_trail;
CREATE TRIGGER trg_audit_trail_no_update_delete
    BEFORE UPDATE OR DELETE ON audit_trail
    FOR EACH ROW EXECUTE FUNCTION audit_trail_immutable();

DROP TRIGGER IF EXISTS trg_audit_trail_no_truncate ON audit_trail;
CREATE TRIGGER trg_audit_trail_no_truncate
    BEFORE TRUNCATE ON audit_trail
    FOR EACH STATEMENT EXECUTE FUNCTION audit_trail_immutable();

-- ---------------------------------------------------------------------------
-- Whitelisted read-only views (Req 2.2)
-- ---------------------------------------------------------------------------

CREATE OR REPLACE VIEW v_recent_logs AS
SELECT log_id, service_name, level, error_code, message, stack_trace, logged_at
FROM service_logs
WHERE logged_at >= now() - INTERVAL '15 minutes'
  AND level IN ('WARN', 'ERROR', 'FATAL');

CREATE OR REPLACE VIEW v_service_topology AS
SELECT service_name, depends_on, tier
FROM (VALUES
    ('payment-gateway', 'auth-db',        'edge'),
    ('payment-gateway', 'ledger-worker',  'edge'),
    ('ledger-worker',   'auth-db',        'core'),
    ('auth-db',         NULL::text,       'data')
) AS t (service_name, depends_on, tier);

CREATE OR REPLACE VIEW v_approved_runbooks AS
SELECT action_id, service_name, title, description
FROM approved_runbooks
WHERE is_active;

COMMIT;
