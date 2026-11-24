-- Optional, idempotent migration for databases created from the old init_mock_logs.sql.
-- Adds incidents.option_count, terminal_at, duplicate_count, re-creates the state CHECK with
-- the FAILED, EXPIRED and NO_ACTION states, and makes sure resolved_requires_all_gates exists.
-- Run it BEFORE 10_schema.sql on such a database. Fresh databases do not need it.

BEGIN;

ALTER TABLE incidents
    ADD COLUMN IF NOT EXISTS option_count SMALLINT CHECK (option_count BETWEEN 0 AND 2);
ALTER TABLE incidents
    ADD COLUMN IF NOT EXISTS terminal_at TIMESTAMPTZ;
ALTER TABLE incidents
    ADD COLUMN IF NOT EXISTS duplicate_count INTEGER NOT NULL DEFAULT 0 CHECK (duplicate_count >= 0);

UPDATE incidents
SET terminal_at = updated_at
WHERE terminal_at IS NULL
  AND state IN ('RESOLVED', 'BLOCKED_BY_TRIPWIRE', 'FAILED', 'EXPIRED', 'NO_ACTION');

ALTER TABLE incidents DROP CONSTRAINT IF EXISTS incidents_state_check;
ALTER TABLE incidents ADD CONSTRAINT incidents_state_check CHECK (
    state IN ('TRIAGING', 'AWAITING_APPROVAL', 'EXECUTING', 'RESOLVED', 'BLOCKED_BY_TRIPWIRE', 'FAILED', 'EXPIRED', 'NO_ACTION')
);

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT FROM pg_constraint
        WHERE conname = 'resolved_requires_all_gates' AND conrelid = 'incidents'::regclass
    ) THEN
        ALTER TABLE incidents ADD CONSTRAINT resolved_requires_all_gates CHECK (
            state <> 'RESOLVED'
            OR (tripwire_check_passed
                AND simulated_step_executed
                AND confirmation_sms_sent
                AND audit_record_committed)
        );
    END IF;
END
$$;

COMMIT;
