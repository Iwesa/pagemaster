-- Pagemaster roles and grants: restricted `mcp_reader` role with SELECT on the three views only.
-- Idempotent and database-name agnostic: grants target current_database() through dynamic SQL.
-- Run after 10_schema.sql, as a role that may create roles (the superuser in the compose init).
-- The initial mcp_reader password is a development default; the backend re-syncs it from
-- MCP_READER_PASSWORD at startup. Requirements: 2.2, 7.6.

BEGIN;

DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'mcp_reader') THEN
        CREATE ROLE mcp_reader WITH LOGIN PASSWORD 'mcp_reader_dev'
            NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOINHERIT;
    END IF;
END
$$;

-- Role settings are scoped to this database so other databases in the cluster are untouched.
DO $$
BEGIN
    EXECUTE format(
        'ALTER ROLE mcp_reader IN DATABASE %I SET default_transaction_read_only = on',
        current_database());
    EXECUTE format(
        'ALTER ROLE mcp_reader IN DATABASE %I SET statement_timeout = %L',
        current_database(), '5s');
END
$$;

REVOKE ALL ON ALL TABLES IN SCHEMA public FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM mcp_reader;
REVOKE CREATE ON SCHEMA public FROM PUBLIC;

DO $$
BEGIN
    EXECUTE format('REVOKE ALL ON DATABASE %I FROM PUBLIC', current_database());
    EXECUTE format('GRANT CONNECT ON DATABASE %I TO mcp_reader', current_database());
    -- Keep the role that applies this script able to connect after revoking PUBLIC.
    EXECUTE format('GRANT CONNECT ON DATABASE %I TO %I', current_database(), current_user);
    -- The compose application role; skipped when it does not exist.
    IF EXISTS (SELECT FROM pg_roles WHERE rolname = 'pagemaster') THEN
        EXECUTE format('GRANT CONNECT ON DATABASE %I TO %I', current_database(), 'pagemaster');
    END IF;
END
$$;

GRANT USAGE ON SCHEMA public TO mcp_reader;
GRANT SELECT ON v_recent_logs, v_service_topology, v_approved_runbooks TO mcp_reader;

COMMIT;
