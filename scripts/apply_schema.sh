#!/bin/sh
# Apply the Pagemaster database scripts to any database.
set -eu

usage() {
    cat <<'EOF'
Usage: scripts/apply_schema.sh [--demo] [-h|--help]

Applies database/10_schema.sql and database/20_roles.sql to the target database.
With --demo it also applies database/30_demo_seed.sql (demo data; never use on a live database).
All scripts are idempotent, so the command can be repeated.

Target database:
  DATABASE_URL     libpq connection URI, for example postgresql://user:pass@host:5432/dbname
  PGHOST, PGPORT, PGUSER, PGPASSWORD, PGDATABASE   used when DATABASE_URL is not set

The connecting role must be able to create roles (20_roles.sql creates mcp_reader).
Databases created from the old init_mock_logs.sql first need
database/migrations/001_hardening_columns.sql.
EOF
}

demo=0
for arg in "$@"; do
    case "$arg" in
        --demo) demo=1 ;;
        -h | --help) usage; exit 0 ;;
        *) echo "unknown argument: $arg" >&2; usage >&2; exit 2 ;;
    esac
done

dir=$(CDPATH= cd -- "$(dirname -- "$0")/../database" && pwd)

apply() {
    echo "applying $1"
    if [ -n "${DATABASE_URL:-}" ]; then
        psql -v ON_ERROR_STOP=1 --no-psqlrc --dbname "$DATABASE_URL" -f "$dir/$1"
    else
        psql -v ON_ERROR_STOP=1 --no-psqlrc -f "$dir/$1"
    fi
}

apply 10_schema.sql
apply 20_roles.sql
if [ "$demo" -eq 1 ]; then
    apply 30_demo_seed.sql
fi
echo "done"
