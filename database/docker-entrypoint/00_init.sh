#!/bin/sh
# Postgres first-boot initialisation (mounted into /docker-entrypoint-initdb.d by docker-compose.yml).
# Applies 10_schema.sql and 20_roles.sql always, and 30_demo_seed.sql only when DEMO_SEED=true.
# The SQL files live in $PAGEMASTER_SQL_DIR (default /pagemaster-sql) so the image runner does not
# execute them on its own. POSIX sh. This file may be sourced by the image entrypoint, so it sets no
# shell options and reports failure through the function's return status.

pagemaster_apply() {
    echo "pagemaster init: applying $1"
    psql -v ON_ERROR_STOP=1 --no-psqlrc -U "$POSTGRES_USER" -d "$POSTGRES_DB" -f "$1"
}

pagemaster_init() {
    sql_dir="${PAGEMASTER_SQL_DIR:-/pagemaster-sql}"
    pagemaster_apply "$sql_dir/10_schema.sql" || return 1
    pagemaster_apply "$sql_dir/20_roles.sql" || return 1
    case "${DEMO_SEED:-false}" in
        true | TRUE | True | 1 | yes)
            pagemaster_apply "$sql_dir/30_demo_seed.sql" || return 1
            ;;
        *)
            echo "pagemaster init: DEMO_SEED is not true, skipping 30_demo_seed.sql"
            ;;
    esac
}

pagemaster_init
