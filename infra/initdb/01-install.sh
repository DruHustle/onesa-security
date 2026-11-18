#!/bin/sh
# PostgreSQL official image invokes this only for a fresh, explicitly local DB volume.
set -eu
if [ -z "${APP_DB_PASSWORD:-}" ]; then echo 'APP_DB_PASSWORD required' >&2; exit 1; fi
psql -v ON_ERROR_STOP=1 -U postgres -d "$POSTGRES_DB" -v passwd="$APP_DB_PASSWORD" <<'SQL'
SELECT format('CREATE ROLE onesa_api LOGIN PASSWORD %L NOINHERIT NOBYPASSRLS', :'passwd') \gexec
SQL
psql -v ON_ERROR_STOP=1 -U postgres -d "$POSTGRES_DB" -f /schema/001_initial.sql
psql -v ON_ERROR_STOP=1 -U postgres -d "$POSTGRES_DB" -f /schema/002_findings_and_approvals.sql
psql -v ON_ERROR_STOP=1 -U postgres -d "$POSTGRES_DB" <<'SQL'
GRANT CONNECT ON DATABASE onesa_security TO onesa_api;
GRANT USAGE ON SCHEMA public TO onesa_api;
-- Local bootstrap only. Production revokes org/membership writes from this role.
GRANT SELECT, INSERT, UPDATE ON ALL TABLES IN SCHEMA public TO onesa_api;
-- Keep audit append-only for normal API role.
REVOKE UPDATE ON audit_entries FROM onesa_api;
SQL
