#!/usr/bin/env bash
# Fixed rehearsal identity. Never accept a database name from CLI or .env input.
REHEARSAL_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
REHEARSAL_DB=go_web_framework_auth0_rehearsal
REHEARSAL_DEPLOYMENT=auth0-rehearsal-local
REHEARSAL_ENV_FILE="$REHEARSAL_ROOT/scripts/rehearsal/.env.rehearsal.local"
REHEARSAL_MARKER_PREFIX=gwf-auth0-rehearsal:v1:
REHEARSAL_BACKEND_PORT=18080
REHEARSAL_FRONTEND_PORT=15173
REHEARSAL_PG_SOCKET_DIR="${REHEARSAL_PG_SOCKET_DIR:-/var/run/postgresql}"
REHEARSAL_PG_PORT="${REHEARSAL_PG_PORT:-5432}"

rehearsal_error() { printf 'Rehearsal: %s\n' "$*" >&2; exit 1; }

rehearsal_require_local_postgres() {
  # Ignore every ambient PG* setting, including service files and PGDATABASE.
  # Only these rehearsal-specific settings select the local PostgreSQL server.
  [[ $REHEARSAL_PG_SOCKET_DIR == /* && -d $REHEARSAL_PG_SOCKET_DIR && ! -L $REHEARSAL_PG_SOCKET_DIR ]] || rehearsal_error 'REHEARSAL_PG_SOCKET_DIR must be an existing local directory, not a symlink'
  [[ $REHEARSAL_PG_PORT =~ ^[0-9]+$ && $REHEARSAL_PG_PORT -ge 1 && $REHEARSAL_PG_PORT -le 65535 ]] || rehearsal_error 'invalid REHEARSAL_PG_PORT'
  [[ -S $REHEARSAL_PG_SOCKET_DIR/.s.PGSQL.$REHEARSAL_PG_PORT ]] || rehearsal_error 'the selected local PostgreSQL Unix socket is unavailable'
}

rehearsal_admin_command() {
  local database="$1"
  shift
  [[ $database == postgres || $database == "$REHEARSAL_DB" ]] || rehearsal_error 'invalid administrative database target'
  # sudo is deliberately limited to PostgreSQL commands. env -i discards
  # PGHOST, PGUSER, PGPASSWORD, PGDATABASE, PGOPTIONS and service settings.
  sudo -n -u postgres -- env -i PATH=/usr/bin:/bin \
    PGHOST="$REHEARSAL_PG_SOCKET_DIR" PGPORT="$REHEARSAL_PG_PORT" \
    PGUSER=postgres PGDATABASE="$database" PGCONNECT_TIMEOUT=5 \
    "$@"
}

rehearsal_admin_sql() {
  rehearsal_admin_command postgres /usr/bin/psql -X -w -qAt -v ON_ERROR_STOP=1 -d postgres -c "$1"
}

rehearsal_db_sql() {
  rehearsal_admin_command "$REHEARSAL_DB" /usr/bin/psql -X -w -qAt -v ON_ERROR_STOP=1 -d "$REHEARSAL_DB" -c "$1"
}

rehearsal_database_exists() {
  rehearsal_admin_sql "SELECT count(*) FROM pg_database WHERE datname='$REHEARSAL_DB'"
}

rehearsal_file_marker() {
  [[ -f $REHEARSAL_ENV_FILE && ! -L $REHEARSAL_ENV_FILE ]] || rehearsal_error 'the local rehearsal environment file is missing or a symlink'
  local line marker
  [[ $(grep -c '^AUTH_REHEARSAL_MARKER=' "$REHEARSAL_ENV_FILE" || true) == 1 ]] || rehearsal_error 'the local rehearsal marker is missing or ambiguous'
  line="$(grep -E '^AUTH_REHEARSAL_MARKER=[0-9a-f]{32}$' "$REHEARSAL_ENV_FILE" || true)"
  marker="${line#AUTH_REHEARSAL_MARKER=}"
  [[ $marker =~ ^[0-9a-f]{32}$ ]] || rehearsal_error 'invalid local rehearsal marker'
  printf '%s' "$marker"
}

rehearsal_database_marker() {
  # Databases are shared objects; comments live in pg_shdescription.
  rehearsal_admin_sql "SELECT COALESCE(shobj_description(oid,'pg_database'),'') FROM pg_database WHERE datname='$REHEARSAL_DB'"
}

rehearsal_verify_marker() {
  local marker actual
  marker="$(rehearsal_file_marker)"
  actual="$(rehearsal_database_marker)"
  [[ $actual == "$REHEARSAL_MARKER_PREFIX$marker" ]] || rehearsal_error 'database marker does not match the locally generated rehearsal identity'
}
