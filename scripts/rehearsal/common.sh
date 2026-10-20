#!/usr/bin/env bash
# Fixed rehearsal identity. Never accept a database name from CLI or .env input.
REHEARSAL_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
REHEARSAL_DB=go_web_framework_auth0_rehearsal
REHEARSAL_DEPLOYMENT=auth0-rehearsal-local
REHEARSAL_ENV_FILE="$REHEARSAL_ROOT/scripts/rehearsal/.env.rehearsal.local"
REHEARSAL_MARKER_PREFIX=gwf-auth0-rehearsal:v1:
REHEARSAL_BACKEND_PORT=18080
REHEARSAL_FRONTEND_PORT=15173

rehearsal_error() { printf 'Rehearsal: %s\n' "$*" >&2; exit 1; }

rehearsal_require_local_postgres() {
  # A local Unix socket or literal loopback host is required. Never let a
  # service file or PGHOSTADDR silently redirect these commands elsewhere.
  [[ -z ${PGSERVICE:-} && -z ${PGSERVICEFILE:-} ]] || rehearsal_error 'PGSERVICE is unsupported; use an explicit local PostgreSQL connection'
  for host in "${PGHOST:-}" "${PGHOSTADDR:-}"; do
    case "$host" in
      ''|localhost|127.0.0.1|::1|/*) ;;
      *) rehearsal_error 'PostgreSQL must use a local Unix socket or loopback host' ;;
    esac
  done
  if [[ -n ${PGPORT:-} ]]; then
    [[ ${PGPORT} =~ ^[0-9]+$ && ${PGPORT} -ge 1 && ${PGPORT} -le 65535 ]] || rehearsal_error 'invalid PGPORT'
  fi
}

rehearsal_admin_sql() {
  psql -X -qAt -v ON_ERROR_STOP=1 -d postgres -c "$1"
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
