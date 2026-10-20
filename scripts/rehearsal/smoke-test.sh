#!/usr/bin/env bash
# Exercises the operator scripts only against a socket-only disposable cluster.
set -euo pipefail
source "$(dirname -- "${BASH_SOURCE[0]}")/common.sh"

[[ $# == 0 ]] || rehearsal_error 'smoke-test takes no arguments'
[[ ! -e $REHEARSAL_ENV_FILE && ! -L $REHEARSAL_ENV_FILE ]] || rehearsal_error 'refusing to test while a local rehearsal configuration exists'
bin="${PG_TEST_BIN:-/usr/lib/postgresql/14/bin}"
[[ -x $bin/initdb && -x $bin/pg_ctl ]] || rehearsal_error 'PostgreSQL test binaries are required (set PG_TEST_BIN)'
directory="$(mktemp -d -t gwf-auth0-rehearsal-test-XXXXXXXX)"
chmod 700 "$directory"
port="$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()')"
started=false
marker=''
finish() {
  # The file did not exist when this test began. Clean it even if setup failed
  # before returning a marker, but only after checking its fixed DB identity.
  if [[ -f $REHEARSAL_ENV_FILE && ! -L $REHEARSAL_ENV_FILE ]] &&
    grep -qx "DB_NAME=$REHEARSAL_DB" "$REHEARSAL_ENV_FILE" &&
    grep -Eq '^AUTH_REHEARSAL_MARKER=[0-9a-f]{32}$' "$REHEARSAL_ENV_FILE"; then
    rm -- "$REHEARSAL_ENV_FILE"
  fi
  if $started; then
    "$bin/pg_ctl" -D "$directory/data" -m immediate -w stop >/dev/null 2>&1 || true
  fi
  rm -rf -- "$directory"
}
trap finish EXIT

mkdir "$directory/bin"
cat > "$directory/bin/sudo" <<'EOF'
#!/usr/bin/env bash
# Disposable cluster: simulate only the sudo command boundary. The postgres
# SQL role is reached through the isolated test socket, not the host cluster.
[[ ${1:-} == -n && ${2:-} == -u && ${3:-} == postgres && ${4:-} == -- ]] || exit 2
shift 4
exec "$@"
EOF
chmod 700 "$directory/bin/sudo"
export PATH="$directory/bin:$PATH"

"$bin/initdb" -D "$directory/data" -U postgres -A trust --no-locale -E UTF8 >/dev/null
if ! "$bin/pg_ctl" -D "$directory/data" -l "$directory/postgres.log" -w -t 10 \
  -o "-F -c listen_addresses=127.0.0.1 -p $port -c unix_socket_permissions=0700 -k $directory" start >/dev/null; then
  cat "$directory/postgres.log" >&2
  rehearsal_error 'disposable PostgreSQL cluster could not start'
fi
started=true
export REHEARSAL_PG_SOCKET_DIR="$directory" REHEARSAL_PG_PORT="$port" REHEARSAL_DB_PASSWORD=disposable-test-password
rehearsal_admin_sql 'CREATE ROLE go_web_app LOGIN' >/dev/null
# A disposable namesake of the normal development database must survive.
rehearsal_admin_command postgres /usr/bin/createdb -w --maintenance-db=postgres go_web_framework
rehearsal_admin_command postgres /usr/bin/psql -X -w -q -v ON_ERROR_STOP=1 -d go_web_framework -c 'CREATE TABLE rehearsal_sentinel(value text NOT NULL); INSERT INTO rehearsal_sentinel VALUES ('\''untouched'\'')' >/dev/null

# All ambient libpq settings point away from the test cluster. Rehearsal
# scripts must ignore them and use only their fixed database/socket choices.
export PGHOST=/tmp/not-the-rehearsal-socket PGHOSTADDR=203.0.113.1 PGPORT=1
export PGUSER=go_web_app PGPASSWORD=wrong-password PGDATABASE=go_web_framework
export PGSERVICE=not-a-rehearsal-service

if env -u REHEARSAL_DB_PASSWORD "$REHEARSAL_ROOT/scripts/rehearsal/setup.sh" </dev/null >"$directory/ambient-password.out" 2>&1; then
  rehearsal_error 'setup accepted an ambient PGPASSWORD as the rehearsal migration credential'
fi
[[ $(rehearsal_database_exists) == 0 && ! -e $REHEARSAL_ENV_FILE ]] || rehearsal_error 'missing explicit migration credentials created rehearsal resources'

"$REHEARSAL_ROOT/scripts/rehearsal/setup.sh" >/dev/null
marker="$(rehearsal_file_marker)"
[[ $(stat -c '%a' "$REHEARSAL_ENV_FILE") == 600 ]] || rehearsal_error 'generated local configuration is not mode 600'
[[ $(stat -c '%u' "$REHEARSAL_ENV_FILE") == "$(id -u)" ]] || rehearsal_error 'generated configuration is not owned by the invoking user'
rehearsal_verify_marker
app_marker="$(env -i PATH=/usr/bin:/bin PGHOST=127.0.0.1 PGPORT="$port" PGUSER=go_web_app PGDATABASE="$REHEARSAL_DB" PGPASSWORD=disposable-test-password /usr/bin/psql -X -w -qAt -v ON_ERROR_STOP=1 -c "SELECT COALESCE(shobj_description(oid,'pg_database'),'') FROM pg_database WHERE datname=current_database()")"
[[ $app_marker == "$REHEARSAL_MARKER_PREFIX$marker" ]] || rehearsal_error 'application role cannot verify rehearsal database marker'
owner="$(rehearsal_admin_sql "SELECT pg_get_userbyid(datdba) FROM pg_database WHERE datname='$REHEARSAL_DB'")"
[[ $owner == go_web_app ]] || rehearsal_error 'rehearsal database is not owned by the application role'
privileges="$(rehearsal_admin_sql "SELECT rolcreatedb::text || '|' || rolsuper::text FROM pg_roles WHERE rolname='go_web_app'")"
[[ $privileges == 'false|false' ]] || rehearsal_error 'application role acquired cluster-wide database privileges'
version="$(rehearsal_db_sql "SELECT version::text || '|' || dirty::text FROM public.schema_migrations")"
[[ $version == '7|false' ]] || rehearsal_error 'disposable migration journal is not clean version 7'
if "$REHEARSAL_ROOT/scripts/rehearsal/setup.sh" >"$directory/repeat.out" 2>&1; then
  rehearsal_error 'setup unexpectedly reused an existing rehearsal database'
fi
sed -i 's/^DB_PASSWORD=$/DB_PASSWORD=disposable-test-password/' "$REHEARSAL_ENV_FILE"
[[ $(stat -c '%a' "$REHEARSAL_ENV_FILE") == 600 ]] || rehearsal_error 'edited local configuration lost mode 600'
if "$REHEARSAL_ROOT/scripts/rehearsal/check.sh" >"$directory/check.out" 2>&1; then
  rehearsal_error 'readiness unexpectedly passed without backend, frontend or administrator bootstrap'
fi
if ! grep -q 'clean version 7' "$directory/check.out"; then
  rehearsal_error 'readiness did not recognize the isolated migration journal'
fi
if ! grep -q 'connected to the marked rehearsal database' "$directory/check.out"; then
  rehearsal_error 'readiness did not verify application-role connectivity under poisoned ambient PG settings'
fi

if printf 'NO\n' | "$REHEARSAL_ROOT/scripts/rehearsal/cleanup.sh" >"$directory/denied.out" 2>&1; then
  rehearsal_error 'cleanup accepted an incorrect confirmation'
fi
[[ $(rehearsal_database_exists) == 1 ]] || rehearsal_error 'incorrect confirmation removed the database'
rehearsal_admin_sql "COMMENT ON DATABASE $REHEARSAL_DB IS 'wrong-marker'" >/dev/null
if printf 'DROP REHEARSAL %s %s\n' "$REHEARSAL_DB" "$marker" | "$REHEARSAL_ROOT/scripts/rehearsal/cleanup.sh" >"$directory/marker-denied.out" 2>&1; then
  rehearsal_error 'cleanup accepted a mismatched database marker'
fi
[[ $(rehearsal_database_exists) == 1 ]] || rehearsal_error 'marker mismatch removed the database'
rehearsal_admin_sql "COMMENT ON DATABASE $REHEARSAL_DB IS '$REHEARSAL_MARKER_PREFIX$marker'" >/dev/null

printf 'DROP REHEARSAL %s %s\n' "$REHEARSAL_DB" "$marker" | "$REHEARSAL_ROOT/scripts/rehearsal/cleanup.sh" >/dev/null
[[ $(rehearsal_database_exists) == 0 && ! -e $REHEARSAL_ENV_FILE ]] || rehearsal_error 'guarded cleanup did not remove only the disposable resources'
sentinel="$(rehearsal_admin_command postgres /usr/bin/psql -X -w -qAt -v ON_ERROR_STOP=1 -d go_web_framework -c 'SELECT value FROM rehearsal_sentinel')"
[[ $sentinel == untouched ]] || rehearsal_error 'normal development database namesake was changed'
printf 'Disposable rehearsal setup, preflight refusal, and guarded cleanup passed.\n'
