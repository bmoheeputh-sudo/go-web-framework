#!/usr/bin/env bash
set -euo pipefail
source "$(dirname -- "${BASH_SOURCE[0]}")/common.sh"

[[ $# == 0 ]] || rehearsal_error 'setup takes no arguments'
rehearsal_require_local_postgres
for program in sudo migrate openssl; do
  command -v "$program" >/dev/null || rehearsal_error "$program is required"
done
for program in psql createdb; do
  [[ -x /usr/bin/$program ]] || rehearsal_error "/usr/bin/$program is required"
done
[[ ! -e $REHEARSAL_ENV_FILE && ! -L $REHEARSAL_ENV_FILE ]] || rehearsal_error 'local rehearsal environment file already exists; refusing to overwrite it'
[[ $(rehearsal_admin_sql 'SELECT 1') == 1 ]] || rehearsal_error 'sudo -u postgres cannot use the selected local Unix socket; run sudo -v first'
[[ $(rehearsal_database_exists) == 0 ]] || rehearsal_error 'rehearsal database already exists; refusing to overwrite or migrate it'
[[ $(rehearsal_admin_sql "SELECT count(*) FROM pg_roles WHERE rolname='go_web_app'") == 1 ]] || rehearsal_error 'existing go_web_app PostgreSQL role is required'

# The existing application role owns only this new database and its migration
# objects. It never receives cluster-wide CREATEDB or superuser privileges.
# Do not reuse ambient PGPASSWORD or credentials from the development .env.
rehearsal_password="${REHEARSAL_DB_PASSWORD:-}"
unset REHEARSAL_DB_PASSWORD
if [[ -z $rehearsal_password && -t 0 ]]; then
  IFS= read -r -s -p 'Existing go_web_app password for rehearsal migrations: ' rehearsal_password
  printf '\n' >&2
fi
[[ -n $rehearsal_password ]] || rehearsal_error 'supply REHEARSAL_DB_PASSWORD or enter it interactively before setup'

umask 077
marker="$(openssl rand -hex 16)"
key="$(openssl rand -base64 32 | tr -d '\n')"
[[ $marker =~ ^[0-9a-f]{32}$ && ${#key} == 44 ]] || rehearsal_error 'could not generate local rehearsal material'
# The initial existence check is for a useful error; noclobber closes the
# check-to-create race and refuses a newly created file or symlink.
set -C
cat > "$REHEARSAL_ENV_FILE" <<EOF
# Generated for the isolated rehearsal database. Git and Drive exclude .env.*.
# Edit only this file; never source the repository's existing .env into rehearsal.
AUTH_REHEARSAL_MARKER=$marker
APP_ENV=development
AUTH_PROVIDER=local_dev
AUTH_CONFIG_DEPLOYMENT=$REHEARSAL_DEPLOYMENT
AUTH_ACTIVATION_AFFINITY_MODE=single_instance
HTTP_ADDR=127.0.0.1:$REHEARSAL_BACKEND_PORT
APP_ORIGIN=http://127.0.0.1:$REHEARSAL_FRONTEND_PORT
AUTH_REHEARSAL_BACKEND_PORT=$REHEARSAL_BACKEND_PORT
AUTH_REHEARSAL_FRONTEND_PORT=$REHEARSAL_FRONTEND_PORT
LOCAL_DEV_SUBJECT=auth0-rehearsal-operator
LOCAL_DEV_EMAIL=rehearsal@example.invalid
LOCAL_DEV_DISPLAY_NAME='Rehearsal Operator'
RBAC_ENABLED=true
ENABLED_MODULES=
DB_HOST=127.0.0.1
DB_PORT=$REHEARSAL_PG_PORT
DB_NAME=$REHEARSAL_DB
DB_USER=go_web_app
# Set the existing go_web_app password locally, using shell quoting if needed.
DB_PASSWORD=
DB_SSLMODE=disable
AUTH_ENCRYPTION_KEY_ID=rehearsal-v1
AUTH_ENCRYPTION_KEY=$key
AUTH_ENCRYPTION_KEYS_JSON=
AUTH_RECOVERY_ENABLED=false
AUTH_RECOVERY_OPERATOR_ID=
AUTH_RECOVERY_AUTHORIZATION_KEY_ID=
AUTH_RECOVERY_AUTHORIZATION_KEY=
DEV_TLS_CERT_FILE=
DEV_TLS_KEY_FILE=
EOF
unset key
chmod 600 "$REHEARSAL_ENV_FILE"

# The postgres OS/database role creates the fixed database; the application
# role owns it so the existing golang-migrate wrapper can run without DDL on
# other databases. The default PUBLIC connect privilege is removed.
rehearsal_admin_command postgres /usr/bin/createdb -w --maintenance-db=postgres --template=template0 --owner=go_web_app "$REHEARSAL_DB"
rehearsal_admin_sql "COMMENT ON DATABASE $REHEARSAL_DB IS '$REHEARSAL_MARKER_PREFIX$marker'" >/dev/null
rehearsal_admin_sql "REVOKE ALL ON DATABASE $REHEARSAL_DB FROM PUBLIC" >/dev/null
rehearsal_admin_sql "GRANT CONNECT ON DATABASE $REHEARSAL_DB TO go_web_app" >/dev/null

# Run migrations as the owner through explicit loopback credentials. The
# wrapper keeps public.schema_migrations and refuses down/force operations.
env -i PATH="$PATH" PGHOST=127.0.0.1 PGPORT="$REHEARSAL_PG_PORT" \
  PGUSER=go_web_app PGPASSWORD="$rehearsal_password" PGDATABASE="$REHEARSAL_DB" \
  PGSSLMODE=disable PGCONNECT_TIMEOUT=5 \
  "$REHEARSAL_ROOT/scripts/migrate-framework.sh" up 7
unset rehearsal_password
rehearsal_verify_marker
version="$(rehearsal_db_sql "SELECT version::text || '|' || dirty::text FROM public.schema_migrations")"
[[ $version == '7|false' ]] || rehearsal_error 'migration journal is not at clean version 7'
printf 'Isolated rehearsal database created at clean migration 7.\nLocal configuration: %s (mode 600; never commit it).\nEdit DB_PASSWORD, then start the two loopback servers and run check.sh.\n' "$REHEARSAL_ENV_FILE"
