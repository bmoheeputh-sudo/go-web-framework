#!/usr/bin/env bash
set -euo pipefail
source "$(dirname -- "${BASH_SOURCE[0]}")/common.sh"

[[ $# == 0 ]] || rehearsal_error 'setup takes no arguments'
rehearsal_require_local_postgres
for program in psql createdb migrate openssl; do
  command -v "$program" >/dev/null || rehearsal_error "$program is required"
done
[[ ! -e $REHEARSAL_ENV_FILE && ! -L $REHEARSAL_ENV_FILE ]] || rehearsal_error 'local rehearsal environment file already exists; refusing to overwrite it'
[[ $(rehearsal_database_exists) == 0 ]] || rehearsal_error 'rehearsal database already exists; refusing to overwrite or migrate it'
[[ $(rehearsal_admin_sql "SELECT count(*) FROM pg_roles WHERE rolname='go_web_app'") == 1 ]] || rehearsal_error 'existing go_web_app PostgreSQL role is required'

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
DB_PORT=${PGPORT:-5432}
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

# Creating a new fixed-name database never reads PGDATABASE from the caller.
createdb --maintenance-db=postgres --template=template0 "$REHEARSAL_DB"
rehearsal_admin_sql "COMMENT ON DATABASE $REHEARSAL_DB IS '$REHEARSAL_MARKER_PREFIX$marker'" >/dev/null
rehearsal_admin_sql "GRANT CONNECT ON DATABASE $REHEARSAL_DB TO go_web_app" >/dev/null

# The wrapper keeps public.schema_migrations and refuses down/force operations.
PGDATABASE="$REHEARSAL_DB" "$REHEARSAL_ROOT/scripts/migrate-framework.sh" up 7
rehearsal_verify_marker
version="$(PGDATABASE="$REHEARSAL_DB" psql -X -qAt -v ON_ERROR_STOP=1 -c "SELECT version::text || '|' || dirty::text FROM public.schema_migrations")"
[[ $version == '7|false' ]] || rehearsal_error 'migration journal is not at clean version 7'
printf 'Isolated rehearsal database created at clean migration 7.\nLocal configuration: %s (mode 600; never commit it).\nEdit DB_PASSWORD, then start the two loopback servers and run check.sh.\n' "$REHEARSAL_ENV_FILE"
