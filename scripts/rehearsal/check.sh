#!/usr/bin/env bash
# Read-only local preflight. It cannot prove Auth0's callback allowlist.
set -euo pipefail
source "$(dirname -- "${BASH_SOURCE[0]}")/common.sh"

[[ $# == 0 ]] || rehearsal_error 'check takes no arguments'
rehearsal_require_local_postgres
for program in sudo curl jq python3; do
  command -v "$program" >/dev/null || rehearsal_error "$program is required"
done
[[ -x /usr/bin/psql ]] || rehearsal_error '/usr/bin/psql is required'
[[ -f $REHEARSAL_ENV_FILE && ! -L $REHEARSAL_ENV_FILE ]] || rehearsal_error 'run setup.sh first'
rehearsal_verify_marker

# The fixed, generated file is local operator configuration. No caller-supplied
# path is evaluated, and its contents are never printed.
set -a
source "$REHEARSAL_ENV_FILE"
set +a
issues=0
check() { printf '%-34s %s\n' "$1" "$2"; }
problem() { check "$1" "$2"; issues=$((issues + 1)); }

[[ ${APP_ENV:-} == development && ${AUTH_PROVIDER:-} == local_dev && ${AUTH_CONFIG_DEPLOYMENT:-} == "$REHEARSAL_DEPLOYMENT" ]] || rehearsal_error 'trusted development authentication scope does not match rehearsal'
[[ ${DB_NAME:-} == "$REHEARSAL_DB" && ${DB_HOST:-} == 127.0.0.1 && ${DB_PORT:-} == "$REHEARSAL_PG_PORT" && ${DB_USER:-} == go_web_app && ${DB_SSLMODE:-} == disable ]] || rehearsal_error 'DB_* must point only to the fixed local rehearsal database'
[[ ${HTTP_ADDR:-} == "127.0.0.1:$REHEARSAL_BACKEND_PORT" && ${APP_ORIGIN:-} == "http://127.0.0.1:$REHEARSAL_FRONTEND_PORT" ]] || rehearsal_error 'rehearsal backend or browser origin does not match the loopback configuration'
[[ ${AUTH_REHEARSAL_BACKEND_PORT:-} == "$REHEARSAL_BACKEND_PORT" && ${AUTH_REHEARSAL_FRONTEND_PORT:-} == "$REHEARSAL_FRONTEND_PORT" ]] || rehearsal_error 'Vite proxy ports do not match the rehearsal listeners'
[[ ${AUTH_ACTIVATION_AFFINITY_MODE:-} == single_instance && ${RBAC_ENABLED:-} == true && -z ${ENABLED_MODULES:-} ]] || rehearsal_error 'single-instance affinity, RBAC and core-only modules are required'
[[ ${AUTH_REHEARSAL_MARKER:-} == "$(rehearsal_file_marker)" ]] || rehearsal_error 'local rehearsal marker changed'
[[ -n ${LOCAL_DEV_SUBJECT:-} && -n ${LOCAL_DEV_EMAIL:-} && -n ${LOCAL_DEV_DISPLAY_NAME:-} ]] || rehearsal_error 'fixed Local DEV identity is incomplete'
check 'Trusted scope and loopback origins' 'OK'

if python3 -c 'import base64, os, sys; s=os.environ.get("AUTH_ENCRYPTION_KEY", ""); b=base64.b64decode(s, validate=True); sys.exit(0 if len(b)==32 and base64.b64encode(b).decode()==s else 1)' 2>/dev/null && [[ -n ${AUTH_ENCRYPTION_KEY_ID:-} ]]; then
  check 'Rehearsal encryption key' 'valid (value hidden)'
else
  problem 'Rehearsal encryption key' 'invalid or missing'
fi

version="$(rehearsal_db_sql "SELECT version::text || '|' || dirty::text FROM public.schema_migrations" 2>/dev/null || true)"
if [[ $version == '7|false' ]]; then
  check 'PostgreSQL migration journal' 'clean version 7'
else
  problem 'PostgreSQL migration journal' 'missing, dirty or not version 7'
fi

if [[ -z ${DB_PASSWORD:-} ]]; then
  problem 'Application database credentials' 'DB_PASSWORD is not configured in the local rehearsal file'
else
  app_marker="$(env -i PATH=/usr/bin:/bin PGPASSWORD="$DB_PASSWORD" PGHOST="$DB_HOST" PGPORT="$DB_PORT" PGUSER="$DB_USER" PGDATABASE="$DB_NAME" PGSSLMODE=disable PGCONNECT_TIMEOUT=5 /usr/bin/psql -X -w -qAt -v ON_ERROR_STOP=1 -c "SELECT COALESCE(shobj_description(oid,'pg_database'),'') FROM pg_database WHERE datname=current_database()" 2>/dev/null || true)"
  if [[ $app_marker == "$REHEARSAL_MARKER_PREFIX$(rehearsal_file_marker)" ]]; then
    check 'Application database credentials' 'connected to the marked rehearsal database'
  else
    problem 'Application database credentials' 'unavailable or points to an unmarked database'
  fi
fi

head="$(rehearsal_db_sql "SELECT COALESCE((SELECT runtime_source || '|' || generation::text || '|' || COALESCE(active_revision_id::text,'') FROM framework.auth_activation_heads WHERE deployment_id='$REHEARSAL_DEPLOYMENT' AND environment='development'),'environment|0|')" 2>/dev/null || true)"
history="$(rehearsal_db_sql "SELECT count(*) FROM framework.auth_activation_history WHERE deployment_id='$REHEARSAL_DEPLOYMENT' AND environment='development'" 2>/dev/null || true)"
active="$(rehearsal_db_sql "SELECT count(*) FROM framework.auth_config_lifecycle WHERE deployment_id='$REHEARSAL_DEPLOYMENT' AND environment='development' AND status='active'" 2>/dev/null || true)"
other_database="$(rehearsal_db_sql "SELECT count(*) FROM framework.auth_activation_heads WHERE runtime_source='database' AND (deployment_id<>'$REHEARSAL_DEPLOYMENT' OR environment<>'development')" 2>/dev/null || true)"
if [[ $head == 'environment|0|' && $history == 0 && $active == 0 && $other_database == 0 ]]; then
  check 'Authoritative authentication' 'Local DEV eligible; generation 0; no active revision'
else
  problem 'Authoritative authentication' 'not an untouched generation-0 environment policy; do not activate or retry blindly'
fi

normal="$APP_ORIGIN/api/auth/callback"
isolated="$APP_ORIGIN/api/auth/test/callback"
check 'Trusted normal callback' "$normal"
check 'Trusted isolated callback' "$isolated"
bad_redirects="$(rehearsal_db_sql "SELECT count(*) FROM framework.auth_config_revisions r JOIN framework.auth_config_lifecycle l ON l.revision_id=r.id WHERE r.deployment_id='$REHEARSAL_DEPLOYMENT' AND r.environment='development' AND r.provider='oidc' AND l.status='approved' AND r.redirect_uri<>'$normal'" 2>/dev/null || true)"
approved="$(rehearsal_db_sql "SELECT count(*) FROM framework.auth_config_revisions r JOIN framework.auth_config_lifecycle l ON l.revision_id=r.id WHERE r.deployment_id='$REHEARSAL_DEPLOYMENT' AND r.environment='development' AND r.provider='oidc' AND l.status='approved'" 2>/dev/null || true)"
if [[ $bad_redirects == 0 ]]; then
  check 'Approved OIDC callback consistency' "OK ($approved approved rehearsal revisions)"
else
  problem 'Approved OIDC callback consistency' "$bad_redirects approved revisions use another callback"
fi

fetch() { curl --noproxy '*' --silent --show-error --fail --max-time 5 "$1" 2>/dev/null; }
if backend_health="$(fetch "http://127.0.0.1:$REHEARSAL_BACKEND_PORT/api/health")" && [[ $(jq -r '.status // ""' <<< "$backend_health" 2>/dev/null) == ok ]]; then
  check 'Rehearsal backend health' 'reachable'
else
  problem 'Rehearsal backend health' 'start the loopback Go server'
fi
if config="$(fetch "$APP_ORIGIN/api/auth/config")" && [[ $(jq -r '.provider // ""' <<< "$config" 2>/dev/null) == local_dev ]]; then
  check 'Vite proxy and runtime provider' 'reachable; local_dev'
else
  problem 'Vite proxy and runtime provider' 'start Vite with the generated rehearsal ports'
fi
if fetch "$APP_ORIGIN/" >/dev/null; then
  check 'Rehearsal frontend' 'reachable'
else
  problem 'Rehearsal frontend' 'start Vite on the dedicated loopback origin'
fi
if setup="$(fetch "$APP_ORIGIN/api/admin/auth/provider-setup")"; then
  if [[ $(jq -r '.normal_callback_url // ""' <<< "$setup" 2>/dev/null) == "$normal" && $(jq -r '.test_callback_url // ""' <<< "$setup" 2>/dev/null) == "$isolated" ]]; then
    check 'Admin callback metadata' 'matches both trusted rehearsal URLs'
  else
    problem 'Admin callback metadata' 'unexpected backend callback URLs'
  fi
else
  problem 'Admin callback metadata' 'bootstrap the isolated Local DEV administrator first'
fi
if runtime="$(fetch "$APP_ORIGIN/api/admin/auth/activation/status")"; then
  if jq -e '.authoritative_source == "environment" and .authoritative_generation == 0 and .local_source == "environment" and .local_provider == "local_dev" and .local_applied_generation == 0 and .reconciliation_required == false and .preparation_enabled == true and .preparation_affinity_mode == "single_instance"' <<< "$runtime" >/dev/null 2>&1; then
    check 'Protected activation status' 'generation 0; Local DEV; single-instance preparation enabled'
  else
    problem 'Protected activation status' 'unexpected provider, generation, synchronization or affinity mode'
  fi
else
  problem 'Protected activation status' 'bootstrap the isolated Local DEV administrator first'
fi

check 'Auth0 callback allowlist' 'MANUAL: verify both exact URLs in the rehearsal Auth0 application'
check 'Auth0 revision and enrollment' 'MANUAL: create, validate, approve, test and enroll only in this database'
if (( issues > 0 )); then
  printf 'Local rehearsal preflight has %d unresolved check(s). No authentication state was changed.\n' "$issues"
  exit 1
fi
printf 'Local rehearsal checks passed; Auth0 callback registration and identity evidence still require manual verification.\n'
