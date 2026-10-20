#!/usr/bin/env bash
set -euo pipefail
source "$(dirname -- "${BASH_SOURCE[0]}")/common.sh"

[[ $# == 0 ]] || rehearsal_error 'cleanup takes no arguments'
rehearsal_require_local_postgres
for program in psql dropdb; do
  command -v "$program" >/dev/null || rehearsal_error "$program is required"
done
[[ $(rehearsal_database_exists) == 1 ]] || rehearsal_error 'rehearsal database does not exist; nothing will be removed'
rehearsal_verify_marker
marker="$(rehearsal_file_marker)"
confirmation="DROP REHEARSAL $REHEARSAL_DB $marker"
printf 'Only the marked database %s and its generated local environment file will be removed.\nType exactly: %s\n> ' "$REHEARSAL_DB" "$confirmation"
IFS= read -r answer || rehearsal_error 'confirmation was not received'
[[ $answer == "$confirmation" ]] || rehearsal_error 'confirmation did not match; nothing was removed'
# Recheck immediately before the destructive command. dropdb does not forcibly
# terminate active sessions; operators must stop the rehearsal processes first.
rehearsal_verify_marker
dropdb --maintenance-db=postgres "$REHEARSAL_DB"
[[ -f $REHEARSAL_ENV_FILE && ! -L $REHEARSAL_ENV_FILE ]] || rehearsal_error 'database removed; local environment file was not safely identifiable for removal'
[[ $(rehearsal_file_marker) == "$marker" ]] || rehearsal_error 'database removed; local environment marker changed, so the file was retained'
rm -- "$REHEARSAL_ENV_FILE"
printf 'Marked rehearsal database and generated local environment file removed.\n'
