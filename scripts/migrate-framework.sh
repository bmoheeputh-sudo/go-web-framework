#!/usr/bin/env bash
# Supported core migration policy: explicit forward steps only. Credentials are
# supplied through the existing PG* environment, never through script arguments.
set -euo pipefail

refuse() {
    echo 'Framework migrations allow only: version | up <positive step count>.' >&2
    echo 'Rollback uses a compatible application version or a forward corrective migration.' >&2
    exit 2
}

# Validate BEFORE starting migrate: even driver initialization may create a journal.
case "${1:-}" in
    version) [[ $# == 1 ]] || refuse ;;
    up) [[ $# == 2 && $2 =~ ^[1-9][0-9]{0,8}$ ]] || refuse ;;
    *) refuse ;;
esac

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
exec migrate -path "$script_dir/../database/migrations" \
    -database 'postgres:///?search_path=public&x-migrations-table=schema_migrations' "$@"
