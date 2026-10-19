#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

if [[ "$(git branch --show-current)" != "main" ]]; then
    echo "Backup must run on the main branch." >&2
    exit 1
fi
remote=$(git remote get-url --push origin)
if [[ "$remote" != git@*:* && "$remote" != ssh://* ]]; then
    echo "origin must use the existing SSH remote." >&2
    exit 1
fi
if [[ ! -x .venv/bin/python ]]; then
    echo "Missing .venv/bin/python; see the backup setup in README.md." >&2
    exit 1
fi

echo "=== GitHub ==="
git add -A

has_changes=false
if ! git diff --cached --quiet; then
    has_changes=true
    echo "Staged changes:"
    git --no-pager diff --cached --stat
    git --no-pager diff --cached --no-ext-diff --no-textconv
else
    echo "No staged changes; no commit will be created."
fi

echo "This will push main to origin/main and synchronize committed source files to Google Drive."
read -r -p "Approve this backup (including a commit if needed)? [y/N] " confirm
[[ "$confirm" == "y" || "$confirm" == "Y" ]] || exit 1

if $has_changes; then
    git commit -m "Update project $(date +%Y-%m-%d_%H-%M-%S)"
fi

if ! git push origin main:main; then
    echo "Git push failed; Google Drive synchronization was not started." >&2
    exit 1
fi

echo "=== Google Drive ==="
.venv/bin/python scripts/drive_sync.py --sync --yes

echo "=== Backup completed ==="
