#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

echo "=== GitHub ==="
git add -A

if ! git diff --cached --quiet; then
    echo "Files staged for commit:"
    git diff --cached --name-only

    read -r -p "Commit and push these files? [y/N] " confirm
    [[ "$confirm" == "y" || "$confirm" == "Y" ]] || exit 1

    git commit -m "Update project $(date +%Y-%m-%d_%H-%M-%S)"
fi

git push origin main

echo "=== Google Drive ==="
.venv/bin/python scripts/drive_sync.py

echo "=== Backup completed ==="
