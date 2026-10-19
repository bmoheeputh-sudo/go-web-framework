# Go Web Framework

Reusable web application framework.

## Technology
- Backend: Go
- Frontend: React + Material UI
- Database: PostgreSQL
- Authentication: Local DEV; OIDC (including Okta) and Google IAP planned
- Authorization: RBAC
- Deployment: Manual

## Development
- WSL Ubuntu
- DEV, TEST, PRD environments

## Run locally (authentication Phase 1)

Requirements: Go matching `backend/go.mod`, and Node/npm compatible with the
frontend lockfile (the current setup uses Node 20.20 and npm 11). No external
identity credentials or PostgreSQL database are needed for this phase.

In the repository root, create your local backend configuration without replacing
an existing `.env`:

```bash
cp -n .env.example .env
```

Review `.env` and set your fixed development subject, email, and display name.
Actual `.env` files are ignored by Git; `.env.example` contains safe examples.
The Go server reads process environment variables, so explicitly load your trusted
local configuration before starting it in the first terminal:

```bash
set -a
. ./.env
set +a
cd backend
go run .
```

In a second terminal, starting from the repository root:

```bash
cd frontend
npm ci
npm run dev
```

Open the local URL printed by Vite (normally `http://127.0.0.1:5173`). Vite binds to
loopback and forwards `/api` to `http://127.0.0.1:8080`. If you change the backend
port, update that proxy target in `frontend/vite.config.ts` too. The dashboard
shows backend connection status independently from authentication, plus the
authenticated user's provider, display name, and email. A 401 displays a signed-out
message without treating the backend as disconnected.

You can also inspect the APIs directly:

```bash
curl http://127.0.0.1:8080/api/health
curl http://127.0.0.1:8080/api/auth/me
```

### Authentication configuration and boundaries

| Variable | Purpose |
| --- | --- |
| `AUTH_PROVIDER` | Must explicitly be `local_dev` to enable the development identity. Unset means public health only; `/api/auth/me` returns 401. |
| `APP_ENV` | Must exactly equal `development` for Local DEV; TEST, PRD, production, and every other value are rejected at startup. |
| `HTTP_ADDR` | Defaults to `127.0.0.1:8080`. Local DEV requires a literal loopback IP and a valid port, such as `127.0.0.1:8080` or `[::1]:8080`. |
| `LOCAL_DEV_SUBJECT` | Required fixed development user identifier; never supplied by the browser. |
| `LOCAL_DEV_EMAIL` | Required locally configured email address. |
| `LOCAL_DEV_DISPLAY_NAME` | Required locally configured display name. |

Local DEV always uses issuer `urn:go-web-framework:local-dev` and reports
`email_verified: false`; it does not verify ownership of the configured email.
It accepts requests only from loopback peers and ignores identity claims in
headers, query parameters, cookies, and proxy forwarding headers. Do not expose
Local DEV through a public reverse proxy, tunnel, or port forward: loopback
proxies can still reach a loopback listener. It is a local development facility,
and never creates production users, session cookies, or database sessions.

The shared `auth.Identity` contains `issuer`, `subject`, `email`, `email_verified`,
`display_name`, and `provider`. Identify users by the issuer/subject pair, not by
email. Common validation requires issuer, subject, and a known provider; email and
display name may be absent for future upstream providers. Identity shape validation
is separate from verifying credentials. Authentication responses use `Cache-Control:
no-store`; unexpected provider failures return a generic error without credentials.

The `auth.Authenticator` interface resolves an identity for an HTTP request.
`auth.Require` validates it and places it in request context for protected handlers.
There is no universal credential string: future OIDC login/callback handlers will
verify their own flow and establish a server-side session; an OIDC request
authenticator can then resolve that session. A future IAP authenticator will verify
the IAP assertion on each request. These integrations, login/logout flows, and
PostgreSQL session storage are not implemented in Phase 1. Selecting `oidc` or
`google_iap` currently fails startup, as do unknown provider names.

React calls same-origin APIs and receives only the public identity fields. Keep
backend authentication configuration out of `VITE_*` variables and frontend code.

### Application checks

```bash
cd backend
go test -race -cover ./...
cd ../frontend
npm run build
npm run lint
```

The Go tests cover identity validation, explicit provider selection, environment
and loopback guards, spoofed identity claims, 401 responses, authenticated identity
responses, and public health checks. No external identity services are contacted.

## Backup to GitHub and Google Drive

Run from the repository on the `main` branch:

```bash
./backup.sh
```

The script stages changes and displays the staged diff. It asks for approval before
committing, pushing to `origin/main` through the existing SSH remote, and syncing
Drive. Answering anything other than `y` cancels the backup (changes remain staged).
No empty commit is created. A failed commit or push stops the backup before Drive.
Approval is also required when there are no new changes to commit.

The existing `.venv` needs these packages. If setting up a new environment:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install google-api-python-client google-auth google-auth-httplib2 httplib2
```

Authentication uses the existing DWD service account file `../secure/google/0.json`
relative to this repository and impersonates `bhoshan.moheeputh@vopak.com`. The Drive
destination is folder `1rwOlHtHd2ogU0Wv5_K454HbmXSGjxYPs`. Keep the credential outside
the repository; the scripts do not modify it or print authentication responses.

Preview the Drive changes in committed `HEAD` without loading credentials, making
API calls, or writing state:

```bash
.venv/bin/python scripts/drive_sync.py
```

To retry just Drive after a successful Git push, run the following and approve its
prompt. Direct Drive runs do not push or verify GitHub:

```bash
.venv/bin/python scripts/drive_sync.py --sync
```

Drive synchronization uses `git diff` from the last successful checkpoint. The
first run considers every tracked file in the current commit, even when the
repository already has commit history, and adopts existing uniquely named Drive
files by ID. Folder structure is preserved. Detected renames retain the file ID;
deleted files remain in Drive. Git renames are detected heuristically: a heavily
rewritten file may be treated as a deletion plus an addition, retaining the old copy.
Unchanged files are not uploaded. Uploads read committed Git blobs, so uncommitted
working tree content is never uploaded by the Drive script.

State is stored at `~/.config/go-web-framework/drive-sync-state.json` with owner-only
permissions. It contains the successful commit, pending commit, Drive IDs, and
completed blob IDs. State updates are atomic and a lock prevents concurrent Drive
runs. The checkpoint advances only when all eligible files succeed. On failure,
rerun the backup or the Drive command: completed uploads are skipped and pending
ones are retried. An interrupted snapshot finishes before newer commits are synced.
Keep this state file during retries; reserved IDs prevent duplicate creates even
when an upload succeeds remotely but its response is lost.

API requests have a 120-second HTTP timeout and up to five attempts with exponential
backoff (1, 2, 4, and 8 seconds) for transient network errors and HTTP 429/5xx.
Ambiguous names, incompatible Drive file types, and unexpected ID conflicts fail
without advancing the checkpoint. Resolve duplicate names in Drive before retrying.
The script never calls Drive's delete API. Each snapshot prints created, updated,
skipped, and failed file counts; folder creation is not included in the file counts.

Only regular Git-tracked source files are eligible. `.env*`, private keys,
credential/secret paths, virtual environments, dependencies, build outputs, common
binary/archive/database artifacts, and recognizable private-key/service-account
content are excluded. Tracked symlinks and submodules are skipped; a working tree
symlink in an otherwise eligible path fails safely. The exclusions are deliberately
conservative and live in `scripts/drive_sync.py`. Review the staged diff for GitHub;
Drive exclusions do not change what Git commits. If Git history is rewritten or
state is corrupt, synchronization stops: restore valid history/state, or archive
the state file and perform a full reconciliation after resolving the cause.

Run the offline tests (temporary Git repositories and mocked Drive responses):

```bash
.venv/bin/python -m unittest discover -s tests -v
bash -n backup.sh
```

These tests do not use credentials, contact Google Drive, or push to GitHub.
