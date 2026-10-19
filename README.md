# Go Web Framework

Reusable web application framework.

## Technology
- Backend: Go
- Frontend: React + Material UI
- Database: PostgreSQL
- Authentication: generic OIDC and Local DEV; Google IAP planned
- Authorization: RBAC
- Deployment: Manual

## Development
- WSL Ubuntu
- DEV, TEST, PRD environments

## Run locally with Local DEV

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
| `AUTH_PROVIDER` | Select `local_dev` or `oidc` explicitly. Unset means public health only; `/api/auth/me` returns 401. |
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
There is no universal credential string: OIDC login/callback handlers verify the
authorization flow and establish a server-side session; the OIDC authenticator
resolves that session on subsequent requests. A future IAP authenticator will
verify the IAP assertion on each request. Google IAP and PostgreSQL session storage
are not implemented. Selecting `google_iap` or an unknown provider fails startup.

React calls same-origin APIs and receives only the public identity fields. Keep
backend authentication configuration out of `VITE_*` variables and frontend code.

## Run locally with OIDC (Phase 2)

OIDC uses the maintained `github.com/coreos/go-oidc/v3/oidc` and
`golang.org/x/oauth2` libraries. It is provider-independent: configure a standards-
compliant OIDC issuer, rather than an Okta-specific endpoint. The development
session store is in memory, so **OIDC currently requires `APP_ENV=development`**.
Other environments are rejected at startup until shared, persistent sessions
(planned PostgreSQL) and shared login transactions are implemented.

Register a **confidential web application** with your chosen provider, enable
Authorization Code flow with PKCE S256, allow scopes `openid profile email`, and
register this exact redirect URI:

```text
https://localhost:5173/api/auth/callback
```

Configure your ignored `.env`:

```dotenv
APP_ENV=development
AUTH_PROVIDER=oidc
HTTP_ADDR=127.0.0.1:8080
OIDC_ISSUER_URL=https://your-issuer.example.invalid
OIDC_CLIENT_ID=your-registered-client-id
OIDC_CLIENT_SECRET='replace-with-your-local-client-secret'
OIDC_REDIRECT_URI=https://localhost:5173/api/auth/callback
DEV_TLS_CERT_FILE=/absolute/path/outside/repository/localhost.pem
DEV_TLS_KEY_FILE=/absolute/path/outside/repository/localhost-key.pem
```

Use the exact issuer advertised by the provider, including any issuer path and
trailing slash. Discovery, authorization, token, and JWKS URLs must use HTTPS;
TLS certificate verification is enabled and backend HTTP redirects are rejected.
Startup rejects missing settings, incompatible discovery metadata, and insecure
URLs. Discovery requests time out after 10 seconds. Token exchange and signature
verification share a 20-second callback deadline.

### Local HTTPS

OIDC cookies always have `Secure`, `HttpOnly`, `SameSite=Lax`, and `Path=/`, with
`__Host-` names and no Domain attribute. There is no insecure-cookie switch.
Therefore the browser-facing frontend must use HTTPS for OIDC. Local DEV can
continue using HTTP with the TLS variables left empty.

Use an existing trusted local certificate, or create one with OpenSSL outside the
repository (do not overwrite an existing key):

```bash
tls_dir="$HOME/.config/go-web-framework/local-tls"
mkdir -p "$tls_dir"
chmod 700 "$tls_dir"
(
  umask 077
  openssl req -x509 -newkey rsa:2048 -sha256 -days 30 -nodes \
    -keyout "$tls_dir/localhost-key.pem" -out "$tls_dir/localhost.pem" \
    -subj '/CN=localhost' -addext 'subjectAltName=DNS:localhost,IP:127.0.0.1'
)
```

Trust the generated certificate in your development browser/OS and put the two
absolute paths in `.env`. With WSL, trust it on the host OS where the browser runs.
This local certificate is for Vite; it does not change trust of your OIDC issuer.
Do not disable TLS verification. Keep the private key outside Git.

Start the backend from the repository root:

```bash
set -a
. ./.env
set +a
cd backend
go run .
```

In a second terminal, also starting from the repository root, export the environment
so Vite can read the TLS file paths:

```bash
set -a
. ./.env
set +a
cd frontend
npm ci
npm run dev
```

Open **`https://localhost:5173`**, matching the redirect URI's scheme, host and port
exactly. Do not switch between `localhost` and `127.0.0.1`: the host-only cookies
will not transfer. Vite keeps port 5173 fixed and proxies API requests to the Go
loopback listener. It reads TLS files only on the server side; backend environment
variables and secrets are never included in the React bundle.

Click **Sign in**, authenticate at your provider, and check the displayed identity.
Click **Sign out** to invalidate the application session. The dashboard handles a
401 as signed out while continuing to show backend health independently.

### OIDC flow and session behavior

| Endpoint | Behavior |
| --- | --- |
| `GET /api/health` | Public health check, unchanged. |
| `GET /api/auth/config` | Public provider name only; lets React show the appropriate controls. |
| `GET /api/auth/login` | Starts OIDC with random state, nonce, PKCE S256, and a browser-bound login cookie. |
| `GET /api/auth/callback` | Consumes the one-use transaction, exchanges the code, verifies the signed ID token, and creates a session. |
| `GET /api/auth/me` | Returns only the shared identity, or HTTP 401 for a missing/expired session. |
| `POST /api/auth/logout` | Requires the exact configured browser Origin, revokes the session and pending login, and clears cookies. GET is not accepted. |

Login/callback/logout routes are available only with `AUTH_PROVIDER=oidc`. Login
transactions expire after 10 minutes and contain state, nonce and PKCE verifier
only on the server. The flow cookie is a separate random value, so a valid state
alone cannot authenticate a different browser. The callback verifies signature,
issuer, audience/authorized party, expiration and nonce using discovery metadata
and JWKS. It accepts query-mode Authorization Code callbacks only. Failures
redirect to a fixed generic dashboard error; provider details are never displayed.
Return destinations are fixed, not taken from request parameters.

Sessions contain only the public identity and an expiration. Session cookies are
opaque random IDs, hashed in the server store, and rotated after successful login.
Sessions expire at the earlier of eight hours or ID-token expiration; there is no
silent renewal. ID, access, and refresh tokens are discarded after validation,
never placed in cookies, React storage, API responses, or application logs.
Authentication responses disable caching and callbacks suppress referrers.

The memory store is concurrency-safe, cleans expired entries on insertion, and is
bounded to 4096 sessions and 4096 login transactions. Restarting the backend logs
everyone out and invalidates pending logins. This is a single-process development
implementation, **not production session storage**. Production requires shared,
persistent PostgreSQL sessions, shared atomic login-transaction storage, and a
deployment review before removing the development-only startup guard.

Sign-out is local to this application. It does not end the identity provider's
browser session, revoke provider tokens, or implement OIDC federated logout; a
subsequent sign-in may reuse the provider's existing session.

### Application checks

```bash
cd backend
go test -race -cover ./...
cd ../frontend
npm run build
npm run lint
```

The Go tests cover identity validation, Local DEV guards, OIDC discovery and
configuration, successful login, PKCE, browser-bound state, nonce, signed tokens,
issuer/audience/expiry rejection, session rotation/expiration, logout CSRF, and
unauthenticated access. OIDC integration tests start a temporary loopback HTTPS
provider with generated signing keys and real JWKS verification; they require
local socket access but no external identity services or credentials. The race
check also exercises concurrent session-store access.

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
