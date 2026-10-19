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
identity credentials or PostgreSQL database are needed for Local DEV.

In the repository root, create your local backend configuration without replacing
an existing `.env`:

```bash
cp -n .env.example .env
vi .env
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
verify the IAP assertion on each request. Google IAP is not implemented.
Selecting `google_iap` or an unknown provider fails startup.

React calls same-origin APIs and receives only the public identity fields. Keep
backend authentication configuration out of `VITE_*` variables and frontend code.

## Run locally with OIDC and PostgreSQL (Phase 3)

OIDC uses the maintained `github.com/coreos/go-oidc/v3/oidc` and
`golang.org/x/oauth2` libraries. It is provider-independent: configure a standards-
compliant OIDC issuer. Sessions and one-use login transactions are stored in
PostgreSQL through `github.com/jackc/pgx/v5/pgxpool`. Apply the version-controlled
migrations through 000003 below before enabling OIDC; the server never applies migrations itself.
OIDC accepts `APP_ENV=development`, `test`/`TEST`, and `production`/`prd`/`PRD`.
Local DEV still requires exactly `development` and does not connect to PostgreSQL.

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

Preserve the existing root `.env` database settings for local PostgreSQL 14:
`DB_HOST`, `DB_PORT`, `DB_NAME=go_web_framework`, `DB_USER=go_web_app`,
`DB_PASSWORD`, and `DB_SSLMODE`. New settings and safe placeholders are in
`.env.example`; use `vi .env` to merge them rather than replacing existing values.

Use the exact issuer advertised by the provider, including any issuer path and
trailing slash. Discovery, authorization, token, and JWKS URLs must use HTTPS;
TLS certificate verification is enabled and backend HTTP redirects are rejected.
Startup rejects missing settings, incompatible discovery metadata, and insecure
URLs. Discovery requests time out after 10 seconds. Token exchange and signature
verification share a 20-second callback deadline.

### Local HTTPS

OIDC HTTPS cookies have `Secure`, `HttpOnly`, `SameSite=Lax`, and `Path=/`, with
`__Host-` names and no Domain attribute. HTTPS is mandatory in TEST and PRD.
Local DEV can continue using HTTP with the TLS variables left empty.

For explicit local HTTP OIDC testing only, set `APP_ENV=development`,
`OIDC_ALLOW_HTTP_DEVELOPMENT=true`, and register/use
`OIDC_REDIRECT_URI=http://localhost:5173/api/auth/callback`. Leave Vite TLS paths
empty and keep `HTTP_ADDR` on a literal loopback IP. This uses separate
`gwf_dev_session`/`gwf_dev_oidc_flow` cookies without Secure, still HttpOnly and
SameSite=Lax. Non-loopback HTTP callbacks and this flag outside development are
rejected. The issuer, discovery, token and JWKS endpoints always require HTTPS.

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

Sessions contain public identity fields (including email verification), creation,
absolute expiration and last activity timestamps. All timestamps are TIMESTAMPTZ.
Cookies hold cryptographically random 256-bit opaque tokens; PostgreSQL receives
only SHA-256 token hashes. Successful authentication atomically inserts a new
session and deletes the previous session; a failed insert preserves the old one.
Lookup checks expiration and updates last activity in one SQL statement, and
logout immediately deletes the session. Expired, idle and revoked sessions return
401. Storage failures return 503 with no credential details. A failed logout keeps
the cookie and reports failure so the user can retry revocation.

`SESSION_IDLE_TIMEOUT` defaults to `30m` and `SESSION_ABSOLUTE_TIMEOUT` to `8h`.
Use positive Go durations of at least one second, with idle <= absolute <= 720h.
Absolute expiration is also capped by ID-token expiry; activity never extends it.
Idle checks use the configured value on every request, so keep it consistent
across instances. ID, access and refresh tokens are discarded after validation,
never stored in PostgreSQL or exposed to React or application logs. Shared login
transactions persist nonce and PKCE verifier for up to ten minutes, but store only
hashes of the state and flow-cookie token. They are atomically consumed once.

Sessions and pending logins survive backend restarts and work across instances
sharing the same database, issuer, public origin and configuration. There is no
in-memory fallback. No refresh-token renewal is implemented. Authentication
responses disable caching and callbacks suppress referrers.

Sign-out is local to this application. It does not end the identity provider's
browser session, revoke provider tokens, or implement OIDC federated logout; a
subsequent sign-in may reuse the provider's existing session.

### Database setup and manual migrations

The pool defaults to 10 maximum connections, no minimum, a 30-minute connection
lifetime and a five-minute idle connection lifetime. `DB_MAX_CONNS` accepts 1–100.
Connection/startup checks have a five-second deadline; session operations have a
three-second deadline. PostgreSQL statement and lock timeouts are five and two
seconds. Shutdown drains HTTP requests and closes the pool.

OIDC startup checks connectivity and the expected schema using read-only queries.
Missing migrations, invalid database settings or an unavailable database stop
startup. An outage after startup blocks authentication; `/api/health` remains a
public process-liveness endpoint, not a database-readiness check.

Review these [golang-migrate](https://github.com/golang-migrate/migrate) migrations:

- `database/migrations/000001_sessions.up.sql` creates sessions, hash/timestamp
  constraints, and indexes for expiry, activity, and issuer/subject.
- `database/migrations/000002_oidc_login_flows.up.sql` creates shared short-lived
  OIDC login transactions and an expiry index.
- `database/migrations/000003_framework_schema.up.sql` creates `framework`, moves
  the two existing tables there with `ALTER TABLE ... SET SCHEMA`, and grants
  `go_web_app` schema USAGE and SELECT/INSERT/UPDATE/DELETE on both tables. Existing
  rows, indexes, constraints, table owners, and grants are retained. Migrations
  000001 and 000002 remain unchanged; do not reapply or edit them on a version-2 DB.
- `public.schema_migrations` stays in `public`; golang-migrate advances its version
  from 2 to 3 normally. Do not copy, move, reset, or recreate this history table.
- Migration 000003's `.down.sql` moves both tables back to `public` without deleting
  data. It leaves the `framework` schema and grants in place, including any unrelated
  objects. The older 000001/000002 down migrations **delete tables and data**.
  Rollback requires separate approval and the matching application version.

**Obtain approval before running migration commands against the actual database.**
The following commands are provided for manual review and execution, not run by
the application. Even `migrate version` may create its metadata table on first use.
Use the golang-migrate CLI with its PostgreSQL driver installed, from the repository
root. The PostgreSQL driver accepts `PG*` environment variables, so no password
appears in a command-line database URL:

```bash
set -a
. ./.env
set +a
export PGHOST="$DB_HOST"
export PGPORT="${DB_PORT:-5432}"
export PGDATABASE="$DB_NAME"
export PGUSER="$DB_USER"
export PGPASSWORD="$DB_PASSWORD"
export PGSSLMODE="${DB_SSLMODE:-verify-full}"
export PGSSLROOTCERT="${DB_SSLROOTCERT:-}"
export PGCONNECT_TIMEOUT=5

# Only after approval, using the intended database and migration role:
migrate -path database/migrations -database 'postgres://?search_path=public' goto 3
migrate -path database/migrations -database 'postgres://?search_path=public' version
unset PGPASSWORD
```

The explicit `search_path=public` keeps golang-migrate using the existing history
in `public`, even if a role has a different default search path. This uses the
[PostgreSQL driver's search_path option](https://github.com/golang-migrate/migrate/blob/master/database/postgres/README.md).
On the existing version-2 database, `goto 3` applies only migration 000003. On a
fresh database it applies migrations 000001–000003 in order. Expect version `3`
without a dirty marker afterward. Do not run these commands against a version
newer than 3; `goto` can also migrate down.

For the version-2 upgrade, stop the backend during the approved maintenance window,
back up the database, apply migration 000003, then start the updated backend.
The old application expects `public` tables; the new application requires
`framework` tables and fails startup until migration 000003 is applied. Table
moves acquire locks, so coordinate with other database clients. A separately
approved rollback from version 3 uses `down 1` and the old application; never run
an unbounded `down` on a database whose data must be preserved.

The migration role must own both existing tables (or have equivalent authority),
be able to CREATE schemas in the database, and access `public.schema_migrations`.
If `framework` already exists, it also needs CREATE and grant authority there.
Fresh installations additionally need CREATE on `public` for migrations 000001/2.
The existing `go_web_app` role must exist before migration 000003; the migration
fails transactionally if it cannot grant the required access. It does not create
roles or alter passwords. For TEST/PRD use a separate migration owner and supply
that role's credentials to the migration command instead of the runtime credentials.

The runtime role needs CONNECT on the database, USAGE on `framework`, and
SELECT/INSERT/UPDATE/DELETE on `framework.sessions` and `framework.oidc_login_flows`.
Migration 000003 grants the schema and table privileges to `go_web_app`; it does
not explicitly grant schema CREATE. Existing privileges and ownership are
preserved. A role that runs the migration owns the newly created schema, and a
runtime role that already owns tables retains that authority. Use a separate
migration owner to keep these ownership privileges out of the runtime role. If a deployment
uses a different runtime role, provision its equivalent grants separately with
approval. Application queries use explicit `framework` names and do not require
changing the runtime search path. No runtime access to migration history is needed.

### TEST/PRD transport security and recovery

TEST and PRD require a browser-facing HTTPS origin and `OIDC_ALLOW_HTTP_DEVELOPMENT=false`.
Terminate HTTPS at a trusted reverse proxy; restrict the backend HTTP listener to
that proxy/private network. Do not expose plaintext backend ports publicly. Cookie
security and logout Origin validation derive from the configured public redirect
URI, never from untrusted forwarding headers.

Database connections outside development require `DB_SSLMODE=verify-full` and
`DB_SSLROOTCERT` pointing to the trusted PostgreSQL CA. `DB_HOST` must match the
server certificate. `require`, `prefer`, `allow`, and `verify-ca` are rejected;
there is no plaintext fallback. `DB_SSLMODE=disable` is accepted only for loopback
PostgreSQL in development. Keep DB/OIDC secrets out of `VITE_*`, logs and Git.

If startup fails, check PostgreSQL service availability, the configured role's
permissions, TLS trust, and migration status. Fix the cause and restart; existing
unexpired database sessions remain valid. Following a database outage, lookup and
logout can be retried once the pool reconnects. A failed callback needs a fresh
sign-in because its state is one-use. Do not bypass checks or fall back to memory.

If a migration is marked dirty, inspect the failed SQL and actual schema before
using any repair/`force` command; get approval for the exact repair first. Do not
blindly roll back: the 000001/000002 down migrations delete tables and data. Back up the database before
approved schema changes. Restoring a backup can restore previously revoked
sessions; revoke restored sessions before reopening authentication if necessary.

No cleanup worker is added. Expired records are always rejected but remain until
an operator performs approved maintenance. For example, after approval, remove
flows with `expires_at <= now()` and sessions with `expires_at <= now()` or
`last_activity_at <= now() - interval '30 minutes'` (use the deployed idle timeout).
Review deletes and revocations before running them. Protect database backups and
access to nonce/PKCE data. Rate limiting, device/session management, federated
logout, and automatic revocation when an account is disabled at the IdP remain
outside this phase; revocation otherwise occurs at logout or expiration. Revoke
existing sessions when changing the registered client/application trust boundary.

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
local socket access but no external identity services or credentials. PostgreSQL
tests create and destroy their own isolated clusters under `/tmp`, using private
Unix sockets with TCP disabled. They never read root `.env` or connect to the
application database. Install PostgreSQL 14 server binaries or set `PG_TEST_BIN`
to their directory; database integration tests are explicitly skipped if binaries
are absent. Run as a non-root user. Install the golang-migrate CLI with the
PostgreSQL driver on PATH to also run `TestFrameworkSchemaMigration`; this test
explicitly skips if the CLI is absent. It starts at migration version 2 with seeded
sessions/login flows and verifies version 3 upgrade, rollback to 2, and re-upgrade
using the real CLI. It checks row preservation, table/index/constraint identities,
ownership, existing grants, runtime privileges, and history remaining in `public`.
Session integration tests run as `go_web_app` with a search path that excludes
`framework`, verifying that explicit schema references and grants work. Tests also
cover all migrations up/down, hash storage, idle/absolute expiry, activity updates,
concurrent lookup, atomic rotation and rollback, shared login-state consumption,
database outages and cookie policy. Destructive old down migrations run only in
the disposable clusters, never against the configured application database.

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
