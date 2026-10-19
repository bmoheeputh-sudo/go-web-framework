# Go Web Framework

Reusable web application framework.

## Technology
- Backend: Go
- Frontend: React + Material UI
- Database: PostgreSQL
- Authentication: generic OIDC, Google IAP, and Local DEV
- Authorization: PostgreSQL RBAC with explicit account associations
- Deployment: Manual

## Development
- WSL Ubuntu
- DEV, TEST, PRD environments

## Run locally with Local DEV

Requirements: Go matching `backend/go.mod`, and Node/npm compatible with the
frontend lockfile (the current setup uses Node 20.20 and npm 11). No external
identity credentials or PostgreSQL database are needed for Local DEV authentication.
Enabling the optional RBAC/Admin Portal requires PostgreSQL with every provider.

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
| `AUTH_PROVIDER` | Select `local_dev`, `oidc`, or `google_iap` explicitly. Unset means public health only; `/api/auth/me` returns 401. |
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
display name may be absent when upstream providers omit them. Identity shape validation
is separate from verifying credentials. Authentication responses use `Cache-Control:
no-store`; unexpected provider failures return a generic error without credentials.

The `auth.Authenticator` interface resolves an identity for an HTTP request.
`auth.Require` validates it and places it in request context for protected handlers.
There is no universal credential string: OIDC login/callback handlers verify the
authorization flow and establish a server-side session; the OIDC authenticator
resolves that session on subsequent requests. The Google IAP authenticator verifies
the signed assertion on every protected request, without creating a session.
Unknown providers and missing required provider configuration fail startup.

React calls same-origin APIs and receives only the public identity fields. Keep
backend authentication configuration out of `VITE_*` variables and frontend code.

## Google IAP on App Engine, Cloud Run, or external hosts (Phase 4)

Set `AUTH_PROVIDER=google_iap` and explicitly set `IAP_AUDIENCE` to the **Signed
Header JWT Audience** of the Google IAP resource protecting this deployment.
Missing or malformed audiences stop startup. No project, audience, or hosting
information is discovered: this provider never uses the Google Cloud Metadata
Server, application default credentials, or a service account. IAP authentication
does not use PostgreSQL; the separate RBAC feature requires it when enabled.
OIDC and Local DEV retain their existing configuration and behavior.

| IAP resource | Exact `IAP_AUDIENCE` format |
| --- | --- |
| App Engine application | `/projects/PROJECT_NUMBER/apps/PROJECT_ID` |
| Global backend service, including an IAP connector forwarding to AWS EC2 | `/projects/PROJECT_NUMBER/global/backendServices/BACKEND_SERVICE_ID` |
| IAP enabled directly on a Cloud Run service | `/projects/PROJECT_NUMBER/locations/REGION/services/SERVICE_NAME` |

Use the numeric project **number**, and the numeric backend service **ID** where
applicable. Copy the actual signed-header audience from the IAP resource's console
settings; it is not the OAuth client ID, AWS instance ID, hostname, or service URL.
For Cloud Run protected at a load balancer, use that backend service's audience;
for direct Cloud Run IAP, use the regional service audience. See Google's
[signed-header audience reference](https://cloud.google.com/iap/docs/signed-headers-howto)
and [Cloud Run IAP options](https://cloud.google.com/iap/docs/enabling-cloud-run).

Edit your local configuration with `vi .env`, keeping real environment values out
of Git. Example for an external deployment (replace both numeric placeholders):

```dotenv
APP_ENV=PRD
AUTH_PROVIDER=google_iap
IAP_AUDIENCE=/projects/123456789/global/backendServices/987654321
HTTP_ADDR=127.0.0.1:8080
```

Load the environment and run the backend as in the local startup instructions.
For App Engine or Cloud Run, supply these variables in deployment configuration
and set `HTTP_ADDR` to the platform-required listener, for example `0.0.0.0:8080`
when its assigned port is 8080. For EC2, bind to loopback behind a local reverse
proxy, or a private interface reachable only by the trusted connector/proxy.
Configure HTTPS at ingress and protected transport to the origin. There is no
IAP development bypass, including in TEST and PRD. For offline UI development use
`AUTH_PROVIDER=local_dev` with `APP_ENV=development` instead.

### External hosting and network boundary

Running on AWS EC2 alone does not provide IAP. Deploy supported Google IAP
connector/proxy infrastructure that authenticates requests and forwards Google's
signed assertion to the origin. Google's [external application connector guide](https://cloud.google.com/iap/docs/enabling-on-prem-howto)
describes this infrastructure. Audience configuration alone is insufficient.
Restrict AWS security groups, firewalls, and origin listeners to the authorized
connector/proxy path; prevent public or alternate ingress that bypasses IAP.
Apply equivalent ingress restrictions on App Engine and Cloud Run. Serve React
and `/api` through the protected same-origin route. The proxy must forward the
IAP assertion without logging it; never synthesize identities from unsigned
`X-Goog-Authenticated-User-*` headers. This change provisions no cloud resources.

### Verification, caching, and operational limits

The existing maintained `go-jose/v4` dependency verifies compact ES256 signatures
using only keys fetched over HTTPS from
`https://www.gstatic.com/iap/verify/public_key-jwk`. The issuer must exactly equal
`https://cloud.google.com/iap`, the audience must be one exact string, and subject,
issued-at, and expiration are required. Clock skew is limited to 30 seconds and
`exp - iat` to 660 seconds. A future `nbf` is also rejected beyond the skew.
Keep host clocks synchronized. No environment setting disables verification or
substitutes a different key URL.

`issuer`, `subject`, `email`, `name` (as `display_name`), and `email_verified` come
only from verified claims. Missing optional email/name stay empty; email verification
stays false unless explicitly asserted. Unsigned identity headers, query strings,
OIDC session cookies, and Authorization headers cannot substitute for the assertion.
React receives only the common identity, displays Google IAP as the provider, and
handles 401 independently of backend health. It receives no assertion or token.
IAP controls sign-in; the application's OIDC login/callback/logout routes are not
registered in this mode, and no application cookies or PostgreSQL sessions are made.

All authenticated handlers must use `auth.Require(provider, handler)`, as
`/api/auth/me` does, to verify each request. `/api/health` and the provider-only
`/api/auth/config` remain public; use `/api/health` for unauthenticated health
probes through the appropriate infrastructure exception.

Public keys are fetched on demand with a five-second HTTP timeout, no redirects,
a 1 MiB response limit, and validation of key IDs/types/algorithms. They are cached
in memory for at most five minutes. An unknown key ID triggers refresh, limited
to once every 30 seconds across concurrent requests, including after errors.
A newly rotated key can therefore be rejected for up to 30 seconds; retry after
that interval. Removed keys stop working when the cache refreshes or expires.
No background worker or database cache is needed.

Invalid or missing assertions return 401. When trusted keys cannot be obtained,
protected requests return a generic 503; fresh cached keys remain usable until
expiry, but stale keys never authorize requests. Startup validates configuration
without fetching keys, so health remains available during a key endpoint outage.
Allow outbound HTTPS to the fixed Google endpoint. Error responses and application
logs never include raw assertions, identity payloads, or key-fetch details.

IAP assertions are bearer credentials and can be replayed until expiry; this phase
does not add per-token revocation or application logout. Phase 5 adds RBAC and
Origin checks to account/admin writes; future APIs must use those protections too. Restrict origin access and protect transport and logs.
Deployment IAM policy, proxy forwarding, actual Google key rotation, and end-to-end
cloud access must still be validated in the target environment; automated tests
use generated ES256 keys and mocked key responses, with no live IAP credentials.

## Run locally with OIDC and PostgreSQL (Phase 3)

OIDC uses the maintained `github.com/coreos/go-oidc/v3/oidc` and
`golang.org/x/oauth2` libraries. It is provider-independent: configure a standards-
compliant OIDC issuer. Sessions and one-use login transactions are stored in
PostgreSQL through `github.com/jackc/pgx/v5/pgxpool`. Apply the version-controlled
migrations through 000003 below before enabling OIDC (000004 for RBAC); the server never applies migrations itself.
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

## RBAC and generic account associations (Phase 5)

RBAC is separate from authentication. Enable it with `RBAC_ENABLED=true`, configure
`DB_*`, and set `APP_ORIGIN` to the exact browser origin, such as
`http://127.0.0.1:5173` for development or `https://app.example.com` for TEST/PRD.
No trailing slash or path is accepted. HTTP is allowed only on loopback in
`APP_ENV=development`. The origin is used for CSRF validation, never inferred from
Host or forwarded headers. All RBAC writes require that exact Origin and JSON.
Do not add permissive CORS middleware. React sends same-origin requests.

`RBAC_ENABLED` defaults to false to preserve existing database-free Local DEV and
IAP authentication. The account/admin APIs then return 503 for authenticated
requests, granting no access. When enabled, unavailable PostgreSQL or missing RBAC
tables stop startup. OIDC shares its existing pool; Local DEV and IAP open a pool
for authorization only. `/api/health`, `/api/auth/me`, OIDC callbacks/sessions, and
IAP per-request verification retain their existing behavior. Disabling a framework
user denies RBAC access immediately, but does not revoke their external identity
or invalidate `/api/auth/me` authentication responses.

### Model and permission policy

Migration `000004_rbac_accounts.up.sql` adds `framework.users`, `roles`,
`permissions`, `role_permissions`, `user_roles`, `accounts`, `user_accounts`,
`audit_log`, and the one-time `admin_bootstrap` marker. Existing migrations
000001–000003, authentication tables, and `public.schema_migrations` are unchanged.

A user is registered or their profile refreshed only when a verified, active
identity accesses `GET /api/access/me` from the dashboard. Permission checks on
other RBAC endpoints are read-only; denied requests do not create users or refresh
profiles/timestamps, and inactive users cannot refresh through the self endpoint.
The unique key is **issuer + subject**;
email is profile data and never links identities. Registration and profile refresh
assign no roles or accounts. Administrators cannot create a claimed identity by
email, edit issuer/subject, or merge identities through the API. Accounts are plain
named records with stable UUIDs and an active flag, without provider credentials,
delegation, ingestion, or login functionality. One user can link to multiple
accounts (up to 100 through this API), and an account can have multiple users.

| Role | Permissions | Account scope |
| --- | --- | --- |
| Admin | `admin.manage`, `accounts.read`, `accounts.write` | Account APIs still require an explicit link; admin management APIs can manage all accounts. |
| User | `accounts.read`, `accounts.write` | Explicitly linked, active accounts only. |
| Viewer | `accounts.read` | Explicitly linked, active accounts only. |
| No role / inactive user | None | No account access. |

Role and permission definitions are a fixed, version-controlled catalog; the
Admin Portal assigns roles but cannot redefine their permissions. Multiple roles
combine permissions. New permission requirements must be deliberately added in
code and a forward migration. Unknown or empty permissions deny access.

Go handlers use `auth.Require` first, then
`store.Require(access.AccountRead, "account", handler)` (or the appropriate
permission), with `account` naming the route parameter. Account checks include
both the membership and the account's active flag. `access.Principal(ctx)` returns
the resolved framework user. Administrative and account mutations recheck the
current permissions inside a transaction after taking a shared advisory lock,
serializing changes against revocations and concurrent administrator changes.
Use this pattern for future account data; React visibility is never authorization.

### Apply migration 000004 manually

Do not run this against the live database without approval. Back up the database
and stop the backend during the approved maintenance window. Load the `PG*`
variables using the earlier manual migration instructions and a migration owner
that owns the `framework` schema and can grant privileges to `go_web_app`.
From the repository root, for a database currently at version 3:

```bash
# ONLY after approval and with the intended database and migration-owner credentials:
migrate -path database/migrations -database 'postgres://?search_path=public' up 1
migrate -path database/migrations -database 'postgres://?search_path=public' version
```

Expect clean version `4`. For a fresh database, target `goto 4` to apply 000001–000004.
The existing schema-move instructions targeting version 3 are for Phase 3 only;
RBAC requires the additional migration. Never use `force` to skip migrations.
Enable RBAC in `vi .env` and restart the application after the migration.

The runtime `go_web_app` role receives required user/account DML, read-only role
catalog access, and INSERT/SELECT on audit records. It receives no UPDATE/DELETE
on audit records or access to the bootstrap marker. **Use a separate migration
owner in TEST/PRD:** an application role that owns these tables can bypass grants.
Database credentials are trusted administrative capabilities, not user credentials.
For another runtime role, provision equivalent grants explicitly with approval.

Rollback from version 4 uses `down 1`, with approval and the backend stopped.
**This drops all Phase 5 users, roles, account associations, audit records, and the
bootstrap marker.** Export and protect these records first. It preserves sessions,
OIDC flows, the framework schema, and public migration history. Run the prior
application version or set `RBAC_ENABLED=false` afterward. Reapplying the migration
creates an empty RBAC system and requires a new bootstrap; rollback is not a
routine administrator reset mechanism. Never use unbounded `down` on a live DB.

### Secure one-time administrator bootstrap

There is no default administrator and no HTTP bootstrap endpoint. First enable
RBAC, authenticate as the intended administrator through the selected provider,
and open the dashboard so `/api/access/me` registers the verified identity.
Inspect that authenticated `/api/auth/me` response and independently confirm its
exact issuer and stable subject belong to the intended administrator. Do not
substitute an email address or copy identity headers from an untrusted request.

After approval to change the actual database, run this operator command from
`backend`, using trusted `DB_*` settings for the migration owner (or a separately
provisioned bootstrap role), not the limited runtime role:

```bash
# Replace both placeholders with values verified above; do not pass DB passwords as flags.
go run ./cmd/bootstrap-admin \
  --issuer 'VERIFIED_ISSUER' \
  --subject 'VERIFIED_SUBJECT' \
  --confirm-verified-identity
```

The command refuses missing confirmation, unknown/unverified or inactive users,
Local DEV identities outside `APP_ENV=development`, an existing Admin assignment,
or a previously consumed bootstrap marker. The grant, durable marker, and audit
entry commit together; concurrent runs cannot grant multiple bootstrap admins.
The marker remains consumed even if someone later removes Admin roles manually.
Restore runtime database credentials before starting the application; do not keep
bootstrap-owner credentials in the application's `.env` or service environment.
The command checks authentication/RBAC schema availability but applies no migration.

For Local DEV, use issuer `urn:go-web-framework:local-dev` and the configured
`LOCAL_DEV_SUBJECT` only after that identity has accessed `/api/access/me`, and only
in development. For OIDC/IAP, use the verified issuer and subject returned by that
provider. Refresh account access in the dashboard after bootstrap. Create a second
verified administrator when needed: users cannot change their own roles or active
status, and API changes cannot eliminate the last active administrator.

### API and Admin Portal

| Endpoint | Access / operation |
| --- | --- |
| `GET /api/access/me` | Authenticated active user; own framework ID, roles, permissions and account IDs. Registers a role-free user if new. |
| `GET /api/accounts` | `accounts.read`; linked active accounts only. |
| `GET /api/accounts/{account}` | `accounts.read` plus explicit account link. |
| `PATCH /api/accounts/{account}` | `accounts.write` plus explicit account link; JSON `{ "name": "New name" }`. |
| `GET /api/admin/users` | `admin.manage`; verified users, roles and associations. |
| `PUT /api/admin/users/{user}` | `admin.manage`; JSON `{ "active": false }`. No self-change. |
| `PUT /api/admin/users/{user}/roles` | `admin.manage`; replaces roles with `{ "roles": ["User"] }`. No self-change. |
| `PUT /api/admin/users/{user}/accounts` | `admin.manage`; replaces links with `{ "account_ids": ["UUID"] }`; empty array removes all. |
| `GET /api/admin/roles` | `admin.manage`; fixed role/permission catalog. |
| `GET, POST /api/admin/accounts` | `admin.manage`; list or create with `{ "name": "Account", "active": true }`. |
| `PUT /api/admin/accounts/{account}` | `admin.manage`; update name and active flag (both required). |
| `GET /api/admin/audit` | `admin.manage`; newest audit entries first. |

List endpoints return pages of 100 records with `?offset=0`, `100`, etc. Every
request is authenticated; new RBAC routes return 401 without authentication, 403
for denied access, 400 for invalid input, and generic 503 on storage failures.
Writes require JSON, reject unknown fields and oversized bodies, and enforce
origin checks. User/account deletion is intentionally represented by deactivation.

The React dashboard shows assigned roles and linked accounts. Administrators also
see Users, Accounts, Roles, and Audit logs in the sidebar. On Users, select a user,
verify their issuer/subject, toggle roles, activate/deactivate users, and link or
unlink accounts. Accounts provides account creation and editing; Roles displays
the existing permission catalog; Audit logs displays the audit history. Admin
grants require an explicit browser confirmation. User selectors, account selectors,
the account-link picker, and audit history have pagination. Use Refresh access on
the dashboard after your roles change. Backend authorization remains authoritative
if the UI becomes stale.

Every successful admin mutation records the actor's framework user ID, target,
action, UTC timestamp, and before/after values in the same transaction. A failed
audit insert rolls back the change. Authorized account renames are audited too.
The audit contains identity identifiers and business metadata, but no authentication
tokens, credentials, or assertion headers. Limit access and apply an appropriate
retention policy manually. This is a database audit trail, not tamper-proof against
a database owner. No external log service, delegated login, ingestion, or worker
is added. Restoring a database backup can restore old role grants and memberships;
review restored access before reopening the application.

## Multilingual interface (Phase 6)

The toolbar language selector supports English (`en`, default/fallback), Dutch
(`nl`), French (`fr`), Spanish (`es`), Brazilian Portuguese (`pt-BR`), Simplified
Chinese (`zh-CN`), Indonesian (`id`), Malay (`ms`), Thai (`th`), Vietnamese (`vi`),
Hindi (`hi`), and Arabic (`ar`). Language names appear in their own languages.

On the first visit, the app uses the first supported language in the browser's
language preferences, otherwise English. Regional variants resolve to the
supported language; Portuguese variants use Brazilian Portuguese and Chinese
variants use Simplified Chinese. An explicit selection takes precedence on later
visits. Only the language code is saved in local storage under `gwf.language`;
no authentication data is stored with this preference. If storage is blocked,
switching still works for the current page. Remove that key in browser developer
tools to test first-visit detection again.

Translations are bundled locally with i18next/react-i18next in
`frontend/src/locales/<language>/{common,auth,admin}.json`. Missing or empty
translations fall back to English. Keep keys and `{{placeholder}}` names identical
across languages when adding text, and add entries to all twelve languages.
Language changes update the existing UI and error messages without reloading
authentication or resetting portal selections. Dates use the selected locale and
the browser's time zone; page numbers and permission lists use `Intl` formatting.
Digit shapes and date conventions follow the browser's locale data.

Arabic sets the document's language/direction, the MUI theme direction, and an
Emotion cache using the official MUI RTL plugin. Global document direction also
covers MUI portal menus. This follows the
[MUI RTL configuration](https://mui.com/material-ui/customization/right-to-left/).
Switching back restores LTR styling. MUI's locale bundles localize its own labels.

Application labels, role/permission descriptions, known audit actions, buttons,
and errors are translated. User names, account names, email addresses, identity
identifiers, the Go Web Framework product name, and protocol/provider names such
as OIDC and Google IAP retain their original values. Audit payloads are explicitly
labelled **Original audit data** and displayed unchanged as LTR JSON; this retains
their exact before/after values and technical field names. Unknown future role,
permission, and audit-action codes remain visible as their original codes until
translations are added. No existing application UI strings are intentionally
left untranslated beyond these data, identifiers, and proper names.

The Go API contract remains unchanged. React maps stable HTTP status codes
(400/401/403/409/5xx) and the fixed `login_failed` callback marker to local messages;
it does not parse English API error prose or display raw response/exception text.
Translations change display labels only: authorization, identity matching, role
assignment payloads, account links, and audit records retain their original codes.

After updating dependencies, start the backend using the existing Local DEV,
OIDC, or IAP configuration and run the frontend as usual:

```bash
cd frontend
npm ci
npm run dev
```

Use the toolbar selector to try each language, refresh to verify persistence,
and select Arabic to inspect RTL layout. No environment variables, database
changes, or migrations are needed for multilingual support.

## Reusable portal and navigation (Phase 7)

The responsive layout has a 260px expanded / 68px collapsed desktop drawer, with
tooltips for collapsed links. Its preference is stored as a boolean string under
`gwf.sidebar.expanded`, separately from `gwf.language`; neither preference contains
authentication data. Below MUI's `md` breakpoint (900px), the menu button opens a
temporary drawer that closes on navigation, including browser back/forward, or
Escape. Arabic explicitly uses a right-hand drawer, left-hand tooltips, and the
matching slide transition. Width transitions respect reduced-motion preferences.
The top bar shows the current page title, language and appearance selectors, and
an avatar that opens the authenticated user’s profile menu.

| Route | Page and access |
| --- | --- |
| `/` | Dashboard, public health and login status; authenticated users also see their roles and linked accounts. |
| `/users` | User roles, activation, and account associations; requires `admin.manage`. |
| `/accounts` | Account creation/editing; requires `admin.manage`. |
| `/roles` | Read-only role/permission catalog; requires `admin.manage`. |
| `/audit` | Paginated audit history; requires `admin.manage`. |
| Other paths | Translated page-not-found view with a dashboard link. |

User and Viewer accounts retain their linked-account view on the dashboard. The
Accounts administration page does not broaden their access. Sidebar filtering and
route guards use the same access predicate, but routes are guarded independently:
typing a hidden URL cannot mount its page or fetch its administration data. An
active authenticated user is required for protected routes; if both a role and a
permission are specified, both are required. Go remains the final authorization
authority for every API request. There are no client-side role grants or bypasses.

The main frontend modules are:

- `navigation/NavigationRegistry.tsx`: typed `NavItem` definitions and static
  registration; `navigation/AppRoutes.tsx`: nested React Router routes.
- `navigation/ProtectedRoute.tsx` and `authorization.ts`: authentication/access
  checks and translated denials.
- `layout/AdminLayout.tsx`: layout with `<Outlet />`; accepts `items` as a prop.
  `Sidebar.tsx` renders links and `TopBar.tsx` renders identity and controls.
- `pages/`: Dashboard, Users, Accounts, Roles, AuditLogs, and NotFound components.
  `lazyPages.ts` declares page-level `React.lazy` boundaries; the layout supplies
  `Suspense`. Administration pages load only when visited and authorized.
- `auth/SessionProvider.tsx` and `session.ts`: shared identity, health, access, and
  logout state above the routes; `AuthenticationNotice.tsx`: existing login UI.
- `api/client.ts`: shared HTTP/error handling and API types; `cache.ts`,
  `queries.ts`, and `QueryProvider.tsx`: small in-memory read cache and hooks.
- `AccessPortal.tsx`: dashboard role/account summary; `components/PageTools.tsx`:
  shared refresh, loading/error indicators, and locale-aware pagination.

### Appearance, profile, and feedback (Phase 7.1)

Use the **Appearance** icon menu in the toolbar to choose Light, Dark, or System. System is the
initial default and follows live operating-system color-scheme changes. An explicit
Light or Dark selection overrides the OS preference. The selection persists under
`gwf.appearance` independently of language and sidebar settings; no identity or
authentication data is stored with these preferences. If browser storage is
blocked, controls continue working for the current page. Preferences are not
synchronized between already-open tabs.

Appearance is integrated into `LanguageProvider.tsx` so MUI colors, locale,
CssBaseline, and the existing Emotion RTL caches stay coordinated. Components use
theme colors for backgrounds, selection, text, and status. `appearance/` contains
the preference context and toolbar selector. A circular 24px floating toggle
straddles the desktop sidebar/content seam at the center of the 80px top toolbar.
It sits outside the drawer's clipped scroll area and follows the 260px/68px width
transition, including in RTL. The collapsed header shows only the logo. A second
control at the bottom uses the same state: a labeled collapse button when expanded
and an expand icon when collapsed. Only the navigation list scrolls, so the bottom
control stays visible. Both controls preserve keyboard focus styling, translated
tooltips, and preference persistence. Mobile hides both desktop controls and
retains the temporary drawer's menu and close buttons.

The compact **Language** button shows the selected code (such as EN or PT-BR) and
opens a menu of all twelve native language names, without flags. The appearance
icon reflects the selected Light, Dark, or System mode. Both menus mark the current
choice, support keyboard navigation and Escape, restore focus to their trigger,
and align with the current LTR/RTL direction. Existing localized labels are reused;
no translation keys or dependencies are required for these controls.

On desktop, the profile button shows the avatar, authenticated display name,
primary application role, and dropdown chevron. A blank display name falls back
to the email from the authentication API. Name and role text use CSS ellipsis,
with a maximum text width of 160px from MUI's md breakpoint (900px) and 220px from
lg (1200px). The avatar and chevron do not shrink. The full name is available in a
tooltip and the profile menu. Mobile shows just the avatar. The primary
role uses existing localized labels with display precedence Admin, User, Viewer;
this is presentation only and does not change role permissions. Inactive users do
not show an active application role. Language, appearance, and profile controls
remain grouped horizontally, with the toolbar able to wrap on narrow screens.

Open the avatar or name to inspect display name, email, provider, issuer, and subject.
`layout/UserProfileMenu.tsx` explicitly renders only these identity fields. OIDC
Sign out uses the existing POST logout and session-clearing behavior. Google IAP
shows that sign-out is managed by the identity provider/IAP; Local DEV explains its
fixed development identity and offers no logout action.

`notifications/NotificationProvider.tsx` queues transient MUI Snackbar/Alert
messages. `useNotifications()` supports `success`, `error`, `warning`, and `info`,
with a namespaced translation key and optional interpolation values. For example,
inside a registered page:

```tsx
const notify = useNotifications()
notify({ severity: 'info', messageKey: 'common:loading' })
```

Import the hook from `notifications/notifications`. Administrative mutations use
this shared hook automatically: successful writes show a confirmation and failed
writes show the existing localized error. Identical visible or queued messages are
coalesced. Errors also remain inline on the page until refresh or the next attempt;
the snackbar does not replace the durable error. Notifications expire after six
seconds (MUI pauses the timer during interaction) or can be dismissed. Logout or
an identity change clears the notification queue along with the read cache.

Users, Accounts, Roles, and Audit logs use `components/CompactTable.tsx`, with
compact rows, translated empty states, and keyboard-focusable horizontal scrolling
contained within each table on small screens. Select a user or account by its name
button to edit it; **Create new account** resets the account form. Pagination,
role confirmations, self-change restrictions, account linking, API paths, and raw
audit JSON retain their existing behavior. The Roles catalog remains read-only.

To check these additions locally, use the existing backend configuration and run
`npm run dev` from `frontend`. Select each appearance, reload, then choose System
and change the OS theme. Try Arabic in both themes, collapse the sidebar and hover
its icons, and inspect the avatar menu with the configured provider. Use the mocked
frontend suite to exercise successful/rejected changes and empty tables without
modifying live records. The UI tests run in jsdom; they do not replace real-browser
visual and screen-reader checks.

### Register application pages

Create the registry once outside a component and pass it to `App`. For example:

```tsx
import { lazy } from 'react'
import AssessmentRounded from '@mui/icons-material/AssessmentRounded'
import App from './App'
import { createNavigationRegistry } from './navigation/NavigationRegistry'

const ReportsPage = lazy(() => import('./pages/ReportsPage'))
const navigation = createNavigationRegistry([
  {
    path: '/reports/daily',
    labelKey: 'common:navReports',
    icon: <AssessmentRounded />,
    element: <ReportsPage />,
    requiredRole: 'User',
    requiredPermission: 'accounts.read',
  },
])

// Inside the existing BrowserRouter / LanguageProvider setup:
<App navigation={navigation} />
```

Add `navReports` to all twelve `common.json` files. The example role requirement
is exact, not a hierarchy: an Admin without the User role would not match it.
Omit `requiredRole` when a permission alone should determine access. With neither
requirement, a route still requires an active authenticated framework user;
`public: true` is explicit and cannot be combined with privilege requirements.
Register static absolute application paths (including nested paths), with no
duplicates or `/api` paths. Parameterized routes, runtime plugin downloads, and
plugin discovery are intentionally outside this simple registry.

### Data freshness and deployment routing

Identity/configuration/health and current access are fetched once per application
mount, not on language changes or ordinary navigation. Page reads are deduplicated
and cached only in memory for the current identity. Successful mutations and the
refresh controls invalidate cached reads; late aborted responses are discarded.
Refresh administration reloads page data; Refresh access reloads current roles and
links. There is no polling or cross-tab synchronization, so changes by another
administrator appear after refresh or reload. API 401 responses expire the UI
session, and logout removes cached protected content. Cached data is never written
to local storage. API 403/409 responses remain localized errors; rejected writes
do not optimistically alter displayed records.

Vite's existing `/api` proxy is unchanged. Direct URL refreshes work through Vite's
SPA fallback. For a deployed build, configure the existing frontend web server to
serve `frontend/dist/index.html` for application routes such as `/users`, while
serving built assets normally and routing **all `/api/*` requests to Go before any
SPA fallback**. This preserves `/api/auth/login`, `/api/auth/callback`, and logout;
OIDC's callback still returns to the dashboard as before. A client-side 404 view
is rendered inside the SPA; its initial HTML response is normally HTTP 200.

Routing follows React Router's
[nested layout routes](https://reactrouter.com/start/declarative/routing), with
`BrowserRouter`, router links, `useLocation`, and `<Outlet />`. No Go routes,
database schema, migrations, or authentication configuration are changed.

### Try the redesigned portal locally

Start the backend using your existing authentication configuration and the earlier
startup instructions, then:

```bash
cd frontend
npm ci
npm run dev
```

Use the same frontend origin as your configured OIDC redirect URI when using OIDC.
With an existing authorized Admin, visit Users, Accounts, Roles, and Audit logs;
refresh each URL and try browser back/forward. Collapse the sidebar, reload, and
verify it stays collapsed. Narrow the viewport below 900px and test the menu.
Switch to Arabic to check the drawer, tooltips, controls, and dates. With an
existing User or Viewer, verify linked accounts on Dashboard and an access-denied
page for a directly entered `/users` URL. Do not grant privileges merely to test
the UI; automated tests use mock identities and disposable databases.

### Application checks

```bash
cd backend
go test -race -cover ./...
go vet ./...
cd ../frontend
npm test
npm run build
npm run lint
cd ..
git diff --check
```

The frontend tests mock all API requests. They validate all 36 translation JSON
files, consistent keys and interpolation placeholders, English fallback, browser
detection, switching all twelve languages, preference persistence and blocked
storage, HTML/MUI direction and actual Emotion style mirroring, locale formatting,
localized HTTP/network errors, and unchanged administrator role request values.
Portal tests additionally cover registry extensions, independent guards on all
administration routes, direct URLs, browser history, persistent desktop widths,
mobile closing behavior, RTL edges/tooltips/slide direction, user activation,
self-change protection, Admin confirmation, account linking/unlinking and picker
pagination, account creation/editing, rejected writes, audit pagination, session
expiry/logout, and cache invalidation/recovery. These UI tests run in jsdom;
viewport and transition geometry are mocked, so they do not replace visual checks
in the deployment's supported browsers.

The Go tests cover identity validation, Local DEV guards, OIDC discovery and
configuration, successful login, PKCE, browser-bound state, nonce, signed tokens,
issuer/audience/expiry rejection, session rotation/expiration, logout CSRF, and
unauthenticated access. IAP tests cover signed identity mapping, all supported
audience formats, invalid claims/signatures/headers, key rotation, expired key
caches, outages, and concurrent refresh. They use generated ES256 keys and mocked
HTTPS transport responses, without contacting Google. OIDC integration tests start a temporary loopback HTTPS
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
Phase 5 tests additionally cover issuer/subject matching, zero default privileges,
role and account isolation, CSRF and strict JSON, bootstrap races and the durable
one-time latch, runtime DB grants, immediate revocation, concurrent administrator
demotions, audit rollback, outages, and migration 4 upgrade/rollback preserving
existing authentication data. The bootstrap command is not run against live data.

## Minimal module registration (Phase 8.1)

Application modules are statically imported Go packages. `backend/module/module.go`
provides the small `Module`, `Manifest`, `Permission`, and `Registrar` contract.
`backend/server.go` contains the explicit catalog; no package-init hooks, runtime
plugin discovery, dynamic code loading, or module-specific migrations are added.
The frontend and existing authentication, account, administrator, and audit APIs
keep their current behavior.

### Configuration and capability endpoint

`ENABLED_MODULES` is an exact, comma-separated allowlist of compiled module IDs.
The default empty value enables none. Whitespace, empty entries, repeated IDs,
unknown IDs, and uppercase IDs fail startup. Catalog IDs and permission declarations
are validated even for disabled modules, while only enabled modules run `Register`.
Enabled modules require `RBAC_ENABLED=true`, an explicit authentication provider,
valid `APP_ORIGIN`, and the existing PostgreSQL settings. Keep `DB_USER=go_web_app`;
startup checks the existing framework schema and performs no permission or schema
writes. Existing database-free Local DEV/IAP behavior remains available when RBAC
and modules are disabled.

For an already configured RBAC deployment, the optional example configuration is:

```dotenv
RBAC_ENABLED=true
ENABLED_MODULES=example
```

Change configuration with `vi .env` and restart through the existing startup
instructions. This does not register permission rows or grant access.
`GET /api/modules` requires verified authentication and returns only:

```json
{"modules":["example"]}
```

With no enabled modules it returns `{"modules":[]}`. IDs are sorted and the
response is not cacheable. This endpoint reports availability, not authorization:
it does not require a framework role, create/refresh a framework user, expose
permission catalogs or secrets, or grant access to module data. Its only identity
source is the existing authentication middleware. Anonymous requests receive 401.
Disabling a module removes its routes (404) without deleting data or grants.
Configuration changes take effect after restart; there is no frontend module UI yet.

### Routes and permission boundaries

The example in `backend/internal/apps/example/module.go` declares `example.read`
and two read-only endpoints, with no storage or external integrations:

| Endpoint | Requirements |
| --- | --- |
| `GET /api/modules/example/info` | Verified identity, active registered framework user, and `example.read`. |
| `GET /api/modules/example/accounts/{account}/info` | The same, plus an explicit link to the active account in the path. |

Neither endpoint has a default grant, including for Admin. Because permission
provisioning/module migrations are outside this phase, an existing database will
normally return 403 even after enabling the example. A permission must be declared
in code **and** exist with an approved role binding in PostgreSQL before it grants
access. Only disposable integration tests provision these example permissions in
this phase. No live permission changes or module migrations are needed to run tests.

To add a module, implement `Manifest()` and `Register(module.Registrar)`, then add
its value explicitly to the server catalog. For example:

```go
func (Module) Register(routes module.Registrar) error {
    return routes.AccountRoute("GET", "/findings", "drive_audit.findings.read", findings)
}
```

`AccountRoute` supplies `/api/modules/<id>/accounts/{account}` as the prefix;
`GlobalRoute` supplies `/api/modules/<id>`. Module IDs use lowercase letters,
digits, and underscores, starting with a letter (up to 40 characters). Core names
are reserved. Permissions must start with that module's ID followed by a dot,
with lowercase dot-separated action segments. Each route needs an explicitly
declared permission; empty, core, foreign, and undeclared requirements are rejected.
Permission declarations never imply role assignments.

Relative route paths begin with a literal segment, such as `/info` or
`/findings/{finding}`. A trailing slash, catch-all wildcard, query string, encoded
segment, traversal, host-qualified pattern, or a redefinition of `{account}` is
rejected. Global paths cannot occupy the reserved `/accounts` subtree. Supported
methods are GET, POST, PUT, PATCH, and DELETE; Go's normal GET-to-HEAD matching is
preserved. Duplicate and ambiguous patterns fail registration using ServeMux's
conflict checks. Registration errors cannot be ignored by module code to mount a
partial module, and retained registrars cannot add routes after startup.

The framework wraps every module handler with `auth.Require`, the existing
origin/JSON write protection, and `access.Store.Require`. Identity comes from the
verified context; account scope comes only from the framework-owned path parameter.
Query parameters, bodies, and unsigned identity headers cannot override either.
Permissions and account membership/active status are checked in PostgreSQL on every
request. Database failures fail closed. Admin does not bypass account membership.
Only the enabled module catalog can extend the permission allowlist; even an
undeclared permission with a database grant is denied.

### Limits and tests

Modules are trusted compiled code, not a sandbox. The registry prevents missing
HTTP middleware but cannot stop malicious same-process code from opening another
listener or using credentials directly. Future domain handlers must constrain
resource queries by the authorized account ID as well as the resource ID; a URL
membership check alone is not sufficient for arbitrary stored resources.

This phase does not add a shared module mutation/audit transaction API. Existing
core mutations retain their transaction-time checks, revocation lock, last-Admin
protection, and audit behavior. The example performs no writes. Before adding real
module mutations, preserve those same transaction-time authorization and atomic
audit requirements; route middleware alone does not solve revocation races.
There are no module migrations, automatic permission provisioning, per-module
roles, background workers, or frontend module routes in this phase.

Run `go test -race -count=1 ./...` and `go vet ./...` from `backend`, then
`npm test`, `npm run build`, and `npm run lint` from `frontend`. New tests cover
configuration/catalog validation, route conflicts, disabled modules, authenticated
capabilities, ungranted Admin access, declared/unknown permissions, account isolation,
revocation, write-origin protection, database outages, unchanged records on denial,
and composition with existing core routes. Integration tests use the existing
disposable PostgreSQL harness and the `go_web_app` runtime role, never root `.env`
settings or the actual development database.

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
