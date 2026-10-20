# Go Web Framework

Reusable web application framework.

## Technology
- Backend: Go
- Frontend: React + Material UI
- Database: PostgreSQL
- Authentication: generic OIDC and development-only Local DEV
- Authorization: PostgreSQL RBAC with explicit account associations
- Deployment: Manual

## Development
- WSL Ubuntu
- DEV, TEST, PRD environments

## Run locally with Local DEV

Requirements: Go matching `backend/go.mod`, and Node/npm compatible with the
frontend lockfile (the current setup uses Node 20.20 and npm 11). No external
identity credentials are needed for Local DEV authentication. Phase 9.2.5D requires
PostgreSQL with migration 000006 and a valid `AUTH_CONFIG_DEPLOYMENT` for the
read-only startup policy check, even when RBAC is disabled. Configure `DB_*`
and a stable, deployment-specific identity before starting; do not change scope
to work around a policy failure.

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
| `AUTH_PROVIDER` | Select `local_dev` or `oidc` explicitly. `google_iap` is retired and fails startup. Unset means public health only; `/api/auth/me` returns 401. |
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
resolves that session on subsequent requests. Local DEV uses a fixed identity
and is restricted to development on loopback.
Unknown providers and missing required provider configuration fail startup.

React calls same-origin APIs and receives only the public identity fields. Keep
backend authentication configuration out of `VITE_*` variables and frontend code.

## Retired Google IAP provider

Google IAP is no longer a supported authentication provider. `AUTH_PROVIDER=google_iap`
now fails startup, even when an OIDC revision is active in PostgreSQL. New IAP
configuration drafts and lifecycle changes are rejected. Existing IAP user,
revision and audit records remain readable as historical data; applied migrations
and their columns are unchanged. Deployments previously using IAP must plan an
OIDC cutover and review their ingress controls before upgrading.

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
  These are historical rollback files for isolated tests, not the supported
  production migration workflow. See the forward-only policy below.

**Obtain approval before running migration commands against the actual database.**
The following commands are provided for manual review and execution, not run by
the application. Even `migrate version` may create its metadata table on first use.
Use `scripts/migrate-framework.sh` with the golang-migrate CLI and its PostgreSQL
driver installed, from the repository root. The wrapper permits only `version` and
`up N` with an explicit positive step count; it rejects all other commands before
starting golang-migrate. It fixes the core path and `public.schema_migrations`
journal. The PostgreSQL driver accepts `PG*` environment variables, so no password
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
# For a confirmed clean version-2 database (use up 3 for a fresh database):
./scripts/migrate-framework.sh up 1
./scripts/migrate-framework.sh version
unset PGPASSWORD
```

The explicit `search_path=public` keeps golang-migrate using the existing history
in `public`, even if a role has a different default search path. This uses the
[PostgreSQL driver's search_path option](https://github.com/golang-migrate/migrate/blob/master/database/postgres/README.md).
On the existing version-2 database, `up 1` applies only migration 000003. On a
fresh database, `up 3` applies migrations 000001–000003 in order. Expect version `3`
without a dirty marker afterward. These are historical Phase 3 upgrade steps;
check the current version and intended target before choosing the step count.

For the version-2 upgrade, stop the backend during the approved maintenance window,
back up the database, apply migration 000003, then start the updated backend.
The old application expects `public` tables; the new application requires
`framework` tables and fails startup until migration 000003 is applied. Table
moves acquire locks, so coordinate with other database clients. Production rollback
uses a schema-compatible application version or a reviewed forward corrective
migration. Historical reverse migrations are exercised only in disposable tests.

The migration role must own both existing tables (or have equivalent authority),
be able to CREATE schemas in the database, and access `public.schema_migrations`.
If `framework` already exists, it also needs CREATE and grant authority there.
Fresh installations additionally need CREATE on `public` for migrations 000001/2.
The existing `go_web_app` role must exist before migration 000003; the migration
fails transactionally if it cannot grant the required access. It does not create
roles or alter passwords. The current deployment uses `go_web_app` for both the
application and migrations; it also owns schemas/tables. Separating a migration
owner from a DML-only runtime role is a future hardening option, not an implemented
property of this deployment.

The runtime role needs CONNECT on the database, USAGE on `framework`, and
SELECT/INSERT/UPDATE/DELETE on `framework.sessions` and `framework.oidc_login_flows`.
Migration 000003 grants the schema and table privileges to `go_web_app`; it does
not explicitly grant schema CREATE. Existing privileges and ownership are
preserved. A role that runs the migration owns the newly created schema, and a
runtime role that already owns tables retains that authority. In this deployment,
`go_web_app` has ownership/migration authority in addition to DML privileges; these
grants do not establish database least-privilege separation. A future deployment
could separate the migration owner and runtime role after an explicit security
review. Application queries use explicit schema names and do not change the
runtime search path. Module startup validation reads the independent journals.

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

`RBAC_ENABLED` defaults to false; account/admin APIs then return 503 for
authenticated requests, granting no access. PostgreSQL is always required for
the startup policy check. When RBAC is enabled, missing RBAC tables also stop
startup. Policy checks, OIDC sessions and authorization reuse the same pool.
`/api/health`, `/api/auth/me`, and OIDC callbacks and sessions retain their
existing behavior. Disabling a framework
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
./scripts/migrate-framework.sh up 1
./scripts/migrate-framework.sh version
```

Expect clean version `4`. For a fresh database, use `up 4` to apply 000001–000004.
The existing schema-move instructions targeting version 3 are for Phase 3 only;
RBAC requires the additional migration. Never use `force` to skip migrations.
Enable RBAC in `vi .env` and restart the application after the migration.

The migrations explicitly grant `go_web_app` required user/account DML, read-only
role catalog access, and INSERT/SELECT on audit records. These explicit grants do
not limit an owner: the current single database user also owns schemas/tables and
runs migrations, so it retains broader authority, including ownership rights over
audit/bootstrap objects it owns. DML-only runtime separation is not implemented.
Database credentials are trusted administrative capabilities, not user credentials.
A separate migration owner would be future hardening and requires explicit approval.

The historical version-4 down migration is not part of the supported production
workflow. **It drops all Phase 5 users, roles, account associations, audit records,
and the bootstrap marker.** It preserves sessions, OIDC flows, the framework schema,
and public migration history. Reapplying that migration would create an empty
RBAC system and require a new bootstrap; rollback is not a
routine administrator reset mechanism. Never use unbounded `down` on a live DB.

### Secure one-time administrator bootstrap

There is no default administrator and no HTTP bootstrap endpoint. First enable
RBAC, authenticate as the intended administrator through the selected provider,
and open the dashboard so `/api/access/me` registers the verified identity.
Inspect that authenticated `/api/auth/me` response and independently confirm its
exact issuer and stable subject belong to the intended administrator. Do not
substitute an email address or copy identity headers from an untrusted request.

After approval to change the actual database, run this operator command from
`backend`, using the trusted operator-controlled `DB_*` settings. In the current
single-user deployment, `go_web_app` also owns the migration/bootstrap objects;
it is not a limited DML-only runtime role. A future split-role deployment would
use a separately authorized owner/bootstrap role:

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
in development. For OIDC, use the verified issuer and subject returned by the
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
as OIDC and historical Google IAP retain their original values. Audit payloads are explicitly
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

After updating dependencies, start the backend using the existing Local DEV or
OIDC configuration and run the frontend as usual:

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
Sign out uses the existing POST logout and session-clearing behavior. Local DEV
explains its fixed development identity and offers no logout action.

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
Phase 5 tests additionally cover issuer/subject matching, zero default privileges,
role and account isolation, CSRF and strict JSON, bootstrap races and the durable
one-time latch, runtime DB grants, immediate revocation, concurrent administrator
demotions, audit rollback, outages, and migration 4 upgrade/rollback preserving
existing authentication data. The bootstrap command is not run against live data.

## Minimal module registration (Phase 8.1)

Application modules are statically imported Go packages. `backend/module/module.go`
provides the small `Module`, `Manifest`, `Permission`, and `Registrar` contract.
`backend/server.go` contains the explicit catalog; no package-init hooks, runtime
plugin discovery or dynamic code loading is used. Phase 8.3 adds optional module
migration metadata and read-only startup checks.
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
writes. Local DEV remains available in development when RBAC and modules are
disabled, subject to the read-only database startup policy check.

For an already configured RBAC deployment, the optional example configuration is:

```dotenv
RBAC_ENABLED=true
ENABLED_MODULES=example
```

Before enabling `example`, manually install its version-1 schema using the Phase
8.3 instructions below. Change configuration with `vi .env` and restart through
the existing startup instructions. This does not register permission rows or grant access.
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
and two read-only endpoints, with an empty owned schema and no external integrations:

| Endpoint | Requirements |
| --- | --- |
| `GET /api/modules/example/info` | Verified identity, active registered framework user, and `example.read`. |
| `GET /api/modules/example/accounts/{account}/info` | The same, plus an explicit link to the active account in the path. |

Neither endpoint has a default grant, including for Admin. Once its required
migration is installed, an existing database will normally return 403 even after
enabling the example until permissions are explicitly provisioned. A permission must be declared
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

Phase 8.2 adds the shared mutation/audit adapter described below. Existing core
mutations retain their transaction-time checks, revocation lock, last-Admin
protection, and audit behavior. The shipped example still performs no writes.
Module migrations are managed independently as described in Phase 8.3 below.
There is no automatic permission provisioning, per-module role system, background
worker, or frontend module route registration.

Run `go test -race -count=1 ./...` and `go vet ./...` from `backend`, then
`npm test`, `npm run build`, and `npm run lint` from `frontend`. New tests cover
configuration/catalog validation, route conflicts, disabled modules, authenticated
capabilities, ungranted Admin access, declared/unknown permissions, account isolation,
revocation, write-origin protection, database outages, unchanged records on denial,
and composition with existing core routes. Integration tests use the existing
disposable PostgreSQL harness and the `go_web_app` runtime role, never root `.env`
settings or the actual development database.

## Shared module transactions and audit (Phase 8.2)

Register writes with `Registrar.AccountMutation` or `Registrar.GlobalMutation`.
These use the same paths, permissions, origin/JSON protections and authentication
as `AccountRoute`/`GlobalRoute`, which remain available unchanged. Mutation routes
accept POST, PUT, PATCH or DELETE, and a registration-time `module.AuditPolicy`.
They receive a `module.TransactionManager` as the third handler argument.
Only enabled modules receive managers; registration never provisions permissions
or grants them to any role, including Admin. `/api/modules` remains unchanged.

The public contract in `backend/module/transaction.go` deliberately removes
caller-selected permission, action, actor and account parameters:

```go
type TransactionManager interface {
    MutateAccount(context.Context, AccountMutateFunc) error
    MutateGlobal(context.Context, MutateFunc) error
}
// AccountMutateFunc receives the validated, route-bound account ID.
type AccountMutateFunc func(context.Context, Transaction, string) (string, AuditDetails, error)
type MutateFunc func(context.Context, Transaction) (string, AuditDetails, error)
```

`Transaction` exposes `Exec`, `Query`, and `QueryRow` methods. Query results use
a minimal `module.Rows` interface that also omits pgx's connection accessor.
Use positional scan targets; pgx `RowScanner` callbacks are rejected because they
receive raw connection-capable rows.
It does not expose `Commit`, `Rollback`, `Begin`, or the underlying connection.
The framework captures the verified issuer/subject and framework principal before
calling the handler, binds the registered permission/action/schema and path account,
and expires the manager when the request handler returns. Use `r.Context()` or a
derived context; an unrelated context or another request's manager is rejected.
A global manager cannot mutate accounts, and an account manager cannot mutate globally.
The callback receives the authorized account directly, even if request path values,
query parameters, or bodies are subsequently changed. No new UUID dependency is
needed: identifiers use the project's existing pgx UUID validation conventions.

For example, after declaring `example.items.write` in the module manifest:

```go
return routes.AccountMutation("POST", "/items/{item}", "example.items.write",
    module.AuditPolicy{
        Action: "example.item.updated",
        Fields: map[string]module.AuditField{
            "changed": {Kind: module.AuditBool},
        },
    }, updateItem)
```

Inside `updateItem`, validate and prepare `itemID` and `newValue`, then call:

```go
err := manager.MutateAccount(r.Context(),
    func(ctx context.Context, tx module.Transaction, accountID string) (string, module.AuditDetails, error) {
        tag, err := tx.Exec(ctx,
            `UPDATE example.items SET value=$1 WHERE id=$2 AND account_id=$3`,
            newValue, itemID, accountID)
        if err != nil { return "", nil, err }
        if tag.RowsAffected() != 1 { return "", nil, errors.New("target not found") }
        return itemID, module.AuditDetails{"changed": true}, nil
    })
```

Handle `err` using `errors.Is` and return the corresponding sanitized HTTP error,
or return 204 on success. Permission/account denials map to 403; missing identity
to 401; invalid account input to 400; timeouts to 504; database unavailability to
503; unexpected callback/audit failures to 500. Do not return raw SQL/callback
errors or log credentials/payloads.

This is an integration sketch, not an enabled business endpoint or migration.
For a global operation use `GlobalMutation`, a separately declared permission
such as `example.settings.write`, action `example.settings.updated`, and
`MutateGlobal`. Runnable account/global examples are in
`backend/internal/modules/transaction_integration_test.go`, using disposable test
tables, prepared parameters, and the `go_web_app` role.

Each call starts a five-second bounded transaction, takes the existing framework
advisory transaction lock, verifies the active actor against the captured identity,
and rechecks its explicit permission and (where applicable) active account link.
This shares the core mutation transaction helper and lock with administrative
revocations. Business writes and `framework.audit_log` insertion commit together;
callback errors, audit validation/insertion errors, cancellations and timeouts roll
back. Rollback cleanup has its own bounded context so a canceled request cannot
prevent cleanup. There are no automatic mutation retries. Statement execution respects the adapter's deadline even if a callback passes
`context.Background()`, as well as shorter statement deadlines/cancellation.

Audit actions must be namespaced to the registered module and contain at least
three segments, such as `example.item.updated`. Targets are required UUIDs.
Policies are copied at registration. Every approved field is required, and extra
fields are rejected. Allowed values are UUIDs, booleans, `int`/`int64`, or explicit
static enum labels. Free-form strings, nested objects, custom serializers, arbitrary
request bodies and complete external responses are not accepted. Field names and
enum labels must be reviewed as non-sensitive configuration; a generic map is not
assumed safe. Secret-bearing field names are rejected. The framework supplies
`account_id` for account events. Serialized details are limited to 4096 bytes and
are rejected rather than truncated. Raw database/callback errors are replaced with
stable `module.TransactionError` values (`errors.Is` works):

- `ErrUnauthenticated`, `ErrPermissionDenied`, `ErrAccountDenied`, `ErrInvalidAccount`
- `ErrScope`, `ErrTimeout`, `ErrCanceled`, `ErrUnavailable`, `ErrMutation`, `ErrAudit`

Perform external API calls, validation and data preparation **outside** the
transaction. Keep callbacks **inside** the transaction limited to prepared database
work; close query rows before returning. A context deadline cannot forcibly stop
arbitrary blocking Go code or external operations. Do not retain the transaction,
manager or context, spawn asynchronous callback work, or perform nested mutations.

Modules remain trusted compiled SQL authors. The adapter cannot parse arbitrary
SQL to prove tenant isolation or sandbox malicious code: every account-owned query
must explicitly constrain the supplied account ID, including INSERT ownership and
UPDATE/DELETE predicates. Never issue transaction-control SQL, access framework
security tables from callbacks, or bypass the adapter via another database pool.
The single database role is not a per-module isolation boundary. Registration and
code review must enforce these rules. Core and adapter mutations coordinate through
the advisory lock; direct operator SQL must also coordinate if concurrent with
application writes. A connection loss during COMMIT can leave the outcome unknown;
reconcile business/audit records before considering a retry.

No database changes are required for this adapter. Migrations 000001–000004 are
unchanged, and no module business tables are installed. Phase 8.3 supplies independent migration management. Future modules still need
reviewed, version-controlled migrations for their own data tables and explicit permission
rows/grants, applied manually after approval. Use the existing `framework.audit_log`
and existing `go_web_app` role; never introduce a second audit table.

## Independent module migrations (Phase 8.3)

Core SQL files `database/migrations/000001`–`000004` and the existing
`public.schema_migrations` journal are unchanged. Each persistent module has a
separate numbered migration sequence and journal:

```text
database/
├── migrations/                         # core: public.schema_migrations
└── modules/
    └── example/
        └── migrations/                 # example: public.schema_migrations_example
            ├── 000001_initial.up.sql
            └── 000001_initial.down.sql
```

Declare optional metadata in the compile-time manifest:

```go
module.Manifest{
    ID: "example",
    Permissions: []module.Permission{"example.read"},
    Migrations: &module.MigrationSpec{
        Schema: "example",
        Directory: "database/modules/example/migrations",
        RequiredVersion: 1,
    },
}
```

A nil `Migrations` value means no persistent schema requirement. To prevent
cross-module configuration mistakes, schema **must equal the module ID** and the
repository-relative directory **must be exactly** `database/modules/<id>/migrations`.
Absolute paths, traversal, URLs, alternative module/core paths, reserved PostgreSQL
schemas and nonpositive versions are rejected. Catalog metadata is validated even
for disabled modules and copied to prevent later mutation. Journal names are
always derived as `public.schema_migrations_<id>`; modules cannot supply or override
a journal name. `Registry.MigrationPlans()` returns copies for enabled modules only.
The runtime neither scans source directories nor executes migration files. Ship
reviewed SQL directories with the deployment tooling; binaries need no SQL files
for startup validation.

After the existing core checks, startup checks enabled persistent modules inside a
bounded, read-only, repeatable-read PostgreSQL transaction. It requires schema
existence/USAGE, a readable regular journal table in `public`, exactly one version
row, `dirty=false`, and an **exact version match**. Both older and newer versions
fail closed. A missing/empty/invalid journal, missing schema, dirty state, timeout,
or database error stops startup with a sanitized error. No journal is created and
no SQL files are applied. Disabled/stateless modules do not need schemas or
journals. Capability responses, permissions, authentication, RBAC and transaction
security are unchanged; the startup check never grants permissions.

### Manual operator workflow

Do not run the following against the live development, TEST or PRD database until
explicitly approved. Stop affected application instances for migration/deployment,
review the SQL and take an appropriate backup. Use the existing `go_web_app` role
for module migrations; no new user or database server is needed. The role needs
CREATE on the database and CREATE/USAGE on `public` to install its own schema and
journal. Have the database owner review/provision these privileges separately if
missing; this implementation never grants them automatically. It does not alter
permissions on the framework journal. The newly created module schema and journal
are owned by `go_web_app`. TEST/PRD still require production-safe database TLS.

From the repository root, with the existing `DB_*` settings exported in your shell:

```bash
export PGHOST="$DB_HOST"
export PGPORT="${DB_PORT:-5432}"
export PGDATABASE="$DB_NAME"
export PGUSER=go_web_app
export PGPASSWORD="$DB_PASSWORD"
export PGSSLMODE="${DB_SSLMODE:-verify-full}"
export PGSSLROOTCERT="${DB_SSLROOTCERT:-}"
```

Keep credentials out of command arguments, shell tracing, logs and source control.
Review local settings with `vi .env`; this documentation does not execute or load it.
Use the existing approved credential handling process to export its values.

Read-only status, including schema presence, current version and dirty state:

```bash
psql -X -v ON_ERROR_STOP=1 <<'SQL'
BEGIN READ ONLY;
SELECT EXISTS (SELECT 1 FROM pg_catalog.pg_namespace WHERE nspname = 'example') AS schema_exists,
       pg_catalog.to_regclass('public.schema_migrations_example') AS journal;
SELECT version, dirty FROM public.schema_migrations_example;
ROLLBACK;
SQL
```

A missing journal produces a relation-not-found error; it is not created by this
status command. A schema without a journal is untracked, not an installed version.
Before enabling the example, install the reviewed version 1 manually:

```bash
migrate -path database/modules/example/migrations \
  -database 'postgres://?search_path=public&x-migrations-table=schema_migrations_example' up 1

migrate -path database/modules/example/migrations \
  -database 'postgres://?search_path=public&x-migrations-table=schema_migrations_example' version
```

The [official golang-migrate PostgreSQL driver](https://github.com/golang-migrate/migrate/blob/master/database/postgres/README.md)
supports `x-migrations-table`; `search_path=public` applies only to this operator
connection so the driver places its selected journal in `public`. Application
requests do not modify their search path. Migration SQL uses fully qualified table
names. Never omit/substitute the journal option when migrating a module. Keep the
core operations on `scripts/migrate-framework.sh`, which fixes `database/migrations`
and `public.schema_migrations`. This forward-only core policy does not change the
separate, explicitly reviewed module rollback policy.
**Even `migrate version` may create a journal on first use**; use the psql read-only
status command for inspection before approval/installation.

For later module versions, review the current status and apply the intended number
of steps with `up N`, then deploy the binary with the matching `RequiredVersion`.
Do not use `goto` without checking the current version: it can migrate down.
The example's initial migration creates only its empty schema, without business
tables, permission grants or external integrations. Its optional approved rollback is:

```bash
migrate -path database/modules/example/migrations \
  -database 'postgres://?search_path=public&x-migrations-table=schema_migrations_example' down 1
```

The example rollback uses `DROP SCHEMA example RESTRICT` and fails if unexpected
objects remain. It never drops any migration journal. Future module rollbacks may
remove data: review each down migration independently. Disabling a module removes
its routes and readiness requirements, but leaves its schema, data and journal intact.

### Dirty-state recovery and boundaries

A dirty journal blocks startup and further migrations. Inspect the failed SQL,
version/dirty row and actual schema before taking action. Keep multi-statement
module DDL transactional (`BEGIN`/`COMMIT`) where PostgreSQL permits. After a failed
transactional upgrade from 1 to 2, first prove the database still matches version 1.
Only after approval, repair the SQL/schema and reconcile the module's marker:

```bash
# Example ONLY when inspection confirms that version 1 is the actual state:
migrate -path database/modules/example/migrations \
  -database 'postgres://?search_path=public&x-migrations-table=schema_migrations_example' force 1
# Then apply the reviewed repair/upgrade with the same module directory and journal.
```

`force` changes metadata; it does not repair or execute SQL. Never blindly force the
required version or touch `public.schema_migrations` to repair a module. The recovery
tests intentionally edit only disposable migration files, never deployed history.

Independent journals prevent accidental version/dirty-state collisions through the
migration infrastructure. SQL migrations remain trusted operator-reviewed code:
with a single database user, this is **not a database sandbox** against deliberately
cross-schema SQL. Review files (including any symlinks) for module-owned objects and
fully qualified SQL; never write framework/other-module journal tables in migration
SQL. Existing framework grants are unchanged. golang-migrate tracks version/dirty
state rather than checksums, and a startup version check does not inspect every
business table or continuously monitor schema drift. Avoid concurrent live migrations.

Tests use disposable PostgreSQL clusters and the real golang-migrate CLI, with
`go_web_app` for migration and readiness connections. They cover installation,
upgrade/rollback, separate numbering/journals, dirty and failed migration recovery,
missing/invalid state, disabled modules, read-only validation, and core/other-module
journal preservation. The CLI with PostgreSQL support and local PostgreSQL binaries
are required; tests explicitly skip if either tool is unavailable.

## Frontend module composition (Phase 8.4)

After `/api/auth/me` authenticates a session, the shell fetches `/api/modules`
with same-origin credentials, no response caching and abortable requests. It
intersects the returned enabled IDs with the explicitly compiled frontend catalog
in `frontend/src/modules/registry.ts`. Server responses cannot supply import URLs,
React code, translation contents or permission grants. Unknown valid IDs produce
a configuration warning and are ignored. Malformed responses, network errors or
module-loading failures leave only the core routes and show a translated warning.
An HTTP 401 uses the existing session-expiration behavior. No module route is
registered from catalog membership alone.

Each compiled module implements `FrontendModule` in `modules/types.ts`: an ID,
protected pages with a mandatory namespaced permission, and a translation bundle
for every supported language. Page paths must stay under `/modules/<id>/`, and
navigation labels use the module namespace. Public pages, missing/foreign/core
permissions, duplicate paths and invalid module IDs are rejected. The existing
`NavigationRegistry`, `ProtectedRoute`, sidebar and backend authorization remain
responsible for access checks; enabling a module is not a permission grant.

`composeModules` is asynchronous so its static import functions load only enabled
module definitions and their translations. It returns pages and an explicit
`registerTranslations` function; registration happens only after the request is
confirmed to belong to the current session. The active i18next instance receives
bundles under the module ID, separate from `common`, `auth` and `admin`. English
fallback, all twelve locales, Arabic RTL and the current MUI theme remain intact.
Module page components use `React.lazy` and the shell's existing Suspense boundary.

The example contributes `/modules/example/items`, guarded by **`example.read`**,
matching the backend manifest. It is a translated, read-only demonstration page;
there is no backend Items API, item persistence or CRUD implementation in this
phase. The module's translations live in twelve JSON files under
`frontend/src/modules/example/locales`. The existing independent example database
migration and explicit role permission grant are still required for a live setup;
no grants or database changes are made by the frontend.

To add another frontend module, implement its definition and lazy pages, provide
all twelve locale bundles with matching keys/placeholders, and add a literal import
function to the static catalog. Rebuild/deploy both compatible frontend and backend
versions. No runtime plugin loader is involved. Capability requests run after
successful authentication, not on ordinary navigation, language changes or access
refreshes. Sign-out/session changes immediately discard module routes, abort stale
requests and fetch capabilities for a subsequent authenticated identity. Loaded
translation strings may remain cached in memory; they contain no session data and
never authorize routes. Capability configuration changes during a session require
reloading/signing in again; there is no polling or automatic retry loop.

For local verification, use the existing startup instructions, explicitly enable
`example` only after its approved migration/grant setup, and open
`/modules/example/items`. A user without `example.read` gets the translated
access-denied view even if Admin. Disabled or unconfirmed modules have no registered
route. Browser route guards render an access-denied view; actual HTTP API 403s are
enforced by Go. Test network-failure fallback with browser request blocking, and
switch to Arabic to check the module label/page and RTL layout. These operations
require no frontend-specific migrations or credentials.

The current single database user, `go_web_app`, owns schemas and runs migrations.
Application RBAC and transaction boundaries remain enforced in Go, but database
DML-only/owner privilege separation is a future design, **not implemented security**.

## Framework Settings: Roles & Permissions (Phase 9.1)

Open **Settings → Roles & Permissions** as a user with `admin.manage`. The
existing Roles page remains a read-only overview. Settings sections are declared
in `frontend/src/pages/SettingsPage.tsx`; future authentication, module and
security sections can be added there when implemented. There are no placeholder
controls that pretend to change those settings.

The matrix uses actual PostgreSQL assignments for Admin, User and Viewer. Search
by permission or description and filter/group by framework or module. Missing
SQL definitions, disabled modules and database permissions absent from the
compiled catalog are marked explicitly. Registration is a separate, confirmed
administrator action for enabled module declarations only; it creates no role
grants. Existing `example.read` registrations/grants are preserved. Core
permissions cannot be recreated through this interface; a missing core definition
requires operator investigation.

Checkbox edits remain local until **Save permissions**, followed by confirmation.
**Cancel** discards them. Language changes preserve the draft. All 12 languages,
Arabic RTL, theme modes and existing Snackbar notifications are reused. Leaving
the page discards an unsaved draft. Future module descriptions are developer-owned
metadata: the existing core/example descriptions are localized; additional modules
must supply frontend translation keys to localize their descriptions.

New authenticated, `admin.manage`-protected endpoints:

| Endpoint | Behavior |
| --- | --- |
| `GET /api/admin/permissions` | Combined compiled/database catalog, role columns and opaque revision token |
| `POST /api/admin/permissions` | Register `{ "permission": "example.read" }`; returns HTTP 201 JSON confirmation, no grant |
| `PUT /api/admin/role-permissions` | Atomically apply up to 100 changed cells with the previously read revision |

Example update body (use the revision from the latest catalog response):

```json
{
  "revision": "<opaque revision from GET>",
  "changes": [
    { "role": "User", "permission": "example.read", "assigned": true }
  ]
}
```

`GET /api/admin/roles` remains unchanged. Writes require the existing exact Origin
and JSON protections. Unknown fields (including actor IDs), undeclared permissions,
invalid roles, duplicate cells and no-op cells are rejected. Disabled compiled
permissions may be revoked but cannot be newly registered or granted. Permissions
belonging to modules absent from the build are visible but read-only.

**Lockout policy:** `admin.manage` assignments cannot be changed by this API,
including grants to User or Viewer. The existing Admin assignment is preserved;
the last-active-Admin guard now also verifies that Admin holds `admin.manage`.
This phase does not implement administrative delegation or a new recovery bypass.
Any pre-existing incorrect critical grants require an explicitly approved operator
repair; startup does not silently rewrite them.

Every write rechecks the active administrator under the existing shared advisory
transaction lock. Assignment changes and fixed-field audit records commit together;
an audit failure rolls back the whole batch. Audit actions are `role.permission`
and `permission.register`; records contain the verified actor, permission, role,
before/after booleans and the existing database timestamp. Registration uses an
empty role because it changes catalog membership, not role assignment. No request
body or identity supplied by the browser is copied into audit details.

The revision covers catalog state and assignments plus the latest permission-audit
sequence. Concurrent edits, including an API edit-and-revert, reject stale revisions
with HTTP 409 instead of overwriting changes. On conflict, cancel the preserved
local draft, refresh, review the current assignments and retry deliberately.
Permission changes take effect at backend authorization checks immediately; other
open browser sessions may need **Refresh access** or reload to update navigation.

No new schema migration is required, and migrations 000001–000004 are unchanged.
The current single `go_web_app` database user owns schemas/tables and runs migrations;
this is not database least-privilege separation. This phase needs INSERT on
`framework.permissions` and INSERT/DELETE on `framework.role_permissions`, which
ownership already permits. A deployment with different ownership needs separately
approved grants; the application never grants privileges at startup. Direct owner
SQL can bypass these application controls and must be handled as a trusted operator
action. Conflict handling assumes application writes use the shared protocol.

Local checks use the existing commands:

```bash
cd backend
go test -race -count=1 ./...
go vet ./...
cd ../frontend
npm test
npm run build
npm run lint
cd ..
git diff --check
```

Integration tests use disposable PostgreSQL clusters. To try the UI locally, start
the application using the existing instructions and visit `/settings` with an
already authorized administrator. Saving/registering against the actual development
database is a live mutation and requires your explicit approval.

## Authentication configuration storage and administration (Phases 9.2.1–9.2.4)

This is **management-only configuration storage**, not a new authentication source.
The Phase 9.2.2 admin APIs use the Phase 9.2.1 repository and encryption. Runtime
`AUTH_PROVIDER`, provider startup and sessions continue using environment settings.
Phase 9.2.3 adds a management UI under Settings → Authentication. There is no
activation method, provider switching, background polling or LISTEN/NOTIFY.
Phase 9.2.4 adds a separate, explicitly initiated OIDC test handshake. Migration 000005 seeds no configuration or active state.
The existing admin, RBAC, account and module APIs retain their behavior.

### Versioned storage and scope

Migration `000005_auth_configuration.up.sql` creates two framework tables:

- `framework.auth_config_revisions`: immutable UUID, deployment/environment,
  monotonically increasing configuration version within that scope, provider,
  issuer URL, client ID, callback URI, legacy IAP audience, explicit loopback-HTTP
  development flag, encrypted secret envelope, creator and creation timestamp.
  PostgreSQL rejects UPDATE and DELETE, including edits to ciphertext or key IDs.
- `framework.auth_config_lifecycle`: revision-bound status, optimistic generation,
  last actor, timestamps for validation/approval/activation/supersession, and
  strictly allowlisted validation metadata. A composite foreign key prevents
  cross-scope lifecycle records. A partial unique index permits at most one
  `active` revision per deployment/environment. The active revision is obtained
  from this indexed state, without a second mutable pointer that could disagree.

All timestamps are `TIMESTAMPTZ`. Provider-specific checks reject mixed settings,
missing/malformed encryption envelopes, invalid providers and Local DEV outside
`development`. Application validation supports OIDC and Local DEV; historical IAP
revisions remain readable but cannot be validated or approved. Local DEV identity values remain environment-configured;
this foundation stores its provider choice only, not a replacement local identity.

`AUTH_CONFIG_DEPLOYMENT` is a required, explicit deployment identifier for the
repository (`[a-z][a-z0-9_-]{0,63}`). Scope also includes canonical `APP_ENV`:
`development`, `test` or `production`; existing TEST/PRD aliases are normalized by
`ScopeFromEnv`. Scope is bound by trusted composition code, never request JSON.
Use distinct deployment IDs and encryption keys for DEV, TEST and PRD. Separate
production databases are preferable: scoped queries and authenticated encryption
are not database-role isolation when the same owner can access all rows.

### Encryption and key custody

`CipherFromEnv` requires both `AUTH_ENCRYPTION_KEY` and `AUTH_ENCRYPTION_KEY_ID`.
The key is **exactly 32 cryptographically random bytes**, encoded as canonical,
padded RFC 4648 standard base64 (44 characters, no surrounding whitespace or
newline). The non-secret key ID matches `[A-Za-z0-9][A-Za-z0-9_-]{0,63}`. Missing,
malformed, wrong-length and trivially constant keys fail closed; no replacement
key is generated. Structural validation cannot prove that an operator generated
key bytes randomly. Do not use passwords, repeated values or hashes of passwords.

Format 1 uses standard-library AES-256-GCM: a fresh random 12-byte nonce per
secret, ciphertext followed by the 16-byte authentication tag, explicit format
version and key ID. Secrets are limited to 4096 bytes. AAD is a stable format-v1
JSON structure binding the purpose `gwf.auth-config.oidc-client-secret`, format,
key ID, deployment/environment, revision UUID, configuration version, creator and
all non-secret provider settings. Lifecycle status is excluded so validation does
not require re-encryption. Moving ciphertext to another revision or deployment,
or changing authenticated settings, makes decryption fail.

For an operator-managed key, an example generation command that does **not print
key material** is shown below. Run only when provisioning the intended deployment;
choose a new path and retain a secure backup. Never overwrite a key used by existing
revisions. These are manual instructions, not application startup behavior:

```bash
set +x
umask 077
mkdir -p ../secure/auth-config
# noclobber prevents accidentally replacing an existing key file.
(set -C; openssl rand -base64 32 > ../secure/auth-config/dev-key-v1.base64)
export AUTH_ENCRYPTION_KEY="$(cat ../secure/auth-config/dev-key-v1.base64)"
export AUTH_ENCRYPTION_KEY_ID=dev-key-v1
export AUTH_CONFIG_DEPLOYMENT=framework-local-dev
```

Keep this file outside Git and use deployment-managed secret injection in TEST/PRD.
Do not paste keys into tickets, logs or command-line arguments. Use `vi .env` only
if choosing the existing ignored local environment file; never edit `.env.example`
to contain real keys. Environment variables and process memory still require host
access controls.

**Rotation design:** retain the old key under its original ID, provision a fresh
random key and new ID, and construct separate trusted old-key reader/new-key
writer repositories for the same scope. An authorized `ReadSecretPrivileged`
followed by `CreateDraft` re-encrypts into a new immutable revision with a fresh
nonce. Tests cover this sequence. Nothing becomes active in this phase. A future
reviewed activation workflow must validate, approve and switch revisions safely.
Do not re-encrypt old rows in place or reuse an ID for different key bytes. Retain
all old keys needed for historical recovery in secure backup; retire keys only
under an explicit retention policy. Rotate well before GCM's per-key message
limits, and use a new key after suspected compromise.

**Recovery:** restore matching database and key backups together and verify the
correct deployment, key IDs and revision metadata. If a historical key is lost,
its secrets are unrecoverable; re-enter the credential into a new draft using a
new key after operator review. Never silently fall back to a new key, plaintext,
or another deployment's credentials. There is no automated rotation/recovery CLI
or multi-key keyring in this phase; old-key access uses an explicitly constructed
repository with that historical key.

### Repository and authorization contract

`backend/internal/authconfig` exposes:

| Operation | Behavior |
| --- | --- |
| `CipherFromEnv`, `ScopeFromEnv`, `NewRepository`, `RepositoryFromEnv` | Server-owned management construction; never a runtime provider loader |
| `LatestVersion(ctx)` | Version to use for optimistic draft creation; zero when empty |
| `CreateDraft(ctx, expectedLatestVersion, settings, secret)` | Append a new revision and initial lifecycle row atomically |
| `Read(ctx, id)` / `List(ctx, beforeVersion, limit)` | Secret-free metadata; descending keyset pagination, limit 1–100 |
| `Transition(ctx, id, expectedGeneration, status)` | Only draft → validated → approved; increments generation |
| `CurrentActive(ctx)` | Indexed active metadata, or `ErrNotFound` when none exists |
| `ReadSecretPrivileged(ctx, id)` | Audited, privileged secret retrieval; never an HTTP response |

Every operation requires verified authentication plus framework principal context
and an active `admin.manage` grant. The shared access-store advisory-lock and audit
helpers are reused; actor identity and authorization are rechecked inside the
transaction. Calls have a five-second maximum deadline, respect cancellation, use
parameterized, qualified SQL and release resources after rollback. Errors are
fixed, recognizable values without database internals or secret contents. There
are no uncontrolled mutation retries.

Creation compares the expected latest version under the lock. Lifecycle updates
compare the revision generation; stale writers get `ErrConflict`. Audit records
and writes commit atomically. Secret retrieval records `auth_config.secret_access`
and returns no secret if audit insertion or commit fails. Other audit actions are
`auth_config.draft_created`, `auth_config.validated` and `auth_config.approved`.
Audit details contain only configuration version, generation and status.

`Secret` is an opaque wrapper whose standard formatting is redacted and whose JSON
serialization fails. `Bytes()` is an explicit trusted-code escape hatch; never log,
persist or serialize those bytes. The repository's metadata types cannot contain
ciphertext, nonce or plaintext. Tests exercise redaction, tampering and rollback.
Go does not guarantee erasure of every key/plaintext copy from memory or crash dumps.

Validation currently records only `{ "check": "static", "version": 1 }`, generated
internally. It proves syntax/envelope validation, not provider reachability, OIDC
login success or deployment safety. Approval is an explicit administrator action;
a separate-approver policy and runtime secret-reader authority remain future design
questions. Active/superseded states are constrained in SQL for future work, but no
repository method can enter them. SQL fixture tests alone exercise active uniqueness.

### Management APIs (Phase 9.2.2)

The server registers these routes; every route requires verified authentication,
an active framework user and `admin.manage`. POST requests require the exact
`APP_ORIGIN` and `Content-Type: application/json`. Bodies use the shared 16 KiB,
unknown-field/trailing-JSON-rejecting decoder. Actor, deployment, environment,
validation results and lifecycle status cannot be supplied by the caller.

| Method | Path | Behavior |
| --- | --- | --- |
| GET | `/api/admin/auth/settings` | Descending revision metadata; `limit` defaults to 50 (1–100), optional nonnegative `before_version` |
| GET | `/api/admin/auth/settings/{id}` | One revision's metadata within the server's deployment/environment |
| POST | `/api/admin/auth/settings` | Append an immutable draft; 201 with metadata and a `Location` header |
| POST | `/api/admin/auth/settings/{id}/validate` | Offline/static validation only; 200 with incremented generation |
| POST | `/api/admin/auth/settings/{id}/approve` | Explicit approval of a validated revision; 200 with incremented generation |
| GET | `/api/admin/auth/status` | Environment-backed runtime provider plus separate latest/active database revision metadata |

Configure `RBAC_ENABLED=true`, the existing database/origin settings,
`AUTH_CONFIG_DEPLOYMENT`, `APP_ENV`, `AUTH_ENCRYPTION_KEY_ID` and
`AUTH_ENCRYPTION_KEY` using the key custody instructions above. Migration 000005
must already be installed through the approved manual workflow; these APIs never
apply migrations. Configuration is read at process startup. As of Phase 9.2.5D,
missing/invalid scope or unreadable startup policy stops startup (migration 000006
is required). Missing/invalid encryption configuration still makes the protected
management service return 503 without replacing the environment login provider. Missing tables, database outages,
audit failures and unavailable historical encryption keys likewise fail closed.
No replacement key or runtime provider is created automatically.

OIDC draft request shape (placeholder only; never put real secrets in source,
shell history, request logs or monitoring payloads):

```json
{
  "expected_latest_version": 0,
  "provider": "oidc",
  "issuer_url": "https://idp.example.invalid",
  "client_id": "application-client",
  "client_secret": "<new OIDC client secret>",
  "redirect_uri": "https://app.example.invalid/api/auth/callback",
  "allow_http_development": false
}
```

`expected_latest_version` is required: use zero when no revisions exist, otherwise
use the highest version from the first list page or status's `latest_revision`.
A stale value yields 409; refresh and review before retrying. A new OIDC draft
always requires a nonempty client secret; no implicit copying of stored secrets.
Google IAP drafts are no longer accepted; historical revisions remain readable.
Local DEV drafts use `provider: "local_dev"` and are allowed
only in `APP_ENV=development`; local identity values remain environment-owned.
HTTP callback allowance is confined to existing loopback development rules.

Validation and approval bodies are `{ "expected_generation": 1 }`, using the
revision's current generation (normally 2 for approval after initial validation).
A stale generation yields 409; an invalid lifecycle step, such as approving a
draft directly, yields 400. Approval is audited and **does not activate anything**.
Validation records only `{ "check": "static", "version": 1 }`; it does not test
OIDC discovery, JWKS, credentials, token exchange or browser login.

List responses are `{ "revisions": [], "next_before_version": 0 }`. A nonzero
cursor can be used for the next page; the last full page may lead to an empty page.
Metadata includes `has_secret` but never a client secret, nonce or ciphertext.
There is no HTTP secret-reading, update-in-place, deletion or activation endpoint.
All management responses use JSON and `Cache-Control: no-store`.

Status returns `runtime_provider`, `runtime_source: "environment"`,
`management_only: true`, `validation_mode: "offline_static"`, `latest_revision`
and `database_active_revision`. Revision fields are null when absent. Even an
existing database `active` row is reported separately and is not loaded into the
running provider. Drafts/approvals never change login behavior.

Call `/api/admin/auth/status` without query parameters. Supplying a deployment,
environment or cache-busting parameter returns 400 `auth_config_invalid` before
the repository is called; scope comes from server configuration. Use a request
`Cache-Control: no-cache` header if needed, rather than adding a query parameter.
An empty configuration store is valid: status returns 200 with both revision
fields null and the environment-backed runtime provider unchanged.

Errors use `{ "error": "..." }`: 400 invalid input/configuration, 401 unauthenticated,
403 denied, 404 unknown or out-of-scope revision, 409 version/generation conflict,
and 503 unavailable configuration/database service. Existing authentication and
access middleware retain their JSON error conventions; management errors use
`auth_config_invalid`, `auth_config_not_found`, `auth_config_conflict` and
`auth_config_unavailable`. SQL, submitted secrets and cryptographic diagnostics
are never included. Authorization is rechecked inside the shared advisory-locked
`AdminTransaction`; mutation and audit commit or roll back together.

The current policy allows the same authorized administrator to create, validate
and approve a revision. Separate approvers, activation, and runtime keyring/rotation management remain
future reviewed phases.

### Authentication Settings UI (Phase 9.2.3)

Open `/settings` as an active user with `admin.manage`, then select
**Authentication**. **Roles & Permissions** remains the default tab and retains
unsaved edits while switching tabs. The Authentication panel loads on demand.
It supports all twelve languages, Arabic RTL and the existing appearance modes.

- Runtime provider/source are displayed separately from the latest and active
  database revisions. Drafts and approvals never alter environment-based login.
- Create an immutable OIDC or Local DEV draft. OIDC requires a newly
  entered secret every time; there is no copy-secret option. The password field
  offers an explicit visibility toggle. Secrets are not written to browser
  storage or the query cache and are cleared on submission, provider changes,
  and leaving the Authentication tab. JavaScript cannot guarantee memory erasure.
- Browse history in pages of twenty and open a revision to fetch its metadata.
  Only a secret-present indicator is displayed for stored credentials.
- **Validate settings** performs offline structural validation only. **Approve
  revision** requires confirmation and records approval without activation.
  Writes include the server version/generation. A 409 refreshes the current
  status/history/selected revision and shows a warning; writes are never retried
  automatically. Review the refreshed state and re-enter a secret before retrying
  OIDC draft creation.
- Errors use localized inline messages and the existing global Snackbar. Raw
  backend error text and cryptographic details are never rendered.

Development-only controls require trusted evidence: a stored revision's
`environment`, or the running `local_dev` provider when history is empty. The
current status contract does not report the environment separately. With OIDC
and no history, the UI conservatively disables Local DEV and HTTP callback
allowance. A future API capability can remove this limitation without trusting
browser-provided environment flags. The backend remains the authorization and
configuration-validation authority.

For local review, start the backend with its existing environment configuration
(`cd backend && go run .`) and the frontend (`cd frontend && npm run dev`), then
visit `http://127.0.0.1:5173/settings`. Use the existing HTTPS workflow if configured.
The management API prerequisites above must already be installed/configured; the
UI never runs migrations. Viewing status/history is read-only. Creating,
validating or approving a draft writes management records and audit events to
the configured database, so use a disposable environment for interactive tests.

Test Connection is implemented in Phase 9.2.4 below. Activation and rollback
remain reserved for Phase 9.2.5, with no operational controls or requests.
Frontend tests mock all HTTP requests; they do not contact an identity provider
or the live database. Automated responsive/RTL tests use a DOM environment;
visual review in a real browser is still advisable.

### Isolated OIDC connection tests (Phase 9.2.4)

Select an **approved OIDC revision** under Settings → Authentication, open its
metadata, and choose **Test Connection**. Allow the popup and sign in to the
provider. The main window polls only this explicitly started operation and shows
its revision, result, callback URL, and verified issuer/subject. Success proves
only that particular identity authenticated with that immutable revision and
generation. It does not prove that other users can log in or have application
access. No provider is activated, and the tested identity is never registered as
a framework user, assigned roles, or issued an application session.

The test callback is **`APP_ORIGIN` + `/api/auth/test/callback`**, separate from
normal `/api/auth/callback`. For the current local origin, add this exact URL to
the Auth0 application's **Allowed Callback URLs** before live testing:

```text
http://localhost:5173/api/auth/test/callback
```

Keep the existing normal-login callback
`http://localhost:8080/api/auth/callback`. Visit the portal through
`http://localhost:5173` consistently; `localhost` and `127.0.0.1` are different
cookie origins. Vite's existing `/api` proxy forwards the test callback to Go.
If `APP_ORIGIN` changes, allowlist its exact test callback instead. HTTPS is
required outside development; local HTTP also requires the approved revision's
HTTP-development allowance. The test deliberately substitutes its isolated
callback for the stored normal callback, so success does **not** verify the
normal callback's provider allowlisting. Configure the stored issuer using the
provider's exact issuer, including its trailing slash. Client credentials come
only from the encrypted approved revision, never frontend variables or code.

| Method | Endpoint | Behavior |
| --- | --- | --- |
| POST | `/api/admin/auth/settings/{id}/test` | `{ "expected_generation": 3 }`; checks approved OIDC revision, audits start, validates discovery/JWKS, returns test metadata and a pending authorization URL |
| GET | `/api/admin/auth/tests/{test_id}` | Returns safe result metadata to the initiating, still-authorized administrator only |
| POST | `/api/admin/auth/tests/{test_id}/cancel` | `{}`; cancels pending work, records an audit result, clears the test cookie |
| GET | `/api/auth/test/callback` | Public one-time callback, correlated with the originating browser; never an application login endpoint |

All administration endpoints retain verified authentication, active user and
`admin.manage` checks; writes require the configured Origin and JSON. The shared
advisory-locked administrator transaction rechecks the actor and exact revision
generation before releasing credentials, before exchange and before publishing
success. A different administrator cannot inspect or cancel another's operation.
Neither the actor nor deployment scope can be supplied by request JSON. Start
and finish audit events use `auth_config.test_started` and
`auth_config.test_finished`; details contain test ID, version, generation, fixed
outcome, and a hash of verified issuer/subject on success. Tokens, codes, client
secrets, raw provider responses and tested email are never audited. If final
revalidation or audit insertion fails, the UI must not receive success.

Tests use random state, nonce, PKCE S256 and a separate per-test HttpOnly,
SameSite=Lax browser-binding cookie (Secure with HTTPS). They consume callback
state before the token exchange, so concurrent/replayed callbacks cannot exchange
again. The existing OIDC identity verification helper and maintained OAuth2/OIDC
libraries check signatures, issuer, audience, nonce, authorized party and expiry.
Test cookies never overwrite normal login/session cookies. Popup pages have no
opener access; result polling does not trust cross-window messages. Closing the
popup, cancelling, or leaving the panel cancels pending tests where possible;
server expiry remains authoritative if a browser closes or loses connectivity.

Outbound requests use a dedicated HTTPS client: no environment proxy, no
redirects, port 443 only, DNS checks rejecting private/loopback/link-local/metadata
and special-purpose ranges, and dialing the already-checked numeric address
while retaining hostname TLS verification. All resolved addresses must be public;
new connections recheck DNS. Authorization, token and JWKS endpoints must share
the approved issuer origin. The test accepts RS256 (RSA at least 2048 bits) and
ES256 (P-256), requires advertised PKCE S256, and currently uses
`client_secret_basic`. Providers with split endpoint origins, nonstandard ports,
other algorithms/authentication methods, or omitted S256 metadata fail closed
rather than silently relaxing these restrictions. Keys are checked during
initial discovery and refreshed before exchange, supporting key rotation.
Responses are bounded to 1 MiB, headers to 64 KiB, with three-second connection/TLS,
five-second response-header and ten-second HTTP timeouts. Existing admin middleware
also bounds start requests to five seconds; callbacks have a twenty-second ceiling.
No external call runs inside a database transaction and failed exchanges are not
retried automatically.

No migration is needed. Test state is process-local, with five-minute validity,
a maximum of 64 retained operations and three pending tests per administrator.
Expired entries are removed lazily after a further five minutes; secrets and
verified identity metadata are never persisted as test-state rows. Successful
start/result audit records remain in the existing database audit table. A restart
invalidates pending tests and makes result IDs unavailable. Multi-instance hosting
requires routing the whole test to the same process; shared persistent test state
is a future change. Abandoned tests may have only a start audit event if expiry is
never observed; database/audit outages cannot guarantee a terminal audit event.
The UI will report failure/unavailability rather than invent a successful result.
JavaScript and Go garbage collectors do not guarantee immediate string erasure.

The backend's DNS/IP restrictions protect its own requests; it cannot control the
browser's DNS or a provider's subsequent browser redirects. Trusted administrator
review of issuers, network egress restrictions and DNS policy remain appropriate.
Configure reverse proxies and observability tools to omit query strings on both
OIDC callback routes and redact authorization URLs, cookies, request bodies and
provider responses. The application does not log these values. Provider-side SSO
cookies may be affected by the user's explicit test login, but framework sessions
and runtime authentication configuration remain unchanged.

Automated tests use synthetic signed tokens, mocked discovery/token/JWKS endpoints
and disposable PostgreSQL clusters. Running the test suite never contacts Auth0
or reads its stored credentials. Live tests create management audit events and
contact the configured provider; initiate those only after operator approval.

### Manual migration and regression checks

**Approval is required before applying 000005 to the actual database.** Review and
back up the intended database first. Use the existing protected `PG*` environment
setup described above; never put credentials in the URL. Inspect the current
`public.schema_migrations` state before mutation. For a clean version-4 deployment,
from the repository root:

```bash
./scripts/migrate-framework.sh version
# Only after approval and confirming clean version 4:
./scripts/migrate-framework.sh up 1
./scripts/migrate-framework.sh version
# Expect clean version 5. Never run a blanket down or force to bypass an error.
```

**Supported core rollback policy: forward-only.** Use `scripts/migrate-framework.sh`
for all normal core operations. It accepts only `version` and `up N` (an explicit
positive number of steps). It rejects `down`, `goto` (even upward targets), `force`,
`drop`, negative/zero counts and extra options **before invoking golang-migrate or
connecting to PostgreSQL**. A refused rollback leaves both the installed schema
and the clean version-5 journal unchanged. There is no destructive rollback switch,
environment override or automatic journal repair. Review the SQL and step count
before any approved `up N`; normal golang-migrate locking and dirty-state checks
still apply. `version` delegates to golang-migrate and may create a journal on first
use; use the read-only psql inspection pattern above if this is not acceptable.

Production rollback means deploying an application version verified compatible
with the installed schema, leaving the journal untouched, or applying an approved
forward corrective migration that retains authentication history and credentials.
An older binary that requires an older schema is not a supported rollback target.
No migration runs automatically at application startup.

Migration 000005's `.down.sql` is a **refusal guard**, not a no-op. A direct CLI
rollback that bypasses the wrapper fails visibly and preserves all version-5
objects/data. golang-migrate sets the target dirty before running SQL, so such an
unsupported bypass leaves a **dirty version 4**, not a falsely clean version 4.
Removing the down file is not a solution: golang-migrate treats a missing direction
as an empty migration. The supported wrapper prevents that journal write entirely.
The SQL guard cannot leave version 5 clean when invoked through raw golang-migrate.

Recovery is a separate, explicitly approved operator procedure, not a wrapper
command. If the old no-op from commit `36d48b5` already produced clean version 4
with version-5 objects, or a raw rollback left a dirty target: stop migration and
release automation, back up the database and encryption keys, and inspect the
actual schema, constraints, triggers, configuration history and journal. Do not
continue down or replay 000005 against existing objects. Only after confirming the
complete version-5 schema is intact may an operator approve a one-time journal
reconciliation to version 5 with the underlying tool. Partial schemas require a
reviewed recovery plan; never guess a version or delete authentication history to
make replay succeed. This update does not repair existing databases automatically.

The wrapper is an operational control, not a database privilege boundary: the
current schema owner can bypass it, edit SQL, run raw `force`/`drop`, or alter the
journal manually. Deployment procedures must use the wrapper and serialize
operator changes. Real migration failures or interrupted processes can still leave
a dirty journal, requiring inspection rather than automatic repair.
Migrations 000001–000004 and `public.schema_migrations` placement are unchanged.
The current single `go_web_app` owner runs migrations; explicit grants also support
non-owner test fixtures. Owner privileges can disable triggers or modify audit
history, so this is not database least-privilege separation or protection against
a compromised application process holding both database access and keys.

Run `go test -race -count=1 ./...` and `go vet ./...` from `backend`, then
`git diff --check` from the root. PostgreSQL tests use only disposable clusters.
The command-policy test proves unsupported arguments never invoke golang-migrate
and accepted commands retain the fixed path/journal and propagate exit status.
The CLI integration test checks 4 → 5 and refused rollback with the journal still
clean at 5, for both empty and populated configurations. It verifies retained
history, encrypted credentials, decryption, active tracking and immutability, and
checks the visible dirty failure of an unsupported direct CLI rollback. CLI tests
explicitly skip if golang-migrate or PostgreSQL test binaries are unavailable.
Historical session rollback tests use a separate version-4 fixture so the
forward-only version-5 history is never discarded.

## Authentication activation persistence (Phase 9.2.5B)

Phase 9.2.5C adds a [request-consistent runtime dispatcher](docs/auth-runtime-dispatcher.md).
Later Phase 9.2.5 work adds internal controlled OIDC activation, startup
rehydration and multi-instance reconciliation. No public activation or rollback
endpoint is enabled, so operators cannot switch providers through the application.

Migration 000006 adds deployment activation heads, immutable transition history,
durable test evidence and explicit session/flow bindings. It creates no active
provider, enrolls no deployment and leaves environment-driven authentication
unchanged. The internal keyring remains compatible with existing single-key
configuration. Phase 9.2.5D now uses the policy for read-only startup enforcement
and persists successful isolated connection-test evidence; provider activation
remains disabled.

See [the persistence design, compatibility policy, keyring format and manual
migration instructions](docs/auth-activation-persistence.md). Apply only after
approval; the supported migration workflow remains forward-only.

## Administrator identity enrollment and startup protection (Phase 9.2.5D)

See [the enrollment workflow and startup policy](docs/auth-identity-enrollment.md).
Settings → Authentication now supports an explicit role grant for the identity
verified by a fresh successful approved-revision OIDC connection test. No user or
role is created by the test itself, and identities are never linked by email.

`POST /api/admin/auth/settings/{id}/enroll` requires `admin.manage`, the original
test administrator, same-origin JSON and explicit confirmation. It accepts only
`evidence_id`, `expected_generation`, `role` and `confirm`. Supported roles are
`Admin`, `User` and `Viewer`; existing roles are retained. Enrollment and both
identity/role audit events commit atomically. No new migration is required.

Startup always checks the trusted deployment/environment policy before preparing
an environment provider. Database-required policy is rehydrated read-only using
the configured encryption keyring and hardened OIDC discovery/JWKS verification.
Failure to load the required runtime stops startup. Missing or unreadable policy storage is never a
reason to start Local DEV. There is no fallback flag or activation endpoint.

## Controlled OIDC activation foundation (Phase 9.2.5E)

The [internal activation and recovery guide](docs/auth-controlled-activation.md)
documents prepared snapshots, revision-bound sessions/flows, isolated normal-callback
readiness tests, transactional activation, bounded draining, transport cleanup and
recovery through a fresh immutable revision. There are no activation or rollback
HTTP endpoints, and the existing portal cannot switch providers. No new migration
is needed. Startup restores the committed generation and any still-permitted
draining provider without extending deadlines or modifying history. PostgreSQL
LISTEN/NOTIFY now reconciles committed changes across instances, with authoritative
SQL admission checks during synchronization failures. The public operator activation
workflow remains a blocker before live activation.
See the guide for startup limits and the optional `AUTH_ENCRYPTION_KEYS_JSON` keyring.

## Authentication synchronization (Phase 9.2.5F)

Each instance subscribes on a dedicated PostgreSQL connection before reconciliation,
then waits for transaction-scoped activation notifications. Reconnects reconcile
again; there is no continuous configuration polling. Notifications contain only
scope and a generation hint. Verified database state remains authoritative.

The listener preserves the last verified snapshot on temporary failure, while
session/flow SQL and environment admission checks prevent stale-provider bypasses.
Initial cutover still requires reauthentication; later drains retain their recorded
maximum thirty-minute deadline. Retired IAP configuration fails startup. See the
[listener, failure policy, internal status and clock requirements](docs/auth-controlled-activation.md#event-driven-multi-instance-synchronization-phase-925f).
Allow one additional session-affine PostgreSQL connection per instance. There are
still no public activation or rollback endpoints, and no migration is needed.

## Offline emergency authentication recovery (Phase 9.2.5G)

Migration 000007 and the dedicated `backend/cmd/auth-recovery` command provide an
offline, explicitly authorized OIDC recovery path without fabricating a framework
user. Recovery accepts only a separately prepared, validated and approved immutable
recovery revision, performs hardened OIDC preparation, records operator evidence,
history and lifecycle changes atomically, and emits the existing transaction-scoped
notification. It gives the retired provider no additional session grace.

See [the recovery authorization, migration and command procedure](docs/offline-auth-recovery.md).
No HTTP recovery endpoint or Local DEV fallback is introduced.

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
