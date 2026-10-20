# Isolated Local DEV to Auth0 rehearsal

**Phase 10.2C compatibility:** this historical schema-7 rehearsal cannot complete
first activation with the new policy-enforcing backend. OIDC now requires
migration 000008, an initialized policy and an eligible approved administrator.
The current policy bootstrap proves an already active database-bound OIDC
administrator session; candidate-bound bootstrap for a fresh first cutover is
still required. Do not bypass that guard or fabricate approval to continue this
procedure. See [OIDC access policy rollout](oidc-access-policy.md).

This procedure is for **development testing only**. It creates a new PostgreSQL
database and a separate activation deployment. It neither copies the existing
development authentication history nor changes its approved Auth0 Revision 2.
It is **not** a production emergency-recovery procedure. The current offline
recovery command cannot restore Local DEV after a first cutover; see
[offline-auth-recovery.md](offline-auth-recovery.md) before treating any rehearsal
as a production recovery plan.

## Prerequisites and isolation

- PostgreSQL 14, the existing `go_web_app` role, `psql`, `createdb`, `dropdb`,
  `migrate`, `openssl`, `curl`, `jq`, Go, and frontend dependencies.
- Local `sudo -u postgres` access and PostgreSQL peer authentication over a
  Unix socket. Run `sudo -v` before setup, checks, or cleanup; the scripts use
  `sudo -n` and fail if authorization is unavailable. By default they use
  `/var/run/postgresql` and port 5432. Set `REHEARSAL_PG_SOCKET_DIR` and
  `REHEARSAL_PG_PORT` explicitly if the local server uses another socket/port.
  Existing `PGHOST`, `PGUSER`, `PGPASSWORD`, `PGDATABASE`, and other `PG*`
  variables are ignored by these scripts.
- Loopback TCP authentication for `go_web_app` on the same PostgreSQL port.
  Administrative commands use the Unix socket as `postgres`; migrations and
  the Go application connect as `go_web_app` over `127.0.0.1` with its existing
  password. Setup refuses to infer that password from ambient credentials.
- The existing `go_web_app` password for the **rehearsal migration only**.
  Setup prompts without echoing it, or accepts the explicit
  `REHEARSAL_DB_PASSWORD` environment variable. It never reads the development
  `.env` or an ambient `PGPASSWORD`.
- Ports **18080** (Go) and **15173** (Vite) free on `127.0.0.1`. Run exactly
  one Go instance and one Vite instance for this deployment. Do not expose
  Local DEV through a proxy, tunnel, port forward, or public listener.
- A dedicated Auth0 **Confidential Web Application** is recommended. Keep its
  client ID and secret in the local rehearsal configuration only. The scripts
  never create or modify Auth0 applications.

The database name is fixed as `go_web_framework_auth0_rehearsal`, and the
deployment ID is fixed as `auth0-rehearsal-local`. Setup refuses an existing
database or local configuration file. It writes a unique marker into a database
comment and the generated, Git-ignored environment file; cleanup requires both
to match. The file is mode 600 and contains a fresh random rehearsal-only
encryption key. The key is never printed. Existing `.env` files are untouched.

## Create the isolated database

From the repository root, in a terminal with **local** PostgreSQL administrator
access (not the development application's `DB_*` configuration):

```bash
sudo -v
./scripts/rehearsal/setup.sh
vi scripts/rehearsal/.env.rehearsal.local
```

Setup creates only the fixed rehearsal database, runs framework migrations
000001–000007 as `go_web_app` through `scripts/migrate-framework.sh`, and verifies a clean
`public.schema_migrations` version 7. It does not run module migrations,
create framework users or revisions, or activate authentication. Set
`DB_PASSWORD` for the existing `go_web_app` role in the generated file. Do not
copy passwords, Auth0 secrets, or encrypted revisions from the development
database. The `postgres` role creates the new database with `go_web_app` as its
owner and revokes the default PUBLIC database grant. `go_web_app` gains no
cluster-wide `CREATEDB` or superuser privilege. The generated file remains
owned by your WSL user with mode 600; `sudo` runs only PostgreSQL client
commands. Keep the file out of Git and backups.

If setup stops partway through, inspect the output and database marker before
retrying. Setup deliberately refuses to reuse a partially created database.
Use the guarded cleanup procedure below for a fresh start. If database
creation itself failed and no rehearsal database exists, cleanup will refuse;
after verifying that absence, remove only the generated rehearsal environment
file manually before retrying. Do not run an unbounded migration or drop
another database by hand.

## Configure Auth0 callbacks

The trusted backend `APP_ORIGIN` in the generated file is
`http://127.0.0.1:15173`. Register **both exact URLs** in the rehearsal Auth0
application's Allowed Callback URLs:

```text
http://127.0.0.1:15173/api/auth/callback
http://127.0.0.1:15173/api/auth/test/callback
```

Use Authorization Code, PKCE S256, scopes `openid profile email`, and a
confidential client supporting `client_secret_basic`. The first URL is used by
normal login and normal-callback readiness; the second is for the isolated
connection test. Vite proxies `/api` to the dedicated Go listener on port
18080. Do not reuse the development application's callback URL. Auth0
allowlisting cannot be proven by a local, unauthenticated read-only API call;
verify it manually in the Auth0 application configuration before testing.

## Start and check the application

In two **separate clean terminals**, load only the generated rehearsal file:

```bash
set -a
. scripts/rehearsal/.env.rehearsal.local
set +a
cd backend
go run .
```

```bash
set -a
. scripts/rehearsal/.env.rehearsal.local
set +a
cd frontend
npm run dev
```

The optional `AUTH_REHEARSAL_FRONTEND_PORT` and
`AUTH_REHEARSAL_BACKEND_PORT` variables change only local Vite listener/proxy
ports. Ordinary development retains ports 5173/8080. Do not add Auth0 secrets
to `VITE_*` variables.

In the PostgreSQL administrator terminal, run (renew `sudo -v` if needed):

```bash
./scripts/rehearsal/check.sh
```

This read-only command verifies the marker, clean migration 7, trusted scope,
Local DEV generation-zero policy, callback consistency, encryption-key shape,
app database connectivity, loopback backend, Vite proxy, and protected
server-provided callback metadata and activation status. On a fresh database it
will report that administrator bootstrap is still required. Start the Go server
only from the generated file: the protected status endpoint reports provider,
generation and affinity, but does not independently attest the server's
deployment ID. The database marker verifies the application's DB connection.
The check prints manual Auth0 checks separately and never claims to have
verified Auth0's allowlist or a login.

## Prepare a rehearsal administrator and OIDC revision

1. Visit `http://127.0.0.1:15173` and call `/api/access/me` in this **rehearsal**
   application to register its fixed Local DEV identity. Verify `/api/auth/me`
   reports issuer `urn:go-web-framework:local-dev` and the generated
   `LOCAL_DEV_SUBJECT`. Do not identify the administrator by email alone.
2. Use the existing one-time `backend/cmd/bootstrap-admin` command with those
   exact verified issuer and subject values. The bootstrap table is not writable
   by the limited application role; run this operator command with an authorized
   database owner credential **pointing only to the marked rehearsal database**.
   From `backend/`, invoke the command below after checking the operator `DB_*`
   values. Restore the application-role `DB_*` values for the Go server afterward.
   Do not change the existing development administrator.

   ```bash
   go run ./cmd/bootstrap-admin --issuer '<verified-issuer>' --subject '<verified-subject>' --confirm-verified-identity
   ```
3. In Settings → Authentication, create a **new** OIDC draft in this database.
   Enter the Auth0 issuer exactly as advertised (including any trailing slash),
   the rehearsal Auth0 client ID and secret, and the normal callback URL above.
   Enable development HTTP only for this loopback rehearsal. Validate the draft
   offline and explicitly approve it. Nothing becomes active automatically.
4. Run the isolated connection test, then the normal-callback readiness test
   through `/api/auth/callback`. They must verify the intended Auth0 issuer and
   subject without creating an application session. Explicitly enroll that
   **verified issuer and subject** as an active framework administrator; no
   email-based linking or automatic role grant is permitted.
5. Re-run `check.sh`. Review the activation status, fresh evidence IDs, exact
   callback, administrator enrollment, affinity mode, and the first-cutover
   warning. The two test-evidence records are short-lived and must be fresh at
   activation time.

## Manual cutover and verification

Only after separate approval for the live rehearsal action, use the existing
Settings → Authentication workflow to prepare and confirm activation. The
first Local DEV → database OIDC transition requires zero grace, immediate
reauthentication, both explicit acknowledgments, and a reason. It never
automatically retries an uncertain result. Inspect authoritative activation
status before any further action. Then sign in through Auth0, verify
`/api/auth/me`, effective `admin.manage`, protected admin APIs, and the
authoritative/applied generation on this one instance.

`check.sh` intentionally expects generation zero and will **fail after a
successful activation**; use the protected activation status view for the
post-cutover comparison. Do not interpret a 401 immediately after cutover as
proof that the database transaction failed.

## Failed rehearsal and cleanup

If Auth0 login fails after a committed first cutover, do not force the
activation head back to environment mode, restart with Local DEV, or run the
OIDC-to-OIDC recovery CLI against an ineligible target. Record non-secret
status and audit evidence, stop both rehearsal servers, and have an operator
inspect the **marked rehearsal database** before cleanup. The present code
does not provide first-cutover Local DEV restoration. Recreate a fresh
rehearsal database after correcting the Auth0 configuration.

With the rehearsal processes stopped, run:

```bash
sudo -v
./scripts/rehearsal/cleanup.sh
```

Cleanup shows the fixed database name and unique local marker, requires typing
both exactly, checks the marker again, and drops only that database. It does
not terminate active sessions or touch `go_web_framework` or any other database.
After a successful drop it removes only the generated local rehearsal file.
If the marker is missing or mismatched, it refuses cleanup; investigate rather
than changing the script's database name or bypassing its check.
