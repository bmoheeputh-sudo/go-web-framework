# Runtime authentication dispatcher (Phase 9.2.5C)

Runtime authentication still comes exclusively from `AUTH_PROVIDER` and its
environment settings. A database draft, approval, activation head, or successful
connection test cannot change the running provider in this phase. Startup does
not read activation heads or write configuration/activation records. Restart is
still necessary to change environment configuration.

## Request consistency

`auth.NewEnvironmentRuntime` takes an already prepared framework authenticator.
The runtime owns an `atomic.Pointer` to a private snapshot. Provider configuration
is copied at construction; session stores and concurrency-safe verification-key
caches remain shared services. Published configuration is never mutated.

The application router calls `Runtime.Capture` before routing, placing one
snapshot in a private request context. Authentication, RBAC/module middleware,
login, callback, logout, public provider configuration and administrator runtime
status all use that captured view. They do not load the atomic pointer again.
Nested capture by the same manager retains the original view; missing or foreign
captures fail closed. Exactly one authenticator is tried.

The private compare-and-swap publication mechanism rejects stale writers and
currently permits only the **same prepared configuration**. It has no exported
setter, HTTP endpoint, database listener, or provider-switching caller. Future
activation must replace this restrictive policy with reviewed preparation,
binding, recovery, transition-expiry and concurrency checks before enabling
configuration changes. No old provider is permitted in the current policy.

## Stable routes and status

These routes are always registered:

| Method | Route | Behavior |
| --- | --- | --- |
| GET | `/api/auth/login` | Existing OIDC login; 404 for other providers |
| GET | `/api/auth/callback` | Existing OIDC callback; 404 for other providers |
| POST | `/api/auth/logout` | Existing OIDC origin-checked logout; 404 for other providers |
| GET | `/api/auth/config` | Only the captured provider name |
| GET | `/api/auth/me` | Existing verified identity, or 401 |

Incorrect methods return 405, including GET logout for non-OIDC providers now
that its POST route is always registered. `/api/health` remains public. Existing
same-origin/JSON checks, RBAC and module permissions are unchanged.

The internal `RuntimeStatus` is a value copy containing deployment/environment,
source, applied generation, provider, active revision, previous-provider/revision
metadata and transition state/deadline. Current values are `environment`,
generation zero, no active/previous revision, and transition state `none`.
Environment aliases TEST and PRD/prd normalize to test and production. Deployment
metadata comes from `AUTH_CONFIG_DEPLOYMENT`; leaving management unconfigured
does not implicitly enroll a deployment.

The existing admin status API obtains provider/source from this request snapshot.
It continues showing stored database revisions separately and remains
management-only. Public configuration does not expose internal runtime metadata.

## Sessions and login flows

PostgreSQL OIDC reads use migration 000006's binding columns. Apply the already
documented forward migration before deploying this dispatcher to an OIDC
environment that has not yet installed version 6. There are no new migrations.

Environment OIDC accepts legacy sessions/flows as legacy, and explicit environment
bindings only when deployment, environment, issuer, client and login purpose match
exactly. Database-bound credentials and isolated/pre-activation test bindings
are rejected. Existing issuer/token verification, single-use flow consumption,
session rotation, idle/absolute expiration and logout revocation still run in
the original provider/store. Binding checks never update binding metadata or
extend expiry. New environment sessions and flows still use the legacy writer;
they are not assigned a revision or generation.

Legacy credentials cannot distinguish environment deployments sharing an issuer,
database and cookie. This is an existing limitation: keep those deployments
isolated. Future database activation must explicitly reject legacy credentials
or define a reviewed, bounded transition; it must never infer a revision from
an issuer/email match. The current dispatcher does not provide that transition.

## Provider boundaries and deferred work

- Local DEV retains development-only startup, loopback binding and fixed identity.
- IAP still verifies the signed assertion on every authenticated request. There
  is no OIDC/local fallback or publication path that can replace mandatory IAP.
  Upstream IAP enforcement and origin restrictions remain infrastructure duties.
- The isolated OIDC connection-test callback remains separate and does not
  create normal sessions. Its existing admin authorization/audit logic is intact.
- Database activation, rollback, coexistence, old-flow routing, listener
  synchronization and multi-instance reconciliation remain future work. Snapshot
  consistency within one process does not establish atomic activation across
  processes.

Validation uses synthetic HTTPS OIDC/IAP fixtures and disposable PostgreSQL
clusters, not the development database or live Auth0 credentials:

```bash
cd backend
go test -race -count=1 ./...
go vet ./...
cd ..
git diff --check
```
