
> **Phase 10.1 compatibility note:** Google IAP is retired. References below describe the historical design; `AUTH_PROVIDER=google_iap` now fails startup. OIDC and Local DEV remain supported.
> Startup follow-up: read-only database rehydration now implements committed-head
> loading, historical-key selection and recorded-deadline restoration. See the
> [current startup and lifecycle design](auth-controlled-activation.md#read-only-startup-rehydration-and-lifecycle-hardening).
> Phase 9.2.5F now adds LISTEN/NOTIFY reconciliation and database-time admission
> checks. The dated findings below describe earlier phases; emergency recovery
> and the operator activation workflow remain outstanding.

# Phase 9.2.5C focused review — commit 52d81ff

The original Phase C review changed tests, logo accessibility text and documentation only. It
does not enable activation, provider switching, rollback, draining or listeners.

## Verified invariants

1. `internal/auth/runtime.go`: `Capture` contains the only production
   `current.Load()` in the runtime. An outer request reads it once. Nested capture
   by the same manager reads it zero times. `snapshot`, `Status`, `Authenticate`
   and all registered auth handlers use the private captured context exclusively.
   `server.go` wraps the complete router, including admin and module routes.
   Concurrent, mid-request replacement and unavailable-pointer tests exercise
   this boundary. Request consistency is not consistency across separate HTTP
   requests or browser login round trips.
2. `publish` is private. After initialization it permits only the same status
   and prepared authenticator pointers, using CAS against the expected snapshot.
   Database source, revision/generation, transition metadata, and replacement
   providers are refused. Initialization with a nil expected pointer cannot
   overwrite an existing runtime. There is no activation caller. Failed
   publication leaves OIDC applied; an unauthenticated loopback request stays
   401 rather than becoming a Local DEV user. Startup provider preparation errors
   return an error, even when valid Local DEV identity variables are present.
3. The commit's branding edits do not touch `ProtectedRoute`, `canAccess`,
   `NavigationRegistry`, module composition/capability fetching or backend RBAC.
   `AdminLayout` still filters sidebar items with `canAccess`; `AppRoutes` still
   guards direct URLs separately. Branding/toggle tests exercise denied Viewer
   and Admin-without-module-permission navigation. Existing module tests cover
   unauthenticated/failed discovery and disabled routes.
4. The logo already uses `${import.meta.env.BASE_URL}assets/vopak-logo.png`.
   Added tests render all twelve languages under `/enterprise/security/` and a
   production build with that base verifies the asset reference and copied PNG.
   `common:brandLogoAlt` now supplies concise localized alt text in all locales.
   The collapsed shield retains its existing application-name accessible label.

## Startup policy finding — addressed in Phase 9.2.5D

The original review found that `newServer` selected `AUTH_PROVIDER` without reading
activation policy. Phase D replaces the deferred-policy characterization with
regression tests and a mandatory read-only policy gate before provider construction.
Missing scope, unreadable/missing schema and inconsistent policy fail startup;
database-required policy returns a safe unsupported-runtime error. No fallback
provider is selected, regardless of RBAC enablement. The gate reuses the shared
pool and does not manufacture an administrator principal or write policy.

No head preserves environment behavior on an unenrolled database. An explicit
clean environment head permits its configured provider. To prevent a typo scope
from evading an existing activation, a missing head is rejected if any other
head requires database authentication. Independently configured environment
scopes in that database therefore need explicit policy. See the
[Phase D policy and limitations](auth-identity-enrollment.md).

Database runtime loading, safe activation/recovery and synchronization remain
unimplemented. A startup check cannot detect policy changes after startup, or
prove the identity of a different/empty database supplied by an operator. Protect
deployment identity and DB configuration operationally. Do not activate a head
while this environment-only runtime is deployed.

## Phase E follow-up

The [controlled activation foundation](auth-controlled-activation.md) implements
revision-bound writers, callback selection, single-entry bounded draining and
request leases for database authenticators. Preparation uses the hardened network
transport and a synchronous validated keyset. The production composition root
still exposes no activation operation. Startup loading, multi-instance
reconciliation and emergency recovery remain deployment blockers. The original
Phase C findings below describe the pre-implementation boundaries and rationale.

## High — Phase 9.2.5E callback binding and bounded draining

The current callback uses the snapshot captured when the callback request arrives,
not the snapshot used by the earlier login request. This is safe only because
configuration switching is currently forbidden. Required changes before switching:

| Area | Required change |
| --- | --- |
| `auth/runtime.go` | Prepare a complete immutable active-plus-draining authenticator set before CAS publication. Key entries by deployment/environment, immutable revision, activation generation, issuer and client ID. Capture this complete set once per request. Do not reload it or try providers until one works. |
| `auth/session.go`, `auth/postgres.go`, `auth/bindings.go` | Add typed bound-flow/session creation and atomic consumption. Current `addFlow`/`addSession` write legacy rows and `loginFlow` carries no configuration identity. Use migration-000006 columns, exact bound predicates and hashed opaque cookie tokens. Do not reclassify legacy rows. |
| Login | Always use the captured active authenticator and persist its precise binding, purpose `login`, nonce, state hash, PKCE verifier and expiry (currently 10 minutes). No new logins through a draining authenticator. |
| Callback dispatch | Resolve the opaque browser flow cookie to server-stored binding metadata, then choose exactly that permitted entry from the captured set. Never select by unverified `iss`, a revision query parameter or identity header. Missing/unknown/expired/revoked bindings fail closed. Keep isolated and pre-activation test purposes out of normal login. |
| Flow consumption | Validate state/browser correlation and atomically consume only the bound, unexpired flow; a metadata read alone is not authentication. Keep ambiguous-query checks, PKCE, nonce, signature, exact issuer/audience and expiry verification. Ensure only one callback can consume the flow. |
| `auth/oidc.go`, `auth/runtime_bindings.go` | Replace environment-only admission with explicit active/draining policies. Exchange the code using the original revision's issuer/client/secret/redirect URI/verifier, never the current revision's values. Retain existing same-origin logout and identity validation. |
| Session issuance | Bind the new session to the configuration actually used, including its original generation. An old callback must not mint a current-generation session. Reject after the drain deadline; cap any permitted old session by token expiry, existing absolute/idle limits and the transition deadline. Recheck the deadline before issuance, even if it expired during token exchange. |
| Durable policy/restart | Use `authconfig/activation.go` history and same-scope references to reconstruct only explicitly permitted draining entries after restart. A revision approved in the DB is insufficient. Keep required historical encryption keys until the allowed use ends. |

Bound callback admission by the earlier of original flow expiry and the recorded
transition deadline, with an absolute maximum 30-minute transition and no extension
on restart. Binding generation means the activation generation; lifecycle
optimistic-concurrency generation and configuration version are separate values
and must not be substituted. Check session deadlines on every request, even if an old request still
holds a snapshot. Specify revocation behavior during in-flight exchanges. Bound
the number of draining entries: reject/defer overlapping activations when the
budget is full rather than accumulating authenticators or evicting an allowed
flow unexpectedly. Separate transition draining from in-process resource leases;
an admitted request may still hold resources after new admissions stop.

Future regression tests must cover login-before/callback-after publication,
rollback to the same revision under a new generation, cross-client/issuer/purpose
confusion, flow replay, expired draining entries, deadline crossing during token
exchange, concurrent activation, restart recovery, and no new old-provider login.
IAP remains infrastructure-pinned and cannot be replaced to bypass assertions.

## Medium — resource ownership must precede repeated publication

Current runtime publication is effectively initialization-only, so repeated
provider retirement is not implemented. `closeResources` currently closes the
application DB pool; the runtime has no retirement API or background worker.

- Give each prepared authenticator an explicit owner/lease and idempotent cleanup.
  Stop admitting flows/sessions at the policy deadline, retire it from new
  snapshots, then release its resources after captured requests finish or their
  bounded contexts expire. Atomic pointer replacement alone does not show when
  old readers have finished. Failed or stale candidate publication must release
  the candidate's resources too.
- Create owned HTTP transports for prepared revisions, or explicitly reference
  count shared ones. Today OIDC wraps a possibly shared `http.DefaultTransport`
  with `httpsTransport`; copying `http.Client` does not clone its transport.
  The wrapper does not forward `CloseIdleConnections`, so calling it on the
  current wrapped client is insufficient. Close idle connections on the owned
  underlying transport only after retirement; do not close a shared active
  transport, shared IAP cache, or the application-wide PostgreSQL pool per revision.
- The installed go-oidc v3.21.0 `Provider.Verifier` uses a background JWKS context.
  `RemoteKeySet` launches a coalesced on-demand fetch goroutine and uses
  `context.WithoutCancel`; even `VerifierContext` ignores cancellation. Cancelling
  a callback therefore does not prove that its JWKS fetch has ended. Preserve
  the existing 10-second HTTP timeout. Future owned transport/lifetime handling
  must bound/track those fetches (and test blocked-JWKS retirement); do not assume
  a constructor cancellation function is sufficient. There is no periodic OIDC
  refresh loop here; IAP refresh is synchronous and request-driven.
- Cancel and join any future listener/drain timers on shutdown. Avoid goroutines
  per request or unbounded retirement queues. Keep response-body closure and
  shutdown ordering: stop admissions, bounded HTTP shutdown, release retired
  authenticators, then close shared stores. Release secret references; Go strings
  and library-held copies do not permit a promise of deterministic memory wiping.
- `authconfig/connection_tests.go` retains `context.WithoutCancel(ctx)` in test
  entries. That now also retains the captured runtime snapshot. Completion clears
  it, but abandoned-entry cleanup is opportunistic on later allocations (after
  expiry plus another five minutes), not a guaranteed wall-clock release. The
  registry is bounded to 64 entries, but idle abandoned entries can persist until
  process exit. Future draining must detach only the framework-verified values
  needed for audit/authorization, or account for explicit bounded leases and
  expiry cleanup. Do not retain the complete runtime/credential graph in a
  long-lived operation context or manufacture an administrator principal. The
  test callback's `valueContext` currently reuses those stored values for trusted
  audit authorization; future runtime dispatch must not inherit an old snapshot
  from that operation context instead of the callback request's captured view.

## Non-root hosting boundary

The logo path is base-aware. This does not make the entire application subpath-
deployable: `main.tsx` currently constructs `BrowserRouter` without a basename,
and API/login URLs intentionally remain rooted at `/api`. Routing basename,
reverse-proxy rewrite and callback configuration require a separate deployment
review. This change does not alter those paths or claim an end-to-end subpath
deployment test.
