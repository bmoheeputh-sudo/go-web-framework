# Controlled OIDC activation foundation (Phase 9.2.5E)

This is an internal backend capability, not an operational deployment feature.
The HTTP composition root does **not** construct an activation service or expose
activation, rollback, or normal-readiness-start endpoints. The existing Admin
Portal cannot activate a provider. Startup now rehydrates an already committed
database-required policy; any failure stops startup without environment or Local
DEV fallback. No migration is required.

## Trusted internal API

- `authconfig.NewActivationService(repo, runtime, store, sessions, callback)` binds
  a service to trusted deployment/environment, existing session limits, the exact
  normal callback URI, PostgreSQL store and runtime. IAP runtimes are refused.
- `Prepare(ctx, revisionID, lifecycleGeneration, expectedActivationGeneration)`
  requires verified administrator context and an approved OIDC revision. It reads
  the secret internally and audits preparation through `AdminTransaction`. Network
  work follows **outside** the transaction. Candidates expire after five minutes;
  callers must defer `PreparedActivation.Close` for unused/error paths.
- `PreparedActivation.Readiness()` returns a copy of the prepared session-impact
  policy: current provider/source, target revision, expected generation,
  `RequiresReauthentication`, and `MaximumSessionGrace`. Read it **before** asking
  an administrator to confirm; it does not replace transactional evidence checks.
- `BeginNormalCallbackTest(candidate, writer, request)` is an internal, explicitly
  invoked readiness operation. There is no HTTP start API. It exercises the
  configured `/api/auth/callback` using the ordinary OIDC callback verifier but
  cannot create an application session. `NormalCallbackResult.Evidence` returns
  safe evidence metadata only after verified completion and atomic audit insertion.
- `Activate(ctx, candidate, ActivationRequest)` requires both evidence IDs, the
  intended enrolled user ID, an explicit reason and a transition duration from
  zero to thirty minutes for database-to-database transitions. The initial
  environment-to-database cutover requires `Transition=0` and explicit
  `AcknowledgeReauthentication=true`; otherwise it is rejected before mutation.
  IDs are references to server-verified evidence, not
  identity claims. It returns desired/applied generations, `Applied`, `Committed` and
  `CommitUncertain` separately.
- `Repository.PrepareRecoveryDraft(ctx, historicalID, expectedLatestVersion)`
  creates a new draft from a same-scope superseded OIDC revision. It does not
  approve or activate that draft.

These APIs are trusted internal capabilities, not DTOs for direct HTTP binding.
A future HTTP adapter must retain verified auth, effective `admin.manage`, origin
and JSON write protection, explicit confirmation, and safe error mapping. It must
not accept issuer, subject, actor, deployment or success flags as evidence.

## Preparation and test evidence

Preparation reuses Phase 9.2.4 discovery/JWKS validation and network transport:
HTTPS, exact issuer, same-origin endpoints, public IP resolution on each new
connection, numeric-address dialing after validation, no proxy, no redirects,
bounded response sizes, ten-second HTTP and twenty-second preparation deadlines.
Only RS256/ES256 are supported. DNS rebinding, metadata IPs and private endpoints
remain denied. Callback URI must exactly match trusted server configuration;
HTTP allowance remains restricted to explicitly configured loopback development.

Database authenticators use synchronous validated JWKS retrieval for each token
verification, avoiding the detached `RemoteKeySet` fetch goroutines used by the
unchanged environment provider. Token exchange uses PKCE S256 and one configured
client-authentication method; no credential-style auto-detection retry is added.
No OAuth tokens are stored, logged or returned.

The internal readiness start creates a five-minute `normal_callback` flow with a
separate HttpOnly/SameSite readiness cookie and server-held candidate/initiator.
It uses the existing normal callback path, one-time state consumption, nonce,
PKCE, ID token issuer/audience/signature/expiration checks. The callback chooses
this explicitly reserved test by its opaque cookie and stored purpose, never by
an issuer/revision query parameter. The test registry is limited to sixteen
pending operations, expires reservations and releases leases, and is instance-local.
Tests cannot be replayed or used as normal session cookies. No session, user or
role is created by the test. Completion rechecks the original administrator and
approved lifecycle generation under the shared lock, then persists evidence and
audit together. Provider errors never become success evidence.

Both fresh isolated and normal-callback evidence must identify the **same**
issuer/subject and intended active OIDC framework user, in the same deployment,
environment, immutable revision and lifecycle generation. They must belong to the
initiating administrator, use verification format one, and remain unexpired.
The enrolled identity must currently have effective `admin.manage` and an existing
explicit enrollment audit event. A previous explicit enrollment of that exact
identity may serve a recovery revision; email matching and repeated role grants
are unnecessary. An Admin label without its permission is insufficient.

## Atomic persistence and publication

The shared advisory-lock administrator transaction rechecks actor identity and
permission, expected head generation and previous revision, candidate freshness,
approval, both evidence records, enrollment, and recovery provenance. It then:

1. Supersedes the previous active lifecycle, if present.
2. Promotes the approved candidate and advances its lifecycle generation.
3. Inserts immutable activation history with actor, reason, previous/target/recovery
   revisions and an explicit transition deadline.
4. Inserts the first head or **updates** an existing head and generation. An upsert
   is inappropriate: migration 000006's BEFORE INSERT trigger rejects generation
   two before PostgreSQL can resolve an insert conflict.
5. Writes the activation audit and rechecks evidence expiry before commit.

The head/history/lifecycle consistency constraints are deferred to commit. Audit
failure rolls everything back; no external request occurs under the advisory lock.
Activation generations and lifecycle generations are separate and never substituted.
No module or core roles/permissions are assigned during activation.

A runtime reservation pauses new HTTP admissions (503) before the activation
transaction, closing the database-commit/local-publication gap. Already captured
requests retain their original leases. A known rollback releases the reservation;
a successful commit resumes admission only after generation-aware publication.
A stale runtime, concurrent shutdown, closed candidate or failed CAS returns
`ErrRuntimeMismatch` and reports the desired versus applied generations. New HTTP
requests then receive 503; the old Local DEV/environment provider is not used as
recovery. An uncertain transaction commit outcome is also fenced and requires
reconciliation; it is not reported as success. Database and in-process publication
are not one atomic operation, nor does this provide atomic multi-instance activation.

## Sessions, callbacks and request consistency

Each outer request captures one snapshot. Middleware, routes and status use it;
control-plane reads do not change that request's selection. Normal database login
always writes the active revision/generation binding. Session/flow selection reads
opaque-token metadata without touching activity, then chooses **one** explicitly
accepted active/draining entry. SQL repeats the exact binding and expiry predicates
before activity updates or one-time flow consumption.

A single previous database configuration may drain, at most thirty minutes. A new
activation is refused while the previous transition remains open. Old callbacks
exchange with their original issuer/client/secret and retain their original
revision/generation. Original flow expiry and transition deadline are checked again
after exchange; session issuance is fenced against retirement. Stored session
expiry is capped at the earlier original/token/absolute limit and grace deadline.
Idle timeout still applies. Revoked/expired rows are never recreated by lookup.
No new login flow may start on a draining authenticator.

**Security exception to the maximum 30-minute session-grace policy:** the first
environment-to-database activation requires immediate reauthentication for new
requests. It rejects all legacy and environment credentials without guessing a
revision, rewriting bindings, or updating their activity. Later grace applies
only to explicitly bound database sessions.

- Local DEV has no verified browser session: it supplies a fixed identity on each
  allowed loopback request. Continuing it during grace would also authenticate
  new requests without OIDC, creating a forbidden fallback.
- Current environment OIDC writers create legacy rows. These contain no client,
  deployment, environment, revision or activation generation; legacy flows also
  lack an issuer. A matching issuer/email/cookie cannot prove missing provenance.
- Even explicitly environment-bound rows lack an immutable configuration revision
  and activation generation. Supporting those in a future design would require a
  separately reviewed, pre-established environment configuration identity and
  retirement policy, not inventing database bindings for existing credentials.

Readiness therefore reports `RequiresReauthentication=true` and
`MaximumSessionGrace=0` for Local DEV and environment OIDC. A future confirmation
UI must explain: **"Existing sign-ins and pending environment logins will not
carry over. Sign in again using the new OIDC configuration."** The internal API
requires explicit acknowledgment and a zero transition duration; activation history
records equal activation/transition timestamps. No activation UI or public endpoint
exists yet, so no claim is made that the present Admin Portal displays this notice.
Subsequent database-to-database readiness reports a maximum of thirty minutes;
the requested interval may be shorter and cannot extend original session/flow expiry.

Request consistency still permits an already captured environment request to
finish with its original snapshot. An environment callback already executing may
produce a legacy cookie, but that cookie is rejected on every request captured
after cutover. Callbacks first arriving after cutover fail closed. This is not a
post-cutover session grace or permission to admit new Local DEV requests.

Cookies remain opaque, hashed in PostgreSQL, HttpOnly, SameSite,
and Secure except permitted local HTTP development. Logout is binding-restricted.

Normal OIDC routes retain their methods. A reserved readiness callback can use
`/api/auth/callback` even while the application runs Local DEV, but cannot change
application authentication. With no reservation, existing environment callback
behavior is unchanged. No Auth0 callback change is required by this internal
normal-readiness path; the existing isolated-test path still needs its separately
configured `/api/auth/test/callback` URI.

## Recovery and resource lifecycle

Recovery decrypts the immutable historical secret internally, creates a new UUID
and configuration version, and encrypts with the current key, a fresh nonce and
new authenticated revision metadata. Recovery provenance and draft auditing commit
with the draft. Historical settings and ciphertext are never overwritten. The new
draft must pass validation, explicit approval, both readiness tests and the same
activation operation. A superseded revision itself is never reactivated; old
sessions cannot regain trust simply because an issuer/client is reused.

Snapshots are immutable. Active and draining authenticators have reference leases
held across complete requests and explicit readiness operations. Retirement stops
new admissions at the deadline; owned transport cleanup runs only after existing
leases end. Expired draining entries are pruned with a new snapshot. Unused
candidates expire after five minutes. Timers are stopped on shutdown and old timers
cannot retire a later configuration. Pool shutdown remains after HTTP shutdown;
authenticator cleanup never closes the shared database pool or shared environment
HTTP transport. The service owns each prepared transport and copies client settings.

Go cannot guarantee erasure of all immutable string/library copies. Cleanup releases
owned network resources and reachable references rather than claiming secure memory
wiping. Captured application contexts or an internal caller retaining candidates can
keep references longer; callers must release them and must not spawn work from
request contexts without an explicit bounded ownership design.

## Read-only startup rehydration and lifecycle hardening

`StartupRuntimeFromEnv` checks authoritative policy before constructing any
`AUTH_PROVIDER` authenticator. An absent head on an unenrolled database or an
explicit clean environment policy keeps existing behavior. Database policy loads
only its active OIDC revision; missing keys, invalid configuration, database or
provider failures stop startup. `AUTH_PROVIDER=google_iap` pins the infrastructure
boundary and refuses a conflicting database OIDC policy.

`StartupLoader` is a separate read-only capability, with no administrator context
or `AdminTransaction`. A repeatable-read, read-only PostgreSQL transaction checks
scope, head/history generation and timestamps, one active lifecycle, immutable
revision metadata, and previous-generation lineage. Under migrations 000005–000006,
active lifecycle generation is four and superseded generation is five; those are
checked separately from the unbounded deployment activation generation. Startup
neither emits audit events nor mutates settings, history, sessions or evidence.

The loader decrypts the authenticated envelope using the selected historical key,
then reuses activation's hardened discovery/JWKS preparation outside the read
transaction. Both active and draining redirect URIs must exactly match trusted
`APP_ORIGIN + /api/auth/callback`. Local HTTP still requires development allowance
and a loopback listener. Existing `SESSION_*` timeout settings remain authoritative.
The keyring supports single-key compatibility or the strict multi-key environment
format in [the persistence guide](auth-activation-persistence.md#encryption-keyring).
No keys are generated, rotated, logged or re-encrypted by startup.

Only the immediately previous revision can drain, using the **recorded** transition
deadline and original activation generation. Restart never grants another thirty
minutes or rebinds old cookies/flows. Expired history is not prepared and needs no
old key or reachable issuer. Missing keys for a still-permitted draining revision
fail startup. If its deadline passes during preparation, it is discarded. The head
and lifecycle are checked again after network preparation; a changed head fails
startup, without retry or fallback. There remains a window after that final read:
this does not synchronize an instance with later activations on another instance.
Keep live activation disabled until multi-instance coordination is delivered.

Preparation is bounded to twenty seconds per provider and fifty seconds for the
whole startup load; SQL reads are bounded to five seconds. Callback exchange and
signature verification have a shared twenty-second request context, ten-second
HTTP timeouts and three-second session/flow queries. Candidates and unused readiness
reservations expire after five minutes. Retired providers deny new credentials at
the deadline; transport cleanup waits for retained in-flight requests. Shutdown
releases pending readiness/candidate references and retains safe runtime status
only. The HTTP server allows forty seconds for graceful shutdown (longer than the
normal callback budget), then cancels remaining connections via standard server
shutdown handling. No provider cleanup timer force-closes a legitimate request.

An arbitrary trusted handler that ignores cancellation or retains a request context
can still retain a snapshot and immutable secret strings. Go cannot safely kill
such a goroutine or guarantee memory erasure. Module handlers must honor context
cancellation and release database connections; bounded network/SQL operations do
not impose a hard lifetime on arbitrary application code. Process termination is
the final memory/resource boundary, not a new authentication fallback.

## Deployment blockers

Do **not** wire these methods to the live deployment yet:

- Startup now rehydrates a committed OIDC policy, but ongoing reconciliation and
  operational desired/applied recovery are not implemented.
- LISTEN/NOTIFY, listener reconnect reconciliation and other-instance fencing are
  not implemented. Use of this foundation is limited to isolated single-process
  tests until multi-instance policy is delivered.
- There is no public normal-readiness start/result workflow or activation/recovery
  UI. The current portal's isolated test cannot activate a configuration by itself.
- Offline emergency recovery and operational desired/applied reconciliation still
  require implementation and review. Never reset a head to environment mode as a
  workaround, disable verification, or use Local DEV after activation.
- The application/migration role remains the single schema owner `go_web_app`.
  Trusted code and that database owner can change the database; no least-privilege
  separation is claimed. Enrollment/recovery provenance currently uses retained
  audit events, which must not be pruned while needed for those safety checks.

## Validation

Automated tests use disposable PostgreSQL 14 clusters, synthetic identities and
signed synthetic OIDC tokens. No real tenant credentials or application database
are used. Existing migrations are applied only inside those disposable clusters.

```bash
cd backend
go test -race -count=1 ./...
go vet ./...
cd ..
git diff --check
```
