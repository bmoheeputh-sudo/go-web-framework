# Controlled OIDC activation and administration APIs (Phase 9.2.5H)

The server exposes a protected backend control plane for preparation,
normal-callback readiness testing, activation, and immutable recovery-draft
creation. There are still no frontend activation controls. Startup rehydrates an
already committed database-required policy; any failure stops startup without
environment or Local DEV fallback. No migration is required.

Every endpoint requires verified authentication, an active user, effective
`admin.manage`, exact trusted origin for writes, and a bounded strict JSON body.
The shared administrator transaction rechecks authorization under the advisory
lock before mutation. Responses use `Cache-Control: no-store` and never contain
client secrets, keys, OAuth tokens, authorization codes, raw provider responses,
or identity/administrator claims supplied by the browser.

## Protected HTTP workflow

1. `POST /api/admin/auth/settings/{id}/activation/prepare` accepts only expected
   revision and activation generations. It performs hardened discovery/JWKS
   preparation outside the mutation transaction and returns a five-minute opaque,
   instance-local preparation ID plus safe session-impact metadata. It does not
   change the runtime or database activation head.
2. `POST /api/admin/auth/activation-preparations/{id}/readiness` starts the
   sessionless test through the real `/api/auth/callback`. The response contains
   the provider authorization URL and a separate HttpOnly readiness cookie.
   `GET /api/admin/auth/activation-preparations/{id}` reports safe progress and a
   durable normal-callback evidence ID after verified completion.
3. `POST /api/admin/auth/activation-preparations/{id}/activate` is one-shot. The
   request repeats revision/generations, references both fresh evidence records and
   the explicitly enrolled administrator, confirms the operation, supplies a
   reason, and requests zero to 1,800 transition seconds. First cutover also
   requires `acknowledge_reauthentication=true`,
   `acknowledge_emergency_recovery=true`, and zero transition seconds.
4. `POST /api/admin/auth/settings/{superseded-id}/rollback` creates a new immutable
   recovery draft with fresh authenticated encryption and atomic reason/provenance
   audit. It never reactivates history. The draft must independently pass
   validation, approval, both readiness tests, and normal activation.

Preparation handles are bounded to sixteen and one per initiating administrator.
They expire after five minutes and are process-local because they own prepared
cryptographic/network resources. A load-balanced administrator flow requires
instance affinity until activation completes; losing that instance requires fresh
preparation and readiness. Set `AUTH_ACTIVATION_AFFINITY_MODE=single_instance`
only for a true single-replica deployment. In a multi-replica deployment, configure
ingress affinity for the entire preparation, readiness callback, status and
activation sequence, then set `AUTH_ACTIVATION_AFFINITY_MODE=session_affinity`.
Blank configuration blocks preparation with `activation_affinity_required`.
Preparation IDs and readiness cookies carry cryptographically random process
markers; a request reaching another process fails with
`activation_preparation_wrong_instance` or an originating-instance callback error.
Neither error weakens state, PKCE, cookie, evidence or administrator correlation.
Durable evidence and the final activation transaction remain
PostgreSQL-authoritative.

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
- `BeginNormalCallbackTest(candidate, writer, request)` is invoked only by the
  protected readiness adapter. It exercises the
  configured `/api/auth/callback` using the ordinary OIDC callback verifier but
  cannot create an application session. `NormalCallbackResult.Evidence` returns
  safe evidence metadata only after verified completion and atomic audit insertion.
- `Activate(ctx, candidate, ActivationRequest)` requires both evidence IDs, the
  intended enrolled user ID, an explicit reason and a transition duration from
  zero to thirty minutes for database-to-database transitions. The initial
  environment-to-database cutover requires `Transition=0` and explicit
  `AcknowledgeReauthentication=true` and
  `AcknowledgeEmergencyRecovery=true`; otherwise it is rejected before mutation.
  IDs are references to server-verified evidence, not
  identity claims. It returns desired/applied generations, `Applied`, `Committed` and
  `CommitUncertain` separately.
- `Repository.PrepareRecoveryDraft(ctx, historicalID, expectedLatestVersion)`
  creates a new draft from a same-scope superseded OIDC revision. It does not
  approve or activate that draft.

The HTTP adapter maps narrow DTOs into these trusted capabilities. It does not
accept issuer, subject, actor, deployment, environment, or success flags as
evidence.

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
reconciliation; it is not reported as success. A PostgreSQL error or explicit
transaction rollback is classified as definitely not committed. Loss of the
connection or protocol result after COMMIT was sent is classified as uncertain;
clients must never retry the activation automatically. Database and in-process
publication are not one atomic operation, nor does this provide atomic
multi-instance activation.

### Activation response contract

Activation responses use stable snake-case fields. `outcome` and
`commit_persisted` are authoritative about what the responding process knows:

| `outcome` | `commit_persisted` | Meaning | Client action |
|---|---:|---|---|
| `committed_applied` | `true` | PostgreSQL committed and this instance published the exact generation. | Do not retry. |
| `committed_not_applied` | `true` | PostgreSQL committed, but this instance did not publish it. | Reconcile or restart; do not activate again. |
| `commit_uncertain` | `null` | The server cannot prove whether COMMIT persisted. | Read authoritative status; never retry automatically. |
| `not_committed` | `false` | The server knows the activation did not commit. | Correct the cause and create a fresh preparation where required. |

The envelope also supplies `desired_generation`, `applied_generation`,
`revision_id`, `authoritative_state_known`, `authoritative_generation`, `authoritative_revision_id`,
`reconciliation_required`, `commit_uncertain`, and
`automatic_retry_allowed` (always `false`). A 503 does not itself determine the
commit outcome. `commit_persisted` is never `true` for an uncertain commit.

`GET /api/admin/auth/activation/status` compares the scoped PostgreSQL head with
the local runtime and listener status. `POST /api/admin/auth/activation/reconcile`
requires the expected authoritative generation and explicit confirmation; it only
loads and publishes the already committed head and never repeats activation.
Both endpoints require the ordinary authenticated, active `admin.manage` checks;
the write also receives origin/JSON protection. If the only instance is fenced
after an ambiguous commit, its authentication boundary intentionally also blocks
these endpoints. Inspect PostgreSQL and restart for startup rehydration, or use a
healthy authenticated peer. There is no Local DEV fallback.

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
carry over. Sign in again using the new OIDC configuration."** The activation API
requires explicit reauthentication and emergency-recovery acknowledgments and a
zero transition duration; activation history
records equal activation/transition timestamps. No activation UI exists yet, so no
claim is made that the present Admin Portal displays this notice.
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

Recovery can be pre-staged while providers are healthy. Create the immutable
recovery draft, validate and approve it, verify the exact normal callback URI,
explicitly enroll an active target OIDC identity with effective `admin.manage`,
and complete fresh isolated and normal-callback tests immediately before
activation. `GET /api/admin/auth/settings/{id}/recovery-readiness` reports durable
configuration/enrollment readiness separately from the two short-lived evidence
records. Evidence remains limited to five minutes and is never promoted into
historical recovery authority.

Portal recovery therefore cannot complete while the selected recovery provider is
unavailable: it must perform fresh discovery, JWKS and both verified login tests.
Preparation returns `recovery_provider_unavailable`, identifies
`auth-recovery-cli`, and forbids automatic retry. The offline procedure removes
dependence on the broken portal login but does **not** bypass OIDC verification;
the recovery provider itself, its discovery/JWKS endpoints, PostgreSQL, audit
infrastructure and required encryption keys must remain available. Operators
should pre-stage a separately operated recovery OIDC provider and regularly verify
the protected offline capability. No unauthenticated HTTP recovery path exists.

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
The listener described below reconciles subsequent committed changes. Keep live
activation disabled pending the remaining operational recovery and rollout review.

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

## Event-driven multi-instance synchronization (Phase 9.2.5F)

Each process owns a dedicated `pgx.Conn` using the validated application pool's
connection/TLS settings and the same `go_web_app` user. It does not check out a pool
connection indefinitely. Allow one additional PostgreSQL connection per instance.
A direct or session-affine connection is required; transaction-pooling proxies
cannot preserve a session's LISTEN subscription.

The code-owned channel is `framework_auth_activation`. The existing activation
transaction calls `pg_notify` with deployment, environment and a generation hint,
after its authorization/evidence/history/audit work. PostgreSQL delivers that event
only on successful commit. Rollback, including deferred commit failure, delivers
nothing. No credentials, identity claims or provider settings enter the payload.
The single database owner remains trusted; no new SQL grants or migrations are
introduced. Hardened installations must permit this role to execute `pg_notify`.

`Synchronizer.Start` connects, successfully executes LISTEN, then reconciles before
HTTP admission begins. On reconnect it repeats that order, covering notifications
missed while disconnected and events racing subscription. The healthy loop blocks
in `WaitForNotification`; there is no periodic configuration poll or heartbeat read.
Relevant scope hints trigger reconciliation regardless of their generation value.
Malformed or other-deployment hints are ignored. Hints are never authoritative.

A mutex serializes reconciliation within each instance. It reads a scoped,
consistent active OIDC head, compares it with locally applied state, and reuses the
read-only startup loader for hardened preparation. After network work it reads the
authoritative head again. Publication requires that exact revision/generation and
the expected locally applied generation. Slow candidates and backward generations
are rejected; duplicate notifications need no preparation. A newer verified runtime
can skip missed generations, but accepts only the current generation and its
explicitly recorded immediate predecessor within the original deadline.

Publication transfers ownership of immutable snapshots and leases. Captured
requests keep their original snapshot; replaced authenticators retire immediately
unless they are precisely the permitted draining binding. Transport cleanup waits
for their final retained reference. Initial environment-to-database publication
never retains Local DEV or environment credentials as a grace provider. IAP-pinned
instances refuse OIDC reconciliation and do not alter upstream IAP infrastructure.
The background service reads/decrypts trusted state without an administrator identity
and never invokes `AdminTransaction` or changes activation records.

### Failure and admission policy

Disconnection or preparation failure marks synchronization degraded but retains the
last verified snapshot. Reconnection/preparation is retried with exponential jitter
from 250–500 milliseconds up to 15–30 seconds between attempts. These are failure
retries, not healthy periodic configuration reads. Network/SQL work remains bounded
and shutdown cancels the listener and joins its goroutine before runtime/pool cleanup.
Silent network failure detection depends on PostgreSQL/TCP error detection; a cached
`Connected` flag is not an authentication trust signal.

Production must provide a session-affine PostgreSQL connection for LISTEN. On every
subscription the listener compares `pg_backend_pid()` before and after LISTEN and
confirms that `pg_listening_channels()` still contains the fixed channel. An obvious
transaction-pooling proxy therefore fails startup/reconnection visibly. This check
cannot prove that an intermediary will preserve affinity forever; configure a direct
or documented session-pooling endpoint and monitor degraded synchronization state.

Every environment authentication/login/callback/logout operation checks scoped
policy. Missing database authority or a database-required cutover denies the affected
operation; Local DEV cannot continue after a missed notification. Database session
lookup/activity updates, new-flow insertion, one-time flow consumption and session
creation check authoritative head/revision/generation inside their parameterized
SQL statement. A stale instance cannot start a new old-generation login. It can
finish an old callback or use an old session only while PostgreSQL authorizes that
exact predecessor. Unknown, expired and retired credentials are denied without
activity updates. Session creation also checks the original consumed flow expiry
against database time after token exchange.

Thus a listener-only outage does not invalidate every existing session. If the head
is unchanged, or an explicitly permitted drain remains valid, requests can continue.
If PostgreSQL cannot establish the required decision, that authentication operation
fails closed. Public health remains public. No listener failure selects an alternate
provider, resets activation state, or grants another thirty minutes. A notification
can be missed without extending credential trust; reconciliation later restores
availability. All supported activation writes must emit the transactional hint;
unsupported manual SQL changes may require reconnection to load the new provider.

### Clock and status boundaries

The authoritative head check and startup lineage check use PostgreSQL time. SQL uses
`clock_timestamp()` for session/flow expiry, idle checks, generation admission and
persisted draining deadlines. New database flows are additionally capped at five
minutes of database time. Positive/negative node-clock skew tests verify that local
lease state cannot extend database authority, even on a node unaware of retirement.

Host clocks must still be synchronized: ID-token validation, browser cookie dates,
local conservative lease rejection and resource timers use host time. A fast host
may reject early; a slow host may retain an unusable verifier in memory longer.
Neither grants credentials past the PostgreSQL deadline. PostgreSQL's own clock and
consistent primary database routing are trusted; no cross-database or replica-lag
consistency is claimed. An operation already admitted against a statement snapshot
may complete while a concurrent activation commits; this is not globally atomic
cluster publication and cannot retroactively cancel prior application work.

`Synchronizer.Status()` and the application's internal status callback expose only
latest **observed** desired generation, applied generation, provider, connection
state, last successful reconciliation, degraded/mismatched state and transition
deadline. This is per-instance status, not a claim that every instance has activated.
Existing management endpoints remain compatible. The protected Phase H endpoints
do not claim cluster-wide success, and no activation UI is added. Configuration
keys and callback/listener settings are captured at process
startup. Provision historical keys on every instance before a new revision needs
them; changing process secrets requires restarting that instance.

Hardened discovery and JWKS GET requests retry HTTP 429 and 503 only. They make at
most three total attempts, using 100–200 ms and 200–400 ms jittered delays inside
the existing request deadline. Redirect, DNS, address and response-size checks run
on every attempt. Token exchange and other non-idempotent requests are never retried.

## Deployment blockers

Do **not** wire these methods to the live deployment yet:

- Startup and LISTEN/NOTIFY reconciliation now load committed OIDC policy. This
  does not make publication simultaneous across instances; inspect each instance's
  desired/applied status and retain a reviewed rollout/recovery procedure.
- There is no public normal-readiness start/result workflow or activation/recovery
  UI. The current portal's isolated test cannot activate a configuration by itself.
- Offline emergency recovery is available only through the separately authorized
  command documented in [offline-auth-recovery.md](offline-auth-recovery.md).
  Operator-facing synchronization diagnostics still require implementation. Never
  reset a head to environment mode, disable verification, or use Local DEV after
  activation.
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
