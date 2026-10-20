# Administrator identity enrollment and startup policy (Phase 9.2.5D)

Phase 9.2.5E adds a separate [internal activation foundation](auth-controlled-activation.md).
The deployed portal protections described here remain in effect. Startup now also
supports [read-only database rehydration](auth-controlled-activation.md#read-only-startup-rehydration-and-lifecycle-hardening);
no activation endpoint or operational recovery bypass has been added.

The enrollment workflow cannot activate a provider or switch sessions. Environment authentication remains authoritative only when startup
policy permits it. Migration 000006 supplies all required tables; no new SQL or
live database changes are needed for this phase.

## Startup gate

`server.go` obtains scope from trusted `AUTH_CONFIG_DEPLOYMENT` and `APP_ENV`,
opens the existing PostgreSQL pool and runs
`ActivationReader.RequireEnvironmentStartup` before preparing **any** provider.
The check is bounded and read-only; it does not use HTTP identities or
`AdminTransaction`. RBAC disablement does not bypass it.

| Observed state | Startup result |
| --- | --- |
| No scoped head, no scoped active lifecycle/history, no database-required head elsewhere | Preserve configured environment provider |
| Explicit environment head, generation zero, no revision/timestamp/history/active lifecycle | Preserve configured environment provider |
| Scoped database-required head | Rehydrate the committed OIDC runtime with validated keys/history, or refuse; never use the environment provider |
| Missing/invalid scope, unreadable DB/schema, inconsistent or orphan activation state | Refuse with safe error |
| Missing scoped head but another head requires database authentication | Refuse ambiguous scope; never assume Local DEV recovery |

This deliberately requires PostgreSQL and migration 000006 even for Local DEV
with RBAC disabled. The existing Local DEV development-only, loopback and fixed
identity checks remain unchanged. A valid explicit environment policy is needed
for an independent unenrolled deployment sharing a database that already contains
a database-required deployment. There is no policy-editing API or fallback flag.
Do not rename deployments or change DB targets to evade a failure. Operators must
protect both configuration values: software cannot establish that an entirely
different, empty database is the intended deployment's authoritative database.

The startup gate does not monitor later policy changes. Internal activation and
version-bound callback draining now exist, but multi-instance synchronization and
reviewed offline recovery remain prerequisites before live activation. Keep heads in their
current unenrolled state until those features are reviewed and delivered.

## Trusted evidence and enrollment

1. In Settings → Authentication, select an approved OIDC revision and run the
   existing isolated **Test Connection** flow. Its state, nonce, PKCE, issuer,
   audience, signature, expiry, browser correlation and network restrictions are
   unchanged. The normal OIDC callback and application sessions are untouched.
2. After verification, the server rechecks the initiating administrator and
   revision under the shared advisory lock. One transaction writes the successful
   test audit, immutable `framework.auth_test_evidence` and its audit. Failure
   releases no usable success evidence. Tests create no user or role.
3. Successful results include an opaque `evidence_id` and `evidence_expires_at`
   plus the existing verified identity. Evidence lasts five minutes from completion
   and is bound to deployment, environment, approved revision, lifecycle generation,
   initiating administrator and isolated-test purpose. No tokens or secrets are
   stored in evidence or returned to the browser.
4. The same active administrator selects **Admin**, **User** or **Viewer** and
   confirms the displayed issuer, subject, revision and role. No role is selected
   by default. The browser submits only:

   ```json
   {
     "evidence_id": "<server-generated UUID>",
     "expected_generation": 3,
     "role": "Admin",
     "confirm": true
   }
   ```

   to `POST /api/admin/auth/settings/{revision_id}/enroll`.

5. Verified authentication, effective `admin.manage`, active user, same-origin and
   JSON protections precede the handler. `AdminTransaction` rechecks authorization
   after acquiring the same lock as administrative revocation. It checks evidence
   ownership, expiry, exact scope/revision/generation/issuer and approved status.
   Unknown JSON fields (including issuer, subject, actor and deployment) are denied.
6. The repository creates or finds the exact `(issuer, subject)` OIDC user. It
   never matches email, copies roles from the initiating administrator, overwrites
   existing profile fields, reactivates disabled users or links accounts. New users
   initially have blank profile fields; normal verified login may populate them.
   Existing roles are retained and the explicitly selected role is added using
   the existing role mutation, last-active-Admin guard and role audit helper.
   Self-role changes and conflicting existing identity providers are denied.
7. `user.roles` records previous/new roles; `auth_config.identity_enrolled` records
   evidence, revision, generation and selected role. Both carry the verified actor,
   target user and database timestamp. Any failure rolls back users, roles and audit.
   A successful enrollment consumes the evidence for this operation using its
   audit event, checked under the shared lock. Concurrent or repeated use returns
   409, including UUID spelling variants. A fresh test is required for another grant.

Responses use existing JSON errors: 400 invalid body/role/confirmation; 401
unauthenticated; 403 denied (including another administrator's evidence); 404
missing or wrong-scope evidence/revision; 409 expired/stale/replayed evidence or
already-assigned role; 503 unavailable database/audit service. Success is 200 with
the existing safe framework user representation. UI notices use the existing
Snackbar system and all twelve locales; Arabic RTL and theme behavior are preserved.

## Boundaries and recovery

- Enrollment grants access but does not establish a session or prove readiness
  for activation. Future activation must recheck the tested identity's **effective**
  `admin.manage`, revision, required normal-callback evidence and recovery policy.
  An Admin role label alone is insufficient if its permissions have been changed.
- Existing approved revisions need a **new** successful test to obtain durable
  evidence. Old in-memory successes have no evidence and cannot enroll identities.
  Test operations remain instance-local; refresh/restart or multi-instance routing
  can require rerunning the test. Durable evidence is not a new public lookup API.
- Evidence replay prevention depends on retaining its enrollment audit record
  while evidence is fresh. Do not prune these rows within the five-minute evidence
  lifetime. Future audit retention must preserve this invariant or add a dedicated
  immutable consumption ledger. The current framework has no audit-pruning worker.
- The single database owner `go_web_app` and trusted backend code remain powerful.
  DB constraints cannot prove an external OIDC handshake against a malicious DB
  owner. No database least-privilege separation is claimed.
- Offline emergency recovery is intentionally deferred. Do not delete activation
  history or select Local DEV as recovery. Keep the existing administrator until
  a separately reviewed activation and recovery process is available.

## Verification

Tests use synthetic signed OIDC tokens and disposable PostgreSQL clusters only:

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

For a UI review, open Settings → Authentication as an administrator. Enrollment
is offered only after a newly successful qualifying test. Confirmation performs
a real user/role mutation in the selected environment; do not confirm against a
live database without authorization. Automated tests exercise the full workflow
without live Auth0 credentials or changes to the development administrator.
