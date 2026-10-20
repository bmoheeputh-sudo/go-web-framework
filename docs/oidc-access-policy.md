# OIDC access policy enforcement (Phase 10.2C)

Normal OIDC login now requires an explicitly initialized access policy. There is
no default allow mode, startup bootstrap, automatic approval, or Local DEV
fallback. This release adds no administrator UI or policy HTTP endpoints.

## Deployment boundary and prerequisites

**One security deployment per PostgreSQL database is required.** Users, roles,
permissions and account associations remain database-global. Policy and approval
rows are deployment/environment-scoped; they are not multi-tenant isolation.
Runtime admission rejects multiple policy scopes or another database-managed
activation scope. Use separate databases for development, test and production.
Scope comes only from `AUTH_CONFIG_DEPLOYMENT` and trusted `APP_ENV`.

Migration 000008 is required for OIDC enforcement. Migrations 000001–000008 are
unchanged, and neither startup nor the new command applies migrations. Local DEV
remains development-only and environment-controlled. Missing or unreadable policy,
invalid default-role permissions, or absence of an eligible explicitly approved
OIDC administrator prevents database OIDC startup/rehydration. It never selects
an alternative provider. Already running instances fail closed on affected
credential operations if policy cannot be read.

## Safe rollout for an already active Auth0 deployment

Do not restart all instances with enforcement before bootstrap. Perform this
sequence under an approved maintenance/change procedure; none is automatic:

1. Keep the previous release running with the existing database-managed OIDC
   configuration. Confirm an independent login by an active, enrolled OIDC
   administrator with effective `admin.manage`. Obtain a fresh **application
   session cookie**, not an Auth0 access token or ID token, from that login.
2. If necessary, separately review and apply the existing migration 000008 using
   `scripts/migrate-framework.sh up`. Confirm the migration journal is clean.
   No new migration is introduced here. For the optional separated production
   roles, review the migration-8 grants in `database/scripts/production-roles.sql`
   before rollout. The current single `go_web_app` owner is not least privilege.
3. Read the authoritative activation generation through the existing protected
   activation-status endpoint. Choose the mode, default Viewer/User role, and
   optional exact domains explicitly. Check the administrator's verified email
   against those domains; an Admin role never bypasses domain eligibility.
4. Build the offline bootstrap command from this release. Run it with the same
   trusted deployment, environment, DB and session-timeout settings as the
   running server. It does not load or change `.env`, provider settings, keys,
   revisions, roles or session expiry. Do not use `bootstrap-admin` for this.

   ```bash
   cd ~/project/go-web-framework/backend
   go build -o /tmp/bootstrap-access-policy ./cmd/bootstrap-access-policy
   # Load trusted server configuration through your existing operator process.
   # Enter the CURRENT opaque application session cookie at the hidden prompt.
   # Never paste it into a command argument, source file, ticket or log.
   read -r -s -p 'Existing OIDC administrator session cookie: ' policy_session
   printf '\n'
   printf '%s' "$policy_session" | /tmp/bootstrap-access-policy \
     --expected-activation-generation <CURRENT_GENERATION> \
     --mode approved_users_only --default-role Viewer \
     --allowed-domains vopak.com \
     --reason 'Approved OIDC access-policy rollout' --confirm
   unset policy_session
   ```

   Replace the generation placeholder; choose actual policy settings deliberately.
   Omit `--allowed-domains` for no domain restriction. Disable shell tracing and
   terminal/session recording while handling the cookie. The command never prints
   it and reads it only from stdin. It requires operator database access **and**
   a valid, unexpired, current-revision/generation/client-bound OIDC session of an
   already active administrator. A supplied issuer, email or actor UUID is not
   accepted. Legacy/unbound and draining sessions are refused.

5. Bootstrap atomically inserts the policy, the exact administrator approval and
   two audit events. It refreshes that user's claims only from the already
   verified session. It creates no users and grants no roles. A duplicate attempt
   conflicts. On an uncertain commit, inspect policy and audit records before any
   retry. If the policy already exists from Phase 10.2B, inspect its eligibility
   instead of bootstrapping again.
6. For `approved_users_only`, explicitly approve every other intended OIDC
   identity using the trusted `AccessPolicyRepository.SetApproval` adapter before
   expecting it to log in. The policy UI is deferred to Phase 10.2D; there is no
   new bulk-approval tool. Bootstrap approves only the proven administrator.
   Do not manually grant Admin to solve missing login approval.
7. Deploy/restart all instances with this release, verify startup and an
   administrator login, then test an eligible non-admin and a denied identity.
   Until all instances are updated, old instances do not enforce the new policy;
   use a controlled maintenance cutover rather than claiming mixed-version
   enforcement. Later policy changes need no restart or cache invalidation.

If bootstrap cannot be completed, keep the prior release running and resolve
prerequisites before deployment. Do not clear activation history or change
`AUTH_PROVIDER` to work around enforcement. This command needs an existing valid
session; it is **not emergency recovery** and cannot rescue a deployment whose
administrators cannot authenticate.

## Admission, provisioning and sessions

`auth.PostgresStore.WithAccessPolicy` installs the deployment-bound
`access.OIDCAdmission`. The server's environment OIDC store, activation service
and startup/synchronization loader all install it. Database-bound stores retain
all existing revision, generation, issuer, client, flow-purpose and draining
predicates. The low-level storage constructor remains usable without admission
for isolated storage tests; production construction must install admission.

After signature, issuer/audience, nonce, PKCE and one-time callback verification,
normal session creation runs inside the existing five-second administrative
advisory-lock transaction:

- Read the current policy and exact issuer/subject approval. Explicit revocation
  denies either mode. Approved-only requires `approved`; domain membership is
  never an approval.
- When domains are configured, require verified email and an exact lowercase
  domain match. No wildcard, subdomain, suffix, display-name or email identity
  merging. Issuer and subject remain byte-exact, including trailing slashes.
- Refuse inactive users and provider collisions. Create an unknown eligible user
  and assign Viewer/User exactly once; existing users retain their explicit
  roles, including an empty role set. Reject a default role with `admin.manage`.
- Audit new provisioning as the verified newly created user, including only the
  default role and deployment scope. Insert/rotate the session in the same
  transaction. Any audit, credential-write or commit failure rolls back user,
  role and audit changes. No session cookie is issued on failure.

Every session use repeats policy/user checks against PostgreSQL with no
per-instance cache, including `/api/auth/me` and other authenticated routes.
Both stored verified session claims and the user's latest verified login claims
must satisfy domains. Policy checks share the mutation lock with revocations;
activity updates are not committed on infrastructure/policy errors. Denied
credentials are deleted; approval revocation, user deactivation and policy
restriction updates also revoke affected sessions atomically. Reapproval cannot
resurrect deleted sessions. Existing idle/absolute expiry and 30-minute maximum
draining deadlines remain in force.

`/api/access/me` is read-only for OIDC and cannot provision unknown users. Trusted
environment Local DEV retains its development self-registration. Isolated and
normal-callback readiness tests remain sessionless: they do not enter session
creation/admission, provision users, consume approvals, grant roles or activate
providers.

## Administrator safety and repository interfaces

`AccessPolicyRepository` retains `Read`, `Bootstrap`, `Update`, `ReadApproval`,
`ListApprovals`, and `SetApproval`. `BootstrapSession` is the new offline rollout
adapter; it reuses the bootstrap transaction body and error mapping. The normal
repository uses `AdminTransaction`; session bootstrap verifies a hashed existing
credential inside the same advisory-lock protocol without manufacturing a
request principal. Reasons, optimistic policy/approval/activation generations and
atomic audits remain mandatory.

Startup and mutation guards require an active OIDC administrator from the active
issuer, effective `admin.manage`, an **explicit approval even in allow-all mode**,
and domain eligibility. User deactivation, role removal, permission changes,
policy/approval updates and activation/recovery share this guard. Authorization
also rechecks policy after acquiring the mutation lock, preventing a request
started before approval revocation from retaining administrator write authority.
Activation additionally checks that the specific tested/enrolled administrator is
eligible; offline recovery requires an eligible administrator of its target
issuer and cannot grant access as a side effect.

## Boundaries and outstanding work

- Fresh Local DEV-to-OIDC deployments and environment-only OIDC deployments have
  no currently supported bootstrap proof for this policy. The existing 10.2B
  bootstrap requires an already active database OIDC issuer. Initial activation
  now refuses missing policy rather than creating approval from test success.
  A separate reviewed candidate/evidence-bound bootstrap is needed for those
  deployments. This is an explicit rollout blocker, not a fallback option.
- Preparing a different recovery/activation issuer requires an explicitly
  approved eligible administrator for that issuer before transition. The offline
  recovery authorization model cannot override login policy.
- No external provider deprovisioning feed exists. Domain/claims are the latest
  server-stored verified information; detecting IdP-only changes requires a fresh
  login, expiry or a future reviewed SCIM mechanism. Local user deactivation and
  approval/policy changes take effect through PostgreSQL immediately.
- Every authenticated OIDC request takes the shared advisory lock and reads the
  policy. This favors simple, strict revocation semantics over maximum throughput;
  measure contention before scaling. There are no uncontrolled retries.
- Requests already admitted can finish; the framework rechecks permissions and
  policy for protected mutations. DB superusers/schema owners remain trusted.
- Phase 10.2D still needs protected policy management UI/API adapters, explicit
  additional approvals, and user-facing policy-denial translations. Login denial
  currently preserves the existing generic safe `login_failed` response.

Tests use synthetic signed tokens and disposable PostgreSQL clusters only. They
cover actual normal callbacks, two runtime instances, domain/approval/user checks,
concurrent provisioning, transactional rollback, bootstrap proof, last-admin
protection and unchanged sessionless readiness/activation/recovery behavior.
