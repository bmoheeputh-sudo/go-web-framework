# OIDC access policy storage (Phase 10.2B)

This phase adds **storage and internal administrator operations only**. It does
not enforce a login policy, change callbacks, issue different sessions, grant
roles, activate a provider, or add HTTP/UI controls. Current Auth0 OIDC, Local DEV,
RBAC, sessions, enrollment and recovery continue using their existing behavior.
An absent policy is not interpreted as either login mode by runtime code.

## Deployment boundary

**One security deployment per database is required.** Policy and approval rows
carry the trusted deployment/environment scope, but users, roles, permissions and
account associations are still global database records. Separate development,
test and production databases; scoped policy rows do not provide multi-tenant
RBAC isolation. Never take repository scope from HTTP request data.

## Migration 000008

`framework.oidc_access_policies` stores mode (`allow_all` or
`approved_users_only`), canonical allowed email domains, default role (`Viewer`
or `User`), optimistic generation, creator/modifier UUIDs, timestamps and reason.
Its primary key is deployment/environment.

`framework.oidc_identity_approvals` stores exact, case-sensitive issuer/subject
keys within that scope, status (`approved` or `revoked`), generation and
administrator provenance. It references the scoped policy. An approval does not
create a user, link by email, activate a disabled user, grant a role or constitute
proof that an identity has authenticated. Pending invitations are **not**
approvals; a future trusted invitation/CSV/SCIM adapter must resolve the verified
issuer/subject and call an authorized write path. There is no parallel user
database or email-merge capability. Future machine provisioning needs a separate
authorization/attribution review; it must not fabricate an administrator context.

The migration creates no rows and changes no existing tables or grants. Primary
keys serve scoped policy lookup, exact approval lookup and paginated
issuer/subject listing. Foreign keys preserve administrator references. Triggers
require generation 1 on insert and exactly +1 on updates, preserve identity and
creation provenance, and refuse deletion/truncation. Revocation is retained;
before/after audit records preserve change history. Migration files 000001–000007
remain unchanged.

The current application's runtime still works at schema version 7: it does not
query these tables. Calling the new repository before migration 8 returns a safe
unavailable error. No bootstrap is required to keep existing Auth0 access.

After review, an operator with the approved migration connection may apply:

```bash
# Use the established PG* migration connection, checking the database first.
scripts/migrate-framework.sh version
# Only when the clean current version is 7:
scripts/migrate-framework.sh up 1
scripts/migrate-framework.sh version
```

These commands have not been run against development. The wrapper forbids down,
goto, force and drop before changing the journal. As with migrations 5–7, direct
golang-migrate `down` is unsupported: the refusing down SQL preserves data but
can leave its journal dirty. Production rollback uses a compatible application
version or a reviewed forward corrective migration, not deletion of policy
history or a no-op down migration.

The optional production role proposal recognizes these two tables when present:
SELECT/INSERT/UPDATE only, plus EXECUTE on the domain constraint helper. After
applying migration 8 in a deployment already using separated roles, the operator
must review/reapply the corresponding ownership and grants; the historical
`go_web_app` grant alone is not a runtime privilege rollout. Nothing applies that
proposal automatically.

## Internal repository API

`authconfig.NewAccessPolicyRepository(store, trustedScope)` needs the existing
access store, not encryption keys. Every method uses `AdminTransaction`, verified
identity/principal correlation, active-user and effective `admin.manage`
revalidation, the shared advisory transaction lock and a five-second deadline.

| Method | Behavior |
| --- | --- |
| `Read(ctx)` | Read current scoped settings; missing policy is `ErrNotFound`. |
| `Bootstrap(ctx, activationGeneration, settings, reason)` | Explicit first policy and approval of the already authenticated OIDC administrator. |
| `Update(ctx, PolicyExpectation, settings, reason)` | Replace settings only at the expected policy and activation generations. |
| `ReadApproval(ctx, identityKey)` | Exact scoped issuer/subject lookup. |
| `ListApprovals(ctx, offset, limit)` | Bounded, stable-order listing (maximum 100 per page). |
| `SetApproval(ctx, PolicyExpectation, key, approvalGeneration, status, reason)` | Explicit creation (generation 0) or versioned approval/revocation; no silent upsert. |

No actor UUID, email identity match, provider selection or authorization claim is
accepted as proof of authority. The actor comes from verified request context.
Writes use parameterized SQL and atomically insert typed, bounded audit details
with `oidc_access.*` actions. Audit failure rolls back the business write.
Conflicts return `ErrConflict`; lockout attempts return
`ErrLastOIDCAdministrator`. Errors do not disclose SQL or connection data.
An uncertain commit retains the existing `ErrCommitUncertain` behavior: inspect
the authoritative policy/approval generations and audit before any manual retry.

## Explicit bootstrap for an existing OIDC administrator

The future protected administration adapter must:

1. Use trusted server scope and read the authoritative database activation
   generation. This initial bootstrap supports an already database-managed OIDC
   deployment, not environment-only authentication.
2. Obtain explicit settings and a meaningful reason (8–512 bytes, no controls).
3. Call `Bootstrap` under the existing verified administrator context.

Inside the shared lock, bootstrap requires the expected active OIDC head and
active configuration lifecycle, the caller's exact issuer matching that active
revision, an OIDC principal, and effective `admin.manage`. It inserts one policy
and one approval for that **existing administrator** with two atomic audit events.
Duplicates conflict. It never creates users or assigns Admin or any other role.
Other existing administrators must receive explicit identity approvals before
future enforcement of `approved_users_only`; do not bulk-approve all users merely
because they already have a database record.

There is intentionally no CLI, HTTP bootstrap route or runtime startup bootstrap
in this phase. A future protected management interface will call this method.

## Validation and lockout protection

- Domain lists contain at most 20 exact ASCII DNS domains (IDNs as A-labels),
  each at most 253 bytes. Case is normalized to lowercase and lists sorted.
  Reject duplicates, whitespace, URLs, email addresses, wildcards, IP literals
  and trailing dots. Subdomains are not implicitly allowed.
- Domain eligibility requires a plain mailbox and `email_verified=true`.
  Email is used only as an eligibility attribute, never an identity key.
- Default roles are Viewer/User only. A write additionally rejects a default role
  that currently grants `admin.manage`; role names alone do not prove this.
- Policy and approval changes must leave an active OIDC user from the **current
  active issuer** with effective `admin.manage`, matching verified email domain
  if restricted, and an approval in approved-only mode. Explicit revocation
  excludes an identity in either mode. Local DEV and historical/other issuers
  cannot satisfy this guard.
- Policy/approval generations prevent lost updates, and expected activation
  generation prevents a write prepared for a previous provider. All operations
  share the existing RBAC/activation advisory lock.

These are guards on **these repository writes**, not complete future login
enforcement. Stored email claims can become stale; the future callback must
evaluate fresh verified claims. Later role changes, user deactivation or provider
activation must revalidate policy eligibility before login policy enforcement is
enabled. A future change granting `admin.manage` to the default role must also be
blocked or make automatic onboarding fail closed. Those existing operations and
their current security rules are deliberately unchanged here.

## Next phase and tests

Before enforcement, integrate one transactional admission check after verified
OIDC token claims and before session creation; cover existing sessions and
deprovisioning explicitly. Reuse `framework.users`, exact issuer/subject keys and
RBAC. Never assign Admin from authentication, domain membership, approval or
import. Multi-instance policy reads must use authoritative generation-aware
storage without stale permissive fallback. No new polling/listener is added here.

Disposable-cluster tests cover empty migration and schema-7 compatibility,
attributed bootstrap, exact identity isolation, scoped reads, domain validation,
effective default role checks, policy/approval conflicts, concurrent writes,
authorization rechecks, lockout protection, audit rollback, database failures,
database constraints, unchanged runtime data and the forward-only migration
policy. They never use the application's DB_* configuration.
