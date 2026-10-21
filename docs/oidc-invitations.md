# OIDC invitation foundation

Phase 10.3B adds storage and administrator-only manual-invitation APIs. It does
not claim invitations during login, send email, import CSV, create users, change
approvals or roles, or change authentication/session admission. A pending
invitation currently grants no access. The supported topology remains one
security deployment per database because framework users and RBAC are global.

## Storage and lifecycle

Migration 000009 creates `framework.oidc_invitations`, a conservative mailbox
canonicalization function, lifecycle/retention triggers and indexes. No records
are backfilled. Apply it only through a separately reviewed operator deployment;
it is not applied at startup. Historical migrations are unchanged.

An invitation is bound to the server-configured deployment/environment and the
currently active database-managed OIDC revision, lifecycle generation, activation
generation, exact issuer and client ID. No issuer, subject, actor or scope is
accepted from administration request bodies. Configuration changes make existing
bindings non-current; list/read preserve their history and report
`binding_current=false`. New writes require fresh authoritative expectations.
Environment-managed OIDC and Local DEV cannot create invitations.

The API accepts conservative ASCII dot-atom mailboxes, not display-name addresses,
quoted local parts, IP-literal domains or internationalized local parts. DNS
domains are lowercased; local-part case, dots, apostrophes and plus tags remain
unchanged. Pending local-part case variants conflict instead of being treated as
the same verified identity. A database unique index enforces this across writers.

The default expiration is seven 24-hour days from PostgreSQL time. An explicit
expiration must be future and no more than 30 days away. Reads and status filters
report elapsed pending rows as expired using database time, without writes or a
worker. A replacement creation retires a matching elapsed pending row, advances
its generation and audits that transition atomically before inserting a new UUID.
The old invitation is never reset. No renewal/edit endpoint exists.

Creation provenance, configuration binding and invitation contents are immutable.
Only pending rows can transition to revoked, expired or (in a future phase)
claimed, with generation advancing exactly once. Terminal rows cannot be changed,
deleted or truncated through normal SQL. Claim fields must be complete and match
an active OIDC framework user; claimed identity is permanent. These structural
constraints do not implement claim authorization: no claim repository method or
HTTP endpoint is provided in this phase. Approval-source changes are deliberately
deferred until the claim transaction is implemented.

Revoking a pending invitation is not user deactivation or identity-approval
revocation. In particular, it does not deny someone otherwise eligible under
Allow All. Existing users, approvals, sessions and roles are untouched.

## Protected API

All paths below are relative to `/api/admin/auth/access-policy`:

| Method | Path | Result |
|---|---|---|
| GET | `/invitations` | Paginated items, total, policy/activation/revision expectations |
| POST | `/invitations` | New immutable pending invitation, HTTP 201 |
| GET | `/invitations/{id}` | Scoped metadata and effective lifecycle |
| POST | `/invitations/{id}/revoke` | Pending-to-revoked transition |

List accepts only `search`, `status` (pending/claimed/revoked/expired), `offset`
(default 0, maximum 100000) and `limit` (default 20, range 1–100). It includes
historical bindings. Sort is creation time descending, then ID.

Creation JSON contains:

```json
{
  "email": "Employee@example.com",
  "display_name": "Employee",
  "expected_policy_generation": 1,
  "expected_activation_generation": 1,
  "revision_id": "<active revision UUID>",
  "expected_revision_generation": 4,
  "reason": "Approved employee onboarding"
}
```

`display_name` is optional and limited to 200 Unicode characters without control
characters. `expires_at` is optional RFC3339. Reason is required, 8–512 bytes with
no control characters. Revocation JSON contains the four policy/configuration
expectation fields above, `expected_invitation_generation`, and `reason`; it does
not accept mailbox, identity or role fields.

Authentication, active-user authorization and effective `admin.manage` are
required. The existing same-origin/application-JSON middleware and strict 16 KiB
request decoder apply. Every repository read/write uses the existing bounded
administrator transaction; writes recheck scope, policy, configuration and
permission after acquiring the shared advisory transaction lock. Mutations and
approved-field audit records commit together. Audit details contain invitation ID,
scope, revision, generation, state and reason, not raw mailbox/profile payloads.
Do not put credentials or unnecessary personal data in operator-supplied reasons.

Responses use `Cache-Control: no-store`. Invalid input/domain violations return
400; authentication/authorization failures return 401/403; missing scoped records
or policy return 404; duplicates, stale generations, terminal state and inactive
configuration conflicts return 409; unavailable infrastructure/audit failures
return 503. Internal SQL and credentials are not returned.

An uncertain commit returns HTTP 503 with:

```json
{
  "error": "oidc_invitation_commit_uncertain",
  "automatic_retry_allowed": false,
  "inspection_required": true
}
```

No automatic retries are performed. After a lost/uncertain response inspect the
scoped list/read and audit history before deciding on another write. Creation
has uniqueness protection but no client idempotency receipts yet. A subsequent
409 is not a substitute for establishing the previous commit outcome.

## Deployment

On a separately approved target, check the clean migration version and advance
one step from version 8 using the existing wrapper:

```sh
bash scripts/migrate-framework.sh version
bash scripts/migrate-framework.sh up 1
bash scripts/migrate-framework.sh version
```

These are operator instructions, not actions performed by implementation/tests.
Migration 000009 is forward-only. The wrapper refuses rollback before touching
the journal. Direct `migrate down` is unsupported and deliberately fails, which
can leave a dirty journal. Use compatible application versions or a reviewed
forward corrective migration; do not remove invitation/authentication history.

The migration grants only SELECT/INSERT/UPDATE and mailbox-function execution to
`go_web_app`, retaining the current single-user deployment convention. The
proposed production-role script also inventories these rights for its restricted
runtime role; do not infer that privilege separation is already deployed. No
security-definer functions or request-specific search paths are introduced.

## Trust, privacy and next phase

A CSV/manual mailbox is never proof of identity. Future claiming must require a
verified email from the trusted active OIDC issuer and bind permanently to its
exact subject inside the existing provisioning/audit/session transaction. It must
not run during isolated tests, readiness callbacks, or retired-provider callbacks,
override revoked approvals, reactivate users, merge by email, or grant Admin.

Email reassignment remains a risk even with `email_verified=true`. Before enabling
claims, review Auth0 tenant/upstream connection verification and mailbox uniqueness
controls; a single issuer can contain identities from multiple connections. If
those guarantees are insufficient, require exact-subject administrator review.
Use short expirations and explicit reissue review. A changed issuer/client/revision
must never silently inherit invitations. Pending invitations do not count toward
last-administrator eligibility.

Invitations retain personal data for auditability. Establish a reviewed retention
and redaction policy before a broad rollout; this phase deliberately supplies no
history-deletion endpoint. Future CSV import needs bounded authoritative parsing,
preview, idempotency receipts and atomic batch auditing. Future claim work must
add explicit approval provenance and race/revocation tests before invitations can
authorize onboarding. No frontend or CSV workflow is included here.
