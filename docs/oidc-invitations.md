# OIDC invitations and verified login claiming

Phase 10.3B provides storage and administrator-only manual-invitation APIs.
Phase 10.3C claims eligible invitations during verified normal OIDC login, inside
the existing admission/provisioning/session transaction. Phase 10.3D adds manual
invitation management in Settings → Authentication → User Access. There is no public
claim endpoint, email delivery or SCIM integration. Phase 10.3E adds bounded CSV
bulk invitations through the same repository and verified login claiming. The supported
topology remains one security deployment per database because users/RBAC are global.

## Manual administration UI

User Access groups the access policy, invitations and exact-identity approvals
into three sections. Add User requires an email and audit reason; display name
is optional. The default expiration uses the server's seven-day deadline. Custom
expirations allow 1–30 whole days and remain subject to server validation.
Creating an invitation sends no email and does not prove identity or grant roles.

Administrators can search, filter, page and inspect invitation history. Technical
configuration and claimed-identity identifiers live in the detail drawer, with
copy controls and an action to inspect a linked user. Only pending, current-bound,
unexpired invitations can be revoked. Revocation requires its own audit reason;
under Allow All it does not independently deny login. Use the existing account
deactivation or exact-identity approval controls to remove access.

Writes capture expectations from protected reads. Conflicts preserve form input
and require an explicit refresh and review before another submission. Uncertain
writes block further invitation mutations in the current view and provide a
read-only inspection action; inspect both authoritative invitation records and
the audit history before deciding on any further write. No write is retried
automatically. Closing an edited form requires an explicit discard decision.
Unsent drafts survive internal navigation in identity-scoped memory, without browser
storage. Leaving during a pending write preserves the inspection-required block.
The interface supports all twelve locales, Arabic RTL, and both appearance modes.

## CSV bulk invitations (Phase 10.3E)

Use Import CSV → Preview → Review import → Confirm Import → Import result in the
Invitations section. Files may contain 500 logical data records and 1 MiB of valid
UTF-8, including an optional BOM. Headers are exactly `email` and optionally
`display_name`, in either order. Quoted fields and CRLF/LF are supported. Unknown
columns, malformed quoting and invalid Unicode are rejected. Empty records are
invalid emails. Duplicates and case variants are all excluded. Dots, plus tags and
local-part case are preserved; mailbox equality never proves identity.

All paths below are relative to `/api/admin/auth/access-policy/invitations`:

| Method | Path | Purpose |
|---|---|---|
| POST | `/import/preview` | Read-only validation and signed preview |
| POST | `/import` | Explicitly confirmed atomic import and receipt |
| GET | `/imports/{id}` | Authoritative receipt inspection |
| GET | `?import_id={id}` | Existing paginated list filtered to this import |

CSV endpoints require verified OIDC authentication, active-user `admin.manage`,
trusted scope and the existing same-origin/JSON middleware. Only the two CSV POST
routes accept a larger JSON envelope: six times the CSV bound plus 32 KiB, for
JSON escaping. The decoded CSV limit remains 1 MiB; other endpoint limits remain
unchanged. Duplicate/unknown JSON keys and invalid surrogate escapes are rejected.

Preview accepts `csv`, `expiration_days` (1–30, default 7), the four authoritative
policy/configuration expectations, and optional `selected_rows`. It returns row
numbers, reason codes, counts, current expectations, selected rows,
`content_digest`, `preview_digest` and `preview_expires_at`. It writes no records.
Existing users always require exact-identity review. Claimed history, pending
invitations, stale bindings, disallowed domains and invalid rows cannot be selected.
Expired pending rows can be replaced using the existing retirement/audit lifecycle.
A stale initial expectation returns non-importable rows and current metadata for
an explicit new preview. Selection is re-previewed before confirmation.

A five-minute HMAC covers exact CSV bytes, selection, expiration, scope,
administrator, configuration generations and eligibility classifications. Migration
000011 adds an installation-local signing seed generated from native random UUIDs.
Instances share it through PostgreSQL. It is never returned or audited and reuses
no authentication credential. Runtime seed access is SELECT only; guards prohibit
updates, deletion and truncation. Rotation needs a reviewed forward migration and
invalidates outstanding previews.

Import adds independent UUIDs `import_id` and `idempotency_key`, the preview digest
and expiry, required audit `reason` (at least 8 Unicode characters and at most
512 UTF-8 bytes, without control characters) and `confirm=true`. The existing five-second
administrator transaction/shared advisory lock covers re-authorization, current
binding, reparsing, selection/signature validation, all invitation and expiry
audits, batch audit and receipt. A local race test processes 500 rows with audits
and receipt in roughly 1–1.5 seconds; security timeouts are unchanged. Measure target
latency before broad rollout. No users, roles, approvals or sessions are created
or changed at import time. Existing verified-login claiming remains authoritative.

Migration 000011 stores immutable completed receipts: scope/administrator,
SHA-256 idempotency/content/payload digests, expectations, selected row numbers,
created/skipped/rejected counts, invitation IDs, timestamps and outcome. Raw CSV
and raw idempotency keys are not retained. A deferred constraint trigger requires
new CSV invitations to have the matching atomic receipt; the receipt verifies its
complete invitation set. Historical pre-11 CSV records are not rewritten or
retrospectively constrained.

Identical retries return the existing receipt without another write, even after
preview expiration or configuration changes. Changed payloads with reused keys are
rejected. The UI never retries uncertain writes: it offers Inspect Import Result. A 2xx
response without a validated receipt contract also requires inspection.
CSV/drafts remain in identity-scoped memory only. The non-secret receipt UUID alone
is retained in the `invitation_import` SPA query parameter for refresh/reopen
recovery; result URLs make protected reads only. Missing receipts are not proof of
failure: retain the reference, inspect again and review audit history before a new
write. Failed/rolled-back transactions leave no completed receipt. Results can
filter the existing invitation list to this import.

Apply migration 000011 through the reviewed operator process before serving CSV
endpoints: from clean version 10 advance one step, or from 9 advance two. It is
forward-only, never automatic. The optional production-role proposal includes
SELECT/INSERT receipt and SELECT signing-seed grants; this does not assert that
role separation is deployed. Migrations 000001–000010 are unchanged. Implementation
applies migrations only to disposable test databases.

CSV values render as text. There is no CSV export or spreadsheet-formula output
path. No email, targeted reminders or SCIM are implemented.

## Storage and lifecycle

Migration 000009 creates `framework.oidc_invitations`, a conservative mailbox
canonicalization function, lifecycle/retention triggers and indexes. No records
are backfilled. Apply it only through a separately reviewed operator deployment;
it is not applied at startup. Migration 000010 adds invitation-based approval
provenance. It allows source `invitation`, adds nullable `invitation_id`, and uses
a composite foreign key to the permanently claimed scope/issuer/subject. A trigger
requires a claimed invitation and the original inviting administrator for initial
approval attribution, and prevents changing the invitation reference. Existing
approvals retain their source and receive only a NULL provenance column. There
is no backfill, new administrator, provider activation or role change. Historical
migrations remain unchanged.

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
The old invitation is never reset. No renewal/edit endpoint exists. Expiration is
a deadline for claiming, not an employment-access expiry: after a claim, remove
access through the existing exact-identity approval revocation/user controls.

Creation provenance, configuration binding and invitation contents are immutable.
Only pending rows can transition to revoked, expired or claimed, with generation
advancing exactly once. Terminal rows cannot be changed,
deleted or truncated through normal SQL. Claim fields must be complete and match
an active OIDC framework user; claimed identity is permanent. These structural
constraints complement the access layer's verified-login claim transaction;
there is deliberately no administrator or public HTTP claim endpoint.

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

On a separately approved target, check the clean migration version. From version
9, advance one step using the existing wrapper (from version 8, advance two steps):

```sh
bash scripts/migrate-framework.sh version
bash scripts/migrate-framework.sh up 1
bash scripts/migrate-framework.sh version
```

These are operator instructions, not live actions performed by implementation.
Tests apply migrations only to disposable PostgreSQL clusters. Migrations 000009
and 000010 are forward-only. The wrapper refuses rollback before touching
the journal. Direct `migrate down` is unsupported and deliberately fails, which
can leave a dirty journal. Use compatible application versions or a reviewed
forward corrective migration; do not remove invitation/authentication history.

The migration grants only SELECT/INSERT/UPDATE and mailbox-function execution to
`go_web_app`, retaining the current single-user deployment convention. The
proposed production-role script also inventories these rights for its restricted
runtime role; do not infer that privilege separation is already deployed. No
security-definer functions or request-specific search paths are introduced.

Apply migration 000010 before deploying claim-enabled binaries. The prior
application remains compatible with its nullable provenance addition; existing
approved Auth0 administrators keep their exact approvals and roles. Deploy the
new binaries to every instance before relying on invitations: older instances
cannot onboard an unapproved invited identity. Restart/redeploy is required to
load the code, but no provider activation, configuration revision, policy
bootstrap or session reset is required. There is no automatic migration or
fallback when storage is unavailable. Missing required invitation infrastructure
fails the affected login closed; it is not treated as no invitation.

## Normal-login admission

`PostgresStore.policyLogin` passes the private prepared authenticator's immutable
`auth.Binding` into `OIDCAdmission.Login`. It never guesses a database binding for
an environment/legacy flow. The existing transaction and advisory lock cover:

1. Verified OIDC identity shape, current policy/domain restrictions and exact
   issuer/subject approval. Explicit revocation is always a denial.
2. Exact user lookup. Inactive users and provider collisions are denied before
   any invitation can help.
3. Optional invitation lookup, only for verified email on a normal database-bound
   flow. Scope, issuer, client, revision, activation generation and active revision
   lifecycle generation must match PostgreSQL's current head. Match the existing
   conservative mailbox key exactly; local-part case variants and aliases do not
   match. Elapsed, revoked, claimed, ambiguous and stale invitations cannot help.
4. Admission: Approved Users Only requires either an existing exact approval or
   an eligible invitation. Allow All uses its existing eligibility rules without
   requiring an invitation. An unusable invitation does not independently revoke
   otherwise eligible access. Domain restrictions apply in both modes.
5. Create a missing user and assign the current Viewer/User default once. Preserve
   existing users' roles, including explicit Admin grants. Use verified OIDC profile
   data, not the invitation's suggested display name.
6. Permanently claim the invitation to the exact issuer, subject and user ID using
   a conditional update and database-time expiration. If no approval exists, insert
   an exact approved identity with source `invitation` and its immutable reference.
   The original inviting administrator remains the approval's authorization
   provenance; the verified claimant is the claim/provisioning audit actor.
   Existing approved records are never overwritten.
7. Write the normal hashed, revision-bound session using the existing authority,
   flow-expiration, idle/absolute timeout and transition-deadline safeguards.
8. Commit once. Audit, claim, provisioning, approval and session failures roll
   everything back. No automatic retries occur. An indeterminate commit issues
   no session cookie and returns the existing safe login failure; investigate
   authoritative records instead of assuming the write did not persist.

Concurrent instances share the advisory lock. Repeated logins find the same exact
user/approval and do not repeat the role grant or claim. Approval revocation uses
the same lock and deletes sessions. Existing-session policy enforcement remains
unchanged: sessions cannot claim invitations to repair a missing/revoked approval.

Verification-only OIDC tests never invoke normal session admission. Explicit
verification flow purposes are rejected by Login as defense in depth. Failed,
expired and replayed callbacks cannot claim or provision. A draining provider
may complete an already-authorized normal login within its original bounds but
cannot use an invitation bound to the current or retired revision. No initial
cutover, recovery, last-administrator or provider-transition rules are changed.

## Trust, privacy and next phase

A CSV/manual mailbox is never proof of identity. Claiming requires a verified
mailbox assertion from the trusted active OIDC issuer; identity is permanently
issuer plus subject. Mailbox equality never selects or merges an existing user.
A matching mailbox belonging to a different existing subject, or permanently
claimed by a different subject, blocks the invitation claim and requires an
identity-specific administrative review. Allow All may still admit a separate
identity under its independent policy; it never attaches it to the original user.
This safeguard also survives changes to the original user's current email.

Email reassignment remains a risk even with `email_verified=true`. Before enabling
claims, review Auth0 tenant/upstream connection verification and mailbox uniqueness
controls; a single issuer can contain identities from multiple connections. If
those guarantees are insufficient, require exact-subject administrator review.
Use short expirations and explicit reissue review. A changed issuer/client/revision
must never silently inherit invitations. Pending invitations do not count toward
last-administrator eligibility.

Invitations retain personal data for auditability. Establish a reviewed retention
and redaction policy before a broad rollout; this phase deliberately supplies no
history-deletion endpoint. Phase 10.3E provides bounded CSV parsing, previews,
idempotency receipts and atomic batch auditing. Email delivery and targeted
reminders are not included. This implementation does not prove the live Auth0
tenant's upstream-email trust configuration or automatically approve a deployment
for production onboarding.
