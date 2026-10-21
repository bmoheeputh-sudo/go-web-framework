# Email notification foundation (Phase 10.4B)

This is an internal backend foundation. It registers no HTTP endpoints, starts no
production worker, sends no email, and loads no Gmail or AWS credentials. It adds
no UI or automatic reminder schedules. Existing manual/CSV invitation creation
continues to send nothing. Authentication, approval, role and claiming decisions
remain in the existing OIDC admission implementation.

## Storage and rollout

Migration `000012_email_notifications.up.sql` is forward-only. Apply it through
the reviewed operator migration process **before deploying the changed login
binary**. Do not run it at server startup. Earlier migrations are unchanged.
This phase has only been exercised on disposable databases, not the live DB.

The migration adds nullable `first_successful_oidc_login_at` and
`last_successful_oidc_login_at` to `framework.users`, with no backfill. Enrollment,
user creation, `verified_at`, session expiry and CSV/import dates do not establish
historical normal-login observations. A missing timestamp means unknown history,
not proof of never having signed in. A permanently claimed invitation is separate
positive onboarding evidence and never fabricates either timestamp.

Normal OIDC admission writes the observations only after its existing session
writer succeeds, inside the same advisory-lock transaction. A database trigger
requires a newly inserted, unexpired normal session with the exact issuer and
subject in that transaction. The database supplies observation time, preserves
the first value, and advances the last. Session, audit, admission or observation
failure rolls the complete login back; uncertain commits never authorize a cookie.
Connection tests and activation readiness have no session and cannot observe a login.

Five new tables hold the notification foundation:

| Table | Purpose and boundaries |
| --- | --- |
| `notification_connectors` | Scoped Gmail/SES metadata, immutable connector UUID/provider/sender/region/credential reference, enabled/default state, generation, independent rate budgets and failure tracking. |
| `notification_requests` | Immutable confirmed enqueue receipt, real initiating admin, audited reason, exact template/locale, connector/sender, policy/configuration expectations, communication-policy fingerprint, SHA-256 payload and idempotency digests. |
| `notification_jobs` | Immutable recipient/source snapshot and request/connector binding, due time, state, generation, lease owner/expiry and attempt count. |
| `notification_attempts` | Append-only dispatch intent followed by one immutable accepted/rejected/uncertain completion, provider correlation ID and allowlisted error code. |
| `notification_suppressions` | Exact email key, invitation UUID or user UUID, active flag, optimistic generation and administrator provenance. Each change is audited with its reason and state. |

Requests and all 1–100 jobs commit together, including the enqueue audit. A
deferred database constraint rejects incomplete sets. New jobs must reference a
request inserted in the same transaction and a scoped invitation or exact verified
OIDC user. Request/job identities and connector sender bindings cannot be rewritten.
Only one enabled connector per scope can be default. Deletion/truncation is denied;
terminal jobs and completed attempts cannot be reset or edited.

Operational PII consists of existing contact information and bounded snapshots;
raw CSV, message bodies, access tokens, plaintext idempotency keys and OAuth/AWS
credentials are absent from these tables. Audit records contain references, fixed
codes and audited reasons, not recipient snapshots or provider response bodies.
History is retained in this phase. Any future PII expiry/redaction policy needs a
reviewed forward migration that preserves receipts, audit attribution and deduplication.

The supported topology remains one security deployment/environment per database.
Repositories validate trusted scope and reject mixed policy/activation deployments.
Communication configuration is deployment-owned: fixed HTTPS application origin,
explicit recipient domains and a cooldown of 72 hours by default (72 hours–30 days).
Its fingerprint fences jobs across instances configured differently. It cannot
relax OIDC allowed domains or change admission eligibility.

## Dual connectors

Both connectors can coexist. Administrator code can select the enabled default or
an explicit enabled connector when enqueuing. Selection captures the immutable
connector UUID and sender in the request and every job. Later default changes do
not rebind pending jobs. Sender/configuration identity changes require a new UUID;
enabled/default flags and per-minute/per-day budgets use generation checks.

| Connector | Foundation contract | Next adapter work |
| --- | --- | --- |
| Gmail | Dedicated sender mailbox, offline delegated OAuth, exactly `gmail.send`; only an opaque `notifications/...` credential reference is stored. | Approved Cloud project/OAuth consent and Workspace policy; secure offline authorization, refresh/revocation handling, sender-alias checks, safe API error mapping and quota integration. Domain-wide delegation is not assumed. |
| SES | Explicit AWS region and approved sender; credential mode is the AWS SDK default credential chain. No access-key fields or stored credential reference. | AWS SDK v2 adapter, workload/IAM role and sender-scoped permissions, production access and regional verified-identity checks, regional quotas, safe API errors and authenticated bounce/complaint ingestion. |

`sender_approved` records operator/administrator attestation; it does not claim that
provider identity verification or authorization has occurred. Connector status is
`disabled`, `configured` or `degraded`, not proof of working credentials. Rate limits
are separately configurable per connector (1–60 attempts/minute, 1–100,000/rolling
24 hours). Counted attempts reserve capacity at dispatch, including uncertain or
rejected attempts. Gmail's quota and SES's account/region limits must also be enforced
by the future adapters; configured values are not claims about provider quotas.

Credentials must use a notification-specific secret store/access policy. Do not
reuse OIDC client-secret rows, the OIDC ciphertext envelope or Auth0 credentials.
No credentials are required to construct or test this foundation.

Reference contracts: [Gmail send scope](https://developers.google.com/workspace/gmail/api/auth/scopes),
[offline OAuth](https://developers.google.com/identity/protocols/oauth2/web-server),
[AWS SDK credential chain and region selection](https://docs.aws.amazon.com/sdk-for-go/v2/developer-guide/configure-gosdk.html).

## Internal repository and worker

`authconfig.NewNotificationRepository` reuses the existing access-policy repository,
administrator transaction, five-second deadline, shared PostgreSQL advisory lock and
atomic auditing. Administrator operations require verified OIDC and recheck active
identity and effective `admin.manage` inside the transaction. There are operations
to configure/read connectors, enqueue/read receipts, list/read jobs and attempts,
inspect eligibility, set/read suppressions and cancel queued/leased jobs.

The request UUID is chosen before writing so an uncertain response can be inspected
using `ReadRequest`. An identical key/payload returns the original receipt without
creating jobs, even after configuration changes. Changed payload/key reuse is a
conflict. A missing read does not prove rollback; do not blindly retry an uncertain
operation. No repository operation retries uncertain commits.

`NotificationRepository.Worker()` exposes only `Acquire`, `Begin`, `Complete` and
`ResolveExpired`. It accepts no fabricated administrator authentication context.
Work is attributed to the original administrator; dispatch/result audits explicitly
identify worker execution, and attempts record the executor UUID. The initiating
administrator must remain active with `admin.manage` before a provider call begins.

The optional production-role proposal grants a separate
`go_web_notification_worker` role queue/attempt/health/audit capabilities and the
minimal supporting reads. It cannot mutate users, roles, approvals, invitations,
suppression policy, connector configuration or requests, and cannot read encrypted
OIDC secrets. No worker login credentials are provisioned or service started.

Acquisition uses `FOR UPDATE SKIP LOCKED`, at most 20 jobs and 5-second–5-minute
leases, inside short shared-lock transactions. The shared lock also serializes
authorization changes, recipient cooldown checks and connector quota reservations.
Generation, owner, exact expiry and connector checks fence stale work. Provider
calls happen only after a dispatch marker definitively commits, with no database
transaction held across the call. A future production runner must bound provider
timeouts below its lease and choose batches that can start within that lease.

`notifications.RunOnce` is an explicit internal orchestration helper, with no
startup registration or scheduling loop. It selects adapters by immutable
**connector ID**, checks the expected provider and never selects a fallback.
Fake Gmail and fake SES adapters have no transport. Missing adapters leave a job
known not to have entered provider execution; lease recovery can requeue it safely.

## Delivery state machine

| Current state | Event | Next state |
| --- | --- | --- |
| Queued | Acquire a due job | Leased |
| Queued/Leased | Admin cancellation or eligibility failure | Cancelled |
| Leased | Lease expires before dispatch marker | Queued, new generation; safe to acquire again |
| Leased | Recheck eligibility, reserve quota, persist dispatch intent | Dispatching, new generation and attempt |
| Dispatching | Provider explicitly accepts | Sent; accepted attempt and optional provider message ID |
| Dispatching | Provider explicitly rejects | Failed; rejected attempt |
| Dispatching | Ambiguous/invalid result | Needs Inspection; uncertain attempt |
| Dispatching | Lease expires without confirmed result | Needs Inspection; uncertain attempt |

Sent, Failed, Cancelled and Needs Inspection are terminal in this phase. There are
no automatic retries for rejected or uncertain sends. An expired dispatch marker is
conservatively uncertain even if a crash happened immediately before the actual
call. A late executor cannot defeat fencing. An uncertain marker commit returns
no dispatch capability; external sending must not proceed.

Provider acceptance is **not confirmed inbox delivery**. Future SES delivery,
bounce and complaint events can correlate by connector/provider message ID through
the provider-neutral `ProviderEvent` contract. Such events are also not onboarding
evidence. Successful employee onboarding requires exact-identity normal-login
observations or existing permanent claim evidence, not email opens or clicks.

PostgreSQL and an external email service cannot share one atomic commit. If a
provider accepted but storing its result/audit fails, retain the dispatch intent
and resolve it to Needs Inspection; do not send again or fail over to another
connector. An operator inspection/evidence workflow is a release requirement for
10.4C. It must preserve historical attempts rather than reset/retry an uncertain job.

## Eligibility, templates and reminders

Every dispatch rechecks current OIDC revision/lifecycle/client/activation/policy
bindings, communication configuration, allowed domains, recipient snapshot,
suppression, cooldown and positive onboarding evidence. An invitation must remain
current, pending and unexpired. An existing user must be active with a verified
address and exact current issuer; revoked approvals deny sends and Approved Users
Only requires an exact approval for user-targeted notifications. A mailbox match
to an existing user is review-only and never chooses, merges or reactivates a user.

Suppressions target exactly one canonical mailbox or an explicit invitation/user
reference. They do not modify authentication or authorization, including Allow All.
Queued/leased messages become cancelled at the dispatch check when suppressed;
already dispatched/accepted messages cannot be recalled. A recent accepted attempt
blocks another notification for the recipient across connectors. Queued, in-flight
or uncertain work also prevents duplicate requests. Case variants are treated
conservatively for communications deduplication without merging identities.

There are no automatic reminder plans or employee roster tables. Known targets do
not represent the entire workforce. Manual reminder jobs use the same checks as
invitation jobs and stop when positive onboarding evidence is present.

The immutable message contract contains approved sender, one recipient, fixed
subject, plain text, escaped optional HTML and deterministic `vgca.<job UUID>`
reference. The versioned `onboarding.v1` contract accepts all 12 application locales;
editorial translations are intentionally deferred to 10.4C and English foundation
copy is the fallback. Only display name is personalized. Header controls and unknown
template/locale values are rejected. The fixed application link is derived from
the deployment-owned HTTPS origin and always `/api/auth/login`, without tokens,
credentials, arbitrary redirects or access grants. Message formatting is redacted.

## Validation and remaining delivery work

Tests use private disposable PostgreSQL clusters and synthetic identities. Coverage
includes migration compatibility/no backfill, successful/repeated/exact-session
observations and rollback, connection/readiness isolation, idempotency, concurrency,
leases/crashes/fencing, all outcomes, uncertain commits and result-audit failure,
suppression/cancellation, revoked/inactive/onboarded targets, scope isolation,
default/explicit connectors, cooldown, role restrictions and calls outside transactions.

Before enabling real delivery, implement and review both actual adapters, secure
credential resolution, provider identity/readiness checks, production timeout and
quota policies, explicit uncertainty inspection, authenticated SES event validation
and replay protection, localized editorial content and administrator preview/send/
history UI. Automatic scheduling and an authoritative employee inventory remain
separate later work. No real delivery should be enabled merely because a connector
record is configured.
