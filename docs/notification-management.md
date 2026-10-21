# Email notification management (Phase 10.4D)

Settings → Notifications contains Email Connectors, Send Invitations, Send
Reminders, Email History and Onboarding Overview. Despite the navigation labels,
this phase **only queues confirmed requests**. The server registers no sending
worker, scheduling loop, simulated-send endpoint, resend endpoint or provider
failover. Invitation creation and CSV import still send nothing.

## Deployment requirements

No new migration is required. Migrations 000001–000013 are unchanged. Deploy only
after the existing invitation/import/notification/connector migrations through
000013 have been applied using the reviewed operator process. No live migrations,
database records, provider credentials, Auth0 configuration or `.env` files were
changed during implementation.

New deployment-owned, non-secret communication settings:

| Setting | Behavior |
| --- | --- |
| `NOTIFICATION_ALLOWED_DOMAINS` | Required comma-separated exact recipient domains, for example `example.com,example.org`. No wildcards. This further restricts, and never relaxes, OIDC allowed domains. |
| `NOTIFICATION_COOLDOWN_HOURS` | Optional integer, 72–720 inclusive; defaults to 72 hours. |
| Existing approved application origin | Must be HTTPS for the existing email-template contract. The fixed login link is always `<origin>/api/auth/login`. |

All instances must use identical communication settings; the existing persisted
communication-policy digest fences different configurations. Missing or invalid
settings disable preview/queue operations and label targets unavailable. History,
receipts, observations, cancellation and suppression remain inspectable under
current administrator authorization. Existing connector configuration is separate.

Queueing requires an enabled Gmail or SES connector with a fresh Ready observation
for its current generation. A successful connection test is a readiness observation,
not evidence of sending permission, inbox delivery or employee onboarding. No
credential is loaded and no provider API is called by the new management APIs.

## Administrator workflow

1. Select pending invitation records, optionally filtered by a CSV import receipt
   UUID. Manual reminders can also target exact, verified existing OIDC user records
   without known positive onboarding evidence. Selections span bounded pages and
   stop at 100 records. No arbitrary recipient-email input is accepted.
2. Choose an enabled, ready connector and preview. The server evaluates current
   policy, exact references, configuration, recipient provenance, activity,
   approvals, suppression, ambiguity and cooldown. Skipped rows retain explanations.
3. Review recipient-specific sender, subject and plain-text content. HTML is never
   injected into the administrator DOM. The existing approved `onboarding.v1`
   template remains English; the UI explicitly discloses this. The administration
   interface itself is translated into all 12 languages.
4. Enter an audited reason, explicitly confirm the ready count and choose **Queue
   emails**. Only the eligible preview selection enters the existing durable queue.
   All invitation/user eligibility is checked again inside the same transaction.
5. Inspect the immutable request receipt or paginated history. Queued is distinct
   from Sent. No history row is marked accepted merely because it was confirmed or
   previewed. Pending jobs can be cancelled with a reason and expected generation.

The original request UUID is placed in SPA history before enqueue. It is not an
authentication capability and grants no access. Preview digests, idempotency keys,
recipient drafts and message content remain in per-session memory only, never
localStorage/sessionStorage. Refreshing/interruption can recover by inspecting the
request UUID. Missing receipt reads do not establish rollback; uncertain requests
have no automatic retry path. Unsaved forms survive settings-tab changes in memory
and require explicit discard; full-page navigation warns while forms are dirty.

## Preview and enqueue binding

Preview performs reads only. A purpose-separated HMAC reuses the installation-local
CSV import signing seed, without reusing OIDC or email-provider credentials. It
covers trusted deployment/environment, real administrator, original exact target
set, ready/skipped classifications, resolved recipient/name and rendered content,
request UUID, type, locale/template version, current policy/revision/activation,
connector generation/sender, communication-policy digest, readiness operation and
expiry. Proofs expire after at most five minutes and never outlive readiness.

Enqueue recomputes the preview under the existing PostgreSQL advisory lock inside
the administrator transaction. Any changed target eligibility, content, policy,
binding, connector or readiness observation rejects the whole new request. No
partial jobs, audit-only commits or silently substituted recipients are permitted.
The existing request and 1–100 jobs commit with their enqueue audit.

The existing idempotency digest now incorporates the management preview binding.
An identical request returns its original receipt before rechecking preview expiry
or eligibility; it creates no new jobs. Changed payload/key reuse conflicts. Current
administrator eligibility is still checked for inspection and every mutation.
Legacy internal requests omit the new optional digest component, preserving their
previous payload hash representation.

## Protected APIs

All paths are under `/api/admin/notifications`. Every route requires verified OIDC
authentication, effective `admin.manage`, active current-issuer identity, current
domain eligibility, no revoked exact approval and a positive exact approval under
Approved Users Only. Writes reuse same-origin/JSON protection and transactional
auditing. All responses are no-store. Request JSON is capped at 16 KiB and rejects
unknown fields, duplicate keys at any nesting depth and invalid Unicode.

| Method and suffix | Purpose |
| --- | --- |
| GET `/onboarding` | Category/counts and bounded known-target pages; `category`, `search`, optional `import_id`, `offset`, `limit`. |
| POST `/preview` | Exact target references (`invitation:<UUID>` or `user:<UUID>`), request UUID, type, locale and connector UUID. No database writes. |
| POST `/enqueue` | Original preview input, authoritative expectations, selected ready targets, proof/expiry, idempotency key, audited reason and explicit confirmation. |
| GET `/requests/{id}` | Confirmed request receipt and paginated jobs, including after uncertain commits. |
| GET `/history` | Bounded recipient search, queue-status and optional request filters. |
| GET `/jobs/{id}` | Exact job, safe diagnostics and at most 10 persisted attempts. |
| GET `/jobs/{id}/attempts` | Bounded persisted attempt outcomes/provider references. |
| POST `/jobs/{id}/cancel` | Expected job generation and required reason; queued/leased only. |
| GET `/suppressions?target=…` | Exact invitation/user target suppression and generation (zero when absent). |
| POST `/suppressions` | Exact target, expected generation, active flag and audit reason. |

Pagination limits are 1–100, default 20; maximum offset 100,000. Search is bounded
and parameterized. Receipt and import filters are checked in trusted scope. Safe
errors distinguish 400/401/403/404/409/503 without database/provider response text.
Uncertain mutations require authoritative inspection and never retry automatically.

## History, suppression and onboarding

History shows the recipient snapshot, type, pinned connector/sender, real requesting
administrator, queue status, last provider-attempt outcome, creation time and safe
diagnostic codes. Drawers expose technical IDs and immutable attempt references.
No attempt means no provider execution evidence. Sent means provider acceptance;
it is not inbox-delivery confirmation. Needs Inspection is terminal and cannot be
reset, automatically retried or switched to another connector by these APIs.

Suppression targets exact invitation/user records. It does not merge mailboxes,
grant or revoke login, reactivate accounts or recall email. The existing dispatch
eligibility check prevents suppressed queued work from reaching a future provider
call. Applying suppression does not rewrite historical jobs into artificial
delivery outcomes. Administrators may separately cancel eligible queued jobs.

The onboarding overview covers current-issuer OIDC users plus scoped pending,
unexpired invitations. Categories separate active users with positive normal-login
observations or permanent claim evidence, pending invitations, active known users
without evidence, and inactive users. User categories are mutually exclusive;
invitation records are counted separately and never linked to users by mailbox.
First/last normal-login observations are displayed only when actually recorded;
claim evidence remains distinct and never fabricates timestamps. Missing history
means unknown history, not proof of never signing in. This is not an authoritative
employee directory or a measure of complete workforce onboarding.

## Validation and future delivery

Tests use fake provider readiness and private disposable PostgreSQL clusters.
Coverage includes read-only preview, bulk/CSV selection, exact target eligibility,
expiry/tampering, generations, concurrent idempotency, audit rollback, uncertain
commit inspection, history/attempts/cancellation, suppression, current authorization,
scope isolation, localization, Arabic RTL and light/dark rendering. Existing queue,
OIDC, admission and migration regressions remain part of the Go race suite.

Validation completed: full Go race suite, final focused race regressions and vet;
PostgreSQL integration/migration regressions; 416 frontend tests in 24 files;
ESLint, production build and `git diff --check`. The build retains the existing
non-fatal large-chunk warning. In the isolated PostgreSQL race test, 100-recipient
preview took approximately 171 ms and atomic confirmation 384 ms; these are local
measurements, not production throughput guarantees. The existing five-second
security transaction deadline was unchanged.

Before real delivery: complete editorial translations in a separately versioned
email contract, explicit approved worker wiring, fresh dispatch readiness and
regional quota coordination, provider credential operations, evidence-backed
uncertain-send resolution and authenticated SES delivery/bounce/complaint events.
Review and cancel/reconfirm queued requests from this queue-only phase before
activating any future worker; do not silently drain old queued work on deployment.
Automatic reminder schedules, directory synchronization and SCIM remain separate.

## Changed implementation files

- `backend/internal/authconfig/notification_management{,_http,_reads,_test}.go`:
  management service, preview proof, protected routes, observation/history DTOs and
  disposable-database regressions.
- `backend/internal/authconfig/notifications.go`: current-policy administrator
  recheck and in-transaction preview preflight with existing idempotency semantics.
- `backend/internal/authconfig/email_connectors_http.go`: shared strict bounded
  JSON decoder, including nested duplicate-key rejection.
- `backend/server.go`: management route/configuration wiring, without delivery.
- `frontend/src/api/notificationManagement.ts`: typed, validated API contracts.
- `frontend/src/settings/{NotificationSettings,NotificationSend,NotificationHistory,
  OnboardingOverview,NotificationControls}.tsx` and
  `notificationManagementState.ts`: existing-design-system workflows and helpers.
- `frontend/src/settings/notificationManagement.test.tsx`: workflow regressions.
- `frontend/src/pages/SettingsPage.tsx`: Notifications subnavigation.
- `frontend/src/locales/{en,nl,fr,es,pt-BR,zh-CN,id,ms,th,vi,hi,ar}/admin.json`:
  translated management labels, diagnostics and security explanations.
- This document and `docs/email-notifications.md`: operator and architecture guidance.
