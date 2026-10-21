# Email connectors (Phase 10.4C)

Settings → Notifications → Email Connectors manages Gmail and Amazon SES independently.
Both can coexist, with at most one enabled default. Connector UUID, provider, sender
and SES region are immutable: create another connector to change them. Limits,
enabled/default flags and audit reasons use optimistic generation checks. Changing
the default never changes a queued job's connector or sender.

This release registers configuration and readiness endpoints only. It starts no
delivery worker and exposes no send endpoint or reminder scheduler. Manual and CSV
invitations still send no email. The transport adapters implement the existing
provider-neutral delivery interface but are not registered for production dispatch.

## Migration and deployment

Apply forward migration `000013_email_connector_readiness.up.sql` through the
operator migration process before deploying this server. Migrations 000001–000012
are unchanged. No migration runs on server startup. Validation uses disposable
PostgreSQL databases; this change has not been applied to the live database.

The migration adds two scoped tables:

- `notification_connector_readiness`: short-lived status, allowlisted error code,
  tested connector generation, operation UUID, administrator, quota observations,
  optional opaque credential version and sender-mailbox reference. Observations
  last five minutes. A new result replaces the current observation; immutable audit
  events preserve configuration and test history.
- `notification_connector_oauth_flows`: five-minute, single-use authorization flows
  bound to initiating administrator, browser, connector generation, current OIDC
  policy/revision/client activation and notification OAuth client digest. Only
  SHA-256 state/browser hashes are stored; no code, token, client secret or PKCE
  verifier is stored in PostgreSQL.

Scope foreign keys, state/generation guards and retention triggers reject rebinding,
replay and deletion/truncation. The optional production-role proposal grants runtime
access and worker read-only readiness access, without OAuth-flow access. The worker
still has no account, role, approval, invitation or connector-configuration mutation
authority. The supported topology remains one security deployment per database.

## Google Workspace configuration

Use a separate Google Cloud OAuth web client and dedicated Workspace mailbox. Enable
the Gmail API; configure an internal Workspace consent audience and API access policy with
the responsible organization administrator. Domain-wide delegation and service-account
impersonation are not required. Register exactly:

`<approved application origin>/api/admin/notifications/email-connectors/gmail/callback`

The flow requests offline authorization, consent and PKCE S256. It requests
`https://www.googleapis.com/auth/gmail.send` and
`https://www.googleapis.com/auth/gmail.settings.basic`. The second scope is necessary
for authoritative primary-mailbox and send-as verification: Google's
[sendAs.list API](https://developers.google.com/workspace/gmail/api/reference/rest/v1/users.settings.sendAs/list)
does not accept `gmail.send`. It also permits basic-settings writes, although VGCA
only reads settings. The UI discloses this and requires explicit acknowledgement.
Approve these scopes under organizational policy before authorizing. Google's
[scope classifications and verification requirements](https://developers.google.com/workspace/gmail/api/auth/scopes)
apply; do not assume approval or external-app verification is already in place.

Deployment settings, supplied by an operator independently of OIDC configuration:

| Setting | Value |
| --- | --- |
| `NOTIFICATION_GMAIL_CLIENT_ID` | Notification OAuth web-client identifier |
| `NOTIFICATION_GMAIL_CLIENT_SECRET_FILE` | Absolute path to private raw client-secret file, owner-only permissions, at most 4096 bytes |
| `NOTIFICATION_SECRET_DIRECTORY` | Pre-provisioned absolute private directory, mode 0700, writable by the application |
| `NOTIFICATION_SECRET_KEY_FILE` | Absolute private file, mode 0600, containing canonical base64 of an independently generated, nonzero 32-byte key |

These are new deployment contracts; existing credentials and `.env` were not changed.
The server reads no secret or AWS credentials at startup. Missing setup leaves Gmail
unavailable for authorization while the rest of the application continues to work.

The replaceable credential-store interface currently uses AES-256-GCM encrypted
files outside PostgreSQL, scoped to deployment/environment/connector/authorization
version/fixed sender. Refresh rotation uses a process-shared file lock and atomic
fsync/rename. Every application instance must use the same private POSIX storage,
key and OAuth client. Storage must support reliable flock and atomic rename; do not
use independent per-instance volumes. A managed secret-store adapter can replace
this implementation. Protect and back up tokens and encryption keys separately.
Key rotation requires an operator-controlled migration or mailbox reauthorization;
there is no automatic key-rotation job.

Authorization requires the chosen mailbox to be Google's primary identity and the
fixed sender to be an accepted send-as identity. Test Connection performs refresh
and sender checks, detects revoked/expired tokens or missing scopes and saves rotated
refresh tokens only in the secret store. Access/refresh tokens and client secrets
never enter frontend responses, browser storage, audit details or notification tables.
Refresh tokens from a flow whose final database commit fails remain unreferenced;
do not automatically activate them. Reviewed orphan cleanup remains operational work.

The reverse proxy must exclude callback query strings and request bodies from access
logs and tracing. Callback cookies are HttpOnly, SameSite=Lax and Secure on HTTPS;
only loopback development can use HTTP. The callback consumes the flow before token
exchange and redirects to a fixed settings route without forwarding codes or state.

## Amazon SES configuration and permissions

The AWS SDK for Go v2 resolves the default credential chain lazily during an explicit
test or future dispatch. Prefer a workload IAM role and remove competing static
credential sources. No access-key fields exist in the UI or PostgreSQL. SES regions
are explicit and fixed per connector; custom service endpoints and SDK request retries
are disabled. See the [AWS credential-chain documentation](https://docs.aws.amazon.com/sdk-for-go/v2/developer-guide/configure-gosdk.html).

Test Connection needs `ses:GetAccount` on `*` and `ses:GetEmailIdentity` on the exact
sender identity and its domain identity in the chosen account/region. Bound both
statements with `aws:RequestedRegion`. No `ses:SendEmail` permission is needed for
configuration or tests. These action/resource boundaries follow the
[SES v2 IAM reference](https://docs.aws.amazon.com/service-authorization/latest/reference/list_sesv2.html).
For example, adapt these placeholders to the approved deployment:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    { "Effect": "Allow", "Action": "ses:GetAccount", "Resource": "*",
      "Condition": { "StringEquals": { "aws:RequestedRegion": "eu-west-1" } } },
    { "Effect": "Allow", "Action": "ses:GetEmailIdentity",
      "Resource": ["arn:aws:ses:eu-west-1:123456789012:identity/onboarding@example.com", "arn:aws:ses:eu-west-1:123456789012:identity/example.com"],
      "Condition": { "StringEquals": { "aws:RequestedRegion": "eu-west-1" } } }
  ]
}
```

The test reads account sending status, production access, exact email identity
(falling back to its exact domain on NotFound), verification and regional quota.
Sandbox accounts remain unready for this onboarding workflow. Requested limits
must fit observed remaining daily quota and send rate. Test Connection does not
prove future `SendEmail` authorization, inbox delivery or recipient onboarding.

## APIs, readiness and audit

All routes are under `/api/admin/notifications/email-connectors`:

| Method and suffix | Purpose |
| --- | --- |
| GET `/` | Bounded list, setup availability and public callback/scopes |
| POST `/` | Create disabled connector with client-chosen UUID and audit reason |
| GET `/{id}` | Authoritative inspection after conflicts or uncertain writes |
| POST `/{id}/configure` | Enabled/default/limits update with expected generation |
| POST `/{id}/test` | Authorization and fixed-sender readiness, no recipient parameter |
| POST `/{id}/gmail/authorize` | Begin browser-bound mailbox authorization |
| GET `/gmail/callback` | Authenticated, one-use OAuth completion |

Administrator mutations use the existing shared advisory-lock transaction and atomic
audits. Provider calls occur between transactions, with bounded deadlines. Completion
rechecks current administrator eligibility, OIDC bindings, connector generation and
operation ownership. Losing a race cannot publish a stale Ready result. All routes
require OIDC authentication and `admin.manage`; current account activity, policy,
exact approval and allowed-domain eligibility are rechecked in the transaction.
The same current-policy check now runs for the initiating administrator at dispatch.

JSON writes are limited to 16 KiB, reject unknown/duplicate keys and use existing
same-origin protection. Responses are no-store; provider bodies/errors are reduced
to fixed safe codes. Test starts have a five-second connector cooldown. The seven
statuses are Configured, Ready, Authentication failed, Sender not verified,
Permission denied, Quota unavailable and Provider unavailable. Ready expires after
five minutes; enabling requires fresh Ready and appropriate observed quota. Raising
limits beyond the observation invalidates readiness. Gmail has no remaining-mailbox
quota endpoint under these scopes: its quota is explicitly unknown, with local
limits retained and provider throttling mapped safely.

The UI supports all 12 locales, RTL, keyboard navigation and dark/light themes.
Unsaved drafts stay in memory across settings tabs; leaving a form requires explicit
discard and full-page navigation warns. Conflicts and uncertain/malformed mutation
responses preserve input and require explicit inspection, never automatic retries.
Browser reload clears in-memory drafts; inspect the connector list after interruption.
No credentials or OAuth state are persisted in browser storage.

## Delivery boundaries and next work

The existing Queued → Leased → Dispatching → terminal state machine remains intact.
Gmail and SES adapters make a single sending request when explicitly invoked by
future orchestration. Explicit rejection, provider acceptance and uncertainty stay
distinct. Transport loss, ambiguous provider replies and uncertain result persistence
require inspection, never automatic resend or cross-provider failover. Accepted means
provider acceptance, not confirmed delivery or successful onboarding.

Before actual delivery: approve provider setup and sender identities; complete the
administrator preview/send/history and uncertainty-inspection workflow; wire a
separately privileged worker explicitly with bounded provider timeouts and current
credential versions; require current readiness at dispatch; review regional/account
quota coordination; finish localized email copy and operational token/key rotation
and cleanup. Grant sender-scoped `ses:SendEmail` with a fixed FromAddress only when
delivery is separately approved. Authenticate and deduplicate SES bounce/complaint
events before enabling event ingestion. Schedules and automatic reminders remain
outside this phase.

Automated tests use synthetic OAuth/SES services and private disposable PostgreSQL
clusters. They do not authorize a live mailbox, use live AWS credentials or send email.

## Implementation file map

- `backend/internal/notifications/{connectors,credentials,gmail,ses}.go`: readiness,
  external token storage and provider adapters; `delivery.go` package documentation
  reflects the isolated transports; `providers_test.go` covers synthetic providers.
- `backend/internal/authconfig/email_connectors.go`, `email_connector_oauth.go`,
  `email_connector_readiness.go`, `email_connectors_http.go`: protected service,
  one-use authorization, two-transaction tests and APIs; `email_connectors_test.go`
  covers PostgreSQL, authorization, races, HTTP and audit rollback.
- `backend/internal/authconfig/notification_eligibility.go` and
  `notification_worker.go`: initiating administrator's current-policy recheck.
- `backend/server.go`, `backend/go.mod`, `backend/go.sum`: protected route wiring
  and AWS SDK dependencies. No delivery startup wiring is added.
- `database/migrations/000013_email_connector_readiness.{up,down}.sql`,
  `database/scripts/production-roles.sql`,
  `backend/internal/authconfig/migrations_test.go` and
  `backend/internal/database/production_roles_test.go`: forward schema, proposed
  role grants, migration compatibility and privilege regression tests.
- `frontend/src/api/emailConnectors.ts`,
  `frontend/src/settings/EmailConnectors.tsx`,
  `frontend/src/settings/emailConnectors.test.tsx`,
  `frontend/src/pages/SettingsPage.tsx`: typed API, settings workflow and tests.
- `frontend/src/locales/{en,nl,fr,es,pt-BR,zh-CN,id,ms,th,vi,hi,ar}/admin.json`:
  all 12 connector UI translations.
- `docs/email-notifications.md` and this document: architecture and rollout guidance.
