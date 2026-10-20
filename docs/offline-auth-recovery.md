# Offline emergency OIDC recovery

`backend/cmd/auth-recovery` is a break-glass command for a deployment whose
database-managed OIDC provider cannot be restored through the normal administrator
path. It is not an HTTP endpoint and does not enable Local DEV, change roles, link
identities or bypass OIDC verification.

## Authorization and attribution

The command requires all of the following from protected process environment:

- `AUTH_RECOVERY_ENABLED=true`, set only for the recovery operation;
- `AUTH_RECOVERY_OPERATOR_ID`, a stable incident-response operator identifier;
- `AUTH_RECOVERY_AUTHORIZATION_KEY_ID`, identifying the controlled break-glass key;
- `AUTH_RECOVERY_AUTHORIZATION_KEY`, a distinct random 32-byte key encoded as
  canonical padded standard Base64.

The authorization key must not be the authentication-configuration encryption key.
Do not store it in the repository or ordinary application `.env`. Restrict command,
database and secret access through the server's operating-system and privileged
access controls. Remove the recovery variables after the operation.

The CLI does not accept a framework-user UUID or operator identity flag. It obtains
operator attribution from the protected environment capability. Each transaction
stores a random event ID and nonce, operator/key IDs, explicit format version 1,
SHA-256 key fingerprint and an HMAC-SHA-256 authorization tag bound to the exact scope, expected generation,
target/source revisions and reason. It never stores or prints the key.

Migration 000007 adds immutable `framework.auth_recovery_audit` records. Activation
history and lifecycle rows reference the same recovery record instead of fabricating
a framework user. Database constraints require exactly one attribution mode: normal
authenticated administrator or offline operator. Audit, lifecycle changes, history,
head update and NOTIFY commit in one advisory-locked transaction.

## Eligible recovery revision

Recovery accepts only a new immutable OIDC revision created through the existing
recovery-draft process. The draft must retain audited provenance to a superseded
historical revision, have identical non-secret settings, use a freshly encrypted
secret envelope, and have reached `validated` then `approved`. A superseded revision
cannot be reactivated directly.

Before showing a preview, the command decrypts the target with the configured
keyring and performs the same hardened discovery, endpoint, algorithm and JWKS
preparation used by controlled activation. Missing keys, invalid metadata, unsafe
network destinations, provider failure or callback mismatch refuses recovery.

Recovery always records a zero-length transition deadline. Existing sessions and
callbacks from the failed provider receive no new grace period; expired/deleted
sessions are never restored. Connected instances receive the transaction-scoped
notification and reconcile through their existing synchronizers. Google IAP-pinned
deployments are rejected.

## Migration

Do not apply migration 000007 without the normal backup, review and approval. From
a confirmed clean version-6 database:

```bash
./scripts/migrate-framework.sh version
./scripts/migrate-framework.sh up 1
./scripts/migrate-framework.sh version
# Expect clean version 7. No operator or activation is created.
```

The down migration deliberately refuses destructive rollback. Use an application
version compatible with schema 7 or a reviewed forward corrective migration.

## Command

Load the ordinary trusted deployment, database, callback, session and encryption
keyring settings without printing them. Load the separate recovery capability from
protected operator secret storage. Then run from `backend`:

```bash
go run ./cmd/auth-recovery \
  --deployment framework-production \
  --environment production \
  --expected-generation 12 \
  --revision 11111111-1111-4111-8111-111111111111 \
  --reason "INC-12345 approved emergency OIDC recovery"
```

The deployment and environment flags must exactly match trusted server configuration.
The command shows only safe metadata and the immediate reauthentication impact. It
then requires typing the displayed deployment, target generation and revision phrase
exactly. There is no noninteractive confirmation flag.

Do not retry an `outcome is uncertain` result. Inspect the scoped activation head,
history and `auth_recovery_audit` record first; the commit may have succeeded even
if the client lost its response. Database, audit, encryption or provider failures
never select an alternate authenticator.

## Operational limits

- Multi-instance reconciliation converges; it is not a simultaneous cluster switch.
- One session-affine LISTEN connection per instance is required. Transaction-pooling
  endpoints are unsupported; startup detects obvious PID/channel loss but cannot
  prove future proxy behavior.
- Discovery/JWKS retries are limited to three total idempotent GET attempts for HTTP
  429/503. Token exchange is not part of offline preparation and is never retried.
- `go_web_app` remains the single application/migration owner and therefore a broad
  trust boundary. Database-owner compromise can bypass application controls.
- The operator key is an externally governed break-glass secret. Rotation and
  revocation remain deployment-secret-management responsibilities.
