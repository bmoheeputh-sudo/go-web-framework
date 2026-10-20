# Authentication activation persistence (Phase 9.2.5B)

Phase B supplied storage only. Subsequent phases add an environment-only runtime
dispatcher and [startup protection and explicit identity enrollment](auth-identity-enrollment.md).
No phase implemented so far switches providers, enrolls deployment activation
heads or creates an active revision. Environment authentication remains authoritative
only when startup policy permits it. Local DEV still uses the configured fixed
identity and does not create PostgreSQL OIDC sessions.

## Migration 000006

Existing migrations 000001–000005 are unchanged. The new migration creates:

- `framework.auth_activation_heads`: one head per deployment/environment, with
  runtime source, activation generation, revision and activation timestamp.
  Environment mode is generation zero with no revision. Database mode requires a
  positive generation and a matching history event. The table starts empty.
- `framework.auth_activation_history`: immutable generations, previous and target
  revisions, optional recovery revision, administrator, reason, timestamp and
  transition deadline. Deadlines range from zero to **30 minutes** after activation.
  A composite predecessor reference prevents generation gaps and cross-scope chains.
- `framework.auth_test_evidence`: immutable successful verification evidence,
  exact revision/generation, scope, initiating administrator, verified issuer and
  subject, purpose, completion/expiry timestamps and verification format version.
  Evidence has at most five minutes of validity. There are no tokens, codes,
  credentials, arbitrary JSON payloads or complete provider responses.

All timestamps use `TIMESTAMPTZ`. Composite foreign keys enforce same-scope
references. Deferred checks allow lifecycle, history and head updates in either
order in one transaction while requiring a consistent final state. Head generations
advance by exactly one; deletion, truncation and resetting to environment mode are
refused. History and evidence cannot be edited, deleted or truncated through normal
SQL operations. No production Go method writes activation heads/history yet.

Existing lifecycle rules still require a **new immutable recovery revision** to
restore old settings. Superseded revisions are not reactivated. Activation history
is configuration transition history; it does not replace `framework.audit_log`.
Future activation must write lifecycle/head/history/audit under `AdminTransaction`
and its advisory lock, with expected-generation comparison. This phase does not
claim an activation service exists or is safe to invoke through manual SQL.

## Internal Go interfaces

`authconfig.NewActivationReader(pool, scope)` creates a scope-bound read capability
without an administrator context. It exposes `Head`, `History`, `ValidateRevision`,
`CheckGeneration` and `Evidence`. Queries use bounded contexts, qualified table
names, parameterized values and sanitized errors. Missing heads yield a virtual
`environment`/generation-zero result **without writing a row**. History reads are
bounded and paginated. No reader decrypts secrets or writes configuration.

`Repository.recordTestEvidence` and its input `verifiedTestEvidence` are
package-private, for trusted verification code inside `authconfig` only.
The input has no exported or JSON-decodable fields and accepts no actor or scope.
The verifier must construct it only after signature, issuer, audience, expiry,
state, nonce, PKCE and browser-correlation verification. The method obtains the
actor from `AdminTransaction`, rechecks the approved revision, issuer and generation,
and inserts evidence and a fixed-schema audit event atomically. Audit failure rolls
back the evidence. Phase D wires successful isolated callbacks through the shared
transaction helper so test completion, evidence and both audit events commit
together. An explicit subsequent administrator action is required to enroll a user.

`Evidence` requires exact scope, revision, generation and purpose, and filters
expired evidence and revisions no longer at the approved generation. An isolated
connection proof cannot satisfy a normal-callback evidence lookup. This is only a
read preflight: future activation must repeat checks in its locked transaction,
verify the tested issuer/subject has current `admin.manage`, enforce actor policy,
and verify the activation generation. Test success never assigns roles or links
users by email. Evidence reads are internal, not an administrator-facing HTTP API.

## Session and flow compatibility

Both tables gain `binding_source`, deployment/environment, revision, activation
generation, client ID and flow purpose; flows additionally gain issuer. Existing
rows and unchanged environment-mode inserts default to `legacy`. No row is
backfilled with guessed deployment, client or database revision information.

- `legacy`: retains existing environment-authentication behavior; no activation
  binding. It can never satisfy `Binding.MatchesDatabase`.
- `environment`: explicit deployment/issuer/client binding, with no revision or
  activation generation. Available to future writers; not used automatically.
- `database`: revision/issuer/client must match immutable configuration. Normal
  sessions and login flows additionally reference the exact activation-history
  generation. A test flow has an explicit `isolated_connection` or `normal_callback`
  purpose and no activation generation, because its target is not active yet.

Bindings cannot be updated, including legacy-to-database reclassification. Sessions
remain normal-login-only; isolated tests cannot be stored as application sessions.
`PostgresStore.SessionBinding` and `FlowBinding` return metadata without touching
activity or consuming a flow. They do not expose cookie hashes or PKCE material.
`Binding.MatchesDatabase` compares an exact nonempty normal-login binding; it does
not grant access or check expiry. Existing session expiry/idle checks are unchanged.

Future dispatch must select one binding and enforce the authoritative active/draining
policy. The 30-minute history deadline does **not** extend any session expiry and
is not yet a runtime grace-period implementation. Future admission must cap trust
at the earliest of the transition deadline, stored expiry and idle expiration.
Unproven legacy provenance requires reauthentication at database enrollment.

## Encryption keyring

The format-v1 AES-256-GCM envelope and authenticated metadata are unchanged.
`CipherFromEnv` still reads only `AUTH_ENCRYPTION_KEY_ID` and
`AUTH_ENCRYPTION_KEY` (canonical padded standard Base64 of 32 random bytes).
Existing environment configuration and ciphertext remain compatible.

The internal `NewKeyring(activeID, encodedKeys)` constructor supports up to 32
explicitly identified keys. It copies them into immutable cipher instances. Only
`activeID` encrypts new records. Historical ciphertext selects a key by envelope
identifier, which is then authenticated along with the immutable revision metadata.
Unknown IDs, incorrect keys, malformed encodings and tampering fail safely. There
is no automatic key creation, key replacement/deletion or re-encryption. Both pointer
and value formatting are redacted; API metadata contains no key material.

A **future, not currently parsed** multi-key environment contract can use:

- `AUTH_ENCRYPTION_KEY_ID`: explicit active key identifier.
- `AUTH_ENCRYPTION_KEYS_JSON`: a bounded JSON object mapping identifiers to canonical
  Base64 keys, supplied through a protected deployment secret mechanism.
- Existing `AUTH_ENCRYPTION_KEY` remains the single-key compatibility mode. Reject
  simultaneous single-key and multi-key configuration, duplicate JSON IDs, unknown
  fields, malformed keys and an active ID absent from the keyring.

Do not set that future variable expecting it to work now. No real keys were rotated.
Before future rotation, provision all required historical keys to every instance,
verify decryption and backups, then select a new active key. Preserve keys while
any active/draining/recovery revision needs them. Losing a key cannot be repaired
by generating a new one. Restoring settings into a new revision requires fresh
AEAD encryption because revision identity is authenticated.

## Manual deployment

Obtain approval before applying this migration to the actual database. Back up the
database and protected encryption keys. Use the existing README's protected `PG*`
environment setup, the intended database, `go_web_app`, and production-safe TLS.
Do not place passwords in command arguments or enable shell tracing.

For a confirmed clean version-5 database, from the repository root:

```bash
./scripts/migrate-framework.sh version
# Only after approval and confirming clean version 5:
./scripts/migrate-framework.sh up 1
./scripts/migrate-framework.sh version
# Expect clean version 6. No provider has been activated.
```

The wrapper rejects rollback before invoking the migration driver, preserving the
clean journal. Migration 000006 also has a refusal `.down.sql`: bypassing the wrapper
with raw golang-migrate fails visibly and preserves data, but can leave **dirty
version 5** because the tool changes the journal before executing SQL. A missing
or no-op down file would incorrectly permit clean schema/version divergence.
Never blindly force, replay migrations or delete history. Inspect and approve any
journal recovery separately. Roll back application code only to a schema-compatible
version, or use a reviewed forward corrective migration. Use `vi` for manual edits.

## Boundaries and validation

`go_web_app` remains the single application/migration owner. Explicit grants give
non-owner fixtures read access to heads/history and insert/read access to evidence;
these do not constrain the real schema owner. Trusted Go code and database-owner
access can fabricate database contents or disable triggers. A private evidence type
prevents ordinary package/HTTP callers from submitting success, not a malicious
server or database owner. Secure evidence is a verifier trust boundary, not database
cryptographic attestation.

The dispatcher and explicit identity enrollment were added after Phase B, but no
activation API, listener, provider switching, retention worker or operator recovery
tool exists. No API can activate a provider. Evidence/history retention is immutable;
a future reviewed retention policy must preserve required recovery/audit records.

Tests use `internal/testdb` disposable PostgreSQL clusters with private Unix sockets,
never application `DB_*` values. CLI migration tests require `migrate` with PostgreSQL
support; database tests require PostgreSQL binaries (default PostgreSQL 14, or
`PG_TEST_BIN`). Missing prerequisites are reported as skipped tests.

```bash
cd backend
go test -race -count=1 ./...
go vet ./...
cd ..
bash -n scripts/migrate-framework.sh
git diff --check
```
