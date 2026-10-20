-- Forward-only offline recovery attribution. No operator, revision, or activation
-- is created by this migration.
BEGIN;

CREATE TABLE framework.auth_recovery_audit (
    id UUID PRIMARY KEY,
    deployment_id TEXT NOT NULL CHECK (deployment_id ~ '^[a-z][a-z0-9_-]{0,63}$'),
    environment TEXT NOT NULL CHECK (environment IN ('development','test','production')),
    generation BIGINT NOT NULL CHECK (generation > 1),
    target_revision_id UUID NOT NULL,
    recovery_revision_id UUID NOT NULL,
    operator_id TEXT NOT NULL CHECK (operator_id ~ '^[A-Za-z0-9][A-Za-z0-9@._:-]{2,127}$'),
    authorization_key_id TEXT NOT NULL CHECK (authorization_key_id ~ '^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$'),
    authorization_format SMALLINT NOT NULL CHECK (authorization_format=1),
    authorization_key_fingerprint BYTEA NOT NULL CHECK (octet_length(authorization_key_fingerprint)=32),
    authorization_nonce BYTEA NOT NULL CHECK (octet_length(authorization_nonce)=32),
    authorization_tag BYTEA NOT NULL CHECK (octet_length(authorization_tag)=32),
    reason TEXT NOT NULL CHECK (length(btrim(reason)) BETWEEN 1 AND 512),
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    CHECK (target_revision_id IS DISTINCT FROM recovery_revision_id),
    UNIQUE (deployment_id,environment,id),
    UNIQUE (deployment_id,environment,generation,target_revision_id,id),
    FOREIGN KEY (deployment_id,environment,target_revision_id)
      REFERENCES framework.auth_config_revisions(deployment_id,environment,id),
    FOREIGN KEY (deployment_id,environment,recovery_revision_id)
      REFERENCES framework.auth_config_revisions(deployment_id,environment,id)
);

CREATE INDEX auth_recovery_audit_scope_idx
ON framework.auth_recovery_audit(deployment_id,environment,generation DESC);

CREATE TRIGGER auth_recovery_audit_immutable
BEFORE UPDATE OR DELETE ON framework.auth_recovery_audit
FOR EACH ROW EXECUTE FUNCTION framework.preserve_auth_config_revision();
CREATE TRIGGER auth_recovery_audit_no_truncate
BEFORE TRUNCATE ON framework.auth_recovery_audit
FOR EACH STATEMENT EXECUTE FUNCTION framework.preserve_auth_config_revision();

ALTER TABLE framework.auth_config_lifecycle
    ALTER COLUMN updated_by DROP NOT NULL,
    ADD COLUMN updated_by_recovery_audit UUID,
    ADD CONSTRAINT auth_config_lifecycle_actor CHECK (
      (updated_by IS NOT NULL AND updated_by_recovery_audit IS NULL)
      OR (updated_by IS NULL AND updated_by_recovery_audit IS NOT NULL)),
    ADD FOREIGN KEY (deployment_id,environment,updated_by_recovery_audit)
      REFERENCES framework.auth_recovery_audit(deployment_id,environment,id);

ALTER TABLE framework.auth_activation_history
    ALTER COLUMN actor_user_id DROP NOT NULL,
    ADD COLUMN recovery_audit_id UUID,
    ADD CONSTRAINT auth_activation_history_actor CHECK (
      (actor_user_id IS NOT NULL AND recovery_audit_id IS NULL)
      OR (actor_user_id IS NULL AND recovery_audit_id IS NOT NULL)),
    ADD FOREIGN KEY (deployment_id,environment,generation,target_revision_id,recovery_audit_id)
      REFERENCES framework.auth_recovery_audit(deployment_id,environment,generation,target_revision_id,id)
      DEFERRABLE INITIALLY DEFERRED;

GRANT SELECT,INSERT ON framework.auth_recovery_audit TO go_web_app;

COMMIT;
