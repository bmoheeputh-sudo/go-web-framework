-- Forward only: history must be retained. No active revision or secret is seeded.
BEGIN;
CREATE TABLE framework.auth_config_revisions (
    id UUID PRIMARY KEY,
    deployment_id TEXT NOT NULL CHECK (deployment_id ~ '^[a-z][a-z0-9_-]{0,63}$'),
    environment TEXT NOT NULL CHECK (environment IN ('development','test','production')),
    configuration_version BIGINT NOT NULL CHECK (configuration_version > 0),
    provider TEXT NOT NULL CHECK (provider IN ('oidc','google_iap','local_dev')),
    issuer_url TEXT NOT NULL DEFAULT '',
    client_id TEXT NOT NULL DEFAULT '',
    redirect_uri TEXT NOT NULL DEFAULT '',
    iap_audience TEXT NOT NULL DEFAULT '',
    allow_http_development BOOLEAN NOT NULL DEFAULT FALSE,
    secret_ciphertext BYTEA,
    secret_nonce BYTEA,
    encryption_format SMALLINT,
    encryption_key_id TEXT,
    created_by UUID NOT NULL REFERENCES framework.users(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (deployment_id, environment, configuration_version),
    UNIQUE (deployment_id, environment, id),
    CHECK (length(issuer_url) <= 2048 AND length(client_id) <= 512 AND length(redirect_uri) <= 2048 AND length(iap_audience) <= 512),
    CHECK (NOT allow_http_development OR (environment='development' AND provider='oidc')),
    CHECK (
      (provider='oidc' AND issuer_url ~ '^https://[^/?#@[:space:]]+[^?#[:space:]]*$'
       AND length(btrim(client_id)) > 0 AND redirect_uri ~ '^https?://[^/?#@[:space:]]+/api/auth/callback$'
       AND (redirect_uri LIKE 'https://%' OR (allow_http_development AND redirect_uri ~ '^http://(localhost|127([.][0-9]{1,3}){3}|\[::1\])(:[0-9]{1,5})?/api/auth/callback$'))
       AND iap_audience='' AND secret_ciphertext IS NOT NULL AND octet_length(secret_ciphertext) BETWEEN 17 AND 4112
       AND secret_nonce IS NOT NULL AND octet_length(secret_nonce)=12
       AND encryption_format IS NOT NULL AND encryption_format=1
       AND encryption_key_id IS NOT NULL AND encryption_key_id ~ '^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$')
      OR
      (provider IN ('google_iap','local_dev') AND issuer_url='' AND client_id='' AND redirect_uri=''
       AND secret_ciphertext IS NULL AND secret_nonce IS NULL AND encryption_format IS NULL AND encryption_key_id IS NULL
       AND NOT allow_http_development
       AND ((provider='local_dev' AND environment='development' AND iap_audience='')
        OR (provider='google_iap' AND iap_audience ~ '^/projects/[0-9]+/(apps/[a-z][a-z0-9-]*|global/backendServices/[0-9]+|locations/[a-z][a-z0-9-]*/services/[a-z][a-z0-9-]*)$')))
    )
);
CREATE TABLE framework.auth_config_lifecycle (
    revision_id UUID PRIMARY KEY,
    deployment_id TEXT NOT NULL,
    environment TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'draft' CHECK (status IN ('draft','validated','approved','active','superseded')),
    generation BIGINT NOT NULL DEFAULT 1 CHECK (generation > 0),
    updated_by UUID NOT NULL REFERENCES framework.users(id),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    validation JSONB NOT NULL DEFAULT '{}'::jsonb,
    validated_at TIMESTAMPTZ,
    approved_at TIMESTAMPTZ,
    activated_at TIMESTAMPTZ,
    superseded_at TIMESTAMPTZ,
    FOREIGN KEY (deployment_id,environment,revision_id) REFERENCES framework.auth_config_revisions(deployment_id,environment,id),
    CHECK ((status='draft' AND validation='{}'::jsonb AND validated_at IS NULL)
        OR (status<>'draft' AND validation='{"check":"static","version":1}'::jsonb AND validated_at IS NOT NULL))
);
-- Require a complete revision/lifecycle pair at commit, allowing the repository
-- to insert both rows in one transaction without leaving invisible orphan history.
ALTER TABLE framework.auth_config_revisions ADD CONSTRAINT auth_config_lifecycle_required
FOREIGN KEY (id) REFERENCES framework.auth_config_lifecycle(revision_id) DEFERRABLE INITIALLY DEFERRED;
CREATE UNIQUE INDEX auth_config_one_active_idx ON framework.auth_config_lifecycle(deployment_id,environment) WHERE status='active';

CREATE FUNCTION framework.preserve_auth_config_revision() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
    RAISE EXCEPTION 'authentication configuration history is immutable' USING ERRCODE='23514';
END;
$$;
CREATE TRIGGER auth_config_revision_immutable BEFORE UPDATE OR DELETE ON framework.auth_config_revisions
FOR EACH ROW EXECUTE FUNCTION framework.preserve_auth_config_revision();

CREATE TRIGGER auth_config_revision_no_truncate BEFORE TRUNCATE ON framework.auth_config_revisions
FOR EACH STATEMENT EXECUTE FUNCTION framework.preserve_auth_config_revision();
CREATE TRIGGER auth_config_lifecycle_no_truncate BEFORE TRUNCATE ON framework.auth_config_lifecycle
FOR EACH STATEMENT EXECUTE FUNCTION framework.preserve_auth_config_revision();

CREATE FUNCTION framework.guard_auth_config_lifecycle() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
    IF TG_OP='DELETE' THEN
        RAISE EXCEPTION 'authentication configuration history is immutable' USING ERRCODE='23514';
    ELSIF TG_OP='INSERT' THEN
        IF NEW.status<>'draft' OR NEW.generation<>1 OR NEW.validation<>'{}'::jsonb
           OR NEW.validated_at IS NOT NULL OR NEW.approved_at IS NOT NULL OR NEW.activated_at IS NOT NULL OR NEW.superseded_at IS NOT NULL
           OR NEW.updated_by IS DISTINCT FROM (SELECT created_by FROM framework.auth_config_revisions WHERE id=NEW.revision_id) THEN
            RAISE EXCEPTION 'invalid initial authentication configuration state' USING ERRCODE='23514';
        END IF;
    ELSE
        IF ROW(NEW.revision_id,NEW.deployment_id,NEW.environment) IS DISTINCT FROM ROW(OLD.revision_id,OLD.deployment_id,OLD.environment)
           OR NEW.generation<>OLD.generation+1
           OR ROW(NEW.validated_at,NEW.approved_at,NEW.activated_at,NEW.superseded_at) IS DISTINCT FROM ROW(OLD.validated_at,OLD.approved_at,OLD.activated_at,OLD.superseded_at)
           OR NOT ((OLD.status='draft' AND NEW.status='validated') OR (OLD.status='validated' AND NEW.status='approved')
                OR (OLD.status='approved' AND NEW.status='active') OR (OLD.status='active' AND NEW.status='superseded'))
           OR (OLD.status<>'draft' AND NEW.validation IS DISTINCT FROM OLD.validation) THEN
            RAISE EXCEPTION 'invalid authentication configuration transition' USING ERRCODE='23514';
        END IF;
        CASE NEW.status
            WHEN 'validated' THEN NEW.validated_at:=clock_timestamp();
            WHEN 'approved' THEN NEW.approved_at:=clock_timestamp();
            WHEN 'active' THEN NEW.activated_at:=clock_timestamp();
            WHEN 'superseded' THEN NEW.superseded_at:=clock_timestamp();
        END CASE;
    END IF;
    NEW.updated_at:=clock_timestamp();
    RETURN NEW;
END;
$$;
CREATE TRIGGER auth_config_lifecycle_guard BEFORE INSERT OR UPDATE OR DELETE ON framework.auth_config_lifecycle
FOR EACH ROW EXECUTE FUNCTION framework.guard_auth_config_lifecycle();
GRANT SELECT,INSERT ON framework.auth_config_revisions TO go_web_app;
GRANT SELECT,INSERT,UPDATE ON framework.auth_config_lifecycle TO go_web_app;
COMMIT;
