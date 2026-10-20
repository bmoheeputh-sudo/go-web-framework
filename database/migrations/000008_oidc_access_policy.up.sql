-- Storage only: deliberately no policy, approval, user or role backfill.
BEGIN;

CREATE FUNCTION framework.valid_access_domains(domains TEXT[]) RETURNS BOOLEAN
LANGUAGE sql IMMUTABLE STRICT SET search_path = pg_catalog AS $$
    SELECT cardinality(domains) <= 20
      AND (cardinality(domains) = 0 OR (array_ndims(domains) = 1 AND array_lower(domains,1) = 1))
      AND NOT EXISTS (
        SELECT 1 FROM unnest(domains) d WHERE d IS NULL OR length(d) > 253
          OR d COLLATE "C" !~ '^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]([a-z0-9-]{0,61}[a-z0-9])?$')
      AND cardinality(domains) = (SELECT count(DISTINCT d COLLATE "C") FROM unnest(domains) d)
$$;

CREATE TABLE framework.oidc_access_policies (
    deployment_id TEXT NOT NULL CHECK (deployment_id ~ '^[a-z][a-z0-9_-]{0,63}$'),
    environment TEXT NOT NULL CHECK (environment IN ('development','test','production')),
    mode TEXT NOT NULL CHECK (mode IN ('allow_all','approved_users_only')),
    allowed_email_domains TEXT[] NOT NULL DEFAULT '{}' CHECK (framework.valid_access_domains(allowed_email_domains)),
    default_role TEXT NOT NULL REFERENCES framework.roles(name) CHECK (default_role IN ('Viewer','User')),
    generation BIGINT NOT NULL DEFAULT 1 CHECK (generation > 0),
    created_by UUID NOT NULL REFERENCES framework.users(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    updated_by UUID NOT NULL REFERENCES framework.users(id),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    reason TEXT NOT NULL CHECK (length(btrim(reason)) BETWEEN 8 AND 512 AND reason !~ '[[:cntrl:]]'),
    PRIMARY KEY (deployment_id,environment)
);

CREATE TABLE framework.oidc_identity_approvals (
    deployment_id TEXT NOT NULL,
    environment TEXT NOT NULL,
    issuer TEXT COLLATE "C" NOT NULL CHECK (length(issuer) BETWEEN 1 AND 2048 AND issuer = btrim(issuer) AND issuer !~ '[[:cntrl:]]'),
    subject TEXT COLLATE "C" NOT NULL CHECK (length(subject) BETWEEN 1 AND 1024 AND subject = btrim(subject) AND subject !~ '[[:cntrl:]]'),
    status TEXT NOT NULL CHECK (status IN ('approved','revoked')),
    generation BIGINT NOT NULL DEFAULT 1 CHECK (generation > 0),
    source TEXT NOT NULL CHECK (source IN ('bootstrap','administrator')),
    created_by UUID NOT NULL REFERENCES framework.users(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    updated_by UUID NOT NULL REFERENCES framework.users(id),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    reason TEXT NOT NULL CHECK (length(btrim(reason)) BETWEEN 8 AND 512 AND reason !~ '[[:cntrl:]]'),
    PRIMARY KEY (deployment_id,environment,issuer,subject),
    FOREIGN KEY (deployment_id,environment) REFERENCES framework.oidc_access_policies(deployment_id,environment)
);

-- Retain revocations; audit events preserve each change. Identity keys and
-- creation provenance cannot be rewritten. Writers must advance generations.
CREATE FUNCTION framework.guard_access_policy_record() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog AS $$
BEGIN
    IF TG_OP IN ('DELETE','TRUNCATE') THEN
        RAISE EXCEPTION 'access policy records must be retained';
    ELSIF TG_OP = 'INSERT' THEN
        IF NEW.generation <> 1 OR NEW.created_by <> NEW.updated_by THEN
            RAISE EXCEPTION 'invalid initial access policy generation or attribution';
        END IF;
    ELSE
        IF NEW.generation <> OLD.generation + 1
          OR NEW.deployment_id <> OLD.deployment_id OR NEW.environment <> OLD.environment
          OR NEW.created_by <> OLD.created_by OR NEW.created_at <> OLD.created_at THEN
            RAISE EXCEPTION 'invalid access policy update';
        END IF;
        IF TG_TABLE_NAME = 'oidc_identity_approvals' THEN
            IF NEW.issuer <> OLD.issuer OR NEW.subject <> OLD.subject OR NEW.source <> OLD.source THEN
                RAISE EXCEPTION 'approval identity and provenance are immutable';
            END IF;
        END IF;
    END IF;
    NEW.updated_at := clock_timestamp();
    RETURN NEW;
END $$;

CREATE TRIGGER access_policy_record BEFORE INSERT OR UPDATE OR DELETE ON framework.oidc_access_policies
FOR EACH ROW EXECUTE FUNCTION framework.guard_access_policy_record();
CREATE TRIGGER access_policy_retain BEFORE TRUNCATE ON framework.oidc_access_policies
FOR EACH STATEMENT EXECUTE FUNCTION framework.guard_access_policy_record();
CREATE TRIGGER identity_approval_record BEFORE INSERT OR UPDATE OR DELETE ON framework.oidc_identity_approvals
FOR EACH ROW EXECUTE FUNCTION framework.guard_access_policy_record();
CREATE TRIGGER identity_approval_retain BEFORE TRUNCATE ON framework.oidc_identity_approvals
FOR EACH STATEMENT EXECUTE FUNCTION framework.guard_access_policy_record();

GRANT SELECT,INSERT,UPDATE ON framework.oidc_access_policies,framework.oidc_identity_approvals TO go_web_app;
REVOKE ALL ON FUNCTION framework.valid_access_domains(TEXT[]) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION framework.valid_access_domains(TEXT[]) TO go_web_app;
REVOKE ALL ON FUNCTION framework.guard_access_policy_record() FROM PUBLIC;
COMMIT;
