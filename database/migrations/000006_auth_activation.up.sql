-- Persistence only. No deployment enrollment, provider activation or session backfill.
BEGIN;
CREATE TABLE framework.auth_activation_history (
    deployment_id TEXT NOT NULL CHECK (deployment_id ~ '^[a-z][a-z0-9_-]{0,63}$'),
    environment TEXT NOT NULL CHECK (environment IN ('development','test','production')),
    generation BIGINT NOT NULL CHECK (generation > 0),
    previous_generation BIGINT GENERATED ALWAYS AS (CASE WHEN generation > 1 THEN generation-1 END) STORED,
    previous_revision_id UUID,
    target_revision_id UUID NOT NULL,
    recovery_revision_id UUID,
    activated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    transition_deadline TIMESTAMPTZ NOT NULL,
    actor_user_id UUID NOT NULL REFERENCES framework.users(id),
    reason TEXT NOT NULL CHECK (length(btrim(reason)) BETWEEN 1 AND 512),
    PRIMARY KEY (deployment_id,environment,generation),
    UNIQUE (deployment_id,environment,generation,target_revision_id),
    CHECK ((generation=1 AND previous_revision_id IS NULL) OR (generation>1 AND previous_revision_id IS NOT NULL)),
    CHECK (isfinite(activated_at) AND isfinite(transition_deadline) AND transition_deadline >= activated_at AND transition_deadline <= activated_at + interval '30 minutes'),
    CHECK (previous_revision_id IS DISTINCT FROM target_revision_id),
    FOREIGN KEY (deployment_id,environment,target_revision_id) REFERENCES framework.auth_config_revisions(deployment_id,environment,id),
    FOREIGN KEY (deployment_id,environment,recovery_revision_id) REFERENCES framework.auth_config_revisions(deployment_id,environment,id),
    FOREIGN KEY (deployment_id,environment,previous_generation,previous_revision_id)
      REFERENCES framework.auth_activation_history(deployment_id,environment,generation,target_revision_id)
);
CREATE FUNCTION framework.guard_auth_activation_target() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM framework.auth_config_revisions r JOIN framework.auth_config_lifecycle l ON l.revision_id=r.id
       WHERE r.id=NEW.target_revision_id AND r.deployment_id=NEW.deployment_id AND r.environment=NEW.environment
       AND r.provider='oidc' AND l.status IN ('approved','active')) THEN
        RAISE EXCEPTION 'activation requires an approved OIDC revision' USING ERRCODE='23514';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER auth_activation_target_guard BEFORE INSERT ON framework.auth_activation_history
FOR EACH ROW EXECUTE FUNCTION framework.guard_auth_activation_target();
CREATE INDEX auth_activation_history_revision_idx ON framework.auth_activation_history(target_revision_id,generation);
CREATE TABLE framework.auth_activation_heads (
    deployment_id TEXT NOT NULL CHECK (deployment_id ~ '^[a-z][a-z0-9_-]{0,63}$'),
    environment TEXT NOT NULL CHECK (environment IN ('development','test','production')),
    generation BIGINT NOT NULL DEFAULT 0,
    runtime_source TEXT NOT NULL DEFAULT 'environment',
    active_revision_id UUID,
    activated_at TIMESTAMPTZ,
    PRIMARY KEY (deployment_id,environment),
    CHECK ((runtime_source='environment' AND generation=0 AND active_revision_id IS NULL AND activated_at IS NULL)
        OR (runtime_source='database' AND generation>0 AND active_revision_id IS NOT NULL AND activated_at IS NOT NULL)),
    FOREIGN KEY (deployment_id,environment,generation,active_revision_id)
      REFERENCES framework.auth_activation_history(deployment_id,environment,generation,target_revision_id) DEFERRABLE INITIALLY DEFERRED
);
CREATE FUNCTION framework.guard_auth_activation_head() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
    IF TG_OP='DELETE' THEN
        RAISE EXCEPTION 'activation head cannot be deleted' USING ERRCODE='23514';
    ELSIF TG_OP='INSERT' THEN
        IF NEW.generation NOT IN (0,1) THEN
            RAISE EXCEPTION 'invalid initial activation generation' USING ERRCODE='23514';
        END IF;
    ELSIF ROW(NEW.deployment_id,NEW.environment) IS DISTINCT FROM ROW(OLD.deployment_id,OLD.environment)
       OR NEW.generation<>OLD.generation+1 OR NEW.runtime_source<>'database' THEN
        RAISE EXCEPTION 'invalid activation generation' USING ERRCODE='23514';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER auth_activation_head_guard BEFORE INSERT OR UPDATE OR DELETE ON framework.auth_activation_heads
FOR EACH ROW EXECUTE FUNCTION framework.guard_auth_activation_head();

-- Deferred checks permit head, lifecycle and history changes in any order within
-- one transaction. They inspect final state, not intermediate transition rows.
CREATE FUNCTION framework.check_auth_activation_consistency() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
DECLARE h framework.auth_activation_heads%ROWTYPE; latest BIGINT;
BEGIN
    SELECT * INTO h FROM framework.auth_activation_heads WHERE deployment_id=NEW.deployment_id AND environment=NEW.environment;
    SELECT COALESCE(max(generation),0) INTO latest FROM framework.auth_activation_history WHERE deployment_id=NEW.deployment_id AND environment=NEW.environment;
    IF h.deployment_id IS NULL THEN
        IF latest<>0 THEN RAISE EXCEPTION 'activation head required' USING ERRCODE='23514'; END IF;
        RETURN NULL;
    END IF;
    IF h.generation<>latest OR (h.runtime_source='environment' AND EXISTS (
        SELECT 1 FROM framework.auth_config_lifecycle WHERE deployment_id=h.deployment_id AND environment=h.environment AND status='active'))
       OR (h.runtime_source='database' AND NOT EXISTS (
        SELECT 1 FROM framework.auth_config_lifecycle l JOIN framework.auth_config_revisions r ON r.id=l.revision_id
        JOIN framework.auth_activation_history a ON a.deployment_id=l.deployment_id AND a.environment=l.environment AND a.target_revision_id=l.revision_id
        WHERE l.deployment_id=h.deployment_id AND l.environment=h.environment AND l.revision_id=h.active_revision_id
          AND l.status='active' AND r.provider='oidc' AND a.generation=h.generation AND a.activated_at=h.activated_at)) THEN
        RAISE EXCEPTION 'inconsistent activation state' USING ERRCODE='23514';
    END IF;
    RETURN NULL;
END;
$$;
CREATE CONSTRAINT TRIGGER auth_activation_head_consistency AFTER INSERT OR UPDATE ON framework.auth_activation_heads
DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION framework.check_auth_activation_consistency();
CREATE CONSTRAINT TRIGGER auth_activation_history_consistency AFTER INSERT ON framework.auth_activation_history
DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION framework.check_auth_activation_consistency();
CREATE CONSTRAINT TRIGGER auth_activation_lifecycle_consistency AFTER INSERT OR UPDATE ON framework.auth_config_lifecycle
DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION framework.check_auth_activation_consistency();
CREATE TRIGGER auth_activation_history_immutable BEFORE UPDATE OR DELETE ON framework.auth_activation_history
FOR EACH ROW EXECUTE FUNCTION framework.preserve_auth_config_revision();
CREATE TRIGGER auth_activation_history_no_truncate BEFORE TRUNCATE ON framework.auth_activation_history
FOR EACH STATEMENT EXECUTE FUNCTION framework.preserve_auth_config_revision();
CREATE TRIGGER auth_activation_head_no_truncate BEFORE TRUNCATE ON framework.auth_activation_heads
FOR EACH STATEMENT EXECUTE FUNCTION framework.preserve_auth_config_revision();

CREATE TABLE framework.auth_test_evidence (
    id UUID PRIMARY KEY,
    deployment_id TEXT NOT NULL,
    environment TEXT NOT NULL,
    revision_id UUID NOT NULL,
    revision_generation BIGINT NOT NULL CHECK (revision_generation>0),
    actor_user_id UUID NOT NULL REFERENCES framework.users(id),
    issuer TEXT NOT NULL CHECK (length(issuer) BETWEEN 1 AND 2048),
    subject TEXT NOT NULL CHECK (length(subject) BETWEEN 1 AND 1024),
    purpose TEXT NOT NULL CHECK (purpose IN ('isolated_connection','normal_callback')),
    completed_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    expires_at TIMESTAMPTZ NOT NULL,
    verification_version SMALLINT NOT NULL CHECK (verification_version=1),
    CHECK (expires_at>completed_at AND expires_at<=completed_at+interval '5 minutes'),
    FOREIGN KEY (deployment_id,environment,revision_id) REFERENCES framework.auth_config_revisions(deployment_id,environment,id)
);
CREATE INDEX auth_test_evidence_revision_idx ON framework.auth_test_evidence(deployment_id,environment,revision_id,revision_generation,expires_at);
CREATE FUNCTION framework.guard_auth_test_evidence() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM framework.auth_config_revisions r JOIN framework.auth_config_lifecycle l ON l.revision_id=r.id
       WHERE r.id=NEW.revision_id AND r.deployment_id=NEW.deployment_id AND r.environment=NEW.environment
       AND r.provider='oidc' AND r.issuer_url=NEW.issuer AND l.generation=NEW.revision_generation AND l.status='approved')
       OR NEW.completed_at>clock_timestamp() OR NEW.expires_at<=clock_timestamp() THEN
        RAISE EXCEPTION 'invalid test evidence' USING ERRCODE='23514';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER auth_test_evidence_guard BEFORE INSERT ON framework.auth_test_evidence
FOR EACH ROW EXECUTE FUNCTION framework.guard_auth_test_evidence();
CREATE TRIGGER auth_test_evidence_immutable BEFORE UPDATE OR DELETE ON framework.auth_test_evidence
FOR EACH ROW EXECUTE FUNCTION framework.preserve_auth_config_revision();
CREATE TRIGGER auth_test_evidence_no_truncate BEFORE TRUNCATE ON framework.auth_test_evidence
FOR EACH STATEMENT EXECUTE FUNCTION framework.preserve_auth_config_revision();

-- Existing rows and unchanged environment-mode inserts remain explicitly legacy.
-- No binding can be retroactively changed, including legacy -> database.
ALTER TABLE framework.auth_config_revisions ADD CONSTRAINT auth_config_oidc_binding_unique
UNIQUE (deployment_id,environment,id,issuer_url,client_id);
ALTER TABLE framework.sessions
    ADD COLUMN binding_source TEXT NOT NULL DEFAULT 'legacy',
    ADD COLUMN deployment_id TEXT,
    ADD COLUMN environment TEXT,
    ADD COLUMN revision_id UUID,
    ADD COLUMN activation_generation BIGINT,
    ADD COLUMN client_id TEXT,
    ADD COLUMN flow_purpose TEXT NOT NULL DEFAULT 'login',
    ADD CONSTRAINT session_binding_shape CHECK (
      flow_purpose='login' AND (
      (binding_source='legacy' AND deployment_id IS NULL AND environment IS NULL AND revision_id IS NULL AND activation_generation IS NULL AND client_id IS NULL)
      OR (binding_source IN ('environment','database') AND deployment_id IS NOT NULL AND deployment_id ~ '^[a-z][a-z0-9_-]{0,63}$'
          AND environment IS NOT NULL AND environment IN ('development','test','production') AND client_id IS NOT NULL AND length(client_id) BETWEEN 1 AND 512
          AND ((binding_source='environment' AND revision_id IS NULL AND activation_generation IS NULL)
            OR (binding_source='database' AND revision_id IS NOT NULL AND activation_generation IS NOT NULL AND activation_generation>0))))),
    ADD FOREIGN KEY (deployment_id,environment,revision_id,issuer,client_id)
      REFERENCES framework.auth_config_revisions(deployment_id,environment,id,issuer_url,client_id),
    ADD FOREIGN KEY (deployment_id,environment,activation_generation,revision_id)
      REFERENCES framework.auth_activation_history(deployment_id,environment,generation,target_revision_id);
ALTER TABLE framework.oidc_login_flows
    ADD COLUMN binding_source TEXT NOT NULL DEFAULT 'legacy',
    ADD COLUMN deployment_id TEXT,
    ADD COLUMN environment TEXT,
    ADD COLUMN revision_id UUID,
    ADD COLUMN activation_generation BIGINT,
    ADD COLUMN issuer TEXT,
    ADD COLUMN client_id TEXT,
    ADD COLUMN flow_purpose TEXT NOT NULL DEFAULT 'login',
    ADD CONSTRAINT flow_binding_shape CHECK (
      (binding_source='legacy' AND deployment_id IS NULL AND environment IS NULL AND revision_id IS NULL AND activation_generation IS NULL AND issuer IS NULL AND client_id IS NULL AND flow_purpose='login')
      OR (binding_source IN ('environment','database') AND deployment_id IS NOT NULL AND deployment_id ~ '^[a-z][a-z0-9_-]{0,63}$'
          AND environment IS NOT NULL AND environment IN ('development','test','production') AND issuer IS NOT NULL AND length(issuer) BETWEEN 1 AND 2048
          AND client_id IS NOT NULL AND length(client_id) BETWEEN 1 AND 512 AND flow_purpose IN ('login','isolated_connection','normal_callback')
          AND ((binding_source='environment' AND revision_id IS NULL AND activation_generation IS NULL AND flow_purpose='login')
            OR (binding_source='database' AND revision_id IS NOT NULL
                AND ((flow_purpose='login' AND activation_generation IS NOT NULL AND activation_generation>0)
                  OR (flow_purpose<>'login' AND activation_generation IS NULL)))))),
    ADD FOREIGN KEY (deployment_id,environment,revision_id,issuer,client_id)
      REFERENCES framework.auth_config_revisions(deployment_id,environment,id,issuer_url,client_id),
    ADD FOREIGN KEY (deployment_id,environment,activation_generation,revision_id)
      REFERENCES framework.auth_activation_history(deployment_id,environment,generation,target_revision_id);
CREATE FUNCTION framework.guard_auth_binding() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
    IF ROW(NEW.binding_source,NEW.deployment_id,NEW.environment,NEW.revision_id,NEW.activation_generation,NEW.issuer,NEW.client_id,NEW.flow_purpose)
       IS DISTINCT FROM ROW(OLD.binding_source,OLD.deployment_id,OLD.environment,OLD.revision_id,OLD.activation_generation,OLD.issuer,OLD.client_id,OLD.flow_purpose) THEN
        RAISE EXCEPTION 'authentication binding is immutable' USING ERRCODE='23514';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER session_binding_immutable BEFORE UPDATE ON framework.sessions FOR EACH ROW EXECUTE FUNCTION framework.guard_auth_binding();
CREATE TRIGGER flow_binding_immutable BEFORE UPDATE ON framework.oidc_login_flows FOR EACH ROW EXECUTE FUNCTION framework.guard_auth_binding();
CREATE INDEX sessions_binding_idx ON framework.sessions(deployment_id,environment,revision_id,activation_generation) WHERE binding_source<>'legacy';
CREATE INDEX oidc_flows_binding_idx ON framework.oidc_login_flows(deployment_id,environment,revision_id,activation_generation) WHERE binding_source<>'legacy';
-- No application activation writer is supplied in this phase.
GRANT SELECT ON framework.auth_activation_heads,framework.auth_activation_history TO go_web_app;
GRANT SELECT,INSERT ON framework.auth_test_evidence TO go_web_app;
COMMIT;
