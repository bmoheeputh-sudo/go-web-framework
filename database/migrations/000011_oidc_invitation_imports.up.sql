-- CSV contents are never retained. Existing invitation/identity history is unchanged.
BEGIN;
CREATE TABLE framework.oidc_invitation_import_keys (
 singleton BOOLEAN PRIMARY KEY DEFAULT true CHECK (singleton),
 signing_key BYTEA NOT NULL CHECK (octet_length(signing_key)=32)
);
-- Native random UUIDs provide an installation-local, cross-instance signing seed.
-- No operator credential or authentication-provider secret is reused.
INSERT INTO framework.oidc_invitation_import_keys(signing_key)
 VALUES(decode(replace(gen_random_uuid()::text,'-','')||replace(gen_random_uuid()::text,'-',''),'hex'));

CREATE TABLE framework.oidc_invitation_imports (
 id UUID PRIMARY KEY,
 deployment_id TEXT NOT NULL,
 environment TEXT NOT NULL,
 actor_user_id UUID NOT NULL REFERENCES framework.users(id),
 idempotency_digest BYTEA NOT NULL CHECK (octet_length(idempotency_digest)=32),
 content_digest BYTEA NOT NULL CHECK (octet_length(content_digest)=32),
 payload_digest BYTEA NOT NULL CHECK (octet_length(payload_digest)=32),
 preview_digest BYTEA NOT NULL CHECK (octet_length(preview_digest)=32),
 policy_generation BIGINT NOT NULL CHECK (policy_generation>0),
 activation_generation BIGINT NOT NULL CHECK (activation_generation>0),
 revision_id UUID NOT NULL,
 revision_generation BIGINT NOT NULL CHECK (revision_generation>0),
 issuer TEXT COLLATE "C" NOT NULL,
 client_id TEXT COLLATE "C" NOT NULL,
 expiration_days INTEGER NOT NULL CHECK (expiration_days BETWEEN 1 AND 30),
 total_rows INTEGER NOT NULL CHECK (total_rows BETWEEN 1 AND 500),
 selected_rows INTEGER[] NOT NULL CHECK (cardinality(selected_rows) BETWEEN 1 AND 500),
 created_count INTEGER NOT NULL CHECK (created_count=cardinality(selected_rows)),
 skipped_count INTEGER NOT NULL CHECK (skipped_count>=0),
 rejected_count INTEGER NOT NULL CHECK (rejected_count>=0),
 created_invitation_ids UUID[] NOT NULL CHECK (cardinality(created_invitation_ids)=created_count),
 created_at TIMESTAMPTZ NOT NULL,
 completed_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp() CHECK (completed_at>=created_at),
 outcome TEXT NOT NULL CHECK (outcome='completed'),
 reason TEXT NOT NULL CHECK (length(btrim(reason)) BETWEEN 8 AND 512 AND reason !~ '[[:cntrl:]]'),
 CHECK (created_count+skipped_count+rejected_count=total_rows),
 UNIQUE (deployment_id,environment,actor_user_id,idempotency_digest),
 FOREIGN KEY (deployment_id,environment) REFERENCES framework.oidc_access_policies(deployment_id,environment),
 FOREIGN KEY (deployment_id,environment,revision_id,issuer,client_id)
   REFERENCES framework.auth_config_revisions(deployment_id,environment,id,issuer_url,client_id),
 FOREIGN KEY (deployment_id,environment,activation_generation,revision_id)
   REFERENCES framework.auth_activation_history(deployment_id,environment,generation,target_revision_id)
);
CREATE INDEX oidc_invitation_import_history ON framework.oidc_invitation_imports(deployment_id,environment,created_at DESC,id);
CREATE INDEX oidc_invitation_import_listing ON framework.oidc_invitations(deployment_id,environment,import_id,created_at DESC,id) WHERE import_id IS NOT NULL;

CREATE FUNCTION framework.retain_oidc_import_history() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
 RAISE EXCEPTION 'invitation import history and preview signing seed are immutable' USING ERRCODE='23514';
END $$;
CREATE TRIGGER oidc_import_key_immutable BEFORE UPDATE OR DELETE ON framework.oidc_invitation_import_keys
 FOR EACH ROW EXECUTE FUNCTION framework.retain_oidc_import_history();
CREATE TRIGGER oidc_import_key_retain BEFORE TRUNCATE ON framework.oidc_invitation_import_keys
 FOR EACH STATEMENT EXECUTE FUNCTION framework.retain_oidc_import_history();
CREATE TRIGGER oidc_import_immutable BEFORE UPDATE OR DELETE ON framework.oidc_invitation_imports
 FOR EACH ROW EXECUTE FUNCTION framework.retain_oidc_import_history();
CREATE TRIGGER oidc_import_retain BEFORE TRUNCATE ON framework.oidc_invitation_imports
 FOR EACH STATEMENT EXECUTE FUNCTION framework.retain_oidc_import_history();

CREATE FUNCTION framework.guard_oidc_import_receipt() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
 IF NEW.selected_rows IS DISTINCT FROM ARRAY(SELECT DISTINCT n FROM unnest(NEW.selected_rows) n ORDER BY n)
   OR EXISTS(SELECT 1 FROM unnest(NEW.selected_rows) n WHERE n IS NULL OR n<1 OR n>NEW.total_rows)
   OR NEW.created_count<>(SELECT count(DISTINCT n) FROM unnest(NEW.created_invitation_ids) n)
   OR NEW.created_count<>(SELECT count(*) FROM framework.oidc_invitations i
     WHERE i.import_id=NEW.id AND i.deployment_id=NEW.deployment_id AND i.environment=NEW.environment)
   OR NEW.created_count<>(SELECT count(*) FROM framework.oidc_invitations i
     WHERE i.id=ANY(NEW.created_invitation_ids) AND i.import_id=NEW.id AND i.source='csv'
       AND i.status='pending' AND i.created_by=NEW.actor_user_id
       AND i.deployment_id=NEW.deployment_id AND i.environment=NEW.environment
       AND i.revision_id=NEW.revision_id AND i.revision_generation=NEW.revision_generation
       AND i.activation_generation=NEW.activation_generation AND i.issuer=NEW.issuer AND i.client_id=NEW.client_id) THEN
   RAISE EXCEPTION 'invalid invitation import receipt' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER oidc_import_receipt BEFORE INSERT ON framework.oidc_invitation_imports
 FOR EACH ROW EXECUTE FUNCTION framework.guard_oidc_import_receipt();

-- Check only new inserts: historical CSV foundation records are not rewritten
-- or retroactively constrained, and normal claim updates remain unchanged.
CREATE FUNCTION framework.require_oidc_import_receipt() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
 IF NEW.source='csv' AND NOT EXISTS(SELECT 1 FROM framework.oidc_invitation_imports r
   WHERE r.id=NEW.import_id AND r.deployment_id=NEW.deployment_id AND r.environment=NEW.environment
     AND r.actor_user_id=NEW.created_by AND NEW.id=ANY(r.created_invitation_ids)) THEN
   RAISE EXCEPTION 'CSV invitation requires its atomic receipt' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END $$;
CREATE CONSTRAINT TRIGGER oidc_invitation_import_receipt AFTER INSERT ON framework.oidc_invitations
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION framework.require_oidc_import_receipt();

REVOKE ALL ON framework.oidc_invitation_import_keys,framework.oidc_invitation_imports FROM PUBLIC;
GRANT SELECT ON framework.oidc_invitation_import_keys TO go_web_app;
GRANT SELECT,INSERT ON framework.oidc_invitation_imports TO go_web_app;
REVOKE ALL ON FUNCTION framework.retain_oidc_import_history(),framework.guard_oidc_import_receipt(),framework.require_oidc_import_receipt() FROM PUBLIC;
COMMIT;
