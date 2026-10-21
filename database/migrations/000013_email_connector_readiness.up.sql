BEGIN;
ALTER TABLE framework.notification_connectors ADD CONSTRAINT notification_connector_scope UNIQUE(deployment_id,environment,id);
CREATE TABLE framework.notification_connector_readiness (
 connector_id UUID PRIMARY KEY,
 deployment_id TEXT NOT NULL,environment TEXT NOT NULL,
 connector_generation BIGINT NOT NULL CHECK(connector_generation>0),
 generation BIGINT NOT NULL DEFAULT 1 CHECK(generation>0),
 operation_id UUID NOT NULL,
 status TEXT NOT NULL CHECK(status IN ('configured','ready','authentication_failed','sender_not_verified','permission_denied','quota_unavailable','provider_unavailable')),
 code TEXT NOT NULL CHECK(code IN ('not_tested','ready','gmail_not_authorized','gmail_setup_required','gmail_scope_required','gmail_authentication_failed','gmail_sender_not_verified','gmail_permission_denied','gmail_quota_unavailable','gmail_provider_unavailable','ses_authentication_failed','ses_sender_not_verified','ses_permission_denied','ses_sandbox','ses_sending_disabled','ses_quota_unavailable','ses_provider_unavailable')),
 credential_version UUID,
 mailbox TEXT NOT NULL DEFAULT '' CHECK(mailbox='' OR (framework.invitation_email_key(mailbox) IS NOT NULL AND mailbox=framework.invitation_email_key(mailbox))),
 quota_known BOOLEAN NOT NULL DEFAULT FALSE,
 remaining_24_hours DOUBLE PRECISION NOT NULL DEFAULT 0 CHECK(remaining_24_hours>=0 AND remaining_24_hours<1e12),
 max_per_second DOUBLE PRECISION NOT NULL DEFAULT 0 CHECK(max_per_second>=0 AND max_per_second<1e9),
 tested_by UUID NOT NULL REFERENCES framework.users(id),
 tested_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
 expires_at TIMESTAMPTZ NOT NULL,
 CHECK(expires_at>tested_at AND expires_at<=tested_at+interval '5 minutes'),
 created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
 FOREIGN KEY(deployment_id,environment,connector_id) REFERENCES framework.notification_connectors(deployment_id,environment,id)
);
CREATE TABLE framework.notification_connector_oauth_flows (
 id UUID PRIMARY KEY,
 deployment_id TEXT NOT NULL,environment TEXT NOT NULL,
 connector_id UUID NOT NULL,
 actor_user_id UUID NOT NULL REFERENCES framework.users(id),
 connector_generation BIGINT NOT NULL CHECK(connector_generation>0),
 policy_generation BIGINT NOT NULL CHECK(policy_generation>0),
 activation_generation BIGINT NOT NULL CHECK(activation_generation>0),
 revision_id UUID NOT NULL,
 revision_generation BIGINT NOT NULL CHECK(revision_generation>0),
 client_id_digest BYTEA NOT NULL CHECK(octet_length(client_id_digest)=32),
 state_hash BYTEA NOT NULL CHECK(octet_length(state_hash)=32),
 browser_hash BYTEA NOT NULL CHECK(octet_length(browser_hash)=32),
 mailbox TEXT NOT NULL CHECK(framework.invitation_email_key(mailbox) IS NOT NULL AND mailbox=framework.invitation_email_key(mailbox)),
 status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','consumed')),
 generation BIGINT NOT NULL DEFAULT 1 CHECK(generation>0),
 reason TEXT NOT NULL CHECK(length(btrim(reason)) BETWEEN 8 AND 512 AND reason !~ '[[:cntrl:]]'),
 created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
 expires_at TIMESTAMPTZ NOT NULL CHECK(expires_at>created_at AND expires_at<=created_at+interval '5 minutes'),
 FOREIGN KEY(deployment_id,environment,connector_id) REFERENCES framework.notification_connectors(deployment_id,environment,id),
 FOREIGN KEY(deployment_id,environment,revision_id) REFERENCES framework.auth_config_revisions(deployment_id,environment,id)
);
CREATE INDEX notification_oauth_pending ON framework.notification_connector_oauth_flows(deployment_id,environment,actor_user_id,expires_at) WHERE status='pending';
CREATE FUNCTION framework.guard_connector_observations() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
 IF TG_OP IN ('DELETE','TRUNCATE') THEN RAISE EXCEPTION 'connector authorization and readiness history is retained' USING ERRCODE='23514'; END IF;
 IF TG_TABLE_NAME='notification_connector_oauth_flows' THEN
   IF OLD.status<>'pending' OR NEW.status<>'consumed' OR NEW.generation<>OLD.generation+1 OR
    (to_jsonb(OLD)-ARRAY['status','generation']) IS DISTINCT FROM (to_jsonb(NEW)-ARRAY['status','generation']) THEN
     RAISE EXCEPTION 'OAuth flows are immutable and single use' USING ERRCODE='23514';
   END IF;
 ELSE
   IF NEW.generation<>OLD.generation+1 OR ROW(NEW.connector_id,NEW.deployment_id,NEW.environment,NEW.created_at) IS DISTINCT FROM ROW(OLD.connector_id,OLD.deployment_id,OLD.environment,OLD.created_at) THEN
     RAISE EXCEPTION 'readiness observation scope is immutable' USING ERRCODE='23514';
   END IF;
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER connector_readiness_history BEFORE UPDATE OR DELETE ON framework.notification_connector_readiness FOR EACH ROW EXECUTE FUNCTION framework.guard_connector_observations();
CREATE TRIGGER connector_readiness_retain BEFORE TRUNCATE ON framework.notification_connector_readiness FOR EACH STATEMENT EXECUTE FUNCTION framework.guard_connector_observations();
CREATE TRIGGER connector_oauth_history BEFORE UPDATE OR DELETE ON framework.notification_connector_oauth_flows FOR EACH ROW EXECUTE FUNCTION framework.guard_connector_observations();
CREATE TRIGGER connector_oauth_retain BEFORE TRUNCATE ON framework.notification_connector_oauth_flows FOR EACH STATEMENT EXECUTE FUNCTION framework.guard_connector_observations();
GRANT SELECT,INSERT,UPDATE ON framework.notification_connector_readiness,framework.notification_connector_oauth_flows TO go_web_app;
COMMIT;
