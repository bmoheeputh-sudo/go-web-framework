BEGIN;

ALTER TABLE framework.users
 ADD COLUMN first_successful_oidc_login_at TIMESTAMPTZ,
 ADD COLUMN last_successful_oidc_login_at TIMESTAMPTZ,
 ADD CONSTRAINT oidc_login_observation_pair CHECK (
   (first_successful_oidc_login_at IS NULL AND last_successful_oidc_login_at IS NULL) OR
   (provider='oidc' AND first_successful_oidc_login_at IS NOT NULL AND last_successful_oidc_login_at IS NOT NULL
    AND last_successful_oidc_login_at>=first_successful_oidc_login_at));

CREATE FUNCTION framework.guard_oidc_login_observation() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog AS $$
DECLARE observed TIMESTAMPTZ;
BEGIN
 IF TG_OP='INSERT' THEN
   IF NEW.first_successful_oidc_login_at IS NOT NULL OR NEW.last_successful_oidc_login_at IS NOT NULL THEN
     RAISE EXCEPTION 'login observations require a normal session transaction' USING ERRCODE='23514';
   END IF;
 ELSIF ROW(NEW.first_successful_oidc_login_at,NEW.last_successful_oidc_login_at)
       IS DISTINCT FROM ROW(OLD.first_successful_oidc_login_at,OLD.last_successful_oidc_login_at) THEN
   IF (OLD.first_successful_oidc_login_at IS NOT NULL AND NEW.first_successful_oidc_login_at IS DISTINCT FROM OLD.first_successful_oidc_login_at)
      OR NEW.first_successful_oidc_login_at IS NULL OR NEW.last_successful_oidc_login_at IS NULL
      OR NOT NEW.active OR NEW.provider<>'oidc'
      OR NOT EXISTS(SELECT 1 FROM framework.sessions s WHERE s.issuer=NEW.issuer COLLATE "C" AND s.subject=NEW.subject COLLATE "C"
        AND s.provider='oidc' AND s.flow_purpose='login' AND s.expires_at>clock_timestamp()
        AND s.xmin=pg_current_xact_id()::text::xid) THEN
     RAISE EXCEPTION 'login observation requires a newly created exact-identity normal session' USING ERRCODE='23514';
   END IF;
   observed:=clock_timestamp();
   NEW.first_successful_oidc_login_at:=COALESCE(OLD.first_successful_oidc_login_at,observed);
   NEW.last_successful_oidc_login_at:=GREATEST(observed,OLD.last_successful_oidc_login_at);
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER oidc_login_observation BEFORE INSERT OR UPDATE ON framework.users
 FOR EACH ROW EXECUTE FUNCTION framework.guard_oidc_login_observation();

-- Connection metadata only. OAuth tokens, client secrets and AWS access keys are never stored here.
CREATE TABLE framework.notification_connectors (
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
 deployment_id TEXT NOT NULL, environment TEXT NOT NULL,
 provider TEXT NOT NULL CHECK(provider IN ('gmail','ses')),
 sender_email TEXT NOT NULL CHECK(framework.invitation_email_key(sender_email) IS NOT NULL AND sender_email=framework.invitation_email_key(sender_email)),
 sender_approved BOOLEAN NOT NULL CHECK(sender_approved),
 credential_reference TEXT NOT NULL DEFAULT '',
 region TEXT NOT NULL DEFAULT '',
 CHECK ((provider='gmail' AND credential_reference ~ '^notifications/[a-zA-Z0-9/_-]{1,100}$' AND region='')
     OR (provider='ses' AND credential_reference='' AND region ~ '^[a-z]{2}(-[a-z0-9]+)+-[0-9]+$' AND length(region)<=32)),
 enabled BOOLEAN NOT NULL DEFAULT FALSE,
 is_default BOOLEAN NOT NULL DEFAULT FALSE CHECK(NOT is_default OR enabled),
 per_minute INTEGER NOT NULL CHECK(per_minute BETWEEN 1 AND 60),
 per_day INTEGER NOT NULL CHECK(per_day BETWEEN 1 AND 100000),
 generation BIGINT NOT NULL DEFAULT 1 CHECK(generation>0),
 failure_count BIGINT NOT NULL DEFAULT 0 CHECK(failure_count>=0),
 last_error_code TEXT NOT NULL DEFAULT '' CHECK(last_error_code IN ('','provider_rejected','provider_uncertain','lease_expired','adapter_unavailable','invalid_result')),
 last_accepted_at TIMESTAMPTZ,
 created_by UUID NOT NULL REFERENCES framework.users(id),
 updated_by UUID NOT NULL REFERENCES framework.users(id),
 reason TEXT NOT NULL CHECK(length(btrim(reason)) BETWEEN 8 AND 512 AND reason !~ '[[:cntrl:]]'),
 created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
 updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
 UNIQUE(deployment_id,environment,id,sender_email),
 FOREIGN KEY(deployment_id,environment) REFERENCES framework.oidc_access_policies(deployment_id,environment)
);
CREATE UNIQUE INDEX notification_default_connector ON framework.notification_connectors(deployment_id,environment) WHERE is_default;

CREATE TABLE framework.notification_requests (
 id UUID PRIMARY KEY,
 deployment_id TEXT NOT NULL, environment TEXT NOT NULL,
 actor_user_id UUID NOT NULL REFERENCES framework.users(id),
 notification_type TEXT NOT NULL CHECK(notification_type IN ('invitation','reminder')),
 template_version TEXT NOT NULL CHECK(template_version='onboarding.v1'),
 locale TEXT NOT NULL CHECK(locale IN ('en','nl','fr','es','pt-BR','zh-CN','id','ms','th','vi','hi','ar')),
 connector_id UUID NOT NULL,
 sender_email TEXT NOT NULL,
 idempotency_digest BYTEA NOT NULL CHECK(octet_length(idempotency_digest)=32),
 payload_digest BYTEA NOT NULL CHECK(octet_length(payload_digest)=32),
 communication_digest BYTEA NOT NULL CHECK(octet_length(communication_digest)=32),
 policy_generation BIGINT NOT NULL CHECK(policy_generation>0),
 revision_id UUID NOT NULL,
 revision_generation BIGINT NOT NULL CHECK(revision_generation>0),
 activation_generation BIGINT NOT NULL CHECK(activation_generation>0),
 confirmed BOOLEAN NOT NULL CHECK(confirmed),
 outcome TEXT NOT NULL CHECK(outcome='enqueued'),
 job_count INTEGER NOT NULL CHECK(job_count BETWEEN 1 AND 100),
 reason TEXT NOT NULL CHECK(length(btrim(reason)) BETWEEN 8 AND 512 AND reason !~ '[[:cntrl:]]'),
 created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
 UNIQUE(deployment_id,environment,actor_user_id,idempotency_digest),
 UNIQUE(deployment_id,environment,id,connector_id,sender_email,notification_type,template_version),
 FOREIGN KEY(deployment_id,environment,connector_id,sender_email) REFERENCES framework.notification_connectors(deployment_id,environment,id,sender_email),
 FOREIGN KEY(deployment_id,environment) REFERENCES framework.oidc_access_policies(deployment_id,environment),
 FOREIGN KEY(deployment_id,environment,revision_id) REFERENCES framework.auth_config_revisions(deployment_id,environment,id)
);

CREATE TABLE framework.notification_jobs (
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
 request_id UUID NOT NULL,
 deployment_id TEXT NOT NULL, environment TEXT NOT NULL,
 connector_id UUID NOT NULL, sender_email TEXT NOT NULL,
 notification_type TEXT NOT NULL, template_version TEXT NOT NULL,
 invitation_id UUID REFERENCES framework.oidc_invitations(id),
 user_id UUID REFERENCES framework.users(id),
 CHECK((invitation_id IS NULL)<>(user_id IS NULL)),
 recipient_email TEXT NOT NULL,
 recipient_key TEXT NOT NULL CHECK(framework.invitation_email_key(recipient_email) IS NOT NULL AND recipient_key=framework.invitation_email_key(recipient_email)),
 provenance TEXT NOT NULL CHECK((provenance='administrator_invitation' AND invitation_id IS NOT NULL) OR (provenance='verified_oidc_user' AND user_id IS NOT NULL)),
 display_name TEXT NOT NULL CHECK(length(display_name)<=200 AND display_name !~ '[[:cntrl:]]'),
 due_at TIMESTAMPTZ NOT NULL,
 status TEXT NOT NULL DEFAULT 'queued' CHECK(status IN ('queued','leased','dispatching','sent','failed','needs_inspection','cancelled')),
 generation BIGINT NOT NULL DEFAULT 1 CHECK(generation>0),
 lease_owner UUID,
 lease_expires_at TIMESTAMPTZ,
 CHECK((status IN ('leased','dispatching'))=(lease_owner IS NOT NULL AND lease_expires_at IS NOT NULL)),
 CHECK((lease_owner IS NULL)=(lease_expires_at IS NULL)),
 attempt_count INTEGER NOT NULL DEFAULT 0 CHECK(attempt_count BETWEEN 0 AND 10),
 disposition_code TEXT NOT NULL DEFAULT '' CHECK(disposition_code IN ('','administrator_cancelled','suppressed','stale_configuration','invitation_unavailable','inactive_user','revoked_identity','onboarded','recipient_changed','domain_blocked','review_required','provider_rejected','provider_uncertain','lease_expired','adapter_unavailable','invalid_result')),
 updated_by UUID NOT NULL REFERENCES framework.users(id),
 created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
 updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
 UNIQUE(deployment_id,environment,id),
 FOREIGN KEY(deployment_id,environment,request_id,connector_id,sender_email,notification_type,template_version)
 REFERENCES framework.notification_requests(deployment_id,environment,id,connector_id,sender_email,notification_type,template_version)
);
CREATE UNIQUE INDEX notification_invitation_once_per_request ON framework.notification_jobs(request_id,invitation_id) WHERE invitation_id IS NOT NULL;
CREATE UNIQUE INDEX notification_user_once_per_request ON framework.notification_jobs(request_id,user_id) WHERE user_id IS NOT NULL;
CREATE INDEX notification_jobs_due ON framework.notification_jobs(deployment_id,environment,due_at,id) WHERE status='queued';
CREATE INDEX notification_jobs_leases ON framework.notification_jobs(deployment_id,environment,lease_expires_at) WHERE status IN ('leased','dispatching');
CREATE INDEX notification_jobs_recipient ON framework.notification_jobs(deployment_id,environment,lower(recipient_key COLLATE "C"),status);

CREATE TABLE framework.notification_attempts (
 job_id UUID NOT NULL REFERENCES framework.notification_jobs(id),
 attempt_number INTEGER NOT NULL CHECK(attempt_number BETWEEN 1 AND 10),
 adapter TEXT NOT NULL CHECK(adapter IN ('gmail','ses')),
 executor_id UUID NOT NULL,
 started_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
 completed_at TIMESTAMPTZ,
 outcome TEXT CHECK(outcome IN ('accepted','rejected','uncertain')),
 provider_message_id TEXT NOT NULL DEFAULT '' CHECK(length(provider_message_id)<=256 AND provider_message_id !~ '[[:cntrl:]]'),
 error_code TEXT NOT NULL DEFAULT '' CHECK(error_code IN ('','provider_rejected','provider_uncertain','lease_expired','adapter_unavailable','invalid_result')),
 CHECK((outcome IS NULL)=(completed_at IS NULL)),
 CHECK(completed_at IS NULL OR completed_at>=started_at),
 CHECK(outcome='accepted' OR provider_message_id=''),
 CHECK((outcome IS NULL AND error_code='') OR (outcome='accepted' AND error_code='') OR (outcome='rejected' AND error_code='provider_rejected') OR (outcome='uncertain' AND error_code IN ('provider_uncertain','lease_expired','invalid_result'))),
 PRIMARY KEY(job_id,attempt_number)
);
-- Future authenticated SES bounce/complaint events can correlate using these IDs.
CREATE INDEX notification_provider_messages ON framework.notification_attempts(adapter,provider_message_id) WHERE provider_message_id<>'';
CREATE INDEX notification_attempts_started ON framework.notification_attempts(started_at,job_id);

CREATE TABLE framework.notification_suppressions (
 deployment_id TEXT NOT NULL, environment TEXT NOT NULL,
 target_key TEXT NOT NULL,
 recipient_key TEXT,
 invitation_id UUID REFERENCES framework.oidc_invitations(id),
 user_id UUID REFERENCES framework.users(id),
 CHECK(num_nonnulls(recipient_key,invitation_id,user_id)=1),
 CHECK((recipient_key IS NULL OR (framework.invitation_email_key(recipient_key) IS NOT NULL AND recipient_key=framework.invitation_email_key(recipient_key)))
   AND target_key=CASE WHEN recipient_key IS NOT NULL THEN 'email:'||recipient_key WHEN invitation_id IS NOT NULL THEN 'invitation:'||invitation_id::text ELSE 'user:'||user_id::text END),
 active BOOLEAN NOT NULL,
 generation BIGINT NOT NULL DEFAULT 1 CHECK(generation>0),
 created_by UUID NOT NULL REFERENCES framework.users(id),
 updated_by UUID NOT NULL REFERENCES framework.users(id),
 reason TEXT NOT NULL CHECK(length(btrim(reason)) BETWEEN 8 AND 512 AND reason !~ '[[:cntrl:]]'),
 created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
 updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(deployment_id,environment,target_key),
 FOREIGN KEY(deployment_id,environment) REFERENCES framework.oidc_access_policies(deployment_id,environment)
);

CREATE FUNCTION framework.guard_notification_history() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
 IF TG_OP='INSERT' AND TG_TABLE_NAME='notification_jobs' THEN
   IF NEW.status<>'queued' OR NEW.generation<>1 OR NEW.attempt_count<>0 OR NEW.lease_owner IS NOT NULL OR NEW.lease_expires_at IS NOT NULL
    OR NOT EXISTS(SELECT 1 FROM framework.notification_requests n JOIN framework.auth_config_revisions r ON r.id=n.revision_id
     WHERE n.id=NEW.request_id AND n.xmin=pg_current_xact_id()::text::xid
     AND ((NEW.invitation_id IS NOT NULL AND EXISTS(SELECT 1 FROM framework.oidc_invitations i WHERE i.id=NEW.invitation_id
       AND i.deployment_id=NEW.deployment_id AND i.environment=NEW.environment AND i.email=NEW.recipient_email AND i.revision_id=n.revision_id))
      OR (NEW.user_id IS NOT NULL AND EXISTS(SELECT 1 FROM framework.users u WHERE u.id=NEW.user_id AND u.issuer=r.issuer_url COLLATE "C"
       AND u.provider='oidc' AND u.active AND u.email_verified AND u.email=NEW.recipient_email)))) THEN
     RAISE EXCEPTION 'jobs require an atomic request and scoped recipient snapshot' USING ERRCODE='23514';
   END IF;
   NEW.created_at:=clock_timestamp(); NEW.updated_at:=NEW.created_at;
   RETURN NEW;
 END IF;
 IF TG_OP IN ('DELETE','TRUNCATE') OR TG_TABLE_NAME='notification_requests' THEN
   RAISE EXCEPTION 'notification history is retained' USING ERRCODE='23514';
 END IF;
 IF TG_TABLE_NAME='notification_jobs' THEN
   IF (to_jsonb(NEW)-ARRAY['status','generation','lease_owner','lease_expires_at','attempt_count','disposition_code','updated_by','updated_at'])
      IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['status','generation','lease_owner','lease_expires_at','attempt_count','disposition_code','updated_by','updated_at'])
      OR NEW.generation<>OLD.generation+1 OR NEW.attempt_count<OLD.attempt_count OR NEW.attempt_count>OLD.attempt_count+1
      OR ((NEW.attempt_count=OLD.attempt_count+1) IS DISTINCT FROM (OLD.status='leased' AND NEW.status='dispatching'))
      OR (NEW.status='dispatching' AND ROW(NEW.lease_owner,NEW.lease_expires_at) IS DISTINCT FROM ROW(OLD.lease_owner,OLD.lease_expires_at))
      OR (NEW.status='leased' AND (NEW.lease_expires_at<=clock_timestamp() OR NEW.lease_expires_at>clock_timestamp()+interval '5 minutes'))
      OR (OLD.status='leased' AND NEW.status='queued' AND OLD.lease_expires_at>clock_timestamp())
      OR (OLD.status='dispatching' AND NOT EXISTS(SELECT 1 FROM framework.notification_attempts a WHERE a.job_id=OLD.id AND a.attempt_number=OLD.attempt_count
        AND a.outcome=CASE NEW.status WHEN 'sent' THEN 'accepted' WHEN 'failed' THEN 'rejected' ELSE 'uncertain' END))
      OR NOT ((OLD.status='queued' AND NEW.status IN ('leased','cancelled'))
       OR (OLD.status='leased' AND NEW.status IN ('queued','dispatching','cancelled'))
       OR (OLD.status='dispatching' AND NEW.status IN ('sent','failed','needs_inspection'))) THEN
     RAISE EXCEPTION 'invalid notification transition or immutable binding' USING ERRCODE='23514';
   END IF;
 ELSIF TG_TABLE_NAME='notification_connectors' THEN
   IF NEW.generation<>OLD.generation+1 OR
      (to_jsonb(NEW)-ARRAY['enabled','is_default','per_minute','per_day','generation','failure_count','last_error_code','last_accepted_at','updated_by','reason','updated_at'])
      IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['enabled','is_default','per_minute','per_day','generation','failure_count','last_error_code','last_accepted_at','updated_by','reason','updated_at']) THEN
     RAISE EXCEPTION 'connector identities are immutable' USING ERRCODE='23514';
   END IF;
 ELSIF TG_TABLE_NAME='notification_suppressions' THEN
   IF NEW.generation<>OLD.generation+1 OR
      ROW(NEW.deployment_id,NEW.environment,NEW.target_key,NEW.recipient_key,NEW.invitation_id,NEW.user_id,NEW.created_by,NEW.created_at)
      IS DISTINCT FROM ROW(OLD.deployment_id,OLD.environment,OLD.target_key,OLD.recipient_key,OLD.invitation_id,OLD.user_id,OLD.created_by,OLD.created_at) THEN
     RAISE EXCEPTION 'suppression target is immutable' USING ERRCODE='23514';
   END IF;
 END IF;
 NEW.updated_at:=clock_timestamp();
 RETURN NEW;
END $$;
-- Attempts have no updated_at column; use a separate completion/retention guard.
CREATE FUNCTION framework.guard_notification_attempt() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
 IF TG_OP='INSERT' THEN
   IF NEW.outcome IS NOT NULL OR NEW.completed_at IS NOT NULL OR NEW.provider_message_id<>'' OR NEW.error_code<>''
    OR NOT EXISTS(SELECT 1 FROM framework.notification_jobs j JOIN framework.notification_connectors c ON c.id=j.connector_id
      WHERE j.id=NEW.job_id AND j.status='dispatching' AND j.attempt_count=NEW.attempt_number AND j.lease_owner=NEW.executor_id
      AND j.lease_expires_at>clock_timestamp() AND c.provider=NEW.adapter) THEN
     RAISE EXCEPTION 'attempt requires a fenced dispatch marker' USING ERRCODE='23514';
   END IF;
   NEW.started_at:=clock_timestamp(); RETURN NEW;
 END IF;
 IF TG_OP IN ('DELETE','TRUNCATE') OR OLD.outcome IS NOT NULL OR NEW.outcome IS NULL OR
 (to_jsonb(NEW)-ARRAY['outcome','completed_at','provider_message_id','error_code']) IS DISTINCT FROM
 (to_jsonb(OLD)-ARRAY['outcome','completed_at','provider_message_id','error_code']) THEN
   RAISE EXCEPTION 'delivery attempt history is retained and immutable' USING ERRCODE='23514';
 END IF;
 IF NOT EXISTS(SELECT 1 FROM framework.notification_jobs j WHERE j.id=NEW.job_id AND j.status='dispatching' AND j.attempt_count=NEW.attempt_number AND j.lease_owner=NEW.executor_id
   AND (j.lease_expires_at>clock_timestamp() OR (NEW.outcome='uncertain' AND NEW.error_code='lease_expired'))) THEN
   RAISE EXCEPTION 'completion requires its live lease or explicit uncertainty recovery' USING ERRCODE='23514';
 END IF;
 NEW.completed_at:=clock_timestamp();
 RETURN NEW;
END $$;
DO $$ DECLARE t TEXT; BEGIN
 FOREACH t IN ARRAY ARRAY['notification_requests','notification_jobs','notification_connectors','notification_suppressions'] LOOP
   EXECUTE format('CREATE TRIGGER notification_history BEFORE UPDATE OR DELETE ON framework.%I FOR EACH ROW EXECUTE FUNCTION framework.guard_notification_history()',t);
   EXECUTE format('CREATE TRIGGER notification_retain BEFORE TRUNCATE ON framework.%I FOR EACH STATEMENT EXECUTE FUNCTION framework.guard_notification_history()',t);
 END LOOP;
END $$;
CREATE TRIGGER notification_attempt_history BEFORE UPDATE OR DELETE ON framework.notification_attempts FOR EACH ROW EXECUTE FUNCTION framework.guard_notification_attempt();
CREATE TRIGGER notification_attempt_retain BEFORE TRUNCATE ON framework.notification_attempts FOR EACH STATEMENT EXECUTE FUNCTION framework.guard_notification_attempt();
CREATE TRIGGER notification_job_insert BEFORE INSERT ON framework.notification_jobs FOR EACH ROW EXECUTE FUNCTION framework.guard_notification_history();
CREATE TRIGGER notification_attempt_insert BEFORE INSERT ON framework.notification_attempts FOR EACH ROW EXECUTE FUNCTION framework.guard_notification_attempt();

CREATE FUNCTION framework.require_notification_jobs() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
 IF (SELECT count(*) FROM framework.notification_jobs WHERE request_id=NEW.id)<>NEW.job_count THEN
   RAISE EXCEPTION 'notification request requires its complete atomic job set' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END $$;
CREATE CONSTRAINT TRIGGER notification_request_complete AFTER INSERT ON framework.notification_requests
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION framework.require_notification_jobs();

GRANT SELECT,INSERT ON framework.notification_requests TO go_web_app;
GRANT SELECT,INSERT,UPDATE ON framework.notification_connectors,framework.notification_jobs,framework.notification_attempts,framework.notification_suppressions TO go_web_app;
COMMIT;
