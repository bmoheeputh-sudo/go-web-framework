-- Storage and manual administration only. No user, approval or policy backfill.
BEGIN;

-- Deliberately conservative ASCII dot-atom mailboxes. Preserve local-part case
-- and aliases; only the DNS domain is canonicalized.
CREATE FUNCTION framework.invitation_email_key(email TEXT) RETURNS TEXT
LANGUAGE sql IMMUTABLE STRICT SET search_path = pg_catalog AS $$
 SELECT CASE WHEN octet_length(email) <= 254
   AND length(split_part(email,'@',1)) BETWEEN 1 AND 64
   AND email COLLATE "C" ~ '^[A-Za-z0-9!#$%&''*+/=?^_`{|}~-]+(\.[A-Za-z0-9!#$%&''*+/=?^_`{|}~-]+)*@[A-Za-z0-9.-]+$'
   AND framework.valid_access_domains(ARRAY[lower(split_part(email,'@',2))])
 THEN split_part(email,'@',1)||'@'||lower(split_part(email,'@',2)) END
$$;

CREATE TABLE framework.oidc_invitations (
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
 deployment_id TEXT NOT NULL,
 environment TEXT NOT NULL,
 issuer TEXT COLLATE "C" NOT NULL,
 revision_id UUID NOT NULL,
 revision_generation BIGINT NOT NULL CHECK (revision_generation > 0),
 activation_generation BIGINT NOT NULL CHECK (activation_generation > 0),
 client_id TEXT COLLATE "C" NOT NULL,
 email TEXT NOT NULL,
 email_key TEXT COLLATE "C" NOT NULL CHECK (framework.invitation_email_key(email) IS NOT NULL AND email_key=framework.invitation_email_key(email)),
 display_name TEXT NOT NULL DEFAULT '' CHECK (length(display_name)<=200 AND display_name !~ '[[:cntrl:]]'),
 expires_at TIMESTAMPTZ NOT NULL,
 status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','claimed','revoked','expired')),
 generation BIGINT NOT NULL DEFAULT 1 CHECK (generation > 0),
 created_by UUID NOT NULL REFERENCES framework.users(id),
 created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
 updated_by UUID NOT NULL REFERENCES framework.users(id),
 updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
 reason TEXT NOT NULL CHECK (length(btrim(reason)) BETWEEN 8 AND 512 AND reason !~ '[[:cntrl:]]'),
 source TEXT NOT NULL DEFAULT 'manual' CHECK (source IN ('manual','csv')),
 import_id UUID,
 claimed_user_id UUID REFERENCES framework.users(id),
 claimed_issuer TEXT COLLATE "C",
 claimed_subject TEXT COLLATE "C",
 claimed_at TIMESTAMPTZ,
 CHECK (source='csv' OR import_id IS NULL),
 CHECK (expires_at>created_at AND expires_at<=created_at+interval '720 hours'),
 CHECK ((status='claimed' AND claimed_user_id IS NOT NULL AND claimed_issuer IS NOT NULL
   AND claimed_issuer=issuer AND claimed_subject IS NOT NULL AND length(claimed_subject)>0
   AND claimed_at IS NOT NULL AND claimed_at>=created_at AND claimed_at<expires_at)
  OR (status<>'claimed' AND claimed_user_id IS NULL AND claimed_issuer IS NULL AND claimed_subject IS NULL AND claimed_at IS NULL)),
 FOREIGN KEY (deployment_id,environment) REFERENCES framework.oidc_access_policies(deployment_id,environment),
 FOREIGN KEY (deployment_id,environment,revision_id,issuer,client_id)
   REFERENCES framework.auth_config_revisions(deployment_id,environment,id,issuer_url,client_id),
 FOREIGN KEY (deployment_id,environment,activation_generation,revision_id)
   REFERENCES framework.auth_activation_history(deployment_id,environment,generation,target_revision_id)
);

-- Reject ambiguous local-part case variants without equating them during login.
-- Expired-but-stored-pending rows are retired explicitly under the shared lock
-- before a replacement insert. No time-dependent partial index or worker.
CREATE UNIQUE INDEX oidc_invitation_pending_email ON framework.oidc_invitations
 (deployment_id,environment,revision_id,lower(email_key COLLATE "C")) WHERE status='pending';
CREATE INDEX oidc_invitation_listing ON framework.oidc_invitations(deployment_id,environment,created_at DESC,id);
CREATE INDEX oidc_invitation_claim_user ON framework.oidc_invitations(claimed_user_id) WHERE claimed_user_id IS NOT NULL;

CREATE FUNCTION framework.guard_oidc_invitation() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog AS $$
BEGIN
 IF TG_OP IN ('DELETE','TRUNCATE') THEN
   RAISE EXCEPTION 'invitation history must be retained' USING ERRCODE='23514';
 ELSIF TG_OP='INSERT' THEN
   IF NEW.status<>'pending' OR NEW.generation<>1 OR NEW.created_by<>NEW.updated_by THEN
     RAISE EXCEPTION 'invalid initial invitation' USING ERRCODE='23514';
   END IF;
   NEW.created_at:=clock_timestamp();
   IF NEW.expires_at<=NEW.created_at OR NEW.expires_at>NEW.created_at+interval '720 hours' THEN
     RAISE EXCEPTION 'invalid invitation expiry' USING ERRCODE='23514';
   END IF;
 ELSE
   IF OLD.status<>'pending' OR NEW.status NOT IN ('claimed','revoked','expired') OR NEW.generation<>OLD.generation+1
     OR ROW(NEW.id,NEW.deployment_id,NEW.environment,NEW.issuer,NEW.revision_id,NEW.revision_generation,
       NEW.activation_generation,NEW.client_id,NEW.email,NEW.email_key,NEW.display_name,NEW.expires_at,
       NEW.created_by,NEW.created_at,NEW.source,NEW.import_id)
       IS DISTINCT FROM ROW(OLD.id,OLD.deployment_id,OLD.environment,OLD.issuer,OLD.revision_id,OLD.revision_generation,
       OLD.activation_generation,OLD.client_id,OLD.email,OLD.email_key,OLD.display_name,OLD.expires_at,
       OLD.created_by,OLD.created_at,OLD.source,OLD.import_id) THEN
     RAISE EXCEPTION 'invitation provenance and terminal history are immutable' USING ERRCODE='23514';
   END IF;
   IF (NEW.status='expired' AND OLD.expires_at>clock_timestamp()) OR
      (NEW.status='claimed' AND (OLD.expires_at<=clock_timestamp() OR NOT EXISTS (
        SELECT 1 FROM framework.users u WHERE u.id=NEW.claimed_user_id AND u.active AND u.provider='oidc'
          AND u.issuer=NEW.claimed_issuer AND u.subject=NEW.claimed_subject))) THEN
     RAISE EXCEPTION 'invalid invitation transition' USING ERRCODE='23514';
   END IF;
   IF NEW.status='claimed' THEN NEW.claimed_at:=clock_timestamp(); END IF;
 END IF;
 NEW.updated_at:=clock_timestamp();
 RETURN NEW;
END $$;
CREATE TRIGGER oidc_invitation_record BEFORE INSERT OR UPDATE OR DELETE ON framework.oidc_invitations
 FOR EACH ROW EXECUTE FUNCTION framework.guard_oidc_invitation();
CREATE TRIGGER oidc_invitation_retain BEFORE TRUNCATE ON framework.oidc_invitations
 FOR EACH STATEMENT EXECUTE FUNCTION framework.guard_oidc_invitation();

GRANT SELECT,INSERT,UPDATE ON framework.oidc_invitations TO go_web_app;
REVOKE ALL ON FUNCTION framework.invitation_email_key(TEXT) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION framework.invitation_email_key(TEXT) TO go_web_app;
REVOKE ALL ON FUNCTION framework.guard_oidc_invitation() FROM PUBLIC;
COMMIT;
