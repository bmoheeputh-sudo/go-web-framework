-- Provenance only: no user, role, approval or invitation backfill.
BEGIN;

ALTER TABLE framework.oidc_invitations ADD CONSTRAINT oidc_invitation_claim_identity
 UNIQUE (deployment_id,environment,id,claimed_issuer,claimed_subject);

ALTER TABLE framework.oidc_identity_approvals
 DROP CONSTRAINT oidc_identity_approvals_source_check,
 ADD CONSTRAINT oidc_identity_approvals_source_check CHECK (source IN ('bootstrap','administrator','invitation')),
 ADD COLUMN invitation_id UUID,
 ADD CONSTRAINT oidc_approval_invitation_source CHECK ((source='invitation')=(invitation_id IS NOT NULL)),
 ADD CONSTRAINT oidc_approval_invitation_identity FOREIGN KEY (deployment_id,environment,invitation_id,issuer,subject)
 REFERENCES framework.oidc_invitations(deployment_id,environment,id,claimed_issuer,claimed_subject);

-- Claim first, then insert the approval in the same transaction. The identity
-- FK cannot point at a pending invitation or a different issuer/subject/scope.
CREATE FUNCTION framework.guard_invitation_approval() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
 IF TG_OP='UPDATE' THEN
   IF NEW.invitation_id IS DISTINCT FROM OLD.invitation_id THEN
     RAISE EXCEPTION 'invitation approval provenance is immutable' USING ERRCODE='23514';
   END IF;
 ELSIF NEW.source='invitation' THEN
   IF NEW.status<>'approved' OR NOT EXISTS (
     SELECT 1 FROM framework.oidc_invitations i WHERE i.id=NEW.invitation_id AND i.status='claimed'
       AND i.created_by=NEW.created_by AND i.created_by=NEW.updated_by
       AND i.deployment_id=NEW.deployment_id AND i.environment=NEW.environment
       AND i.claimed_issuer=NEW.issuer AND i.claimed_subject=NEW.subject
   ) THEN
     RAISE EXCEPTION 'invalid invitation approval provenance' USING ERRCODE='23514';
   END IF;
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER identity_approval_invitation BEFORE INSERT OR UPDATE ON framework.oidc_identity_approvals
 FOR EACH ROW EXECUTE FUNCTION framework.guard_invitation_approval();
REVOKE ALL ON FUNCTION framework.guard_invitation_approval() FROM PUBLIC;
COMMIT;
