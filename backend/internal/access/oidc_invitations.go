package access

import (
	"context"
	"errors"

	"github.com/bmoheeputh-sudo/go-web-framework/backend/internal/auth"
	"github.com/jackc/pgx/v5"
)

type loginInvitation struct {
	id, creator, revision            string
	generation, activationGeneration int64
}

// An invitation is optional evidence of preauthorization, never an identity.
// The binding originates in the prepared authenticator, not the request or a
// guessed current revision. Draining/environment/verification flows cannot claim.
func (p *OIDCAdmission) loginInvitation(ctx context.Context, tx pgx.Tx, identity auth.Identity, b auth.Binding) (*loginInvitation, error) {
	if !identity.EmailVerified || !b.MatchesDatabase(b) || b.DeploymentID != p.deployment || b.Environment != p.environment || b.Issuer != identity.Issuer {
		return nil, nil
	}
	var key *string
	// Reuse migration 000009's conservative canonicalization, also used and parity
	// tested by invitation administration. A nonmatching syntax is not an approval.
	if err := tx.QueryRow(ctx, `SELECT framework.invitation_email_key($1)`, identity.Email).Scan(&key); err != nil {
		return nil, ErrUnavailable
	}
	if key == nil {
		return nil, nil
	}
	rows, err := tx.Query(ctx, `SELECT i.id::text,i.generation,i.created_by::text,i.email_key
 FROM framework.oidc_invitations i
 JOIN framework.auth_activation_heads h ON h.deployment_id=i.deployment_id AND h.environment=i.environment
   AND h.active_revision_id=i.revision_id AND h.generation=i.activation_generation AND h.runtime_source='database'
 JOIN framework.auth_config_revisions r ON r.id=i.revision_id AND r.issuer_url=i.issuer AND r.client_id=i.client_id AND r.provider='oidc'
 JOIN framework.auth_config_lifecycle l ON l.revision_id=i.revision_id AND l.status='active' AND l.generation=i.revision_generation
 WHERE i.deployment_id=$1 AND i.environment=$2 AND i.issuer=$3 COLLATE "C" AND i.revision_id=$4
   AND i.activation_generation=$5 AND i.client_id=$6 COLLATE "C"
   AND i.status='pending' AND i.expires_at>clock_timestamp() AND h.activated_at<=clock_timestamp()
   AND lower(i.email_key COLLATE "C")=lower($7 COLLATE "C")`, p.deployment, p.environment, b.Issuer, b.RevisionID, b.ActivationGeneration, b.ClientID, *key)
	if err != nil {
		return nil, ErrUnavailable
	}
	var candidate *loginInvitation
	count := 0
	for rows.Next() {
		var i loginInvitation
		var invitationKey string
		if err := rows.Scan(&i.id, &i.generation, &i.creator, &invitationKey); err != nil {
			rows.Close()
			return nil, ErrUnavailable
		}
		count++
		if invitationKey == *key {
			i.revision = b.RevisionID
			i.activationGeneration = b.ActivationGeneration
			candidate = &i
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, ErrUnavailable
	}
	if count != 1 || candidate == nil {
		return nil, nil
	}
	// Mailbox equality never merges users. A conflicting historical claim or
	// existing different subject requires identity-specific administrator review.
	// In Allow All this blocks the claim, not independent policy-authorized login.
	var collision bool
	err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM framework.users u
 WHERE u.provider='oidc' AND u.issuer=$3 COLLATE "C" AND u.subject<>$4 COLLATE "C"
   AND lower(framework.invitation_email_key(u.email) COLLATE "C")=lower($5 COLLATE "C"))
 OR EXISTS(SELECT 1 FROM framework.oidc_invitations i WHERE i.deployment_id=$1 AND i.environment=$2
   AND i.issuer=$3 COLLATE "C" AND i.status='claimed' AND i.claimed_subject<>$4 COLLATE "C"
   AND lower(i.email_key COLLATE "C")=lower($5 COLLATE "C"))`, p.deployment, p.environment, identity.Issuer, identity.Subject, *key).Scan(&collision)
	if err != nil {
		return nil, ErrUnavailable
	}
	if collision {
		return nil, nil
	}
	return candidate, nil
}

func (p *OIDCAdmission) claimInvitation(ctx context.Context, tx pgx.Tx, identity auth.Identity, userID string, i loginInvitation, createApproval bool) error {
	var generation int64
	err := tx.QueryRow(ctx, `UPDATE framework.oidc_invitations
 SET status='claimed',generation=generation+1,updated_by=$4,reason='Claimed by verified OIDC login',
   claimed_user_id=$4,claimed_issuer=$5,claimed_subject=$6,claimed_at=clock_timestamp()
 WHERE deployment_id=$1 AND environment=$2 AND id=$3 AND generation=$7 AND status='pending' AND expires_at>clock_timestamp()
 RETURNING generation`, p.deployment, p.environment, i.id, userID, identity.Issuer, identity.Subject, i.generation).Scan(&generation)
	if errors.Is(err, pgx.ErrNoRows) {
		return auth.ErrUnauthenticated
	}
	if err != nil {
		return ErrUnavailable
	}
	if createApproval {
		// The original administrator authorized onboarding; the verified claimant is
		// the audit actor. This is not an administrator impersonation or a role grant.
		_, err = tx.Exec(ctx, `INSERT INTO framework.oidc_identity_approvals
   (deployment_id,environment,issuer,subject,status,source,invitation_id,created_by,updated_by,reason)
   VALUES($1,$2,$3,$4,'approved','invitation',$5,$6,$6,'Approved through verified invitation claim')`, p.deployment, p.environment, identity.Issuer, identity.Subject, i.id, i.creator)
		if err != nil {
			return ErrUnavailable
		}
	}
	details := struct {
		DeploymentID         string `json:"deployment_id"`
		Environment          string `json:"environment"`
		RevisionID           string `json:"revision_id"`
		ActivationGeneration int64  `json:"activation_generation"`
		InvitationGeneration int64  `json:"invitation_generation"`
		AuthorizedBy         string `json:"authorized_by"`
		ApprovalCreated      bool   `json:"approval_created"`
	}{p.deployment, p.environment, i.revision, i.activationGeneration, generation, i.creator, createApproval}
	return audit(ctx, tx, userID, "oidc_access.invitation_claimed", i.id, details)
}
