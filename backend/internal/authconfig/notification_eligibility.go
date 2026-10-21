package authconfig

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/bmoheeputh-sudo/go-web-framework/backend/internal/access"
	"github.com/jackc/pgx/v5"
)

// Revalidate the real initiating administrator using current persisted OIDC
// eligibility, independently of the permission observed when a job was queued.
func (r *NotificationRepository) administratorEligible(ctx context.Context, tx pgx.Tx, id string, b invitationBinding) (bool, error) {
	var email, approval string
	var active, verified, permission bool
	err := tx.QueryRow(ctx, `SELECT u.email,u.email_verified,u.active,
 EXISTS(SELECT 1 FROM framework.user_roles ur JOIN framework.role_permissions rp ON rp.role=ur.role WHERE ur.user_id=u.id AND rp.permission='admin.manage'),
 COALESCE((SELECT a.status FROM framework.oidc_identity_approvals a WHERE a.deployment_id=$2 AND a.environment=$3 AND a.issuer=u.issuer COLLATE "C" AND a.subject=u.subject COLLATE "C"),'')
 FROM framework.users u WHERE u.id=$1 AND u.provider='oidc' AND u.issuer=$4 COLLATE "C"`, id, r.policy.scope.DeploymentID, r.policy.scope.Environment, b.issuer).Scan(&email, &verified, &active, &permission, &approval)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return active && permission && approval != "revoked" && (b.policy.Mode == "allow_all" || approval == "approved") && policyEmailAllowed(b.policy.AllowedEmailDomains, email, verified), nil
}

// eligible never binds an identity by mailbox equality. A mailbox collision is
// review-only. Existing claim bindings and exact user IDs provide positive proof.
func (r *NotificationRepository) eligible(ctx context.Context, tx pgx.Tx, b invitationBinding, j *NotificationJob, snapshot bool) (string, error) {
	var email, key, name, provenance string
	if j.InvitationID != "" {
		i, err := r.policy.readInvitation(ctx, tx, j.InvitationID, b)
		if errors.Is(err, pgx.ErrNoRows) {
			return "invitation_unavailable", nil
		}
		if err != nil {
			return "", err
		}
		if !i.BindingCurrent {
			return "stale_configuration", nil
		}
		if i.Status == "claimed" {
			return "onboarded", nil
		}
		var now time.Time
		if err = tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
			return "", err
		}
		if i.Status != "pending" || !i.ExpiresAt.After(now) {
			return "invitation_unavailable", nil
		}
		var collision bool
		if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM framework.users WHERE lower(framework.invitation_email_key(email) COLLATE "C")=lower($1 COLLATE "C"))`, i.EmailKey).Scan(&collision); err != nil {
			return "", err
		}
		if collision {
			return "review_required", nil
		}
		email, key, name, provenance = i.Email, i.EmailKey, i.DisplayName, "administrator_invitation"
	} else {
		var issuer, subject, approval string
		var active, verified, onboarded bool
		err := tx.QueryRow(ctx, `SELECT u.issuer,u.subject,u.email,u.email_verified,u.display_name,u.active,
 COALESCE((SELECT status FROM framework.oidc_identity_approvals a WHERE a.deployment_id=$2 AND a.environment=$3 AND a.issuer=u.issuer COLLATE "C" AND a.subject=u.subject COLLATE "C"),''),
 u.first_successful_oidc_login_at IS NOT NULL OR EXISTS(SELECT 1 FROM framework.oidc_invitations i WHERE i.deployment_id=$2 AND i.environment=$3 AND i.claimed_user_id=u.id AND i.status='claimed')
 FROM framework.users u WHERE u.id=$1 AND u.provider='oidc'`, j.UserID, r.policy.scope.DeploymentID, r.policy.scope.Environment).Scan(&issuer, &subject, &email, &verified, &name, &active, &approval, &onboarded)
		if errors.Is(err, pgx.ErrNoRows) {
			return "inactive_user", nil
		}
		if err != nil {
			return "", err
		}
		if !active {
			return "inactive_user", nil
		}
		if issuer != b.issuer {
			return "stale_configuration", nil
		}
		if approval == "revoked" {
			return "revoked_identity", nil
		}
		if !verified || (b.policy.Mode == "approved_users_only" && approval != "approved") {
			return "review_required", nil
		}
		if onboarded {
			return "onboarded", nil
		}
		key, err = invitationEmailKey(email)
		if err != nil {
			return "recipient_changed", nil
		}
		provenance = "verified_oidc_user"
	}
	if !policyEmailAllowed(b.policy.AllowedEmailDomains, key, true) || !policyEmailAllowed(r.communication.AllowedDomains, key, true) {
		return "domain_blocked", nil
	}
	if snapshot && (j.Recipient != email || j.RecipientKey != key || j.Provenance != provenance) {
		return "recipient_changed", nil
	}
	if !snapshot {
		j.Recipient, j.RecipientKey, j.DisplayName, j.Provenance = email, key, name, provenance
	}
	blocked, err := r.suppressed(ctx, tx, j.NotificationTarget, key)
	if err != nil {
		return "", err
	}
	if blocked {
		return "suppressed", nil
	}
	var recent bool
	err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM framework.notification_jobs j WHERE j.deployment_id=$1 AND j.environment=$2
 AND lower(j.recipient_key COLLATE "C")=lower($3 COLLATE "C") AND j.id IS DISTINCT FROM NULLIF($4,'')::uuid
 AND (j.status IN ('queued','leased','dispatching','needs_inspection') OR EXISTS(SELECT 1 FROM framework.notification_attempts a WHERE a.job_id=j.id AND a.outcome='accepted' AND a.completed_at>clock_timestamp()-($5::double precision*interval '1 second'))))`, r.policy.scope.DeploymentID, r.policy.scope.Environment, key, j.ID, r.communication.Cooldown.Seconds()).Scan(&recent)
	if err != nil {
		return "", err
	}
	if recent {
		return "review_required", nil
	}
	return "", nil
}

func (r *NotificationRepository) Eligibility(ctx context.Context, target NotificationTarget, kind string) (string, error) {
	if !target.valid() || (kind != "invitation" && kind != "reminder") {
		return "", ErrInvalid
	}
	var code string
	err := r.admin(ctx, func(ctx context.Context, tx pgx.Tx, _ access.User) error {
		b, err := r.policy.invitationContext(ctx, tx, nil)
		if err != nil {
			return err
		}
		j := NotificationJob{NotificationTarget: target, Type: kind}
		code, err = r.eligible(ctx, tx, b, &j, false)
		return err
	})
	return code, err
}

type SuppressionTarget struct {
	NotificationTarget
	Email string
}

func (t SuppressionTarget) key() (string, error) {
	if t.Email != "" {
		if t.InvitationID != "" || t.UserID != "" {
			return "", ErrInvalid
		}
		k, err := invitationEmailKey(t.Email)
		if err != nil || k != t.Email {
			return "", ErrInvalid
		}
		return "email:" + k, nil
	}
	if !t.NotificationTarget.valid() {
		return "", ErrInvalid
	}
	return t.NotificationTarget.key(), nil
}

type NotificationSuppression struct {
	Target            SuppressionTarget
	Active            bool
	Generation        int64
	Reason, UpdatedBy string
}

func (r *NotificationRepository) suppressed(ctx context.Context, tx pgx.Tx, target NotificationTarget, key string) (bool, error) {
	var blocked bool
	err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM framework.notification_suppressions WHERE deployment_id=$1 AND environment=$2 AND active
 AND (recipient_key=$3 COLLATE "C" OR invitation_id=NULLIF($4,'')::uuid OR user_id=NULLIF($5,'')::uuid))`, r.policy.scope.DeploymentID, r.policy.scope.Environment, key, target.InvitationID, target.UserID).Scan(&blocked)
	return blocked, err
}
func (r *NotificationRepository) SetSuppression(ctx context.Context, target SuppressionTarget, expected int64, active bool, reason string) (NotificationSuppression, error) {
	key, err := target.key()
	if err != nil || expected < 0 || !validPolicyReason(reason) {
		return NotificationSuppression{}, ErrInvalid
	}
	n := NotificationSuppression{Target: target, Active: active, Reason: reason}
	err = r.admin(ctx, func(ctx context.Context, tx pgx.Tx, actor access.User) error {
		// Scope membership is checked without following a mailbox to an identity.
		if target.InvitationID != "" {
			var ok bool
			if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM framework.oidc_invitations WHERE id=$1 AND deployment_id=$2 AND environment=$3)`, target.InvitationID, r.policy.scope.DeploymentID, r.policy.scope.Environment).Scan(&ok); err != nil {
				return err
			}
			if !ok {
				return ErrNotFound
			}
		}
		if target.UserID != "" {
			b, err := r.policy.invitationContext(ctx, tx, nil)
			if err != nil {
				return err
			}
			var ok bool
			if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM framework.users WHERE id=$1 AND issuer=$2 COLLATE "C" AND provider='oidc')`, target.UserID, b.issuer).Scan(&ok); err != nil {
				return err
			}
			if !ok {
				return ErrNotFound
			}
		}
		if expected == 0 {
			err := tx.QueryRow(ctx, `INSERT INTO framework.notification_suppressions(deployment_id,environment,target_key,recipient_key,invitation_id,user_id,active,created_by,updated_by,reason)
 VALUES($1,$2,$3,NULLIF($4,''),NULLIF($5,'')::uuid,NULLIF($6,'')::uuid,$7,$8,$8,$9) RETURNING generation`, r.policy.scope.DeploymentID, r.policy.scope.Environment, key, target.Email, target.InvitationID, target.UserID, active, actor.ID, reason).Scan(&n.Generation)
			if err != nil {
				return err
			}
		} else {
			err := tx.QueryRow(ctx, `UPDATE framework.notification_suppressions SET active=$4,reason=$5,updated_by=$6,generation=generation+1 WHERE deployment_id=$1 AND environment=$2 AND target_key=$3 AND generation=$7 RETURNING generation`, r.policy.scope.DeploymentID, r.policy.scope.Environment, key, active, reason, actor.ID, expected).Scan(&n.Generation)
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrConflict
			}
			if err != nil {
				return err
			}
		}
		n.UpdatedBy = actor.ID
		// An email suppression key contains PII; audit a digest instead.
		return access.RecordAudit(ctx, tx, actor.ID, "notification.suppression_changed", shaText(key), struct {
			Scope
			Active     bool
			Generation int64
			Reason     string
		}{r.policy.scope, active, n.Generation, reason})
	})
	return n, err
}
func (r *NotificationRepository) ReadSuppression(ctx context.Context, target SuppressionTarget) (NotificationSuppression, error) {
	key, err := target.key()
	if err != nil {
		return NotificationSuppression{}, err
	}
	n := NotificationSuppression{Target: target}
	err = r.admin(ctx, func(ctx context.Context, tx pgx.Tx, _ access.User) error {
		return tx.QueryRow(ctx, `SELECT active,generation,reason,updated_by::text FROM framework.notification_suppressions WHERE deployment_id=$1 AND environment=$2 AND target_key=$3`, r.policy.scope.DeploymentID, r.policy.scope.Environment, key).Scan(&n.Active, &n.Generation, &n.Reason, &n.UpdatedBy)
	})
	return n, err
}

func (r *NotificationRepository) cancel(ctx context.Context, tx pgx.Tx, j NotificationJob, actor, code string) error {
	tag, err := tx.Exec(ctx, `UPDATE framework.notification_jobs SET status='cancelled',disposition_code=$4,lease_owner=NULL,lease_expires_at=NULL,generation=generation+1,updated_by=$5 WHERE deployment_id=$1 AND environment=$2 AND id=$3 AND generation=$6 AND status IN ('queued','leased')`, j.DeploymentID, j.Environment, j.ID, code, actor, j.Generation)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return ErrConflict
	}
	return notificationAudit(ctx, tx, actor, "notification.cancelled", j.ID, r.policy.scope, code)
}
func (r *NotificationRepository) Cancel(ctx context.Context, id string, generation int64, reason string) error {
	if !validID(id) || generation < 1 || !validPolicyReason(reason) {
		return ErrInvalid
	}
	return r.admin(ctx, func(ctx context.Context, tx pgx.Tx, actor access.User) error {
		j, err := r.job(ctx, tx, id)
		if err != nil {
			return err
		}
		if j.Generation != generation {
			return ErrConflict
		}
		if err = r.cancel(ctx, tx, j, actor.ID, "administrator_cancelled"); err != nil {
			return err
		}
		return access.RecordAudit(ctx, tx, actor.ID, "notification.cancellation_reason", id, struct {
			Reason string `json:"reason"`
		}{strings.TrimSpace(reason)})
	})
}
