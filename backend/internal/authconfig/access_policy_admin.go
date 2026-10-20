package authconfig

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/bmoheeputh-sudo/go-web-framework/backend/internal/access"
	"github.com/jackc/pgx/v5"
)

// Access-policy administration is deployment-bound and independent of encryption
// keys. Reads use the existing administrator transaction for consistent results.
type AccessOverview struct {
	Approved        int64 `json:"approved"`
	Revoked         int64 `json:"revoked"`
	ActiveOIDCUsers int64 `json:"active_oidc_users"`
}
type AccessPolicySnapshot struct {
	Policy               AccessPolicy   `json:"policy"`
	ActivationGeneration int64          `json:"activation_generation"`
	ActiveIssuer         string         `json:"active_issuer"`
	Overview             AccessOverview `json:"overview"`
}

func (r *AccessPolicyRepository) snapshot(ctx context.Context, tx pgx.Tx) (AccessPolicySnapshot, error) {
	var s AccessPolicySnapshot
	var err error
	s.Policy, err = r.read(ctx, tx)
	if err != nil {
		return s, err
	}
	err = tx.QueryRow(ctx, `SELECT COALESCE((SELECT h.generation FROM framework.auth_activation_heads h WHERE h.deployment_id=$1 AND h.environment=$2),0),
 COALESCE((SELECT r.issuer_url FROM framework.auth_activation_heads h JOIN framework.auth_config_revisions r ON r.id=h.active_revision_id WHERE h.deployment_id=$1 AND h.environment=$2 AND h.runtime_source='database' AND r.provider='oidc'),'')`, r.scope.DeploymentID, r.scope.Environment).Scan(&s.ActivationGeneration, &s.ActiveIssuer)
	if err != nil {
		return s, err
	}
	err = tx.QueryRow(ctx, `SELECT count(*) FILTER(WHERE status='approved'),count(*) FILTER(WHERE status='revoked'),
 (SELECT count(*) FROM framework.users WHERE provider='oidc' AND active)
 FROM framework.oidc_identity_approvals WHERE deployment_id=$1 AND environment=$2`, r.scope.DeploymentID, r.scope.Environment).Scan(&s.Overview.Approved, &s.Overview.Revoked, &s.Overview.ActiveOIDCUsers)
	return s, err
}
func (r *AccessPolicyRepository) Snapshot(ctx context.Context) (AccessPolicySnapshot, error) {
	var s AccessPolicySnapshot
	err := adminTransaction(ctx, r.store, func(ctx context.Context, tx pgx.Tx, _ access.User) error {
		var err error
		s, err = r.snapshot(ctx, tx)
		return err
	})
	return s, err
}

type AccessIdentity struct {
	UserID             string    `json:"user_id"`
	Issuer             string    `json:"issuer"`
	Subject            string    `json:"subject"`
	Email              string    `json:"email"`
	DisplayName        string    `json:"display_name"`
	UserActive         bool      `json:"user_active"`
	Roles              []string  `json:"roles"`
	ApprovalStatus     string    `json:"approval_status"`
	ApprovalGeneration int64     `json:"approval_generation"`
	UpdatedAt          time.Time `json:"updated_at"`
	ProviderCurrent    bool      `json:"provider_current"`
}
type AccessIdentities struct {
	Items                []AccessIdentity `json:"items"`
	Total                int64            `json:"total"`
	Offset               int              `json:"offset"`
	Limit                int              `json:"limit"`
	PolicyGeneration     int64            `json:"policy_generation"`
	ActivationGeneration int64            `json:"activation_generation"`
}

const accessIdentityCTE = `WITH identities AS (
 SELECT issuer,subject FROM framework.users WHERE provider='oidc'
 UNION SELECT issuer,subject FROM framework.oidc_identity_approvals WHERE deployment_id=$1 AND environment=$2
 ), candidates AS (
 SELECT COALESCE(u.id::text,'') AS user_id,i.issuer,i.subject,
 CASE WHEN u.email_verified THEN u.email ELSE '' END AS email,COALESCE(u.display_name,'') AS display_name,
 COALESCE(u.active,false) AS user_active,
 ARRAY(SELECT role FROM framework.user_roles WHERE user_id=u.id ORDER BY role) AS roles,
 COALESCE(a.status,'not_approved') AS approval_status,COALESCE(a.generation,0) AS approval_generation,
 COALESCE(a.updated_at,u.created_at) AS updated_at
 FROM identities i LEFT JOIN framework.users u ON u.issuer=i.issuer COLLATE "C" AND u.subject=i.subject COLLATE "C" AND u.provider='oidc'
 LEFT JOIN framework.oidc_identity_approvals a ON a.issuer=i.issuer COLLATE "C" AND a.subject=i.subject COLLATE "C" AND a.deployment_id=$1 AND a.environment=$2
 ) `

func scanAccessIdentity(row pgx.Row) (AccessIdentity, error) {
	var a AccessIdentity
	err := row.Scan(&a.UserID, &a.Issuer, &a.Subject, &a.Email, &a.DisplayName, &a.UserActive, &a.Roles, &a.ApprovalStatus, &a.ApprovalGeneration, &a.UpdatedAt)
	return a, err
}
func (r *AccessPolicyRepository) Identities(ctx context.Context, search, status string, offset, limit int) (AccessIdentities, error) {
	result := AccessIdentities{Items: []AccessIdentity{}, Offset: offset, Limit: limit}
	if len(search) > 200 || strings.ContainsAny(search, "\x00\r\n") || offset < 0 || offset > 100000 || limit < 1 || limit > 100 || (status != "" && status != "approved" && status != "revoked" && status != "not_approved") {
		return result, ErrInvalid
	}
	err := adminTransaction(ctx, r.store, func(ctx context.Context, tx pgx.Tx, _ access.User) error {
		s, err := r.snapshot(ctx, tx)
		if err != nil {
			return err
		}
		result.PolicyGeneration, result.ActivationGeneration = s.Policy.Generation, s.ActivationGeneration
		where := ` WHERE strpos(lower(issuer||' '||subject||' '||email||' '||display_name),lower($3))>0 AND ($4='' OR approval_status=$4)`
		if err := tx.QueryRow(ctx, accessIdentityCTE+`SELECT count(*) FROM candidates`+where, r.scope.DeploymentID, r.scope.Environment, search, status).Scan(&result.Total); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, accessIdentityCTE+`SELECT * FROM candidates`+where+` ORDER BY issuer COLLATE "C",subject COLLATE "C" LIMIT $5 OFFSET $6`, r.scope.DeploymentID, r.scope.Environment, search, status, limit, offset)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			a, err := scanAccessIdentity(rows)
			if err != nil {
				return err
			}
			a.ProviderCurrent = a.Issuer == s.ActiveIssuer && s.ActiveIssuer != ""
			result.Items = append(result.Items, a)
		}
		return rows.Err()
	})
	return result, err
}
func (r *AccessPolicyRepository) Identity(ctx context.Context, userID string) (AccessIdentity, error) {
	if !validID(userID) {
		return AccessIdentity{}, ErrInvalid
	}
	var a AccessIdentity
	err := adminTransaction(ctx, r.store, func(ctx context.Context, tx pgx.Tx, _ access.User) error {
		s, err := r.snapshot(ctx, tx)
		if err != nil {
			return err
		}
		a, err = scanAccessIdentity(tx.QueryRow(ctx, accessIdentityCTE+`SELECT * FROM candidates WHERE user_id=$3`, r.scope.DeploymentID, r.scope.Environment, userID))
		a.ProviderCurrent = a.Issuer == s.ActiveIssuer && s.ActiveIssuer != ""
		return err
	})
	return a, err
}

type PolicyPreview struct {
	PolicyGeneration                int64 `json:"policy_generation"`
	ActivationGeneration            int64 `json:"activation_generation"`
	AffectedUsers                   int   `json:"affected_users"`
	EligibleUsers                   int   `json:"eligible_users"`
	EligibleAdministrators          int   `json:"eligible_administrators"`
	CurrentAdministratorLosesAccess bool  `json:"current_administrator_loses_access"`
	CanApply                        bool  `json:"can_apply"`
}

func policyEligible(p AccessPolicySettings, active, verified bool, email, status string) bool {
	return active && status != "revoked" && (p.Mode == "allow_all" || status == "approved") && access.EmailDomainAllowed(p.AllowedEmailDomains, email, verified)
}
func (r *AccessPolicyRepository) preview(ctx context.Context, tx pgx.Tx, actor access.User, expected PolicyExpectation, settings AccessPolicySettings) (PolicyPreview, error) {
	result := PolicyPreview{PolicyGeneration: expected.Generation, ActivationGeneration: expected.ActivationGeneration}
	issuer, err := r.activeIssuer(ctx, tx, expected.ActivationGeneration)
	if err != nil {
		return result, err
	}
	before, err := r.read(ctx, tx)
	if err != nil {
		return result, err
	}
	if before.Generation != expected.Generation {
		return result, ErrConflict
	}
	if err = policyRoleAllowed(ctx, tx, settings.DefaultRole); err != nil {
		return result, err
	}
	rows, err := tx.Query(ctx, `SELECT u.id::text,u.active,u.email,u.email_verified,COALESCE(a.status,''),
 EXISTS(SELECT 1 FROM framework.user_roles ur JOIN framework.role_permissions rp ON rp.role=ur.role WHERE ur.user_id=u.id AND rp.permission='admin.manage')
 FROM framework.users u LEFT JOIN framework.oidc_identity_approvals a ON a.issuer=u.issuer COLLATE "C" AND a.subject=u.subject COLLATE "C" AND a.deployment_id=$1 AND a.environment=$2
 WHERE u.provider='oidc' AND u.issuer=$3 COLLATE "C"`, r.scope.DeploymentID, r.scope.Environment, issuer)
	if err != nil {
		return result, err
	}
	defer rows.Close()
	for rows.Next() {
		var id, email, status string
		var active, verified, admin bool
		if err := rows.Scan(&id, &active, &email, &verified, &status, &admin); err != nil {
			return result, err
		}
		eligible := policyEligible(settings, active, verified, email, status)
		if eligible {
			result.EligibleUsers++
			if admin && status == "approved" {
				result.EligibleAdministrators++
			}
		}
		if policyEligible(before.AccessPolicySettings, active, verified, email, status) && !eligible {
			result.AffectedUsers++
		}
		if id == actor.ID && !eligible {
			result.CurrentAdministratorLosesAccess = true
		}
	}
	if err := rows.Err(); err != nil {
		return result, err
	}
	result.CanApply = result.EligibleAdministrators > 0
	return result, nil
}
func (r *AccessPolicyRepository) Preview(ctx context.Context, expected PolicyExpectation, settings AccessPolicySettings) (PolicyPreview, error) {
	settings, err := normalizePolicy(settings)
	if err != nil || expected.Generation < 1 {
		return PolicyPreview{}, ErrInvalid
	}
	var result PolicyPreview
	err = adminTransaction(ctx, r.store, func(ctx context.Context, tx pgx.Tx, actor access.User) error {
		var err error
		result, err = r.preview(ctx, tx, actor, expected, settings)
		return err
	})
	return result, err
}

var ErrSelfAccessLoss = errors.New("access_policy_self_access_loss_confirmation_required")

func (r *AccessPolicyRepository) UpdateReviewed(ctx context.Context, expected PolicyExpectation, settings AccessPolicySettings, reason string, confirmLoss bool) (AccessPolicy, error) {
	return r.update(ctx, expected, settings, reason, &confirmLoss)
}

// User ID is a selector, never proof of identity. Resolution occurs under the
// same advisory lock and authorization transaction as the approval mutation.
func (r *AccessPolicyRepository) SetUserApproval(ctx context.Context, expected PolicyExpectation, userID string, generation int64, status, reason string) (OIDCIdentityApproval, error) {
	if !validID(userID) {
		return OIDCIdentityApproval{}, ErrInvalid
	}
	return r.setApproval(ctx, expected, func(ctx context.Context, tx pgx.Tx) (OIDCIdentityKey, error) {
		var key OIDCIdentityKey
		err := tx.QueryRow(ctx, `SELECT issuer,subject FROM framework.users WHERE id=$1 AND provider='oidc'`, userID).Scan(&key.Issuer, &key.Subject)
		return key, err
	}, generation, status, reason, true)
}
