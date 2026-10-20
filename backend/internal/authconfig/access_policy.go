package authconfig

import (
	"context"
	"errors"
	"net/mail"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode"

	"github.com/bmoheeputh-sudo/go-web-framework/backend/internal/access"
	"github.com/bmoheeputh-sudo/go-web-framework/backend/internal/auth"
	"github.com/jackc/pgx/v5"
)

var ErrLastOIDCAdministrator = errors.New("access_policy_last_oidc_administrator")

type AccessPolicySettings struct {
	Mode                string   `json:"mode"`
	AllowedEmailDomains []string `json:"allowed_email_domains"`
	DefaultRole         string   `json:"default_role"`
}

type PolicyModification struct {
	Generation int64     `json:"generation"`
	CreatedBy  string    `json:"created_by"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedBy  string    `json:"updated_by"`
	UpdatedAt  time.Time `json:"updated_at"`
	Reason     string    `json:"reason"`
}

type AccessPolicy struct {
	Scope
	AccessPolicySettings
	PolicyModification
}

type OIDCIdentityKey struct {
	Issuer  string `json:"issuer"`
	Subject string `json:"subject"`
}

type OIDCIdentityApproval struct {
	Scope
	OIDCIdentityKey
	Status string `json:"status"`
	Source string `json:"source"`
	PolicyModification
}

// Both expectations come from trusted reads. Provider changes invalidate pending
// policy writes even if the policy itself has not changed.
type PolicyExpectation struct {
	Generation           int64
	ActivationGeneration int64
}

// AccessPolicyRepository is an internal, administrator-authorized storage
// capability. It is deliberately NOT used by authentication or session issuance.
// Scope is supplied by trusted server configuration, never request JSON.
type AccessPolicyRepository struct {
	store *access.Store
	scope Scope
}

func NewAccessPolicyRepository(store *access.Store, scope Scope) (*AccessPolicyRepository, error) {
	if store == nil || !scope.valid() {
		return nil, ErrInvalid
	}
	return &AccessPolicyRepository{store, scope}, nil
}

var accessDomain = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]([a-z0-9-]{0,61}[a-z0-9])?$`)

func normalizePolicy(settings AccessPolicySettings) (AccessPolicySettings, error) {
	if (settings.Mode != "allow_all" && settings.Mode != "approved_users_only") ||
		(settings.DefaultRole != "Viewer" && settings.DefaultRole != "User") || len(settings.AllowedEmailDomains) > 20 {
		return AccessPolicySettings{}, ErrInvalid
	}
	domains := make([]string, 0, len(settings.AllowedEmailDomains))
	for _, d := range settings.AllowedEmailDomains {
		// ASCII DNS names only; IDNs must be entered as A-labels. Do not trim,
		// accept URLs, wildcard suffixes, mailboxes or silently discard entries.
		if strings.ContainsFunc(d, func(r rune) bool { return r > 127 }) {
			return AccessPolicySettings{}, ErrInvalid
		}
		d = strings.ToLower(d)
		if len(d) > 253 || !accessDomain.MatchString(d) || slices.Contains(domains, d) {
			return AccessPolicySettings{}, ErrInvalid
		}
		domains = append(domains, d)
	}
	slices.Sort(domains)
	settings.AllowedEmailDomains = domains
	return settings, nil
}

func validPolicyReason(reason string) bool {
	return len(strings.TrimSpace(reason)) >= 8 && len(reason) <= 512 && !strings.ContainsFunc(reason, unicode.IsControl)
}

func (key OIDCIdentityKey) valid() bool {
	if len(key.Issuer) > 2048 || len(key.Subject) == 0 || len(key.Subject) > 1024 ||
		strings.TrimSpace(key.Issuer) != key.Issuer || strings.TrimSpace(key.Subject) != key.Subject ||
		strings.ContainsFunc(key.Issuer+key.Subject, unicode.IsControl) {
		return false
	}
	u, err := url.Parse(key.Issuer)
	// Preserve issuer bytes, including case and trailing slash.
	return err == nil && u.Scheme == "https" && u.Hostname() != "" && u.User == nil && u.RawQuery == "" && !u.ForceQuery && u.Fragment == ""
}

// This only protects administrative policy writes using last verified claims.
// Future login admission must evaluate the freshly verified ID-token claims.
func policyEmailAllowed(domains []string, email string, verified bool) bool {
	if len(domains) == 0 {
		return true
	}
	if !verified {
		return false
	}
	a, err := mail.ParseAddress(email)
	if err != nil || a.Address != email || a.Name != "" {
		return false
	}
	_, domain, ok := strings.Cut(email, "@")
	return ok && slices.Contains(domains, strings.ToLower(domain))
}

const policySelect = `SELECT mode,allowed_email_domains,default_role,generation,created_by::text,created_at,updated_by::text,updated_at,reason
 FROM framework.oidc_access_policies WHERE deployment_id=$1 AND environment=$2`

func (r *AccessPolicyRepository) read(ctx context.Context, tx pgx.Tx) (AccessPolicy, error) {
	p := AccessPolicy{Scope: r.scope}
	err := tx.QueryRow(ctx, policySelect, r.scope.DeploymentID, r.scope.Environment).Scan(
		&p.Mode, &p.AllowedEmailDomains, &p.DefaultRole, &p.Generation, &p.CreatedBy, &p.CreatedAt, &p.UpdatedBy, &p.UpdatedAt, &p.Reason)
	return p, err
}

func (r *AccessPolicyRepository) Read(ctx context.Context) (AccessPolicy, error) {
	var result AccessPolicy
	err := adminTransaction(ctx, r.store, func(ctx context.Context, tx pgx.Tx, _ access.User) error {
		var err error
		result, err = r.read(ctx, tx)
		return err
	})
	if err != nil {
		return AccessPolicy{}, err
	}
	return result, nil
}

func (r *AccessPolicyRepository) activeIssuer(ctx context.Context, tx pgx.Tx, generation int64) (string, error) {
	if generation < 1 {
		return "", ErrInvalid
	}
	var issuer string
	err := tx.QueryRow(ctx, `SELECT r.issuer_url FROM framework.auth_activation_heads h
 JOIN framework.auth_config_revisions r ON r.id=h.active_revision_id AND r.deployment_id=h.deployment_id AND r.environment=h.environment
 JOIN framework.auth_config_lifecycle l ON l.revision_id=r.id
 WHERE h.deployment_id=$1 AND h.environment=$2 AND h.generation=$3
 AND h.runtime_source='database' AND r.provider='oidc' AND l.status='active'`,
		r.scope.DeploymentID, r.scope.Environment, generation).Scan(&issuer)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrConflict
	}
	return issuer, err
}

func policyRoleAllowed(ctx context.Context, tx pgx.Tx, role string) error {
	var allowed bool
	err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM framework.roles r WHERE r.name=$1
 AND NOT EXISTS(SELECT 1 FROM framework.role_permissions p WHERE p.role=r.name AND p.permission='admin.manage'))`, role).Scan(&allowed)
	if err != nil {
		return err
	}
	if !allowed {
		return ErrInvalid
	}
	return nil
}

func (r *AccessPolicyRepository) guardAdministrator(ctx context.Context, tx pgx.Tx, p AccessPolicy, issuer string) error {
	rows, err := tx.Query(ctx, `SELECT u.email,u.email_verified FROM framework.users u
 WHERE u.active AND u.provider='oidc' AND u.issuer COLLATE "C"=$3 COLLATE "C"
 AND EXISTS(SELECT 1 FROM framework.user_roles ur JOIN framework.role_permissions rp ON rp.role=ur.role
            WHERE ur.user_id=u.id AND rp.permission='admin.manage')
 AND NOT EXISTS(SELECT 1 FROM framework.oidc_identity_approvals a
   WHERE a.deployment_id=$1 AND a.environment=$2 AND a.issuer=u.issuer COLLATE "C"
     AND a.subject=u.subject COLLATE "C" AND a.status='revoked')
 AND ($4='allow_all' OR EXISTS(SELECT 1 FROM framework.oidc_identity_approvals a
   WHERE a.deployment_id=$1 AND a.environment=$2 AND a.issuer=u.issuer COLLATE "C"
     AND a.subject=u.subject COLLATE "C" AND a.status='approved'))`,
		r.scope.DeploymentID, r.scope.Environment, issuer, p.Mode)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var email string
		var verified bool
		if err := rows.Scan(&email, &verified); err != nil {
			return err
		}
		if policyEmailAllowed(p.AllowedEmailDomains, email, verified) {
			return nil
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	return ErrLastOIDCAdministrator
}

func policyAudit(ctx context.Context, tx pgx.Tx, actor access.User, scope Scope, action string, details any) error {
	if access.RecordAudit(ctx, tx, actor.ID, action, scope.DeploymentID+"/"+scope.Environment, details) != nil {
		return ErrAudit
	}
	return nil
}

// Bootstrap is explicit enrollment of a POLICY, not administrator enrollment.
// Only the current, already privileged OIDC identity of the active DB issuer can
// initialize it. No other identities, role grants or runtime settings are changed.
func (r *AccessPolicyRepository) Bootstrap(ctx context.Context, activationGeneration int64, settings AccessPolicySettings, reason string) (AccessPolicy, error) {
	settings, err := normalizePolicy(settings)
	if err != nil || !validPolicyReason(reason) {
		return AccessPolicy{}, ErrInvalid
	}
	var result AccessPolicy
	err = adminTransaction(ctx, r.store, func(ctx context.Context, tx pgx.Tx, actor access.User) error {
		issuer, err := r.activeIssuer(ctx, tx, activationGeneration)
		if err != nil {
			return err
		}
		identity, ok := auth.IdentityFromContext(ctx)
		if !ok || identity.Provider != auth.OIDC || actor.Provider != string(auth.OIDC) || actor.Issuer != issuer ||
			!(OIDCIdentityKey{issuer, actor.Subject}).valid() {
			return ErrDenied
		}
		if err = policyRoleAllowed(ctx, tx, settings.DefaultRole); err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `INSERT INTO framework.oidc_access_policies
 (deployment_id,environment,mode,allowed_email_domains,default_role,created_by,updated_by,reason)
 VALUES($1,$2,$3,$4,$5,$6,$6,$7)`, r.scope.DeploymentID, r.scope.Environment, settings.Mode, settings.AllowedEmailDomains, settings.DefaultRole, actor.ID, reason)
		if err != nil {
			return err
		}
		key := OIDCIdentityKey{issuer, actor.Subject}
		approval, err := r.writeApproval(ctx, tx, actor, key, 0, "approved", "bootstrap", reason)
		if err != nil {
			return err
		}
		result, err = r.read(ctx, tx)
		if err != nil {
			return err
		}
		if err = r.guardAdministrator(ctx, tx, result, issuer); err != nil {
			return err
		}
		if err = policyAudit(ctx, tx, actor, r.scope, "oidc_access.identity_bootstrapped", approval); err != nil {
			return err
		}
		return policyAudit(ctx, tx, actor, r.scope, "oidc_access.policy_bootstrapped", result)
	})
	if err != nil {
		return AccessPolicy{}, err
	}
	return result, nil
}

func (r *AccessPolicyRepository) Update(ctx context.Context, expected PolicyExpectation, settings AccessPolicySettings, reason string) (AccessPolicy, error) {
	settings, err := normalizePolicy(settings)
	if err != nil || !validPolicyReason(reason) || expected.Generation < 1 {
		return AccessPolicy{}, ErrInvalid
	}
	var result AccessPolicy
	err = adminTransaction(ctx, r.store, func(ctx context.Context, tx pgx.Tx, actor access.User) error {
		issuer, err := r.activeIssuer(ctx, tx, expected.ActivationGeneration)
		if err != nil {
			return err
		}
		before, err := r.read(ctx, tx)
		if err != nil {
			return err
		}
		if before.Generation != expected.Generation {
			return ErrConflict
		}
		if err = policyRoleAllowed(ctx, tx, settings.DefaultRole); err != nil {
			return err
		}
		tag, err := tx.Exec(ctx, `UPDATE framework.oidc_access_policies SET mode=$3,allowed_email_domains=$4,
 default_role=$5,generation=generation+1,updated_by=$6,reason=$7
 WHERE deployment_id=$1 AND environment=$2 AND generation=$8`, r.scope.DeploymentID, r.scope.Environment,
			settings.Mode, settings.AllowedEmailDomains, settings.DefaultRole, actor.ID, reason, expected.Generation)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return ErrConflict
		}
		result, err = r.read(ctx, tx)
		if err != nil {
			return err
		}
		if err = r.guardAdministrator(ctx, tx, result, issuer); err != nil {
			return err
		}
		return policyAudit(ctx, tx, actor, r.scope, "oidc_access.policy_updated", struct {
			Before AccessPolicy `json:"before"`
			After  AccessPolicy `json:"after"`
		}{before, result})
	})
	if err != nil {
		return AccessPolicy{}, err
	}
	return result, nil
}

const approvalSelect = `SELECT issuer,subject,status,source,generation,created_by::text,created_at,updated_by::text,updated_at,reason
 FROM framework.oidc_identity_approvals WHERE deployment_id=$1 AND environment=$2`

func (r *AccessPolicyRepository) scanApproval(row pgx.Row) (OIDCIdentityApproval, error) {
	a := OIDCIdentityApproval{Scope: r.scope}
	err := row.Scan(&a.Issuer, &a.Subject, &a.Status, &a.Source, &a.Generation, &a.CreatedBy, &a.CreatedAt, &a.UpdatedBy, &a.UpdatedAt, &a.Reason)
	return a, err
}

func (r *AccessPolicyRepository) readApproval(ctx context.Context, tx pgx.Tx, key OIDCIdentityKey) (OIDCIdentityApproval, error) {
	return r.scanApproval(tx.QueryRow(ctx, approvalSelect+` AND issuer=$3 AND subject=$4`, r.scope.DeploymentID, r.scope.Environment, key.Issuer, key.Subject))
}

func (r *AccessPolicyRepository) ReadApproval(ctx context.Context, key OIDCIdentityKey) (OIDCIdentityApproval, error) {
	if !key.valid() {
		return OIDCIdentityApproval{}, ErrInvalid
	}
	var result OIDCIdentityApproval
	err := adminTransaction(ctx, r.store, func(ctx context.Context, tx pgx.Tx, _ access.User) error {
		var err error
		result, err = r.readApproval(ctx, tx, key)
		return err
	})
	if err != nil {
		return OIDCIdentityApproval{}, err
	}
	return result, nil
}

func (r *AccessPolicyRepository) ListApprovals(ctx context.Context, offset, limit int) ([]OIDCIdentityApproval, error) {
	if offset < 0 || offset > 100000 || limit < 1 || limit > 100 {
		return nil, ErrInvalid
	}
	result := []OIDCIdentityApproval{}
	err := adminTransaction(ctx, r.store, func(ctx context.Context, tx pgx.Tx, _ access.User) error {
		rows, err := tx.Query(ctx, approvalSelect+` ORDER BY issuer,subject OFFSET $3 LIMIT $4`, r.scope.DeploymentID, r.scope.Environment, offset, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			a, err := r.scanApproval(rows)
			if err != nil {
				return err
			}
			result = append(result, a)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

func (r *AccessPolicyRepository) writeApproval(ctx context.Context, tx pgx.Tx, actor access.User, key OIDCIdentityKey, generation int64, status, source, reason string) (OIDCIdentityApproval, error) {
	if generation == 0 {
		_, err := tx.Exec(ctx, `INSERT INTO framework.oidc_identity_approvals
 (deployment_id,environment,issuer,subject,status,source,created_by,updated_by,reason)
 VALUES($1,$2,$3,$4,$5,$6,$7,$7,$8)`, r.scope.DeploymentID, r.scope.Environment, key.Issuer, key.Subject, status, source, actor.ID, reason)
		if err != nil {
			return OIDCIdentityApproval{}, err
		}
	} else {
		tag, err := tx.Exec(ctx, `UPDATE framework.oidc_identity_approvals SET status=$5,generation=generation+1,updated_by=$6,reason=$7
 WHERE deployment_id=$1 AND environment=$2 AND issuer=$3 AND subject=$4 AND generation=$8 AND status<>$5`,
			r.scope.DeploymentID, r.scope.Environment, key.Issuer, key.Subject, status, actor.ID, reason, generation)
		if err != nil {
			return OIDCIdentityApproval{}, err
		}
		if tag.RowsAffected() != 1 {
			return OIDCIdentityApproval{}, ErrConflict
		}
	}
	return r.readApproval(ctx, tx, key)
}

// SetApproval authorizes an exact identity, not an email or a framework role.
// generation=0 is an explicit create; duplicates never silently upsert.
func (r *AccessPolicyRepository) SetApproval(ctx context.Context, expected PolicyExpectation, key OIDCIdentityKey, generation int64, status, reason string) (OIDCIdentityApproval, error) {
	if !key.valid() || !validPolicyReason(reason) || expected.Generation < 1 || generation < 0 ||
		(status != "approved" && status != "revoked") || (generation == 0 && status != "approved") {
		return OIDCIdentityApproval{}, ErrInvalid
	}
	var result OIDCIdentityApproval
	err := adminTransaction(ctx, r.store, func(ctx context.Context, tx pgx.Tx, actor access.User) error {
		issuer, err := r.activeIssuer(ctx, tx, expected.ActivationGeneration)
		if err != nil {
			return err
		}
		p, err := r.read(ctx, tx)
		if err != nil {
			return err
		}
		if p.Generation != expected.Generation {
			return ErrConflict
		}
		var before *OIDCIdentityApproval
		if generation > 0 {
			a, err := r.readApproval(ctx, tx, key)
			if err != nil {
				return err
			}
			before = &a
		}
		result, err = r.writeApproval(ctx, tx, actor, key, generation, status, "administrator", reason)
		if err != nil {
			return err
		}
		if err = r.guardAdministrator(ctx, tx, p, issuer); err != nil {
			return err
		}
		return policyAudit(ctx, tx, actor, r.scope, "oidc_access.approval_changed", struct {
			Before *OIDCIdentityApproval `json:"before"`
			After  OIDCIdentityApproval  `json:"after"`
		}{before, result})
	})
	if err != nil {
		return OIDCIdentityApproval{}, err
	}
	return result, nil
}
