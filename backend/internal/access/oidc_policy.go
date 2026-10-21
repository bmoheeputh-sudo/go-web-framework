package access

import (
	"context"
	"errors"
	"net/mail"
	"slices"
	"strings"
	"time"

	"github.com/bmoheeputh-sudo/go-web-framework/backend/internal/auth"
	"github.com/jackc/pgx/v5"
)

var ErrPolicyNotReady = errors.New("OIDC access policy requires explicit bootstrap and an approved eligible administrator")

// EmailDomainAllowed never treats a suffix, display name, or unverified email
// as a domain authorization. Issuer and subject are not normalized.
func EmailDomainAllowed(domains []string, email string, verified bool) bool {
	if len(domains) == 0 {
		return true
	}
	if !verified {
		return false
	}
	address, err := mail.ParseAddress(email)
	if err != nil || address.Address != email {
		return false
	}
	parts := strings.Split(email, "@")
	return len(parts) == 2 && slices.Contains(domains, strings.ToLower(parts[1]))
}

type oidcPolicy struct {
	mode, role string
	domains    []string
}

func readOIDCPolicy(ctx context.Context, tx querier, deployment, environment string) (oidcPolicy, error) {
	var p oidcPolicy
	var safe bool
	err := tx.QueryRow(ctx, `SELECT mode,default_role,allowed_email_domains,
 framework.valid_access_domains(allowed_email_domains)
 AND (SELECT count(*)=1 FROM framework.oidc_access_policies)
 AND NOT EXISTS(SELECT 1 FROM framework.auth_activation_heads
   WHERE runtime_source='database' AND (deployment_id<>$1 OR environment<>$2))
 AND NOT EXISTS(SELECT 1 FROM framework.role_permissions WHERE role=default_role AND permission='admin.manage')
 FROM framework.oidc_access_policies WHERE deployment_id=$1 AND environment=$2`, deployment, environment).
		Scan(&p.mode, &p.role, &p.domains, &safe)
	if errors.Is(err, pgx.ErrNoRows) {
		return p, ErrPolicyNotReady
	}
	if err != nil {
		return p, ErrUnavailable
	}
	if !safe || (p.mode != "allow_all" && p.mode != "approved_users_only") || (p.role != "Viewer" && p.role != "User") {
		return p, ErrPolicyNotReady
	}
	return p, nil
}

// CheckOIDCAdministrator is shared by startup, RBAC changes, policy management,
// activation and offline recovery. Callers use a consistent read or hold the
// framework mutation lock. Bootstrap always requires an explicitly approved
// administrator, even in allow_all mode.
func CheckOIDCAdministrator(ctx context.Context, tx pgx.Tx, deployment, environment, issuer string) error {
	return CheckOIDCAdministratorIdentity(ctx, tx, deployment, environment, issuer, "")
}

// An activation's tested/enrolled administrator must itself remain eligible.
func CheckOIDCAdministratorIdentity(ctx context.Context, tx pgx.Tx, deployment, environment, issuer, userID string) error {
	p, err := readOIDCPolicy(ctx, tx, deployment, environment)
	if err != nil {
		return err
	}
	rows, err := tx.Query(ctx, `SELECT u.email,u.email_verified FROM framework.users u
 JOIN framework.oidc_identity_approvals a ON a.issuer=u.issuer COLLATE "C" AND a.subject=u.subject COLLATE "C"
 WHERE a.deployment_id=$1 AND a.environment=$2 AND a.status='approved'
 AND u.active AND u.provider='oidc' AND u.issuer COLLATE "C"=$3 COLLATE "C" AND ($4='' OR u.id::text=$4)
 AND EXISTS(SELECT 1 FROM framework.user_roles ur JOIN framework.role_permissions rp ON rp.role=ur.role
 WHERE ur.user_id=u.id AND rp.permission='admin.manage')`, deployment, environment, issuer, userID)
	if err != nil {
		return ErrUnavailable
	}
	defer rows.Close()
	for rows.Next() {
		var email string
		var verified bool
		if err := rows.Scan(&email, &verified); err != nil {
			return ErrUnavailable
		}
		if EmailDomainAllowed(p.domains, email, verified) {
			return nil
		}
	}
	if rows.Err() != nil {
		return ErrUnavailable
	}
	return ErrPolicyNotReady
}

// Existing pre-policy Local DEV installations remain usable. Once initialized,
// an OIDC policy's final eligible administrator is protected through every core
// role/active/permission mutation, not just the policy repository.
func guardActiveOIDCPolicies(ctx context.Context, tx pgx.Tx) error {
	var installed bool
	if err := tx.QueryRow(ctx, `SELECT to_regclass('framework.oidc_access_policies') IS NOT NULL`).Scan(&installed); err != nil {
		return ErrUnavailable
	}
	if !installed {
		return nil
	}
	rows, err := tx.Query(ctx, `SELECT p.deployment_id,p.environment,r.issuer_url
 FROM framework.oidc_access_policies p JOIN framework.auth_activation_heads h USING(deployment_id,environment)
 JOIN framework.auth_config_revisions r ON r.id=h.active_revision_id
 WHERE h.runtime_source='database' AND r.provider='oidc'`)
	if err != nil {
		return ErrUnavailable
	}
	var scopes [][3]string
	for rows.Next() {
		var scope [3]string
		if err := rows.Scan(&scope[0], &scope[1], &scope[2]); err != nil {
			rows.Close()
			return ErrUnavailable
		}
		scopes = append(scopes, scope)
	}
	rows.Close()
	if rows.Err() != nil {
		return ErrUnavailable
	}
	for _, scope := range scopes {
		if err := CheckOIDCAdministrator(ctx, tx, scope[0], scope[1], scope[2]); err != nil {
			if errors.Is(err, ErrPolicyNotReady) {
				return ErrConflict
			}
			return err
		}
	}
	return nil
}

// OIDCAdmission is immutable and deployment-bound. There is deliberately no
// permissive cache or HTTP-controlled scope. Every credential use reads policy.
type OIDCAdmission struct {
	store                   *Store
	deployment, environment string
}

func (s *Store) OIDCAdmission(deployment, environment string) *OIDCAdmission {
	return &OIDCAdmission{s, deployment, environment}
}

func (p *OIDCAdmission) CheckStartup(ctx context.Context, issuer string) error {
	return p.store.AuthRecoveryRead(ctx, func(tx pgx.Tx) error {
		return CheckOIDCAdministrator(ctx, tx, p.deployment, p.environment, issuer)
	})
}

// RevokeIneligibleOIDCSessions runs inside an authorized policy mutation. A
// later relaxation must not resurrect credentials invalidated by a tightening.
func RevokeIneligibleOIDCSessions(ctx context.Context, tx pgx.Tx, deployment, environment string) error {
	p, err := readOIDCPolicy(ctx, tx, deployment, environment)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `DELETE FROM framework.sessions s WHERE s.provider='oidc'
 AND (s.binding_source='legacy' OR (s.deployment_id=$1 AND s.environment=$2))
 AND (
 NOT EXISTS(SELECT 1 FROM framework.users u WHERE u.issuer=s.issuer AND u.subject=s.subject AND u.active AND u.provider='oidc'
   AND (cardinality($4::text[])=0 OR (u.email_verified AND array_length(string_to_array(u.email,'@'),1)=2 AND lower(split_part(u.email,'@',2))=ANY($4))))
 OR EXISTS(SELECT 1 FROM framework.oidc_identity_approvals a WHERE a.deployment_id=$1 AND a.environment=$2 AND a.issuer=s.issuer AND a.subject=s.subject AND a.status='revoked')
 OR ($3='approved_users_only' AND NOT EXISTS(SELECT 1 FROM framework.oidc_identity_approvals a WHERE a.deployment_id=$1 AND a.environment=$2 AND a.issuer=s.issuer AND a.subject=s.subject AND a.status='approved'))
 OR (cardinality($4::text[])>0 AND (NOT s.email_verified OR array_length(string_to_array(s.email,'@'),1)<>2 OR NOT lower(split_part(s.email,'@',2))=ANY($4)))
 )`, deployment, environment, p.mode, p.domains)
	return dbError(err)
}

// Common checks may never be overridden by an invitation. The missing approval
// decision is separate so only a verified normal login can supply a claim.
func (p *OIDCAdmission) eligibility(ctx context.Context, tx querier, identity auth.Identity) (oidcPolicy, string, error) {
	if identity.Provider != auth.OIDC || identity.Validate() != nil {
		return oidcPolicy{}, "", auth.ErrUnauthenticated
	}
	policy, err := readOIDCPolicy(ctx, tx, p.deployment, p.environment)
	if err != nil {
		return policy, "", err
	}
	var status string
	err = tx.QueryRow(ctx, `SELECT status FROM framework.oidc_identity_approvals
 WHERE deployment_id=$1 AND environment=$2 AND issuer=$3 COLLATE "C" AND subject=$4 COLLATE "C"`, p.deployment, p.environment, identity.Issuer, identity.Subject).Scan(&status)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return policy, "", ErrUnavailable
	}
	if status == "revoked" || !EmailDomainAllowed(policy.domains, identity.Email, identity.EmailVerified) {
		return policy, status, auth.ErrUnauthenticated
	}
	return policy, status, nil
}
func (p *OIDCAdmission) eligible(ctx context.Context, tx querier, identity auth.Identity) (oidcPolicy, error) {
	policy, status, err := p.eligibility(ctx, tx, identity)
	if err == nil && policy.mode == "approved_users_only" && status != "approved" {
		err = auth.ErrUnauthenticated
	}
	return policy, err
}

// Recheck initialized policy during authorization too, notably after waiting for
// the shared administrative/module mutation lock. A request authenticated just
// before approval revocation must not retain administrative mutation authority.
func policyPrincipal(ctx context.Context, q querier, id string) error {
	var installed bool
	if err := q.QueryRow(ctx, `SELECT to_regclass('framework.oidc_access_policies') IS NOT NULL`).Scan(&installed); err != nil {
		return ErrUnavailable
	}
	if !installed {
		return nil // Pre-policy Local DEV and migration-7 compatibility.
	}
	var deployment, environment string
	err := q.QueryRow(ctx, `SELECT deployment_id,environment FROM framework.oidc_access_policies`).Scan(&deployment, &environment)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil // OIDC runtime startup/admission separately refuses missing policy.
	}
	if err != nil {
		return ErrUnavailable
	}
	var identity auth.Identity
	if err := q.QueryRow(ctx, `SELECT issuer,subject,email,email_verified,display_name,provider FROM framework.users WHERE id=$1`, id).
		Scan(&identity.Issuer, &identity.Subject, &identity.Email, &identity.EmailVerified, &identity.DisplayName, &identity.Provider); err != nil {
		return ErrUnavailable
	}
	if identity.Provider == auth.LocalDev {
		return nil // Runtime authority still fences Local DEV after first activation.
	}
	p := OIDCAdmission{deployment: deployment, environment: environment}
	if _, err := p.eligible(ctx, q, identity); err != nil {
		if errors.Is(err, auth.ErrUnauthenticated) {
			return ErrDenied
		}
		return ErrUnavailable
	}
	return nil
}

func admissionError(err error) error {
	if err == nil || errors.Is(err, auth.ErrUnauthenticated) {
		return err
	}
	// No SQL, identities, policy contents or commit details reach HTTP errors.
	return auth.ErrStoreUnavailable
}

func (p *OIDCAdmission) Login(ctx context.Context, identity auth.Identity, binding auth.Binding, write func(context.Context, pgx.Tx) error) error {
	if (binding.Purpose != "" && binding.Purpose != "login") ||
		(binding.Source == "database" && (!binding.MatchesDatabase(binding) || binding.DeploymentID != p.deployment || binding.Environment != p.environment || binding.Issuer != identity.Issuer)) {
		return auth.ErrUnauthenticated
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	err := p.store.withMutation(ctx, func(tx pgx.Tx) error { return nil }, func(tx pgx.Tx) error {
		policy, approval, err := p.eligibility(ctx, tx, identity)
		if err != nil {
			return err
		}
		var id, provider string
		var active bool
		err = tx.QueryRow(ctx, `SELECT id::text,active,provider FROM framework.users
 WHERE issuer=$1 COLLATE "C" AND subject=$2 COLLATE "C"`, identity.Issuer, identity.Subject).Scan(&id, &active, &provider)
		missing := errors.Is(err, pgx.ErrNoRows)
		if err != nil && !missing {
			return ErrUnavailable
		}
		if !missing && (!active || provider != "oidc") {
			return auth.ErrUnauthenticated
		}
		invitation, err := p.loginInvitation(ctx, tx, identity, binding)
		if err != nil {
			return err
		}
		if policy.mode == "approved_users_only" && approval != "approved" && invitation == nil {
			return auth.ErrUnauthenticated
		}
		if missing {
			err = tx.QueryRow(ctx, `INSERT INTO framework.users(issuer,subject,email,email_verified,display_name,provider)
 VALUES($1,$2,$3,$4,$5,'oidc') RETURNING id::text`, identity.Issuer, identity.Subject, identity.Email, identity.EmailVerified, identity.DisplayName).Scan(&id)
			if err != nil {
				return ErrUnavailable
			}
			if _, err = tx.Exec(ctx, `INSERT INTO framework.user_roles(user_id,role) VALUES($1,$2)`, id, policy.role); err != nil {
				return ErrUnavailable
			}
			// The actor is the verified newly provisioned identity, never a
			// fabricated administrator. No tokens/claim blobs are audited.
			if err = audit(ctx, tx, id, "oidc_access.user_provisioned", id, map[string]string{
				"role": policy.role, "deployment_id": p.deployment, "environment": p.environment,
			}); err != nil {
				return err
			}
		} else {
			if _, err = tx.Exec(ctx, `UPDATE framework.users SET email=$2,email_verified=$3,display_name=$4,verified_at=clock_timestamp()
 WHERE id=$1`, id, identity.Email, identity.EmailVerified, identity.DisplayName); err != nil {
				return ErrUnavailable
			}
		}
		if invitation != nil {
			if err := p.claimInvitation(ctx, tx, identity, id, *invitation, approval == ""); err != nil {
				return err
			}
		}
		return write(ctx, tx)
	})
	return admissionError(err)
}

func (p *OIDCAdmission) Session(ctx context.Context, read func(context.Context, pgx.Tx) (auth.Identity, error)) (auth.Identity, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	var identity auth.Identity
	denied := false
	err := p.store.withMutation(ctx, func(tx pgx.Tx) error { return nil }, func(tx pgx.Tx) error {
		var err error
		identity, err = read(ctx, tx)
		if err != nil {
			return err
		}
		// Session claims originate in verified ID tokens. Also require current
		// user claims, refreshed only by verified normal logins, to remain eligible.
		_, err = p.eligible(ctx, tx, identity)
		if err != nil && !errors.Is(err, auth.ErrUnauthenticated) {
			return err
		}
		denied = err != nil
		var active bool
		current := identity
		err = tx.QueryRow(ctx, `SELECT active,email,email_verified FROM framework.users
 WHERE issuer=$1 COLLATE "C" AND subject=$2 COLLATE "C" AND provider='oidc'`, identity.Issuer, identity.Subject).
			Scan(&active, &current.Email, &current.EmailVerified)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return ErrUnavailable
		}
		denied = denied || !active || errors.Is(err, pgx.ErrNoRows)
		if !denied {
			_, err = p.eligible(ctx, tx, current)
			if err != nil && !errors.Is(err, auth.ErrUnauthenticated) {
				return err
			}
			denied = err != nil
		}
		if denied {
			// Revocation is durable: later reapproval cannot resurrect these
			// credentials. The database has exactly one security deployment.
			_, err = tx.Exec(ctx, `DELETE FROM framework.sessions WHERE issuer=$1 AND subject=$2 AND provider='oidc'
 AND (binding_source='legacy' OR (deployment_id=$3 AND environment=$4))`,
				identity.Issuer, identity.Subject, p.deployment, p.environment)
			return err
		}
		return nil
	})
	if err != nil {
		return auth.Identity{}, admissionError(err)
	}
	if denied {
		return auth.Identity{}, auth.ErrUnauthenticated
	}
	return identity, nil
}
