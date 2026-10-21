package authconfig

import (
	"context"
	"errors"
	"net/mail"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/bmoheeputh-sudo/go-web-framework/backend/internal/access"
	"github.com/jackc/pgx/v5"
)

// InvitationExpectation binds writes to authoritative reads, not browser identity claims.
type InvitationExpectation struct {
	PolicyExpectation
	RevisionID         string
	RevisionGeneration int64
}

type InvitationInput struct {
	Email       string     `json:"email"`
	DisplayName string     `json:"display_name"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
	Reason      string     `json:"reason"`
}

type Invitation struct {
	ID string `json:"id"`
	Scope
	Issuer               string    `json:"issuer"`
	RevisionID           string    `json:"revision_id"`
	RevisionGeneration   int64     `json:"revision_generation"`
	ActivationGeneration int64     `json:"activation_generation"`
	ClientID             string    `json:"client_id"`
	Email                string    `json:"email"`
	EmailKey             string    `json:"email_key"`
	DisplayName          string    `json:"display_name"`
	ExpiresAt            time.Time `json:"expires_at"`
	Status               string    `json:"status"`
	PolicyModification
	Source         string     `json:"source"`
	ImportID       string     `json:"import_id,omitempty"`
	ClaimedUserID  string     `json:"claimed_user_id,omitempty"`
	ClaimedIssuer  string     `json:"claimed_issuer,omitempty"`
	ClaimedSubject string     `json:"claimed_subject,omitempty"`
	ClaimedAt      *time.Time `json:"claimed_at,omitempty"`
	BindingCurrent bool       `json:"binding_current"`
}

type Invitations struct {
	Items                []Invitation `json:"items"`
	Total                int64        `json:"total"`
	Offset               int          `json:"offset"`
	Limit                int          `json:"limit"`
	PolicyGeneration     int64        `json:"policy_generation"`
	ActivationGeneration int64        `json:"activation_generation"`
	RevisionID           string       `json:"revision_id"`
	RevisionGeneration   int64        `json:"revision_generation"`
}

var invitationLocal = regexp.MustCompile("^[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+(\\.[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+)*$")

// Only ASCII dot-atom mailbox syntax is supported initially. Never case-fold the
// local part or strip aliases. Case variants conflict instead of being merged.
func invitationEmailKey(email string) (string, error) {
	if len(email) > 254 || strings.ContainsFunc(email, func(r rune) bool { return r > 127 || unicode.IsControl(r) }) {
		return "", ErrInvalid
	}
	parsed, err := mail.ParseAddress(email)
	if err != nil || parsed.Address != email || parsed.Name != "" || strings.Count(email, "@") != 1 {
		return "", ErrInvalid
	}
	parts := strings.Split(email, "@")
	if len(parts[0]) > 64 || !invitationLocal.MatchString(parts[0]) {
		return "", ErrInvalid
	}
	domain := strings.ToLower(parts[1])
	if len(domain) > 253 || !accessDomain.MatchString(domain) {
		return "", ErrInvalid
	}
	return parts[0] + "@" + domain, nil
}

func (e InvitationExpectation) valid() bool {
	return e.Generation > 0 && e.ActivationGeneration > 0 && validID(e.RevisionID) && e.RevisionGeneration > 0
}

type invitationBinding struct {
	policy                                   AccessPolicy
	revision, issuer, client                 string
	revisionGeneration, activationGeneration int64
}

func (r *AccessPolicyRepository) invitationContext(ctx context.Context, tx pgx.Tx, expected *InvitationExpectation) (invitationBinding, error) {
	var b invitationBinding
	var err error
	b.policy, err = r.read(ctx, tx)
	if err != nil {
		return b, err
	}
	if _, err = normalizePolicy(b.policy.AccessPolicySettings); err != nil {
		return b, err
	}
	if err = policyRoleAllowed(ctx, tx, b.policy.DefaultRole); err != nil {
		return b, err
	}
	// The users/RBAC tables are global: the supported topology remains one security deployment per DB.
	var isolated bool
	if err = tx.QueryRow(ctx, `SELECT NOT EXISTS(SELECT 1 FROM framework.oidc_access_policies WHERE deployment_id<>$1 OR environment<>$2)
 AND NOT EXISTS(SELECT 1 FROM framework.auth_activation_heads WHERE deployment_id<>$1 OR environment<>$2)`, r.scope.DeploymentID, r.scope.Environment).Scan(&isolated); err != nil {
		return b, err
	}
	if !isolated {
		return b, ErrConflict
	}
	err = tx.QueryRow(ctx, `SELECT h.active_revision_id::text,h.generation,l.generation,r.issuer_url,r.client_id
 FROM framework.auth_activation_heads h JOIN framework.auth_config_revisions r
 ON r.id=h.active_revision_id AND r.deployment_id=h.deployment_id AND r.environment=h.environment
 JOIN framework.auth_config_lifecycle l ON l.revision_id=r.id
 WHERE h.deployment_id=$1 AND h.environment=$2 AND h.runtime_source='database' AND r.provider='oidc' AND l.status='active'`, r.scope.DeploymentID, r.scope.Environment).Scan(&b.revision, &b.activationGeneration, &b.revisionGeneration, &b.issuer, &b.client)
	if errors.Is(err, pgx.ErrNoRows) {
		return b, ErrConflict
	}
	if err != nil {
		return b, err
	}
	if expected != nil && (expected.Generation != b.policy.Generation || expected.ActivationGeneration != b.activationGeneration || expected.RevisionID != b.revision || expected.RevisionGeneration != b.revisionGeneration) {
		return b, ErrConflict
	}
	return b, nil
}

const invitationColumns = `id::text,deployment_id,environment,issuer,revision_id::text,revision_generation,activation_generation,client_id,
 email,email_key,display_name,expires_at,CASE WHEN status='pending' AND expires_at<=clock_timestamp() THEN 'expired' ELSE status END,
 generation,created_by::text,created_at,updated_by::text,updated_at,reason,source,COALESCE(import_id::text,''),
 COALESCE(claimed_user_id::text,''),COALESCE(claimed_issuer,''),COALESCE(claimed_subject,''),claimed_at`

func scanInvitation(row pgx.Row, b invitationBinding) (Invitation, error) {
	var i Invitation
	err := row.Scan(&i.ID, &i.DeploymentID, &i.Environment, &i.Issuer, &i.RevisionID, &i.RevisionGeneration, &i.ActivationGeneration, &i.ClientID,
		&i.Email, &i.EmailKey, &i.DisplayName, &i.ExpiresAt, &i.Status, &i.Generation, &i.CreatedBy, &i.CreatedAt, &i.UpdatedBy, &i.UpdatedAt, &i.Reason, &i.Source, &i.ImportID, &i.ClaimedUserID, &i.ClaimedIssuer, &i.ClaimedSubject, &i.ClaimedAt)
	i.BindingCurrent = i.RevisionID == b.revision && i.RevisionGeneration == b.revisionGeneration && i.ActivationGeneration == b.activationGeneration && i.Issuer == b.issuer && i.ClientID == b.client
	return i, err
}
func (r *AccessPolicyRepository) readInvitation(ctx context.Context, tx pgx.Tx, id string, b invitationBinding) (Invitation, error) {
	return scanInvitation(tx.QueryRow(ctx, `SELECT `+invitationColumns+` FROM framework.oidc_invitations WHERE deployment_id=$1 AND environment=$2 AND id=$3`, r.scope.DeploymentID, r.scope.Environment, id), b)
}
func invitationAudit(ctx context.Context, tx pgx.Tx, actor access.User, i Invitation, action string) error {
	// Approved fields only. Do not copy arbitrary request bodies or mailbox PII into audit details.
	details := struct {
		Scope
		RevisionID string `json:"revision_id"`
		Generation int64  `json:"generation"`
		Status     string `json:"status"`
		Reason     string `json:"reason"`
	}{i.Scope, i.RevisionID, i.Generation, i.Status, i.Reason}
	if access.RecordAudit(ctx, tx, actor.ID, action, i.ID, details) != nil {
		return ErrAudit
	}
	return nil
}

func (r *AccessPolicyRepository) CreateInvitation(ctx context.Context, expected InvitationExpectation, input InvitationInput) (Invitation, error) {
	key, err := invitationEmailKey(input.Email)
	if err != nil || !expected.valid() || !validPolicyReason(input.Reason) || !utf8.ValidString(input.DisplayName) || utf8.RuneCountInString(input.DisplayName) > 200 || strings.ContainsFunc(input.DisplayName, unicode.IsControl) {
		return Invitation{}, ErrInvalid
	}
	var result Invitation
	err = adminTransaction(ctx, r.store, func(ctx context.Context, tx pgx.Tx, actor access.User) error {
		b, err := r.invitationContext(ctx, tx, &expected)
		if err != nil {
			return err
		}
		result, err = r.createInvitationTx(ctx, tx, actor, b, input, key, "manual", "")
		return err
	})
	if err != nil {
		return Invitation{}, err
	}
	return result, nil
}

func (r *AccessPolicyRepository) createInvitationTx(ctx context.Context, tx pgx.Tx, actor access.User, b invitationBinding, input InvitationInput, key, source, importID string) (Invitation, error) {
	var result Invitation
	var err error
	var importRef *string
	if importID != "" {
		importRef = &importID
	}
	// This checks policy domains only, not proof of mailbox ownership. That proof is required by a future claim operation.
	if !policyEmailAllowed(b.policy.AllowedEmailDomains, key, true) {
		return Invitation{}, ErrInvalid
	}
	var now time.Time
	if err = tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		return Invitation{}, err
	}
	expires := now.Add(7 * 24 * time.Hour)
	if input.ExpiresAt != nil {
		expires = *input.ExpiresAt
	}
	if !expires.After(now) || expires.After(now.Add(30*24*time.Hour)) {
		return Invitation{}, ErrInvalid
	}
	// Retire elapsed pending records and audit each transition in the same transaction.
	rows, err := tx.Query(ctx, `UPDATE framework.oidc_invitations SET status='expired',generation=generation+1,updated_by=$5,reason=$6
   WHERE deployment_id=$1 AND environment=$2 AND revision_id=$3 AND lower(email_key COLLATE "C")=lower($4 COLLATE "C")
   AND status='pending' AND expires_at<=clock_timestamp() RETURNING `+invitationColumns, r.scope.DeploymentID, r.scope.Environment, b.revision, key, actor.ID, input.Reason)
	if err != nil {
		return Invitation{}, err
	}
	expired := []Invitation{}
	for rows.Next() {
		i, e := scanInvitation(rows, b)
		if e != nil {
			rows.Close()
			return Invitation{}, e
		}
		expired = append(expired, i)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return Invitation{}, err
	}
	for _, i := range expired {
		if err = invitationAudit(ctx, tx, actor, i, "oidc_access.invitation_expired"); err != nil {
			return Invitation{}, err
		}
	}
	result, err = scanInvitation(tx.QueryRow(ctx, `INSERT INTO framework.oidc_invitations
   (deployment_id,environment,issuer,revision_id,revision_generation,activation_generation,client_id,email,email_key,display_name,expires_at,created_by,updated_by,reason,source,import_id)
   VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$12,$13,$14,$15) RETURNING `+invitationColumns,
		r.scope.DeploymentID, r.scope.Environment, b.issuer, b.revision, b.revisionGeneration, b.activationGeneration, b.client, input.Email, key, input.DisplayName, expires, actor.ID, input.Reason, source, importRef), b)
	if err != nil {
		return Invitation{}, err
	}
	return result, invitationAudit(ctx, tx, actor, result, "oidc_access.invitation_created")
}

func (r *AccessPolicyRepository) ReadInvitation(ctx context.Context, id string) (Invitation, error) {
	if !validID(id) {
		return Invitation{}, ErrInvalid
	}
	var result Invitation
	err := adminTransaction(ctx, r.store, func(ctx context.Context, tx pgx.Tx, _ access.User) error {
		b, err := r.invitationContext(ctx, tx, nil)
		if err != nil {
			return err
		}
		result, err = r.readInvitation(ctx, tx, id, b)
		return err
	})
	return result, err
}
func (r *AccessPolicyRepository) ListInvitations(ctx context.Context, search, status string, offset, limit int, importIDs ...string) (Invitations, error) {
	result := Invitations{Items: []Invitation{}, Offset: offset, Limit: limit}
	var importID *string
	if len(importIDs) > 1 {
		return result, ErrInvalid
	}
	if len(importIDs) == 1 && importIDs[0] != "" {
		if !validID(importIDs[0]) {
			return result, ErrInvalid
		}
		importID = &importIDs[0]
	}
	if !utf8.ValidString(search) || len(search) > 200 || strings.ContainsFunc(search, unicode.IsControl) || offset < 0 || offset > 100000 || limit < 1 || limit > 100 || (status != "" && status != "pending" && status != "claimed" && status != "revoked" && status != "expired") {
		return result, ErrInvalid
	}
	err := adminTransaction(ctx, r.store, func(ctx context.Context, tx pgx.Tx, _ access.User) error {
		b, err := r.invitationContext(ctx, tx, nil)
		if err != nil {
			return err
		}
		result.PolicyGeneration, result.ActivationGeneration, result.RevisionID, result.RevisionGeneration = b.policy.Generation, b.activationGeneration, b.revision, b.revisionGeneration
		// Freeze DB time for count and page so expiry cannot change membership between the two queries.
		var now time.Time
		if err = tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
			return err
		}
		where := ` WHERE deployment_id=$1 AND environment=$2 AND strpos(lower(email||' '||display_name),lower($3))>0
   AND ($4='' OR (CASE WHEN status='pending' AND expires_at<=$5 THEN 'expired' ELSE status END)=$4) AND ($8::uuid IS NULL OR import_id=$8)`
		if err = tx.QueryRow(ctx, `SELECT count(*) FROM framework.oidc_invitations`+strings.ReplaceAll(where, "$8", "$6"), r.scope.DeploymentID, r.scope.Environment, search, status, now, importID).Scan(&result.Total); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `SELECT `+strings.ReplaceAll(invitationColumns, "clock_timestamp()", "$5")+` FROM framework.oidc_invitations`+where+` ORDER BY created_at DESC,id LIMIT $6 OFFSET $7`, r.scope.DeploymentID, r.scope.Environment, search, status, now, limit, offset, importID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			i, err := scanInvitation(rows, b)
			if err != nil {
				return err
			}
			result.Items = append(result.Items, i)
		}
		return rows.Err()
	})
	return result, err
}
func (r *AccessPolicyRepository) RevokeInvitation(ctx context.Context, expected InvitationExpectation, id string, generation int64, reason string) (Invitation, error) {
	if !expected.valid() || !validID(id) || generation < 1 || !validPolicyReason(reason) {
		return Invitation{}, ErrInvalid
	}
	var result Invitation
	err := adminTransaction(ctx, r.store, func(ctx context.Context, tx pgx.Tx, actor access.User) error {
		b, err := r.invitationContext(ctx, tx, &expected)
		if err != nil {
			return err
		}
		before, err := r.readInvitation(ctx, tx, id, b)
		if err != nil {
			return err
		}
		if before.Generation != generation || before.Status != "pending" || !before.BindingCurrent {
			return ErrConflict
		}
		result, err = scanInvitation(tx.QueryRow(ctx, `UPDATE framework.oidc_invitations SET status='revoked',generation=generation+1,updated_by=$4,reason=$5
   WHERE deployment_id=$1 AND environment=$2 AND id=$3 AND generation=$6 AND status='pending' AND expires_at>clock_timestamp() RETURNING `+invitationColumns, r.scope.DeploymentID, r.scope.Environment, id, actor.ID, reason, generation), b)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrConflict
		}
		if err != nil {
			return err
		}
		return invitationAudit(ctx, tx, actor, result, "oidc_access.invitation_revoked")
	})
	if err != nil {
		return Invitation{}, err
	}
	return result, nil
}
