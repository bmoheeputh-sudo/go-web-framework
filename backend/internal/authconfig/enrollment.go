package authconfig

import (
	"context"
	"errors"

	"github.com/bmoheeputh-sudo/go-web-framework/backend/internal/access"
	"github.com/bmoheeputh-sudo/go-web-framework/backend/internal/auth"
	"github.com/jackc/pgx/v5"
)

// EnrollIdentity grants one explicitly selected role. Identity and scope are
// always taken from durable verifier evidence, never HTTP fields. Evidence is
// single-use for enrollment, serialized by the shared administrative lock.
func (r *Repository) EnrollIdentity(ctx context.Context, revisionID, evidenceID string, generation int64, role string) (access.User, error) {
	if !validID(revisionID) || !validID(evidenceID) || generation < 1 || (role != "Admin" && role != "User" && role != "Viewer") {
		return access.User{}, ErrInvalid
	}
	var user access.User
	err := r.transaction(ctx, func(ctx context.Context, tx pgx.Tx, actor access.User) error {
		m, err := r.get(ctx, tx, revisionID)
		if err != nil {
			return err
		}
		if m.Status != Approved || m.Provider != auth.OIDC || m.Generation != generation {
			return ErrConflict
		}
		var issuer, subject, initiator, purpose string
		var evidenceGeneration int64
		var fresh bool
		err = tx.QueryRow(ctx, `SELECT id::text,issuer,subject,actor_user_id::text,purpose,revision_generation,
            completed_at<=clock_timestamp() AND expires_at>clock_timestamp() AND verification_version=1
            FROM framework.auth_test_evidence WHERE id=$1 AND revision_id=$2 AND deployment_id=$3 AND environment=$4`, evidenceID, revisionID, r.scope.DeploymentID, r.scope.Environment).
			Scan(&evidenceID, &issuer, &subject, &initiator, &purpose, &evidenceGeneration, &fresh)
		if err != nil {
			return err
		}
		if initiator != actor.ID {
			return ErrDenied
		}
		if !fresh || evidenceGeneration != generation || issuer != m.IssuerURL || purpose != string(IsolatedConnection) {
			return ErrConflict
		}
		var used bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM framework.audit_log WHERE action='auth_config.identity_enrolled' AND details->>'evidence_id'=$1)`, evidenceID).Scan(&used); err != nil {
			return err
		}
		if used {
			return ErrConflict
		}
		user, err = access.EnrollVerifiedOIDCIdentity(ctx, tx, actor, auth.Identity{Issuer: issuer, Subject: subject, Provider: auth.OIDC}, role)
		if errors.Is(err, access.ErrConflict) {
			return ErrConflict
		}
		if errors.Is(err, access.ErrInvalid) {
			return ErrInvalid
		}
		if err != nil {
			return err
		}
		details := struct {
			EvidenceID string `json:"evidence_id"`
			RevisionID string `json:"revision_id"`
			Generation int64  `json:"generation"`
			Role       string `json:"role"`
		}{evidenceID, revisionID, generation, role}
		if access.RecordAudit(ctx, tx, actor.ID, "auth_config.identity_enrolled", user.ID, details) != nil {
			return ErrAudit
		}
		if err := tx.QueryRow(ctx, `SELECT expires_at>clock_timestamp() FROM framework.auth_test_evidence WHERE id=$1`, evidenceID).Scan(&fresh); err != nil {
			return err
		}
		if !fresh {
			return ErrConflict
		}
		return nil
	})
	if err != nil {
		return access.User{}, err
	}
	return user, nil
}
