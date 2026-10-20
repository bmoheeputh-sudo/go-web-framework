package access

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"time"

	"github.com/bmoheeputh-sudo/go-web-framework/backend/internal/auth"
	"github.com/jackc/pgx/v5"
)

// PolicyBootstrapTransaction is an offline rollout capability, not an HTTP
// authentication bypass. The operator must possess a currently valid, bound
// OIDC admin session as well as server/database access. Identity is read from
// the hashed session, never an operator-supplied issuer/subject/user ID.
func (s *Store) PolicyBootstrapTransaction(ctx context.Context, token, deployment, environment string, generation int64, idle time.Duration, fn func(context.Context, pgx.Tx, User, auth.Identity) error) error {
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(token)
	if err != nil || len(decoded) != 32 || len(token) != 43 || generation < 1 || idle <= 0 || idle > 24*time.Hour || fn == nil {
		return ErrDenied
	}
	hash := sha256.Sum256([]byte(token))
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return s.withMutation(ctx, func(tx pgx.Tx) error { return nil }, func(tx pgx.Tx) error {
		var identity auth.Identity
		err := tx.QueryRow(ctx, `SELECT s.issuer,s.subject,s.email,s.email_verified,s.display_name,s.provider
 FROM framework.sessions s JOIN framework.auth_activation_heads h
 ON h.deployment_id=s.deployment_id AND h.environment=s.environment AND h.generation=s.activation_generation AND h.active_revision_id=s.revision_id
 JOIN framework.auth_config_revisions r ON r.id=h.active_revision_id
 JOIN framework.auth_config_lifecycle l ON l.revision_id=r.id
 WHERE s.token_hash=$1 AND s.binding_source='database' AND s.flow_purpose='login'
 AND h.deployment_id=$2 AND h.environment=$3 AND h.generation=$4 AND h.runtime_source='database'
 AND s.issuer=r.issuer_url COLLATE "C" AND s.client_id=r.client_id AND s.provider='oidc' AND r.provider='oidc'
 AND l.status='active' AND s.expires_at>clock_timestamp()
 AND s.last_activity_at>clock_timestamp()-($5::double precision*interval '1 second')`,
			hash[:], deployment, environment, generation, idle.Seconds()).Scan(
			&identity.Issuer, &identity.Subject, &identity.Email, &identity.EmailVerified, &identity.DisplayName, &identity.Provider)
		if err == pgx.ErrNoRows {
			return ErrDenied
		}
		if err != nil {
			return ErrUnavailable
		}
		if identity.Validate() != nil {
			return ErrDenied
		}
		actor, err := scanUser(tx.QueryRow(ctx, userSelect+`WHERE u.issuer=$1 COLLATE "C" AND u.subject=$2 COLLATE "C" AND u.active AND u.provider='oidc'`, identity.Issuer, identity.Subject))
		if err != nil {
			return ErrDenied
		}
		if err := s.allowed(ctx, tx, actor.ID, AdminManage, ""); err != nil {
			return err
		}
		// Refresh only claims already verified in this existing session; no
		// user creation, reactivation, session extension or role assignment.
		if _, err := tx.Exec(ctx, `UPDATE framework.users SET email=$2,email_verified=$3,display_name=$4 WHERE id=$1`,
			actor.ID, identity.Email, identity.EmailVerified, identity.DisplayName); err != nil {
			return ErrUnavailable
		}
		return fn(ctx, tx, actor, identity)
	})
}
