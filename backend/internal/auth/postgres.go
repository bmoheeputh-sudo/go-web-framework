package auth

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"golang.org/x/oauth2"
)

type sessionDB interface {
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
	QueryRow(context.Context, string, ...any) pgx.Row
}

type PostgresStore struct {
	db     sessionDB
	idle   time.Duration
	policy OIDCAccessPolicy
}

func NewPostgresStore(db sessionDB, config SessionConfig) (*PostgresStore, error) {
	if db == nil {
		return nil, ErrStoreUnavailable
	}
	if err := config.validate(); err != nil {
		return nil, err
	}
	return &PostgresStore{db: db, idle: config.IdleTimeout}, nil
}

func tokenHash(token string) []byte {
	hash := sha256.Sum256([]byte(token))
	return hash[:]
}

func validToken(token string) bool {
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(token)
	return err == nil && len(decoded) == 32 && len(token) == 43
}

// Rotation is atomic: an insert failure rolls back deletion of the old session.
// Only hashes, never raw cookie values, reach PostgreSQL.
func (s *PostgresStore) addSession(ctx context.Context, identity Identity, expires time.Time, previous string) (string, error) {
	if s.policy != nil {
		return s.policyLogin(ctx, identity, expires, previous, nil)
	}
	if identity.Validate() != nil || identity.Provider != OIDC || !time.Now().Before(expires) {
		return "", errors.New("invalid session")
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	token := oauth2.GenerateVerifier()
	_, err := s.db.Exec(ctx, `WITH revoked AS (
		DELETE FROM framework.sessions WHERE token_hash = $1
	) INSERT INTO framework.sessions
		(token_hash, issuer, subject, email, email_verified, display_name, provider, expires_at)
		VALUES ($2, $3, $4, $5, $6, $7, $8, $9)`,
		tokenHash(previous), tokenHash(token), identity.Issuer, identity.Subject,
		identity.Email, identity.EmailVerified, identity.DisplayName, string(identity.Provider), expires)
	if err != nil {
		return "", ErrStoreUnavailable
	}
	return token, nil
}

// Check expiration and touch activity atomically. A deleted row cannot be
// resurrected by a concurrent lookup. PostgreSQL supplies the activity clock.
func (s *PostgresStore) identity(ctx context.Context, token string) (Identity, error) {
	if s.policy != nil {
		return s.policySession(ctx, token, nil)
	}
	if !validToken(token) {
		return Identity{}, ErrUnauthenticated
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	var identity Identity
	err := s.db.QueryRow(ctx, `UPDATE framework.sessions
		SET last_activity_at = GREATEST(last_activity_at, clock_timestamp())
		WHERE token_hash = $1 AND expires_at > clock_timestamp()
		AND last_activity_at > clock_timestamp() - ($2::double precision * interval '1 second')
		RETURNING issuer, subject, email, email_verified, display_name, provider`,
		tokenHash(token), s.idle.Seconds()).Scan(&identity.Issuer, &identity.Subject, &identity.Email,
		&identity.EmailVerified, &identity.DisplayName, &identity.Provider)
	if errors.Is(err, pgx.ErrNoRows) {
		return Identity{}, ErrUnauthenticated
	}
	if err != nil || identity.Validate() != nil {
		return Identity{}, ErrStoreUnavailable
	}
	return identity, nil
}

func (s *PostgresStore) deleteSession(ctx context.Context, token string) error {
	if !validToken(token) {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	if _, err := s.db.Exec(ctx, `DELETE FROM framework.sessions WHERE token_hash = $1`, tokenHash(token)); err != nil {
		return ErrStoreUnavailable
	}
	return nil
}

func (s *PostgresStore) addFlow(ctx context.Context, flow loginFlow) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	token := oauth2.GenerateVerifier()
	_, err := s.db.Exec(ctx, `INSERT INTO framework.oidc_login_flows
		(token_hash, state_hash, nonce, pkce_verifier, expires_at) VALUES ($1, $2, $3, $4, $5)`,
		tokenHash(token), tokenHash(flow.State), flow.Nonce, flow.Verifier, flow.Expires)
	if err != nil {
		return "", ErrStoreUnavailable
	}
	return token, nil
}

func (s *PostgresStore) takeFlow(ctx context.Context, token, state string) (loginFlow, error) {
	if !validToken(token) {
		return loginFlow{}, ErrUnauthenticated
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	var flow loginFlow
	var hash []byte
	var unexpired bool
	err := s.db.QueryRow(ctx, `DELETE FROM framework.oidc_login_flows WHERE token_hash = $1
		RETURNING state_hash, nonce, pkce_verifier, expires_at, expires_at > clock_timestamp()`,
		tokenHash(token)).Scan(&hash, &flow.Nonce, &flow.Verifier, &flow.Expires, &unexpired)
	if errors.Is(err, pgx.ErrNoRows) {
		return loginFlow{}, ErrUnauthenticated
	}
	if err != nil {
		return loginFlow{}, ErrStoreUnavailable
	}
	if !unexpired || subtle.ConstantTimeCompare(hash, tokenHash(state)) != 1 {
		return loginFlow{}, ErrUnauthenticated
	}
	return flow, nil
}
