package auth

import (
	"context"
	"crypto/subtle"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"golang.org/x/oauth2"
)

// databaseBoundStore is private: callers cannot choose bindings per operation.
// Binding admission and expiry are predicates of the mutation itself, before
// touching activity. The lease also fences in-flight callbacks after retirement.
type databaseBoundStore struct {
	base    *PostgresStore
	binding Binding
	lease   *providerLease
}

const bindingPredicate = `binding_source='database' AND deployment_id=$3 AND environment=$4 AND revision_id=$5 AND activation_generation=$6 AND issuer=$7 AND client_id=$8 AND flow_purpose='login'`

func (s *databaseBoundStore) args(token string, second any) []any {
	b := s.binding
	return []any{tokenHash(token), second, b.DeploymentID, b.Environment, b.RevisionID, b.ActivationGeneration, b.Issuer, b.ClientID}
}
func (s *databaseBoundStore) identity(ctx context.Context, token string) (Identity, error) {
	if s.base.policy != nil {
		return s.base.policySession(ctx, token, s)
	}
	if !validToken(token) {
		return Identity{}, ErrUnauthenticated
	}
	s.lease.mu.Lock()
	defer s.lease.mu.Unlock()
	if !s.lease.allowedLocked(false) {
		return Identity{}, ErrUnauthenticated
	}
	deadline := s.lease.until
	if deadline.IsZero() {
		deadline = time.Date(9999, 1, 1, 0, 0, 0, 0, time.UTC)
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	args := append(s.args(token, s.base.idle.Seconds()), deadline)
	var identity Identity
	err := s.base.db.QueryRow(ctx, `WITH `+authoritySQL(3, 4, 5, 6)+` UPDATE framework.sessions SET last_activity_at=GREATEST(last_activity_at,clock_timestamp()),expires_at=LEAST(expires_at,$9,(SELECT deadline FROM policy))
 WHERE token_hash=$1 AND expires_at>clock_timestamp() AND last_activity_at>clock_timestamp()-($2::double precision*interval '1 second') AND $9>clock_timestamp() AND EXISTS(SELECT 1 FROM policy) AND `+bindingPredicate+`
 RETURNING issuer,subject,email,email_verified,display_name,provider`, args...).Scan(&identity.Issuer, &identity.Subject, &identity.Email, &identity.EmailVerified, &identity.DisplayName, &identity.Provider)
	if errors.Is(err, pgx.ErrNoRows) {
		return Identity{}, ErrUnauthenticated
	}
	if err != nil || identity.Validate() != nil {
		return Identity{}, ErrStoreUnavailable
	}
	return identity, nil
}
func (s *databaseBoundStore) addSession(ctx context.Context, identity Identity, expires time.Time, previous string) (string, error) {
	if s.base.policy != nil {
		return s.base.policyLogin(ctx, identity, expires, previous, s)
	}
	deadline, ok := s.lease.deadline(false)
	if !ok || identity.Validate() != nil || identity.Provider != OIDC || identity.Issuer != s.binding.Issuer {
		return "", ErrUnauthenticated
	}
	if deadline.Before(expires) {
		expires = deadline
	}
	if !time.Now().Before(expires) {
		return "", ErrUnauthenticated
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	// Publication and deadline checks cannot race this final credential write.
	s.lease.mu.Lock()
	defer s.lease.mu.Unlock()
	if !s.lease.allowedLocked(false) {
		return "", ErrUnauthenticated
	}
	if !s.lease.until.IsZero() && s.lease.until.Before(expires) {
		expires = s.lease.until
	}
	token := oauth2.GenerateVerifier()
	b := s.binding

	flowExpiry := expires
	if original, ok := ctx.Value(flowExpiryKey{}).(time.Time); ok {
		flowExpiry = original
	}
	var stored []byte
	err := s.base.db.QueryRow(ctx, `WITH `+authoritySQL(9, 10, 11, 12)+`, created AS (
 INSERT INTO framework.sessions(token_hash,issuer,subject,email,email_verified,display_name,provider,expires_at,binding_source,deployment_id,environment,revision_id,activation_generation,client_id,flow_purpose)
 SELECT $2,$3,$4,$5,$6,$7,'oidc',LEAST($8,(SELECT deadline FROM policy)),'database',$9,$10,$11,$12,$13,'login' WHERE $8>clock_timestamp() AND $14::timestamptz>clock_timestamp() AND EXISTS(SELECT 1 FROM policy) RETURNING token_hash
 ), revoked AS (DELETE FROM framework.sessions WHERE token_hash=$1 AND deployment_id=$9 AND environment=$10 AND EXISTS(SELECT 1 FROM created)) SELECT token_hash FROM created`, tokenHash(previous), tokenHash(token), identity.Issuer, identity.Subject, identity.Email, identity.EmailVerified, identity.DisplayName, expires, b.DeploymentID, b.Environment, b.RevisionID, b.ActivationGeneration, b.ClientID, flowExpiry).Scan(&stored)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrUnauthenticated
	}
	if err != nil {
		return "", ErrStoreUnavailable
	}

	return token, nil
}
func (s *databaseBoundStore) deleteSession(ctx context.Context, token string) error {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	// Scope-restricted logout; it cannot revoke another deployment's credentials.
	_, err := s.base.db.Exec(ctx, `DELETE FROM framework.sessions WHERE token_hash=$1 AND $2::boolean AND `+bindingPredicate, s.args(token, true)...)
	if err != nil {
		return ErrStoreUnavailable
	}
	return nil
}
func (s *databaseBoundStore) addFlow(ctx context.Context, flow loginFlow) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	s.lease.mu.Lock()
	defer s.lease.mu.Unlock()
	if !s.lease.allowedLocked(true) {
		return "", ErrUnauthenticated
	}
	token := oauth2.GenerateVerifier()
	b := s.binding
	var stored []byte
	err := s.base.db.QueryRow(ctx, `WITH `+authoritySQL(6, 7, 8, 9)+` INSERT INTO framework.oidc_login_flows(token_hash,state_hash,nonce,pkce_verifier,expires_at,binding_source,deployment_id,environment,revision_id,activation_generation,issuer,client_id,flow_purpose)
 SELECT $1,$2,$3,$4,LEAST($5::timestamptz,clock_timestamp()+interval '5 minutes'),'database',$6,$7,$8,$9,$10,$11,'login' WHERE EXISTS(SELECT 1 FROM policy WHERE current) RETURNING token_hash`, tokenHash(token), tokenHash(flow.State), flow.Nonce, flow.Verifier, flow.Expires, b.DeploymentID, b.Environment, b.RevisionID, b.ActivationGeneration, b.Issuer, b.ClientID).Scan(&stored)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrUnauthenticated
	}
	if err != nil {
		return "", ErrStoreUnavailable
	}
	return token, nil
}
func (s *databaseBoundStore) takeFlow(ctx context.Context, token, state string) (loginFlow, error) {
	if !validToken(token) {
		return loginFlow{}, ErrUnauthenticated
	}
	deadline, ok := s.lease.deadline(false)
	if !ok {
		return loginFlow{}, ErrUnauthenticated
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	var flow loginFlow
	var hash []byte
	var fresh bool
	args := append(s.args(token, true), deadline)
	err := s.base.db.QueryRow(ctx, `WITH `+authoritySQL(3, 4, 5, 6)+` DELETE FROM framework.oidc_login_flows WHERE token_hash=$1 AND $2::boolean AND EXISTS(SELECT 1 FROM policy) AND `+bindingPredicate+` RETURNING state_hash,nonce,pkce_verifier,LEAST(expires_at,$9,(SELECT deadline FROM policy)),expires_at>clock_timestamp() AND $9>clock_timestamp()`, args...).Scan(&hash, &flow.Nonce, &flow.Verifier, &flow.Expires, &fresh)
	if errors.Is(err, pgx.ErrNoRows) {
		return loginFlow{}, ErrUnauthenticated
	}
	if err != nil {
		return loginFlow{}, ErrStoreUnavailable
	}
	if !fresh || subtle.ConstantTimeCompare(hash, tokenHash(state)) != 1 {
		return loginFlow{}, ErrUnauthenticated
	}
	return flow, nil
}
