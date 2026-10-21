package auth

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
)

// OIDCAccessPolicy is supplied by the access layer, using trusted deployment
// configuration. Its transaction includes admission and the credential write.
// Verification-only flows never call addSession and therefore never provision.
type OIDCAccessPolicy interface {
	Login(context.Context, Identity, Binding, func(context.Context, pgx.Tx) error) error
	Session(context.Context, func(context.Context, pgx.Tx) (Identity, error)) (Identity, error)
}

// WithAccessPolicy returns a copy; published stores are never mutated.
func (s *PostgresStore) WithAccessPolicy(policy OIDCAccessPolicy) *PostgresStore {
	copy := *s
	copy.policy = policy
	return &copy
}

func (s *PostgresStore) transactionStore(tx pgx.Tx) *PostgresStore {
	copy := *s
	copy.db, copy.policy = tx, nil
	return &copy
}

func (s *PostgresStore) policyLogin(ctx context.Context, identity Identity, expires time.Time, previous string, bound *databaseBoundStore) (string, error) {
	var token string
	// Only the private prepared database store supplies this binding. Never
	// infer one from the current head or request parameters for legacy logins.
	var binding Binding
	if bound != nil {
		binding = bound.binding
	}
	err := s.policy.Login(ctx, identity, binding, func(ctx context.Context, tx pgx.Tx) error {
		var err error
		store := s.transactionStore(tx)
		if bound == nil {
			token, err = store.addSession(ctx, identity, expires, previous)
		} else {
			copy := *bound
			copy.base = store
			token, err = copy.addSession(ctx, identity, expires, previous)
		}
		return err
	})
	if err != nil {
		return "", err
	}
	return token, nil
}

func (s *PostgresStore) policySession(ctx context.Context, token string, bound *databaseBoundStore) (Identity, error) {
	return s.policy.Session(ctx, func(ctx context.Context, tx pgx.Tx) (Identity, error) {
		store := s.transactionStore(tx)
		if bound == nil {
			return store.identity(ctx, token)
		}
		copy := *bound
		copy.base = store
		return copy.identity(ctx, token)
	})
}
