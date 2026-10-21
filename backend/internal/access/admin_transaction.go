package access

import (
	"context"
	"time"

	"github.com/bmoheeputh-sudo/go-web-framework/backend/internal/auth"
	"github.com/jackc/pgx/v5"
)

// AdminTransaction is for trusted internal repositories, never module callbacks.
// The actor comes only from verified framework context. Authorization and identity
// are rechecked after the existing shared mutation lock; callbacks own no commit.
func (s *Store) AdminTransaction(ctx context.Context, fn func(context.Context, pgx.Tx, User) error) error {
	if s == nil || s.pool == nil || fn == nil {
		return ErrUnavailable
	}
	identity, verified := auth.IdentityFromContext(ctx)
	actor, present := Principal(ctx)
	if !verified || !present || identity.Validate() != nil || !actor.Active || actor.Issuer != identity.Issuer || actor.Subject != identity.Subject {
		return ErrDenied
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return s.withMutation(ctx, func(tx pgx.Tx) error {
		var matched bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM framework.users WHERE id=$1 AND issuer=$2 AND subject=$3 AND active)`, actor.ID, identity.Issuer, identity.Subject).Scan(&matched); err != nil {
			return ErrUnavailable
		}
		if !matched {
			return ErrDenied
		}
		return s.allowed(ctx, tx, actor.ID, AdminManage, "")
	}, func(tx pgx.Tx) error { return fn(ctx, tx, actor) })
}

// RecordAudit reuses the core audit insert. Trusted repositories must supply
// fixed, reviewed detail structs, never request bodies or secrets.
func RecordAudit(ctx context.Context, tx pgx.Tx, actor, action, target string, details any) error {
	return audit(ctx, tx, actor, action, target, details)
}

// NotificationWorkerTransaction is a trusted notification-repository primitive.
// It has no HTTP registration and does not manufacture an administrator context.
// Its caller exposes only queue/attempt operations, never users, roles or approvals.
// Provider I/O must occur after this transaction has definitively committed.
func (s *Store) NotificationWorkerTransaction(ctx context.Context, fn func(context.Context, pgx.Tx) error) error {
	if s == nil || s.pool == nil || fn == nil {
		return ErrUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return s.withMutation(ctx, func(pgx.Tx) error { return nil }, func(tx pgx.Tx) error { return fn(ctx, tx) })
}
