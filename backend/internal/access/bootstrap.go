package access

import (
	"context"
	"errors"
	"github.com/jackc/pgx/v5"
)

// Bootstrap is an operator-only operation. Runtime DB grants intentionally exclude
// admin_bootstrap. The target must already exist after a verified authentication.
func (s *Store) Bootstrap(ctx context.Context, issuer, subject, environment string) error {
	if issuer == "" || subject == "" {
		return ErrInvalid
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return ErrUnavailable
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, mutationLock); err != nil {
		return ErrUnavailable
	}
	var used bool
	if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM framework.admin_bootstrap) OR EXISTS(SELECT 1 FROM framework.user_roles WHERE role='Admin')`).Scan(&used); err != nil {
		return ErrUnavailable
	}
	if used {
		return ErrConflict
	}
	var id, provider string
	var active bool
	err = tx.QueryRow(ctx, `SELECT id::text,provider,active FROM framework.users WHERE issuer=$1 AND subject=$2 AND verified_at IS NOT NULL`, issuer, subject).Scan(&id, &provider, &active)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrDenied
	}
	if err != nil {
		return ErrUnavailable
	}
	if !active || (provider == "local_dev" && environment != "development") {
		return ErrDenied
	}
	if _, err = tx.Exec(ctx, `INSERT INTO framework.user_roles(user_id,role) VALUES($1,'Admin')`, id); err != nil {
		return ErrUnavailable
	}
	if _, err = tx.Exec(ctx, `INSERT INTO framework.admin_bootstrap(singleton,user_id) VALUES(TRUE,$1)`, id); err != nil {
		return ErrUnavailable
	}
	if err = audit(ctx, tx, id, "admin.bootstrap", id, map[string]string{"source": "operator command"}); err != nil {
		return err
	}
	return dbError(tx.Commit(ctx))
}
