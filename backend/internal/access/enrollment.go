package access

import (
	"context"
	"slices"

	"github.com/bmoheeputh-sudo/go-web-framework/backend/internal/auth"
	"github.com/jackc/pgx/v5"
)

// EnrollVerifiedOIDCIdentity is a trusted-repository helper, not an HTTP API.
// Call only inside AdminTransaction after checking durable verifier evidence.
// It never associates by email, replaces roles, reactivates users, or links accounts.
func EnrollVerifiedOIDCIdentity(ctx context.Context, tx pgx.Tx, actor User, identity auth.Identity, role string) (User, error) {
	if identity.Validate() != nil || identity.Provider != auth.OIDC || (role != "Admin" && role != "User" && role != "Viewer") {
		return User{}, ErrInvalid
	}
	_, err := tx.Exec(ctx, `INSERT INTO framework.users(issuer,subject,provider) VALUES($1,$2,'oidc') ON CONFLICT(issuer,subject) DO NOTHING`, identity.Issuer, identity.Subject)
	if err != nil {
		return User{}, ErrUnavailable
	}
	u, err := scanUser(tx.QueryRow(ctx, userSelect+`WHERE u.issuer=$1 AND u.subject=$2 FOR UPDATE`, identity.Issuer, identity.Subject))
	if err != nil {
		return User{}, ErrUnavailable
	}
	var provider string
	if err := tx.QueryRow(ctx, `SELECT provider FROM framework.users WHERE id=$1`, u.ID).Scan(&provider); err != nil {
		return User{}, ErrUnavailable
	}
	if !u.Active || provider != "oidc" || u.ID == actor.ID {
		return User{}, ErrDenied
	}
	if slices.Contains(u.Roles, role) {
		return User{}, ErrConflict
	}
	roles := append(slices.Clone(u.Roles), role)
	slices.Sort(roles)
	if err := setRolesTx(ctx, tx, actor.ID, u.ID, roles); err != nil {
		return User{}, err
	}
	return scanUser(tx.QueryRow(ctx, userSelect+`WHERE u.id=$1`, u.ID))
}
