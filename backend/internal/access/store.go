// Package access applies database-backed authorization to verified identities.
package access

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"
	"unicode"

	"github.com/bmoheeputh-sudo/go-web-framework/backend/internal/auth"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	AdminManage  = "admin.manage"
	AccountRead  = "accounts.read"
	AccountWrite = "accounts.write"
	mutationLock = 78541705
)

var (
	ErrDenied      = errors.New("access denied")
	ErrInvalid     = errors.New("invalid request")
	ErrConflict    = errors.New("change conflicts with current state")
	ErrUnavailable = errors.New("authorization temporarily unavailable")
)

type User struct {
	ID          string   `json:"id"`
	Issuer      string   `json:"issuer"`
	Subject     string   `json:"subject"`
	Email       string   `json:"email"`
	DisplayName string   `json:"display_name"`
	Active      bool     `json:"active"`
	Roles       []string `json:"roles"`
	Permissions []string `json:"permissions"`
	AccountIDs  []string `json:"account_ids"`
}
type Account struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Active bool   `json:"active"`
}
type Role struct {
	Name        string   `json:"name"`
	Permissions []string `json:"permissions"`
}
type Audit struct {
	ID        string          `json:"id"`
	CreatedAt time.Time       `json:"created_at"`
	ActorID   string          `json:"actor_id"`
	Action    string          `json:"action"`
	TargetID  string          `json:"target_id"`
	Details   json.RawMessage `json:"details"`
}
type Store struct {
	pool                  *pgxpool.Pool
	permissionDefinitions map[string]PermissionDefinition
	modulePermissions     map[string]bool // immutable, copied during registry construction
}

func New(pool *pgxpool.Pool) *Store { return &Store{pool: pool} }

// Read-only check; live migrations are always a separate operator action.
func (s *Store) Check(ctx context.Context) error {
	for _, query := range []string{
		`SELECT id, issuer, subject, email, email_verified, display_name, provider, active, verified_at FROM framework.users LIMIT 0`,
		`SELECT name FROM framework.roles LIMIT 0`, `SELECT name FROM framework.permissions LIMIT 0`,
		`SELECT role, permission FROM framework.role_permissions LIMIT 0`, `SELECT user_id, role FROM framework.user_roles LIMIT 0`,
		`SELECT id, name, active FROM framework.accounts LIMIT 0`, `SELECT user_id, account_id FROM framework.user_accounts LIMIT 0`,
		`SELECT id, actor_user_id, action, target_id, details, created_at FROM framework.audit_log LIMIT 0`,
	} {
		if _, err := s.pool.Exec(ctx, query); err != nil {
			return ErrUnavailable
		}
	}
	return nil
}

const userSelect = `SELECT u.id::text, u.issuer, u.subject, u.email, u.display_name, u.active,
 ARRAY(SELECT role FROM framework.user_roles WHERE user_id=u.id ORDER BY role),
 ARRAY(SELECT DISTINCT rp.permission FROM framework.role_permissions rp JOIN framework.user_roles ur ON ur.role=rp.role WHERE ur.user_id=u.id ORDER BY rp.permission),
 ARRAY(SELECT account_id::text FROM framework.user_accounts WHERE user_id=u.id ORDER BY account_id)
 FROM framework.users u `

func scanUser(row pgx.Row) (User, error) {
	var u User
	err := row.Scan(&u.ID, &u.Issuer, &u.Subject, &u.Email, &u.DisplayName, &u.Active, &u.Roles, &u.Permissions, &u.AccountIDs)
	return u, err
}

// lookup is read-only: a denied permission check must not create or refresh users.
func (s *Store) lookup(ctx context.Context, identity auth.Identity) (User, error) {
	if identity.Validate() != nil {
		return User{}, ErrDenied
	}
	u, err := scanUser(s.pool.QueryRow(ctx, userSelect+`WHERE u.issuer=$1 AND u.subject=$2`, identity.Issuer, identity.Subject))
	if errors.Is(err, pgx.ErrNoRows) {
		return User{}, ErrDenied
	}
	if err != nil {
		return User{}, ErrUnavailable
	}
	if !u.Active {
		return User{}, ErrDenied
	}
	return u, nil
}

// Resolve registers/refreshes only through the authenticated self endpoint.
// It never updates an inactive user, roles, or account links. The identity comes
// from auth.Require, never a request body.
func (s *Store) Resolve(ctx context.Context, identity auth.Identity) (User, error) {
	if identity.Validate() != nil {
		return User{}, ErrDenied
	}
	var id string
	err := s.pool.QueryRow(ctx, `INSERT INTO framework.users(issuer,subject,email,email_verified,display_name,provider)
 VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(issuer,subject) DO UPDATE SET
 email=EXCLUDED.email,email_verified=EXCLUDED.email_verified,display_name=EXCLUDED.display_name,
 provider=EXCLUDED.provider,verified_at=clock_timestamp()
 WHERE framework.users.active RETURNING id::text`, identity.Issuer, identity.Subject, identity.Email, identity.EmailVerified, identity.DisplayName, string(identity.Provider)).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return User{}, ErrDenied
	}
	if err != nil {
		return User{}, ErrUnavailable
	}
	u, err := scanUser(s.pool.QueryRow(ctx, userSelect+`WHERE u.id=$1`, id))
	if err != nil {
		return User{}, ErrUnavailable
	}
	if !u.Active {
		return User{}, ErrDenied
	}
	return u, nil
}

type querier interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

func (s *Store) allowed(ctx context.Context, q querier, userID, permission, accountID string) error {
	if permission != AdminManage && permission != AccountRead && permission != AccountWrite && !s.modulePermissions[permission] {
		return ErrDenied
	}
	var ok bool
	err := q.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM framework.users u
 JOIN framework.user_roles ur ON ur.user_id=u.id JOIN framework.role_permissions rp ON rp.role=ur.role
 WHERE u.id=$1 AND u.active AND rp.permission=$2
 AND ($3='' OR EXISTS(SELECT 1 FROM framework.user_accounts ua JOIN framework.accounts a ON a.id=ua.account_id
 WHERE ua.user_id=u.id AND a.id::text=$3 AND a.active)))`, userID, permission, accountID).Scan(&ok)
	if err != nil {
		return ErrUnavailable
	}
	if !ok {
		return ErrDenied
	}
	return nil
}
func (s *Store) Allowed(ctx context.Context, id, permission, accountID string) error {
	return s.allowed(ctx, s.pool, id, permission, accountID)
}
func validID(id string) bool { var v pgtype.UUID; return len(id) == 36 && v.Scan(id) == nil && v.Valid }
func validName(name string) bool {
	return name != "" && len([]rune(name)) <= 200 && strings.TrimSpace(name) == name && !strings.ContainsFunc(name, unicode.IsControl)
}
func dbError(err error) error {
	if err == nil {
		return nil
	}
	var pg *pgconn.PgError
	if errors.As(err, &pg) && (pg.Code == "23503" || pg.Code == "23505" || pg.Code == "23514" || pg.Code == "22P02") {
		return ErrInvalid
	}
	return ErrUnavailable
}

// Serializing mutations makes permission revocation, last-admin guards and writes
// atomic relative to each other. Authorization is rechecked after acquiring the lock.
func (s *Store) mutate(ctx context.Context, actor, permission, accountID string, fn func(pgx.Tx) error) error {
	return s.withMutation(ctx, func(tx pgx.Tx) error {
		return s.allowed(ctx, tx, actor, permission, accountID)
	}, fn)
}

// withMutation is shared by core and module writes, including revocations.
func (s *Store) withMutation(ctx context.Context, authorize func(pgx.Tx) error, fn func(pgx.Tx) error) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return ErrUnavailable
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = tx.Rollback(cleanup)
	}()
	if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, mutationLock); err != nil {
		return ErrUnavailable
	}
	if err = authorize(tx); err != nil {
		return err
	}
	if err = fn(tx); err != nil {
		return err
	}
	return dbError(tx.Commit(ctx))
}
func audit(ctx context.Context, tx pgx.Tx, actor, action, target string, details any) error {
	data, err := json.Marshal(details)
	if err != nil {
		return ErrUnavailable
	}
	_, err = tx.Exec(ctx, `INSERT INTO framework.audit_log(actor_user_id,action,target_id,details) VALUES($1,$2,$3,$4)`, actor, action, target, data)
	return dbError(err)
}
func lastAdminGuard(ctx context.Context, tx pgx.Tx) error {
	var exists bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM framework.users u JOIN framework.user_roles r ON r.user_id=u.id JOIN framework.role_permissions rp ON rp.role=r.role WHERE u.active AND r.role='Admin' AND rp.permission='admin.manage')`).Scan(&exists); err != nil {
		return ErrUnavailable
	}
	if !exists {
		return ErrConflict
	}
	return nil
}
func (s *Store) SetRoles(ctx context.Context, actor, target string, roles []string) error {
	if !validID(target) || len(roles) > 3 {
		return ErrInvalid
	}
	if strings.EqualFold(target, actor) {
		return ErrDenied
	}
	seen := map[string]bool{}
	for _, r := range roles {
		if (r != "Admin" && r != "User" && r != "Viewer") || seen[r] {
			return ErrInvalid
		}
		seen[r] = true
	}
	return s.mutate(ctx, actor, AdminManage, "", func(tx pgx.Tx) error {
		return setRolesTx(ctx, tx, actor, target, roles)
	})
}

// Caller must hold the shared mutation lock and have revalidated admin.manage.
func setRolesTx(ctx context.Context, tx pgx.Tx, actor, target string, roles []string) error {
	before, err := scanUser(tx.QueryRow(ctx, userSelect+`WHERE u.id=$1`, target))
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrInvalid
	}
	if err != nil {
		return ErrUnavailable
	}
	if _, err = tx.Exec(ctx, `DELETE FROM framework.user_roles WHERE user_id=$1`, target); err != nil {
		return ErrUnavailable
	}
	for _, role := range roles {
		if _, err = tx.Exec(ctx, `INSERT INTO framework.user_roles(user_id,role) VALUES($1,$2)`, target, role); err != nil {
			return dbError(err)
		}
	}
	if err = lastAdminGuard(ctx, tx); err != nil {
		return err
	}
	return audit(ctx, tx, actor, "user.roles", target, map[string]any{"before": before.Roles, "after": roles})
}
func (s *Store) SetActive(ctx context.Context, actor, target string, active bool) error {
	if !validID(target) {
		return ErrInvalid
	}
	if strings.EqualFold(target, actor) {
		return ErrDenied
	}
	return s.mutate(ctx, actor, AdminManage, "", func(tx pgx.Tx) error {
		var before bool
		if err := tx.QueryRow(ctx, `SELECT active FROM framework.users WHERE id=$1`, target).Scan(&before); errors.Is(err, pgx.ErrNoRows) {
			return ErrInvalid
		} else if err != nil {
			return ErrUnavailable
		}
		if _, err := tx.Exec(ctx, `UPDATE framework.users SET active=$2 WHERE id=$1`, target, active); err != nil {
			return ErrUnavailable
		}
		if err := lastAdminGuard(ctx, tx); err != nil {
			return err
		}
		return audit(ctx, tx, actor, "user.active", target, map[string]bool{"before": before, "after": active})
	})
}
func (s *Store) SetAccounts(ctx context.Context, actor, target string, ids []string) error {
	if !validID(target) || len(ids) > 100 {
		return ErrInvalid
	}
	seen := map[string]bool{}
	for _, id := range ids {
		if !validID(id) || seen[id] {
			return ErrInvalid
		}
		seen[id] = true
	}
	return s.mutate(ctx, actor, AdminManage, "", func(tx pgx.Tx) error {
		before, err := scanUser(tx.QueryRow(ctx, userSelect+`WHERE u.id=$1`, target))
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrInvalid
		}
		if err != nil {
			return ErrUnavailable
		}
		if _, err = tx.Exec(ctx, `DELETE FROM framework.user_accounts WHERE user_id=$1`, target); err != nil {
			return ErrUnavailable
		}
		for _, id := range ids {
			if _, err = tx.Exec(ctx, `INSERT INTO framework.user_accounts(user_id,account_id) VALUES($1,$2)`, target, id); err != nil {
				return dbError(err)
			}
		}
		return audit(ctx, tx, actor, "user.accounts", target, map[string]any{"before": before.AccountIDs, "after": ids})
	})
}
func (s *Store) SaveAccount(ctx context.Context, actor, id, name string, active bool) (Account, error) {
	a := Account{ID: id, Name: name, Active: active}
	if !validName(name) || (id != "" && !validID(id)) {
		return a, ErrInvalid
	}
	err := s.mutate(ctx, actor, AdminManage, "", func(tx pgx.Tx) error {
		var before *Account
		if id == "" {
			if err := tx.QueryRow(ctx, `INSERT INTO framework.accounts(name,active) VALUES($1,$2) RETURNING id::text`, name, active).Scan(&a.ID); err != nil {
				return dbError(err)
			}
		} else {
			before = &Account{ID: id}
			if err := tx.QueryRow(ctx, `SELECT name,active FROM framework.accounts WHERE id=$1`, id).Scan(&before.Name, &before.Active); errors.Is(err, pgx.ErrNoRows) {
				return ErrInvalid
			} else if err != nil {
				return ErrUnavailable
			}
			if _, err := tx.Exec(ctx, `UPDATE framework.accounts SET name=$2,active=$3 WHERE id=$1`, id, name, active); err != nil {
				return dbError(err)
			}
		}
		return audit(ctx, tx, actor, "account.save", a.ID, map[string]any{"before": before, "after": a})
	})
	return a, err
}
func (s *Store) RenameAccount(ctx context.Context, actor, id, name string) error {
	if !validID(id) || !validName(name) {
		return ErrInvalid
	}
	return s.mutate(ctx, actor, AccountWrite, id, func(tx pgx.Tx) error {
		var before string
		if err := tx.QueryRow(ctx, `SELECT name FROM framework.accounts WHERE id=$1`, id).Scan(&before); err != nil {
			return ErrUnavailable
		}
		if _, err := tx.Exec(ctx, `UPDATE framework.accounts SET name=$2 WHERE id=$1`, id, name); err != nil {
			return ErrUnavailable
		}
		return audit(ctx, tx, actor, "account.rename", id, map[string]string{"before": before, "after": name})
	})
}
func (s *Store) Users(ctx context.Context, offset int) ([]User, error) {
	rows, err := s.pool.Query(ctx, userSelect+`ORDER BY u.id LIMIT 100 OFFSET $1`, offset)
	if err != nil {
		return nil, ErrUnavailable
	}
	defer rows.Close()
	result := []User{}
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, ErrUnavailable
		}
		result = append(result, u)
	}
	return result, dbError(rows.Err())
}
func (s *Store) Accounts(ctx context.Context, userID string, offset int) ([]Account, error) {
	rows, err := s.pool.Query(ctx, `SELECT a.id::text,a.name,a.active FROM framework.accounts a
 WHERE $1='' OR (a.active AND EXISTS(SELECT 1 FROM framework.user_accounts ua WHERE ua.account_id=a.id AND ua.user_id::text=$1)) ORDER BY a.id LIMIT 100 OFFSET $2`, userID, offset)
	if err != nil {
		return nil, ErrUnavailable
	}
	defer rows.Close()
	result := []Account{}
	for rows.Next() {
		var a Account
		if err := rows.Scan(&a.ID, &a.Name, &a.Active); err != nil {
			return nil, ErrUnavailable
		}
		result = append(result, a)
	}
	return result, dbError(rows.Err())
}
func (s *Store) Account(ctx context.Context, id string) (Account, error) {
	var a Account
	err := s.pool.QueryRow(ctx, `SELECT id::text,name,active FROM framework.accounts WHERE id=$1`, id).Scan(&a.ID, &a.Name, &a.Active)
	return a, dbError(err)
}
func (s *Store) Roles(ctx context.Context) ([]Role, error) {
	rows, err := s.pool.Query(ctx, `SELECT name,ARRAY(SELECT permission FROM framework.role_permissions WHERE role=r.name ORDER BY permission) FROM framework.roles r ORDER BY name`)
	if err != nil {
		return nil, ErrUnavailable
	}
	defer rows.Close()
	result := []Role{}
	for rows.Next() {
		var r Role
		if err := rows.Scan(&r.Name, &r.Permissions); err != nil {
			return nil, ErrUnavailable
		}
		result = append(result, r)
	}
	return result, dbError(rows.Err())
}
func (s *Store) Audit(ctx context.Context, offset int) ([]Audit, error) {
	rows, err := s.pool.Query(ctx, `SELECT id::text,created_at,actor_user_id::text,action,target_id,details FROM framework.audit_log ORDER BY framework.audit_log.id DESC LIMIT 100 OFFSET $1`, offset)
	if err != nil {
		return nil, ErrUnavailable
	}
	defer rows.Close()
	result := []Audit{}
	for rows.Next() {
		var a Audit
		if err := rows.Scan(&a.ID, &a.CreatedAt, &a.ActorID, &a.Action, &a.TargetID, &a.Details); err != nil {
			return nil, ErrUnavailable
		}
		result = append(result, a)
	}
	return result, dbError(rows.Err())
}
