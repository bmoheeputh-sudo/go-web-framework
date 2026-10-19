package access

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/bmoheeputh-sudo/go-web-framework/backend/internal/auth"
	"github.com/bmoheeputh-sudo/go-web-framework/backend/module"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

var auditFieldName = regexp.MustCompile(`^[a-z][a-z0-9_]{0,39}$`)

// CopyAuditPolicy validates the registration-time schema and takes an immutable
// snapshot. Field meanings and enum labels must be reviewed for sensitive data.
func CopyAuditPolicy(namespace string, policy module.AuditPolicy) (module.AuditPolicy, error) {
	if !ValidModulePermission(policy.Action) || !strings.HasPrefix(policy.Action, namespace+".") || strings.Count(policy.Action, ".") < 2 || len(policy.Fields) > 16 {
		return module.AuditPolicy{}, module.ErrAudit
	}
	result := module.AuditPolicy{Action: policy.Action, Fields: make(map[string]module.AuditField)}
	for name, field := range policy.Fields {
		if !auditFieldName.MatchString(name) || name == "account_id" {
			return module.AuditPolicy{}, module.ErrAudit
		}
		for _, forbidden := range []string{"password", "token", "secret", "credential", "body", "response", "cookie", "authorization", "key"} {
			if strings.Contains(name, forbidden) {
				return module.AuditPolicy{}, module.ErrAudit
			}
		}
		switch field.Kind {
		case module.AuditUUID, module.AuditBool, module.AuditInteger:
			if len(field.Values) != 0 {
				return module.AuditPolicy{}, module.ErrAudit
			}
		case module.AuditEnum:
			if len(field.Values) == 0 || len(field.Values) > 32 {
				return module.AuditPolicy{}, module.ErrAudit
			}
			for _, value := range field.Values {
				if value == "" || len(value) > 512 || strings.ContainsAny(value, "\x00\r\n") {
					return module.AuditPolicy{}, module.ErrAudit
				}
			}
		default:
			return module.AuditPolicy{}, module.ErrAudit
		}
		field.Values = slices.Clone(field.Values)
		result.Fields[name] = field
	}
	return result, nil
}

func auditPayload(policy module.AuditPolicy, account, target string, details module.AuditDetails) (json.RawMessage, error) {
	if !validID(target) || len(details) != len(policy.Fields) {
		return nil, module.ErrAudit
	}
	safe := make(map[string]any, len(details)+1)
	for name, field := range policy.Fields {
		value, exists := details[name]
		if !exists {
			return nil, module.ErrAudit
		}
		switch field.Kind {
		case module.AuditUUID:
			v, ok := value.(string)
			if !ok || !validID(v) {
				return nil, module.ErrAudit
			}
			safe[name] = strings.ToLower(v)
		case module.AuditEnum:
			v, ok := value.(string)
			if !ok || !slices.Contains(field.Values, v) {
				return nil, module.ErrAudit
			}
			safe[name] = v
		case module.AuditBool:
			v, ok := value.(bool)
			if !ok {
				return nil, module.ErrAudit
			}
			safe[name] = v
		case module.AuditInteger:
			switch v := value.(type) {
			case int:
				safe[name] = v
			case int64:
				safe[name] = v
			default:
				return nil, module.ErrAudit
			}
		default:
			return nil, module.ErrAudit
		}
	}
	if account != "" {
		safe["account_id"] = account
	}
	data, err := json.Marshal(safe)
	if err != nil || len(data) > module.MaxAuditBytes {
		return nil, module.ErrAudit
	}
	return data, nil
}

type mutationBindingKey struct{}
type boundMutation struct {
	store               *Store
	request             context.Context
	actor               User
	identity            auth.Identity
	permission, account string
	policy              module.AuditPolicy
}

// BindMutation is constructed only by the registry, inside auth.Require,
// ProtectWrites and Store.Require. It creates a short-lived request capability.
func (s *Store) BindMutation(permission, accountParameter string, policy module.AuditPolicy, next module.MutationHandler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		identity, ok := auth.IdentityFromContext(r.Context())
		if !ok || identity.Validate() != nil {
			respond(w, 401, map[string]string{"error": module.ErrUnauthenticated.Error()})
			return
		}
		actor, ok := Principal(r.Context())
		if !ok || !actor.Active || !validID(actor.ID) || actor.Issuer != identity.Issuer || actor.Subject != identity.Subject {
			respond(w, 403, map[string]string{"error": module.ErrUnauthenticated.Error()})
			return
		}
		if s == nil || !s.modulePermissions[permission] {
			respond(w, 403, map[string]string{"error": module.ErrPermissionDenied.Error()})
			return
		}
		account := ""
		if accountParameter != "" {
			account = r.PathValue(accountParameter)
			if !validID(account) {
				respond(w, 400, map[string]string{"error": module.ErrInvalidAccount.Error()})
				return
			}
			account = strings.ToLower(account)
		}
		ctx, cancel := context.WithCancel(r.Context())
		defer cancel() // retained managers cannot outlive their request
		manager := &boundMutation{store: s, request: ctx, actor: actor, identity: identity, permission: permission, account: account, policy: policy}
		ctx = context.WithValue(ctx, mutationBindingKey{}, manager)
		next(w, r.WithContext(ctx), manager)
	})
}

func (m *boundMutation) MutateAccount(ctx context.Context, fn module.AccountMutateFunc) error {
	if m.account == "" || fn == nil {
		return module.ErrScope
	}
	return m.run(ctx, func(ctx context.Context, tx module.Transaction) (string, module.AuditDetails, error) {
		return fn(ctx, tx, m.account)
	})
}
func (m *boundMutation) MutateGlobal(ctx context.Context, fn module.MutateFunc) error {
	if m.account != "" || fn == nil {
		return module.ErrScope
	}
	return m.run(ctx, fn)
}
func (m *boundMutation) run(caller context.Context, fn module.MutateFunc) error {
	if caller == nil || caller.Value(mutationBindingKey{}) != m {
		return module.ErrScope
	}
	identity, ok := auth.IdentityFromContext(caller)
	actor, present := Principal(caller)
	if !ok || !present || identity != m.identity || actor.ID != m.actor.ID || actor.Issuer != m.actor.Issuer || actor.Subject != m.actor.Subject || !actor.Active {
		return module.ErrUnauthenticated
	}
	if !m.store.modulePermissions[m.permission] {
		return module.ErrPermissionDenied
	}
	ctx, cancel := context.WithTimeout(caller, 5*time.Second)
	defer cancel()
	stop := context.AfterFunc(m.request, cancel)
	defer stop()
	if err := m.request.Err(); err != nil {
		return module.ErrCanceled
	}
	if err := ctx.Err(); err != nil {
		return transactionContextError(err)
	}
	err := m.store.withMutation(ctx, func(tx pgx.Tx) error {
		var active bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM framework.users WHERE id=$1 AND issuer=$2 AND subject=$3 AND active)`, m.actor.ID, m.identity.Issuer, m.identity.Subject).Scan(&active); err != nil {
			return module.ErrUnavailable
		}
		if !active {
			return module.ErrUnauthenticated
		}
		if err := m.store.allowed(ctx, tx, m.actor.ID, m.permission, ""); err != nil {
			if errors.Is(err, ErrDenied) {
				return module.ErrPermissionDenied
			}
			return module.ErrUnavailable
		}
		if m.account != "" {
			if err := m.store.allowed(ctx, tx, m.actor.ID, m.permission, m.account); err != nil {
				if errors.Is(err, ErrDenied) {
					return module.ErrAccountDenied
				}
				return module.ErrUnavailable
			}
		}
		return nil
	}, func(tx pgx.Tx) error {
		target, details, err := fn(ctx, moduleTransaction{tx: tx, ctx: ctx})
		if err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return transactionContextError(err)
			}
			return module.ErrMutation // never disclose callback/database errors
		}
		data, err := auditPayload(m.policy, m.account, target, details)
		if err != nil {
			return module.ErrAudit
		}
		if err := audit(ctx, tx, m.actor.ID, m.policy.Action, strings.ToLower(target), data); err != nil {
			return module.ErrAudit
		}
		return nil
	})
	// A confirmed commit is successful even if the deadline fires immediately
	// afterwards. Commit failures are never retried (their outcome may be unknown).
	if err == nil {
		return nil
	}
	if ctx.Err() != nil {
		return transactionContextError(ctx.Err())
	}
	if err != nil {
		var typed module.TransactionError
		if errors.As(err, &typed) {
			return typed
		}
		return module.ErrUnavailable
	}
	return nil
}
func transactionContextError(err error) error {
	if errors.Is(err, context.DeadlineExceeded) {
		return module.ErrTimeout
	}
	return module.ErrCanceled
}

// Statement contexts cannot outlive the transaction; caller cancellation and
// shorter statement deadlines are also honored. No lifecycle/connection escapes.
type moduleTransaction struct {
	tx  pgx.Tx
	ctx context.Context
}

func (t moduleTransaction) statementContext(caller context.Context) (context.Context, context.CancelFunc) {
	if caller == nil {
		caller = t.ctx
	}
	deadline, _ := t.ctx.Deadline()
	ctx, cancel := context.WithDeadline(caller, deadline)
	stop := context.AfterFunc(t.ctx, cancel)
	if t.ctx.Err() != nil {
		cancel()
	}
	return ctx, func() { stop(); cancel() }
}
func (t moduleTransaction) Exec(caller context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	ctx, cancel := t.statementContext(caller)
	defer cancel()
	return t.tx.Exec(ctx, sql, args...)
}
func (t moduleTransaction) Query(caller context.Context, sql string, args ...any) (module.Rows, error) {
	ctx, cancel := t.statementContext(caller)
	rows, err := t.tx.Query(ctx, sql, args...)
	if err != nil {
		cancel()
		return nil, err
	}
	return &moduleRows{rows: rows, cancel: cancel}, nil
}
func (t moduleTransaction) QueryRow(caller context.Context, sql string, args ...any) pgx.Row {
	ctx, cancel := t.statementContext(caller)
	return moduleRow{row: t.tx.QueryRow(ctx, sql, args...), cancel: cancel}
}

type moduleRows struct {
	rows   pgx.Rows
	cancel context.CancelFunc
}

func (r *moduleRows) Close()     { r.rows.Close(); r.cancel() }
func (r *moduleRows) Err() error { return r.rows.Err() }
func (r *moduleRows) Next() bool {
	ok := r.rows.Next()
	if !ok {
		r.Close()
	}
	return ok
}
func (r *moduleRows) Scan(dest ...any) error {
	if exposesRows(dest) {
		r.Close()
		return module.ErrScope
	}
	err := r.rows.Scan(dest...)
	if err != nil {
		r.Close()
	}
	return err
}

type moduleRow struct {
	row    pgx.Row
	cancel context.CancelFunc
}

func (r moduleRow) Scan(dest ...any) error {
	defer r.cancel()
	if exposesRows(dest) {
		// Drain/close the underlying single row without passing the scanner.
		_ = r.row.Scan()
		return module.ErrScope
	}
	return r.row.Scan(dest...)
}

// pgx.RowScanner receives raw pgx.Rows (and thus Conn). Use ordinary positional
// scan targets; do not pass that connection-capable callback through the facade.
func exposesRows(dest []any) bool {
	if len(dest) != 1 {
		return false
	}
	_, ok := dest[0].(pgx.RowScanner)
	return ok
}
