package module

import (
	"context"
	"net/http"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// Transaction deliberately omits Commit, Rollback, Conn and Begin. Only the
// framework owns transaction lifecycle. Modules are trusted SQL authors: never
// issue transaction-control SQL or retain this value after the callback returns.
type Transaction interface {
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
	Query(context.Context, string, ...any) (Rows, error)
	QueryRow(context.Context, string, ...any) pgx.Row
}

// Rows omits pgx.Rows.Conn so queries cannot expose the underlying connection.
type Rows interface {
	Close()
	Err() error
	Next() bool
	Scan(...any) error
}

type AuditDetails map[string]any

type MutateFunc func(context.Context, Transaction) (targetID string, details AuditDetails, err error)

// AccountMutateFunc receives the authorized account, never a caller-selected
// scope. Every account-owned SELECT/INSERT/UPDATE/DELETE must constrain that ID.
type AccountMutateFunc func(ctx context.Context, tx Transaction, accountID string) (targetID string, details AuditDetails, err error)

type TransactionManager interface {
	MutateAccount(context.Context, AccountMutateFunc) error
	MutateGlobal(context.Context, MutateFunc) error
}

type MutationHandler func(http.ResponseWriter, *http.Request, TransactionManager)

type AuditKind string

const (
	AuditUUID    AuditKind = "uuid"
	AuditBool    AuditKind = "bool"
	AuditInteger AuditKind = "integer"
	AuditEnum    AuditKind = "enum"
)

// Fields are a code-reviewed allowlist. Every declared field is required.
// No free text, nested objects, custom serializers or arbitrary external payloads.
type AuditField struct {
	Kind   AuditKind
	Values []string // enum only; fixed, non-sensitive labels
}
type AuditPolicy struct {
	Action string
	Fields map[string]AuditField
}

const MaxAuditBytes = 4096

// TransactionError values are stable, sanitized errors, usable with errors.Is.
type TransactionError string

func (e TransactionError) Error() string { return string(e) }

const (
	ErrUnauthenticated  TransactionError = "mutation_unauthenticated"
	ErrAccountDenied    TransactionError = "mutation_account_denied"
	ErrPermissionDenied TransactionError = "mutation_permission_denied"
	ErrInvalidAccount   TransactionError = "invalid_account_id"
	ErrScope            TransactionError = "mutation_scope_mismatch"
	ErrTimeout          TransactionError = "mutation_timeout"
	ErrCanceled         TransactionError = "mutation_canceled"
	ErrUnavailable      TransactionError = "mutation_unavailable"
	ErrMutation         TransactionError = "mutation_failed"
	ErrAudit            TransactionError = "mutation_audit_failed"
)
