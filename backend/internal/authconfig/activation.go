package authconfig

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ActivationReader is a deployment-bound, read-only internal capability. It is
// deliberately independent of HTTP principal context and cannot decrypt secrets
// or mutate configuration. No runtime component uses it in this phase.
type ActivationReader struct {
	pool  *pgxpool.Pool
	scope Scope
}

func NewActivationReader(pool *pgxpool.Pool, scope Scope) (*ActivationReader, error) {
	if pool == nil || !scope.valid() {
		return nil, ErrInvalid
	}
	return &ActivationReader{pool, scope}, nil
}

type ActivationHead struct {
	Scope
	Generation       int64
	RuntimeSource    string
	ActiveRevisionID string
	ActivatedAt      *time.Time
}
type ActivationEvent struct {
	Scope
	Generation         int64
	PreviousRevisionID string
	TargetRevisionID   string
	RecoveryRevisionID string
	ActivatedAt        time.Time
	TransitionDeadline time.Time
	ActorUserID        string
	Reason             string
}

func readError(ctx context.Context, err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return ErrTimeout
	}
	if errors.Is(ctx.Err(), context.Canceled) {
		return ErrCanceled
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	return ErrUnavailable
}

// Head returns a virtual environment-policy generation zero when no head exists.
// Reading an unenrolled deployment never creates a row or changes its policy.
func (r *ActivationReader) Head(ctx context.Context) (ActivationHead, error) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	h := ActivationHead{Scope: r.scope, RuntimeSource: "environment"}
	err := r.pool.QueryRow(ctx, `SELECT generation,runtime_source,COALESCE(active_revision_id::text,''),activated_at
      FROM framework.auth_activation_heads WHERE deployment_id=$1 AND environment=$2`, r.scope.DeploymentID, r.scope.Environment).
		Scan(&h.Generation, &h.RuntimeSource, &h.ActiveRevisionID, &h.ActivatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return ActivationHead{Scope: r.scope, RuntimeSource: "environment"}, nil
	}
	if err != nil {
		return ActivationHead{}, readError(ctx, err)
	}
	return h, nil
}

// CheckGeneration is a read-only preflight, not a substitute for CAS under the
// advisory lock in a future activation transaction.
func (r *ActivationReader) CheckGeneration(ctx context.Context, expected int64) error {
	if expected < 0 {
		return ErrInvalid
	}
	h, err := r.Head(ctx)
	if err != nil {
		return err
	}
	if h.Generation != expected {
		return ErrConflict
	}
	return nil
}
func (r *ActivationReader) History(ctx context.Context, before int64, limit int) ([]ActivationEvent, error) {
	if before < 0 || limit < 1 || limit > 100 {
		return nil, ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	rows, err := r.pool.Query(ctx, `SELECT generation,COALESCE(previous_revision_id::text,''),target_revision_id::text,
      COALESCE(recovery_revision_id::text,''),activated_at,transition_deadline,actor_user_id::text,reason
      FROM framework.auth_activation_history WHERE deployment_id=$1 AND environment=$2 AND ($3::bigint=0 OR generation<$3)
      ORDER BY generation DESC LIMIT $4`, r.scope.DeploymentID, r.scope.Environment, before, limit)
	if err != nil {
		return nil, readError(ctx, err)
	}
	defer rows.Close()
	events := []ActivationEvent{}
	for rows.Next() {
		e := ActivationEvent{Scope: r.scope}
		if err = rows.Scan(&e.Generation, &e.PreviousRevisionID, &e.TargetRevisionID, &e.RecoveryRevisionID, &e.ActivatedAt, &e.TransitionDeadline, &e.ActorUserID, &e.Reason); err != nil {
			return nil, readError(ctx, err)
		}
		events = append(events, e)
	}
	if err = rows.Err(); err != nil {
		return nil, readError(ctx, err)
	}
	return events, nil
}
func (r *ActivationReader) ValidateRevision(ctx context.Context, id string, generation int64) error {
	if !validID(id) || generation < 1 {
		return ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	var actual int64
	err := r.pool.QueryRow(ctx, `SELECT generation FROM framework.auth_config_lifecycle
      WHERE deployment_id=$1 AND environment=$2 AND revision_id=$3`, r.scope.DeploymentID, r.scope.Environment, id).Scan(&actual)
	if err != nil {
		return readError(ctx, err)
	}
	if actual != generation {
		return ErrConflict
	}
	return nil
}
