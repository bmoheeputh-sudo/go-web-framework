package notifications

import (
	"context"
	"errors"
	"time"
)

type Lease struct {
	ID, ConnectorID, Provider, Owner string
	Generation                       int64
	ExpiresAt                        time.Time
}
type Dispatch struct {
	Lease   Lease
	Message Message
}

// Queue is deliberately smaller than the administrator repository. No user,
// approval, connector configuration or role mutation is exposed to a worker.
type Queue interface {
	Acquire(context.Context, string, int, time.Duration) ([]Lease, error)
	Begin(context.Context, Lease) (Dispatch, error)
	Complete(context.Context, Lease, Result) error
	ResolveExpired(context.Context, int) (int, error)
}

// RunOnce is explicitly invoked by internal tests/operations. There is no
// production loop, startup hook, network adapter or automatic failover.
func RunOnce(ctx context.Context, q Queue, owner string, adapters map[string]Adapter, limit int, lease time.Duration) error {
	if q == nil {
		return ErrInvalid
	}
	if _, err := q.ResolveExpired(ctx, limit); err != nil {
		return err
	}
	jobs, err := q.Acquire(ctx, owner, limit, lease)
	if err != nil {
		return err
	}
	var result error
	for _, job := range jobs {
		adapter := adapters[job.ConnectorID]
		if adapter == nil || adapter.Provider() != job.Provider {
			continue
		} // known not started; lease may safely expire.
		d, err := q.Begin(ctx, job)
		if err != nil {
			result = errors.Join(result, err)
			continue
		}
		// Begin must definitively commit before Send. Panics/cancellation/crashes
		// after this marker leave dispatching work for inspection, never requeue.
		r := adapter.Send(ctx, d.Message)
		if !r.Validate() {
			r = Result{Outcome: Uncertain, ErrorCode: "provider_uncertain"}
		}
		if err = q.Complete(ctx, d.Lease, r); err != nil {
			result = errors.Join(result, err)
		}
	}
	return result
}
