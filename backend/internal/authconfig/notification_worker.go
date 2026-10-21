package authconfig

import (
	"context"
	"errors"
	"slices"
	"time"

	"github.com/bmoheeputh-sudo/go-web-framework/backend/internal/access"
	"github.com/bmoheeputh-sudo/go-web-framework/backend/internal/notifications"
	"github.com/jackc/pgx/v5"
)

// NotificationWorker exposes only queue capabilities. It owns no HTTP routes,
// authentication context, administrator operations, transport or startup loop.
type NotificationWorker struct{ repository *NotificationRepository }

func (r *NotificationRepository) Worker() *NotificationWorker { return &NotificationWorker{r} }

var _ notifications.Queue = (*NotificationWorker)(nil)

func (w *NotificationWorker) Acquire(ctx context.Context, owner string, limit int, lease time.Duration) ([]notifications.Lease, error) {
	if !validID(owner) || limit < 1 || limit > 20 || lease < 5*time.Second || lease > 5*time.Minute {
		return nil, ErrInvalid
	}
	r := w.repository
	result := []notifications.Lease{}
	err := r.worker(ctx, func(ctx context.Context, tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT j.id::text,c.provider FROM framework.notification_jobs j JOIN framework.notification_connectors c ON c.id=j.connector_id
 WHERE j.deployment_id=$1 AND j.environment=$2 AND j.status='queued' AND j.due_at<=clock_timestamp() AND c.enabled
 ORDER BY j.due_at,j.id LIMIT $3 FOR UPDATE OF j SKIP LOCKED`, r.policy.scope.DeploymentID, r.policy.scope.Environment, limit)
		if err != nil {
			return err
		}
		type candidate struct{ id, provider string }
		candidates := []candidate{}
		for rows.Next() {
			var c candidate
			if err = rows.Scan(&c.id, &c.provider); err != nil {
				rows.Close()
				return err
			}
			candidates = append(candidates, c)
		}
		rows.Close()
		if err = rows.Err(); err != nil {
			return err
		}
		for _, c := range candidates {
			var l notifications.Lease
			l.ID, l.Provider, l.Owner = c.id, c.provider, owner
			err = tx.QueryRow(ctx, `UPDATE framework.notification_jobs SET status='leased',lease_owner=$4,lease_expires_at=clock_timestamp()+($5::double precision*interval '1 second'),generation=generation+1
 WHERE deployment_id=$1 AND environment=$2 AND id=$3 AND status='queued' RETURNING connector_id::text,generation,lease_expires_at`, r.policy.scope.DeploymentID, r.policy.scope.Environment, c.id, owner, lease.Seconds()).Scan(&l.ConnectorID, &l.Generation, &l.ExpiresAt)
			if err != nil {
				return err
			}
			result = append(result, l)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

func leaseMatches(j NotificationJob, l notifications.Lease, now time.Time, status string) bool {
	return j.Status == status && j.ID == l.ID && j.ConnectorID == l.ConnectorID && j.Generation == l.Generation && j.LeaseOwner == l.Owner && j.LeaseExpiresAt != nil && j.LeaseExpiresAt.Equal(l.ExpiresAt) && j.LeaseExpiresAt.After(now)
}
func (w *NotificationWorker) Begin(ctx context.Context, l notifications.Lease) (notifications.Dispatch, error) {
	if !validID(l.ID) || !validID(l.Owner) || !validID(l.ConnectorID) {
		return notifications.Dispatch{}, ErrInvalid
	}
	r := w.repository
	var d notifications.Dispatch
	blocked := false
	err := r.worker(ctx, func(ctx context.Context, tx pgx.Tx) error {
		j, err := r.job(ctx, tx, l.ID)
		if err != nil {
			return err
		}
		var now time.Time
		if err = tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
			return err
		}
		if !leaseMatches(j, l, now, "leased") {
			return ErrConflict
		}
		n, err := r.request(ctx, tx, j.RequestID)
		if err != nil {
			return err
		}
		var e InvitationExpectation
		var communicationDigest []byte
		if err = tx.QueryRow(ctx, `SELECT policy_generation,activation_generation,revision_id::text,revision_generation,communication_digest FROM framework.notification_requests WHERE id=$1`, n.ID).Scan(&e.Generation, &e.ActivationGeneration, &e.RevisionID, &e.RevisionGeneration, &communicationDigest); err != nil {
			return err
		}
		if !slices.Equal(communicationDigest, r.communicationDigest[:]) {
			blocked = true
			return r.cancel(ctx, tx, j, n.ActorID, "stale_configuration")
		}
		b, err := r.policy.invitationContext(ctx, tx, &e)
		if err != nil {
			if errors.Is(err, ErrConflict) {
				blocked = true
				return r.cancel(ctx, tx, j, n.ActorID, "stale_configuration")
			}
			return err
		}
		authorized, err := r.administratorEligible(ctx, tx, n.ActorID, b)
		if err != nil {
			return err
		}
		if !authorized {
			blocked = true
			return r.cancel(ctx, tx, j, n.ActorID, "review_required")
		}
		code, err := r.eligible(ctx, tx, b, &j, true)
		if err != nil {
			return err
		}
		if code != "" {
			blocked = true
			return r.cancel(ctx, tx, j, n.ActorID, code)
		}
		c, err := r.connector(ctx, tx, j.ConnectorID)
		if err != nil {
			return err
		}
		if !c.Enabled || c.Provider != l.Provider || c.Sender != j.Sender {
			return ErrConflict
		}
		var minute, day int
		if err = tx.QueryRow(ctx, `SELECT count(*) FILTER(WHERE a.started_at>clock_timestamp()-interval '1 minute'),count(*) FROM framework.notification_attempts a JOIN framework.notification_jobs j ON j.id=a.job_id
 WHERE j.deployment_id=$1 AND j.environment=$2 AND j.connector_id=$3 AND a.started_at>clock_timestamp()-interval '24 hours'`, j.DeploymentID, j.Environment, j.ConnectorID).Scan(&minute, &day); err != nil {
			return err
		}
		if minute >= c.PerMinute || day >= c.PerDay {
			return ErrConflict
		}
		message, err := r.template.Render(j.Type, j.TemplateVersion, n.Locale, j.Sender, j.Recipient, j.DisplayName, "vgca."+j.ID)
		if err != nil {
			blocked = true
			return r.cancel(ctx, tx, j, n.ActorID, "review_required")
		}
		var generation int64
		err = tx.QueryRow(ctx, `UPDATE framework.notification_jobs SET status='dispatching',attempt_count=attempt_count+1,generation=generation+1
 WHERE deployment_id=$1 AND environment=$2 AND id=$3 AND generation=$4 AND status='leased' AND lease_owner=$5 AND lease_expires_at>clock_timestamp() RETURNING generation`, j.DeploymentID, j.Environment, j.ID, j.Generation, l.Owner).Scan(&generation)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrConflict
		}
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `INSERT INTO framework.notification_attempts(job_id,attempt_number,adapter,executor_id) VALUES($1,$2,$3,$4)`, j.ID, j.AttemptCount+1, c.Provider, l.Owner)
		if err != nil {
			return err
		}
		if err = notificationAudit(ctx, tx, n.ActorID, "notification.dispatch_started", j.ID, r.policy.scope, "dispatching"); err != nil {
			return err
		}
		l.Generation = generation
		d = notifications.Dispatch{Lease: l, Message: message}
		return nil
	})
	if err != nil {
		return notifications.Dispatch{}, err
	}
	if blocked {
		return notifications.Dispatch{}, ErrConflict
	}
	return d, nil
}

func (r *NotificationRepository) connectorOutcome(ctx context.Context, tx pgx.Tx, j NotificationJob, actor, code string, accepted bool) error {
	_, err := tx.Exec(ctx, `UPDATE framework.notification_connectors SET generation=generation+1,failure_count=failure_count+CASE WHEN $4 THEN 0 ELSE 1 END,last_error_code=$5,last_accepted_at=CASE WHEN $4 THEN clock_timestamp() ELSE last_accepted_at END,updated_by=$6
 WHERE deployment_id=$1 AND environment=$2 AND id=$3`, j.DeploymentID, j.Environment, j.ConnectorID, accepted, code, actor)
	return err
}
func (w *NotificationWorker) Complete(ctx context.Context, l notifications.Lease, result notifications.Result) error {
	if !validID(l.ID) || !validID(l.Owner) || !validID(l.ConnectorID) {
		return ErrInvalid
	}
	if !result.Validate() {
		result = notifications.Result{Outcome: notifications.Uncertain, ErrorCode: "provider_uncertain"}
	}
	r := w.repository
	return r.worker(ctx, func(ctx context.Context, tx pgx.Tx) error {
		j, err := r.job(ctx, tx, l.ID)
		if err != nil {
			return err
		}
		var now time.Time
		if err = tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
			return err
		}
		if !leaseMatches(j, l, now, "dispatching") {
			return ErrConflict
		}
		n, err := r.request(ctx, tx, j.RequestID)
		if err != nil {
			return err
		}
		c, err := r.connector(ctx, tx, j.ConnectorID)
		if err != nil {
			return err
		}
		if c.Provider != l.Provider {
			return ErrConflict
		}
		tag, err := tx.Exec(ctx, `UPDATE framework.notification_attempts SET outcome=$3,completed_at=clock_timestamp(),provider_message_id=$4,error_code=$5 WHERE job_id=$1 AND attempt_number=$2 AND executor_id=$6 AND adapter=$7 AND outcome IS NULL`, j.ID, j.AttemptCount, string(result.Outcome), result.ProviderMessageID, result.ErrorCode, l.Owner, l.Provider)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return ErrConflict
		}
		status := "needs_inspection"
		if result.Outcome == notifications.Accepted {
			status = "sent"
		}
		if result.Outcome == notifications.Rejected {
			status = "failed"
		}
		_, err = tx.Exec(ctx, `UPDATE framework.notification_jobs SET status=$4,disposition_code=$5,lease_owner=NULL,lease_expires_at=NULL,generation=generation+1 WHERE deployment_id=$1 AND environment=$2 AND id=$3`, j.DeploymentID, j.Environment, j.ID, status, result.ErrorCode)
		if err != nil {
			return err
		}
		if err = r.connectorOutcome(ctx, tx, j, n.ActorID, result.ErrorCode, result.Outcome == notifications.Accepted); err != nil {
			return err
		}
		return notificationAudit(ctx, tx, n.ActorID, "notification.delivery_recorded", j.ID, r.policy.scope, string(result.Outcome))
	})
}

func (w *NotificationWorker) ResolveExpired(ctx context.Context, limit int) (int, error) {
	if limit < 1 || limit > 20 {
		return 0, ErrInvalid
	}
	r := w.repository
	resolved := 0
	err := r.worker(ctx, func(ctx context.Context, tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT id::text FROM framework.notification_jobs WHERE deployment_id=$1 AND environment=$2 AND status IN ('leased','dispatching') AND lease_expires_at<=clock_timestamp() ORDER BY lease_expires_at,id LIMIT $3 FOR UPDATE SKIP LOCKED`, r.policy.scope.DeploymentID, r.policy.scope.Environment, limit)
		if err != nil {
			return err
		}
		ids := []string{}
		for rows.Next() {
			var id string
			if err = rows.Scan(&id); err != nil {
				rows.Close()
				return err
			}
			ids = append(ids, id)
		}
		rows.Close()
		if err = rows.Err(); err != nil {
			return err
		}
		for _, id := range ids {
			j, err := r.job(ctx, tx, id)
			if err != nil {
				return err
			}
			n, err := r.request(ctx, tx, j.RequestID)
			if err != nil {
				return err
			}
			status := "queued"
			code := ""
			if j.Status == "dispatching" {
				status, code = "needs_inspection", "lease_expired"
				tag, err := tx.Exec(ctx, `UPDATE framework.notification_attempts SET outcome='uncertain',completed_at=clock_timestamp(),error_code='lease_expired' WHERE job_id=$1 AND attempt_number=$2 AND outcome IS NULL`, id, j.AttemptCount)
				if err != nil {
					return err
				}
				if tag.RowsAffected() != 1 {
					return ErrConflict
				}
				if err = r.connectorOutcome(ctx, tx, j, n.ActorID, code, false); err != nil {
					return err
				}
			}
			_, err = tx.Exec(ctx, `UPDATE framework.notification_jobs SET status=$4,disposition_code=$5,lease_owner=NULL,lease_expires_at=NULL,generation=generation+1 WHERE deployment_id=$1 AND environment=$2 AND id=$3`, j.DeploymentID, j.Environment, id, status, code)
			if err != nil {
				return err
			}
			if err = notificationAudit(ctx, tx, n.ActorID, "notification.lease_resolved", id, r.policy.scope, status); err != nil {
				return err
			}
			resolved++
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	return resolved, nil
}

func (r *NotificationRepository) ReadAttempts(ctx context.Context, id string) ([]NotificationAttempt, error) {
	if !validID(id) {
		return nil, ErrInvalid
	}
	result := []NotificationAttempt{}
	err := r.admin(ctx, func(ctx context.Context, tx pgx.Tx, _ access.User) error {
		if _, err := r.job(ctx, tx, id); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `SELECT job_id::text,attempt_number,adapter,executor_id::text,started_at,completed_at,COALESCE(outcome,''),provider_message_id,error_code FROM framework.notification_attempts WHERE job_id=$1 ORDER BY attempt_number`, id)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var a NotificationAttempt
			if err = rows.Scan(&a.JobID, &a.Number, &a.Adapter, &a.ExecutorID, &a.StartedAt, &a.CompletedAt, &a.Outcome, &a.ProviderMessageID, &a.ErrorCode); err != nil {
				return err
			}
			result = append(result, a)
		}
		return rows.Err()
	})
	return result, err
}
