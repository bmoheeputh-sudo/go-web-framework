package auth

import (
	"context"
	"fmt"
)

// Code-owned parameter positions only. PostgreSQL time and committed policy,
// not listener health or a node's wall clock, authorize database credentials.
func authoritySQL(deployment, environment, revision, generation int) string {
	return fmt.Sprintf(`policy AS (
 SELECT h.generation=$%[4]d AND h.active_revision_id=$%[3]d AS current,
 CASE WHEN h.generation=$%[4]d AND h.active_revision_id=$%[3]d THEN 'infinity'::timestamptz ELSE a.transition_deadline END AS deadline
 FROM framework.auth_activation_heads h
 JOIN framework.auth_activation_history a ON a.deployment_id=h.deployment_id AND a.environment=h.environment AND a.generation=h.generation AND a.target_revision_id=h.active_revision_id AND a.activated_at=h.activated_at
 JOIN framework.auth_config_lifecycle l ON l.revision_id=h.active_revision_id AND l.deployment_id=h.deployment_id AND l.environment=h.environment AND l.status='active' AND l.generation=4
 WHERE h.deployment_id=$%[1]d AND h.environment=$%[2]d AND h.runtime_source='database' AND h.activated_at<=clock_timestamp()
 AND ((h.generation=$%[4]d AND h.active_revision_id=$%[3]d)
 OR (h.generation=$%[4]d+1 AND a.previous_revision_id=$%[3]d AND a.transition_deadline>clock_timestamp()))
)`, deployment, environment, revision, generation)
}

type flowExpiryKey struct{}

// AdmissionGuard is installed once by the trusted composition root. The
// captured request uses this same guard and snapshot throughout its lifetime.
type AdmissionGuard func(context.Context, RuntimeStatus) error

func (m *Runtime) SetAdmissionGuard(guard AdmissionGuard) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed || m.guard != nil || guard == nil {
		return ErrRuntimeConflict
	}
	m.guard = guard
	return nil
}
func (m *Runtime) checkAdmission(ctx context.Context, s *runtimeSnapshot) error {
	request, ok := ctx.Value(runtimeRequestKey{}).(runtimeRequest)
	if !ok || request.owner != m {
		return ErrStoreUnavailable
	}
	if request.guard != nil {
		return request.guard(ctx, s.status)
	}
	return nil
}
