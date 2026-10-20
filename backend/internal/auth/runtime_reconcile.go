package auth

import "time"

// Reconcile adopts a fully verified, independently prepared database runtime.
// This is a trusted control-plane operation, never a request DTO. Preparation
// and authoritative head checks belong to the serialized reconciler.
func (m *Runtime) Reconcile(candidate *Runtime, expected int64) error {
	if candidate == nil || candidate == m {
		return ErrRuntimeConflict
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	candidate.mu.Lock()
	defer candidate.mu.Unlock()
	old, next := m.current.Load(), candidate.current.Load()
	if m.closed || m.pending != nil || old == nil || old.status.Provider == GoogleIAP || candidate.closed || next == nil || next.prepared == nil || next.status.Source != "database" || old.status.AppliedGeneration != expected || next.status.AppliedGeneration <= expected || old.status.DeploymentID != next.status.DeploymentID || old.status.Environment != next.status.Environment {
		return ErrRuntimeConflict
	}
	// References held by captured requests keep their own verifier alive. A
	// skipped generation retires immediately unless exactly the permitted drain.
	for _, p := range []*PreparedOIDC{old.prepared, old.draining} {
		if p == nil {
			continue
		}
		deadline := time.Now()
		if next.draining != nil && p.binding == next.draining.binding {
			deadline = next.status.TransitionDeadline
		}
		p.lease.retire(deadline)
	}
	if m.drainTimer != nil {
		m.drainTimer.Stop()
		m.drainTimer = nil
	}
	if candidate.drainTimer != nil {
		candidate.drainTimer.Stop()
		candidate.drainTimer = nil
	}
	m.current.Store(next)
	m.desiredGeneration = next.status.AppliedGeneration
	m.mismatch = false
	// Transfer ownership; candidate.Close must not retire adopted leases.
	candidate.current.Store(&runtimeSnapshot{status: next.status})
	candidate.closed = true
	if next.draining != nil {
		m.drainTimer = time.AfterFunc(time.Until(next.status.TransitionDeadline), func() { m.mu.Lock(); defer m.mu.Unlock(); m.pruneExpiredLocked() })
	}
	return nil
}

// Confirm reconciles an uncertain local publication only after the authoritative
// policy has been read and its exact revision/generation confirmed.
func (m *Runtime) Confirm(status RuntimeStatus) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := m.current.Load()
	if m.closed || m.pending != nil || s == nil || status.Source != s.status.Source || status.AppliedGeneration != s.status.AppliedGeneration || status.ActiveRevisionID != s.status.ActiveRevisionID || status.DeploymentID != s.status.DeploymentID || status.Environment != s.status.Environment {
		return ErrRuntimeConflict
	}
	m.mismatch = false
	m.desiredGeneration = status.AppliedGeneration
	return nil
}
