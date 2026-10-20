package auth

import "time"

// NewDatabaseRuntime rehydrates an already committed policy. It cannot replace
// a running runtime and performs no writes. The caller must verify DB authority,
// scope, lifecycle and history; only trusted startup code owns this capability.
func NewDatabaseRuntime(active, draining *PreparedOIDC, activatedAt, deadline time.Time) (*Runtime, error) {
	if active == nil || !active.binding.MatchesDatabase(active.binding) || activatedAt.IsZero() || deadline.Before(activatedAt) || deadline.After(activatedAt.Add(30*time.Minute)) {
		return nil, ErrRuntimeConflict
	}
	if draining != nil {
		a, d := active.binding, draining.binding
		if !d.MatchesDatabase(d) || d.DeploymentID != a.DeploymentID || d.Environment != a.Environment || d.ActivationGeneration != a.ActivationGeneration-1 || d.RevisionID == a.RevisionID || active.provider.config.RedirectURL != draining.provider.config.RedirectURL || active.provider.sessionCookie != draining.provider.sessionCookie {
			return nil, ErrRuntimeConflict
		}
		if !time.Now().Before(deadline) {
			draining.Close()
			draining = nil
		}
	}
	claim := func(p *PreparedOIDC) bool {
		p.lease.mu.Lock()
		defer p.lease.mu.Unlock()
		if p.lease.closed || p.lease.retired || p.lease.published {
			return false
		}
		p.lease.published = true
		if p.lease.timer != nil {
			p.lease.timer.Stop()
			p.lease.timer = nil
		}
		return true
	}
	if !claim(active) {
		return nil, ErrRuntimeConflict
	}
	if draining != nil && !claim(draining) {
		active.lease.retire(time.Now())
		return nil, ErrRuntimeConflict
	}
	s := &runtimeSnapshot{status: RuntimeStatus{DeploymentID: active.binding.DeploymentID, Environment: active.binding.Environment, Source: "database", Provider: OIDC, AppliedGeneration: active.binding.ActivationGeneration, ActiveRevisionID: active.binding.RevisionID, TransitionState: "none"}, auth: active.provider, oidc: active.provider, prepared: active}
	m := &Runtime{desiredGeneration: active.binding.ActivationGeneration}
	if draining != nil {
		draining.lease.retire(deadline)
		s.draining = draining
		s.status.PreviousProvider = OIDC
		s.status.PreviousRevisionID = draining.binding.RevisionID
		s.status.TransitionDeadline = deadline
		s.status.TransitionState = "draining"
	}
	m.current.Store(s)
	if draining != nil {
		m.drainTimer = time.AfterFunc(time.Until(deadline), func() { m.mu.Lock(); defer m.mu.Unlock(); m.pruneExpiredLocked() })
	}
	return m, nil
}
