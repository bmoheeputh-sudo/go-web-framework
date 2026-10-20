package auth

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

var ErrRuntimeConflict = errors.New("authentication runtime conflict")
var ErrRuntimeMismatch = errors.New("authentication desired and applied state differ")

// providerLease owns only a database authenticator's transport and references.
// All cryptographic/network work uses request contexts and synchronous keysets.
// No RemoteKeySet background goroutine is introduced for database providers.
type providerLease struct {
	mu                         sync.Mutex
	refs                       int
	retired, closed, published bool
	until                      time.Time
	cleanup                    func()
	timer                      *time.Timer
}

func (l *providerLease) allowedLocked(login bool) bool {
	return !l.closed && (!l.retired || (!login && time.Now().Before(l.until)))
}
func (l *providerLease) deadline(login bool) (time.Time, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.allowedLocked(login) {
		return time.Time{}, false
	}
	if l.until.IsZero() {
		return time.Date(9999, 1, 1, 0, 0, 0, 0, time.UTC), true
	}
	return l.until, true
}
func (l *providerLease) retain() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.allowedLocked(false) {
		return false
	}
	l.refs++
	return true
}
func (l *providerLease) release() { l.mu.Lock(); defer l.mu.Unlock(); l.refs--; l.closeLocked() }
func (l *providerLease) closeLocked() {
	if l.retired && !time.Now().Before(l.until) && l.refs == 0 && !l.closed {
		l.closed = true
		if l.timer != nil {
			l.timer.Stop()
		}
		if l.cleanup != nil {
			l.cleanup()
			l.cleanup = nil
		}
	}
}
func (l *providerLease) retire(until time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.retired && !until.Before(l.until) {
		return
	}
	l.retired = true
	l.until = until
	if l.timer != nil {
		l.timer.Stop()
	}
	l.closeLocked()
	if !l.closed && time.Now().Before(until) {
		l.timer = time.AfterFunc(time.Until(until), func() { l.mu.Lock(); defer l.mu.Unlock(); l.closeLocked() })
	}
}

type PreparedOIDC struct {
	provider *OIDCAuthenticator
	binding  Binding
	lease    *providerLease
	store    *PostgresStore
}

// NewPreparedDatabaseOIDC accepts only trusted, already validated discovery and
// a synchronous verification keyset from the hardened preparation service.
func NewPreparedDatabaseOIDC(config OIDCConfig, endpoint oauth2.Endpoint, keys oidc.KeySet, algorithms []string, client *http.Client, store *PostgresStore, binding Binding, cleanup func()) (*PreparedOIDC, error) {
	if config.Validate() != nil || keys == nil || client == nil || client.Timeout <= 0 || client.Timeout > 10*time.Second || store == nil || !binding.MatchesDatabase(binding) || binding.Issuer != config.Issuer || binding.ClientID != config.ClientID || binding.Environment != config.AppEnv || len(algorithms) == 0 {
		return nil, ErrRuntimeConflict
	}
	for _, alg := range algorithms {
		if alg != oidc.RS256 && alg != oidc.ES256 {
			return nil, ErrRuntimeConflict
		}
	}
	for _, raw := range []string{endpoint.AuthURL, endpoint.TokenURL} {
		if _, err := httpsURL(raw); err != nil {
			return nil, ErrRuntimeConflict
		}
	}
	clientCopy := *client
	client = &clientCopy
	u, _ := url.Parse(config.RedirectURI)
	secure := u.Scheme == "https"
	lease := &providerLease{cleanup: cleanup}
	p := &OIDCAuthenticator{config: oauth2.Config{ClientID: config.ClientID, ClientSecret: config.ClientSecret, RedirectURL: config.RedirectURI, Endpoint: endpoint, Scopes: []string{oidc.ScopeOpenID, "profile", "email"}}, issuer: config.Issuer, origin: u.Scheme + "://" + u.Host, client: client,
		verifier: oidc.NewVerifier(config.Issuer, keys, &oidc.Config{ClientID: config.ClientID, SupportedSigningAlgs: slices.Clone(algorithms)}), secureCookies: secure, absoluteTimeout: config.Sessions.AbsoluteTimeout, sessionCookie: sessionCookie, flowCookie: flowCookie}
	if !secure {
		p.sessionCookie = "gwf_dev_session"
		p.flowCookie = "gwf_dev_oidc_flow"
	}
	p.store = &databaseBoundStore{base: store, binding: binding, lease: lease}
	// Configuration stays immutable, even on retirement. The lease releases
	// owned network resources; pruning snapshots lets credential references be GC'd.
	prepared := &PreparedOIDC{p, binding, lease, store}
	lease.timer = time.AfterFunc(5*time.Minute, prepared.Close)
	return prepared, nil
}
func (p *PreparedOIDC) Close() {
	if p == nil {
		return
	}
	p.lease.mu.Lock()
	defer p.lease.mu.Unlock()
	if !p.lease.published {
		p.lease.retired = true
		p.lease.until = time.Now()
		p.lease.closeLocked()
	}
}

type Publication struct {
	runtime  *Runtime
	expected *runtimeSnapshot
	prepared *PreparedOIDC
}

// Stage is control-plane preparation, not an HTTP parameter decoder. Only the
// administrator activation service may commit after its DB transaction succeeds.
func (m *Runtime) Stage(p *PreparedOIDC, expectedGeneration int64) (*Publication, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.pruneExpiredLocked()
	s := m.current.Load()
	if m.closed || m.mismatch || s == nil || p == nil || s.status.Provider == GoogleIAP || s.status.AppliedGeneration != expectedGeneration || p.binding.ActivationGeneration != expectedGeneration+1 || p.binding.DeploymentID != s.status.DeploymentID || p.binding.Environment != s.status.Environment {
		return nil, ErrRuntimeConflict
	}
	if s.draining != nil && time.Now().Before(s.status.TransitionDeadline) {
		return nil, ErrRuntimeConflict
	}
	if s.oidc != nil && (s.oidc.origin != p.provider.origin || s.oidc.sessionCookie != p.provider.sessionCookie || s.oidc.flowCookie != p.provider.flowCookie) {
		return nil, ErrRuntimeConflict
	}
	p.lease.mu.Lock()
	ok := !p.lease.closed && !p.lease.retired && !p.lease.published
	p.lease.mu.Unlock()
	if !ok {
		return nil, ErrRuntimeConflict
	}
	return &Publication{m, s, p}, nil
}

// Reserve pauses new request admission across the DB commit/publication gap.
// Captured in-flight requests retain their original bounded leases.
func (c *Publication) Reserve() error {
	m := c.runtime
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed || m.mismatch || m.pending != nil || m.current.Load() != c.expected {
		return ErrRuntimeConflict
	}
	m.pending = c
	return nil
}

// Abort only reopens admission after the caller knows the DB did not commit.
func (c *Publication) Abort() {
	m := c.runtime
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.pending == c {
		m.pending = nil
	}
}

// Commit is internal control-plane only. If DB desired state was committed but
// publication fails, poison new request admission instead of serving Local DEV.
func (c *Publication) Commit(deadline time.Time) error {
	m := c.runtime
	m.mu.Lock()
	defer m.mu.Unlock()
	p := c.prepared
	if m.closed || m.mismatch || (m.pending != nil && m.pending != c) || deadline.After(time.Now().Add(30*time.Minute)) || m.current.Load() != c.expected {
		m.mismatch = true
		m.desiredGeneration = p.binding.ActivationGeneration
		return ErrRuntimeMismatch
	}
	p.lease.mu.Lock()
	if p.lease.closed || p.lease.retired || p.lease.published {
		p.lease.mu.Unlock()
		m.mismatch = true
		m.desiredGeneration = p.binding.ActivationGeneration
		return ErrRuntimeMismatch
	}
	p.lease.published = true
	if p.lease.timer != nil {
		p.lease.timer.Stop()
		p.lease.timer = nil
	}
	p.lease.mu.Unlock()
	old := c.expected
	next := &runtimeSnapshot{status: RuntimeStatus{DeploymentID: p.binding.DeploymentID, Environment: p.binding.Environment, Source: "database", AppliedGeneration: p.binding.ActivationGeneration, Provider: OIDC, ActiveRevisionID: p.binding.RevisionID, TransitionState: "none"}, auth: p.provider, oidc: p.provider, prepared: p}
	if old.prepared != nil {
		old.prepared.lease.retire(deadline)
		if time.Now().Before(deadline) {
			next.draining = old.prepared
			next.status.PreviousProvider = OIDC
			next.status.PreviousRevisionID = old.status.ActiveRevisionID
			next.status.TransitionDeadline = deadline
			next.status.TransitionState = "draining"
		}
	}
	if old.draining != nil {
		old.draining.lease.retire(time.Now())
	}
	if !m.current.CompareAndSwap(old, next) {
		m.mismatch = true
		m.desiredGeneration = p.binding.ActivationGeneration
		p.lease.retire(time.Now())
		return ErrRuntimeMismatch
	}
	m.desiredGeneration = p.binding.ActivationGeneration
	if m.pending == c {
		m.pending = nil
	}
	if m.drainTimer != nil {
		m.drainTimer.Stop()
		m.drainTimer = nil
	}
	if next.draining != nil {
		m.drainTimer = time.AfterFunc(time.Until(deadline), func() { m.mu.Lock(); defer m.mu.Unlock(); m.pruneExpiredLocked() })
	}
	return nil
}

// ControlStatus is for trusted activation operations; HTTP status still uses the
// one request capture. A mismatch never claims the desired generation is applied.
func (m *Runtime) ControlStatus() (RuntimeStatus, int64, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := m.current.Load()
	if s == nil {
		return RuntimeStatus{}, m.desiredGeneration, true
	}
	return snapshotStatus(s), m.desiredGeneration, m.mismatch
}
func (m *Runtime) Close() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closed = true
	if m.drainTimer != nil {
		m.drainTimer.Stop()
		m.drainTimer = nil
	}
	for token, e := range m.readiness {
		e.timer.Stop()
		delete(m.readiness, token)
		e.prepared.Close()
		e.prepared.lease.release()
	}
	if m.pending != nil {
		m.pending.prepared.Close()
		m.pending = nil
	}
	s := m.current.Load()
	if s != nil {
		for _, p := range []*PreparedOIDC{s.prepared, s.draining} {
			if p != nil {
				p.lease.retire(time.Now())
			}
		}
		// Retain safe status only. In-flight contexts own their old snapshot;
		// shutdown must not retain credential strings after those requests end.
		m.current.Store(&runtimeSnapshot{status: s.status})
	}
}

// Server-stored opaque-token metadata chooses exactly one permitted verifier.
// A query-string issuer/revision is never a dispatch key.
func selectBoundProvider(ctx context.Context, s *runtimeSnapshot, r *http.Request, flow bool) (*OIDCAuthenticator, error) {
	name := s.oidc.sessionCookie
	if flow {
		name = s.oidc.flowCookie
	}
	cookies := r.CookiesNamed(name)
	if len(cookies) != 1 {
		return nil, ErrUnauthenticated
	}
	var b Binding
	var err error
	if flow {
		b, err = s.prepared.store.FlowBinding(ctx, cookies[0].Value)
	} else {
		b, err = s.prepared.store.SessionBinding(ctx, cookies[0].Value)
	}
	if err != nil {
		return nil, err
	}
	for _, p := range []*PreparedOIDC{s.prepared, s.draining} {
		if p != nil && b.MatchesDatabase(p.binding) {
			if _, ok := p.lease.deadline(false); ok {
				return p.provider, nil
			}
			break
		}
	}
	return nil, ErrUnauthenticated
}

// Fence refuses new requests after an uncertain commit. An uncertain outcome is
// never a reason to keep accepting the old environment provider.
func (m *Runtime) Fence(desired int64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.mismatch = true
	m.desiredGeneration = desired
}

// Caller owns m.mu. Publish a new container, never mutate a captured snapshot.
func (m *Runtime) pruneExpiredLocked() {
	s := m.current.Load()
	if s == nil || s.draining == nil || time.Now().Before(s.status.TransitionDeadline) {
		return
	}
	next := *s
	next.draining = nil
	next.status.PreviousProvider = ""
	next.status.PreviousRevisionID = ""
	next.status.TransitionState = "none"
	next.status.TransitionDeadline = time.Time{}
	m.current.CompareAndSwap(s, &next)
}
