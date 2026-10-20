package auth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/oauth2"
)

// RuntimeStatus contains no credentials. It is returned by value, never as a
// reference to published configuration. Zero generation/revision means the
// environment provider, not a pending or approved database revision.
type RuntimeStatus struct {
	DeploymentID, Environment string
	Source                    string
	AppliedGeneration         int64
	Provider                  Provider
	ActiveRevisionID          string
	PreviousProvider          Provider
	PreviousRevisionID        string
	TransitionState           string
	TransitionDeadline        time.Time
}

type runtimeSnapshot struct {
	status             RuntimeStatus
	auth               Authenticator
	oidc               *OIDCAuthenticator
	prepared, draining *PreparedOIDC
}

// Runtime owns immutable configuration snapshots. Provider caches and session
// stores remain concurrency-safe services, not mutable configuration. There is
// no HTTP publication endpoint or automatic database activation reader.
type Runtime struct {
	current           atomic.Pointer[runtimeSnapshot]
	mu                sync.Mutex
	closed, mismatch  bool
	desiredGeneration int64
	readiness         map[string]*readinessEntry
	drainTimer        *time.Timer
	pending           *Publication
	guard             AdmissionGuard
	readinessInstance string
}

type runtimeRequestKey struct{}
type runtimeRequest struct {
	owner    *Runtime
	snapshot *runtimeSnapshot
	guard    AdmissionGuard
}

// NewEnvironmentRuntime accepts only the framework's prepared providers. Scope
// is informational for legacy authentication and is not inferred from a client.
// Management configuration is optional; an absent deployment does not enroll it.
func NewEnvironmentRuntime(provider Authenticator, deployment, environment string) (*Runtime, error) {
	switch environment {
	case "TEST":
		environment = "test"
	case "PRD", "prd":
		environment = "production"
	}
	s, err := prepareEnvironment(provider, RuntimeStatus{
		DeploymentID: deployment, Environment: environment, Source: "environment", TransitionState: "none",
	})
	if err != nil {
		return nil, err
	}
	runtime := &Runtime{readinessInstance: oauth2.GenerateVerifier()}
	if !runtime.publish(nil, s) {
		return nil, errors.New("authentication runtime initialization failed")
	}
	return runtime, nil
}

func prepareEnvironment(provider Authenticator, status RuntimeStatus) (*runtimeSnapshot, error) {
	s := &runtimeSnapshot{status: status}
	switch p := provider.(type) {
	case nil:
	case *LocalDevAuthenticator:
		if status.Environment != "development" || p == nil || p.identity.Validate() != nil || p.identity.Provider != LocalDev {
			return nil, errors.New("unprepared local authentication provider")
		}
		copy := *p
		s.auth, s.status.Provider = &copy, LocalDev
	case *IAPAuthenticator:
		if p == nil || p.keys == nil || p.now == nil || ValidateIAPAudience(p.audience) != nil {
			return nil, errors.New("unprepared IAP authentication provider")
		}
		copy := *p
		s.auth, s.status.Provider = &copy, GoogleIAP
	case *OIDCAuthenticator:
		if p == nil || p.store == nil || p.verifier == nil || p.client == nil || p.issuer == "" || p.config.ClientID == "" {
			return nil, errors.New("unprepared OIDC authentication provider")
		}
		copy := *p
		copy.config.Scopes = slices.Clone(p.config.Scopes)
		client := *p.client
		copy.client = &client
		// Environment authentication must not accept a database revision's
		// session/flow merely because it shares an issuer or cookie name.
		if reader, ok := p.store.(bindingReader); ok {
			copy.store = environmentBoundStore{sessionStore: p.store, reader: reader,
				expected: Binding{Source: "environment", DeploymentID: status.DeploymentID,
					Environment: status.Environment, Issuer: p.issuer, ClientID: p.config.ClientID, Purpose: "login"}}
		}
		s.auth, s.oidc, s.status.Provider = &copy, &copy, OIDC
	default:
		return nil, errors.New("unsupported runtime authentication provider")
	}
	return s, nil
}

// publish is the legacy environment-only path: it permits only re-publication
// of the same prepared configuration. Controlled database transitions use
// Stage/Publication through the internal administrator activation service.
// Neither path permits replacing an IAP deployment with OIDC.
func (m *Runtime) publish(expected, next *runtimeSnapshot) bool {
	if next == nil || next.status.Source != "environment" || next.status.TransitionState != "none" || next.status.AppliedGeneration != 0 ||
		next.status.ActiveRevisionID != "" || next.status.PreviousRevisionID != "" ||
		next.status.PreviousProvider != "" || !next.status.TransitionDeadline.IsZero() {
		return false
	}
	if expected != nil && (next.status != expected.status || next.auth != expected.auth || next.oidc != expected.oidc) {
		return false
	}
	// Own the snapshot container; callers cannot alter published status later.
	copy := *next
	return m.current.CompareAndSwap(expected, &copy)
}

// Capture must wrap the entire router, including callbacks and public config.
// Nested use preserves the original snapshot; a different manager fails closed.
func (m *Runtime) Capture(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if captured, ok := r.Context().Value(runtimeRequestKey{}).(runtimeRequest); ok {
			if captured.owner != m || captured.snapshot == nil {
				runtimeUnavailable(w)
				return
			}
			next.ServeHTTP(w, r)
			return
		}
		m.mu.Lock()
		snapshot := m.current.Load()
		if m.closed || m.mismatch || m.pending != nil || snapshot == nil {
			m.mu.Unlock()
			runtimeUnavailable(w)
			return
		}
		leases := []*providerLease{}
		for _, p := range []*PreparedOIDC{snapshot.prepared, snapshot.draining} {
			if p != nil && p.lease.retain() {
				leases = append(leases, p.lease)
			}
		}
		guard := m.guard
		m.mu.Unlock()
		defer func() {
			for _, l := range leases {
				l.release()
			}
		}()
		ctx := context.WithValue(r.Context(), runtimeRequestKey{}, runtimeRequest{m, snapshot, guard})
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (m *Runtime) snapshot(ctx context.Context) (*runtimeSnapshot, bool) {
	request, ok := ctx.Value(runtimeRequestKey{}).(runtimeRequest)
	return request.snapshot, ok && request.owner == m && request.snapshot != nil
}

// Status reads the captured request, never the atomic pointer again.
func (m *Runtime) Status(ctx context.Context) (RuntimeStatus, bool) {
	s, ok := m.snapshot(ctx)
	if !ok {
		return RuntimeStatus{}, false
	}
	return snapshotStatus(s), true
}

func (m *Runtime) Authenticate(r *http.Request) (Identity, error) {
	s, ok := m.snapshot(r.Context())
	if !ok {
		return Identity{}, ErrStoreUnavailable
	}
	if err := m.checkAdmission(r.Context(), s); err != nil {
		return Identity{}, err
	}
	if s.auth == nil {
		return Identity{}, ErrUnauthenticated
	}
	if s.prepared != nil {
		p, err := selectBoundProvider(r.Context(), s, r, false)
		if err != nil {
			return Identity{}, err
		}
		return p.Authenticate(r)
	}
	// Exactly one authenticator. No fallback.
	return s.auth.Authenticate(r)
}

func runtimeUnavailable(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	http.Error(w, "authentication unavailable", http.StatusServiceUnavailable)
}

// RegisterRoutes keeps route/method ownership stable across startup providers.
func (m *Runtime) RegisterRoutes(mux *http.ServeMux) {
	for pattern, operation := range map[string]func(*OIDCAuthenticator, http.ResponseWriter, *http.Request){
		"GET /api/auth/login":    (*OIDCAuthenticator).Login,
		"GET /api/auth/callback": (*OIDCAuthenticator).Callback,
		"POST /api/auth/logout":  (*OIDCAuthenticator).Logout,
	} {
		mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Cache-Control", "no-store")
			s, ok := m.snapshot(r.Context())
			if !ok {
				runtimeUnavailable(w)
				return
			}
			if err := m.checkAdmission(r.Context(), s); err != nil {
				runtimeUnavailable(w)
				return
			}
			if pattern == "GET /api/auth/callback" && m.readinessCallback(w, r) {
				return
			}
			if s.oidc == nil {
				http.NotFound(w, r)
				return
			}
			p := s.oidc
			if s.prepared != nil && pattern != "GET /api/auth/login" {
				selected, err := selectBoundProvider(r.Context(), s, r, pattern == "GET /api/auth/callback")
				if err != nil {
					if errors.Is(err, ErrStoreUnavailable) {
						runtimeUnavailable(w)
					} else {
						writeError(w, http.StatusUnauthorized, "unauthenticated")
					}
					return
				}
				p = selected
			}
			operation(p, w, r)
		})
	}
	mux.HandleFunc("GET /api/auth/config", func(w http.ResponseWriter, r *http.Request) {
		status, ok := m.Status(r.Context())
		if !ok {
			runtimeUnavailable(w)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]Provider{"provider": status.Provider})
	})
	mux.Handle("GET /api/auth/me", Require(m, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		identity, _ := IdentityFromContext(r.Context()) // Require validates first.
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(identity)
	})))
}

func snapshotStatus(s *runtimeSnapshot) RuntimeStatus {
	status := s.status
	if status.TransitionState == "draining" && !time.Now().Before(status.TransitionDeadline) {
		status.TransitionState = "expired"
	}
	return status
}
