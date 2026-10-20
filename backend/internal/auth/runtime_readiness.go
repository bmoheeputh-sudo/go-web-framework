package auth

import (
	"context"
	"crypto/subtle"
	"errors"
	"net/http"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"golang.org/x/oauth2"
)

// Readiness is an explicitly initiated, sessionless normal-callback test. Its
// separate opaque cookie and stored purpose cannot be used as normal login.
// There is no public start endpoint: only the trusted administrator service can
// reserve a candidate. A callback runs the normal OIDC PKCE/nonce/token verifier.
type readinessEntry struct {
	provider *OIDCAuthenticator
	prepared *PreparedOIDC
	timer    *time.Timer
	expires  time.Time
}

func readinessCookie(secure bool) string {
	if secure {
		return "__Host-gwf_oidc_readiness"
	}
	return "gwf_dev_oidc_readiness"
}

func (m *Runtime) BeginReadiness(p *PreparedOIDC, w http.ResponseWriter, r *http.Request, verified func(context.Context, Identity) error) error {
	if p == nil || verified == nil {
		return ErrRuntimeConflict
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	current := m.current.Load()
	if m.closed || m.mismatch || m.pending != nil || current == nil || current.status.Provider == GoogleIAP || current.status.DeploymentID != p.binding.DeploymentID || current.status.Environment != p.binding.Environment || len(m.readiness) >= 16 {
		return ErrRuntimeConflict
	}
	p.lease.mu.Lock()
	published := p.lease.published
	p.lease.mu.Unlock()
	if published || !p.lease.retain() {
		return ErrRuntimeConflict
	}
	if m.readiness == nil {
		m.readiness = map[string]*readinessEntry{}
	}
	copy := *p.provider
	e := &readinessEntry{prepared: p, expires: time.Now().Add(5 * time.Minute)}
	store := &readinessStore{base: p.store, binding: p.binding, expires: e.expires}
	copy.store = store
	copy.flowCookie = readinessCookie(copy.secureCookies)
	copy.onVerified = verified
	e.provider = &copy
	// Login only writes a test flow and a readiness cookie; no session operation.
	copy.Login(w, r)
	store.mu.Lock()
	token := store.token
	store.mu.Unlock()
	if token == "" {
		p.lease.release()
		return ErrStoreUnavailable
	}
	m.readiness[token] = e
	e.timer = time.AfterFunc(time.Until(e.expires), func() {
		m.mu.Lock()
		defer m.mu.Unlock()
		if m.readiness[token] == e {
			delete(m.readiness, token)
			e.prepared.lease.release()
		}
	})
	return nil
}
func (m *Runtime) readinessCallback(w http.ResponseWriter, r *http.Request) bool {
	var cookies []*http.Cookie
	for _, name := range []string{readinessCookie(true), readinessCookie(false)} {
		cookies = append(cookies, r.CookiesNamed(name)...)
	}
	if len(cookies) == 0 {
		return false
	}
	clearReadiness := func() {
		for _, secure := range []bool{true, false} {
			http.SetCookie(w, &http.Cookie{Name: readinessCookie(secure), Path: "/", MaxAge: -1, Secure: secure, HttpOnly: true, SameSite: http.SameSiteLaxMode})
		}
	}
	if len(cookies) != 1 {
		clearReadiness()
		writeError(w, 401, "invalid test callback")
		return true
	}
	m.mu.Lock()
	e := m.readiness[cookies[0].Value]
	if e != nil {
		delete(m.readiness, cookies[0].Value)
		e.timer.Stop()
	}
	m.mu.Unlock()
	if e == nil {
		clearReadiness()
		writeError(w, 401, "invalid test callback")
		return true
	}
	defer e.prepared.lease.release()
	if _, ok := e.prepared.lease.deadline(false); !ok {
		clearReadiness()
		writeError(w, 401, "expired test callback")
		return true
	}
	if !time.Now().Before(e.expires) {
		clearReadiness()
		writeError(w, 401, "expired test callback")
		return true
	}
	e.provider.Callback(w, r)
	return true
}

type readinessStore struct {
	base    *PostgresStore
	binding Binding
	expires time.Time
	mu      sync.Mutex
	token   string
}

func (s *readinessStore) addSession(context.Context, Identity, time.Time, string) (string, error) {
	return "", ErrUnauthenticated
}
func (s *readinessStore) identity(context.Context, string) (Identity, error) {
	return Identity{}, ErrUnauthenticated
}
func (s *readinessStore) deleteSession(context.Context, string) error { return ErrUnauthenticated }
func (s *readinessStore) addFlow(ctx context.Context, f loginFlow) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	// Generate an opaque token with the same CSPRNG as ordinary flows.
	token := oauth2.GenerateVerifier()
	b := s.binding
	_, err := s.base.db.Exec(ctx, `INSERT INTO framework.oidc_login_flows(token_hash,state_hash,nonce,pkce_verifier,expires_at,binding_source,deployment_id,environment,revision_id,issuer,client_id,flow_purpose)
 VALUES($1,$2,$3,$4,$5,'database',$6,$7,$8,$9,$10,'normal_callback')`, tokenHash(token), tokenHash(f.State), f.Nonce, f.Verifier, s.expires, b.DeploymentID, b.Environment, b.RevisionID, b.Issuer, b.ClientID)
	if err != nil {
		return "", ErrStoreUnavailable
	}
	s.mu.Lock()
	s.token = token
	s.mu.Unlock()
	return token, nil
}
func (s *readinessStore) takeFlow(ctx context.Context, token, state string) (loginFlow, error) {
	if !validToken(token) {
		return loginFlow{}, ErrUnauthenticated
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	b := s.binding
	var f loginFlow
	var hash []byte
	var fresh bool
	err := s.base.db.QueryRow(ctx, `DELETE FROM framework.oidc_login_flows WHERE token_hash=$1 AND binding_source='database' AND deployment_id=$2 AND environment=$3 AND revision_id=$4 AND issuer=$5 AND client_id=$6 AND flow_purpose='normal_callback' AND activation_generation IS NULL
 RETURNING state_hash,nonce,pkce_verifier,expires_at,expires_at>clock_timestamp()`, tokenHash(token), b.DeploymentID, b.Environment, b.RevisionID, b.Issuer, b.ClientID).Scan(&hash, &f.Nonce, &f.Verifier, &f.Expires, &fresh)
	if errors.Is(err, pgx.ErrNoRows) {
		return loginFlow{}, ErrUnauthenticated
	}
	if err != nil {
		return loginFlow{}, ErrStoreUnavailable
	}
	if !fresh || subtle.ConstantTimeCompare(hash, tokenHash(state)) != 1 {
		return loginFlow{}, ErrUnauthenticated
	}
	return f, nil
}
