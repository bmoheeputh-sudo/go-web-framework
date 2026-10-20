package authconfig

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/bmoheeputh-sudo/go-web-framework/backend/internal/access"
	"github.com/bmoheeputh-sudo/go-web-framework/backend/internal/auth"
	"github.com/jackc/pgx/v5"
	"golang.org/x/oauth2"
)

const testLifetime = 5 * time.Minute

type connectionResult struct {
	ID                string         `json:"id"`
	RevisionID        string         `json:"revision_id"`
	Version           int64          `json:"configuration_version"`
	Generation        int64          `json:"generation"`
	Status            string         `json:"status"`
	Expires           time.Time      `json:"expires_at"`
	CallbackURI       string         `json:"callback_uri"`
	Reason            string         `json:"reason,omitempty"`
	Identity          *auth.Identity `json:"tested_identity,omitempty"`
	EvidenceID        string         `json:"evidence_id,omitempty"`
	EvidenceExpiresAt *time.Time     `json:"evidence_expires_at,omitempty"`
}
type connectionTest struct {
	mu                     sync.Mutex
	result                 connectionResult
	actor                  string
	context                context.Context // verified framework values, retained only until bounded expiry
	metadata               Metadata
	state, nonce, verifier string
	browser                [32]byte
	probe                  *connectionProbe
}

func (*connectionTest) Format(w fmt.State, _ rune) { _, _ = w.Write([]byte("[OIDC CONNECTION TEST]")) }
func (*connectionProbe) Format(w fmt.State, _ rune) {
	_, _ = w.Write([]byte("[OIDC CONNECTION PROBE]"))
}

type connectionTests struct {
	mu      sync.Mutex
	entries map[string]*connectionTest
	repo    *Repository
	origin  string
	client  func(context.Context, string) (*http.Client, error)
}

func newConnectionTests(repo *Repository, origin string) *connectionTests {
	return &connectionTests{entries: map[string]*connectionTest{}, repo: repo, origin: origin, client: newTestClient}
}

// All accesses revalidate the verified active administrator under the existing
// advisory lock. Revision state/generation are checked in the same transaction.
func (r *Repository) testTransaction(ctx context.Context, id string, generation int64, testID, action, outcome string, identity *auth.Identity, secret *Secret) (Metadata, error) {
	if !validID(id) || generation < 1 {
		return Metadata{}, ErrInvalid
	}
	var m Metadata
	err := r.transaction(ctx, func(ctx context.Context, tx pgx.Tx, actor access.User) error {
		var err error
		m, err = r.testTransactionTx(ctx, tx, actor, id, generation, testID, action, outcome, identity, secret)
		return err
	})
	if err != nil && secret != nil {
		clear(secret.value)
	}
	return m, err
}
func (r *Repository) testTransactionTx(ctx context.Context, tx pgx.Tx, actor access.User, id string, generation int64, testID, action, outcome string, identity *auth.Identity, secret *Secret) (Metadata, error) {
	var m Metadata
	var err error
	m, err = r.get(ctx, tx, id)
	if err != nil {
		return Metadata{}, err
	}
	if m.Generation != generation {
		return Metadata{}, ErrConflict
	}
	if m.Provider != auth.OIDC || m.Status != Approved {
		return Metadata{}, ErrInvalid
	}
	if secret != nil {
		*secret, err = r.readSecret(ctx, tx, m)
		if err != nil {
			return Metadata{}, err
		}
	}
	if action == "" {
		return m, nil
	}
	details := struct {
		TestID       string `json:"test_id"`
		Generation   int64  `json:"generation"`
		Version      int64  `json:"configuration_version"`
		Outcome      string `json:"outcome"`
		IdentityHash string `json:"identity_hash,omitempty"`
	}{TestID: testID, Generation: generation, Version: m.Version, Outcome: outcome}
	if identity != nil {
		sum := sha256.Sum256([]byte(identity.Issuer + "\x00" + identity.Subject))
		details.IdentityHash = hex.EncodeToString(sum[:])
	}
	if access.RecordAudit(ctx, tx, actor.ID, action, id, details) != nil {
		return Metadata{}, ErrAudit
	}
	return m, nil
}

// Only the correlated callback calls this after cryptographic verification.
func (r *Repository) completeVerifiedTest(ctx context.Context, e *connectionTest, identity auth.Identity) (TestEvidence, error) {
	var evidence TestEvidence
	err := r.transaction(ctx, func(ctx context.Context, tx pgx.Tx, actor access.User) error {
		if time.Now().After(e.result.Expires) {
			return ErrConflict
		}
		if _, err := r.testTransactionTx(ctx, tx, actor, e.result.RevisionID, e.result.Generation, e.result.ID, "auth_config.test_finished", "succeeded", &identity, nil); err != nil {
			return err
		}
		now := time.Now()
		var err error
		evidence, err = r.recordTestEvidenceTx(ctx, tx, actor, verifiedTestEvidence{revisionID: e.result.RevisionID, revisionGeneration: e.result.Generation, identity: identity, purpose: IsolatedConnection, completedAt: now, expiresAt: now.Add(5 * time.Minute)})
		return err
	})
	if err != nil {
		return TestEvidence{}, err
	}
	return evidence, nil
}

func (s *connectionTests) get(id string) *connectionTest {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.entries[id]
}
func (s *connectionTests) allocate(ctx context.Context, id string, generation int64) (*connectionTest, error) {
	actor, ok := access.Principal(ctx)
	if !ok {
		return nil, ErrDenied
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	active := 0
	for id, e := range s.entries {
		// Never hold the registry lock while waiting for discovery or an audit.
		// Busy entries conservatively count as active for the initiating actor.
		if !e.mu.TryLock() {
			if e.actor == actor.ID {
				active++
			}
			continue
		}
		if time.Now().After(e.result.Expires.Add(testLifetime)) {
			e.probe = nil
			e.context = nil
			e.result.Status = "expired"
			e.state, e.nonce, e.verifier = "", "", ""
			e.browser = [32]byte{}
			delete(s.entries, id)
		} else if e.actor == actor.ID && pending(e.result.Status) {
			active++
		}
		e.mu.Unlock()
	}
	if len(s.entries) >= 64 || active >= 3 {
		return nil, ErrConflict
	}
	e := &connectionTest{actor: actor.ID, context: context.WithoutCancel(ctx), result: connectionResult{ID: oauth2.GenerateVerifier(), RevisionID: id, Generation: generation, Status: "checking", Expires: time.Now().Add(testLifetime)}}
	s.entries[e.result.ID] = e
	return e, nil
}
func pending(status string) bool {
	return status == "checking" || status == "pending" || status == "processing"
}
func cookieName(e *connectionTest) string {
	if strings.HasPrefix(e.result.CallbackURI, "https://") {
		return "__Host-gwf_oidc_test_" + e.result.ID
	}
	return "gwf_dev_oidc_test_" + e.result.ID
}
func testCookie(w http.ResponseWriter, e *connectionTest, value string) {
	age := int(time.Until(e.result.Expires).Seconds())
	if value == "" {
		age = -1
	}
	http.SetCookie(w, &http.Cookie{Name: cookieName(e), Value: value, Path: "/", HttpOnly: true, Secure: strings.HasPrefix(e.result.CallbackURI, "https://"), SameSite: http.SameSiteLaxMode, MaxAge: age})
}

// finish is called with the entry locked. Audit success precedes publication of
// a successful result. No database transaction spans an external HTTP request.
func (s *connectionTests) finish(ctx context.Context, e *connectionTest, status, reason string, identity *auth.Identity) {
	if !pending(e.result.Status) {
		return
	}
	if time.Now().After(e.result.Expires) {
		status, reason, identity = "expired", "expired", nil
	}
	var err error
	if status == "succeeded" && identity != nil {
		var evidence TestEvidence
		evidence, err = s.repo.completeVerifiedTest(ctx, e, *identity)
		if err == nil {
			e.result.EvidenceID = evidence.ID
			e.result.EvidenceExpiresAt = &evidence.ExpiresAt
		}
	} else {
		_, err = s.repo.testTransaction(ctx, e.result.RevisionID, e.result.Generation, e.result.ID, "auth_config.test_finished", status, identity, nil)
	}
	if err != nil {
		status, reason, identity = "failed", "authorization_or_audit_unavailable", nil
	}
	e.result.Status, e.result.Reason, e.result.Identity = status, reason, identity
	e.probe = nil
	e.context = nil
	e.nonce = ""
	e.verifier = ""
	e.state = ""
	e.browser = [32]byte{}
}
func (s *connectionTests) start(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Generation *int64 `json:"expected_generation"`
	}
	if !access.DecodeJSON(w, r, &body) {
		return
	}
	if body.Generation == nil {
		httpError(w, ErrInvalid)
		return
	}
	e, err := s.allocate(r.Context(), r.PathValue("id"), *body.Generation)
	if err != nil {
		httpError(w, err)
		return
	}
	// A reservation counts towards the bound even while discovery is in flight.
	e.mu.Lock()
	defer e.mu.Unlock()
	var secret Secret
	defer func() { clear(secret.value) }()
	e.metadata, err = s.repo.testTransaction(r.Context(), e.result.RevisionID, e.result.Generation, e.result.ID, "auth_config.test_started", "checking", nil, &secret)
	if err != nil {
		e.result.Status = "failed"
		e.context = nil
		httpError(w, err)
		return
	}
	e.result.Version = e.metadata.Version
	e.result.CallbackURI, err = testCallback(s.origin, e.metadata)
	if err == nil {
		var client *http.Client
		client, err = s.client(r.Context(), e.metadata.IssuerURL)
		if err == nil {
			e.probe, err = newConnectionProbe(r.Context(), e.metadata, secret, e.result.CallbackURI, client)
		}
	}
	if err != nil {
		s.finish(r.Context(), e, "failed", "discovery_failed", nil)
		reply(w, 201, e.result)
		return
	}
	// Check authorization again after outbound work before releasing a login URL.
	if _, err = s.repo.testTransaction(r.Context(), e.result.RevisionID, e.result.Generation, e.result.ID, "", "", nil, nil); err != nil {
		s.finish(r.Context(), e, "failed", "authorization_changed", nil)
		httpError(w, err)
		return
	}
	e.state = e.result.ID + "." + oauth2.GenerateVerifier()
	e.nonce = oauth2.GenerateVerifier()
	e.verifier = oauth2.GenerateVerifier()
	browser := oauth2.GenerateVerifier()
	e.browser = sha256.Sum256([]byte(browser))
	e.result.Status = "pending"
	testCookie(w, e, browser)
	reply(w, 201, struct {
		connectionResult
		AuthorizationURL string `json:"authorization_url"`
	}{e.result, e.probe.authorization(e.state, e.nonce, e.verifier)})
}
func (s *connectionTests) inspect(w http.ResponseWriter, r *http.Request) {
	e := s.get(r.PathValue("test_id"))
	actor, _ := access.Principal(r.Context())
	if e == nil || actor.ID != e.actor {
		httpError(w, ErrNotFound)
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if _, err := s.repo.testTransaction(r.Context(), e.result.RevisionID, e.result.Generation, e.result.ID, "", "", nil, nil); err != nil {
		httpError(w, err)
		return
	}
	if time.Now().After(e.result.Expires) && pending(e.result.Status) {
		s.finish(r.Context(), e, "expired", "expired", nil)
	}
	if r.Method == "POST" {
		var body struct{}
		if !access.DecodeJSON(w, r, &body) {
			return
		}
		s.finish(r.Context(), e, "cancelled", "cancelled", nil)
		testCookie(w, e, "")
	}
	reply(w, 200, e.result)
}

// valueContext combines the callback deadline with only the server-retained,
// previously verified context values. No callback identity is accepted.
type valueContext struct {
	context.Context
	values context.Context
}

func (c valueContext) Value(key any) any { return c.values.Value(key) }
func (s *connectionTests) callback(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	defer http.Redirect(w, r, s.origin+"/settings", http.StatusSeeOther)
	if len(r.URL.RawQuery) > 8192 {
		return
	}
	q, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		return
	}
	for _, key := range []string{"state", "code", "error", "iss"} {
		if len(q[key]) > 1 {
			return
		}
	}
	id, _, ok := strings.Cut(q.Get("state"), ".")
	if !ok {
		return
	}
	e := s.get(id)
	if e == nil {
		return
	}
	e.mu.Lock()
	cookie, err := r.Cookie(cookieName(e))
	var browser [32]byte
	if err == nil {
		browser = sha256.Sum256([]byte(cookie.Value))
	}
	if e.result.Status != "pending" || err != nil || subtle.ConstantTimeCompare(browser[:], e.browser[:]) != 1 || subtle.ConstantTimeCompare([]byte(q.Get("state")), []byte(e.state)) != 1 {
		e.mu.Unlock()
		return
	}
	testCookie(w, e, "")
	ctx, cancel := context.WithTimeout(valueContext{r.Context(), e.context}, 20*time.Second)
	defer cancel()
	if time.Now().After(e.result.Expires) {
		s.finish(ctx, e, "expired", "expired", nil)
		e.mu.Unlock()
		return
	}
	if q.Get("error") != "" || q.Get("code") == "" || (q.Get("iss") != "" && q.Get("iss") != e.metadata.IssuerURL) {
		s.finish(ctx, e, "failed", "handshake_failed", nil)
		e.mu.Unlock()
		return
	}
	if _, err = s.repo.testTransaction(ctx, e.result.RevisionID, e.result.Generation, e.result.ID, "", "", nil, nil); err != nil {
		s.finish(ctx, e, "failed", "authorization_changed", nil)
		e.mu.Unlock()
		return
	}
	// Consume once before any exchange. Replay cannot execute the token request.
	e.result.Status = "processing"
	probe, nonce, verifier := e.probe, e.nonce, e.verifier
	e.mu.Unlock()
	identity, err := probe.exchange(ctx, q.Get("code"), nonce, verifier)
	e.mu.Lock()
	defer e.mu.Unlock()
	if err != nil {
		s.finish(ctx, e, "failed", "handshake_failed", nil)
		return
	}
	s.finish(ctx, e, "succeeded", "", &identity)
}
func (s *connectionTests) register(mux *http.ServeMux, route func(string, http.HandlerFunc)) {
	available := func(handler http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Referrer-Policy", "no-referrer")
			if s.repo == nil {
				httpError(w, ErrUnavailable)
				return
			}
			handler(w, r)
		}
	}
	route("POST /api/admin/auth/settings/{id}/test", available(s.start))
	route("GET /api/admin/auth/tests/{test_id}", available(s.inspect))
	route("POST /api/admin/auth/tests/{test_id}/cancel", available(s.inspect))
	// Only the one-time correlated callback is public. It never authenticates an
	// application request and cannot create a session, user or role assignment.
	mux.HandleFunc("GET /api/auth/test/callback", available(s.callback))
}
