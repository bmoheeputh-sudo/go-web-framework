package auth

import (
	"context"
	"crypto"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bmoheeputh-sudo/go-web-framework/backend/internal/testdb"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/oauth2"
)

const revisionOne = "11111111-1111-4111-8111-111111111111"
const revisionTwo = "22222222-2222-4222-8222-222222222222"

// Synthetic constraints-only fixture; never reads application environment/DB.
func runtimeRevision(t *testing.T, pool *pgxpool.Pool, id string, generation int64, previous, issuer string) {
	t.Helper()
	runtimeRevisionWithTransition(t, pool, id, generation, previous, issuer, 30*time.Minute)
}
func runtimeRevisionWithTransition(t *testing.T, pool *pgxpool.Pool, id string, generation int64, previous, issuer string, transition time.Duration) {
	t.Helper()
	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	var actor string
	err = tx.QueryRow(ctx, `INSERT INTO framework.users(issuer,subject,provider) VALUES('https://admin.test','actor','oidc') ON CONFLICT(issuer,subject) DO UPDATE SET display_name='' RETURNING id::text`).Scan(&actor)
	if err != nil {
		t.Fatal(err)
	}
	_, err = tx.Exec(ctx, `INSERT INTO framework.auth_config_revisions(id,deployment_id,environment,configuration_version,provider,issuer_url,client_id,redirect_uri,secret_ciphertext,secret_nonce,encryption_format,encryption_key_id,created_by)
 VALUES($1,'test-deployment','development',$2,'oidc',$3,'client-id',$4,decode(repeat('00',17),'hex'),decode(repeat('00',12),'hex'),1,'synthetic',$5)`, id, generation, issuer, testOrigin+"/api/auth/callback", actor)
	if err != nil {
		t.Fatal(err)
	}
	_, err = tx.Exec(ctx, `INSERT INTO framework.auth_config_lifecycle(revision_id,deployment_id,environment,updated_by) VALUES($1,'test-deployment','development',$2)`, id, actor)
	if err != nil {
		t.Fatal(err)
	}
	for _, status := range []string{"validated", "approved"} {
		if _, err = tx.Exec(ctx, `UPDATE framework.auth_config_lifecycle SET status=$2,generation=generation+1,validation='{"check":"static","version":1}' WHERE revision_id=$1`, id, status); err != nil {
			t.Fatal(err)
		}
	}
	if previous != "" {
		if _, err = tx.Exec(ctx, `UPDATE framework.auth_config_lifecycle SET status='superseded',generation=generation+1 WHERE revision_id=$1`, previous); err != nil {
			t.Fatal(err)
		}
	}
	if _, err = tx.Exec(ctx, `UPDATE framework.auth_config_lifecycle SET status='active',generation=generation+1 WHERE revision_id=$1`, id); err != nil {
		t.Fatal(err)
	}
	var when time.Time
	if err = tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&when); err != nil {
		t.Fatal(err)
	}
	_, err = tx.Exec(ctx, `INSERT INTO framework.auth_activation_history(deployment_id,environment,generation,previous_revision_id,target_revision_id,actor_user_id,activated_at,transition_deadline,reason)
 VALUES('test-deployment','development',$1,NULLIF($2,'')::uuid,$3,$4,$5,$5::timestamptz+($6::double precision*interval '1 second'),'test fixture')`, generation, previous, id, actor, when, transition.Seconds())
	if err != nil {
		t.Fatal(err)
	}
	if generation == 1 {
		_, err = tx.Exec(ctx, `INSERT INTO framework.auth_activation_heads(deployment_id,environment,generation,runtime_source,active_revision_id,activated_at) VALUES('test-deployment','development',$1,'database',$2,$3)`, generation, id, when)
	} else {
		_, err = tx.Exec(ctx, `UPDATE framework.auth_activation_heads SET generation=$1,active_revision_id=$2,activated_at=$3 WHERE deployment_id='test-deployment' AND environment='development'`, generation, id, when)
	}
	if err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
}
func preparedRuntime(t *testing.T, f *testIssuer, store *PostgresStore, id string, generation int64, closed *atomic.Int32) *PreparedOIDC {
	t.Helper()
	c := f.server.Client()
	c.Timeout = 10 * time.Second
	b := Binding{Source: "database", DeploymentID: "test-deployment", Environment: "development", RevisionID: id, ActivationGeneration: generation, Issuer: f.server.URL, ClientID: "client-id", Purpose: "login"}
	p, err := NewPreparedDatabaseOIDC(f.config(), oauth2.Endpoint{AuthURL: f.server.URL + "/authorize", TokenURL: f.server.URL + "/token", AuthStyle: oauth2.AuthStyleInHeader}, &oidc.StaticKeySet{PublicKeys: []crypto.PublicKey{&f.key.PublicKey}}, []string{oidc.RS256}, c, store, b, func() { closed.Add(1); c.CloseIdleConnections() })
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	return p
}
func runtimeLogin(t *testing.T, h http.Handler, f *testIssuer) (string, *http.Cookie) {
	t.Helper()
	w := httptest.NewRecorder()
	h.ServeHTTP(w, runtimeRequestFor("GET", "/api/auth/login"))
	if w.Code != 302 {
		t.Fatal("login failed", w.Code)
	}
	cookie := responseCookie(t, w, flowCookie)
	c := f.server.Client()
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	response, err := c.Get(w.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != 302 {
		t.Fatal("authorization failed")
	}
	return response.Header.Get("Location"), cookie
}
func runtimeCallback(t *testing.T, h http.Handler, location string, cookie *http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	u, err := url.Parse(location)
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, runtimeRequestFor("GET", u.RequestURI(), cookie))
	return w
}
func TestDatabaseRuntimeBoundSessionsAndDrainingCallbacks(t *testing.T) {
	pool, _ := testdb.New(t)
	testdb.Migrations(t, pool, "up")
	f := newTestIssuer(t)
	store, _ := NewPostgresStore(pool, testSessionConfig())
	m := runtimeFor(t, runtimeLocal(t))
	defer m.Close()
	h := runtimeRouter(m)
	var closed1, closed2 atomic.Int32
	runtimeRevision(t, pool, revisionOne, 1, "", f.server.URL)
	p1 := preparedRuntime(t, f, store, revisionOne, 1, &closed1)
	ticket, err := m.Stage(p1, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err = ticket.Commit(time.Now()); err != nil {
		t.Fatal(err)
	}
	callback, flow := runtimeLogin(t, h, f)
	binding, err := store.FlowBinding(context.Background(), flow.Value)
	if err != nil || binding != p1.binding {
		t.Fatal("flow binding missing", err)
	}
	// A second login remains in flight across publication.
	w := runtimeCallback(t, h, callback, flow)
	session := responseCookie(t, w, sessionCookie)
	oldCallback, oldFlow := runtimeLogin(t, h, f)
	f2 := newTestIssuer(t)
	runtimeRevision(t, pool, revisionTwo, 2, revisionOne, f2.server.URL)
	p2 := preparedRuntime(t, f2, store, revisionTwo, 2, &closed2)
	next, err := m.Stage(p2, 1)
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Minute)
	if err = next.Commit(deadline); err != nil {
		t.Fatal(err)
	}
	w = runtimeCallback(t, h, oldCallback, oldFlow)
	if w.Code != 303 || w.Header().Get("Location") != testOrigin+"/" {
		t.Fatal("old callback failed", w.Code)
	}
	drained := responseCookie(t, w, sessionCookie)
	b, err := store.SessionBinding(context.Background(), drained.Value)
	if err != nil || b != p1.binding {
		t.Fatal("old callback rebound to active revision")
	}
	var expires time.Time
	if err = pool.QueryRow(context.Background(), `SELECT expires_at FROM framework.sessions WHERE token_hash=$1`, tokenHash(drained.Value)).Scan(&expires); err != nil || expires.After(deadline) {
		t.Fatal("drained callback extended expiry", err)
	}
	if runtimeCallback(t, h, oldCallback, oldFlow).Code != 401 {
		t.Fatal("callback replay admitted")
	}
	for _, c := range []*http.Cookie{session, drained} {
		w = httptest.NewRecorder()
		h.ServeHTTP(w, runtimeRequestFor("GET", "/api/auth/me", c))
		if w.Code != 200 {
			t.Fatal("old session failed before grace deadline", w.Code)
		}
	}
	callback, flow = runtimeLogin(t, h, f2)
	w = runtimeCallback(t, h, callback, flow)
	active := responseCookie(t, w, sessionCookie)
	b, err = store.SessionBinding(context.Background(), active.Value)
	if err != nil || b != p2.binding {
		t.Fatal("new session not active-bound")
	}
	// Unknown configuration must not update activity.
	var before, after time.Time
	pool.QueryRow(context.Background(), `SELECT last_activity_at FROM framework.sessions WHERE token_hash=$1`, tokenHash(active.Value)).Scan(&before)
	if _, err = p1.provider.store.identity(context.Background(), active.Value); !errors.Is(err, ErrUnauthenticated) {
		t.Fatal("cross-revision identity accepted")
	}
	pool.QueryRow(context.Background(), `SELECT last_activity_at FROM framework.sessions WHERE token_hash=$1`, tokenHash(active.Value)).Scan(&after)
	if before != after {
		t.Fatal("unaccepted credential touched activity")
	}
	p1.lease.retire(time.Now().Add(-time.Second))
	for _, c := range []*http.Cookie{session, drained} {
		w = httptest.NewRecorder()
		h.ServeHTTP(w, runtimeRequestFor("GET", "/api/auth/me", c))
		if w.Code != 401 {
			t.Fatal("retired session resurrected", w.Code)
		}
	}
	if closed1.Load() != 1 {
		t.Fatal("retired transport not closed")
	}
	legacy, err := store.addSession(context.Background(), Identity{Issuer: f2.server.URL, Subject: "legacy", Provider: OIDC}, time.Now().Add(time.Hour), "")
	if err != nil {
		t.Fatal(err)
	}
	w = httptest.NewRecorder()
	h.ServeHTTP(w, runtimeRequestFor("GET", "/api/auth/me", &http.Cookie{Name: sessionCookie, Value: legacy}))
	if w.Code != 401 {
		t.Fatal("legacy session elevated")
	}
	legacyBinding, _ := store.SessionBinding(context.Background(), legacy)
	if legacyBinding.Source != "legacy" {
		t.Fatal("legacy rebound")
	}
	// An expired active-generation session stays rejected, then can be revoked.
	if _, err = pool.Exec(context.Background(), `UPDATE framework.sessions SET created_at=clock_timestamp()-interval '2 hours',last_activity_at=clock_timestamp()-interval '1 hour',expires_at=clock_timestamp()-interval '1 second' WHERE token_hash=$1`, tokenHash(active.Value)); err != nil {
		t.Fatal(err)
	}
	w = httptest.NewRecorder()
	h.ServeHTTP(w, runtimeRequestFor("GET", "/api/auth/me", active))
	if w.Code != 401 {
		t.Fatal("expired session resurrected")
	}
	// Logout revokes, and neither old nor new provider can resurrect the row.
	r := runtimeRequestFor("POST", "/api/auth/logout", active)
	r.Header.Set("Origin", testOrigin)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 204 {
		t.Fatal("logout failed", w.Code)
	}
	w = httptest.NewRecorder()
	h.ServeHTTP(w, runtimeRequestFor("GET", "/api/auth/me", active))
	if w.Code != 401 {
		t.Fatal("revoked session accepted")
	}
}
func TestDatabaseRuntimeLeaseCleanupAndPublicationConflict(t *testing.T) {
	pool, _ := testdb.New(t)
	testdb.Migrations(t, pool, "up")
	f := newTestIssuer(t)
	store, _ := NewPostgresStore(pool, testSessionConfig())
	m := runtimeFor(t, runtimeLocal(t))
	defer m.Close()
	var closed atomic.Int32
	p := preparedRuntime(t, f, store, revisionOne, 1, &closed)
	first, _ := m.Stage(p, 0)
	stale, _ := m.Stage(p, 0)
	if err := first.Commit(time.Now()); err != nil {
		t.Fatal(err)
	}
	entered, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	go func() {
		m.Capture(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { close(entered); <-release })).ServeHTTP(httptest.NewRecorder(), runtimeRequestFor("GET", "/held"))
		close(done)
	}()
	<-entered
	m.Close()
	if closed.Load() != 0 {
		t.Fatal("in-flight authenticator closed early")
	}
	close(release)
	<-done
	if closed.Load() != 1 {
		t.Fatal("transport not closed after lease release")
	}
	if err := stale.Commit(time.Now()); !errors.Is(err, ErrRuntimeMismatch) {
		t.Fatal("stale publication accepted")
	}
	w := httptest.NewRecorder()
	runtimeRouter(m).ServeHTTP(w, runtimeRequestFor("GET", "/api/auth/me"))
	if w.Code != 503 {
		t.Fatal("publication failure fell back to Local DEV")
	}
}
func TestDatabaseRuntimeIAPPinning(t *testing.T) {
	iap, err := NewGoogleIAP("/projects/123/apps/test-app")
	if err != nil {
		t.Fatal(err)
	}
	m := runtimeFor(t, iap)
	if _, err = m.Stage(&PreparedOIDC{binding: Binding{ActivationGeneration: 1}}, 0); !errors.Is(err, ErrRuntimeConflict) {
		t.Fatal("IAP could be replaced")
	}
}

func TestProviderLeaseDeadlineCleanup(t *testing.T) {
	var closed atomic.Int32
	lease := &providerLease{cleanup: func() { closed.Add(1) }}
	if !lease.retain() {
		t.Fatal("lease unavailable")
	}
	lease.retire(time.Now().Add(20 * time.Millisecond))
	time.Sleep(30 * time.Millisecond)
	if _, ok := lease.deadline(false); ok {
		t.Fatal("expired lease admits credentials")
	}
	if closed.Load() != 0 {
		t.Fatal("expired lease closed an in-flight request")
	}
	lease.release()
	if closed.Load() != 1 {
		t.Fatal("expired resource retained")
	}
	lease.retire(time.Now())
	if closed.Load() != 1 {
		t.Fatal("cleanup not idempotent")
	}
}

func TestRuntimeCaptureReleasesProviderLeaseOnCompletionAndCancellation(t *testing.T) {
	for _, mode := range []string{"normal", "cancel", "deadline"} {
		t.Run(mode, func(t *testing.T) {
			var closed atomic.Int32
			lease := &providerLease{cleanup: func() { closed.Add(1) }}
			m := &Runtime{}
			m.current.Store(&runtimeSnapshot{prepared: &PreparedOIDC{lease: lease}})
			entered := make(chan struct{})
			h := m.Capture(m.Capture(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
				close(entered)
				if mode != "normal" {
					<-r.Context().Done()
				}
			})))
			ctx := context.Background()
			var cancel context.CancelFunc
			if mode == "deadline" {
				ctx, cancel = context.WithTimeout(ctx, 20*time.Millisecond)
			} else {
				ctx, cancel = context.WithCancel(ctx)
			}
			defer cancel()
			done := make(chan struct{})
			go func() {
				h.ServeHTTP(httptest.NewRecorder(), runtimeRequestFor("GET", "/held").WithContext(ctx))
				close(done)
			}()
			<-entered
			if mode != "normal" {
				m.Close() // An in-flight request keeps its leased transport alive.
				if closed.Load() != 0 {
					t.Fatal("retired provider closed before handler completion")
				}
				if mode == "cancel" {
					cancel()
				}
			}
			<-done
			m.Close()
			if closed.Load() != 1 {
				t.Fatalf("provider cleanup calls = %d, want one", closed.Load())
			}
			lease.mu.Lock()
			refs := lease.refs
			lease.mu.Unlock()
			if refs != 0 {
				t.Fatalf("outstanding request leases = %d", refs)
			}
		})
	}
}

func TestConcurrentReconciliationAndRequestCancellationReleasesRetiredLease(t *testing.T) {
	pool, _ := testdb.New(t)
	testdb.Migrations(t, pool, "up")
	f := newTestIssuer(t)
	store, err := NewPostgresStore(pool, testSessionConfig())
	if err != nil {
		t.Fatal(err)
	}
	m := runtimeFor(t, runtimeLocal(t))
	defer m.Close()
	var firstClosed, secondClosed atomic.Int32
	first := preparedRuntime(t, f, store, revisionOne, 1, &firstClosed)
	staged, err := m.Stage(first, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := staged.Commit(time.Now()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	entered, done := make(chan struct{}), make(chan struct{})
	go func() {
		m.Capture(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { close(entered); <-r.Context().Done() })).ServeHTTP(httptest.NewRecorder(), runtimeRequestFor("GET", "/held").WithContext(ctx))
		close(done)
	}()
	<-entered
	second := preparedRuntime(t, f, store, revisionTwo, 2, &secondClosed)
	now := time.Now()
	candidate, err := NewDatabaseRuntime(second, nil, now, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Reconcile(candidate, 1); err != nil {
		t.Fatal(err)
	}
	candidate.Close()
	if firstClosed.Load() != 0 {
		t.Fatal("reconciliation closed an active request")
	}
	cancel()
	<-done
	if firstClosed.Load() != 1 {
		t.Fatalf("retired provider cleanup count %d", firstClosed.Load())
	}
	m.Close()
	if secondClosed.Load() != 1 {
		t.Fatalf("active provider cleanup count %d", secondClosed.Load())
	}
}
func TestDatabaseRuntimeCASConflictWithoutFallback(t *testing.T) {
	pool, _ := testdb.New(t)
	testdb.Migrations(t, pool, "up")
	f := newTestIssuer(t)
	store, _ := NewPostgresStore(pool, testSessionConfig())
	m := runtimeFor(t, runtimeLocal(t))
	defer m.Close()
	var closed atomic.Int32
	p := preparedRuntime(t, f, store, revisionOne, 1, &closed)
	first, _ := m.Stage(p, 0)
	stale, _ := m.Stage(p, 0)
	if err := first.Commit(time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := stale.Commit(time.Now()); !errors.Is(err, ErrRuntimeMismatch) {
		t.Fatal("stale CAS accepted", err)
	}
	status, desired, mismatch := m.ControlStatus()
	if status.Provider != OIDC || status.AppliedGeneration != 1 || desired != 1 || !mismatch {
		t.Fatal("applied state lost or fallback chosen")
	}
	w := httptest.NewRecorder()
	runtimeRouter(m).ServeHTTP(w, runtimeRequestFor("GET", "/api/auth/me"))
	if w.Code != 503 {
		t.Fatal("mismatched runtime still authenticates")
	}
}

func TestDatabaseCallbackCrossingRetirementCannotMintSession(t *testing.T) {
	pool, _ := testdb.New(t)
	testdb.Migrations(t, pool, "up")
	f := newTestIssuer(t)
	store, _ := NewPostgresStore(pool, testSessionConfig())
	m := runtimeFor(t, runtimeLocal(t))
	defer m.Close()
	h := runtimeRouter(m)
	var closed1, closed2 atomic.Int32
	runtimeRevision(t, pool, revisionOne, 1, "", f.server.URL)
	p1 := preparedRuntime(t, f, store, revisionOne, 1, &closed1)
	entered, release := make(chan struct{}), make(chan struct{})
	base := p1.provider.client.Transport
	// Install the synthetic transport before publication; published configs stay immutable.
	p1.provider.client.Transport = iapRoundTripper(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path == "/token" {
			close(entered)
			select {
			case <-release:
			case <-r.Context().Done():
				return nil, r.Context().Err()
			}
		}
		return base.RoundTrip(r)
	})
	first, _ := m.Stage(p1, 0)
	if err := first.Commit(time.Now()); err != nil {
		t.Fatal(err)
	}
	callback, cookie := runtimeLogin(t, h, f)
	u, _ := url.Parse(callback)
	r := runtimeRequestFor("GET", u.RequestURI(), cookie)
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() { w := httptest.NewRecorder(); h.ServeHTTP(w, r); done <- w }()
	<-entered
	runtimeRevision(t, pool, revisionTwo, 2, revisionOne, f.server.URL)
	p2 := preparedRuntime(t, f, store, revisionTwo, 2, &closed2)
	next, err := m.Stage(p2, 1)
	if err != nil {
		t.Fatal(err)
	}
	if err = next.Commit(time.Now()); err != nil {
		t.Fatal(err)
	}
	if closed1.Load() != 0 {
		t.Fatal("closed transport under an in-flight exchange")
	}
	close(release)
	w := <-done
	if w.Header().Get("Location") != testOrigin+"/?auth_error=login_failed" {
		t.Fatal("expired callback accepted")
	}
	var sessions int
	if err = pool.QueryRow(context.Background(), `SELECT count(*) FROM framework.sessions`).Scan(&sessions); err != nil || sessions != 0 {
		t.Fatal("callback crossing deadline minted session", err)
	}
	if closed1.Load() != 1 {
		t.Fatal("completed retired exchange leaked transport")
	}
}

func TestInitialCutoverRejectsLocalDevAndEnvironmentCredentials(t *testing.T) {
	for _, source := range []string{"local_dev", "legacy", "environment"} {
		t.Run(source, func(t *testing.T) {
			pool, _ := testdb.New(t)
			testdb.Migrations(t, pool, "up")
			ctx := context.Background()
			f := newTestIssuer(t)
			store, _ := NewPostgresStore(pool, testSessionConfig())
			var provider Authenticator = runtimeLocal(t)
			if source != "local_dev" {
				p := f.provider(t)
				p.store = store
				provider = p
			}
			m := runtimeFor(t, provider)
			defer m.Close()
			h := runtimeRouter(m)
			var session, flow *http.Cookie
			var callback string
			if source != "local_dev" {
				location, login := runtimeLogin(t, h, f)
				session = responseCookie(t, runtimeCallback(t, h, location, login), sessionCookie)
				callback, flow = runtimeLogin(t, h, f)
				if source == "environment" {
					// Explicit environment bindings are supported by the schema but
					// current environment writers use legacy rows. Create synthetic
					// bound rows at insertion, never by relabeling a credential.
					st, ft := oauth2.GenerateVerifier(), oauth2.GenerateVerifier()
					_, err := pool.Exec(ctx, `INSERT INTO framework.sessions(token_hash,issuer,subject,provider,expires_at,binding_source,deployment_id,environment,client_id)
 SELECT $1,issuer,subject,provider,expires_at,'environment','test-deployment','development','client-id' FROM framework.sessions WHERE token_hash=$2`, tokenHash(st), tokenHash(session.Value))
					if err != nil {
						t.Fatal(err)
					}
					_, err = pool.Exec(ctx, `INSERT INTO framework.oidc_login_flows(token_hash,state_hash,nonce,pkce_verifier,expires_at,binding_source,deployment_id,environment,issuer,client_id)
 SELECT $1,state_hash,nonce,pkce_verifier,expires_at,'environment','test-deployment','development',$3,'client-id' FROM framework.oidc_login_flows WHERE token_hash=$2`, tokenHash(ft), tokenHash(flow.Value), f.server.URL)
					if err != nil {
						t.Fatal(err)
					}
					session.Value, flow.Value = st, ft
				}
			}
			request := runtimeRequestFor("GET", "/api/auth/me")
			if session != nil {
				request.AddCookie(session)
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, request)
			if w.Code != 200 {
				t.Fatal("environment authentication broken before cutover", w.Code)
			}
			var sessionBefore, flowBefore Binding
			var activity time.Time
			if session != nil {
				var err error
				sessionBefore, err = store.SessionBinding(ctx, session.Value)
				if err != nil {
					t.Fatal(err)
				}
				flowBefore, err = store.FlowBinding(ctx, flow.Value)
				if err != nil {
					t.Fatal(err)
				}
				if err = pool.QueryRow(ctx, `SELECT last_activity_at FROM framework.sessions WHERE token_hash=$1`, tokenHash(session.Value)).Scan(&activity); err != nil {
					t.Fatal(err)
				}
			}
			// Even the exact same issuer/client must not infer revision membership.
			runtimeRevision(t, pool, revisionOne, 1, "", f.server.URL)
			var closed atomic.Int32
			candidate := preparedRuntime(t, f, store, revisionOne, 1, &closed)
			publication, err := m.Stage(candidate, 0)
			if err != nil {
				t.Fatal(err)
			}
			if err = publication.Commit(time.Now()); err != nil {
				t.Fatal(err)
			}
			status, _, _ := m.ControlStatus()
			if status.TransitionState != "none" || status.PreviousProvider != "" || status.PreviousRevisionID != "" {
				t.Fatal("initial transition incorrectly drains an environment provider")
			}
			w = httptest.NewRecorder()
			h.ServeHTTP(w, request)
			if w.Code != 401 {
				t.Fatal("environment identity survived initial cutover", w.Code)
			}
			if session != nil {
				if runtimeCallback(t, h, callback, flow).Code != 401 {
					t.Fatal("environment callback admitted after cutover")
				}
				after, err := store.SessionBinding(ctx, session.Value)
				if err != nil || after != sessionBefore {
					t.Fatal("session reclassified", err)
				}
				fb, err := store.FlowBinding(ctx, flow.Value)
				if err != nil || fb != flowBefore {
					t.Fatal("flow consumed or reclassified", err)
				}
				var afterActivity time.Time
				if err = pool.QueryRow(ctx, `SELECT last_activity_at FROM framework.sessions WHERE token_hash=$1`, tokenHash(session.Value)).Scan(&afterActivity); err != nil || !afterActivity.Equal(activity) {
					t.Fatal("denied credential touched activity", err)
				}
			}
			// Fresh database login is available; rejection does not create lockout
			// by disabling the newly configured login route.
			location, login := runtimeLogin(t, h, f)
			fresh := responseCookie(t, runtimeCallback(t, h, location, login), sessionCookie)
			binding, err := store.SessionBinding(ctx, fresh.Value)
			if err != nil || !binding.MatchesDatabase(candidate.binding) {
				t.Fatal("fresh login not revision-bound", err)
			}
		})
	}
}

func TestDrainingDeadlineRejectsPendingCallbackAndSession(t *testing.T) {
	pool, _ := testdb.New(t)
	testdb.Migrations(t, pool, "up")
	f := newTestIssuer(t)
	store, _ := NewPostgresStore(pool, testSessionConfig())
	m := runtimeFor(t, runtimeLocal(t))
	defer m.Close()
	h := runtimeRouter(m)
	var closed1, closed2 atomic.Int32
	runtimeRevision(t, pool, revisionOne, 1, "", f.server.URL)
	p1 := preparedRuntime(t, f, store, revisionOne, 1, &closed1)
	first, err := m.Stage(p1, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err = first.Commit(time.Now()); err != nil {
		t.Fatal(err)
	}
	location, flow := runtimeLogin(t, h, f)
	session := responseCookie(t, runtimeCallback(t, h, location, flow), sessionCookie)
	pending, pendingFlow := runtimeLogin(t, h, f)
	runtimeRevision(t, pool, revisionTwo, 2, revisionOne, f.server.URL)
	p2 := preparedRuntime(t, f, store, revisionTwo, 2, &closed2)
	next, err := m.Stage(p2, 1)
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(100 * time.Millisecond)
	if err = next.Commit(deadline); err != nil {
		t.Fatal(err)
	}
	// Wait for the actual published deadline, without changing a provider lease.
	time.Sleep(time.Until(deadline) + 10*time.Millisecond)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, runtimeRequestFor("GET", "/api/auth/me", session))
	if w.Code != 401 {
		t.Fatal("session outlived transition", w.Code)
	}
	if runtimeCallback(t, h, pending, pendingFlow).Code != 401 {
		t.Fatal("pending callback outlived transition")
	}
	var count int
	if err = pool.QueryRow(context.Background(), `SELECT count(*) FROM framework.sessions`).Scan(&count); err != nil || count != 1 {
		t.Fatal("retired callback created session", err)
	}
	if _, err = store.FlowBinding(context.Background(), pendingFlow.Value); err != nil {
		t.Fatal("rejected retired callback consumed flow", err)
	}
	if _, err = p1.provider.store.identity(context.Background(), session.Value); !errors.Is(err, ErrUnauthenticated) {
		t.Fatal("direct retired store accepts session", err)
	}
	if _, err = p1.provider.store.takeFlow(context.Background(), pendingFlow.Value, "untrusted"); !errors.Is(err, ErrUnauthenticated) {
		t.Fatal("direct retired store accepts flow", err)
	}
}
