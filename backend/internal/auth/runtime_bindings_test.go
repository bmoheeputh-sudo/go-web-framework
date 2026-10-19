package auth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/bmoheeputh-sudo/go-web-framework/backend/internal/testdb"
	"golang.org/x/oauth2"
)

func TestRuntimeBindingAdmissionPolicy(t *testing.T) {
	expected := Binding{Source: "environment", DeploymentID: "installation-a", Environment: "development",
		Issuer: "https://issuer.example.invalid", ClientID: "client", Purpose: "login"}
	store := environmentBoundStore{expected: expected}
	for _, b := range []Binding{{Source: "legacy", Purpose: "login"}, {Source: "legacy", Purpose: "login", Issuer: expected.Issuer}, expected} {
		if !store.accepts(b) {
			t.Fatal("environment binding rejected")
		}
	}
	for name, change := range map[string]func(*Binding){
		"database":             func(b *Binding) { b.Source = "database"; b.RevisionID = "revision"; b.ActivationGeneration = 1 },
		"deployment":           func(b *Binding) { b.DeploymentID = "other" },
		"environment":          func(b *Binding) { b.Environment = "production" },
		"issuer":               func(b *Binding) { b.Issuer = "https://other.example.invalid" },
		"client":               func(b *Binding) { b.ClientID = "other" },
		"test flow":            func(b *Binding) { b.Purpose = "isolated_connection" },
		"normal callback test": func(b *Binding) { b.Purpose = "normal_callback" },
		"revision":             func(b *Binding) { b.RevisionID = "unexpected" },
		"generation":           func(b *Binding) { b.ActivationGeneration = 1 },
		"unknown":              func(b *Binding) { b.Source = "unknown" },
		"malformed legacy":     func(b *Binding) { b.Source = "legacy" },
	} {
		t.Run(name, func(t *testing.T) {
			b := expected
			change(&b)
			if store.accepts(b) {
				t.Fatal("foreign or test binding admitted")
			}
		})
	}
	store.expected.DeploymentID = ""
	if store.accepts(expected) {
		t.Fatal("missing deployment admitted scoped credential")
	}
}

func TestRuntimePostgresLegacySessionsFlowsAndNoActivation(t *testing.T) {
	pool, _ := testdb.New(t)
	testdb.Migrations(t, pool, "up")
	ctx := context.Background()
	store, err := NewPostgresStore(pool, testSessionConfig())
	if err != nil {
		t.Fatal(err)
	}
	f := newTestIssuer(t)
	p := f.provider(t)
	p.store = store
	m := runtimeFor(t, p)
	h := runtimeRouter(m)
	identity := Identity{Issuer: f.server.URL, Subject: "legacy-user", Provider: OIDC}
	token, err := store.addSession(ctx, identity, time.Now().Add(time.Hour), "")
	if err != nil {
		t.Fatal(err)
	}
	before, err := store.SessionBinding(ctx, token)
	if err != nil {
		t.Fatal(err)
	}
	var expiresBefore, expiresAfter time.Time
	if err := pool.QueryRow(ctx, `SELECT expires_at FROM framework.sessions WHERE token_hash=$1`, tokenHash(token)).Scan(&expiresBefore); err != nil {
		t.Fatal(err)
	}
	request := runtimeRequestFor("GET", "/api/auth/me", &http.Cookie{Name: sessionCookie, Value: token})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, request)
	if w.Code != 200 {
		t.Fatal("legacy session refused", w.Code)
	}
	after, err := store.SessionBinding(ctx, token)
	if err != nil || before != after || after.Source != "legacy" || after.RevisionID != "" || after.ActivationGeneration != 0 {
		t.Fatal("legacy session rebound")
	}
	if err := pool.QueryRow(ctx, `SELECT expires_at FROM framework.sessions WHERE token_hash=$1`, tokenHash(token)).Scan(&expiresAfter); err != nil || !expiresBefore.Equal(expiresAfter) {
		t.Fatal("absolute expiry altered")
	}
	// Check both absolute and idle expiry through the dispatcher.
	for _, expiry := range []string{"created_at=clock_timestamp()-interval '2 hours',last_activity_at=clock_timestamp()-interval '1 hour',expires_at=clock_timestamp()-interval '1 minute'", "last_activity_at=clock_timestamp()-interval '1 hour',created_at=clock_timestamp()-interval '2 hours'"} {
		expired, err := store.addSession(ctx, identity, time.Now().Add(time.Hour), "")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(ctx, `UPDATE framework.sessions SET `+expiry+` WHERE token_hash=$1`, tokenHash(expired)); err != nil {
			t.Fatal(err)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, runtimeRequestFor("GET", "/api/auth/me", &http.Cookie{Name: sessionCookie, Value: expired}))
		if w.Code != 401 {
			t.Fatal("expired session accepted")
		}
	}
	// New environment logins still write legacy flows and retain one-use state.
	login := httptest.NewRecorder()
	h.ServeHTTP(login, runtimeRequestFor("GET", "/api/auth/login"))
	flow := responseCookie(t, login, flowCookie)
	fb, err := store.FlowBinding(ctx, flow.Value)
	if err != nil || fb.Source != "legacy" || fb.RevisionID != "" || fb.ActivationGeneration != 0 {
		t.Fatal("new environment flow enrolled")
	}
	client := *f.server.Client()
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	authorized, err := client.Get(login.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	authorized.Body.Close()
	callback := httptest.NewRequest("GET", authorized.Header.Get("Location"), nil)
	callback.AddCookie(flow)
	result := httptest.NewRecorder()
	h.ServeHTTP(result, callback)
	if result.Code != 303 || result.Header().Get("Location") != testOrigin+"/" {
		t.Fatal("legacy callback failed")
	}
	newToken := responseCookie(t, result, sessionCookie).Value
	b, err := store.SessionBinding(ctx, newToken)
	if err != nil || b.Source != "legacy" || b.RevisionID != "" {
		t.Fatal("callback rebound new session")
	}
	if _, err := store.FlowBinding(ctx, flow.Value); !errors.Is(err, ErrUnauthenticated) {
		t.Fatal("flow not consumed")
	}
	replay := httptest.NewRecorder()
	h.ServeHTTP(replay, callback)
	assertFailedCallback(t, replay)
	// Explicit environment bindings must match deployment, issuer and client.
	for _, deployment := range []string{"test-deployment", "another-deployment"} {
		boundToken := oauth2.GenerateVerifier()
		_, err := pool.Exec(ctx, `INSERT INTO framework.sessions(token_hash,issuer,subject,provider,expires_at,binding_source,deployment_id,environment,client_id)
		 VALUES($1,$2,'bound-user','oidc',clock_timestamp()+interval '1 hour','environment',$3,'development','client-id')`, tokenHash(boundToken), f.server.URL, deployment)
		if err != nil {
			t.Fatal(err)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, runtimeRequestFor("GET", "/api/auth/me", &http.Cookie{Name: sessionCookie, Value: boundToken}))
		want := 200
		if deployment != "test-deployment" {
			want = 401
		}
		if w.Code != want {
			t.Fatal("environment scope not enforced", w.Code)
		}
	}
	for _, table := range []string{"auth_activation_heads", "auth_activation_history", "auth_test_evidence", "auth_config_revisions"} {
		var count int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM framework.`+table).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != 0 {
			t.Fatal("runtime wrote activation/configuration data", table)
		}
	}
	pool.Close()
	w = httptest.NewRecorder()
	h.ServeHTTP(w, request)
	if w.Code != 503 {
		t.Fatal("database failure fell back to another provider", w.Code)
	}
}
