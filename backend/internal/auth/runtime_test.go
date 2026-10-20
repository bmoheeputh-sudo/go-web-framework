package auth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func runtimeLocal(t *testing.T) *LocalDevAuthenticator {
	t.Helper()
	p, err := NewLocalDev("development", LocalDevConfig{Subject: "runtime-user", Email: "user@example.invalid", DisplayName: "Runtime User"})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func runtimeFor(t *testing.T, provider Authenticator) *Runtime {
	t.Helper()
	m, err := NewEnvironmentRuntime(provider, "test-deployment", "development")
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func runtimeRouter(m *Runtime) http.Handler {
	mux := http.NewServeMux()
	m.RegisterRoutes(mux)
	return m.Capture(mux)
}

func runtimeRequestFor(method, path string, cookies ...*http.Cookie) *http.Request {
	r := httptest.NewRequest(method, testOrigin+path, nil)
	r.RemoteAddr = "127.0.0.1:1234"
	for _, cookie := range cookies {
		r.AddCookie(cookie)
	}
	return r
}

func TestRuntimeLocalAndStableRoutes(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		var provider Authenticator
		if enabled {
			provider = runtimeLocal(t)
		}
		m := runtimeFor(t, provider)
		h := runtimeRouter(m)
		for _, tc := range []struct {
			method, path string
			status       int
		}{
			{"GET", "/api/auth/config", 200}, {"GET", "/api/auth/login", 404},
			{"GET", "/api/auth/callback", 404}, {"POST", "/api/auth/logout", 404},
			{"GET", "/api/auth/logout", 405}, {"POST", "/api/auth/login", 405},
			{"POST", "/api/auth/callback", 405}, {"POST", "/api/auth/config", 405},
			{"POST", "/api/auth/me", 405},
		} {
			w := httptest.NewRecorder()
			h.ServeHTTP(w, runtimeRequestFor(tc.method, tc.path))
			if w.Code != tc.status || len(w.Result().Cookies()) != 0 {
				t.Fatalf("%s %s: %d", tc.method, tc.path, w.Code)
			}
		}
		for _, remote := range []string{"127.0.0.1:1234", "192.0.2.2:1234"} {
			r := runtimeRequestFor("GET", "/api/auth/me")
			r.RemoteAddr = remote
			r.Header.Set("X-Goog-Authenticated-User-Id", "forged")
			r.Header.Set("Authorization", "Bearer forged")
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			want := 401
			if enabled && strings.HasPrefix(remote, "127.") {
				want = 200
			}
			if w.Code != want {
				t.Fatalf("local authentication: got %d want %d", w.Code, want)
			}
			if want == 200 && !strings.Contains(w.Body.String(), `"subject":"runtime-user"`) {
				t.Fatal("client identity trusted")
			}
		}
	}
}

func TestRuntimeRejectsUnpreparedProvidersAndMissingCapture(t *testing.T) {
	for _, p := range []Authenticator{&OIDCAuthenticator{}, (*LocalDevAuthenticator)(nil)} {
		if _, err := NewEnvironmentRuntime(p, "test", "development"); err == nil {
			t.Fatal("unprepared provider accepted")
		}
	}
	if _, err := NewEnvironmentRuntime(runtimeLocal(t), "test", "TEST"); err == nil {
		t.Fatal("Local DEV runtime outside development")
	}
	m := runtimeFor(t, runtimeLocal(t))
	request := runtimeRequestFor("GET", "/api/auth/me")
	if _, err := m.Authenticate(request); !errors.Is(err, ErrStoreUnavailable) {
		t.Fatal("missing snapshot accepted")
	}
	if _, ok := m.Status(request.Context()); ok {
		t.Fatal("uncaptured status returned")
	}
	mux := http.NewServeMux()
	m.RegisterRoutes(mux)
	for _, path := range []string{"/api/auth/me", "/api/auth/config", "/api/auth/login", "/api/auth/callback"} {
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, runtimeRequestFor("GET", path))
		if w.Code != 503 {
			t.Fatal("uncaptured route did not fail closed", path, w.Code)
		}
	}
	other := runtimeFor(t, runtimeLocal(t))
	w := httptest.NewRecorder()
	m.Capture(other.Capture(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("foreign snapshot accepted") }))).ServeHTTP(w, request)
	if w.Code != 503 {
		t.Fatal("foreign capture accepted")
	}
}

func TestRuntimeSnapshotImmutabilityAndPublicationPolicy(t *testing.T) {
	p := runtimeLocal(t)
	m := runtimeFor(t, p)
	original := m.current.Load()
	p.identity.Subject = "changed-after-construction"
	next := *original
	if !m.publish(original, &next) {
		t.Fatal("same-configuration CAS failed")
	}
	next.status.Provider = OIDC
	if m.current.Load().status.Provider != LocalDev {
		t.Fatal("published status mutated")
	}
	if m.publish(original, original) {
		t.Fatal("stale writer accepted")
	}
	for _, mutate := range []func(*runtimeSnapshot){
		func(s *runtimeSnapshot) {
			s.status.Source = "database"
			s.status.AppliedGeneration = 1
			s.status.ActiveRevisionID = "revision"
		},
		func(s *runtimeSnapshot) { s.status.DeploymentID = "another" },
		func(s *runtimeSnapshot) {
			s.status.PreviousProvider = LocalDev
			s.status.PreviousRevisionID = "previous"
			s.status.TransitionDeadline = time.Now().Add(time.Minute)
		},
		func(s *runtimeSnapshot) { s.auth = runtimeLocal(t) },
	} {
		current := m.current.Load()
		candidate := *current
		mutate(&candidate)
		if m.publish(current, &candidate) {
			t.Fatal("configuration change enabled in preparation phase")
		}
	}
	w := httptest.NewRecorder()
	m.Capture(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		status, ok := m.Status(r.Context())
		if !ok || status.Provider != LocalDev || status.Source != "environment" || status.AppliedGeneration != 0 || status.ActiveRevisionID != "" || !status.TransitionDeadline.IsZero() {
			t.Error("wrong runtime status")
		}
		status.Provider = OIDC
		again, _ := m.Status(r.Context())
		if again.Provider != LocalDev {
			t.Error("status reference leaked")
		}
		identity, err := m.Authenticate(r)
		if err != nil || identity.Subject != "runtime-user" {
			t.Error("provider configuration mutated")
		}
	})).ServeHTTP(w, runtimeRequestFor("GET", "/"))
}

func TestRuntimeRequestConsistentConcurrentSnapshots(t *testing.T) {
	m := runtimeFor(t, runtimeLocal(t))
	var wg sync.WaitGroup
	h := m.Capture(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		before, _ := m.snapshot(r.Context())
		// Publish a fresh container during this request. No configuration switch.
		for {
			old := m.current.Load()
			if m.publish(old, old) {
				break
			}
		}
		m.Capture(Require(m, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			after, ok := m.snapshot(r.Context())
			if !ok || after != before {
				t.Error("request reloaded snapshot")
			}
			identity, valid := IdentityFromContext(r.Context())
			if !valid || identity.Subject != "runtime-user" {
				t.Error("lost identity")
			}
			status, valid := m.Status(r.Context())
			if !valid || status != before.status {
				t.Error("status not request-consistent")
			}
		}))).ServeHTTP(w, r)
	}))
	for range 100 {
		wg.Go(func() {
			w := httptest.NewRecorder()
			h.ServeHTTP(w, runtimeRequestFor("GET", "/"))
			if w.Code != 200 {
				t.Error("concurrent request failed")
			}
		})
	}
	wg.Wait()
}

func TestRuntimeNestedCaptureDoesNotReloadUnavailableSnapshot(t *testing.T) {
	m := runtimeFor(t, runtimeLocal(t))
	mux := http.NewServeMux()
	m.RegisterRoutes(mux)
	h := m.Capture(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured, _ := m.snapshot(r.Context())
		// Test-only fault injection. No production API can remove the snapshot.
		m.current.Store(nil)
		defer m.current.Store(captured)
		status, ok := m.Status(r.Context())
		if !ok || status.Provider != LocalDev {
			t.Fatal("status reloaded unavailable global state")
		}
		m.Capture(mux).ServeHTTP(w, r)
	}))
	for _, path := range []string{"/api/auth/me", "/api/auth/config"} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, runtimeRequestFor("GET", path))
		if w.Code != 200 {
			t.Fatal("downstream authentication reloaded snapshot", path, w.Code)
		}
	}
	m.current.Store(nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, runtimeRequestFor("GET", "/api/auth/me"))
	if w.Code != 503 {
		t.Fatal("a new request did not fail closed without a snapshot")
	}
}

func TestRuntimeRefusedActivationRetainsOIDCWithoutLocalFallback(t *testing.T) {
	m := runtimeFor(t, newTestIssuer(t).provider(t))
	original := m.current.Load()
	local := runtimeFor(t, runtimeLocal(t)).current.Load()
	database := *original
	database.status.Source = "database"
	database.status.ActiveRevisionID = "unapproved-test-revision"
	database.status.AppliedGeneration = 1
	for _, candidate := range []*runtimeSnapshot{local, &database, nil} {
		if m.publish(original, candidate) || m.current.Load() != original {
			t.Fatal("refused activation changed applied authentication")
		}
	}
	if m.publish(nil, local) { // initialization cannot overwrite an existing value
		t.Fatal("initialization bypassed the publication policy")
	}
	w := httptest.NewRecorder()
	runtimeRouter(m).ServeHTTP(w, runtimeRequestFor("GET", "/api/auth/me"))
	if w.Code != 401 {
		t.Fatal("failed publication fell back to loopback Local DEV identity")
	}
}

func TestRuntimeOIDCLoginCallbackLogoutAndCapturedDispatch(t *testing.T) {
	f := newTestIssuer(t)
	p := f.provider(t)
	m := runtimeFor(t, p)
	mux := http.NewServeMux()
	m.RegisterRoutes(mux)
	// Simulate a future publication only in the test: production publish refuses
	// this change. Every handler must still use the request's captured OIDC view.
	other := runtimeFor(t, runtimeLocal(t)).current.Load()
	oidcSnapshot := m.current.Load()
	h := m.Capture(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		m.current.Store(other)
		defer m.current.Store(oidcSnapshot)
		mux.ServeHTTP(w, r)
	}))
	call := func(r *http.Request) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	config := call(runtimeRequestFor("GET", "/api/auth/config"))
	if strings.TrimSpace(config.Body.String()) != `{"provider":"oidc"}` {
		t.Fatal("config reloaded provider")
	}
	if call(runtimeRequestFor("GET", "/api/auth/me")).Code != 401 {
		t.Fatal("OIDC fell back to Local DEV")
	}
	login := call(runtimeRequestFor("GET", "/api/auth/login"))
	if login.Code != 302 {
		t.Fatal("login reloaded provider")
	}
	flow := responseCookie(t, login, flowCookie)
	assertSecureCookie(t, flow)
	client := *f.server.Client()
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	response, err := client.Get(login.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != 302 {
		t.Fatal("mock provider rejected PKCE flow")
	}
	callback := httptest.NewRequest("GET", response.Header.Get("Location"), nil)
	callback.AddCookie(flow)
	result := call(callback)
	if result.Code != 303 || result.Header().Get("Location") != testOrigin+"/" {
		t.Fatal("callback failed")
	}
	session := responseCookie(t, result, sessionCookie)
	assertSecureCookie(t, session)
	me := call(runtimeRequestFor("GET", "/api/auth/me", session))
	var identity Identity
	if me.Code != 200 || json.Unmarshal(me.Body.Bytes(), &identity) != nil || identity.Subject != "stable-subject" || identity.Issuer != f.server.URL {
		t.Fatal("session authentication changed")
	}
	assertFailedCallback(t, call(callback)) // single-use callback, no replay
	logout := runtimeRequestFor("POST", "/api/auth/logout", session)
	logout.Header.Set("Origin", "https://evil.example.invalid")
	if call(logout).Code != 403 {
		t.Fatal("logout origin protection lost")
	}
	logout.Header.Set("Origin", testOrigin)
	if call(logout).Code != 204 {
		t.Fatal("logout reloaded provider")
	}
	if call(runtimeRequestFor("GET", "/api/auth/me", session)).Code != 401 {
		t.Fatal("logout did not revoke")
	}
	if _, ok := m.Status(context.Background()); ok {
		t.Fatal("status loaded independently")
	}
}

func TestRetiredIAPAssertionDoesNotAuthenticateOIDC(t *testing.T) {
	m := runtimeFor(t, newTestIssuer(t).provider(t))
	r := runtimeRequestFor("GET", "/api/auth/me")
	r.Header.Set("X-Goog-IAP-JWT-Assertion", "untrusted-legacy-assertion")
	r.Header.Set("X-Goog-Authenticated-User-Email", "accounts.google.com:forged@example.invalid")
	w := httptest.NewRecorder()
	runtimeRouter(m).ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("legacy IAP headers authenticated OIDC: %d", w.Code)
	}
}
