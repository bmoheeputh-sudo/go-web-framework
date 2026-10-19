package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/bmoheeputh-sudo/go-web-framework/backend/internal/auth"
)

func developmentEnvironment() map[string]string {
	return map[string]string{
		"APP_ENV": "development", "AUTH_PROVIDER": "local_dev",
		"LOCAL_DEV_SUBJECT": "dev-1", "LOCAL_DEV_EMAIL": "dev@example.invalid",
		"LOCAL_DEV_DISPLAY_NAME": "Local Developer",
	}
}

func envReader(environment map[string]string) func(string) string {
	return func(key string) string { return environment[key] }
}

func TestLocalDevStartupGuards(t *testing.T) {
	for _, environment := range []string{"", "TEST", "PRD", "test", "production", "staging", "dev"} {
		t.Run("environment/"+environment, func(t *testing.T) {
			values := developmentEnvironment()
			values["APP_ENV"] = environment
			if _, err := newServer(envReader(values)); err == nil {
				t.Fatal("unsafe environment accepted")
			}
		})
	}
	for _, address := range []string{":8080", "0.0.0.0:8080", "[::]:8080", "192.0.2.1:8080", "localhost:8080", "127.0.0.1", "127.0.0.1:0", "127.0.0.1:65536", "127.0.0.1:http"} {
		t.Run("address/"+address, func(t *testing.T) {
			values := developmentEnvironment()
			values["HTTP_ADDR"] = address
			if _, err := newServer(envReader(values)); err == nil {
				t.Fatal("unsafe address accepted")
			}
		})
	}
	for _, address := range []string{"", "127.0.0.1:8080", "[::1]:8080"} {
		values := developmentEnvironment()
		values["HTTP_ADDR"] = address
		server, err := newServer(envReader(values))
		if err != nil {
			t.Fatal(err)
		}
		if address == "" {
			address = "127.0.0.1:8080"
		}
		if server.Addr != address {
			t.Fatalf("server bound to %q, want %q", server.Addr, address)
		}
	}
}

func TestInvalidProviderConfigurationFailsClosed(t *testing.T) {
	for _, provider := range []string{"oidc", "google_iap", "iap", "LOCAL_DEV", "local_dev ", "unknown"} {
		values := developmentEnvironment()
		values["AUTH_PROVIDER"] = provider
		if _, err := newServer(envReader(values)); err == nil {
			t.Errorf("unsupported provider %q accepted", provider)
		}
	}
}

func TestIAPStartupAndRoutesWithoutDatabase(t *testing.T) {
	for _, environment := range []string{"development", "TEST", "PRD"} {
		t.Run(environment, func(t *testing.T) {
			values := map[string]string{
				"APP_ENV": environment, "AUTH_PROVIDER": "google_iap",
				"IAP_AUDIENCE": "/projects/123/global/backendServices/456",
				// IAP must not initialize OIDC sessions or require DB configuration.
				"DB_HOST": "invalid.example.invalid", "DB_PORT": "invalid",
			}
			server, err := newServer(envReader(values))
			if err != nil {
				t.Fatal(err)
			}
			defer server.closeResources()
			for path, status := range map[string]int{
				"/api/health": http.StatusOK, "/api/auth/config": http.StatusOK,
				"/api/auth/me": http.StatusUnauthorized, "/api/auth/login": http.StatusNotFound,
				"/api/auth/callback": http.StatusNotFound, "/api/auth/logout": http.StatusNotFound,
			} {
				request := httptest.NewRequest("GET", path, nil)
				request.Header.Set("X-Goog-Authenticated-User-Email", "forged@example.invalid")
				request.Header.Set("X-Goog-Authenticated-User-Id", "forged")
				response := httptest.NewRecorder()
				server.Handler.ServeHTTP(response, request)
				if response.Code != status || len(response.Result().Cookies()) != 0 {
					t.Fatalf("%s: unexpected status or session cookie: %d", path, response.Code)
				}
				if path == "/api/auth/config" && strings.TrimSpace(response.Body.String()) != `{"provider":"google_iap"}` {
					t.Fatal("IAP public configuration must contain only provider name")
				}
			}
			delete(values, "IAP_AUDIENCE")
			if _, err := newServer(envReader(values)); err == nil {
				t.Fatal("IAP started without explicit audience")
			}
		})
	}
}

func TestPublicAuthConfigAndOIDCRouteMethods(t *testing.T) {
	handler := newHandler(&auth.OIDCAuthenticator{})
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest("GET", "/api/auth/config", nil))
	if response.Code != http.StatusOK || strings.TrimSpace(response.Body.String()) != `{"provider":"oidc"}` {
		t.Fatal("public auth configuration must contain only the provider name")
	}
	for _, request := range []*http.Request{
		httptest.NewRequest("GET", "/api/auth/logout", nil),
		httptest.NewRequest("POST", "/api/auth/login", nil),
		httptest.NewRequest("POST", "/api/auth/callback", nil),
	} {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusMethodNotAllowed {
			t.Fatal("incorrect method accepted")
		}
	}
}

func TestPublicHealthAndUnauthenticatedMe(t *testing.T) {
	values := developmentEnvironment()
	delete(values, "AUTH_PROVIDER") // Neither development nor profile variables implicitly enable authentication.
	server, err := newServer(envReader(values))
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/api/health", "/api/auth/me"} {
		request := httptest.NewRequest("GET", path, nil)
		request.RemoteAddr = "127.0.0.1:1234"
		request.Header.Set("X-Goog-Authenticated-User-Email", "forged@example.invalid")
		request.Header.Set("Authorization", "Bearer forged")
		response := httptest.NewRecorder()
		server.Handler.ServeHTTP(response, request)
		if path == "/api/health" {
			if response.Code != http.StatusOK {
				t.Fatal(response.Code)
			}
			var body map[string]string
			if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
				t.Fatal(err)
			}
			if body["status"] != "ok" || body["service"] != "go-web-framework" {
				t.Fatal(body)
			}
		} else {
			if response.Code != http.StatusUnauthorized {
				t.Fatal(response.Code)
			}
			if response.Header().Get("Cache-Control") != "no-store" {
				t.Fatal("auth error may be cached")
			}
		}
	}
}

func TestAuthenticatedMe(t *testing.T) {
	server, err := newServer(envReader(developmentEnvironment()))
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest("GET", "/api/auth/me?email=forged@example.invalid", nil)
	request.RemoteAddr = "127.0.0.1:1234"
	request.Header.Set("X-User-ID", "forged")
	response := httptest.NewRecorder()
	server.Handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status %d: %s", response.Code, response.Body.String())
	}
	var identity auth.Identity
	if err := json.Unmarshal(response.Body.Bytes(), &identity); err != nil {
		t.Fatal(err)
	}
	want := auth.Identity{Issuer: auth.LocalDevIssuer, Subject: "dev-1", Email: "dev@example.invalid",
		EmailVerified: false, DisplayName: "Local Developer", Provider: auth.LocalDev}
	if identity != want {
		t.Fatalf("identity = %+v, want %+v", identity, want)
	}
	if response.Header().Get("Content-Type") != "application/json" {
		t.Fatal("not JSON")
	}
	if response.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("identity may be cached")
	}
	if len(response.Result().Cookies()) != 0 {
		t.Fatal("local development created a session cookie")
	}
}

type authenticatorFunc func(*http.Request) (auth.Identity, error)

func (f authenticatorFunc) Authenticate(r *http.Request) (auth.Identity, error) { return f(r) }

func TestAuthenticationFailuresDoNotLeakOrReachHandler(t *testing.T) {
	for _, test := range []struct {
		name     string
		provider auth.Authenticator
		status   int
	}{
		{"missing provider", nil, http.StatusUnauthorized},
		{"missing credentials", authenticatorFunc(func(*http.Request) (auth.Identity, error) {
			return auth.Identity{}, auth.ErrUnauthenticated
		}), http.StatusUnauthorized},
		{"provider error", authenticatorFunc(func(*http.Request) (auth.Identity, error) {
			return auth.Identity{}, errors.New("sensitive credentials")
		}), http.StatusInternalServerError},
		{"invalid identity", authenticatorFunc(func(*http.Request) (auth.Identity, error) {
			return auth.Identity{}, nil
		}), http.StatusInternalServerError},
	} {
		t.Run(test.name, func(t *testing.T) {
			called := false
			handler := auth.Require(test.provider, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true }))
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, httptest.NewRequest("GET", "/api/auth/me", nil))
			if called || response.Code != test.status {
				t.Fatalf("called=%v, status=%d", called, response.Code)
			}
			if strings.Contains(response.Body.String(), "sensitive") {
				t.Fatal("provider error leaked")
			}
		})
	}
}

func TestLocalDevRemoteRequestDeniedButHealthPublic(t *testing.T) {
	server, err := newServer(envReader(developmentEnvironment()))
	if err != nil {
		t.Fatal(err)
	}
	for path, status := range map[string]int{"/api/auth/me": http.StatusUnauthorized, "/api/health": http.StatusOK} {
		request := httptest.NewRequest("GET", path, nil)
		request.RemoteAddr = "192.0.2.1:1234"
		request.Header.Set("X-Forwarded-For", "127.0.0.1")
		response := httptest.NewRecorder()
		server.Handler.ServeHTTP(response, request)
		if response.Code != status {
			t.Errorf("%s: status %d, want %d", path, response.Code, status)
		}
	}
}

func TestRBACConfigurationAndDisabledRoutes(t *testing.T) {
	for _, change := range []func(map[string]string){
		func(v map[string]string) { v["RBAC_ENABLED"] = "invalid" },
		func(v map[string]string) { v["RBAC_ENABLED"] = "true" },
		func(v map[string]string) {
			v["RBAC_ENABLED"] = "true"
			v["APP_ORIGIN"] = "http://remote.example.invalid"
		},
		func(v map[string]string) {
			v["RBAC_ENABLED"] = "true"
			v["APP_ORIGIN"] = "http://127.0.0.1:5173"
			v["DB_PORT"] = "invalid"
		},
		func(v map[string]string) {
			v["RBAC_ENABLED"] = "true"
			v["APP_ORIGIN"] = "https://app.example.invalid"
			v["AUTH_PROVIDER"] = ""
		},
		func(v map[string]string) {
			v["RBAC_ENABLED"] = "true"
			v["APP_ORIGIN"] = "https://app.example.invalid"
			v["AUTH_PROVIDER"] = "google_iap"
			v["IAP_AUDIENCE"] = "/projects/123/apps/example"
			v["DB_PORT"] = "invalid"
		},
	} {
		values := developmentEnvironment()
		change(values)
		if server, err := newServer(envReader(values)); err == nil {
			server.closeResources()
			t.Fatal("invalid RBAC startup accepted")
		}
	}
	server, err := newServer(envReader(developmentEnvironment()))
	if err != nil {
		t.Fatal(err)
	}
	defer server.closeResources()
	for path, status := range map[string]int{"/api/health": 200, "/api/auth/me": 200, "/api/access/me": 503, "/api/admin/users": 503, "/api/accounts": 503} {
		r := httptest.NewRequest("GET", path, nil)
		r.RemoteAddr = "127.0.0.1:1234"
		w := httptest.NewRecorder()
		server.Handler.ServeHTTP(w, r)
		if w.Code != status {
			t.Fatalf("%s: got %d want %d", path, w.Code, status)
		}
	}
}

func TestAuthConfigurationManagementUnavailablePreservesRuntime(t *testing.T) {
	for _, authenticated := range []bool{true, false} {
		values := developmentEnvironment()
		values["APP_ORIGIN"] = "http://127.0.0.1:5173"
		values["AUTH_CONFIG_DEPLOYMENT"] = "test-installation"
		values["AUTH_ENCRYPTION_KEY"] = "invalid-test-key"
		values["AUTH_ENCRYPTION_KEY_ID"] = "test-key"
		if !authenticated {
			delete(values, "AUTH_PROVIDER")
		}
		app, err := newServer(envReader(values))
		if err != nil {
			t.Fatal("management configuration changed runtime startup", err)
		}
		defer app.closeResources()
		for _, route := range []struct{ method, path string }{
			{"GET", "/api/admin/auth/settings"}, {"GET", "/api/admin/auth/settings/11111111-1111-4111-8111-111111111111"},
			{"POST", "/api/admin/auth/settings"}, {"POST", "/api/admin/auth/settings/11111111-1111-4111-8111-111111111111/validate"},
			{"POST", "/api/admin/auth/settings/11111111-1111-4111-8111-111111111111/approve"}, {"GET", "/api/admin/auth/status"},
		} {
			r := httptest.NewRequest(route.method, route.path, strings.NewReader(`{}`))
			r.RemoteAddr = "127.0.0.1:4321"
			r.Header.Set("Origin", values["APP_ORIGIN"])
			r.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			app.Handler.ServeHTTP(w, r)
			want := 401
			if authenticated {
				want = 503
			}
			if w.Code != want {
				t.Fatalf("%s: got %d want %d", route.path, w.Code, want)
			}
			if w.Header().Get("Content-Type") != "application/json" || strings.Contains(w.Body.String(), values["AUTH_ENCRYPTION_KEY"]) {
				t.Fatal("unsafe management failure")
			}
		}
		for _, path := range []string{"/api/health", "/api/auth/me", "/api/auth/config"} {
			r := httptest.NewRequest("GET", path, nil)
			r.RemoteAddr = "127.0.0.1:4321"
			w := httptest.NewRecorder()
			app.Handler.ServeHTTP(w, r)
			want := 200
			if path == "/api/auth/me" && !authenticated {
				want = 401
			}
			if w.Code != want {
				t.Fatal("existing endpoint changed", path, w.Code)
			}
		}
	}
}
