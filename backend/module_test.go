package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/bmoheeputh-sudo/go-web-framework/backend/internal/access"
	"github.com/bmoheeputh-sudo/go-web-framework/backend/internal/apps/example"
	"github.com/bmoheeputh-sudo/go-web-framework/backend/internal/auth"
	"github.com/bmoheeputh-sudo/go-web-framework/backend/internal/modules"
	"github.com/bmoheeputh-sudo/go-web-framework/backend/internal/testdb"
	"github.com/bmoheeputh-sudo/go-web-framework/backend/module"
)

func TestModuleConfigurationStartup(t *testing.T) {
	for _, enabled := range []string{"unknown", "example,example", " example", "example,"} {
		env := developmentEnvironment()
		env["ENABLED_MODULES"] = enabled
		if _, err := newProviderTestServer(envReader(env)); err == nil || !strings.Contains(err.Error(), "ENABLED_MODULES") {
			t.Fatalf("bad configuration %q: %v", enabled, err)
		}
	}
	env := developmentEnvironment()
	env["ENABLED_MODULES"] = "example"
	if _, err := newProviderTestServer(envReader(env)); err == nil || !strings.Contains(err.Error(), "RBAC_ENABLED") {
		t.Fatal("modules started without RBAC", err)
	}
	env["RBAC_ENABLED"] = "true"
	env["APP_ORIGIN"] = "http://127.0.0.1:5173"
	delete(env, "AUTH_PROVIDER")
	if _, err := newProviderTestServer(envReader(env)); err == nil || !strings.Contains(err.Error(), "AUTH_PROVIDER") {
		t.Fatal("modules started without authentication", err)
	}
	env["AUTH_PROVIDER"] = "local_dev"
	if _, err := newProviderTestServer(envReader(env)); err == nil {
		t.Fatal("modules started without a configured database")
	}
}

func TestDisabledModuleRoutesInApplication(t *testing.T) {
	for _, authenticated := range []bool{true, false} {
		env := developmentEnvironment()
		if !authenticated {
			delete(env, "AUTH_PROVIDER")
		}
		app, err := newProviderTestServer(envReader(env))
		if err != nil {
			t.Fatal(err)
		}
		defer app.closeResources()
		for path, expected := range map[string]int{"/api/health": 200, "/api/modules/example/info": 404, "/api/modules": 200} {
			if path == "/api/modules" && !authenticated {
				expected = 401
			}
			r := moduleRequest("GET", path, nil)
			r.RemoteAddr = "127.0.0.1:1234"
			w := httptest.NewRecorder()
			app.Handler.ServeHTTP(w, r)
			if w.Code != expected {
				t.Fatalf("%s: status %d want %d", path, w.Code, expected)
			}
			if path == "/api/modules" && authenticated && strings.TrimSpace(w.Body.String()) != `{"modules":[]}` {
				t.Fatal(w.Body.String())
			}
		}
	}
}

func TestModuleCompositionPreservesExistingRoutes(t *testing.T) {
	pool, _ := testdb.New(t)
	testdb.Migrations(t, pool, "up")
	store := access.New(pool)
	runtime, identity := moduleTestRuntime(t, "example-user")
	if _, err := store.Resolve(context.Background(), identity); err != nil {
		t.Fatal(err)
	}
	registry, err := modules.New([]module.Module{example.Module{}}, "example")
	if err != nil {
		t.Fatal(err)
	}
	handler, err := newHandlerWithModules(runtime, store, "https://app.example.test", registry)
	if err != nil {
		t.Fatal(err)
	}
	for path, expected := range map[string]int{
		"/api/health": 200, "/api/auth/me": 200, "/api/auth/config": 200, "/api/access/me": 200,
		"/api/admin/users": 403, "/api/admin/roles": 403, "/api/admin/accounts": 403, "/api/admin/audit": 403, "/api/accounts": 403,
		"/api/modules": 200, "/api/modules/example/info": 403, "/api/modules/disabled/info": 404,
	} {
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, moduleRequest("GET", path, nil))
		if w.Code != expected {
			t.Fatalf("%s: got %d want %d", path, w.Code, expected)
		}
	}
}

func TestSettingsUsesCompiledModuleCatalog(t *testing.T) {
	pool, _ := testdb.New(t)
	testdb.Migrations(t, pool, "up")
	ctx := context.Background()
	store := access.New(pool)
	runtime, identity := moduleTestRuntime(t, "settings-admin")
	if _, err := store.Resolve(ctx, identity); err != nil {
		t.Fatal(err)
	}
	if err := store.Bootstrap(ctx, identity.Issuer, identity.Subject, "development"); err != nil {
		t.Fatal(err)
	}
	for _, enabled := range []string{"", "example"} {
		registry, err := modules.New([]module.Module{example.Module{}}, enabled)
		if err != nil {
			t.Fatal(err)
		}
		handler, err := newHandlerWithModules(runtime, store, "https://app.example.test", registry)
		if err != nil {
			t.Fatal(err)
		}
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, moduleRequest("GET", "/api/admin/permissions", nil))
		if response.Code != 200 {
			t.Fatal(response.Code, response.Body.String())
		}
		var catalog access.PermissionCatalog
		if err = json.Unmarshal(response.Body.Bytes(), &catalog); err != nil {
			t.Fatal(err)
		}
		found := false
		for _, permission := range catalog.Permissions {
			if permission.Name == "example.read" {
				found = true
				if permission.Enabled != (enabled != "") || permission.Registered || len(permission.Roles) != 0 {
					t.Fatal(permission)
				}
			}
		}
		if !found {
			t.Fatal("compiled permission not exposed")
		}
		request := moduleRequest("POST", "/api/admin/permissions", strings.NewReader(`{"permission":"example.read"}`))
		request.Header.Set("Origin", "https://app.example.test")
		request.Header.Set("Content-Type", "application/json")
		response = httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		expected := 400
		if enabled != "" {
			expected = 201
		}
		if response.Code != expected {
			t.Fatal(response.Code, response.Body.String())
		}
		if expected == 201 {
			var result map[string]string
			if err = json.Unmarshal(response.Body.Bytes(), &result); err != nil || result["permission"] != "example.read" {
				t.Fatal("registration must return JSON", err)
			}
			response = httptest.NewRecorder()
			handler.ServeHTTP(response, moduleRequest("GET", "/api/modules/example/info", nil))
			if response.Code != 403 {
				t.Fatal("registration granted access to Admin", response.Code)
			}
		}
	}
}

// Exercise real Local DEV through the dispatcher; identities remain synthetic.
func moduleTestRuntime(t *testing.T, subject string) (*auth.Runtime, auth.Identity) {
	t.Helper()
	provider, err := auth.NewLocalDev("development", auth.LocalDevConfig{Subject: subject, Email: "test@example.invalid", DisplayName: "Test User"})
	if err != nil {
		t.Fatal(err)
	}
	runtime, err := auth.NewEnvironmentRuntime(provider, "test", "development")
	if err != nil {
		t.Fatal(err)
	}
	identity, err := provider.Authenticate(moduleRequest("GET", "/", nil))
	if err != nil {
		t.Fatal(err)
	}
	return runtime, identity
}

func moduleRequest(method, path string, body io.Reader) *http.Request {
	r := httptest.NewRequest(method, path, body)
	r.RemoteAddr = "127.0.0.1:1234"
	return r
}
