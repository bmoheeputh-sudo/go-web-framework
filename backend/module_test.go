package main

import (
	"context"
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
		if _, err := newServer(envReader(env)); err == nil || !strings.Contains(err.Error(), "ENABLED_MODULES") {
			t.Fatalf("bad configuration %q: %v", enabled, err)
		}
	}
	env := developmentEnvironment()
	env["ENABLED_MODULES"] = "example"
	if _, err := newServer(envReader(env)); err == nil || !strings.Contains(err.Error(), "RBAC_ENABLED") {
		t.Fatal("modules started without RBAC", err)
	}
	env["RBAC_ENABLED"] = "true"
	env["APP_ORIGIN"] = "http://127.0.0.1:5173"
	delete(env, "AUTH_PROVIDER")
	if _, err := newServer(envReader(env)); err == nil || !strings.Contains(err.Error(), "AUTH_PROVIDER") {
		t.Fatal("modules started without authentication", err)
	}
	env["AUTH_PROVIDER"] = "local_dev"
	if _, err := newServer(envReader(env)); err == nil {
		t.Fatal("modules started without a configured database")
	}
}

func TestDisabledModuleRoutesInApplication(t *testing.T) {
	for _, authenticated := range []bool{true, false} {
		env := developmentEnvironment()
		if !authenticated {
			delete(env, "AUTH_PROVIDER")
		}
		app, err := newServer(envReader(env))
		if err != nil {
			t.Fatal(err)
		}
		defer app.closeResources()
		for path, expected := range map[string]int{"/api/health": 200, "/api/modules/example/info": 404, "/api/modules": 200} {
			if path == "/api/modules" && !authenticated {
				expected = 401
			}
			r := httptest.NewRequest("GET", path, nil)
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
	identity := auth.Identity{Issuer: "https://issuer.test", Subject: "example-user", Provider: auth.OIDC}
	if _, err := store.Resolve(context.Background(), identity); err != nil {
		t.Fatal(err)
	}
	provider := authenticatorFunc(func(*http.Request) (auth.Identity, error) { return identity, nil })
	registry, err := modules.New([]module.Module{example.Module{}}, "example")
	if err != nil {
		t.Fatal(err)
	}
	handler, err := newHandlerWithModules(provider, store, "https://app.example.test", registry)
	if err != nil {
		t.Fatal(err)
	}
	for path, expected := range map[string]int{
		"/api/health": 200, "/api/auth/me": 200, "/api/auth/config": 200, "/api/access/me": 200,
		"/api/admin/users": 403, "/api/admin/roles": 403, "/api/admin/accounts": 403, "/api/admin/audit": 403, "/api/accounts": 403,
		"/api/modules": 200, "/api/modules/example/info": 403, "/api/modules/disabled/info": 404,
	} {
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, httptest.NewRequest("GET", path, nil))
		if w.Code != expected {
			t.Fatalf("%s: got %d want %d", path, w.Code, expected)
		}
	}
}
