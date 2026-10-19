package modules

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/bmoheeputh-sudo/go-web-framework/backend/internal/access"
	"github.com/bmoheeputh-sudo/go-web-framework/backend/internal/apps/example"
	"github.com/bmoheeputh-sudo/go-web-framework/backend/internal/auth"
	"github.com/bmoheeputh-sudo/go-web-framework/backend/module"
)

type testModule struct {
	manifest module.Manifest
	register func(module.Registrar) error
}

func (m testModule) Manifest() module.Manifest { return m.manifest }
func (m testModule) Register(r module.Registrar) error {
	if m.register != nil {
		return m.register(r)
	}
	return nil
}
func candidate(id string, register func(module.Registrar) error) testModule {
	return testModule{module.Manifest{ID: id, Permissions: []module.Permission{module.Permission(id + ".read")}}, register}
}
func noContent(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) }

func TestConfiguration(t *testing.T) {
	for _, value := range []string{" ", "example,", ",example", "example,,second", "example, example", "Example", "example\n", "example,example", "unknown", "example,*", "../example"} {
		t.Run(value, func(t *testing.T) {
			if _, err := New([]module.Module{example.Module{}, candidate("second", nil)}, value); err == nil {
				t.Fatal("invalid configuration accepted")
			}
		})
	}
	t.Run("empty disables registration", func(t *testing.T) {
		registry, err := New([]module.Module{candidate("example", func(module.Registrar) error { t.Fatal("disabled module registered"); return nil })}, "")
		if err != nil || len(registry.Enabled()) != 0 {
			t.Fatalf("disabled: %v", err)
		}
	})
	t.Run("explicit deterministic registration and immutable IDs", func(t *testing.T) {
		calls := []string{}
		var retained module.Registrar
		registry, err := New([]module.Module{
			candidate("second", func(r module.Registrar) error {
				calls = append(calls, "second")
				return r.GlobalRoute("GET", "/info", "second.read", noContent)
			}),
			candidate("example", func(r module.Registrar) error {
				retained = r
				calls = append(calls, "example")
				return r.GlobalRoute("GET", "/info", "example.read", noContent)
			}),
		}, "second,example")
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(calls, []string{"example", "second"}) {
			t.Fatal(calls)
		}
		ids := registry.Enabled()
		ids[0] = "changed"
		if registry.Enabled()[0] != "example" {
			t.Fatal("mutable registry")
		}
		if retained.GlobalRoute("GET", "/later", "example.read", noContent) == nil {
			t.Fatal("late registration accepted")
		}
	})
}

func TestInvalidCatalog(t *testing.T) {
	for name, catalog := range map[string][]module.Module{
		"nil": {nil}, "duplicate": {example.Module{}, example.Module{}},
		"empty": {candidate("", nil)}, "uppercase": {candidate("Example", nil)},
		"reserved": {candidate("accounts", nil)}, "path": {candidate("../auth", nil)},
		"foreign permission":   {testModule{manifest: module.Manifest{ID: "example", Permissions: []module.Permission{"other.read"}}}},
		"core permission":      {testModule{manifest: module.Manifest{ID: "example", Permissions: []module.Permission{"admin.manage"}}}},
		"empty permission":     {testModule{manifest: module.Manifest{ID: "example", Permissions: []module.Permission{""}}}},
		"malformed permission": {testModule{manifest: module.Manifest{ID: "example", Permissions: []module.Permission{"example.read.*"}}}},
		"duplicate permission": {testModule{manifest: module.Manifest{ID: "example", Permissions: []module.Permission{"example.read", "example.read"}}}},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := New(catalog, ""); err == nil {
				t.Fatal("invalid catalog accepted even when disabled")
			}
		})
	}
}

func TestRouteValidation(t *testing.T) {
	for name, register := range map[string]func(module.Registrar) error{
		"empty permission":   func(r module.Registrar) error { return r.GlobalRoute("GET", "/info", "", noContent) },
		"unknown permission": func(r module.Registrar) error { return r.GlobalRoute("GET", "/info", "example.unknown", noContent) },
		"core permission":    func(r module.Registrar) error { return r.GlobalRoute("GET", "/info", "admin.manage", noContent) },
		"nil handler":        func(r module.Registrar) error { return r.GlobalRoute("GET", "/info", "example.read", nil) },
		"methodless":         func(r module.Registrar) error { return r.GlobalRoute("", "/info", "example.read", noContent) },
		"unsupported method": func(r module.Registrar) error { return r.GlobalRoute("TRACE", "/info", "example.read", noContent) },
		"scope override": func(r module.Registrar) error {
			return r.AccountRoute("GET", "/items/{account}", "example.read", noContent)
		},
		"global account bypass": func(r module.Registrar) error {
			return r.GlobalRoute("GET", "/accounts/{id}/info", "example.read", noContent)
		},
		"duplicate": func(r module.Registrar) error {
			if err := r.GlobalRoute("GET", "/info", "example.read", noContent); err != nil {
				return err
			}
			return r.GlobalRoute("GET", "/info", "example.read", noContent)
		},
		"equivalent wildcards": func(r module.Registrar) error {
			if err := r.AccountRoute("GET", "/items/{id}", "example.read", noContent); err != nil {
				return err
			}
			return r.AccountRoute("GET", "/items/{other}", "example.read", noContent)
		},
		"ambiguous patterns": func(r module.Registrar) error {
			if err := r.GlobalRoute("GET", "/items/{id}/detail", "example.read", noContent); err != nil {
				return err
			}
			return r.GlobalRoute("GET", "/items/current/{field}", "example.read", noContent)
		},
		"repeated parameter": func(r module.Registrar) error {
			return r.GlobalRoute("GET", "/items/{id}/{id}", "example.read", noContent)
		},
		"ignored error":      func(r module.Registrar) error { _ = r.GlobalRoute("GET", "/info", "", noContent); return nil },
		"registration error": func(module.Registrar) error { return errors.New("failed") },
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := New([]module.Module{candidate("example", register)}, "example"); err == nil {
				t.Fatal("invalid route accepted")
			}
		})
	}
	for _, path := range []string{"", "/", "/info/", "/../auth/me", "/info?account=a", "https://example.test/", "//auth/me", "/{name}", "/items/{rest...}", "/items/%61", "/items/{$}"} {
		t.Run("path"+path, func(t *testing.T) {
			m := candidate("example", func(r module.Registrar) error { return r.GlobalRoute("GET", path, "example.read", noContent) })
			if _, err := New([]module.Module{m}, "example"); err == nil {
				t.Fatal("unsafe path accepted")
			}
		})
	}
}

type fixedAuth struct {
	identity auth.Identity
	err      error
}

func (a fixedAuth) Authenticate(*http.Request) (auth.Identity, error) { return a.identity, a.err }
func verified(subject string) auth.Identity {
	return auth.Identity{Issuer: "https://issuer.test", Subject: subject, Provider: auth.OIDC}
}

func TestDisabledCapabilitiesAndStartupRequirements(t *testing.T) {
	registry, err := New([]module.Module{example.Module{}}, "")
	if err != nil {
		t.Fatal(err)
	}
	for _, authenticated := range []bool{false, true} {
		var provider auth.Authenticator
		if authenticated {
			provider = fixedAuth{identity: verified("test")}
		}
		h, err := registry.Handler(provider, nil, "")
		if err != nil {
			t.Fatal(err)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("GET", "/api/modules", nil))
		want := 401
		if authenticated {
			want = 200
			if strings.TrimSpace(w.Body.String()) != `{"modules":[]}` {
				t.Fatal(w.Body.String())
			}
		}
		if w.Code != want || w.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("status %d", w.Code)
		}
		w = httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("GET", "/api/modules/example/info", nil))
		if w.Code != 404 {
			t.Fatal("disabled endpoint reachable")
		}
	}
	registry, err = New([]module.Module{example.Module{}}, "example")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = registry.Handler(nil, nil, ""); err == nil {
		t.Fatal("enabled without security dependencies")
	}
}

func TestCapabilitiesDirectResponse(t *testing.T) {
	for _, enabled := range []string{"", "second,example"} {
		for _, authenticated := range []bool{false, true} {
			name := enabled + "/anonymous"
			provider := fixedAuth{err: auth.ErrUnauthenticated}
			if authenticated {
				name = enabled + "/authenticated"
				provider = fixedAuth{identity: verified("test")}
			}
			t.Run(name, func(t *testing.T) {
				registry, err := New([]module.Module{example.Module{}, candidate("second", nil), candidate("disabled", nil)}, enabled)
				if err != nil {
					t.Fatal(err)
				}
				// Capabilities need no database access. A nil pool makes accidental
				// database use fail this test rather than contact a real database.
				handler, err := registry.Handler(provider, access.New(nil), "https://app.example.test")
				if err != nil {
					t.Fatal(err)
				}
				// Exercise the exact and subtree mounts used by the application.
				outer := http.NewServeMux()
				outer.Handle("/api/modules", handler)
				outer.Handle("/api/modules/", handler)
				w := httptest.NewRecorder()
				outer.ServeHTTP(w, httptest.NewRequest("GET", "/api/modules", nil))
				want, body := 401, `{"error":"unauthenticated"}`
				if authenticated {
					want, body = 200, `{"modules":[]}`
					if enabled != "" {
						body = `{"modules":["example","second"]}`
					}
				}
				if w.Code != want || w.Header().Get("Location") != "" || strings.TrimSpace(w.Body.String()) != body {
					t.Fatalf("direct response: status=%d location=%q body=%s", w.Code, w.Header().Get("Location"), w.Body.String())
				}
				if w.Header().Get("Content-Type") != "application/json" || w.Header().Get("Cache-Control") != "no-store" {
					t.Fatal("missing JSON/no-store headers")
				}
			})
		}
	}
}
