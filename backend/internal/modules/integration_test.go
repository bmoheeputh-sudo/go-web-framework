package modules

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/bmoheeputh-sudo/go-web-framework/backend/internal/access"
	"github.com/bmoheeputh-sudo/go-web-framework/backend/internal/apps/example"
	"github.com/bmoheeputh-sudo/go-web-framework/backend/internal/auth"
	"github.com/bmoheeputh-sudo/go-web-framework/backend/internal/testdb"
	"github.com/bmoheeputh-sudo/go-web-framework/backend/module"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestModuleSecurityIntegration(t *testing.T) {
	owner, connection := testdb.New(t) // disposable cluster; never reads DB_* or .env
	testdb.Migrations(t, owner, "up")
	ctx := context.Background()
	config, err := pgxpool.ParseConfig(connection)
	if err != nil {
		t.Fatal(err)
	}
	config.ConnConfig.User = "go_web_app"
	config.ConnConfig.RuntimeParams["search_path"] = "pg_catalog"
	runtime, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(runtime.Close)
	store := access.New(runtime)
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := owner.Exec(ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	users := map[string]access.User{}
	for _, role := range []string{"Admin", "User", "Viewer", "None", "Inactive"} {
		u, err := store.Resolve(ctx, verified(role))
		if err != nil {
			t.Fatal(err)
		}
		users[role] = u
		if role != "None" && role != "Inactive" {
			exec(`INSERT INTO framework.user_roles(user_id,role) VALUES($1,$2)`, u.ID, role)
		}
	}
	exec(`UPDATE framework.users SET active=false WHERE id=$1`, users["Inactive"].ID)
	accounts := map[string]string{}
	for _, name := range []string{"linked", "second", "unlinked", "inactive"} {
		var id string
		if err := owner.QueryRow(ctx, `INSERT INTO framework.accounts(name,active) VALUES($1,$2) RETURNING id::text`, name, name != "inactive").Scan(&id); err != nil {
			t.Fatal(err)
		}
		accounts[name] = id
		if name != "unlinked" {
			exec(`INSERT INTO framework.user_accounts(user_id,account_id) VALUES($1,$2)`, users["User"].ID, id)
		}
	}
	exec(`INSERT INTO framework.user_accounts(user_id,account_id) VALUES($1,$2),($3,$2)`, users["Admin"].ID, accounts["linked"], users["Viewer"].ID)
	registry, err := New([]module.Module{example.Module{}}, "example")
	if err != nil {
		t.Fatal(err)
	}
	request := func(registry *Registry, identity auth.Identity, authErr error, method, path, origin, contentType string, customize ...func(*http.Request)) *httptest.ResponseRecorder {
		t.Helper()
		h, err := registry.Handler(fixedAuth{identity, authErr}, store, "https://app.example.test")
		if err != nil {
			t.Fatal(err)
		}
		r := httptest.NewRequest(method, path, strings.NewReader(`{"account":"forged","subject":"Admin","permission":"admin.manage"}`))
		r.Header.Set("Origin", origin)
		r.Header.Set("Content-Type", contentType)
		r.Header.Set("X-User-ID", users["Admin"].ID)
		r.Header.Set("X-Goog-Authenticated-User-Email", "admin@example.test")
		for _, modify := range customize {
			modify(r)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	get := func(role, path string) *httptest.ResponseRecorder {
		return request(registry, verified(role), nil, "GET", path, "", "")
	}
	status := func(w *httptest.ResponseRecorder, want int) {
		t.Helper()
		if w.Code != want {
			t.Fatalf("status %d want %d: %s", w.Code, want, w.Body.String())
		}
		if strings.Contains(w.Body.String(), "password") {
			t.Fatal("error leaked")
		}
	}
	snapshot := func() string {
		t.Helper()
		result := ""
		for _, table := range []string{"users", "user_roles", "accounts", "user_accounts", "permissions", "role_permissions", "audit_log"} {
			var rows string
			if err := owner.QueryRow(ctx, `SELECT COALESCE(jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text),'[]'::jsonb)::text FROM framework.`+table+` t`).Scan(&rows); err != nil {
				t.Fatal(err)
			}
			result += rows
		}
		return result
	}
	t.Run("no startup writes or automatic Admin grants", func(t *testing.T) {
		before := snapshot()
		for _, role := range []string{"Admin", "User", "Viewer", "None"} {
			status(get(role, "/api/modules/example/info"), 403)
		}
		if snapshot() != before {
			t.Fatal("registration or denied requests changed records")
		}
	})
	// Explicit test-only owner grants. Production startup never runs these SQL statements.
	exec(`INSERT INTO framework.permissions(name,description) VALUES('example.read','test'),('example.undeclared','test')`)
	exec(`INSERT INTO framework.role_permissions(role,permission) VALUES('User','example.read'),('User','example.undeclared')`)
	t.Run("capabilities contain IDs only and require authentication", func(t *testing.T) {
		status(request(registry, auth.Identity{}, auth.ErrUnauthenticated, "GET", "/api/modules", "", ""), 401)
		before := snapshot()
		w := get("unregistered", "/api/modules")
		status(w, 200)
		if strings.TrimSpace(w.Body.String()) != `{"modules":["example"]}` || w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("Location") != "" {
			t.Fatal(w.Body.String())
		}
		if snapshot() != before {
			t.Fatal("capabilities resolved/created a user")
		}
		status(request(registry, verified("User"), nil, "POST", "/api/modules", "https://app.example.test", "application/json"), 405)
	})
	t.Run("permission and account checks are independent and read-only", func(t *testing.T) {
		before := snapshot()
		for _, role := range []string{"Admin", "Viewer", "None", "Inactive", "unregistered"} {
			status(get(role, "/api/modules/example/info"), 403)
			status(get(role, "/api/modules/example/accounts/"+accounts["linked"]+"/info"), 403)
		}
		status(get("User", "/api/modules/example/info"), 200)
		for _, name := range []string{"linked", "second"} {
			w := get("User", "/api/modules/example/accounts/"+accounts[name]+"/info?account="+accounts["unlinked"]+"&permission=admin.manage&subject=Admin")
			status(w, 200)
			var body map[string]string
			if json.Unmarshal(w.Body.Bytes(), &body) != nil || body["account_id"] != accounts[name] {
				t.Fatal("scope came from an unverified source")
			}
		}
		for _, id := range []string{accounts["unlinked"], accounts["inactive"], "00000000-0000-0000-0000-000000000000"} {
			status(get("User", "/api/modules/example/accounts/"+id+"/info?account="+accounts["linked"]), 403)
		}
		otherIssuer := verified("User")
		otherIssuer.Issuer = "https://other.test"
		status(request(registry, otherIssuer, nil, "GET", "/api/modules/example/info", "", ""), 403)
		status(request(registry, auth.Identity{}, auth.ErrUnauthenticated, "GET", "/api/modules/example/info", "", ""), 401)
		status(request(registry, auth.Identity{}, auth.ErrUnauthenticated, "GET", "/api/modules/example/accounts/"+accounts["linked"]+"/info", "", ""), 401)
		if snapshot() != before {
			t.Fatal("module reads or denials changed authorization/audit records")
		}
	})
	t.Run("malformed account IDs return sanitized bad requests", func(t *testing.T) {
		before := snapshot()
		for _, role := range []string{"User", "Admin"} {
			for _, id := range []string{"not-a-uuid", "00000000-0000-0000-0000-00000000000g", "00000000000000000000000000000000", "%27"} {
				w := get(role, "/api/modules/example/accounts/"+id+"/info")
				status(w, 400)
				if strings.TrimSpace(w.Body.String()) != `{"error":"invalid_account_id"}` || w.Header().Get("Content-Type") != "application/json" {
					t.Fatalf("unexpected invalid account response: %s", w.Body.String())
				}
			}
		}
		// Authentication still takes precedence over request validation.
		status(request(registry, auth.Identity{}, auth.ErrUnauthenticated, "GET", "/api/modules/example/accounts/not-a-uuid/info", "", ""), 401)
		if snapshot() != before {
			t.Fatal("malformed requests changed database records")
		}
	})
	t.Run("Admin with explicit module permission still needs linked active accounts", func(t *testing.T) {
		exec(`INSERT INTO framework.role_permissions(role,permission) VALUES('Admin','example.read')`)
		defer exec(`DELETE FROM framework.role_permissions WHERE role='Admin' AND permission='example.read'`)
		before := snapshot()
		status(get("Admin", "/api/modules/example/info"), 200)
		status(get("Admin", "/api/modules/example/accounts/"+accounts["linked"]+"/info"), 200)
		for _, id := range []string{accounts["unlinked"], accounts["second"], "00000000-0000-0000-0000-000000000000"} {
			status(get("Admin", "/api/modules/example/accounts/"+id+"/info"), 403)
		}
		if snapshot() != before {
			t.Fatal("Admin requests changed database records")
		}
		exec(`UPDATE framework.accounts SET active=false WHERE id=$1`, accounts["linked"])
		defer exec(`UPDATE framework.accounts SET active=true WHERE id=$1`, accounts["linked"])
		status(get("Admin", "/api/modules/example/accounts/"+accounts["linked"]+"/info"), 403)
	})
	t.Run("unknown database permissions are still denied and core store is unchanged", func(t *testing.T) {
		moduleStore, err := store.WithModulePermissions([]string{"example.read"})
		if err != nil {
			t.Fatal(err)
		}
		if err := moduleStore.Allowed(ctx, users["User"].ID, "example.read", accounts["linked"]); err != nil {
			t.Fatal(err)
		}
		for _, permission := range []string{"", "unknown", "example.undeclared", "example.typo"} {
			if !errors.Is(moduleStore.Allowed(ctx, users["User"].ID, permission, ""), access.ErrDenied) {
				t.Fatal("unknown permission allowed")
			}
		}
		if !errors.Is(store.Allowed(ctx, users["User"].ID, "example.read", ""), access.ErrDenied) {
			t.Fatal("original store was mutated")
		}
		if err := store.Allowed(ctx, users["Admin"].ID, access.AdminManage, ""); err != nil {
			t.Fatal("core permission changed", err)
		}
	})
	t.Run("revocation and account deactivation take effect on next request", func(t *testing.T) {
		exec(`UPDATE framework.accounts SET active=false WHERE id=$1`, accounts["linked"])
		status(get("User", "/api/modules/example/accounts/"+accounts["linked"]+"/info"), 403)
		exec(`UPDATE framework.accounts SET active=true WHERE id=$1`, accounts["linked"])
		exec(`DELETE FROM framework.user_accounts WHERE user_id=$1 AND account_id=$2`, users["User"].ID, accounts["linked"])
		status(get("User", "/api/modules/example/accounts/"+accounts["linked"]+"/info"), 403)
		exec(`INSERT INTO framework.user_accounts(user_id,account_id) VALUES($1,$2)`, users["User"].ID, accounts["linked"])
		exec(`DELETE FROM framework.role_permissions WHERE role='User' AND permission='example.read'`)
		status(get("User", "/api/modules/example/info"), 403)
		exec(`INSERT INTO framework.role_permissions(role,permission) VALUES('User','example.read')`)
	})
	t.Run("middleware security matrix before handler execution", func(t *testing.T) {
		calls := 0
		methods := []string{"GET", "POST", "PUT", "PATCH", "DELETE"}
		writer := testModule{manifest: module.Manifest{ID: "writer", Permissions: []module.Permission{"writer.write"}}, register: func(r module.Registrar) error {
			handler := func(w http.ResponseWriter, req *http.Request) {
				calls++
				if _, ok := auth.IdentityFromContext(req.Context()); !ok {
					t.Error("handler did not receive verified identity")
				}
				if _, ok := access.Principal(req.Context()); !ok {
					t.Error("handler did not receive authorized principal")
				}
				w.WriteHeader(204)
			}
			for _, method := range methods {
				if err := r.GlobalRoute(method, "/action", "writer.write", handler); err != nil {
					return err
				}
				if err := r.AccountRoute(method, "/action", "writer.write", handler); err != nil {
					return err
				}
			}
			return nil
		}}
		r, err := New([]module.Module{writer}, "writer")
		if err != nil {
			t.Fatal(err)
		}
		exec(`INSERT INTO framework.permissions(name,description) VALUES('writer.write','test')`)
		exec(`INSERT INTO framework.role_permissions(role,permission) VALUES('User','writer.write')`)
		disabled, err := New([]module.Module{writer}, "")
		if err != nil {
			t.Fatal(err)
		}
		for _, method := range methods {
			for _, scope := range []string{"global", "account"} {
				t.Run(method+"/"+scope, func(t *testing.T) {
					path := "/api/modules/writer/action"
					if scope == "account" {
						path = "/api/modules/writer/accounts/" + accounts["linked"] + "/action"
					}
					type testCase struct {
						name, role, path, origin, contentType string
						authErr                               error
						want                                  int
						customize                             func(*http.Request)
					}
					cases := []testCase{
						{"unauthenticated", "User", path, "https://app.example.test", "application/json", auth.ErrUnauthenticated, 401, nil},
						{"authentication before write checks", "User", path, "", "", auth.ErrUnauthenticated, 401, nil},
						{"Admin without grant", "Admin", path, "https://app.example.test", "application/json", nil, 403, nil},
						{"no permission", "Viewer", path, "https://app.example.test", "application/json", nil, 403, nil},
						{"no roles", "None", path, "https://app.example.test", "application/json", nil, 403, nil},
						{"inactive user", "Inactive", path, "https://app.example.test", "application/json", nil, 403, nil},
						{"unregistered user", "unregistered", path, "https://app.example.test", "application/json", nil, 403, nil},
					}
					if scope == "account" {
						cases = append(cases, testCase{"malformed account", "User", "/api/modules/writer/accounts/not-a-uuid/action", "https://app.example.test", "application/json", nil, 400, nil})
						for _, account := range []string{"unlinked", "inactive"} {
							cases = append(cases, testCase{account, "User", "/api/modules/writer/accounts/" + accounts[account] + "/action", "https://app.example.test", "application/json", nil, 403, nil})
						}
					}
					if method != "GET" {
						for _, headers := range [][3]string{
							{"missing origin", "", "application/json"},
							{"cross origin", "https://evil.test", "application/json"},
							{"null origin", "null", "application/json"},
							{"missing content type", "https://app.example.test", ""},
							{"non JSON", "https://app.example.test", "text/plain"},
							{"malformed content type", "https://app.example.test", "application/json;broken"},
						} {
							cases = append(cases, testCase{headers[0], "User", path, headers[1], headers[2], nil, 403, nil})
						}
						cases = append(cases, testCase{"duplicate origin", "User", path, "https://app.example.test", "application/json", nil, 403, func(req *http.Request) { req.Header.Add("Origin", "https://app.example.test") }})
					}
					for _, tc := range cases {
						t.Run(tc.name, func(t *testing.T) {
							before, callsBefore := snapshot(), calls
							var customize []func(*http.Request)
							if tc.customize != nil {
								customize = append(customize, tc.customize)
							}
							w := request(r, verified(tc.role), tc.authErr, method, tc.path, tc.origin, tc.contentType, customize...)
							status(w, tc.want)
							wantBody := map[int]string{400: `{"error":"invalid_account_id"}`, 401: `{"error":"unauthenticated"}`, 403: `{"error":"access denied"}`}[tc.want]
							if strings.TrimSpace(w.Body.String()) != wantBody {
								t.Fatalf("unexpected error details: %s", w.Body.String())
							}
							if calls != callsBefore || snapshot() != before {
								t.Fatal("denied request reached handler or changed records")
							}
						})
					}
					before := calls
					status(request(disabled, verified("User"), nil, method, path, "https://app.example.test", "application/json"), 404)
					if calls != before {
						t.Fatal("disabled handler executed")
					}
					status(request(r, verified("User"), nil, method, path, "https://app.example.test", "application/json; charset=utf-8"), 204)
					if calls != before+1 {
						t.Fatal("authorized handler did not execute exactly once")
					}
					if scope == "account" {
						t.Run("Admin grant does not bypass membership", func(t *testing.T) {
							exec(`INSERT INTO framework.role_permissions(role,permission) VALUES('Admin','writer.write')`)
							defer exec(`DELETE FROM framework.role_permissions WHERE role='Admin' AND permission='writer.write'`)
							before, callsBefore := snapshot(), calls
							status(request(r, verified("Admin"), nil, method, "/api/modules/writer/accounts/"+accounts["unlinked"]+"/action", "https://app.example.test", "application/json"), 403)
							if calls != callsBefore || snapshot() != before {
								t.Fatal("unlinked Admin reached handler or changed records")
							}
							status(request(r, verified("Admin"), nil, method, path, "https://app.example.test", "application/json"), 204)
							if calls != callsBefore+1 {
								t.Fatal("explicitly authorized Admin did not reach handler")
							}
						})
					}
				})
			}
		}
	})
	t.Run("disabled routes stay absent even with database grants", func(t *testing.T) {
		disabled, err := New([]module.Module{example.Module{}}, "")
		if err != nil {
			t.Fatal(err)
		}
		status(request(disabled, verified("User"), nil, "GET", "/api/modules/example/info", "", ""), 404)
	})
	t.Run("database failure fails closed", func(t *testing.T) {
		runtime.Close()
		w := get("User", "/api/modules/example/info")
		status(w, 503)
		if strings.TrimSpace(w.Body.String()) != `{"error":"authorization temporarily unavailable"}` {
			t.Fatalf("database error details leaked: %s", w.Body.String())
		}
	})
}
