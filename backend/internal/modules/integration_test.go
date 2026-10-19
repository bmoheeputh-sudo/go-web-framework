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
	request := func(registry *Registry, identity auth.Identity, authErr error, method, path, origin, contentType string) *httptest.ResponseRecorder {
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
		if strings.TrimSpace(w.Body.String()) != `{"modules":["example"]}` || w.Header().Get("Cache-Control") != "no-store" {
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
		for _, id := range []string{accounts["unlinked"], accounts["inactive"], "not-a-uuid", "00000000-0000-0000-0000-000000000000"} {
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
	t.Run("all writes receive existing origin protection and account checks", func(t *testing.T) {
		calls := 0
		writer := testModule{manifest: module.Manifest{ID: "writer", Permissions: []module.Permission{"writer.write"}}, register: func(r module.Registrar) error {
			return r.AccountRoute("POST", "/action", "writer.write", func(w http.ResponseWriter, _ *http.Request) { calls++; w.WriteHeader(204) })
		}}
		r, err := New([]module.Module{writer}, "writer")
		if err != nil {
			t.Fatal(err)
		}
		exec(`INSERT INTO framework.permissions(name,description) VALUES('writer.write','test')`)
		exec(`INSERT INTO framework.role_permissions(role,permission) VALUES('User','writer.write')`)
		before := snapshot()
		for _, headers := range [][2]string{{"", "application/json"}, {"https://evil.test", "application/json"}, {"https://app.example.test", "text/plain"}} {
			status(request(r, verified("User"), nil, "POST", "/api/modules/writer/accounts/"+accounts["linked"]+"/action", headers[0], headers[1]), 403)
		}
		status(request(r, verified("User"), nil, "POST", "/api/modules/writer/accounts/"+accounts["unlinked"]+"/action", "https://app.example.test", "application/json"), 403)
		status(request(r, verified("Admin"), nil, "POST", "/api/modules/writer/accounts/"+accounts["linked"]+"/action", "https://app.example.test", "application/json"), 403)
		if calls != 0 || snapshot() != before {
			t.Fatal("denied writes reached module or changed records")
		}
		status(request(r, verified("User"), nil, "POST", "/api/modules/writer/accounts/"+accounts["linked"]+"/action", "https://app.example.test", "application/json"), 204)
		if calls != 1 {
			t.Fatal("authorized request did not reach handler exactly once")
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
		status(get("User", "/api/modules/example/info"), 503)
	})
}
