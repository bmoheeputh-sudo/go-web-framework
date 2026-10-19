package access

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bmoheeputh-sudo/go-web-framework/backend/internal/auth"
)

type unauthenticatedSettings struct{}

func (unauthenticatedSettings) Authenticate(*http.Request) (auth.Identity, error) {
	return auth.Identity{}, auth.ErrUnauthenticated
}

func settingsFixture(t *testing.T) *securityFixture {
	t.Helper()
	f := newSecurityFixture(t)
	// Existing production go_web_app owns these objects. This fixture deliberately
	// uses a non-owner runtime role, with only the additional tested DML grants.
	if _, err := f.owner.Exec(context.Background(), `GRANT INSERT ON framework.permissions TO go_web_app; GRANT INSERT,DELETE ON framework.role_permissions TO go_web_app`); err != nil {
		t.Fatal(err)
	}
	var err error
	f.store, err = f.store.WithPermissionDefinitions([]PermissionDefinition{
		{"example.read", "Read the example module", "example", true},
		{"disabled.read", "Disabled module", "disabled", false},
	})
	if err != nil {
		t.Fatal(err)
	}
	return f
}
func settingsCatalog(t *testing.T, f *securityFixture) PermissionCatalog {
	t.Helper()
	response := f.request("Admin", "GET", "/api/admin/permissions", nil)
	requireStatus(t, response, 200)
	var catalog PermissionCatalog
	if err := json.Unmarshal(response.Body.Bytes(), &catalog); err != nil {
		t.Fatal(err)
	}
	return catalog
}
func change(role, permission string, assigned bool) PermissionChange {
	return PermissionChange{permission, role, &assigned}
}
func settingsUpdate(f *securityFixture, revision string, changes ...PermissionChange) *httptest.ResponseRecorder {
	return f.request("Admin", "PUT", "/api/admin/role-permissions", map[string]any{"revision": revision, "changes": changes})
}
func TestPermissionSettings(t *testing.T) {
	f := settingsFixture(t)
	t.Run("catalog reports compiled missing enabled and disabled definitions and database grants", func(t *testing.T) {
		catalog := settingsCatalog(t, f)
		if len(catalog.Permissions) != 5 || len(catalog.Roles) != 3 || len(catalog.Revision) != 64 {
			t.Fatal(catalog)
		}
		for _, p := range catalog.Permissions {
			if p.Name == "example.read" && (p.Registered || !p.Enabled || !p.Known || len(p.Roles) != 0) {
				t.Fatal(p)
			}
			if p.Name == "disabled.read" && (p.Registered || p.Enabled) {
				t.Fatal(p)
			}
			if p.Name == AccountWrite && (!p.Registered || strings.Join(p.Roles, ",") != "Admin,User") {
				t.Fatal(p)
			}
		}
	})
	t.Run("denied readers and writers leave all records unchanged", func(t *testing.T) {
		for _, role := range []string{"User", "Viewer", "None"} {
			f.denied(t, role, "GET", "/api/admin/permissions", nil)
			f.denied(t, role, "POST", "/api/admin/permissions", map[string]any{"permission": "example.read"})
			f.denied(t, role, "PUT", "/api/admin/role-permissions", map[string]any{"revision": settingsCatalog(t, f).Revision, "changes": []PermissionChange{change(role, AccountWrite, true)}})
		}
		before := f.snapshot(t)
		for _, method := range []string{"GET", "POST", "PUT"} {
			path := "/api/admin/permissions"
			if method == "PUT" {
				path = "/api/admin/role-permissions"
			}
			mux := http.NewServeMux()
			Register(mux, unauthenticatedSettings{}, f.store, origin)
			response := httptest.NewRecorder()
			mux.ServeHTTP(response, httptest.NewRequest(method, path, strings.NewReader(`{}`)))
			requireStatus(t, response, 401)
		}
		f.assertUnchanged(t, before)
	})
	t.Run("register explicit enabled declaration and audit without automatic grants", func(t *testing.T) {
		before := f.auditCount(t)
		requireStatus(t, f.request("Admin", "POST", "/api/admin/permissions", map[string]string{"permission": "example.read"}), 201)
		f.assertAudit(t, before, f.users["Admin"].ID, "permission.register", "example.read", permissionAudit{"example.read", "", false, true})
		for _, p := range settingsCatalog(t, f).Permissions {
			if p.Name == "example.read" && (!p.Registered || len(p.Roles) != 0) {
				t.Fatal(p)
			}
		}
	})
	t.Run("invalid registration duplicate arbitrary actor and origin are rejected", func(t *testing.T) {
		before := f.snapshot(t)
		for _, name := range []string{"example.unknown", "disabled.read", "admin.manage", "bad;DROP TABLE", "", "external.read"} {
			requireStatus(t, f.request("Admin", "POST", "/api/admin/permissions", map[string]string{"permission": name}), 400)
		}
		requireStatus(t, f.request("Admin", "POST", "/api/admin/permissions", map[string]string{"permission": "example.read"}), 409)
		requireStatus(t, f.request("Admin", "POST", "/api/admin/permissions", map[string]string{"permission": "example.read", "actor": f.users["User"].ID}), 400)
		requireStatus(t, call(f.store, f.identities["Admin"], "POST", "/api/admin/permissions", `{"permission":"example.read"}`, "https://evil.test"), 403)
		f.assertUnchanged(t, before)
	})
	t.Run("grant revoke and audit actual previous and new assignments", func(t *testing.T) {
		before := f.auditCount(t)
		revision := settingsCatalog(t, f).Revision
		requireStatus(t, settingsUpdate(f, revision, change("Viewer", "example.read", true)), 204)
		f.assertAudit(t, before, f.users["Admin"].ID, "role.permission", "Viewer", permissionAudit{"example.read", "Viewer", false, true})
		roles, err := f.store.Roles(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(strings.Join(roles[2].Permissions, ","), "example.read") {
			t.Fatal(roles)
		}
		before = f.auditCount(t)
		requireStatus(t, settingsUpdate(f, settingsCatalog(t, f).Revision, change("Viewer", "example.read", false)), 204)
		f.assertAudit(t, before, f.users["Admin"].ID, "role.permission", "Viewer", permissionAudit{"example.read", "Viewer", true, false})
		// Even when assignments return to the initial values, the old revision fails.
		requireStatus(t, settingsUpdate(f, revision, change("Viewer", "example.read", true)), 409)
	})
	t.Run("critical grants malformed batches and unknown permissions fail atomically", func(t *testing.T) {
		revision := settingsCatalog(t, f).Revision
		before := f.snapshot(t)
		for _, c := range []PermissionChange{change("Admin", AdminManage, false), change("User", AdminManage, true), change("Viewer", AdminManage, true)} {
			requireStatus(t, settingsUpdate(f, revision, c), 403)
		}
		for _, c := range []PermissionChange{change("Viewer", "example.unknown", true), change("Viewer", "disabled.read", true), change("Owner", AccountRead, true), {Permission: AccountRead, Role: "Viewer"}} {
			requireStatus(t, settingsUpdate(f, revision, change("Viewer", AccountWrite, true), c), 400)
		}
		requireStatus(t, settingsUpdate(f, revision, change("Viewer", AccountWrite, true), change("Viewer", AccountWrite, false)), 400)
		requireStatus(t, settingsUpdate(f, "invalid", change("Viewer", AccountWrite, true)), 400)
		f.assertUnchanged(t, before)
	})
	t.Run("concurrent administrators cannot overwrite conflicting snapshots", func(t *testing.T) {
		f.identities["AdminTwo"] = identity("settings-second-admin")
		second, err := f.store.Resolve(context.Background(), f.identities["AdminTwo"])
		if err != nil {
			t.Fatal(err)
		}
		if err = f.store.SetRoles(context.Background(), f.users["Admin"].ID, second.ID, []string{"Admin"}); err != nil {
			t.Fatal(err)
		}
		revision := settingsCatalog(t, f).Revision
		var wg sync.WaitGroup
		statuses := make(chan int, 2)
		for _, actor := range []string{"Admin", "AdminTwo"} {
			wg.Add(1)
			go func() {
				defer wg.Done()
				statuses <- f.request(actor, "PUT", "/api/admin/role-permissions", map[string]any{"revision": revision, "changes": []PermissionChange{change("Viewer", AccountWrite, true)}}).Code
			}()
		}
		wg.Wait()
		close(statuses)
		counts := map[int]int{}
		for status := range statuses {
			counts[status]++
		}
		if counts[204] != 1 || counts[409] != 1 {
			t.Fatal(counts)
		}
		requireStatus(t, settingsUpdate(f, settingsCatalog(t, f).Revision, change("Viewer", AccountWrite, false)), 204)
	})
	t.Run("audit insertion failure rolls back whole batch and registration", func(t *testing.T) {
		ctx := context.Background()
		if _, err := f.owner.Exec(ctx, `REVOKE INSERT ON framework.audit_log FROM go_web_app`); err != nil {
			t.Fatal(err)
		}
		defer func() {
			_, err := f.owner.Exec(ctx, `GRANT INSERT ON framework.audit_log TO go_web_app`)
			if err != nil {
				t.Error(err)
			}
		}()
		before := f.snapshot(t)
		requireStatus(t, settingsUpdate(f, settingsCatalog(t, f).Revision, change("Viewer", AccountWrite, true), change("User", "example.read", true)), 503)
		f.assertUnchanged(t, before)
		var err error
		f.store, err = f.store.WithPermissionDefinitions([]PermissionDefinition{{"newmodule.read", "New module", "newmodule", true}})
		if err != nil {
			t.Fatal(err)
		}
		requireStatus(t, f.request("Admin", "POST", "/api/admin/permissions", map[string]string{"permission": "newmodule.read"}), 503)
		f.assertUnchanged(t, before)
	})
	t.Run("disabled existing permissions can only be revoked and orphan permissions are read only", func(t *testing.T) {
		var err error
		f.store, err = f.store.WithPermissionDefinitions([]PermissionDefinition{{"example.read", "Read example", "example", false}})
		if err != nil {
			t.Fatal(err)
		}
		if _, err = f.owner.Exec(context.Background(), `INSERT INTO framework.role_permissions(role,permission) VALUES('User','example.read'); INSERT INTO framework.permissions(name,description) VALUES('orphan.read','Legacy definition')`); err != nil {
			t.Fatal(err)
		}
		before := f.snapshot(t)
		requireStatus(t, settingsUpdate(f, settingsCatalog(t, f).Revision, change("Viewer", "example.read", true)), 400)
		requireStatus(t, settingsUpdate(f, settingsCatalog(t, f).Revision, change("Viewer", "orphan.read", true)), 400)
		f.assertUnchanged(t, before)
		requireStatus(t, settingsUpdate(f, settingsCatalog(t, f).Revision, change("User", "example.read", false)), 204)
	})
	t.Run("revoked administrator cannot use transaction helper", func(t *testing.T) {
		revision := settingsCatalog(t, f).Revision
		if _, err := f.owner.Exec(context.Background(), `UPDATE framework.users SET active=false WHERE id=$1`, f.users["Admin"].ID); err != nil {
			t.Fatal(err)
		}
		before := f.snapshot(t)
		if err := f.store.SetPermissions(context.Background(), f.users["Admin"].ID, revision, []PermissionChange{change("Viewer", AccountWrite, true)}); err != ErrDenied {
			t.Fatal(err)
		}
		f.assertUnchanged(t, before)
	})
}

func TestPermissionSettingsWriteProtection(t *testing.T) {
	f := settingsFixture(t)
	for _, path := range []string{"/api/admin/permissions", "/api/admin/role-permissions"} {
		method := "POST"
		body := `{"permission":"example.read"}`
		if strings.HasSuffix(path, "role-permissions") {
			method = "PUT"
			encoded, _ := json.Marshal(map[string]any{"revision": settingsCatalog(t, f).Revision, "changes": []PermissionChange{change("Viewer", AccountWrite, true)}})
			body = string(encoded)
		}
		for _, headers := range []map[string]string{{}, {"Origin": origin}, {"Origin": "https://foreign.test", "Content-Type": "application/json"}, {"Origin": origin, "Content-Type": "text/plain"}} {
			before := f.snapshot(t)
			mux := http.NewServeMux()
			Register(mux, fixedAuth{f.identities["Admin"]}, f.store, origin)
			r := httptest.NewRequest(method, path, strings.NewReader(body))
			for key, value := range headers {
				r.Header.Set(key, value)
			}
			response := httptest.NewRecorder()
			mux.ServeHTTP(response, r)
			requireStatus(t, response, 403)
			f.assertUnchanged(t, before)
		}
	}
}

func TestPermissionSettingsAuthorizationAfterLock(t *testing.T) {
	f := settingsFixture(t)
	ctx := context.Background()
	revision := settingsCatalog(t, f).Revision
	tx, err := f.owner.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, mutationLock); err != nil {
		t.Fatal(err)
	}
	result := make(chan *httptest.ResponseRecorder, 1)
	go func() { result <- settingsUpdate(f, revision, change("Viewer", AccountWrite, true)) }()
	// Prove the HTTP check completed and the transaction is waiting on our lock.
	deadline := time.Now().Add(3 * time.Second)
	for {
		var waiting bool
		if err = f.owner.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE usename='go_web_app' AND wait_event='advisory')`).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("mutation did not wait on shared advisory lock")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if _, err = tx.Exec(ctx, `DELETE FROM framework.user_roles WHERE user_id=$1`, f.users["Admin"].ID); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	before := f.snapshot(t)
	select {
	case response := <-result:
		requireStatus(t, response, 403)
	case <-time.After(3 * time.Second):
		t.Fatal("mutation did not complete")
	}
	f.assertUnchanged(t, before)
}
