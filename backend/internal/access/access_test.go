package access

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/bmoheeputh-sudo/go-web-framework/backend/internal/auth"
	"github.com/bmoheeputh-sudo/go-web-framework/backend/internal/testdb"
	"github.com/jackc/pgx/v5/pgxpool"
)

const origin = "https://app.example.invalid"

type fixedAuth struct{ identity auth.Identity }

func (f fixedAuth) Authenticate(*http.Request) (auth.Identity, error) { return f.identity, nil }
func identity(subject string) auth.Identity {
	return auth.Identity{Issuer: "https://issuer.example.invalid", Subject: subject, Email: "same@example.invalid", DisplayName: "User", Provider: auth.OIDC}
}
func call(s *Store, i auth.Identity, method, path, body, requestOrigin string) *httptest.ResponseRecorder {
	mux := http.NewServeMux()
	Register(mux, fixedAuth{i}, s, origin)
	request := httptest.NewRequest(method, path, strings.NewReader(body))
	if requestOrigin != "" {
		request.Header.Set("Origin", requestOrigin)
	}
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	mux.ServeHTTP(response, request)
	return response
}
func requireStatus(t *testing.T, response *httptest.ResponseRecorder, status int) {
	t.Helper()
	if response.Code != status {
		t.Fatalf("status %d want %d: %s", response.Code, status, response.Body.String())
	}
}
func TestRBACIntegration(t *testing.T) {
	pool, connection := testdb.New(t)
	ctx := context.Background()
	owner := New(pool)
	if owner.Check(ctx) == nil {
		t.Fatal("missing schema accepted")
	}
	testdb.Migrations(t, pool, "up")
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
	defer runtime.Close()
	s := New(runtime)
	if err = s.Check(ctx); err != nil {
		t.Fatal(err)
	}
	adminIdentity := identity("admin")
	userIdentity := identity("user")
	viewerIdentity := identity("viewer")
	outsiderIdentity := identity("outsider")
	resolve := func(i auth.Identity) User {
		t.Helper()
		u, err := s.Resolve(ctx, i)
		if err != nil {
			t.Fatal(err)
		}
		return u
	}
	admin := resolve(adminIdentity)
	user := resolve(userIdentity)
	viewer := resolve(viewerIdentity)
	outsider := resolve(outsiderIdentity)
	t.Run("identity is issuer and subject and no default privileges", func(t *testing.T) {
		if admin.ID == user.ID || len(admin.Roles) != 0 || len(admin.Permissions) != 0 || len(admin.AccountIDs) != 0 {
			t.Fatal("unsafe initial identity or role allocation")
		}
		other := userIdentity
		other.Issuer = "https://another.example.invalid"
		if resolve(other).ID == user.ID {
			t.Fatal("issuer ignored")
		}
		changed := userIdentity
		changed.Email = "changed@example.invalid"
		if resolve(changed).ID != user.ID {
			t.Fatal("email used as identity")
		}
		requireStatus(t, call(s, userIdentity, "GET", "/api/access/me", "", ""), 200)
		for _, path := range []string{"/api/admin/users", "/api/admin/roles", "/api/admin/accounts", "/api/admin/audit", "/api/accounts"} {
			requireStatus(t, call(s, userIdentity, "GET", path, "", ""), 403)
		}
		if err := s.Allowed(ctx, user.ID, "", ""); !errors.Is(err, ErrDenied) {
			t.Fatal("empty permission allowed")
		}
		if err := s.Allowed(ctx, user.ID, "unknown", ""); !errors.Is(err, ErrDenied) {
			t.Fatal("unknown permission allowed")
		}
	})
	t.Run("operator bootstrap only previously verified identities and once", func(t *testing.T) {
		if err := owner.Bootstrap(ctx, adminIdentity.Issuer, "never-verified", "PRD"); !errors.Is(err, ErrDenied) {
			t.Fatal("unverified target bootstrapped")
		}
		if err := s.Bootstrap(ctx, adminIdentity.Issuer, adminIdentity.Subject, "PRD"); !errors.Is(err, ErrUnavailable) {
			t.Fatal("runtime role can bootstrap")
		}
		local := auth.Identity{Issuer: auth.LocalDevIssuer, Subject: "dev", Provider: auth.LocalDev}
		resolve(local)
		if err := owner.Bootstrap(ctx, local.Issuer, local.Subject, "PRD"); !errors.Is(err, ErrDenied) {
			t.Fatal("Local DEV bootstrap outside development")
		}
		results := make(chan error, 2)
		var wg sync.WaitGroup
		for range 2 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				results <- owner.Bootstrap(ctx, adminIdentity.Issuer, adminIdentity.Subject, "PRD")
			}()
		}
		wg.Wait()
		close(results)
		successes, conflicts := 0, 0
		for err := range results {
			if err == nil {
				successes++
			} else if errors.Is(err, ErrConflict) {
				conflicts++
			} else {
				t.Fatal(err)
			}
		}
		if successes != 1 || conflicts != 1 {
			t.Fatal("bootstrap race")
		}
		if _, err := pool.Exec(ctx, `DELETE FROM framework.user_roles WHERE user_id=$1`, admin.ID); err != nil {
			t.Fatal(err)
		}
		if err := owner.Bootstrap(ctx, userIdentity.Issuer, userIdentity.Subject, "PRD"); !errors.Is(err, ErrConflict) {
			t.Fatal("one-time latch bypassed after removing Admin")
		}
		if _, err := pool.Exec(ctx, `INSERT INTO framework.user_roles(user_id,role) VALUES($1,'Admin')`, admin.ID); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("role escalation and strict requests", func(t *testing.T) {
		path := "/api/admin/users/" + user.ID + "/roles"
		requireStatus(t, call(s, adminIdentity, "PUT", "/api/admin/users/"+strings.ToUpper(admin.ID)+"/roles", `{"roles":[]}`, origin), 403)
		requireStatus(t, call(s, userIdentity, "PUT", path, `{"roles":["Admin"]}`, origin), 403)
		requireStatus(t, call(s, adminIdentity, "PUT", "/api/admin/users/"+admin.ID+"/roles", `{"roles":[]}`, origin), 403)
		requireStatus(t, call(s, adminIdentity, "PUT", path, `{"roles":["SuperAdmin"]}`, origin), 400)
		requireStatus(t, call(s, adminIdentity, "PUT", path, `{"roles":["User"],"active":true}`, origin), 400)
		requireStatus(t, call(s, adminIdentity, "PUT", path, `{"roles":null}`, origin), 400)
		requireStatus(t, call(s, adminIdentity, "PUT", path, `{}`, origin), 400)
		requireStatus(t, call(s, adminIdentity, "PUT", path, `{"roles":["User"]} {}`, origin), 400)
		requireStatus(t, call(s, adminIdentity, "PUT", path, strings.Repeat("x", 17000), origin), 400)
		for _, o := range []string{"", "null", "https://attacker.example.invalid"} {
			requireStatus(t, call(s, adminIdentity, "PUT", path, `{"roles":["User"]}`, o), 403)
		}
		requireStatus(t, call(s, adminIdentity, "PUT", path, `{"roles":["User"]}`, origin), 204)
		requireStatus(t, call(s, adminIdentity, "PUT", "/api/admin/users/"+viewer.ID+"/roles", `{"roles":["Viewer"]}`, origin), 204)
		requireStatus(t, call(s, adminIdentity, "GET", "/api/admin/users?offset=-1", "", ""), 400)
		requireStatus(t, call(s, adminIdentity, "GET", "/api/admin/users?offset=100", "", ""), 200)
		for _, path := range []string{"/api/admin/users", "/api/admin/roles", "/api/admin/audit"} {
			requireStatus(t, call(s, adminIdentity, "GET", path, "", ""), 200)
		}
	})
	t.Run("account management HTTP validation and updates", func(t *testing.T) {
		requireStatus(t, call(s, userIdentity, "POST", "/api/admin/accounts", `{"name":"Forbidden"}`, origin), 403)
		response := call(s, adminIdentity, "POST", "/api/admin/accounts", `{"name":"Created via API"}`, origin)
		requireStatus(t, response, 201)
		var created Account
		if err := json.Unmarshal(response.Body.Bytes(), &created); err != nil || !validID(created.ID) || !created.Active {
			t.Fatal("invalid account creation response")
		}
		requireStatus(t, call(s, adminIdentity, "PUT", "/api/admin/accounts/"+created.ID, `{"name":"Archived","active":false}`, origin), 200)
		requireStatus(t, call(s, adminIdentity, "GET", "/api/admin/accounts", "", ""), 200)
		requireStatus(t, call(s, adminIdentity, "PUT", "/api/admin/accounts/"+created.ID, `{"name":"Missing active flag"}`, origin), 400)
		requireStatus(t, call(s, adminIdentity, "PUT", "/api/admin/accounts/not-a-uuid", `{"name":"Invalid","active":true}`, origin), 400)
		requireStatus(t, call(s, adminIdentity, "POST", "/api/admin/accounts", `{"name":""}`, origin), 400)
		requireStatus(t, call(s, adminIdentity, "PUT", "/api/admin/users/"+user.ID, `{}`, origin), 400)
		requireStatus(t, call(s, adminIdentity, "PUT", "/api/admin/users/"+user.ID+"/accounts", `{}`, origin), 400)
		if err := s.SetRoles(ctx, admin.ID, viewer.ID, []string{"Viewer", "Viewer"}); !errors.Is(err, ErrInvalid) {
			t.Fatal("duplicate role assignment accepted")
		}
	})
	a, err := s.SaveAccount(ctx, admin.ID, "", "Account A", true)
	if err != nil {
		t.Fatal(err)
	}
	b, err := s.SaveAccount(ctx, admin.ID, "", "Account B", true)
	if err != nil {
		t.Fatal(err)
	}
	c, err := s.SaveAccount(ctx, admin.ID, "", "Unlinked", true)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.SetAccounts(ctx, admin.ID, user.ID, []string{a.ID, b.ID}); err != nil {
		t.Fatal(err)
	}
	if err = s.SetAccounts(ctx, admin.ID, viewer.ID, []string{a.ID}); err != nil {
		t.Fatal(err)
	}
	t.Run("account isolation and role matrix", func(t *testing.T) {
		response := call(s, userIdentity, "GET", "/api/accounts", "", "")
		requireStatus(t, response, 200)
		var accounts []Account
		if err := json.Unmarshal(response.Body.Bytes(), &accounts); err != nil || len(accounts) != 2 {
			t.Fatal("multiple account links missing")
		}
		requireStatus(t, call(s, userIdentity, "GET", "/api/accounts/"+a.ID, "", ""), 200)
		requireStatus(t, call(s, userIdentity, "PATCH", "/api/accounts/"+b.ID, `{"name":"Renamed"}`, origin), 204)
		requireStatus(t, call(s, viewerIdentity, "GET", "/api/accounts/"+a.ID, "", ""), 200)
		requireStatus(t, call(s, viewerIdentity, "PATCH", "/api/accounts/"+a.ID, `{"name":"Forbidden"}`, origin), 403)
		requireStatus(t, call(s, userIdentity, "GET", "/api/accounts/"+c.ID, "", ""), 403)
		requireStatus(t, call(s, userIdentity, "PATCH", "/api/accounts/"+c.ID, `{"name":"Forbidden"}`, origin), 403)
		requireStatus(t, call(s, userIdentity, "GET", "/api/accounts/invalid", "", ""), 403)
		requireStatus(t, call(s, adminIdentity, "GET", "/api/accounts/"+a.ID, "", ""), 403)
		requireStatus(t, call(s, outsiderIdentity, "PUT", "/api/admin/users/"+outsider.ID+"/accounts", `{"account_ids":["`+a.ID+`"]}`, origin), 403)
		// Direct service writes repeat authorization even if a handler check was bypassed.
		if err := s.RenameAccount(ctx, user.ID, c.ID, "Forbidden"); !errors.Is(err, ErrDenied) {
			t.Fatal("write trusted handler-only check")
		}
		if _, err := s.SaveAccount(ctx, user.ID, "", "Forbidden", true); !errors.Is(err, ErrDenied) {
			t.Fatal("non-admin created account")
		}
	})
	t.Run("atomic associations audit and revocation", func(t *testing.T) {
		before, _ := s.Audit(ctx, 0)
		err := s.SetAccounts(ctx, admin.ID, user.ID, []string{a.ID, "00000000-0000-0000-0000-000000000001"})
		if !errors.Is(err, ErrInvalid) {
			t.Fatal("nonexistent account accepted")
		}
		after, _ := s.Audit(ctx, 0)
		if len(before) != len(after) {
			t.Fatal("failed change committed audit")
		}
		if err := s.Allowed(ctx, user.ID, AccountRead, b.ID); err != nil {
			t.Fatal("failed association replacement changed existing links")
		}
		requireStatus(t, call(s, adminIdentity, "PUT", "/api/admin/users/"+user.ID+"/accounts", `{"account_ids":["`+a.ID+`"]}`, origin), 204)
		requireStatus(t, call(s, userIdentity, "GET", "/api/accounts/"+b.ID, "", ""), 403)
		if _, err := s.SaveAccount(ctx, admin.ID, a.ID, "Account A", false); err != nil {
			t.Fatal(err)
		}
		requireStatus(t, call(s, userIdentity, "GET", "/api/accounts/"+a.ID, "", ""), 403)
		if _, err := s.SaveAccount(ctx, admin.ID, a.ID, "Account A", true); err != nil {
			t.Fatal(err)
		}
		requireStatus(t, call(s, adminIdentity, "PUT", "/api/admin/users/"+user.ID, `{"active":false}`, origin), 204)
		requireStatus(t, call(s, userIdentity, "GET", "/api/access/me", "", ""), 403)
		if err := s.RenameAccount(ctx, user.ID, a.ID, "Forbidden"); !errors.Is(err, ErrDenied) {
			t.Fatal("disabled user retained write permissions")
		}
		requireStatus(t, call(s, adminIdentity, "PUT", "/api/admin/users/"+user.ID, `{"active":true}`, origin), 204)
		if err := s.SetRoles(ctx, admin.ID, user.ID, []string{}); err != nil {
			t.Fatal(err)
		}
		if err := s.RenameAccount(ctx, user.ID, a.ID, "Forbidden"); !errors.Is(err, ErrDenied) {
			t.Fatal("revoked role retained permissions")
		}
		records, err := s.Audit(ctx, 0)
		if err != nil || len(records) < 8 {
			t.Fatal("missing audit records")
		}
		for _, record := range records {
			if record.ActorID == "" || record.TargetID == "" || record.Action == "" || !json.Valid(record.Details) {
				t.Fatal("incomplete audit event")
			}
		}
		if _, err = runtime.Exec(ctx, `DELETE FROM framework.audit_log`); err == nil {
			t.Fatal("runtime can erase audit")
		}
		if _, err = runtime.Exec(ctx, `INSERT INTO framework.role_permissions(role,permission) VALUES('Viewer','admin.manage')`); err == nil {
			t.Fatal("runtime can alter permission catalog")
		}
	})
	t.Run("audit failure rolls back administrative mutation", func(t *testing.T) {
		if _, err := pool.Exec(ctx, `REVOKE INSERT ON framework.audit_log FROM go_web_app`); err != nil {
			t.Fatal(err)
		}
		err := s.SetRoles(ctx, admin.ID, viewer.ID, []string{"Admin"})
		if !errors.Is(err, ErrUnavailable) {
			t.Fatal("unaudited write succeeded")
		}
		if _, err := pool.Exec(ctx, `GRANT INSERT ON framework.audit_log TO go_web_app`); err != nil {
			t.Fatal(err)
		}
		if err := s.Allowed(ctx, viewer.ID, AdminManage, ""); !errors.Is(err, ErrDenied) {
			t.Fatal("unaudited role was committed")
		}
	})
	t.Run("concurrent demotions cannot eliminate all administrators", func(t *testing.T) {
		if err := s.SetRoles(ctx, admin.ID, user.ID, []string{"Admin"}); err != nil {
			t.Fatal(err)
		}
		results := make(chan error, 2)
		var wg sync.WaitGroup
		for _, pair := range [][2]string{{admin.ID, user.ID}, {user.ID, admin.ID}} {
			wg.Add(1)
			go func(actor, target string) { defer wg.Done(); results <- s.SetRoles(ctx, actor, target, []string{}) }(pair[0], pair[1])
		}
		wg.Wait()
		close(results)
		success := 0
		for err := range results {
			if err == nil {
				success++
			} else if !errors.Is(err, ErrDenied) {
				t.Fatal(err)
			}
		}
		if success != 1 {
			t.Fatal("concurrent revocation not serialized")
		}
		var count int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM framework.user_roles WHERE role='Admin'`).Scan(&count); err != nil || count != 1 {
			t.Fatal("last Admin removed")
		}
	})
	runtime.Close()
	requireStatus(t, call(s, adminIdentity, "GET", "/api/access/me", "", ""), 503)
}

func TestOriginAndMiddlewareFailClosed(t *testing.T) {
	for _, test := range []struct {
		value, env string
		valid      bool
	}{
		{origin, "PRD", true}, {"http://127.0.0.1:5173", "development", true}, {"http://[::1]:5173", "development", true},
		{"", "development", false}, {"http://localhost:5173", "TEST", false}, {"http://remote.invalid", "development", false},
		{origin + "/path", "PRD", false}, {"https://user:password@app.invalid", "PRD", false}, {origin + "?q=1", "PRD", false},
	} {
		if (ValidateOrigin(test.value, test.env) == nil) != test.valid {
			t.Errorf("origin validation %q", test.value)
		}
	}
	requireStatus(t, call(nil, identity("user"), "GET", "/api/access/me", "", ""), 503)
	handler := New(nil).Require("", "", http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("unauthenticated middleware reached handler") }))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest("GET", "/protected", nil))
	requireStatus(t, response, 403)
	mux := http.NewServeMux()
	Register(mux, nil, nil, origin)
	response = httptest.NewRecorder()
	mux.ServeHTTP(response, httptest.NewRequest("GET", "/api/admin/users", nil))
	requireStatus(t, response, 401)
	for _, body := range []string{`{"roles":[]}`, `{}`} {
		h := protectWrites(origin, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("unsafe request reached handler") }))
		r := httptest.NewRequest("PUT", "/", strings.NewReader(body))
		r.Header.Set("Origin", origin)
		r.Header.Set("Content-Type", "text/plain")
		response := httptest.NewRecorder()
		h.ServeHTTP(response, r)
		requireStatus(t, response, 403)
	}
}

func TestLocalDevBootstrap(t *testing.T) {
	pool, _ := testdb.New(t)
	testdb.Migrations(t, pool, "up")
	s := New(pool)
	ctx := context.Background()
	provider, err := auth.NewLocalDev("development", auth.LocalDevConfig{Subject: "dev", Email: "dev@example.invalid", DisplayName: "Local Developer"})
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("GET", "/api/access/me", nil)
	r.RemoteAddr = "127.0.0.1:1234"
	verified, err := provider.Authenticate(r)
	if err != nil {
		t.Fatal(err)
	}
	user, err := s.Resolve(ctx, verified)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.Bootstrap(ctx, verified.Issuer, verified.Subject, "development"); err != nil {
		t.Fatal(err)
	}
	if err = s.Allowed(ctx, user.ID, AdminManage, ""); err != nil {
		t.Fatal(err)
	}
}
