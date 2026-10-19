package access

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bmoheeputh-sudo/go-web-framework/backend/internal/auth"
	"github.com/bmoheeputh-sudo/go-web-framework/backend/internal/testdb"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Every fixture has its own disposable cluster. Only the application pool serves
// HTTP requests; the owner pool is used for fixture setup and independent checks.
type securityFixture struct {
	store      *Store
	owner      *pgxpool.Pool
	identities map[string]auth.Identity
	users      map[string]User
	accounts   map[string]Account
}

func newSecurityFixture(t *testing.T) *securityFixture {
	t.Helper()
	owner, connection := testdb.New(t)
	testdb.Migrations(t, owner, "up")
	config, err := pgxpool.ParseConfig(connection)
	if err != nil {
		t.Fatal(err)
	}
	config.ConnConfig.User = "go_web_app"
	config.ConnConfig.RuntimeParams["search_path"] = "pg_catalog"
	runtime, err := pgxpool.NewWithConfig(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(runtime.Close)
	f := &securityFixture{store: New(runtime), owner: owner, identities: map[string]auth.Identity{}, users: map[string]User{}, accounts: map[string]Account{}}
	for _, role := range []string{"Admin", "User", "Viewer", "None"} {
		f.identities[role] = identity("security-" + role)
		response := f.request(role, "GET", "/api/access/me", nil)
		requireStatus(t, response, 200)
		var u User
		if err := json.Unmarshal(response.Body.Bytes(), &u); err != nil {
			t.Fatal(err)
		}
		if len(u.Roles) != 0 || len(u.Permissions) != 0 {
			t.Fatal("fixture user gained automatic privileges")
		}
		f.users[role] = u
	}
	admin := f.identities["Admin"]
	if err := New(owner).Bootstrap(context.Background(), admin.Issuer, admin.Subject, "PRD"); err != nil {
		t.Fatal(err)
	}
	for _, role := range []string{"User", "Viewer"} {
		requireStatus(t, f.request("Admin", "PUT", "/api/admin/users/"+f.users[role].ID+"/roles", map[string]any{"roles": []string{role}}), 204)
	}
	for _, name := range []string{"linked-a", "linked-b", "inactive", "unlinked"} {
		response := f.request("Admin", "POST", "/api/admin/accounts", map[string]any{"name": name, "active": name != "inactive"})
		requireStatus(t, response, 201)
		var account Account
		if err := json.Unmarshal(response.Body.Bytes(), &account); err != nil {
			t.Fatal(err)
		}
		f.accounts[name] = account
	}
	// Even the role-free user has links: membership alone must never grant access.
	for _, role := range []string{"Admin", "User", "Viewer", "None"} {
		requireStatus(t, f.request("Admin", "PUT", "/api/admin/users/"+f.users[role].ID+"/accounts", map[string]any{"account_ids": f.links()}), 204)
	}
	return f
}
func (f *securityFixture) links() []string {
	return []string{f.accounts["linked-a"].ID, f.accounts["linked-b"].ID, f.accounts["inactive"].ID}
}
func (f *securityFixture) request(role, method, path string, body any) *httptest.ResponseRecorder {
	data, _ := json.Marshal(body) // All bodies below are JSON-compatible test literals.
	return call(f.store, f.identities[role], method, path, string(data), origin)
}
func (f *securityFixture) snapshot(t *testing.T) map[string]string {
	t.Helper()
	result := map[string]string{}
	for _, table := range []string{"users", "roles", "permissions", "role_permissions", "user_roles", "accounts", "user_accounts", "audit_log", "admin_bootstrap", "sessions", "oidc_login_flows"} {
		var rows string
		// Table names are fixed test constants. Include complete rows, even verified_at.
		if err := f.owner.QueryRow(context.Background(), `SELECT COALESCE(jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text),'[]'::jsonb)::text FROM framework.`+table+` t`).Scan(&rows); err != nil {
			t.Fatal(err)
		}
		result[table] = rows
	}
	return result
}
func (f *securityFixture) assertUnchanged(t *testing.T, before map[string]string) {
	t.Helper()
	after := f.snapshot(t)
	for table, rows := range before {
		if after[table] != rows {
			t.Errorf("denied request changed framework.%s records", table)
		}
	}
}
func (f *securityFixture) denied(t *testing.T, role, method, path string, body any) {
	t.Helper()
	before := f.snapshot(t)
	requireStatus(t, f.request(role, method, path, body), http.StatusForbidden)
	f.assertUnchanged(t, before)
}
func (f *securityFixture) auditCount(t *testing.T) int {
	t.Helper()
	var n int
	if err := f.owner.QueryRow(context.Background(), `SELECT count(*) FROM framework.audit_log`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}
func (f *securityFixture) assertAudit(t *testing.T, before int, actor, action, target string, details any) {
	t.Helper()
	if f.auditCount(t) != before+1 {
		t.Fatal("successful change must commit exactly one audit event")
	}
	var got Audit
	err := f.owner.QueryRow(context.Background(), `SELECT id::text,created_at,actor_user_id::text,action,target_id,details FROM framework.audit_log ORDER BY framework.audit_log.id DESC LIMIT 1`).Scan(&got.ID, &got.CreatedAt, &got.ActorID, &got.Action, &got.TargetID, &got.Details)
	if err != nil {
		t.Fatal(err)
	}
	if got.ActorID != actor || got.Action != action || got.TargetID != target || got.CreatedAt.IsZero() || got.CreatedAt.After(time.Now().Add(time.Second)) {
		t.Fatalf("incorrect audit attribution: %+v", got)
	}
	var actual, want any
	if err := json.Unmarshal(got.Details, &actual); err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(details)
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(data, &want); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(actual, want) {
		t.Fatalf("audit details = %s, want %s", got.Details, data)
	}
}
func (f *securityFixture) activeAdmins(t *testing.T) int {
	t.Helper()
	var n int
	if err := f.owner.QueryRow(context.Background(), `SELECT count(*) FROM framework.users u JOIN framework.user_roles r ON r.user_id=u.id WHERE u.active AND r.role='Admin'`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestRBACDeniedRequestsAreReadOnly(t *testing.T) {
	f := newSecurityFixture(t)
	t.Run("existing user profile and all other records", func(t *testing.T) {
		// A verified identity can legitimately have a new profile, but a denied
		// administrative request must not refresh that profile or its timestamp.
		changed := f.identities["Viewer"]
		changed.Email = "new@example.invalid"
		changed.DisplayName = "Changed profile"
		before := f.snapshot(t)
		requireStatus(t, call(f.store, changed, "PUT", "/api/admin/users/"+f.users["Viewer"].ID+"/roles", `{"roles":["Admin"]}`, origin), 403)
		f.assertUnchanged(t, before)
	})
	t.Run("unregistered identity cannot create records through a denied route", func(t *testing.T) {
		before := f.snapshot(t)
		requireStatus(t, call(f.store, identity("not-registered"), "GET", "/api/admin/users", "", origin), 403)
		f.assertUnchanged(t, before)
	})
	t.Run("inactive user cannot refresh profile through self endpoint", func(t *testing.T) {
		requireStatus(t, f.request("Admin", "PUT", "/api/admin/users/"+f.users["User"].ID, map[string]any{"active": false}), 204)
		f.denied(t, "User", "GET", "/api/access/me", nil)
	})
}

func TestRBACHTTPRoleAndAccountMatrix(t *testing.T) {
	f := newSecurityFixture(t)
	for _, role := range []string{"Admin", "User", "Viewer", "None"} {
		t.Run(role, func(t *testing.T) {
			if role == "None" {
				f.denied(t, role, "GET", "/api/accounts", nil)
			} else {
				response := f.request(role, "GET", "/api/accounts", nil)
				requireStatus(t, response, 200)
				var accounts []Account
				if err := json.Unmarshal(response.Body.Bytes(), &accounts); err != nil {
					t.Fatal(err)
				}
				got := []string{}
				for _, a := range accounts {
					got = append(got, a.ID)
					if !a.Active {
						t.Fatal("inactive account leaked in list")
					}
				}
				want := []string{f.accounts["linked-a"].ID, f.accounts["linked-b"].ID}
				sort.Strings(got)
				sort.Strings(want)
				if !reflect.DeepEqual(got, want) {
					t.Fatalf("account listing = %v, want %v", got, want)
				}
			}
			for _, account := range []string{"linked-a", "linked-b", "inactive", "unlinked"} {
				path := "/api/accounts/" + f.accounts[account].ID
				for _, method := range []string{"GET", "PATCH"} {
					t.Run(method+"/"+account, func(t *testing.T) {
						body := map[string]any{"name": "Updated by " + role}
						linked := account == "linked-a" || account == "linked-b"
						permitted := linked && role != "None" && (method == "GET" || role == "Admin" || role == "User")
						if !permitted {
							f.denied(t, role, method, path, body)
							return
						}
						if method == "GET" {
							requireStatus(t, f.request(role, method, path, nil), 200)
							return
						}
						before, err := f.store.Account(context.Background(), f.accounts[account].ID)
						if err != nil {
							t.Fatal(err)
						}
						count := f.auditCount(t)
						requireStatus(t, f.request(role, method, path, body), 204)
						after, err := f.store.Account(context.Background(), before.ID)
						if err != nil || after.Name != body["name"] {
							t.Fatal("authorized account update not persisted")
						}
						f.assertAudit(t, count, f.users[role].ID, "account.rename", before.ID, map[string]any{"before": before.Name, "after": body["name"]})
					})
				}
			}
		})
	}
}

func TestRBACNonAdminModificationsAndSelfEscalation(t *testing.T) {
	f := newSecurityFixture(t)
	for _, role := range []string{"User", "Viewer", "None"} {
		t.Run(role, func(t *testing.T) {
			for _, target := range []string{f.users[role].ID, f.users["Admin"].ID} {
				f.denied(t, role, "PUT", "/api/admin/users/"+target+"/roles", map[string]any{"roles": []string{"Admin"}})
				f.denied(t, role, "PUT", "/api/admin/users/"+target, map[string]any{"active": false})
				f.denied(t, role, "PUT", "/api/admin/users/"+target+"/accounts", map[string]any{"account_ids": []string{f.accounts["unlinked"].ID}})
			}
			f.denied(t, role, "POST", "/api/admin/accounts", map[string]any{"name": "Unauthorized account"})
			f.denied(t, role, "PUT", "/api/admin/accounts/"+f.accounts["linked-a"].ID, map[string]any{"name": "Unauthorized overwrite", "active": false})
			for _, path := range []string{"users", "roles", "accounts", "audit"} {
				f.denied(t, role, "GET", "/api/admin/"+path, nil)
			}
		})
	}
}

func TestRBACAdminChangesPersistAndAreAudited(t *testing.T) {
	f := newSecurityFixture(t)
	actor := f.users["Admin"].ID
	target := f.users["None"].ID
	for _, path := range []string{"users", "roles", "accounts", "audit"} {
		requireStatus(t, f.request("Admin", "GET", "/api/admin/"+path, nil), 200)
	}
	for _, roles := range [][]string{{"Admin"}, {"Viewer"}, {}} {
		before, err := scanUser(f.owner.QueryRow(context.Background(), userSelect+`WHERE u.id=$1`, target))
		if err != nil {
			t.Fatal(err)
		}
		count := f.auditCount(t)
		requireStatus(t, f.request("Admin", "PUT", "/api/admin/users/"+target+"/roles", map[string]any{"roles": roles}), 204)
		after, err := scanUser(f.owner.QueryRow(context.Background(), userSelect+`WHERE u.id=$1`, target))
		if err != nil || !reflect.DeepEqual(after.Roles, roles) {
			t.Fatal("role assignment did not persist")
		}
		f.assertAudit(t, count, actor, "user.roles", target, map[string]any{"before": before.Roles, "after": roles})
	}
	for _, active := range []bool{false, true} {
		count := f.auditCount(t)
		requireStatus(t, f.request("Admin", "PUT", "/api/admin/users/"+target, map[string]any{"active": active}), 204)
		var actual bool
		if err := f.owner.QueryRow(context.Background(), `SELECT active FROM framework.users WHERE id=$1`, target).Scan(&actual); err != nil || actual != active {
			t.Fatal("active status did not persist")
		}
		f.assertAudit(t, count, actor, "user.active", target, map[string]bool{"before": !active, "after": active})
	}
	for _, links := range [][]string{{f.accounts["linked-a"].ID, f.accounts["unlinked"].ID}, {}} {
		before, err := scanUser(f.owner.QueryRow(context.Background(), userSelect+`WHERE u.id=$1`, target))
		if err != nil {
			t.Fatal(err)
		}
		count := f.auditCount(t)
		requireStatus(t, f.request("Admin", "PUT", "/api/admin/users/"+target+"/accounts", map[string]any{"account_ids": links}), 204)
		after, err := scanUser(f.owner.QueryRow(context.Background(), userSelect+`WHERE u.id=$1`, target))
		if err != nil {
			t.Fatal(err)
		}
		want := append([]string{}, links...)
		sort.Strings(want)
		if !reflect.DeepEqual(after.AccountIDs, want) {
			t.Fatal("account links did not persist")
		}
		f.assertAudit(t, count, actor, "user.accounts", target, map[string]any{"before": before.AccountIDs, "after": links})
	}
	count := f.auditCount(t)
	response := f.request("Admin", "POST", "/api/admin/accounts", map[string]any{"name": "New account"})
	requireStatus(t, response, 201)
	var a Account
	if err := json.Unmarshal(response.Body.Bytes(), &a); err != nil {
		t.Fatal(err)
	}
	f.assertAudit(t, count, actor, "account.save", a.ID, map[string]any{"before": nil, "after": a})
	count = f.auditCount(t)
	updated := Account{ID: a.ID, Name: "Archived account", Active: false}
	requireStatus(t, f.request("Admin", "PUT", "/api/admin/accounts/"+a.ID, map[string]any{"name": updated.Name, "active": false}), 200)
	got, err := f.store.Account(context.Background(), a.ID)
	if err != nil || got != updated {
		t.Fatal("account change not persisted")
	}
	f.assertAudit(t, count, actor, "account.save", a.ID, map[string]any{"before": a, "after": updated})
	// Numeric audit IDs are serialized as strings. ORDER BY must still be numeric:
	// once IDs reach 10, lexicographic ordering would incorrectly put 9 first.
	for _, offset := range []int{0, 1} {
		response := f.request("Admin", "GET", "/api/admin/audit?offset="+strconv.Itoa(offset), nil)
		requireStatus(t, response, 200)
		var events []Audit
		if err := json.Unmarshal(response.Body.Bytes(), &events); err != nil {
			t.Fatal(err)
		}
		var newest int64
		if err := f.owner.QueryRow(context.Background(), `SELECT id FROM framework.audit_log ORDER BY id DESC LIMIT 1 OFFSET $1`, offset).Scan(&newest); err != nil {
			t.Fatal(err)
		}
		if len(events) == 0 || events[0].ID != strconv.FormatInt(newest, 10) {
			t.Fatal("audit API did not return the newest event at the requested offset")
		}
		for i := 1; i < len(events); i++ {
			previous, err1 := strconv.ParseInt(events[i-1].ID, 10, 64)
			current, err2 := strconv.ParseInt(events[i].ID, 10, 64)
			if err1 != nil || err2 != nil || previous <= current {
				t.Fatal("audit API must sort IDs numerically in descending order")
			}
		}
	}
}

func TestRBACLastActiveAdminProtection(t *testing.T) {
	f := newSecurityFixture(t)
	// A dormant Admin assignment must not be counted as an active administrator.
	requireStatus(t, f.request("Admin", "PUT", "/api/admin/users/"+f.users["None"].ID+"/roles", map[string]any{"roles": []string{"Admin"}}), 204)
	requireStatus(t, f.request("Admin", "PUT", "/api/admin/users/"+f.users["None"].ID, map[string]any{"active": false}), 204)
	if f.activeAdmins(t) != 1 {
		t.Fatal("fixture must have exactly one active administrator")
	}
	for _, target := range []string{f.users["Admin"].ID, strings.ToUpper(f.users["Admin"].ID)} {
		for _, roles := range [][]string{{}, {"Viewer"}} {
			f.denied(t, "Admin", "PUT", "/api/admin/users/"+target+"/roles", map[string]any{"roles": roles})
		}
		f.denied(t, "Admin", "PUT", "/api/admin/users/"+target, map[string]any{"active": false})
	}
	f.denied(t, "None", "PUT", "/api/admin/users/"+f.users["Admin"].ID, map[string]any{"active": false})
	if f.activeAdmins(t) != 1 {
		t.Fatal("last active administrator changed")
	}
}

func TestRBACConcurrentAdminRemovalHTTP(t *testing.T) {
	for _, change := range []string{"demote", "deactivate", "mixed"} {
		t.Run(change, func(t *testing.T) {
			f := newSecurityFixture(t)
			requireStatus(t, f.request("Admin", "PUT", "/api/admin/users/"+f.users["User"].ID+"/roles", map[string]any{"roles": []string{"Admin"}}), 204)
			count := f.auditCount(t)
			start := make(chan struct{})
			results := make(chan int, 2)
			var wg sync.WaitGroup
			for i, pair := range [][2]string{{"Admin", "User"}, {"User", "Admin"}} {
				wg.Add(1)
				go func() {
					defer wg.Done()
					<-start
					path := "/api/admin/users/" + f.users[pair[1]].ID
					body := map[string]any{"active": false}
					if change == "demote" || (change == "mixed" && i == 0) {
						path += "/roles"
						body = map[string]any{"roles": []string{"Viewer"}}
					}
					results <- f.request(pair[0], "PUT", path, body).Code
				}()
			}
			close(start)
			wg.Wait()
			close(results)
			statuses := []int{}
			for status := range results {
				statuses = append(statuses, status)
			}
			sort.Ints(statuses)
			if !reflect.DeepEqual(statuses, []int{204, 403}) || f.activeAdmins(t) != 1 || f.auditCount(t) != count+1 {
				t.Fatalf("concurrent administrator removal was not serialized: %v", statuses)
			}
		})
	}
}

func TestRBACUserPermissionsAreNotHardcoded(t *testing.T) {
	f := newSecurityFixture(t)
	// Change the permission catalog only in this disposable fixture to verify that
	// authorization follows configured permissions rather than role-name shortcuts.
	if _, err := f.owner.Exec(context.Background(), `DELETE FROM framework.role_permissions WHERE role='User' AND permission='accounts.write'`); err != nil {
		t.Fatal(err)
	}
	requireStatus(t, f.request("User", "GET", "/api/accounts/"+f.accounts["linked-a"].ID, nil), 200)
	f.denied(t, "User", "PATCH", "/api/accounts/"+f.accounts["linked-a"].ID, map[string]any{"name": "No longer allowed"})
}
