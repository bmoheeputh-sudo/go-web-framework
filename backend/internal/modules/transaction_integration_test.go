package modules

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/bmoheeputh-sudo/go-web-framework/backend/internal/access"
	"github.com/bmoheeputh-sudo/go-web-framework/backend/internal/auth"
	"github.com/bmoheeputh-sudo/go-web-framework/backend/internal/testdb"
	"github.com/bmoheeputh-sudo/go-web-framework/backend/module"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type connectionScanner struct{ called bool }

func (s *connectionScanner) ScanRow(pgx.Rows) error { s.called = true; return nil }

func TestModuleTransactions(t *testing.T) {
	owner, connection := testdb.New(t)
	testdb.Migrations(t, owner, "up")
	ctx := context.Background()
	cfg, err := pgxpool.ParseConfig(connection)
	if err != nil {
		t.Fatal(err)
	}
	cfg.ConnConfig.User = "go_web_app"
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	store := access.New(pool)
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := owner.Exec(ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	user, err := store.Resolve(ctx, verified("user"))
	if err != nil {
		t.Fatal(err)
	}
	admin, err := store.Resolve(ctx, verified("admin"))
	if err != nil {
		t.Fatal(err)
	}
	exec(`INSERT INTO framework.user_roles(user_id,role) VALUES($1,'User'),($2,'Admin')`, user.ID, admin.ID)
	exec(`INSERT INTO framework.permissions(name,description) VALUES('example.items.write','test'),('example.settings.write','test')`)
	exec(`INSERT INTO framework.role_permissions(role,permission) VALUES('User','example.items.write'),('User','example.settings.write')`)
	var account, other, item, otherItem, setting string
	for _, dest := range []*string{&account, &other} {
		if err := owner.QueryRow(ctx, `INSERT INTO framework.accounts(name) VALUES('test') RETURNING id::text`).Scan(dest); err != nil {
			t.Fatal(err)
		}
	}
	exec(`INSERT INTO framework.user_accounts(user_id,account_id) VALUES($1,$2)`, user.ID, account)
	exec(`CREATE SCHEMA module_test; CREATE TABLE module_test.items(id uuid PRIMARY KEY DEFAULT gen_random_uuid(),account_id uuid NOT NULL,value integer NOT NULL DEFAULT 0); CREATE TABLE module_test.settings(id uuid PRIMARY KEY DEFAULT gen_random_uuid(),value integer NOT NULL DEFAULT 0); GRANT USAGE ON SCHEMA module_test TO go_web_app; GRANT SELECT,INSERT,UPDATE,DELETE ON module_test.items,module_test.settings TO go_web_app`)
	for i, dest := range []*string{&item, &otherItem} {
		id := account
		if i == 1 {
			id = other
		}
		if err := owner.QueryRow(ctx, `INSERT INTO module_test.items(account_id) VALUES($1) RETURNING id::text`, id).Scan(dest); err != nil {
			t.Fatal(err)
		}
	}
	if err := owner.QueryRow(ctx, `INSERT INTO module_test.settings DEFAULT VALUES RETURNING id::text`).Scan(&setting); err != nil {
		t.Fatal(err)
	}
	policy := module.AuditPolicy{Action: "example.item.updated", Fields: map[string]module.AuditField{"changed": {Kind: module.AuditBool}, "count": {Kind: module.AuditInteger}}}
	largePolicy := module.AuditPolicy{Action: "example.item.updated", Fields: map[string]module.AuditField{}}
	largeDetails := module.AuditDetails{}
	for i := 0; i < 16; i++ {
		name := fmt.Sprintf("field_%d", i)
		value := strings.Repeat("x", 512)
		largePolicy.Fields[name] = module.AuditField{Kind: module.AuditEnum, Values: []string{value}}
		largeDetails[name] = value
	}
	var before func(*http.Request)
	var callback module.AccountMutateFunc
	var invoke func(*http.Request, module.TransactionManager) error
	var result error
	calls := 0
	defaultCallback := func(ctx context.Context, tx module.Transaction, scope string) (string, module.AuditDetails, error) {
		calls++
		if scope == "" {
			_, err := tx.Exec(ctx, `UPDATE module_test.settings SET value=value+1 WHERE id=$1`, setting)
			return setting, module.AuditDetails{"changed": true, "count": 1}, err
		}
		// The predicate is mandatory even though the route has checked membership.
		tag, err := tx.Exec(ctx, `UPDATE module_test.items SET value=value+1 WHERE id=$1 AND account_id=$2`, item, scope)
		if err == nil && tag.RowsAffected() != 1 {
			err = errors.New("target not in authorized account")
		}
		return item, module.AuditDetails{"changed": true, "count": 1}, err
	}
	handler := func(w http.ResponseWriter, r *http.Request, manager module.TransactionManager) {
		if before != nil {
			before(r)
		}
		if invoke != nil {
			result = invoke(r, manager)
		} else if r.PathValue("account") != "" {
			result = manager.MutateAccount(r.Context(), callback)
		} else {
			result = manager.MutateGlobal(r.Context(), func(ctx context.Context, tx module.Transaction) (string, module.AuditDetails, error) {
				return callback(ctx, tx, "")
			})
		}
		if result != nil {
			w.WriteHeader(409)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": result.Error()})
			return
		}
		w.WriteHeader(204)
	}
	app := testModule{manifest: module.Manifest{ID: "example", Permissions: []module.Permission{"example.items.write", "example.settings.write"}}, register: func(r module.Registrar) error {
		if err := r.AccountMutation("POST", "/items", "example.items.write", policy, handler); err != nil {
			return err
		}
		if err := r.AccountMutation("POST", "/oversized", "example.items.write", largePolicy, handler); err != nil {
			return err
		}
		p := policy
		p.Action = "example.settings.updated"
		return r.GlobalMutation("POST", "/settings", "example.settings.write", p, handler)
	}}
	registry, err := New([]module.Module{app}, "example")
	if err != nil {
		t.Fatal(err)
	}
	// Mutating the module-owned schema after registration must have no effect.
	policy.Fields["token"] = module.AuditField{Kind: module.AuditUUID}
	request := func(subject, path string, authErr error) *httptest.ResponseRecorder {
		t.Helper()
		h, err := registry.Handler(fixedAuth{verified(subject), authErr}, store, "https://app.test")
		if err != nil {
			t.Fatal(err)
		}
		r := httptest.NewRequest("POST", path, strings.NewReader(`{"actor":"admin","permission":"admin.manage","account":"forged"}`))
		r.Header.Set("Origin", "https://app.test")
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	accountPath := "/api/modules/example/accounts/" + account + "/items"
	globalPath := "/api/modules/example/settings"
	snapshot := func() string {
		t.Helper()
		var value string
		if err := owner.QueryRow(ctx, `SELECT jsonb_build_array((SELECT jsonb_agg(to_jsonb(i) ORDER BY id) FROM module_test.items i),(SELECT jsonb_agg(to_jsonb(s) ORDER BY id) FROM module_test.settings s),(SELECT coalesce(jsonb_agg(to_jsonb(a) ORDER BY id),'[]') FROM framework.audit_log a))::text`).Scan(&value); err != nil {
			t.Fatal(err)
		}
		return value
	}
	reset := func() { before = nil; invoke = nil; callback = defaultCallback; result = nil; calls = 0 }
	check := func(t *testing.T, w *httptest.ResponseRecorder, status int, want error) {
		t.Helper()
		if w.Code != status || !errors.Is(result, want) {
			t.Fatalf("status=%d error=%v want=%d/%v body=%s", w.Code, result, status, want, w.Body.String())
		}
	}
	for _, global := range []bool{false, true} {
		t.Run(fmt.Sprintf("successful mutation and audit global=%v", global), func(t *testing.T) {
			reset()
			path, action, target := accountPath, "example.item.updated", item
			if global {
				path, action, target = globalPath, "example.settings.updated", setting
			}
			check(t, request("user", path, nil), 204, nil)
			var actor, actualAction, actualTarget string
			var details map[string]any
			if err := owner.QueryRow(ctx, `SELECT actor_user_id::text,action,target_id,details FROM framework.audit_log ORDER BY id DESC LIMIT 1`).Scan(&actor, &actualAction, &actualTarget, &details); err != nil {
				t.Fatal(err)
			}
			if actor != user.ID || actualAction != action || actualTarget != target || details["changed"] != true || calls != 1 {
				t.Fatal("incorrect audit event", actor, actualAction, actualTarget, details, calls)
			}
			if !global && details["account_id"] != account {
				t.Fatal("missing bound account")
			}
			var value int
			sql := `SELECT value FROM module_test.items WHERE id=$1`
			if global {
				sql = `SELECT value FROM module_test.settings WHERE id=$1`
			}
			if err := owner.QueryRow(ctx, sql, target).Scan(&value); err != nil || value != 1 {
				t.Fatal("business write missing", value, err)
			}
		})
	}
	for _, tc := range []struct {
		name, subject, path string
		authErr             error
		status              int
	}{
		{"missing authentication", "user", accountPath, auth.ErrUnauthenticated, 401},
		{"Admin has no implicit module permission", "admin", accountPath, nil, 403},
		{"unlinked account", "user", "/api/modules/example/accounts/" + other + "/items", nil, 403},
		{"malformed account", "user", "/api/modules/example/accounts/bad/items", nil, 400},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reset()
			start := snapshot()
			check(t, request(tc.subject, tc.path, tc.authErr), tc.status, nil)
			if calls != 0 || snapshot() != start {
				t.Fatal("denial changed records")
			}
		})
	}
	for _, tc := range []struct {
		name, sql, restore string
		arg                any
	}{
		{"inactive account", `UPDATE framework.accounts SET active=false WHERE id=$1`, `UPDATE framework.accounts SET active=true WHERE id=$1`, account},
		{"inactive user", `UPDATE framework.users SET active=false WHERE id=$1`, `UPDATE framework.users SET active=true WHERE id=$1`, user.ID},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reset()
			exec(tc.sql, tc.arg)
			defer exec(tc.restore, tc.arg)
			start := snapshot()
			check(t, request("user", accountPath, nil), 403, nil)
			if calls != 0 || snapshot() != start {
				t.Fatal("inactive access wrote records")
			}
		})
	}
	t.Run("account SQL cannot update another account target", func(t *testing.T) {
		reset()
		callback = func(ctx context.Context, tx module.Transaction, scope string) (string, module.AuditDetails, error) {
			calls++
			tag, err := tx.Exec(ctx, `UPDATE module_test.items SET value=999 WHERE id=$1 AND account_id=$2`, otherItem, scope)
			if err == nil && tag.RowsAffected() == 0 {
				err = errors.New("not found")
			}
			return otherItem, nil, err
		}
		start := snapshot()
		check(t, request("user", accountPath, nil), 409, module.ErrMutation)
		if snapshot() != start {
			t.Fatal("cross-account write")
		}
	})
	for _, tc := range []struct {
		name    string
		hook    func(*http.Request)
		restore func()
		want    error
	}{
		{"association revoked before transaction", func(*http.Request) { exec(`DELETE FROM framework.user_accounts WHERE user_id=$1`, user.ID) }, func() {
			exec(`INSERT INTO framework.user_accounts(user_id,account_id) VALUES($1,$2)`, user.ID, account)
		}, module.ErrAccountDenied},
		{"permission revoked before transaction", func(*http.Request) {
			exec(`DELETE FROM framework.role_permissions WHERE role='User' AND permission='example.items.write'`)
		}, func() {
			exec(`INSERT INTO framework.role_permissions(role,permission) VALUES('User','example.items.write')`)
		}, module.ErrPermissionDenied},
		{"user deactivated before transaction", func(*http.Request) { exec(`UPDATE framework.users SET active=false WHERE id=$1`, user.ID) }, func() { exec(`UPDATE framework.users SET active=true WHERE id=$1`, user.ID) }, module.ErrUnauthenticated},
		{"account deactivated before transaction", func(*http.Request) { exec(`UPDATE framework.accounts SET active=false WHERE id=$1`, account) }, func() { exec(`UPDATE framework.accounts SET active=true WHERE id=$1`, account) }, module.ErrAccountDenied},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reset()
			before = tc.hook
			defer tc.restore()
			start := snapshot()
			check(t, request("user", accountPath, nil), 409, tc.want)
			if calls != 0 || snapshot() != start {
				t.Fatal("revocation did not prevent write")
			}
		})
	}
	for _, tc := range []struct {
		name        string
		target      string
		details     module.AuditDetails
		callbackErr error
		want        error
	}{
		{"callback error", item, nil, errors.New("database secret password"), module.ErrMutation},
		{"missing target", "", module.AuditDetails{"changed": true, "count": 1}, nil, module.ErrAudit},
		{"invalid target", "raw secret", module.AuditDetails{"changed": true, "count": 1}, nil, module.ErrAudit},
		{"unapproved field", item, module.AuditDetails{"changed": true, "count": 1, "token": "secret"}, nil, module.ErrAudit},
		{"wrong type", item, module.AuditDetails{"changed": "secret", "count": 1}, nil, module.ErrAudit},
		{"nested payload", item, module.AuditDetails{"changed": true, "count": map[string]any{"token": "secret"}}, nil, module.ErrAudit},
		{"missing field", item, module.AuditDetails{"changed": true}, nil, module.ErrAudit},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reset()
			callback = func(ctx context.Context, tx module.Transaction, scope string) (string, module.AuditDetails, error) {
				_, _, err := defaultCallback(ctx, tx, scope)
				if err != nil {
					return "", nil, err
				}
				return tc.target, tc.details, tc.callbackErr
			}
			start := snapshot()
			check(t, request("user", accountPath, nil), 409, tc.want)
			if calls != 1 || snapshot() != start {
				t.Fatal("failed callback/audit did not roll back")
			}
		})
	}
	t.Run("oversized audit rolls back", func(t *testing.T) {
		reset()
		callback = func(ctx context.Context, tx module.Transaction, scope string) (string, module.AuditDetails, error) {
			target, _, err := defaultCallback(ctx, tx, scope)
			return target, largeDetails, err
		}
		start := snapshot()
		check(t, request("user", "/api/modules/example/accounts/"+account+"/oversized", nil), 409, module.ErrAudit)
		if snapshot() != start {
			t.Fatal("oversized audit committed")
		}
	})
	t.Run("audit insert failure rolls back business write", func(t *testing.T) {
		reset()
		exec(`REVOKE INSERT ON framework.audit_log FROM go_web_app`)
		defer exec(`GRANT INSERT ON framework.audit_log TO go_web_app`)
		start := snapshot()
		check(t, request("user", accountPath, nil), 409, module.ErrAudit)
		if calls != 1 || snapshot() != start {
			t.Fatal("audit failure committed business write")
		}
	})
	for _, tc := range []struct {
		name, path string
		invoke     func(*http.Request, module.TransactionManager) error
	}{
		{"account route cannot mutate global", accountPath, func(r *http.Request, m module.TransactionManager) error {
			return m.MutateGlobal(r.Context(), func(ctx context.Context, tx module.Transaction) (string, module.AuditDetails, error) {
				return defaultCallback(ctx, tx, "")
			})
		}},
		{"global route cannot mutate account", globalPath, func(r *http.Request, m module.TransactionManager) error {
			return m.MutateAccount(r.Context(), defaultCallback)
		}},
		{"replacement context cannot change authority", accountPath, func(r *http.Request, m module.TransactionManager) error {
			return m.MutateAccount(context.Background(), defaultCallback)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reset()
			invoke = tc.invoke
			start := snapshot()
			check(t, request("user", tc.path, nil), 409, module.ErrScope)
			if calls != 0 || snapshot() != start {
				t.Fatal("scope bypass")
			}
		})
	}
	t.Run("request fields cannot replace bound scope", func(t *testing.T) {
		reset()
		before = func(r *http.Request) { r.SetPathValue("account", other) }
		invoke = func(r *http.Request, m module.TransactionManager) error {
			ctx := context.WithValue(r.Context(), "permission", "admin.manage")
			return m.MutateAccount(ctx, func(ctx context.Context, tx module.Transaction, scope string) (string, module.AuditDetails, error) {
				if scope != account {
					t.Fatal("request changed bound scope")
				}
				return defaultCallback(ctx, tx, scope)
			})
		}
		check(t, request("user", accountPath+"?actor=admin&account="+other, nil), 204, nil)
		var value int
		if err := owner.QueryRow(ctx, `SELECT value FROM module_test.items WHERE id=$1`, otherItem).Scan(&value); err != nil || value != 0 {
			t.Fatal("unlinked record changed", value, err)
		}
	})
	t.Run("callback panic rolls back", func(t *testing.T) {
		reset()
		callback = func(ctx context.Context, tx module.Transaction, scope string) (string, module.AuditDetails, error) {
			_, _, err := defaultCallback(ctx, tx, scope)
			if err != nil {
				return "", nil, err
			}
			panic("test callback")
		}
		start := snapshot()
		func() {
			defer func() {
				if recover() == nil {
					t.Error("expected callback panic")
				}
			}()
			request("user", accountPath, nil)
		}()
		if snapshot() != start {
			t.Fatal("panic left partial records")
		}
	})
	t.Run("canceled caller rolls back", func(t *testing.T) {
		reset()
		invoke = func(r *http.Request, m module.TransactionManager) error {
			ctx, cancel := context.WithCancel(r.Context())
			callback = func(ctx context.Context, tx module.Transaction, scope string) (string, module.AuditDetails, error) {
				target, details, err := defaultCallback(ctx, tx, scope)
				cancel()
				return target, details, err
			}
			return m.MutateAccount(ctx, callback)
		}
		start := snapshot()
		check(t, request("user", accountPath, nil), 409, module.ErrCanceled)
		if snapshot() != start {
			t.Fatal("canceled mutation committed")
		}
	})
	t.Run("default five second deadline and connection release", func(t *testing.T) {
		reset()
		callback = func(ctx context.Context, tx module.Transaction, scope string) (string, module.AuditDetails, error) {
			target, details, err := defaultCallback(ctx, tx, scope)
			if err != nil {
				return "", nil, err
			}
			_, err = tx.Exec(context.Background(), `SELECT pg_sleep(10)`)
			return target, details, err
		}
		start := snapshot()
		began := time.Now()
		check(t, request("user", accountPath, nil), 409, module.ErrTimeout)
		if elapsed := time.Since(began); elapsed < 4*time.Second || elapsed > 8*time.Second {
			t.Fatal("unexpected deadline", elapsed)
		}
		if snapshot() != start {
			t.Fatal("timed out mutation committed")
		}
		if err := pool.Ping(ctx); err != nil {
			t.Fatal("connection not released", err)
		}
	})
	t.Run("query results retain scope without connection access", func(t *testing.T) {
		reset()
		callback = func(ctx context.Context, tx module.Transaction, scope string) (string, module.AuditDetails, error) {
			rows, err := tx.Query(ctx, `SELECT id::text FROM module_test.items WHERE account_id=$1`, scope)
			if err != nil {
				return "", nil, err
			}
			defer rows.Close()
			// A pgx.Rows assertion would expose Conn; the adapter never returns it.
			if _, ok := rows.(interface{ Conn() *pgx.Conn }); ok {
				t.Fatal("query exposed connection")
			}
			count := 0
			for rows.Next() {
				var id string
				if err := rows.Scan(&id); err != nil {
					return "", nil, err
				}
				if id != item {
					t.Fatal("query leaked another account")
				}
				count++
			}
			if err := rows.Err(); err != nil {
				return "", nil, err
			}
			if count != 1 {
				t.Fatal("incorrect scoped query count", count)
			}
			var id string
			if err := tx.QueryRow(ctx, `SELECT id::text FROM module_test.items WHERE id=$1 AND account_id=$2`, item, scope).Scan(&id); err != nil {
				return "", nil, err
			}
			return defaultCallback(ctx, tx, scope)
		}
		check(t, request("user", accountPath, nil), 204, nil)
	})
	for _, single := range []bool{false, true} {
		t.Run(fmt.Sprintf("RowScanner connection escape rejected single=%v", single), func(t *testing.T) {
			reset()
			scanner := &connectionScanner{}
			callback = func(ctx context.Context, tx module.Transaction, scope string) (string, module.AuditDetails, error) {
				target, details, err := defaultCallback(ctx, tx, scope)
				if err != nil {
					return "", nil, err
				}
				if single {
					err = tx.QueryRow(ctx, `SELECT 1`).Scan(scanner)
				} else {
					rows, e := tx.Query(ctx, `SELECT 1`)
					if e != nil {
						return "", nil, e
					}
					defer rows.Close()
					if rows.Next() {
						err = rows.Scan(scanner)
					}
				}
				return target, details, err
			}
			start := snapshot()
			check(t, request("user", accountPath, nil), 409, module.ErrMutation)
			if scanner.called || snapshot() != start {
				t.Fatal("RowScanner obtained underlying rows or committed")
			}
		})
	}
	for _, mode := range []string{"Exec", "Query", "QueryRow"} {
		t.Run("shorter statement deadline "+mode, func(t *testing.T) {
			reset()
			callback = func(ctx context.Context, tx module.Transaction, scope string) (string, module.AuditDetails, error) {
				target, details, err := defaultCallback(ctx, tx, scope)
				if err != nil {
					return "", nil, err
				}
				short, cancel := context.WithTimeout(ctx, 30*time.Millisecond)
				defer cancel()
				switch mode {
				case "Exec":
					_, err = tx.Exec(short, `SELECT pg_sleep(1)`)
				case "Query":
					var rows module.Rows
					rows, err = tx.Query(short, `SELECT pg_sleep(1)`)
					if rows != nil {
						for rows.Next() {
						}
						err = rows.Err()
						rows.Close()
					}
				case "QueryRow":
					var result any
					err = tx.QueryRow(short, `SELECT pg_sleep(1)`).Scan(&result)
				}
				return target, details, err
			}
			start := snapshot()
			check(t, request("user", accountPath, nil), 409, module.ErrTimeout)
			if snapshot() != start {
				t.Fatal("statement timeout committed")
			}
		})
	}
	t.Run("manager cannot outlive request", func(t *testing.T) {
		reset()
		var manager module.TransactionManager
		var retained context.Context
		invoke = func(r *http.Request, m module.TransactionManager) error {
			manager, retained = m, r.Context()
			return nil
		}
		check(t, request("user", accountPath, nil), 204, nil)
		start := snapshot()
		if err := manager.MutateAccount(retained, defaultCallback); !errors.Is(err, module.ErrCanceled) {
			t.Fatal(err)
		}
		if calls != 0 || snapshot() != start {
			t.Fatal("retained manager wrote records")
		}
	})
	t.Run("concurrent module mutation and administrator revocation serialize", func(t *testing.T) {
		reset()
		entered, release := make(chan struct{}), make(chan struct{})
		callback = func(ctx context.Context, tx module.Transaction, scope string) (string, module.AuditDetails, error) {
			close(entered)
			select {
			case <-release:
			case <-ctx.Done():
				return "", nil, ctx.Err()
			}
			return defaultCallback(ctx, tx, scope)
		}
		response := make(chan *httptest.ResponseRecorder, 1)
		go func() { response <- request("user", accountPath, nil) }()
		<-entered
		revoked := make(chan error, 1)
		go func() { revoked <- store.SetAccounts(ctx, admin.ID, user.ID, nil) }()
		deadline := time.Now().Add(2 * time.Second)
		waiting := false
		for time.Now().Before(deadline) {
			if err := owner.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE usename='go_web_app' AND wait_event='advisory')`).Scan(&waiting); err != nil {
				t.Fatal(err)
			}
			if waiting {
				break
			}
			time.Sleep(5 * time.Millisecond)
		}
		close(release)
		w := <-response
		err := <-revoked
		if !waiting || err != nil {
			t.Fatal("revocation did not wait for module lock", waiting, err)
		}
		check(t, w, 204, nil)
		defer exec(`INSERT INTO framework.user_accounts(user_id,account_id) VALUES($1,$2)`, user.ID, account)
		reset()
		start := snapshot()
		check(t, request("user", accountPath, nil), 403, nil)
		if snapshot() != start {
			t.Fatal("post-revocation write")
		}
	})
	t.Run("database unavailable after route checks", func(t *testing.T) {
		reset()
		before = func(*http.Request) { pool.Close() }
		start := snapshot()
		check(t, request("user", accountPath, nil), 409, module.ErrUnavailable)
		if calls != 0 || snapshot() != start {
			t.Fatal("database failure wrote records")
		}
	})
}
