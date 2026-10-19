package authconfig

import (
	"bytes"
	"context"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bmoheeputh-sudo/go-web-framework/backend/internal/access"
	"github.com/bmoheeputh-sudo/go-web-framework/backend/internal/auth"
	"github.com/bmoheeputh-sudo/go-web-framework/backend/internal/testdb"
)

func TestAuthConfigurationMigrationRollbackPolicy(t *testing.T) {
	for _, name := range []string{"empty", "populated"} {
		t.Run(name, func(t *testing.T) { testAuthConfigurationRollbackPolicy(t, name == "populated") })
	}
}

func testAuthConfigurationRollbackPolicy(t *testing.T, populated bool) {
	t.Helper()
	cli, err := exec.LookPath("migrate")
	if err != nil {
		t.Skip("requires golang-migrate CLI with PostgreSQL driver")
	}
	pool, connection := testdb.New(t)
	directory, err := filepath.Abs("../../../database/migrations")
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(connection)
	if err != nil {
		t.Fatal("invalid isolated connection")
	}
	query := u.Query()
	query.Set("search_path", "public")
	u.RawQuery = query.Encode()
	script := frameworkMigrationScript(t)
	runCommand := func(raw bool, args ...string) error {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		command := exec.CommandContext(ctx, "bash", append([]string{script}, args...)...)
		if raw {
			command = exec.CommandContext(ctx, cli, append([]string{"-path", directory, "-database", u.String()}, args...)...)
		}
		for _, entry := range os.Environ() {
			if !strings.HasPrefix(entry, "PG") {
				command.Env = append(command.Env, entry)
			}
		}
		// Only the disposable cluster: never inherit application DB settings.
		command.Env = append(command.Env, "PGHOST="+u.Query().Get("host"),
			"PGDATABASE=postgres", "PGUSER=postgres", "PGSSLMODE=disable")
		// No credentials or connection strings in test output.
		_, err := command.CombinedOutput()
		return err
	}
	run := func(args ...string) error { return runCommand(false, args...) }
	if err = run("up", "4"); err != nil {
		t.Fatal("isolated version 4 migration failed")
	}
	ctx := context.Background()
	var journal uint32
	if err = pool.QueryRow(ctx, `SELECT 'public.schema_migrations'::regclass::oid`).Scan(&journal); err != nil {
		t.Fatal(err)
	}
	if err = run("up", "1"); err != nil {
		t.Fatal("isolated version 5 migration failed")
	}
	var version int
	var dirty bool
	var after uint32
	var revisions, active int
	if err = pool.QueryRow(ctx, `SELECT version,dirty,'public.schema_migrations'::regclass::oid,(SELECT count(*) FROM framework.auth_config_revisions),(SELECT count(*) FROM framework.auth_config_lifecycle WHERE status='active') FROM public.schema_migrations`).Scan(&version, &dirty, &after, &revisions, &active); err != nil {
		t.Fatal(err)
	}
	if version != 5 || dirty || journal != after || revisions != 0 || active != 0 {
		t.Fatal("migration changed history or activated configuration")
	}
	if err = run("version"); err != nil {
		t.Fatal("migration version command failed")
	}
	var f *fixture
	var history []Metadata
	if populated {
		store := access.New(pool)
		identity := auth.Identity{Issuer: "https://issuer.example.test", Subject: "migration-admin", Provider: auth.OIDC}
		if _, err = store.Resolve(ctx, identity); err != nil {
			t.Fatal(err)
		}
		if err = store.Bootstrap(ctx, identity.Issuer, identity.Subject, "development"); err != nil {
			t.Fatal(err)
		}
		repo, err := NewRepository(store, Scope{"installation-a", "development"}, testCipher(t, "key-v1"))
		if err != nil {
			t.Fatal(err)
		}
		f = &fixture{owner: pool, pool: pool, store: store, repo: repo, identity: identity}
		history = []Metadata{f.draft(t, 0), f.draft(t, 1)}
		f.run(t, func(ctx context.Context) {
			if _, err := repo.Transition(ctx, history[0].ID, 1, Validated); err != nil {
				t.Fatal(err)
			}
			if _, err := repo.Transition(ctx, history[0].ID, 2, Approved); err != nil {
				t.Fatal(err)
			}
		})
		// Test-only activation fixture; the repository has no activation API.
		if _, err = pool.Exec(ctx, `UPDATE framework.auth_config_lifecycle SET status='active',generation=generation+1 WHERE revision_id=$1`, history[0].ID); err != nil {
			t.Fatal(err)
		}
	}
	// Compare every stored field, including ciphertext, nonce, key ID, lifecycle
	// generations/timestamps and audit history. Never print the snapshot.
	snapshot := func() string {
		t.Helper()
		var data string
		err := pool.QueryRow(ctx, `SELECT jsonb_build_array(
			(SELECT jsonb_agg(to_jsonb(r) ORDER BY id) FROM framework.auth_config_revisions r),
			(SELECT jsonb_agg(to_jsonb(l) ORDER BY revision_id) FROM framework.auth_config_lifecycle l),
			(SELECT jsonb_agg(to_jsonb(a) ORDER BY id) FROM framework.audit_log a),
			'framework.auth_config_revisions'::regclass::oid,
			'framework.auth_config_lifecycle'::regclass::oid)::text`).Scan(&data)
		if err != nil {
			t.Fatal("configuration snapshot failed")
		}
		return data
	}
	before := snapshot()
	for _, args := range [][]string{{"down", "1"}, {"down"}, {"goto", "4"}, {"force", "4"}, {"drop", "-f"}, {"up", "-1"}} {
		if err = run(args...); err == nil {
			t.Fatal("unsupported operation was accepted")
		}
		if err = pool.QueryRow(ctx, `SELECT version,dirty,'public.schema_migrations'::regclass::oid FROM public.schema_migrations`).Scan(&version, &dirty, &after); err != nil {
			t.Fatal(err)
		}
		if version != 5 || dirty || journal != after {
			t.Fatal("refused operation changed the clean version-5 journal")
		}
		if snapshot() != before {
			t.Fatal("refused operation changed configuration history, credentials or audit records")
		}
	}
	if err = run("version"); err != nil {
		t.Fatal("clean migration version unavailable after refusal")
	}
	if populated {
		f.run(t, func(ctx context.Context) {
			for _, revision := range history {
				secret, err := f.repo.ReadSecretPrivileged(ctx, revision.ID)
				if err != nil || !bytes.Equal(secret.Bytes(), []byte("fake-secret-for-tests")) {
					t.Fatal("retained credential cannot be decrypted")
				}
			}
			active, err := f.repo.CurrentActive(ctx)
			if err != nil || active.ID != history[0].ID {
				t.Fatal("active configuration tracking changed")
			}
		})
		for _, sql := range []string{
			`UPDATE framework.auth_config_revisions SET client_id='changed' WHERE id=$1`,
			`DELETE FROM framework.auth_config_revisions WHERE id=$1`,
			`DELETE FROM framework.auth_config_lifecycle WHERE revision_id=$1`,
		} {
			_, err := pool.Exec(ctx, sql, history[0].ID)
			assertConstraint(t, err)
		}
		_, err := pool.Exec(ctx, `TRUNCATE framework.auth_config_revisions,framework.auth_config_lifecycle`)
		assertConstraint(t, err)
	}
	// Unsupported direct CLI bypass must fail visibly, never claim a clean
	// version 4 while keeping version-5 objects. It requires operator recovery.
	before = snapshot()
	if err = runCommand(true, "down", "1"); err == nil {
		t.Fatal("direct rollback silently succeeded")
	}
	if err = pool.QueryRow(ctx, `SELECT version,dirty FROM public.schema_migrations`).Scan(&version, &dirty); err != nil {
		t.Fatal(err)
	}
	if version != 4 || !dirty || snapshot() != before {
		t.Fatal("direct rollback did not preserve history with a visible dirty failure")
	}
	if err = run("up", "1"); err == nil {
		t.Fatal("dirty journal did not block subsequent migrations")
	}
}
