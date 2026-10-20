package modules

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/bmoheeputh-sudo/go-web-framework/backend/internal/apps/example"
	"github.com/bmoheeputh-sudo/go-web-framework/backend/internal/testdb"
	"github.com/bmoheeputh-sudo/go-web-framework/backend/module"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestMigrationMetadata(t *testing.T) {
	for _, tc := range []struct {
		name, id, schema, directory string
		version                     int64
	}{
		{"invalid ID", "bad-name", "bad-name", "database/modules/bad-name/migrations", 1},
		{"core ID", "framework", "framework", "database/modules/framework/migrations", 1},
		{"system schema", "pg_catalog", "pg_catalog", "database/modules/pg_catalog/migrations", 1},
		{"information schema", "information_schema", "information_schema", "database/modules/information_schema/migrations", 1},
		{"core schema", "example", "framework", "database/modules/example/migrations", 1},
		{"foreign schema", "example", "reporting", "database/modules/example/migrations", 1},
		{"schema SQL injection", "example", "example; DROP SCHEMA framework", "database/modules/example/migrations", 1},
		{"missing schema", "example", "", "database/modules/example/migrations", 1},
		{"absolute path", "example", "example", "/database/modules/example/migrations", 1},
		{"traversal", "example", "example", "database/modules/example/../../migrations", 1},
		{"other module path", "example", "example", "database/modules/reporting/migrations", 1},
		{"core path", "example", "example", "database/migrations", 1},
		{"URL", "example", "example", "https://example.test/migrations", 1},
		{"encoded path", "example", "example", "database/modules/%65xample/migrations", 1},
		{"noncanonical path", "example", "example", "database/modules/example/./migrations", 1},
		{"missing directory", "example", "example", "", 1},
		{"zero version", "example", "example", "database/modules/example/migrations", 0},
		{"negative version", "example", "example", "database/modules/example/migrations", -1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := candidate(tc.id, nil)
			m.manifest.Migrations = &module.MigrationSpec{Schema: tc.schema, Directory: tc.directory, RequiredVersion: tc.version}
			if _, err := New([]module.Module{m}, ""); err == nil {
				t.Fatal("invalid metadata accepted even when disabled")
			}
		})
	}
	t.Run("metadata copies and derived journals", func(t *testing.T) {
		m := candidate("reporting", nil)
		m.manifest.Migrations = &module.MigrationSpec{Schema: "reporting", Directory: "database/modules/reporting/migrations", RequiredVersion: 1}
		registry, err := New([]module.Module{m, example.Module{}}, "reporting,example")
		if err != nil {
			t.Fatal(err)
		}
		expected := registry.MigrationPlans()
		m.manifest.Migrations.Schema = "framework"
		plans := registry.MigrationPlans()
		plans[0].Journal = "schema_migrations"
		plans[1].RequiredVersion = 999
		if !reflect.DeepEqual(expected, registry.MigrationPlans()) {
			t.Fatal("mutable migration metadata")
		}
		for _, plan := range expected {
			if plan.Schema != plan.ID || plan.Journal != "schema_migrations_"+plan.ID || len(plan.Journal) > 63 {
				t.Fatal("unsafe derived schema/journal", plan)
			}
		}
	})
	for _, enabled := range []string{"", "stateless"} {
		t.Run("no migrations "+enabled, func(t *testing.T) {
			r, err := New([]module.Module{example.Module{}, candidate("stateless", nil)}, enabled)
			if err != nil {
				t.Fatal(err)
			}
			if len(r.MigrationPlans()) != 0 || r.CheckMigrations(context.Background(), nil) != nil {
				t.Fatal("disabled/stateless module required a database")
			}
		})
	}
}

func TestIndependentModuleMigrations(t *testing.T) {
	cli, err := exec.LookPath("migrate")
	if err != nil {
		t.Skip("requires golang-migrate CLI with postgres driver")
	}
	owner, connection := testdb.New(t)
	ctx := context.Background()
	execute := func(sql string, args ...any) {
		t.Helper()
		if _, err := owner.Exec(ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	// Existing single application role also runs module DDL in this isolated DB.
	execute(`GRANT CREATE ON DATABASE postgres TO go_web_app; GRANT CREATE,USAGE ON SCHEMA public TO go_web_app`)
	u, err := url.Parse(connection)
	if err != nil {
		t.Fatal(err)
	}
	u.User = url.User("go_web_app")
	config, err := pgxpool.ParseConfig(u.String())
	if err != nil {
		t.Fatal(err)
	}
	config.ConnConfig.RuntimeParams["search_path"] = "pg_catalog"
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	root, err := filepath.Abs("../../..")
	if err != nil {
		t.Fatal(err)
	}
	run := func(directory, journal string, args ...string) error {
		t.Helper()
		ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
		defer cancel()
		target := *u
		q := target.Query()
		q.Set("search_path", "public")
		q.Set("x-migrations-table", journal)
		target.RawQuery = q.Encode()
		command := exec.CommandContext(ctx, cli, append([]string{"-path", directory, "-database", target.String()}, args...)...)
		for _, entry := range os.Environ() {
			if !strings.HasPrefix(entry, "PG") {
				command.Env = append(command.Env, entry)
			}
		}
		output, err := command.CombinedOutput()
		if err != nil {
			return fmt.Errorf("isolated migrate %v: %w: %s", args, err, output)
		}
		return nil
	}
	mustRun := func(directory, journal string, args ...string) {
		t.Helper()
		if err := run(directory, journal, args...); err != nil {
			t.Fatal(err)
		}
	}
	mustRun(filepath.Join(root, "database/migrations"), "schema_migrations", "up")
	journalSnapshot := func(journal string) string {
		t.Helper()
		var value string
		if err := owner.QueryRow(ctx, `SELECT jsonb_build_object('oid',$1::regclass::oid,'rows',(SELECT jsonb_agg(to_jsonb(j) ORDER BY version) FROM `+pgx.Identifier{"public", journal}.Sanitize()+` j))::text`, "public."+journal).Scan(&value); err != nil {
			t.Fatal(err)
		}
		return value
	}
	coreBefore := journalSnapshot("schema_migrations")
	registry, err := New([]module.Module{example.Module{}}, "example")
	if err != nil {
		t.Fatal(err)
	}
	plan := registry.MigrationPlans()[0]
	path := filepath.Join(root, filepath.FromSlash(plan.Directory))
	check := func(want string) {
		t.Helper()
		err := registry.CheckMigrations(ctx, pool)
		if want == "" {
			if err != nil {
				t.Fatal(err)
			}
		} else if err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("want %q, got %v", want, err)
		}
	}
	assertCore := func() {
		t.Helper()
		if journalSnapshot("schema_migrations") != coreBefore {
			t.Fatal("core history modified")
		}
	}
	t.Run("fresh installation", func(t *testing.T) {
		check("schema missing")
		mustRun(path, plan.Journal, "up")
		check("")
		mustRun(path, plan.Journal, "version")
		assertCore()
	})
	t.Run("independent numbering and journals", func(t *testing.T) {
		dir := t.TempDir()
		writeMigration(t, dir, "000001_initial.up.sql", "BEGIN; CREATE SCHEMA reporting AUTHORIZATION go_web_app; COMMIT;")
		mustRun(dir, "schema_migrations_reporting", "up")
		var core, example, reporting int64
		if err := owner.QueryRow(ctx, `SELECT (SELECT version FROM public.schema_migrations),(SELECT version FROM public.schema_migrations_example),(SELECT version FROM public.schema_migrations_reporting)`).Scan(&core, &example, &reporting); err != nil {
			t.Fatal(err)
		}
		if core != 8 || example != 1 || reporting != 1 {
			t.Fatal("migration numbering interfered", core, example, reporting)
		}
	})
	reportingBefore := journalSnapshot("schema_migrations_reporting")
	assertOthers := func() {
		t.Helper()
		assertCore()
		if journalSnapshot("schema_migrations_reporting") != reportingBefore {
			t.Fatal("another module history modified")
		}
	}
	t.Run("read only readiness and unchanged records", func(t *testing.T) {
		before := journalSnapshot(plan.Journal)
		roConfig := config.Copy()
		roConfig.ConnConfig.RuntimeParams["default_transaction_read_only"] = "on"
		ro, err := pgxpool.NewWithConfig(ctx, roConfig)
		if err != nil {
			t.Fatal(err)
		}
		defer ro.Close()
		if err := registry.CheckMigrations(ctx, ro); err != nil {
			t.Fatal(err)
		}
		if journalSnapshot(plan.Journal) != before {
			t.Fatal("startup wrote journal")
		}
		assertOthers()
	})
	for _, tc := range []struct{ name, change, restore, want string }{
		{"missing schema", `ALTER SCHEMA example RENAME TO example_saved`, `ALTER SCHEMA example_saved RENAME TO example`, "schema missing"},
		{"missing journal", `ALTER TABLE public.schema_migrations_example RENAME TO journal_saved`, `ALTER TABLE public.journal_saved RENAME TO schema_migrations_example`, "journal missing"},
		{"dirty state", `UPDATE public.schema_migrations_example SET dirty=true`, `UPDATE public.schema_migrations_example SET dirty=false`, "dirty migration"},
		{"older version", `UPDATE public.schema_migrations_example SET version=0`, `UPDATE public.schema_migrations_example SET version=1`, "exactly 1 required"},
		{"newer version", `UPDATE public.schema_migrations_example SET version=2`, `UPDATE public.schema_migrations_example SET version=1`, "exactly 1 required"},
		{"empty journal", `DELETE FROM public.schema_migrations_example`, `INSERT INTO public.schema_migrations_example(version,dirty) VALUES(1,false)`, "exactly one"},
		{"multiple versions", `INSERT INTO public.schema_migrations_example(version,dirty) VALUES(2,false)`, `DELETE FROM public.schema_migrations_example WHERE version=2`, "exactly one"},
	} {
		t.Run(tc.name, func(t *testing.T) { execute(tc.change); defer execute(tc.restore); check(tc.want); assertOthers() })
	}
	t.Run("disabled modules need no installation", func(t *testing.T) {
		execute(`ALTER SCHEMA example RENAME TO example_saved; ALTER TABLE public.schema_migrations_example RENAME TO journal_saved`)
		defer execute(`ALTER SCHEMA example_saved RENAME TO example; ALTER TABLE public.journal_saved RENAME TO schema_migrations_example`)
		disabled, err := New([]module.Module{example.Module{}}, "")
		if err != nil {
			t.Fatal(err)
		}
		if err := disabled.CheckMigrations(ctx, pool); err != nil {
			t.Fatal(err)
		}
		var absent bool
		if err := owner.QueryRow(ctx, `SELECT pg_catalog.to_regclass('public.schema_migrations_example') IS NULL`).Scan(&absent); err != nil || !absent {
			t.Fatal("validation created a journal", err)
		}
	})
	// Simulate later releases without adding permanent example business tables.
	upgrade := t.TempDir()
	for _, name := range []string{"000001_initial.up.sql", "000001_initial.down.sql"} {
		data, err := os.ReadFile(filepath.Join(path, name))
		if err != nil {
			t.Fatal(err)
		}
		writeMigration(t, upgrade, name, string(data))
	}
	writeMigration(t, upgrade, "000002_items.up.sql", `BEGIN; CREATE TABLE example.items(id uuid PRIMARY KEY); COMMIT;`)
	writeMigration(t, upgrade, "000002_items.down.sql", `BEGIN; DROP TABLE example.items; COMMIT;`)
	t.Run("upgrade and rollback", func(t *testing.T) {
		mustRun(upgrade, plan.Journal, "up", "1")
		check("exactly 1 required")
		m := candidate("example", nil)
		m.manifest.Migrations = &module.MigrationSpec{Schema: "example", Directory: plan.Directory, RequiredVersion: 2}
		newer, err := New([]module.Module{m}, "example")
		if err != nil {
			t.Fatal(err)
		}
		if err := newer.CheckMigrations(ctx, pool); err != nil {
			t.Fatal(err)
		}
		mustRun(upgrade, plan.Journal, "down", "1")
		check("")
		assertOthers()
	})
	t.Run("failed migration and reviewed recovery", func(t *testing.T) {
		writeMigration(t, upgrade, "000003_failure.up.sql", `BEGIN; CREATE TABLE example.partial(id integer); SELECT 1/0; COMMIT;`)
		writeMigration(t, upgrade, "000003_failure.down.sql", `BEGIN; DROP TABLE example.partial; COMMIT;`)
		mustRun(upgrade, plan.Journal, "up", "1") // version 2
		if err := run(upgrade, plan.Journal, "up", "1"); err == nil {
			t.Fatal("broken migration succeeded")
		}
		check("dirty migration")
		var absent bool
		if err := owner.QueryRow(ctx, `SELECT pg_catalog.to_regclass('example.partial') IS NULL`).Scan(&absent); err != nil || !absent {
			t.Fatal("failed transactional DDL left partial table", err)
		}
		if err := run(upgrade, plan.Journal, "up"); err == nil {
			t.Fatal("dirty state did not block further migrations")
		}
		// Test-only recovery: inspect actual state (v2) before clearing the v3 marker.
		mustRun(upgrade, plan.Journal, "force", "2")
		writeMigration(t, upgrade, "000003_failure.up.sql", `BEGIN; CREATE TABLE example.partial(id integer); COMMIT;`)
		mustRun(upgrade, plan.Journal, "up", "1")
		mustRun(upgrade, plan.Journal, "down", "1")
		mustRun(upgrade, plan.Journal, "down", "1")
		check("")
		assertOthers()
	})
	t.Run("initial rollback keeps journals and protects unexpected data", func(t *testing.T) {
		execute(`CREATE TABLE example.unexpected(id integer); INSERT INTO example.unexpected VALUES(42)`)
		if err := run(path, plan.Journal, "down", "1"); err == nil {
			t.Fatal("schema rollback destroyed unexpected table")
		}
		var value int
		if err := owner.QueryRow(ctx, `SELECT id FROM example.unexpected`).Scan(&value); err != nil || value != 42 {
			t.Fatal("unexpected data lost", err)
		}
		execute(`DROP TABLE example.unexpected`)
		// The schema still matches v1 after the RESTRICT failure; clear only its marker.
		mustRun(path, plan.Journal, "force", "1")
		mustRun(path, plan.Journal, "down", "1")
		check("schema missing")
		var exists bool
		if err := owner.QueryRow(ctx, `SELECT pg_catalog.to_regclass('public.schema_migrations_example') IS NOT NULL`).Scan(&exists); err != nil || !exists {
			t.Fatal("rollback dropped journal", err)
		}
		assertOthers()
		mustRun(path, plan.Journal, "up")
		check("")
	})
	t.Run("unavailable database fails closed", func(t *testing.T) { pool.Close(); check("status unavailable") })
}

func writeMigration(t *testing.T, directory, name, sql string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(directory, name), []byte(sql), 0600); err != nil {
		t.Fatal(err)
	}
}
