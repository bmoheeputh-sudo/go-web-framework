// Package testdb creates disposable PostgreSQL clusters for integration tests.
// It never reads DB_* variables or connects to the application's database.
package testdb

import (
	"context"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

func New(t *testing.T) (*pgxpool.Pool, string) {
	t.Helper()
	bin := os.Getenv("PG_TEST_BIN")
	if bin == "" {
		bin = "/usr/lib/postgresql/14/bin"
	}
	if _, err := os.Stat(filepath.Join(bin, "initdb")); err != nil {
		t.Skip("PostgreSQL integration tests require local PostgreSQL binaries (set PG_TEST_BIN)")
	}
	directory, err := os.MkdirTemp("", "gwf-test-pg-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	data := filepath.Join(directory, "data")
	run := func(name string, args ...string) {
		t.Helper()
		output, err := exec.Command(filepath.Join(bin, name), args...).CombinedOutput()
		if err != nil {
			t.Fatalf("isolated PostgreSQL %s failed: %v\n%s", name, err, output)
		}
	}
	run("initdb", "-D", data, "-U", "postgres", "-A", "trust", "--no-locale", "-E", "UTF8")
	// No TCP listener; the trusted Unix socket is inside an owner-only directory.
	run("pg_ctl", "-D", data, "-l", filepath.Join(directory, "postgres.log"), "-w", "-t", "10",
		"-o", "-F -c listen_addresses='' -c unix_socket_permissions=0700 -k "+directory, "start")
	t.Cleanup(func() {
		if err := exec.Command(filepath.Join(bin, "pg_ctl"), "-D", data, "-m", "immediate", "-w", "stop").Run(); err != nil {
			t.Error("could not stop isolated PostgreSQL test cluster")
		}
	})
	connection := "postgres://postgres@/postgres?" + url.Values{"host": {directory}, "sslmode": {"disable"}}.Encode()
	pool, err := pgxpool.New(context.Background(), connection)
	if err != nil {
		t.Fatal("test pool creation failed")
	}
	t.Cleanup(pool.Close)
	if err := pool.Ping(context.Background()); err != nil {
		t.Fatal("isolated test database unavailable")
	}
	if _, err := pool.Exec(context.Background(), "CREATE ROLE go_web_app LOGIN"); err != nil {
		t.Fatal("could not create isolated application role")
	}
	return pool, connection
}

func Migrations(t *testing.T, pool *pgxpool.Pool, direction string) {
	t.Helper()
	_, file, _, _ := runtime.Caller(0)
	paths, err := filepath.Glob(filepath.Join(filepath.Dir(file), "../../../database/migrations/*."+direction+".sql"))
	if err != nil || len(paths) == 0 {
		t.Fatal("expected versioned migration files")
	}
	if direction == "down" {
		slices.Reverse(paths)
	}
	for _, path := range paths {
		contents, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(context.Background(), string(contents)); err != nil {
			t.Fatalf("test migration %s failed: %v", filepath.Base(path), err)
		}
	}
}
