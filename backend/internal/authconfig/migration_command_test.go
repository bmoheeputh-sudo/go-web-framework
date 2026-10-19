package authconfig

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func frameworkMigrationScript(t *testing.T) string {
	t.Helper()
	path, err := filepath.Abs("../../../scripts/migrate-framework.sh")
	if err != nil {
		t.Fatal(err)
	}
	return path
}

func TestFrameworkMigrationCommandPolicy(t *testing.T) {
	script := frameworkMigrationScript(t)
	bin := t.TempDir()
	calls := filepath.Join(bin, "calls")
	// Fake executable proves rejected operations never even initialize a driver.
	if err := os.WriteFile(filepath.Join(bin, "migrate"), []byte("#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$MIGRATE_TEST_CALLS\"\nexit \"${MIGRATE_TEST_EXIT:-0}\"\n"), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("MIGRATE_TEST_CALLS", calls)
	t.Setenv("MIGRATE_TEST_EXIT", "0")
	for _, args := range [][]string{
		nil, {"down"}, {"down", "1"}, {"down", "-all"}, {"goto", "4"}, {"goto", "6"},
		{"force", "5"}, {"drop", "-f"}, {"up"}, {"up", "0"}, {"up", "-1"},
		{"up", "1; down"}, {"up", "99999999999999999999"}, {"up", "01"},
		{"up", "1", "down"}, {"version", "down"}, {"-database", "override", "up", "1"},
	} {
		cmd := exec.Command("bash", append([]string{script}, args...)...)
		if err := cmd.Run(); err == nil {
			t.Fatalf("unsupported arguments accepted: %q", args)
		} else if exit, ok := err.(*exec.ExitError); !ok || exit.ExitCode() != 2 {
			t.Fatalf("expected policy refusal for %q: %v", args, err)
		}
		if _, err := os.Stat(calls); !os.IsNotExist(err) {
			t.Fatal("rejected operation invoked migrate")
		}
	}
	for _, args := range [][]string{{"version"}, {"up", "1"}, {"up", "5"}} {
		cmd := exec.Command("bash", append([]string{script}, args...)...)
		cmd.Dir = bin // Paths must resolve relative to the script, not the caller.
		if err := cmd.Run(); err != nil {
			t.Fatal("supported operation failed", err)
		}
		got, err := os.ReadFile(calls)
		want := "-path\n" + filepath.Dir(script) + "/../database/migrations\n-database\npostgres:///?search_path=public&x-migrations-table=schema_migrations\n" + strings.Join(args, "\n") + "\n"
		if err != nil || string(got) != want {
			t.Fatal("incorrect migration path, journal or arguments")
		}
	}
	t.Setenv("MIGRATE_TEST_EXIT", "7")
	if err := exec.Command("bash", script, "up", "1").Run(); err == nil {
		t.Fatal("migration failure hidden")
	} else if exit, ok := err.(*exec.ExitError); !ok || exit.ExitCode() != 7 {
		t.Fatal("migration exit status not preserved")
	}
}
