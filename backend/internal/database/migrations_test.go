package database

import (
	"context"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bmoheeputh-sudo/go-web-framework/backend/internal/testdb"
)

func TestFrameworkSchemaMigration(t *testing.T) {
	migrate, err := exec.LookPath("migrate")
	if err != nil {
		t.Skip("migration history integration test requires the golang-migrate CLI with the postgres driver")
	}
	pool, connection := testdb.New(t)
	ctx := context.Background()
	directory, err := filepath.Abs("../../../database/migrations")
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(connection)
	if err != nil {
		t.Fatal(err)
	}
	query := u.Query()
	query.Set("search_path", "public")
	u.RawQuery = query.Encode()
	run := func(args ...string) {
		t.Helper()
		ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
		defer cancel()
		command := exec.CommandContext(ctx, migrate, append([]string{"-path", directory, "-database", u.String()}, args...)...)
		// Never let inherited PostgreSQL settings redirect this command to another DB.
		for _, value := range os.Environ() {
			if !strings.HasPrefix(value, "PG") {
				command.Env = append(command.Env, value)
			}
		}
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("isolated migration %v failed: %v\n%s", args, err, output)
		}
	}
	run("goto", "2")
	if CheckSchema(ctx, pool) == nil {
		t.Fatal("application accepted old public-only schema")
	}
	// Seed the already-applied version 2 layout, including an independent table grant.
	_, err = pool.Exec(ctx, `
		CREATE ROLE session_auditor;
		GRANT SELECT ON public.sessions, public.oidc_login_flows TO session_auditor;
		INSERT INTO public.sessions
		(token_hash, issuer, subject, email, email_verified, display_name, provider, expires_at)
		VALUES (decode(repeat('ab',32),'hex'), 'https://issuer.example.invalid', 'existing-user',
		'user@example.invalid', true, 'Existing User', 'oidc', now()+interval '1 hour');
		INSERT INTO public.oidc_login_flows (token_hash, state_hash, nonce, pkce_verifier, expires_at)
		VALUES (decode(repeat('cd',32),'hex'), decode(repeat('ef',32),'hex'),
		'existing-nonce', 'existing-verifier', now()+interval '5 minutes');`)
	if err != nil {
		t.Fatal(err)
	}
	var historyOID uint32
	if err := pool.QueryRow(ctx, `SELECT 'public.schema_migrations'::regclass::oid`).Scan(&historyOID); err != nil {
		t.Fatal(err)
	}
	// Compare object identities, owners, index/constraint definitions and complete rows.
	snapshot := func(schema string) string {
		t.Helper()
		var result string
		err := pool.QueryRow(ctx, `SELECT jsonb_build_object(
			'tables', (SELECT jsonb_agg(jsonb_build_array(c.oid, c.relname, c.relowner) ORDER BY c.oid)
			 FROM pg_class c WHERE c.oid IN (($1||'.sessions')::regclass, ($1||'.oidc_login_flows')::regclass)),
			'indexes', (SELECT jsonb_agg(jsonb_build_array(i.indexrelid, i.indrelid, i.indkey::text,
			 i.indisunique, i.indisprimary, i.indisvalid) ORDER BY i.indexrelid)
			 FROM pg_index i WHERE i.indrelid IN (($1||'.sessions')::regclass, ($1||'.oidc_login_flows')::regclass)),
			'constraints', (SELECT jsonb_agg(jsonb_build_array(c.oid, c.conname, pg_get_constraintdef(c.oid)) ORDER BY c.oid)
			 FROM pg_constraint c WHERE c.conrelid IN (($1||'.sessions')::regclass, ($1||'.oidc_login_flows')::regclass))
		)::text`, schema).Scan(&result)
		if err != nil {
			t.Fatal(err)
		}
		for _, table := range []string{"sessions", "oidc_login_flows"} {
			var rows string
			// Schema/table names are fixed test constants, never input from a request.
			if err := pool.QueryRow(ctx, `SELECT jsonb_agg(to_jsonb(t) ORDER BY token_hash)::text FROM `+schema+`.`+table+` t`).Scan(&rows); err != nil {
				t.Fatal(err)
			}
			result += rows
		}
		return result
	}
	before := snapshot("public")
	check := func(schema, absent string, version int) {
		t.Helper()
		if got := snapshot(schema); got != before {
			t.Fatal("migration changed table/index/constraint identity, ownership, or data")
		}
		var currentOID uint32
		var currentVersion int
		var dirty, absentTables, grants bool
		err := pool.QueryRow(ctx, `SELECT 'public.schema_migrations'::regclass::oid, version, dirty,
			to_regclass($1||'.sessions') IS NULL AND to_regclass($1||'.oidc_login_flows') IS NULL,
			has_table_privilege('session_auditor', $2||'.sessions', 'SELECT') AND
			has_table_privilege('session_auditor', $2||'.oidc_login_flows', 'SELECT')
			FROM public.schema_migrations`, absent, schema).Scan(&currentOID, &currentVersion, &dirty, &absentTables, &grants)
		if err != nil {
			t.Fatal(err)
		}
		if currentOID != historyOID || currentVersion != version || dirty || !absentTables || !grants {
			t.Fatal("migration history, table namespace, or existing grants not preserved")
		}
	}
	run("up", "1")
	check("framework", "public", 3)
	if err := CheckSchema(ctx, pool); err != nil {
		t.Fatal(err)
	}
	var usage, create, history, tablePrivileges bool
	err = pool.QueryRow(ctx, `SELECT
		has_schema_privilege('go_web_app', 'framework', 'USAGE'),
		has_schema_privilege('go_web_app', 'framework', 'CREATE'),
		to_regclass('framework.schema_migrations') IS NOT NULL,
		(SELECT bool_and(has_table_privilege('go_web_app', t, p))
		 FROM unnest(ARRAY['framework.sessions', 'framework.oidc_login_flows']) t
		 CROSS JOIN unnest(ARRAY['SELECT', 'INSERT', 'UPDATE', 'DELETE']) p)
	`).Scan(&usage, &create, &history, &tablePrivileges)
	if err != nil || !usage || create || history || !tablePrivileges {
		t.Fatalf("unexpected schema or runtime role privileges: %v", err)
	}
	// Only migration 3 is rolled back: neither table nor its data is dropped.
	run("down", "1")
	check("public", "framework", 2)
	if CheckSchema(ctx, pool) == nil {
		t.Fatal("application accepted rolled-back schema")
	}
	run("up", "1")
	check("framework", "public", 3)
}
