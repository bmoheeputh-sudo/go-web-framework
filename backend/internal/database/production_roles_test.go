package database

import (
	"context"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/bmoheeputh-sudo/go-web-framework/backend/internal/testdb"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestProposedProductionRolesInDisposableCluster(t *testing.T) {
	owner, dsn := testdb.New(t)
	testdb.Migrations(t, owner, "up")
	ctx := context.Background()
	if _, err := owner.Exec(ctx, `CREATE TABLE public.schema_migrations(version bigint NOT NULL,dirty boolean NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	_, file, _, _ := runtime.Caller(0)
	script, err := os.ReadFile(filepath.Join(filepath.Dir(file), "../../../database/scripts/production-roles.sql"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := owner.Exec(ctx, string(script)); err != nil {
		t.Fatalf("production role proposal cannot be applied to isolated cluster: %v", err)
	}
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	u.User = url.User("go_web_app_runtime")
	app, err := pgxpool.New(ctx, u.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(app.Close)
	if err := app.Ping(ctx); err != nil {
		t.Fatal(err)
	}
	// Keep this inventory in sync with the exact framework tables in migrations.
	rights := map[string]string{
		"sessions": "SELECT,INSERT,UPDATE,DELETE", "oidc_login_flows": "SELECT,INSERT,UPDATE,DELETE",
		"users": "SELECT,INSERT,UPDATE", "accounts": "SELECT,INSERT,UPDATE",
		"roles": "SELECT", "permissions": "SELECT,INSERT",
		"role_permissions": "SELECT,INSERT,DELETE", "user_roles": "SELECT,INSERT,DELETE",
		"user_accounts": "SELECT,INSERT,DELETE", "audit_log": "SELECT,INSERT",
		"auth_config_revisions": "SELECT,INSERT", "auth_config_lifecycle": "SELECT,INSERT,UPDATE",
		"auth_activation_heads": "SELECT,INSERT,UPDATE", "auth_activation_history": "SELECT,INSERT",
		"auth_test_evidence": "SELECT,INSERT", "auth_recovery_audit": "SELECT,INSERT",
		"admin_bootstrap": "",
	}
	rows, err := owner.Query(ctx, `SELECT relname FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='framework' AND c.relkind IN ('r','p')`)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatal(err)
		}
		names = append(names, name)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if len(names) != len(rights) {
		t.Fatalf("framework table inventory changed: %v", names)
	}
	for _, name := range names {
		allowed, ok := rights[name]
		if !ok {
			t.Fatalf("unreviewed framework table: %s", name)
		}
		for _, privilege := range []string{"SELECT", "INSERT", "UPDATE", "DELETE", "TRUNCATE", "REFERENCES", "TRIGGER"} {
			var granted bool
			if err := owner.QueryRow(ctx, `SELECT has_table_privilege('go_web_app_runtime',$1,$2)`, "framework."+name, privilege).Scan(&granted); err != nil {
				t.Fatal(err)
			}
			want := false
			for _, part := range []string{"SELECT", "INSERT", "UPDATE", "DELETE"} {
				if part == privilege && containsPrivilege(allowed, part) {
					want = true
				}
			}
			if granted != want {
				t.Fatalf("%s %s grant = %v, want %v", name, privilege, granted, want)
			}
		}
	}
	var schemaUse, schemaCreate, seqUse, functionExec, member, definer bool
	if err := owner.QueryRow(ctx, `SELECT
  has_schema_privilege('go_web_app_runtime','framework','USAGE'),
  has_schema_privilege('go_web_app_runtime','framework','CREATE'),
  has_sequence_privilege('go_web_app_runtime','framework.audit_log_id_seq','USAGE'),
  has_function_privilege('go_web_app_runtime','framework.preserve_auth_config_revision()','EXECUTE'),
  EXISTS(SELECT 1 FROM pg_auth_members m JOIN pg_roles r ON r.oid=m.member WHERE r.rolname='go_web_app_runtime'),
  EXISTS(SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='framework' AND p.prosecdef)`).Scan(&schemaUse, &schemaCreate, &seqUse, &functionExec, &member, &definer); err != nil {
		t.Fatal(err)
	}
	if !schemaUse || schemaCreate || !seqUse || functionExec || member || definer {
		t.Fatal("schema, sequence, function, membership or SECURITY DEFINER boundary is wrong")
	}
	var oldRoleUse, oldRoleAuditInsert bool
	if err := owner.QueryRow(ctx, `SELECT has_schema_privilege('go_web_app','framework','USAGE'),has_table_privilege('go_web_app','framework.audit_log','INSERT')`).Scan(&oldRoleUse, &oldRoleAuditInsert); err != nil {
		t.Fatal(err)
	}
	if oldRoleUse || oldRoleAuditInsert {
		t.Fatal("historical shared application role retained framework privileges")
	}
	var functionCount, triggerCount, sequenceCount int
	if err := owner.QueryRow(ctx, `SELECT
 (SELECT count(*) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='framework'),
 (SELECT count(*) FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='framework' AND NOT t.tgisinternal),
 (SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='framework' AND c.relkind='S')`).Scan(&functionCount, &triggerCount, &sequenceCount); err != nil {
		t.Fatal(err)
	}
	if functionCount != 7 || triggerCount != 19 || sequenceCount != 1 {
		t.Fatalf("review framework functions/triggers/sequences: %d/%d/%d", functionCount, triggerCount, sequenceCount)
	}
	var actor string
	if err := app.QueryRow(ctx, `INSERT INTO framework.users(issuer,subject,provider) VALUES('https://issuer.example.test','role-test','oidc') RETURNING id::text`).Scan(&actor); err != nil {
		t.Fatalf("legitimate user insert failed: %v", err)
	}
	if _, err := app.Exec(ctx, `UPDATE framework.users SET display_name='Role Test' WHERE id=$1`, actor); err != nil {
		t.Fatalf("legitimate user update failed: %v", err)
	}
	if _, err := app.Exec(ctx, `INSERT INTO framework.audit_log(actor_user_id,action,target_id,details) VALUES($1::uuid,'role.test',$1::text,'{}')`, actor); err != nil {
		t.Fatalf("atomic audit insert needs table and sequence rights: %v", err)
	}
	if _, err := app.Exec(ctx, `INSERT INTO framework.sessions(token_hash,issuer,subject,provider,expires_at)
 VALUES(decode(repeat('ab',32),'hex'),'https://issuer.example.test','role-test','oidc',clock_timestamp()+interval '1 hour')`); err != nil {
		t.Fatalf("session creation failed: %v", err)
	}
	if _, err := app.Exec(ctx, `UPDATE framework.sessions SET last_activity_at=clock_timestamp() WHERE token_hash=decode(repeat('ab',32),'hex')`); err != nil {
		t.Fatalf("session activity update failed: %v", err)
	}
	if _, err := app.Exec(ctx, `DELETE FROM framework.sessions WHERE token_hash=decode(repeat('ab',32),'hex')`); err != nil {
		t.Fatalf("session revocation failed: %v", err)
	}
	if _, err := app.Exec(ctx, `INSERT INTO framework.oidc_login_flows(token_hash,state_hash,nonce,pkce_verifier,expires_at)
 VALUES(decode(repeat('ab',32),'hex'),decode(repeat('cd',32),'hex'),'nonce','verifier',clock_timestamp()+interval '5 minutes')`); err != nil {
		t.Fatalf("OIDC flow creation failed: %v", err)
	}
	if _, err := app.Exec(ctx, `DELETE FROM framework.oidc_login_flows WHERE token_hash=decode(repeat('ab',32),'hex')`); err != nil {
		t.Fatalf("one-time OIDC flow consumption failed: %v", err)
	}
	// Exercise the grants and existing deferred constraints used by an atomic
	// activation. This uses synthetic data only in the disposable cluster.
	const revision = "11111111-1111-4111-8111-111111111111"
	tx, err := app.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_, err = tx.Exec(ctx, `INSERT INTO framework.auth_config_revisions(id,deployment_id,environment,configuration_version,provider,issuer_url,client_id,redirect_uri,secret_ciphertext,secret_nonce,encryption_format,encryption_key_id,created_by)
 VALUES($1,'role-test','test',1,'oidc','https://issuer.example.test','synthetic-client','https://app.example.test/api/auth/callback',decode(repeat('00',17),'hex'),decode(repeat('00',12),'hex'),1,'synthetic',$2)`, revision, actor)
	if err == nil {
		_, err = tx.Exec(ctx, `INSERT INTO framework.auth_config_lifecycle(revision_id,deployment_id,environment,updated_by) VALUES($1,'role-test','test',$2)`, revision, actor)
	}
	if err == nil {
		err = tx.Commit(ctx)
	} else {
		_ = tx.Rollback(ctx)
	}
	if err != nil {
		t.Fatalf("immutable draft transaction failed: %v", err)
	}
	for _, state := range []string{"validated", "approved"} {
		if _, err := app.Exec(ctx, `UPDATE framework.auth_config_lifecycle SET status=$2,generation=generation+1,validation='{"check":"static","version":1}' WHERE revision_id=$1`, revision, state); err != nil {
			t.Fatalf("lifecycle %s failed: %v", state, err)
		}
	}
	tx, err = app.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var activatedAt string
	if err = tx.QueryRow(ctx, `SELECT clock_timestamp()::text`).Scan(&activatedAt); err == nil {
		_, err = tx.Exec(ctx, `UPDATE framework.auth_config_lifecycle SET status='active',generation=generation+1 WHERE revision_id=$1`, revision)
	}
	if err == nil {
		_, err = tx.Exec(ctx, `INSERT INTO framework.auth_activation_history(deployment_id,environment,generation,target_revision_id,actor_user_id,activated_at,transition_deadline,reason)
 VALUES('role-test','test',1,$1,$2,$3::timestamptz,$3::timestamptz,'synthetic role verification')`, revision, actor, activatedAt)
	}
	if err == nil {
		_, err = tx.Exec(ctx, `INSERT INTO framework.auth_activation_heads(deployment_id,environment,generation,runtime_source,active_revision_id,activated_at)
 VALUES('role-test','test',1,'database',$1,$2::timestamptz)`, revision, activatedAt)
	}
	if err == nil {
		_, err = tx.Exec(ctx, `INSERT INTO framework.audit_log(actor_user_id,action,target_id,details) VALUES($1,'auth_config.activated',$2,'{}')`, actor, revision)
	}
	if err == nil {
		_, err = tx.Exec(ctx, `SELECT pg_notify('framework_auth_activation','role-test/test/1')`)
	}
	if err == nil {
		err = tx.Commit(ctx)
	} else {
		_ = tx.Rollback(ctx)
	}
	if err != nil {
		t.Fatalf("synthetic activation/audit transaction failed under runtime grants: %v", err)
	}
	for name, statement := range map[string]string{
		"audit update":          `UPDATE framework.audit_log SET action='tampered'`,
		"audit delete":          `DELETE FROM framework.audit_log`,
		"audit truncate":        `TRUNCATE framework.audit_log`,
		"history update":        `UPDATE framework.auth_activation_history SET reason='tampered'`,
		"history delete":        `DELETE FROM framework.auth_activation_history`,
		"evidence update":       `UPDATE framework.auth_test_evidence SET subject='tampered'`,
		"recovery audit delete": `DELETE FROM framework.auth_recovery_audit`,
		"schema DDL":            `CREATE TABLE framework.runtime_must_not_create(id int)`,
		"public DDL":            `CREATE TABLE public.runtime_must_not_create(id int)`,
		"migration journal":     `INSERT INTO public.schema_migrations(version,dirty) VALUES(7,false)`,
		"bootstrap":             `INSERT INTO framework.admin_bootstrap(user_id) VALUES(NULL)`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := app.Exec(ctx, statement); err == nil {
				t.Fatal("runtime role accepted prohibited operation")
			}
		})
	}
	var ownerName string
	if err := owner.QueryRow(ctx, `SELECT pg_get_userbyid(relowner) FROM pg_class WHERE oid='framework.audit_log'::regclass`).Scan(&ownerName); err != nil || ownerName != "go_web_app_migrator" {
		t.Fatalf("audit table owner = %q: %v", ownerName, err)
	}
	if err := owner.QueryRow(ctx, `SELECT pg_get_userbyid(relowner) FROM pg_class WHERE oid='public.schema_migrations'::regclass`).Scan(&ownerName); err != nil || ownerName != "go_web_app_migrator" {
		t.Fatalf("migration journal owner = %q: %v", ownerName, err)
	}
}

func containsPrivilege(list, privilege string) bool {
	for _, item := range strings.Split(list, ",") {
		if item == privilege {
			return true
		}
	}
	return false
}
