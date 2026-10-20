-- PROPOSAL: run manually as a database administrator in a dedicated production
-- database after migrations 000001-000007. Never run during application startup.
-- The operator provisions LOGIN passwords outside this file and updates DB_USER.
BEGIN;

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='go_web_app_migrator') THEN
    CREATE ROLE go_web_app_migrator LOGIN NOINHERIT;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='go_web_app_runtime') THEN
    CREATE ROLE go_web_app_runtime LOGIN NOINHERIT;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='go_web_app') THEN
    RAISE EXCEPTION 'historical migrations require the existing go_web_app role';
  END IF;
  IF EXISTS (SELECT 1 FROM pg_auth_members m JOIN pg_roles r ON r.oid=m.member
             WHERE r.rolname='go_web_app_runtime') THEN
    RAISE EXCEPTION 'runtime role must not be a member of another role';
  END IF;
END;
$$;
ALTER ROLE go_web_app_migrator NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOINHERIT;
ALTER ROLE go_web_app_runtime NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOINHERIT;

-- Transfer only known framework objects. Indexes/triggers belong to tables;
-- sequences and trigger functions are transferred separately.
DO $$
DECLARE o record;
BEGIN
  FOR o IN SELECT c.relname, c.relkind FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
           WHERE n.nspname='framework' AND c.relkind IN ('r','p','S') LOOP
    IF o.relkind='S' THEN
      EXECUTE format('ALTER SEQUENCE framework.%I OWNER TO go_web_app_migrator',o.relname);
    ELSE
      EXECUTE format('ALTER TABLE framework.%I OWNER TO go_web_app_migrator',o.relname);
    END IF;
  END LOOP;
  FOR o IN SELECT p.proname, pg_get_function_identity_arguments(p.oid) AS args
           FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='framework' LOOP
    EXECUTE format('ALTER FUNCTION framework.%I(%s) OWNER TO go_web_app_migrator',o.proname,o.args);
  END LOOP;
  IF to_regclass('public.schema_migrations') IS NOT NULL THEN
    ALTER TABLE public.schema_migrations OWNER TO go_web_app_migrator;
  END IF;
END;
$$;
ALTER SCHEMA framework OWNER TO go_web_app_migrator;

REVOKE ALL ON SCHEMA framework FROM PUBLIC,go_web_app,go_web_app_runtime;
REVOKE ALL ON ALL TABLES IN SCHEMA framework FROM PUBLIC,go_web_app,go_web_app_runtime;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA framework FROM PUBLIC,go_web_app,go_web_app_runtime;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA framework FROM PUBLIC,go_web_app,go_web_app_runtime;
-- PostgreSQL 14 grants CREATE on public to PUBLIC by default. A dedicated
-- database must remove it or the runtime can create unrelated objects there.
REVOKE CREATE ON SCHEMA public FROM PUBLIC,go_web_app_runtime;
GRANT USAGE,CREATE ON SCHEMA public TO go_web_app_migrator;
GRANT USAGE ON SCHEMA framework TO go_web_app_runtime;

GRANT SELECT,INSERT,UPDATE,DELETE ON framework.sessions,framework.oidc_login_flows TO go_web_app_runtime;
GRANT SELECT,INSERT,UPDATE ON framework.users,framework.accounts TO go_web_app_runtime;
GRANT SELECT ON framework.roles TO go_web_app_runtime;
GRANT SELECT,INSERT ON framework.permissions TO go_web_app_runtime;
GRANT SELECT,INSERT,DELETE ON framework.role_permissions,framework.user_roles,framework.user_accounts TO go_web_app_runtime;
GRANT SELECT,INSERT ON framework.audit_log TO go_web_app_runtime;
GRANT SELECT ON framework.auth_config_revisions TO go_web_app_runtime;
GRANT INSERT ON framework.auth_config_revisions TO go_web_app_runtime;
GRANT SELECT,INSERT,UPDATE ON framework.auth_config_lifecycle,framework.auth_activation_heads TO go_web_app_runtime;
GRANT SELECT,INSERT ON framework.auth_activation_history,framework.auth_test_evidence,framework.auth_recovery_audit TO go_web_app_runtime;
GRANT USAGE ON SEQUENCE framework.audit_log_id_seq TO go_web_app_runtime;
-- admin_bootstrap is deliberately excluded: its one-time command uses an
-- operator/migrator credential, not the ordinary HTTP runtime credential.

-- New framework functions must not inherit PostgreSQL's PUBLIC EXECUTE default.
ALTER DEFAULT PRIVILEGES FOR ROLE go_web_app_migrator REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
-- No default table grants: each future migration must explicitly review and
-- grant its own runtime DML. Module schemas need a separate privilege review.
COMMIT;
