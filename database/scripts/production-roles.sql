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
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='go_web_notification_worker') THEN
    CREATE ROLE go_web_notification_worker LOGIN NOINHERIT;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='go_web_app') THEN
    RAISE EXCEPTION 'historical migrations require the existing go_web_app role';
  END IF;
  IF EXISTS (SELECT 1 FROM pg_auth_members m JOIN pg_roles r ON r.oid=m.member
             WHERE r.rolname IN ('go_web_app_runtime','go_web_notification_worker')) THEN
    RAISE EXCEPTION 'runtime and notification worker roles must not be members of another role';
  END IF;
END;
$$;
ALTER ROLE go_web_app_migrator NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOINHERIT;
ALTER ROLE go_web_app_runtime NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOINHERIT;
ALTER ROLE go_web_notification_worker NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOINHERIT;

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

REVOKE ALL ON SCHEMA framework FROM PUBLIC,go_web_app,go_web_app_runtime,go_web_notification_worker;
REVOKE ALL ON ALL TABLES IN SCHEMA framework FROM PUBLIC,go_web_app,go_web_app_runtime,go_web_notification_worker;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA framework FROM PUBLIC,go_web_app,go_web_app_runtime,go_web_notification_worker;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA framework FROM PUBLIC,go_web_app,go_web_app_runtime,go_web_notification_worker;
-- PostgreSQL 14 grants CREATE on public to PUBLIC by default. A dedicated
-- database must remove it or the runtime can create unrelated objects there.
REVOKE CREATE ON SCHEMA public FROM PUBLIC,go_web_app_runtime,go_web_notification_worker;
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
-- Optional storage foundation, introduced in 000008. Keep this proposal usable
-- on version 7; no grants or policies are applied to the live deployment.
DO $$
BEGIN
  IF to_regclass('framework.oidc_access_policies') IS NOT NULL THEN
    GRANT SELECT,INSERT,UPDATE ON framework.oidc_access_policies,framework.oidc_identity_approvals TO go_web_app_runtime;
    GRANT EXECUTE ON FUNCTION framework.valid_access_domains(TEXT[]) TO go_web_app_runtime;
  END IF;
  IF to_regclass('framework.oidc_invitations') IS NOT NULL THEN
    GRANT SELECT,INSERT,UPDATE ON framework.oidc_invitations TO go_web_app_runtime;
    GRANT EXECUTE ON FUNCTION framework.invitation_email_key(TEXT) TO go_web_app_runtime;
  END IF;
  IF to_regclass('framework.oidc_invitation_imports') IS NOT NULL THEN
    GRANT SELECT,INSERT ON framework.oidc_invitation_imports TO go_web_app_runtime;
    GRANT SELECT ON framework.oidc_invitation_import_keys TO go_web_app_runtime;
  END IF;
  IF to_regclass('framework.notification_jobs') IS NOT NULL THEN
    GRANT SELECT,INSERT ON framework.notification_requests TO go_web_app_runtime;
    GRANT SELECT,INSERT,UPDATE ON framework.notification_connectors,framework.notification_jobs,framework.notification_attempts,framework.notification_suppressions TO go_web_app_runtime;
    -- Optional future worker login. No credentials are provisioned or worker started.
    GRANT USAGE ON SCHEMA framework TO go_web_notification_worker;
    GRANT SELECT ON framework.notification_requests,framework.notification_jobs,framework.notification_attempts,framework.notification_connectors,framework.notification_suppressions,
      framework.users,framework.user_roles,framework.role_permissions,framework.roles,framework.oidc_access_policies,framework.oidc_identity_approvals,framework.oidc_invitations,
      framework.auth_activation_heads,framework.auth_config_lifecycle TO go_web_notification_worker;
    GRANT SELECT(id,deployment_id,environment,issuer_url,client_id,provider) ON framework.auth_config_revisions TO go_web_notification_worker;
    GRANT UPDATE(status,generation,lease_owner,lease_expires_at,attempt_count,disposition_code,updated_by,updated_at) ON framework.notification_jobs TO go_web_notification_worker;
    GRANT UPDATE(generation,failure_count,last_error_code,last_accepted_at,updated_by,updated_at) ON framework.notification_connectors TO go_web_notification_worker;
    GRANT INSERT ON framework.notification_attempts TO go_web_notification_worker;
    GRANT UPDATE(outcome,completed_at,provider_message_id,error_code) ON framework.notification_attempts TO go_web_notification_worker;
    GRANT INSERT ON framework.audit_log TO go_web_notification_worker;
    GRANT USAGE ON SEQUENCE framework.audit_log_id_seq TO go_web_notification_worker;
    GRANT EXECUTE ON FUNCTION framework.invitation_email_key(TEXT) TO go_web_notification_worker;
    GRANT EXECUTE ON FUNCTION framework.valid_access_domains(TEXT[]) TO go_web_notification_worker;
  END IF;
  IF to_regclass('framework.notification_connector_readiness') IS NOT NULL THEN
    GRANT SELECT,INSERT,UPDATE ON framework.notification_connector_readiness,framework.notification_connector_oauth_flows TO go_web_app_runtime;
    GRANT SELECT ON framework.notification_connector_readiness TO go_web_notification_worker;
  END IF;
END $$;
-- admin_bootstrap is deliberately excluded: its one-time command uses an
-- operator/migrator credential, not the ordinary HTTP runtime credential.

-- New framework functions must not inherit PostgreSQL's PUBLIC EXECUTE default.
ALTER DEFAULT PRIVILEGES FOR ROLE go_web_app_migrator REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
-- No default table grants: each future migration must explicitly review and
-- grant its own runtime DML. Module schemas need a separate privilege review.
COMMIT;
