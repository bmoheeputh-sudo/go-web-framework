BEGIN;

CREATE SCHEMA IF NOT EXISTS framework;

-- Move the existing objects, preserving their rows, indexes, constraints and owners.
-- public.schema_migrations stays in place and remains managed by golang-migrate.
ALTER TABLE public.sessions SET SCHEMA framework;
ALTER TABLE public.oidc_login_flows SET SCHEMA framework;

-- The existing application role needs access, not schema creation privileges.
GRANT USAGE ON SCHEMA framework TO go_web_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE
    framework.sessions, framework.oidc_login_flows TO go_web_app;

COMMIT;
