BEGIN;

-- Roll back only the namespace change; preserve all rows and migration history.
ALTER TABLE framework.sessions SET SCHEMA public;
ALTER TABLE framework.oidc_login_flows SET SCHEMA public;

-- Leave the schema and grants intact: other objects may now depend on them.
COMMIT;
