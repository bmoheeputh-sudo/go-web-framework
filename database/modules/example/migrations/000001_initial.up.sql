-- Manual installation only. Journal: public.schema_migrations_example.
-- Fail on an existing schema rather than adopting untracked objects.
BEGIN;
CREATE SCHEMA example AUTHORIZATION go_web_app;
GRANT USAGE ON SCHEMA example TO go_web_app;
COMMIT;
