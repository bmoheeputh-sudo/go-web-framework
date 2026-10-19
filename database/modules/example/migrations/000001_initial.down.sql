-- Manual rollback only. RESTRICT (the default) protects unexpected objects.
-- Keep public.schema_migrations_example: golang-migrate owns its version state.
BEGIN;
DROP SCHEMA example RESTRICT;
COMMIT;
