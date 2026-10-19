-- Forward-only boundary: never delete authentication history or report a clean
-- version 4 with version-5 objects still installed. Use scripts/migrate-framework.sh
-- to reject rollback BEFORE golang-migrate touches the journal.
-- This guard is defense in depth for unsupported direct CLI use: golang-migrate
-- marks the target dirty before running SQL, so bypass requires operator recovery.
DO $$ BEGIN
    RAISE EXCEPTION 'migration 000005 cannot be rolled back; use a compatible application version or a forward corrective migration';
END $$;
