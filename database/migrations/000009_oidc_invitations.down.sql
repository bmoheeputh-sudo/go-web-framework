-- The supported wrapper refuses down before touching the migration journal.
DO $$ BEGIN
 RAISE EXCEPTION 'OIDC invitation history is forward-only; use a compatible application or a forward corrective migration';
END $$;
