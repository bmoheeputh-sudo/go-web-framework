-- Use scripts/migrate-framework.sh, which refuses rollback before touching the
-- journal. Direct golang-migrate down is unsupported and can mark it dirty.
DO $$ BEGIN
    RAISE EXCEPTION 'OIDC access policy history is forward-only; use a compatible application or a forward corrective migration';
END $$;
