-- Unsupported raw CLI rollback must fail visibly, never report a false clean v5.
-- Use scripts/migrate-framework.sh: it refuses rollback before journal mutation.
DO $$ BEGIN
    RAISE EXCEPTION 'authentication activation persistence is forward-only; use a compatible application or a forward corrective migration';
END $$;
