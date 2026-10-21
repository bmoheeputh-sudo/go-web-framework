DO $$ BEGIN RAISE EXCEPTION 'migration 000013 is forward-only; retain connector authorization and readiness history'; END $$;
