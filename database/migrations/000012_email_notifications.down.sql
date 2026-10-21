DO $$ BEGIN RAISE EXCEPTION 'migration 000012 is forward-only; notification and observation history must be preserved'; END $$;
