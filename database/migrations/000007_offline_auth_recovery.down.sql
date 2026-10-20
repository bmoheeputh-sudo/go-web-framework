-- Recovery attribution and history are forward-only. A destructive down
-- migration could erase forensic evidence or leave activation history falsely
-- attributed. Use a compatible application or a forward corrective migration.
DO $$ BEGIN
    RAISE EXCEPTION 'offline authentication recovery history is forward-only; use a compatible application or a forward corrective migration';
END $$;
