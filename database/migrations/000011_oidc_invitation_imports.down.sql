DO $$ BEGIN
 RAISE EXCEPTION 'OIDC invitation imports are forward-only; use a compatible application or a forward corrective migration';
END $$;
