-- Use the forward-only wrapper; direct migrate down is unsupported.
DO $$ BEGIN
 RAISE EXCEPTION 'OIDC invitation approvals are forward-only; use a compatible application or a forward corrective migration';
END $$;
