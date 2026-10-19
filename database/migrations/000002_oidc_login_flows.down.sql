BEGIN;
-- Destructive: this invalidates pending OIDC logins. Manual approval required.
DROP TABLE public.oidc_login_flows;
COMMIT;
