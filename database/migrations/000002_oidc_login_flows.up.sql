BEGIN;
-- Shared transactions allow callbacks on any backend instance.
-- Only flow-cookie/state hashes are stored; PKCE verifier is server-only data.
CREATE TABLE public.oidc_login_flows (
    token_hash BYTEA PRIMARY KEY CHECK (octet_length(token_hash) = 32),
    state_hash BYTEA NOT NULL CHECK (octet_length(state_hash) = 32),
    nonce TEXT NOT NULL,
    pkce_verifier TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    expires_at TIMESTAMPTZ NOT NULL CHECK (expires_at > created_at)
);
CREATE INDEX oidc_login_flows_expires_at_idx ON public.oidc_login_flows (expires_at);
COMMIT;
