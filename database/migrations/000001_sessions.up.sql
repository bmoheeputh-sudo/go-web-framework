BEGIN;
CREATE TABLE public.sessions (
    token_hash BYTEA PRIMARY KEY CHECK (octet_length(token_hash) = 32),
    issuer TEXT NOT NULL CHECK (issuer <> ''),
    subject TEXT NOT NULL CHECK (subject <> ''),
    email TEXT NOT NULL DEFAULT '',
    email_verified BOOLEAN NOT NULL DEFAULT FALSE,
    display_name TEXT NOT NULL DEFAULT '',
    provider TEXT NOT NULL CHECK (provider = 'oidc'),
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    expires_at TIMESTAMPTZ NOT NULL,
    last_activity_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    CHECK (expires_at > created_at),
    CHECK (last_activity_at >= created_at)
);
CREATE INDEX sessions_expires_at_idx ON public.sessions (expires_at);
CREATE INDEX sessions_last_activity_at_idx ON public.sessions (last_activity_at);
CREATE INDEX sessions_identity_idx ON public.sessions (issuer, subject);
COMMIT;
