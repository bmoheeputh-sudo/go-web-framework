BEGIN;
-- Destructive: this revokes every application session. Manual approval required.
DROP TABLE public.sessions;
COMMIT;
