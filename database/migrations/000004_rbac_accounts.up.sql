BEGIN;
CREATE TABLE framework.users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    issuer TEXT NOT NULL CHECK (issuer <> ''),
    subject TEXT NOT NULL CHECK (subject <> ''),
    email TEXT NOT NULL DEFAULT '',
    email_verified BOOLEAN NOT NULL DEFAULT FALSE,
    display_name TEXT NOT NULL DEFAULT '',
    provider TEXT NOT NULL CHECK (provider IN ('oidc', 'google_iap', 'local_dev')),
    active BOOLEAN NOT NULL DEFAULT TRUE,
    verified_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (issuer, subject)
);
CREATE TABLE framework.roles (name TEXT PRIMARY KEY CHECK (name IN ('Admin', 'User', 'Viewer')));
CREATE TABLE framework.permissions (name TEXT PRIMARY KEY, description TEXT NOT NULL);
CREATE TABLE framework.role_permissions (
    role TEXT NOT NULL REFERENCES framework.roles(name),
    permission TEXT NOT NULL REFERENCES framework.permissions(name),
    PRIMARY KEY (role, permission)
);
CREATE TABLE framework.user_roles (
    user_id UUID NOT NULL REFERENCES framework.users(id),
    role TEXT NOT NULL REFERENCES framework.roles(name),
    PRIMARY KEY (user_id, role)
);
CREATE INDEX user_roles_role_idx ON framework.user_roles(role);
CREATE TABLE framework.accounts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL CHECK (length(btrim(name)) BETWEEN 1 AND 200),
    active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE framework.user_accounts (
    user_id UUID NOT NULL REFERENCES framework.users(id),
    account_id UUID NOT NULL REFERENCES framework.accounts(id),
    PRIMARY KEY (user_id, account_id)
);
CREATE INDEX user_accounts_account_idx ON framework.user_accounts(account_id);
CREATE TABLE framework.audit_log (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    actor_user_id UUID NOT NULL REFERENCES framework.users(id),
    action TEXT NOT NULL,
    target_id TEXT NOT NULL,
    details JSONB NOT NULL
);
CREATE INDEX audit_log_actor_idx ON framework.audit_log(actor_user_id, created_at);
-- A durable one-time latch. The application role cannot write this table.
CREATE TABLE framework.admin_bootstrap (
    singleton BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (singleton),
    user_id UUID NOT NULL REFERENCES framework.users(id),
    completed_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
INSERT INTO framework.roles(name) VALUES ('Admin'), ('User'), ('Viewer');
INSERT INTO framework.permissions(name, description) VALUES
    ('admin.manage', 'Manage users, role assignments, accounts and associations'),
    ('accounts.read', 'Read explicitly linked active accounts'),
    ('accounts.write', 'Update explicitly linked active accounts');
INSERT INTO framework.role_permissions(role, permission) VALUES
    ('Admin', 'admin.manage'), ('Admin', 'accounts.read'), ('Admin', 'accounts.write'),
    ('User', 'accounts.read'), ('User', 'accounts.write'), ('Viewer', 'accounts.read');
GRANT SELECT, INSERT, UPDATE ON framework.users, framework.accounts TO go_web_app;
GRANT SELECT ON framework.roles, framework.permissions, framework.role_permissions TO go_web_app;
GRANT SELECT, INSERT, DELETE ON framework.user_roles, framework.user_accounts TO go_web_app;
GRANT SELECT, INSERT ON framework.audit_log TO go_web_app;
GRANT USAGE ON SEQUENCE framework.audit_log_id_seq TO go_web_app;
COMMIT;
