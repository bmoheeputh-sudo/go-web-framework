-- Destructive rollback of Phase 5 only. Export RBAC data and audit records first.
-- Sessions, OIDC flows, the framework schema, and public migration history remain.
BEGIN;
DROP TABLE framework.admin_bootstrap;
DROP TABLE framework.audit_log;
DROP TABLE framework.user_accounts;
DROP TABLE framework.user_roles;
DROP TABLE framework.role_permissions;
DROP TABLE framework.accounts;
DROP TABLE framework.permissions;
DROP TABLE framework.roles;
DROP TABLE framework.users;
COMMIT;
