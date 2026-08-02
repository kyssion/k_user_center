\set ON_ERROR_STOP on

-- =============================================================================
-- baseline/schemas/authz/security.sql
-- authz Schema 对象级最小权限；必须在 baseline/roles.sql 之后执行
-- =============================================================================

BEGIN;
SET LOCAL ROLE kuc_owner;

SELECT (NOT EXISTS (SELECT 1 FROM core.schema_migration WHERE version = 'baseline:authz:security'))::text AS kuc_run_security \gset
\if :kuc_run_security

REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA authz FROM PUBLIC;

GRANT USAGE ON SCHEMA authz TO kuc_app;
GRANT SELECT ON ALL TABLES IN SCHEMA authz TO kuc_app;
GRANT SELECT, INSERT, UPDATE ON authz.relationship_tuple TO kuc_app;
GRANT INSERT ON authz.authorization_decision TO kuc_app;
REVOKE DELETE ON ALL TABLES IN SCHEMA authz FROM kuc_app;

GRANT USAGE ON SCHEMA authz TO kuc_control_writer;
GRANT SELECT, INSERT, UPDATE ON authz.permission, authz.role, authz.role_permission,
    authz.role_exclusion, authz.role_assignment, authz.policy_release, authz.obligation_type,
    authz.pep_capability, authz.access_review, authz.permission_simulation TO kuc_control_writer;
REVOKE DELETE ON ALL TABLES IN SCHEMA authz FROM kuc_control_writer;

GRANT USAGE ON SCHEMA authz TO kuc_audit_writer;
GRANT SELECT ON authz.authorization_decision TO kuc_audit_writer;

GRANT USAGE ON SCHEMA authz TO kuc_readonly;
GRANT SELECT ON ALL TABLES IN SCHEMA authz TO kuc_readonly;

GRANT USAGE, CREATE ON SCHEMA authz TO kuc_migrator;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA authz TO kuc_migrator;
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA authz TO kuc_migrator;

SELECT core.fn_register_migration('baseline:authz:security', 'authz Schema 对象权限');
COMMIT;
\else
ROLLBACK;
\endif
