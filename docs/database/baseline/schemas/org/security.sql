\set ON_ERROR_STOP on

-- =============================================================================
-- baseline/schemas/org/security.sql
-- org Schema 对象级最小权限；必须在 baseline/roles.sql 之后执行
-- =============================================================================

BEGIN;
SET LOCAL ROLE kuc_owner;

SELECT (NOT EXISTS (SELECT 1 FROM core.schema_migration WHERE version = 'baseline:org:security'))::text AS kuc_run_security \gset
\if :kuc_run_security

REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA org FROM PUBLIC;

GRANT USAGE ON SCHEMA org TO kuc_app;
GRANT SELECT ON ALL TABLES IN SCHEMA org TO kuc_app;
GRANT SELECT, INSERT, UPDATE ON org.membership, org.invitation, org.user_group,
    org.group_member, org.usage_meter TO kuc_app;
REVOKE DELETE ON ALL TABLES IN SCHEMA org FROM kuc_app;

GRANT USAGE ON SCHEMA org TO kuc_authn_writer;
GRANT SELECT ON ALL TABLES IN SCHEMA org TO kuc_authn_writer;

GRANT USAGE ON SCHEMA org TO kuc_control_writer;
GRANT SELECT, INSERT, UPDATE ON org.business_line, org.tenant, org.tenant_domain,
    org.organization TO kuc_control_writer;
REVOKE DELETE ON ALL TABLES IN SCHEMA org FROM kuc_control_writer;

GRANT USAGE ON SCHEMA org TO kuc_audit_writer;
GRANT SELECT ON org.tenant TO kuc_audit_writer;

GRANT USAGE ON SCHEMA org TO kuc_readonly;
GRANT SELECT ON ALL TABLES IN SCHEMA org TO kuc_readonly;

GRANT USAGE, CREATE ON SCHEMA org TO kuc_migrator;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA org TO kuc_migrator;
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA org TO kuc_migrator;

SELECT core.fn_register_migration('baseline:org:security', 'org Schema 对象权限');
COMMIT;
\else
ROLLBACK;
\endif
