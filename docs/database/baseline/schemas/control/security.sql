\set ON_ERROR_STOP on

-- =============================================================================
-- baseline/schemas/control/security.sql
-- control Schema 对象级最小权限；必须在 baseline/roles.sql 之后执行
-- =============================================================================

BEGIN;
SET LOCAL ROLE kuc_owner;

SELECT (NOT EXISTS (SELECT 1 FROM core.schema_migration WHERE version = 'baseline:control:security'))::text AS kuc_run_security \gset
\if :kuc_run_security

REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA control FROM PUBLIC;

GRANT USAGE ON SCHEMA control TO kuc_control_writer;
GRANT SELECT ON ALL TABLES IN SCHEMA control TO kuc_control_writer;
GRANT SELECT, INSERT, UPDATE ON ALL TABLES IN SCHEMA control TO kuc_control_writer;
REVOKE DELETE ON ALL TABLES IN SCHEMA control FROM kuc_control_writer;

GRANT USAGE ON SCHEMA control TO kuc_audit_writer;
GRANT SELECT ON control.approval_case TO kuc_audit_writer;

GRANT USAGE ON SCHEMA control TO kuc_auditor;
GRANT SELECT ON ALL TABLES IN SCHEMA control TO kuc_auditor;

GRANT USAGE ON SCHEMA control TO kuc_readonly;
GRANT SELECT ON ALL TABLES IN SCHEMA control TO kuc_readonly;

GRANT USAGE, CREATE ON SCHEMA control TO kuc_migrator;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA control TO kuc_migrator;
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA control TO kuc_migrator;

SELECT core.fn_register_migration('baseline:control:security', 'control Schema 对象权限');
COMMIT;
\else
ROLLBACK;
\endif
