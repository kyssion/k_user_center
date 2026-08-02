\set ON_ERROR_STOP on

-- =============================================================================
-- baseline/schemas/assurance/security.sql
-- assurance Schema 对象级最小权限；必须在 baseline/roles.sql 之后执行
-- =============================================================================

BEGIN;
SET LOCAL ROLE kuc_owner;

SELECT (NOT EXISTS (SELECT 1 FROM core.schema_migration WHERE version = 'baseline:assurance:security'))::text AS kuc_run_security \gset
\if :kuc_run_security

REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA assurance FROM PUBLIC;

GRANT USAGE ON SCHEMA assurance TO kuc_app;
GRANT SELECT ON ALL TABLES IN SCHEMA assurance TO kuc_app;
REVOKE SELECT ON assurance.recovery_request FROM kuc_app;
REVOKE DELETE ON ALL TABLES IN SCHEMA assurance FROM kuc_app;

GRANT USAGE ON SCHEMA assurance TO kuc_authn_writer;
GRANT SELECT ON ALL TABLES IN SCHEMA assurance TO kuc_authn_writer;

GRANT USAGE ON SCHEMA assurance TO kuc_control_writer;
GRANT SELECT ON ALL TABLES IN SCHEMA assurance TO kuc_control_writer;
GRANT SELECT, INSERT, UPDATE ON ALL TABLES IN SCHEMA assurance TO kuc_control_writer;
REVOKE DELETE ON ALL TABLES IN SCHEMA assurance FROM kuc_control_writer;

GRANT USAGE ON SCHEMA assurance TO kuc_readonly;
GRANT SELECT ON ALL TABLES IN SCHEMA assurance TO kuc_readonly;

GRANT USAGE, CREATE ON SCHEMA assurance TO kuc_migrator;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA assurance TO kuc_migrator;
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA assurance TO kuc_migrator;

SELECT core.fn_register_migration('baseline:assurance:security', 'assurance Schema 对象权限');
COMMIT;
\else
ROLLBACK;
\endif
