\set ON_ERROR_STOP on

-- =============================================================================
-- baseline/schemas/workload/security.sql
-- workload Schema 对象级最小权限；必须在 baseline/roles.sql 之后执行
-- =============================================================================

BEGIN;
SET LOCAL ROLE kuc_owner;

SELECT (NOT EXISTS (SELECT 1 FROM core.schema_migration WHERE version = 'baseline:workload:security'))::text AS kuc_run_security \gset
\if :kuc_run_security

REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA workload FROM PUBLIC;

GRANT USAGE ON SCHEMA workload TO kuc_app;
GRANT SELECT ON ALL TABLES IN SCHEMA workload TO kuc_app;
REVOKE SELECT ON workload.machine_credential FROM kuc_app;
REVOKE DELETE ON ALL TABLES IN SCHEMA workload FROM kuc_app;

GRANT USAGE ON SCHEMA workload TO kuc_authn_writer;
GRANT SELECT ON ALL TABLES IN SCHEMA workload TO kuc_authn_writer;
GRANT SELECT, INSERT, UPDATE ON workload.token_exchange TO kuc_authn_writer;

GRANT USAGE ON SCHEMA workload TO kuc_control_writer;
GRANT SELECT, INSERT, UPDATE ON workload.machine_principal, workload.machine_credential,
    workload.trust_bundle, workload.workload_attestation TO kuc_control_writer;
REVOKE DELETE ON ALL TABLES IN SCHEMA workload FROM kuc_control_writer;

GRANT USAGE ON SCHEMA workload TO kuc_readonly;
GRANT SELECT ON ALL TABLES IN SCHEMA workload TO kuc_readonly;
REVOKE SELECT ON workload.machine_credential FROM kuc_readonly;

GRANT USAGE, CREATE ON SCHEMA workload TO kuc_migrator;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA workload TO kuc_migrator;
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA workload TO kuc_migrator;

SELECT core.fn_register_migration('baseline:workload:security', 'workload Schema 对象权限');
COMMIT;
\else
ROLLBACK;
\endif
