\set ON_ERROR_STOP on

-- =============================================================================
-- baseline/schemas/core/security.sql
-- core Schema 对象级最小权限；必须在 baseline/roles.sql 之后执行
-- =============================================================================

BEGIN;
SET LOCAL ROLE kuc_owner;

SELECT (NOT EXISTS (SELECT 1 FROM core.schema_migration WHERE version = 'baseline:core:security'))::text AS kuc_run_security \gset
\if :kuc_run_security

REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA core FROM PUBLIC;

GRANT USAGE ON SCHEMA core TO kuc_app;
GRANT SELECT ON ALL TABLES IN SCHEMA core TO kuc_app;
GRANT SELECT, INSERT, UPDATE ON core.async_operation, core.async_operation_step, core.idempotency_request TO kuc_app;
REVOKE DELETE ON ALL TABLES IN SCHEMA core FROM kuc_app;

GRANT USAGE ON SCHEMA core TO kuc_authn_writer;
GRANT SELECT ON ALL TABLES IN SCHEMA core TO kuc_authn_writer;

GRANT USAGE ON SCHEMA core TO kuc_control_writer;
GRANT SELECT ON ALL TABLES IN SCHEMA core TO kuc_control_writer;

GRANT USAGE ON SCHEMA core TO kuc_audit_writer;
GRANT SELECT ON core.data_classification TO kuc_audit_writer;
GRANT EXECUTE ON FUNCTION core.fn_hash_jsonb(jsonb) TO kuc_audit_writer;

GRANT USAGE ON SCHEMA core TO kuc_auditor;
GRANT SELECT ON core.data_dictionary, core.requirement_trace, core.security_profile, core.error_registry TO kuc_auditor;

GRANT USAGE ON SCHEMA core TO kuc_readonly;
GRANT SELECT ON ALL TABLES IN SCHEMA core TO kuc_readonly;

GRANT USAGE, CREATE ON SCHEMA core TO kuc_migrator;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA core TO kuc_migrator;
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA core TO kuc_migrator;
REVOKE ALL ON FUNCTION core.fn_apply_complete_column_comments() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION core.fn_apply_complete_column_comments() TO kuc_migrator;
REVOKE ALL ON FUNCTION core.fn_apply_complete_object_comments() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION core.fn_apply_complete_object_comments() TO kuc_migrator;

SELECT core.fn_register_migration('baseline:core:security', 'core Schema 对象权限');
COMMIT;
\else
ROLLBACK;
\endif
