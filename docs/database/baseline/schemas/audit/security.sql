\set ON_ERROR_STOP on

-- =============================================================================
-- baseline/schemas/audit/security.sql
-- audit Schema 对象级最小权限；必须在 baseline/roles.sql 之后执行
-- =============================================================================

BEGIN;
SET LOCAL ROLE kuc_owner;

SELECT (NOT EXISTS (SELECT 1 FROM core.schema_migration WHERE version = 'baseline:audit:security'))::text AS kuc_run_security \gset
\if :kuc_run_security

REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA audit FROM PUBLIC;

GRANT USAGE ON SCHEMA audit TO kuc_app;
GRANT INSERT ON audit.audit_outbox TO kuc_app;
REVOKE DELETE ON ALL TABLES IN SCHEMA audit FROM kuc_app;

GRANT USAGE ON SCHEMA audit TO kuc_authn_writer;
GRANT INSERT ON audit.audit_outbox TO kuc_authn_writer;

GRANT USAGE ON SCHEMA audit TO kuc_control_writer;
GRANT INSERT ON audit.audit_outbox TO kuc_control_writer;

GRANT USAGE ON SCHEMA audit TO kuc_message_dispatcher;
GRANT INSERT ON audit.audit_outbox TO kuc_message_dispatcher;

GRANT USAGE ON SCHEMA audit TO kuc_audit_writer;
GRANT SELECT ON ALL TABLES IN SCHEMA audit TO kuc_audit_writer;
GRANT INSERT ON audit.audit_outbox, audit.audit_event, audit.audit_seal,
    audit.data_access_event TO kuc_audit_writer;
GRANT UPDATE (persistence_state, remote_persisted_at)
    ON audit.audit_outbox TO kuc_audit_writer;

GRANT USAGE ON SCHEMA audit TO kuc_auditor;
GRANT SELECT ON ALL TABLES IN SCHEMA audit TO kuc_auditor;

GRANT USAGE ON SCHEMA audit TO kuc_readonly;
GRANT SELECT ON ALL TABLES IN SCHEMA audit TO kuc_readonly;
REVOKE SELECT ON audit.audit_outbox FROM kuc_readonly;

GRANT USAGE, CREATE ON SCHEMA audit TO kuc_migrator;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA audit TO kuc_migrator;
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA audit TO kuc_migrator;

SELECT core.fn_register_migration('baseline:audit:security', 'audit Schema 对象权限');
COMMIT;
\else
ROLLBACK;
\endif
