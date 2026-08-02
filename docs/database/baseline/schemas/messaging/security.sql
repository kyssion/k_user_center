\set ON_ERROR_STOP on

-- =============================================================================
-- baseline/schemas/messaging/security.sql
-- messaging Schema 对象级最小权限；必须在 baseline/roles.sql 之后执行
-- =============================================================================

BEGIN;
SET LOCAL ROLE kuc_owner;

SELECT (NOT EXISTS (SELECT 1 FROM core.schema_migration WHERE version = 'baseline:messaging:security'))::text AS kuc_run_security \gset
\if :kuc_run_security

REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA messaging FROM PUBLIC;

GRANT USAGE ON SCHEMA messaging TO kuc_app;
GRANT SELECT ON ALL TABLES IN SCHEMA messaging TO kuc_app;
REVOKE SELECT ON messaging.message_send FROM kuc_app;
GRANT INSERT ON messaging.message_send TO kuc_app;
REVOKE DELETE ON ALL TABLES IN SCHEMA messaging FROM kuc_app;

GRANT USAGE ON SCHEMA messaging TO kuc_control_writer;
GRANT SELECT, INSERT, UPDATE ON messaging.provider, messaging.route_policy,
    messaging.message_template, messaging.content_compliance_rule TO kuc_control_writer;
REVOKE DELETE ON ALL TABLES IN SCHEMA messaging FROM kuc_control_writer;

GRANT USAGE ON SCHEMA messaging TO kuc_message_dispatcher;
GRANT SELECT ON ALL TABLES IN SCHEMA messaging TO kuc_message_dispatcher;
GRANT UPDATE (send_state, provider_id, provider_message_ref_hash, attempt_count,
    next_attempt_at, sent_at, delivered_at, failed_at, failure_code, updated_at, row_version)
    ON messaging.message_send TO kuc_message_dispatcher;
GRANT INSERT ON messaging.delivery_receipt, messaging.provider_metric TO kuc_message_dispatcher;
GRANT INSERT, UPDATE ON messaging.reachability TO kuc_message_dispatcher;

GRANT USAGE ON SCHEMA messaging TO kuc_readonly;
GRANT SELECT ON ALL TABLES IN SCHEMA messaging TO kuc_readonly;
REVOKE SELECT ON messaging.message_send FROM kuc_readonly;

GRANT USAGE, CREATE ON SCHEMA messaging TO kuc_migrator;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA messaging TO kuc_migrator;
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA messaging TO kuc_migrator;

SELECT core.fn_register_migration('baseline:messaging:security', 'messaging Schema 对象权限');
COMMIT;
\else
ROLLBACK;
\endif
