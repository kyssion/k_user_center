\set ON_ERROR_STOP on

-- =============================================================================
-- baseline/schemas/integration/security.sql
-- integration Schema 对象级最小权限；必须在 baseline/roles.sql 之后执行
-- =============================================================================

BEGIN;
SET LOCAL ROLE kuc_owner;

SELECT (NOT EXISTS (SELECT 1 FROM core.schema_migration WHERE version = 'baseline:integration:security'))::text AS kuc_run_security \gset
\if :kuc_run_security

REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA integration FROM PUBLIC;

GRANT USAGE ON SCHEMA integration TO kuc_app;
GRANT SELECT ON ALL TABLES IN SCHEMA integration TO kuc_app;
REVOKE SELECT ON integration.event_replay_request FROM kuc_app;
GRANT INSERT ON integration.outbox_event TO kuc_app;
REVOKE DELETE ON ALL TABLES IN SCHEMA integration FROM kuc_app;

GRANT USAGE ON SCHEMA integration TO kuc_authn_writer;
GRANT INSERT ON integration.outbox_event TO kuc_authn_writer;

GRANT USAGE ON SCHEMA integration TO kuc_control_writer;
GRANT SELECT, INSERT, UPDATE ON integration.event_schema, integration.webhook_subscription,
    integration.event_replay_request TO kuc_control_writer;
GRANT INSERT ON integration.outbox_event TO kuc_control_writer;
REVOKE DELETE ON ALL TABLES IN SCHEMA integration FROM kuc_control_writer;

GRANT USAGE ON SCHEMA integration TO kuc_outbox_dispatcher;
GRANT SELECT ON integration.outbox_event, integration.webhook_subscription,
    integration.webhook_delivery, integration.event_schema,
    integration.consumer_watermark TO kuc_outbox_dispatcher;
GRANT UPDATE (publish_state, attempt_count, next_attempt_at, published_at, broker_partition,
    broker_offset, last_error_code) ON integration.outbox_event TO kuc_outbox_dispatcher;
GRANT INSERT ON integration.webhook_delivery TO kuc_outbox_dispatcher;
GRANT UPDATE (delivery_state, response_status, response_body_hash, next_attempt_at,
    first_attempt_at, delivered_at, dead_lettered_at)
    ON integration.webhook_delivery TO kuc_outbox_dispatcher;
GRANT INSERT, UPDATE ON integration.consumer_watermark TO kuc_outbox_dispatcher;

GRANT USAGE ON SCHEMA integration TO kuc_message_dispatcher;
GRANT INSERT ON integration.outbox_event TO kuc_message_dispatcher;

GRANT USAGE ON SCHEMA integration TO kuc_readonly;
GRANT SELECT ON ALL TABLES IN SCHEMA integration TO kuc_readonly;

GRANT USAGE, CREATE ON SCHEMA integration TO kuc_migrator;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA integration TO kuc_migrator;
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA integration TO kuc_migrator;

SELECT core.fn_register_migration('baseline:integration:security', 'integration Schema 对象权限');
COMMIT;
\else
ROLLBACK;
\endif
