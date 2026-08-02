\set ON_ERROR_STOP on

-- =============================================================================
-- baseline/schemas/federation/security.sql
-- federation Schema 对象级最小权限；必须在 baseline/roles.sql 之后执行
-- =============================================================================

BEGIN;
SET LOCAL ROLE kuc_owner;

SELECT (NOT EXISTS (SELECT 1 FROM core.schema_migration WHERE version = 'baseline:federation:security'))::text AS kuc_run_security \gset
\if :kuc_run_security

REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA federation FROM PUBLIC;

GRANT USAGE ON SCHEMA federation TO kuc_authn_writer;
GRANT SELECT ON federation.identity_provider, federation.identity_provider_key,
    federation.external_identity, federation.attribute_mapping,
    federation.assertion_replay TO kuc_authn_writer;
GRANT INSERT, UPDATE ON federation.external_identity TO kuc_authn_writer;
GRANT INSERT ON federation.identity_provider_key, federation.assertion_replay TO kuc_authn_writer;

GRANT USAGE ON SCHEMA federation TO kuc_control_writer;
GRANT SELECT ON ALL TABLES IN SCHEMA federation TO kuc_control_writer;
GRANT SELECT, INSERT, UPDATE ON ALL TABLES IN SCHEMA federation TO kuc_control_writer;
REVOKE DELETE ON ALL TABLES IN SCHEMA federation FROM kuc_control_writer;

GRANT USAGE ON SCHEMA federation TO kuc_readonly;
GRANT SELECT ON ALL TABLES IN SCHEMA federation TO kuc_readonly;

GRANT USAGE, CREATE ON SCHEMA federation TO kuc_migrator;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA federation TO kuc_migrator;
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA federation TO kuc_migrator;

SELECT core.fn_register_migration('baseline:federation:security', 'federation Schema 对象权限');
COMMIT;
\else
ROLLBACK;
\endif
