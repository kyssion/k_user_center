\set ON_ERROR_STOP on

-- =============================================================================
-- baseline/schemas/authn/security.sql
-- authn Schema 对象级最小权限；必须在 baseline/roles.sql 之后执行
-- =============================================================================

BEGIN;
SET LOCAL ROLE kuc_owner;

SELECT (NOT EXISTS (SELECT 1 FROM core.schema_migration WHERE version = 'baseline:authn:security'))::text AS kuc_run_security \gset
\if :kuc_run_security

REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA authn FROM PUBLIC;

GRANT USAGE ON SCHEMA authn TO kuc_authn_writer;
GRANT SELECT ON ALL TABLES IN SCHEMA authn TO kuc_authn_writer;
GRANT SELECT, INSERT, UPDATE ON ALL TABLES IN SCHEMA authn TO kuc_authn_writer;
REVOKE DELETE ON ALL TABLES IN SCHEMA authn FROM kuc_authn_writer;

GRANT USAGE ON SCHEMA authn TO kuc_readonly;
GRANT SELECT ON ALL TABLES IN SCHEMA authn TO kuc_readonly;
REVOKE SELECT ON authn.password_credential, authn.password_history, authn.recovery_code,
    authn.verification_challenge, authn.device_authorization FROM kuc_readonly;

GRANT USAGE, CREATE ON SCHEMA authn TO kuc_migrator;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA authn TO kuc_migrator;
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA authn TO kuc_migrator;

SELECT core.fn_register_migration('baseline:authn:security', 'authn Schema 对象权限');
COMMIT;
\else
ROLLBACK;
\endif
