\set ON_ERROR_STOP on

-- =============================================================================
-- baseline/schemas/crypto/security.sql
-- crypto Schema 对象级最小权限；必须在 baseline/roles.sql 之后执行
-- =============================================================================

BEGIN;
SET LOCAL ROLE kuc_owner;

SELECT (NOT EXISTS (SELECT 1 FROM core.schema_migration WHERE version = 'baseline:crypto:security'))::text AS kuc_run_security \gset
\if :kuc_run_security

REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA crypto FROM PUBLIC;

GRANT USAGE ON SCHEMA crypto TO kuc_control_writer;
GRANT SELECT ON ALL TABLES IN SCHEMA crypto TO kuc_control_writer;
GRANT SELECT, INSERT, UPDATE ON ALL TABLES IN SCHEMA crypto TO kuc_control_writer;
REVOKE DELETE ON ALL TABLES IN SCHEMA crypto FROM kuc_control_writer;

GRANT USAGE ON SCHEMA crypto TO kuc_readonly;
GRANT SELECT ON ALL TABLES IN SCHEMA crypto TO kuc_readonly;
REVOKE SELECT ON crypto.key_asset FROM kuc_readonly;

GRANT USAGE, CREATE ON SCHEMA crypto TO kuc_migrator;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA crypto TO kuc_migrator;
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA crypto TO kuc_migrator;

SELECT core.fn_register_migration('baseline:crypto:security', 'crypto Schema 对象权限');
COMMIT;
\else
ROLLBACK;
\endif
