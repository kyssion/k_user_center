\set ON_ERROR_STOP on

-- =============================================================================
-- baseline/schemas/migration/security.sql
-- migration Schema 对象级最小权限；必须在 baseline/roles.sql 之后执行
-- =============================================================================

BEGIN;
SET LOCAL ROLE kuc_owner;

SELECT (NOT EXISTS (SELECT 1 FROM core.schema_migration WHERE version = 'baseline:migration:security'))::text AS kuc_run_security \gset
\if :kuc_run_security

REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA migration FROM PUBLIC;

GRANT USAGE ON SCHEMA migration TO kuc_readonly;
GRANT SELECT ON ALL TABLES IN SCHEMA migration TO kuc_readonly;

GRANT USAGE, CREATE ON SCHEMA migration TO kuc_migrator;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA migration TO kuc_migrator;
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA migration TO kuc_migrator;

SELECT core.fn_register_migration('baseline:migration:security', 'migration Schema 对象权限');
COMMIT;
\else
ROLLBACK;
\endif
