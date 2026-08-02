\set ON_ERROR_STOP on

-- =============================================================================
-- baseline/schemas/profile/security.sql
-- profile Schema 对象级最小权限；必须在 baseline/roles.sql 之后执行
-- =============================================================================

BEGIN;
SET LOCAL ROLE kuc_owner;

SELECT (NOT EXISTS (SELECT 1 FROM core.schema_migration WHERE version = 'baseline:profile:security'))::text AS kuc_run_security \gset
\if :kuc_run_security

REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA profile FROM PUBLIC;

GRANT USAGE ON SCHEMA profile TO kuc_app;
GRANT SELECT ON ALL TABLES IN SCHEMA profile TO kuc_app;
GRANT SELECT, INSERT, UPDATE ON profile.user_profile, profile.sensitive_attribute,
    profile.business_profile, profile.profile_change, profile.user_preference,
    profile.notification_preference TO kuc_app;
REVOKE DELETE ON ALL TABLES IN SCHEMA profile FROM kuc_app;
REVOKE UPDATE ON profile.profile_change FROM kuc_app;

GRANT USAGE ON SCHEMA profile TO kuc_control_writer;
GRANT SELECT, INSERT, UPDATE ON profile.field_definition TO kuc_control_writer;
REVOKE DELETE ON ALL TABLES IN SCHEMA profile FROM kuc_control_writer;

GRANT USAGE ON SCHEMA profile TO kuc_readonly;
GRANT SELECT ON ALL TABLES IN SCHEMA profile TO kuc_readonly;
REVOKE SELECT ON profile.sensitive_attribute, profile.business_profile FROM kuc_readonly;

GRANT USAGE, CREATE ON SCHEMA profile TO kuc_migrator;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA profile TO kuc_migrator;
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA profile TO kuc_migrator;

SELECT core.fn_register_migration('baseline:profile:security', 'profile Schema 对象权限');
COMMIT;
\else
ROLLBACK;
\endif
