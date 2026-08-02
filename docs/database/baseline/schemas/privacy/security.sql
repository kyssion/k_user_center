\set ON_ERROR_STOP on

-- =============================================================================
-- baseline/schemas/privacy/security.sql
-- privacy Schema 对象级最小权限；必须在 baseline/roles.sql 之后执行
-- =============================================================================

BEGIN;
SET LOCAL ROLE kuc_owner;

SELECT (NOT EXISTS (SELECT 1 FROM core.schema_migration WHERE version = 'baseline:privacy:security'))::text AS kuc_run_security \gset
\if :kuc_run_security

REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA privacy FROM PUBLIC;

GRANT USAGE ON SCHEMA privacy TO kuc_app;
GRANT SELECT ON ALL TABLES IN SCHEMA privacy TO kuc_app;
GRANT SELECT, INSERT, UPDATE ON privacy.agreement_acceptance, privacy.consent,
    privacy.marketing_subscription, privacy.privacy_request, privacy.privacy_request_task,
    privacy.export_job TO kuc_app;
GRANT SELECT, INSERT ON privacy.consent_aggregate TO kuc_app;
REVOKE DELETE ON ALL TABLES IN SCHEMA privacy FROM kuc_app;

GRANT USAGE ON SCHEMA privacy TO kuc_authn_writer;
GRANT SELECT ON ALL TABLES IN SCHEMA privacy TO kuc_authn_writer;

GRANT USAGE ON SCHEMA privacy TO kuc_control_writer;
GRANT SELECT, INSERT, UPDATE ON privacy.purpose, privacy.data_category,
    privacy.purpose_data_mapping, privacy.agreement, privacy.legal_hold,
    privacy.retention_rule, privacy.cross_border_authorization, privacy.minor_protection,
    privacy.privacy_impact_assessment TO kuc_control_writer;
REVOKE DELETE ON ALL TABLES IN SCHEMA privacy FROM kuc_control_writer;

GRANT USAGE ON SCHEMA privacy TO kuc_readonly;
GRANT SELECT ON ALL TABLES IN SCHEMA privacy TO kuc_readonly;

GRANT USAGE, CREATE ON SCHEMA privacy TO kuc_migrator;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA privacy TO kuc_migrator;
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA privacy TO kuc_migrator;

SELECT core.fn_register_migration('baseline:privacy:security', 'privacy Schema 对象权限');
COMMIT;
\else
ROLLBACK;
\endif
