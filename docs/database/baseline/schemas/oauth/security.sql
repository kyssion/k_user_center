\set ON_ERROR_STOP on

-- =============================================================================
-- baseline/schemas/oauth/security.sql
-- oauth Schema 对象级最小权限；必须在 baseline/roles.sql 之后执行
-- =============================================================================

BEGIN;
SET LOCAL ROLE kuc_owner;

SELECT (NOT EXISTS (SELECT 1 FROM core.schema_migration WHERE version = 'baseline:oauth:security'))::text AS kuc_run_security \gset
\if :kuc_run_security

REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA oauth FROM PUBLIC;

GRANT USAGE ON SCHEMA oauth TO kuc_app;
GRANT SELECT ON ALL TABLES IN SCHEMA oauth TO kuc_app;
REVOKE SELECT ON oauth.client_credential, oauth.refresh_token, oauth.authorization_code,
    oauth.reference_access_token FROM kuc_app;
REVOKE DELETE ON ALL TABLES IN SCHEMA oauth FROM kuc_app;

GRANT USAGE ON SCHEMA oauth TO kuc_authn_writer;
GRANT SELECT ON ALL TABLES IN SCHEMA oauth TO kuc_authn_writer;
GRANT SELECT, INSERT, UPDATE ON oauth.device, oauth.authorization_grant, oauth.user_session,
    oauth.token_family, oauth.refresh_token, oauth.authorization_code, oauth.reference_access_token,
    oauth.revocation_record, oauth.logout_request, oauth.logout_target_result TO kuc_authn_writer;
REVOKE DELETE ON ALL TABLES IN SCHEMA oauth FROM kuc_authn_writer;
GRANT EXECUTE ON FUNCTION oauth.fn_mark_refresh_token_reuse(uuid, text) TO kuc_authn_writer;

GRANT USAGE ON SCHEMA oauth TO kuc_control_writer;
GRANT SELECT, INSERT, UPDATE ON oauth.application, oauth.client, oauth.client_uri,
    oauth.client_credential, oauth.api_resource, oauth.scope_definition TO kuc_control_writer;
REVOKE DELETE ON ALL TABLES IN SCHEMA oauth FROM kuc_control_writer;

GRANT USAGE ON SCHEMA oauth TO kuc_readonly;
GRANT SELECT ON ALL TABLES IN SCHEMA oauth TO kuc_readonly;
REVOKE SELECT ON oauth.client_credential, oauth.refresh_token, oauth.authorization_code,
    oauth.reference_access_token FROM kuc_readonly;

GRANT USAGE, CREATE ON SCHEMA oauth TO kuc_migrator;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA oauth TO kuc_migrator;
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA oauth TO kuc_migrator;

SELECT core.fn_register_migration('baseline:oauth:security', 'oauth Schema 对象权限');
COMMIT;
\else
ROLLBACK;
\endif
