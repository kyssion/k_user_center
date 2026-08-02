\set ON_ERROR_STOP on

-- =============================================================================
-- baseline/schemas/iam/security.sql
-- iam Schema 对象级最小权限；必须在 baseline/roles.sql 之后执行
-- =============================================================================

BEGIN;
SET LOCAL ROLE kuc_owner;

SELECT (NOT EXISTS (SELECT 1 FROM core.schema_migration WHERE version = 'baseline:iam:security'))::text AS kuc_run_security \gset
\if :kuc_run_security

REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA iam FROM PUBLIC;

GRANT USAGE ON SCHEMA iam TO kuc_app;
GRANT SELECT ON ALL TABLES IN SCHEMA iam TO kuc_app;
GRANT SELECT, INSERT, UPDATE ON iam.user_account, iam.subject_assignment, iam.identifier,
    iam.account_merge, iam.account_merge_item, iam.account_deletion TO kuc_app;
REVOKE DELETE ON ALL TABLES IN SCHEMA iam FROM kuc_app;
REVOKE UPDATE ON iam.subject_assignment FROM kuc_app;

GRANT USAGE ON SCHEMA iam TO kuc_authn_writer;
GRANT SELECT ON ALL TABLES IN SCHEMA iam TO kuc_authn_writer;

GRANT USAGE ON SCHEMA iam TO kuc_message_dispatcher;
GRANT SELECT (id, identifier_state, value_cipher, cipher_key_version, value_masked)
    ON iam.identifier TO kuc_message_dispatcher;

GRANT USAGE ON SCHEMA iam TO kuc_readonly;
GRANT SELECT ON ALL TABLES IN SCHEMA iam TO kuc_readonly;
REVOKE SELECT ON iam.identifier, iam.identifier_tombstone FROM kuc_readonly;

GRANT USAGE, CREATE ON SCHEMA iam TO kuc_migrator;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA iam TO kuc_migrator;
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA iam TO kuc_migrator;

SELECT core.fn_register_migration('baseline:iam:security', 'iam Schema 对象权限');
COMMIT;
\else
ROLLBACK;
\endif
