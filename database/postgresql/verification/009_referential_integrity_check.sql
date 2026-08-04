\set ON_ERROR_STOP on

DO $referential_integrity_check$
DECLARE
    foreign_key_count integer;
    invalid_action text;
    invalid_validation text;
    missing_critical text;
BEGIN
    SELECT count(*)
      INTO foreign_key_count
      FROM pg_constraint c
      JOIN pg_namespace n ON n.oid = c.connamespace
     WHERE n.nspname = 'iam'
       AND c.contype = 'f';

    SELECT string_agg(c.conname, ', ' ORDER BY c.conname)
      INTO invalid_action
      FROM pg_constraint c
      JOIN pg_namespace n ON n.oid = c.connamespace
     WHERE n.nspname = 'iam'
       AND c.contype = 'f'
       AND (c.confdeltype <> 'r' OR c.confupdtype <> 'a' OR c.condeferrable OR c.condeferred);

    SELECT string_agg(c.conname, ', ' ORDER BY c.conname)
      INTO invalid_validation
      FROM pg_constraint c
      JOIN pg_namespace n ON n.oid = c.connamespace
     WHERE n.nspname = 'iam'
       AND c.contype = 'f'
       AND NOT c.convalidated;

    SELECT string_agg(required.constraint_name, ', ' ORDER BY required.constraint_name)
      INTO missing_critical
      FROM (VALUES
        ('fk_access_token_records_authorization_decision_id'),
        ('fk_access_token_records_tenant_id'),
        ('fk_access_token_policy_versions_token_jti'),
        ('fk_access_token_policy_versions_policy_version_id'),
        ('fk_api_resources_active_configuration_id'),
        ('fk_approval_cases_policy_version_id'),
        ('fk_authorization_decision_policy_versions_decision_id'),
        ('fk_authorization_decision_policy_versions_policy_version_id'),
        ('fk_authorization_decisions_client_id'),
        ('fk_authorization_decisions_risk_assessment_id'),
        ('fk_message_delivery_attempts_request_id'),
        ('fk_operation_policy_versions_operation_id'),
        ('fk_operation_policy_versions_policy_version_id'),
        ('fk_risk_assessment_signals_signal_id'),
        ('fk_risk_assessments_risk_policy_version_id'),
        ('fk_webhook_delivery_attempts_delivery_id'),
        ('fk_credential_materials_key_id'),
        ('fk_data_export_artifacts_key_id'),
        ('fk_identifiers_key_id'),
        ('fk_user_subjects_user_id'),
        ('fk_user_subjects_client_id'),
        ('fk_session_policy_versions_session_id'),
        ('fk_session_policy_versions_policy_version_id')
      ) AS required(constraint_name)
     WHERE NOT EXISTS (
        SELECT 1
        FROM pg_constraint c
        JOIN pg_namespace n ON n.oid = c.connamespace
        WHERE n.nspname = 'iam'
          AND c.contype = 'f'
          AND c.conname = required.constraint_name
     );

    IF foreign_key_count <> 201 OR invalid_action IS NOT NULL OR invalid_validation IS NOT NULL OR missing_critical IS NOT NULL THEN
        RAISE EXCEPTION '引用完整性门禁失败：fk_count=%, invalid_action=%, invalid_validation=%, missing_critical=%',
            foreign_key_count, coalesce(invalid_action, '<none>'), coalesce(invalid_validation, '<none>'), coalesce(missing_critical, '<none>');
    END IF;
END
$referential_integrity_check$;

SELECT 'PASS: 201 个直接内部引用由已验证 RESTRICT 外键保护；多态和外部引用保留代码校验' AS result;
