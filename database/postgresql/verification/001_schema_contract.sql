\set ON_ERROR_STOP on

DO $schema_contract$
DECLARE
    expected_tables text[] := ARRAY[
        'idempotency_records','operations','operation_steps','outbox_events','inbox_messages','audit_events',
        'global_users','user_subjects','identifiers','identifier_claims','identifier_bindings','user_identities','user_aliases',
        'authenticators','credential_materials','password_history','recovery_code_batches','recovery_codes','auth_challenges','login_transactions','login_transaction_steps','authentication_contexts','authentication_attempts',
        'business_lines','applications','oauth_clients','api_resources','oauth_scopes','tenants','tenant_domains','organizations','memberships','invitations','groups','group_members','usage_records','resource_quotas',
        'devices','sessions','session_participants','authorization_codes','authorization_grants','token_families','refresh_token_instances','access_token_records','revocation_entries',
        'user_profiles','profile_documents','identity_assurance_assertions','agreement_versions','agreement_acceptances','consent_aggregates','consents','privacy_requests','legal_holds','data_export_artifacts','deletion_proofs',
        'permissions','roles','role_permissions','user_role_assignments','group_role_assignments','machine_role_assignments','data_scope_definitions','policy_versions','policy_bindings','authorization_decisions','relationship_tuples',
        'identity_providers','directory_connectors','directory_sync_cursors','directory_sync_batches','directory_object_mappings',
        'risk_signals','risk_assessments','risk_assessment_signals','risk_cases','security_signals','restriction_entries','risk_entity_links',
        'machine_principals','machine_credentials','workload_trust_bundle_versions','workload_attestations','delegations','approval_cases','approval_actions',
        'cryptographic_keys','certificates','jwks_releases','jwks_release_keys','configuration_versions','configuration_releases','configuration_release_items','security_exceptions',
        'event_schema_versions','webhook_subscriptions','webhook_signing_keys','webhook_deliveries','webhook_delivery_attempts','event_replay_requests','consumer_checkpoints',
        'message_providers','message_template_versions','message_requests','message_delivery_attempts','contact_reachability','message_suppressions',
        'legacy_systems','legacy_id_mappings','migration_batches','migration_items','migration_change_logs'
    ];
    missing text;
    unexpected text;
    missing_required_columns text;
    nullable_mismatches text;
    actual_count integer;
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_namespace WHERE nspname = 'iam') THEN
        RAISE EXCEPTION 'iam schema 不存在';
    END IF;

    SELECT string_agg(expected.table_name, ', ' ORDER BY expected.table_name)
      INTO missing
      FROM unnest(expected_tables) AS expected(table_name)
     WHERE NOT EXISTS (
        SELECT 1
          FROM pg_class c
          JOIN pg_namespace n ON n.oid = c.relnamespace
         WHERE n.nspname = 'iam'
           AND c.relname = expected.table_name
           AND c.relkind IN ('r','p')
           AND NOT c.relispartition
     );

    SELECT count(*)
      INTO actual_count
      FROM pg_class c
      JOIN pg_namespace n ON n.oid = c.relnamespace
     WHERE n.nspname = 'iam'
       AND c.relkind IN ('r','p')
       AND NOT c.relispartition;

    SELECT string_agg(c.relname, ', ' ORDER BY c.relname)
      INTO unexpected
      FROM pg_class c
      JOIN pg_namespace n ON n.oid = c.relnamespace
     WHERE n.nspname = 'iam'
       AND c.relkind IN ('r','p')
       AND NOT c.relispartition
       AND NOT (c.relname = ANY(expected_tables));

    WITH required(table_name, column_name, is_nullable) AS (
        VALUES
            ('operations','caller_scope','NO'),('operations','idempotency_key','NO'),('operations','request_digest','NO'),
            ('operations','capability_code','NO'),('operations','saga_type','NO'),('operations','policy_version_ids','NO'),
            ('outbox_events','business_line_id','YES'),('outbox_events','producer_type','NO'),('outbox_events','producer_id','NO'),
            ('outbox_events','subject_ref_type','NO'),('outbox_events','subject_ref_id','NO'),('outbox_events','actor_type','YES'),
            ('outbox_events','actor_id_type','YES'),('outbox_events','actor_id','YES'),('outbox_events','occurred_at','NO'),
            ('outbox_events','data_version','YES'),('outbox_events','trace_id','NO'),('outbox_events','correlation_id','YES'),
            ('outbox_events','causation_id','YES'),('outbox_events','data_classification','NO'),
            ('global_users','user_type','NO'),('global_users','authentication_lock_state','NO'),
            ('global_users','security_freeze_state','NO'),('global_users','guest_expires_at','YES'),
            ('user_profiles','primary_contact_identifier_id','YES'),
            ('authorization_grants','requested_at','NO'),('authorization_grants','granted_at','YES'),
            ('machine_credentials','replaces_credential_id','YES'),
            ('sessions','security_profile_code','NO'),('sessions','security_profile_version','NO'),
            ('sessions','policy_version_ids','NO'),('sessions','consent_id','YES'),('sessions','consent_epoch','YES'),
            ('sessions','revocation_watermark','YES'),
            ('access_token_records','subject_type','NO'),('access_token_records','actor_type','YES'),
            ('access_token_records','actor_id','YES'),('access_token_records','delegation_id','YES'),
            ('access_token_records','delegation_chain_snapshot','NO'),('access_token_records','security_profile_code','NO'),
            ('access_token_records','security_profile_version','NO'),('access_token_records','policy_version_ids','NO'),
            ('access_token_records','consent_id','YES'),('access_token_records','consent_epoch','YES'),
            ('access_token_records','revocation_watermark','YES'),('access_token_records','sender_constraint_type','YES'),
            ('access_token_records','sender_constraint_thumbprint','YES'),('access_token_records','authorization_decision_id','YES'),
            ('authorization_decisions','actor_type','YES'),('authorization_decisions','actor_id','YES'),
            ('authorization_decisions','delegation_id','YES'),('authorization_decisions','delegation_chain_snapshot','NO'),
            ('authorization_decisions','security_profile_code','NO'),('authorization_decisions','security_profile_version','NO'),
            ('authorization_decisions','context_version_snapshot','NO'),('authorization_decisions','consent_id','YES'),
            ('authorization_decisions','consent_epoch','YES'),('authorization_decisions','valid_until','NO'),
            ('approval_cases','execution_id','YES'),('event_schema_versions','approval_case_id','YES'),
            ('message_requests','delivery_secret_handle','YES'),('message_requests','delivery_secret_expires_at','YES')
    )
    SELECT string_agg(format('%I.%I', required.table_name, required.column_name), ', ' ORDER BY required.table_name, required.column_name)
      INTO missing_required_columns
      FROM required
     WHERE NOT EXISTS (
        SELECT 1
          FROM information_schema.columns c
         WHERE c.table_schema = 'iam'
           AND c.table_name = required.table_name
           AND c.column_name = required.column_name
     );

    WITH required(table_name, column_name, is_nullable) AS (
        VALUES
            ('operations','caller_scope','NO'),('operations','idempotency_key','NO'),('operations','request_digest','NO'),
            ('operations','capability_code','NO'),('operations','saga_type','NO'),('operations','policy_version_ids','NO'),
            ('outbox_events','producer_type','NO'),('outbox_events','producer_id','NO'),('outbox_events','subject_ref_type','NO'),
            ('outbox_events','subject_ref_id','NO'),('outbox_events','occurred_at','NO'),('outbox_events','trace_id','NO'),
            ('outbox_events','data_classification','NO'),('global_users','user_type','NO'),
            ('global_users','authentication_lock_state','NO'),('global_users','security_freeze_state','NO'),
            ('authorization_grants','requested_at','NO'),('authorization_grants','granted_at','YES'),
            ('machine_credentials','replaces_credential_id','YES'),
            ('sessions','security_profile_code','NO'),('sessions','security_profile_version','NO'),('sessions','policy_version_ids','NO'),
            ('access_token_records','subject_type','NO'),('access_token_records','delegation_chain_snapshot','NO'),
            ('access_token_records','security_profile_code','NO'),('access_token_records','security_profile_version','NO'),
            ('access_token_records','policy_version_ids','NO'),('authorization_decisions','delegation_chain_snapshot','NO'),
            ('authorization_decisions','security_profile_code','NO'),('authorization_decisions','security_profile_version','NO'),
            ('authorization_decisions','context_version_snapshot','NO'),('authorization_decisions','valid_until','NO'),
            ('message_requests','delivery_secret_handle','YES'),('message_requests','delivery_secret_expires_at','YES')
    )
    SELECT string_agg(format('%I.%I expected %s got %s', required.table_name, required.column_name, required.is_nullable, c.is_nullable), ', ' ORDER BY required.table_name, required.column_name)
      INTO nullable_mismatches
      FROM required
      JOIN information_schema.columns c
        ON c.table_schema = 'iam'
       AND c.table_name = required.table_name
       AND c.column_name = required.column_name
     WHERE c.is_nullable <> required.is_nullable;

    IF missing IS NOT NULL OR unexpected IS NOT NULL OR actual_count <> 113 OR missing_required_columns IS NOT NULL OR nullable_mismatches IS NOT NULL THEN
        RAISE EXCEPTION 'Schema 契约失败：count=%, missing=%, unexpected=%, missing_columns=%, nullability=%',
            actual_count, coalesce(missing, '<none>'), coalesce(unexpected, '<none>'),
            coalesce(missing_required_columns, '<none>'), coalesce(nullable_mismatches, '<none>');
    END IF;
END
$schema_contract$;

SELECT 'PASS: iam 113 张目标父表及关键安全字段完整' AS result;
