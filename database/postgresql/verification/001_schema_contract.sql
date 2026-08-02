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

    IF missing IS NOT NULL OR unexpected IS NOT NULL OR actual_count <> 113 THEN
        RAISE EXCEPTION 'Schema 契约失败：count=%, missing=%, unexpected=%', actual_count, coalesce(missing, '<none>'), coalesce(unexpected, '<none>');
    END IF;
END
$schema_contract$;

SELECT 'PASS: iam 113 张目标父表完整' AS result;

