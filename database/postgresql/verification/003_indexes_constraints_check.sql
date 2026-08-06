\set ON_ERROR_STOP on

DO $index_contract$
DECLARE
    missing_primary_keys text;
    missing_constraints text;
    missing_indexes text;
    partition_parent_count integer;
    parent_without_child text;
    invalid_partition_contract text;
    missing_future_partitions text;
    default_partition_rows bigint := 0;
    default_item record;
    default_count bigint;
BEGIN
    SELECT string_agg(c.relname, ', ' ORDER BY c.relname)
      INTO missing_primary_keys
      FROM pg_class c
      JOIN pg_namespace n ON n.oid = c.relnamespace
     WHERE n.nspname = 'iam'
       AND c.relkind IN ('r','p')
       AND NOT c.relispartition
       AND NOT EXISTS (
           SELECT 1 FROM pg_constraint con WHERE con.conrelid = c.oid AND con.contype = 'p'
       );

    SELECT string_agg(format('%s.%s', required.table_name, required.constraint_name), ', ' ORDER BY required.table_name, required.constraint_name)
      INTO missing_constraints
      FROM (VALUES
        ('global_users','uq_global_users_public'),('user_subjects','uq_user_subject_client_subject'),
        ('user_subjects','uq_user_subject_current'),('user_subjects','ck_user_subject_rotation_shape'),
        ('identifier_claims','uq_identifier_claim'),
        ('oauth_clients','uq_oauth_clients_client_id'),('api_resources','uq_api_resources_audience'),('oauth_scopes','uq_oauth_scopes_code'),
        ('idempotency_records','uq_idempotency_caller_key'),('outbox_events','uq_outbox_event_id'),('inbox_messages','uq_inbox_consumer_event'),
        ('operations','uq_operations_caller_key'),('approval_cases','uq_approval_cases_execution_id'),
        ('memberships','uq_memberships_current'),('memberships','ck_memberships_current_slot'),
        ('configuration_versions','uq_configuration_version'),('policy_versions','uq_policy_versions'),('event_schema_versions','uq_event_schema_version'),
        ('legacy_id_mappings','uq_legacy_external_mapping'),('auth_challenges','uq_auth_challenge_token'),
        ('refresh_token_instances','uq_refresh_token_hash'),('refresh_token_instances','uq_refresh_token_sequence'),
        ('authorization_codes','uq_authorization_codes_hash'),
        ('machine_credentials','uq_machine_credential_replacement'),('authorization_grants','ck_authorization_grants_granted_at')
      ) AS required(table_name, constraint_name)
     WHERE NOT EXISTS (
        SELECT 1
          FROM pg_constraint c
          JOIN pg_class t ON t.oid = c.conrelid
          JOIN pg_namespace n ON n.oid = t.relnamespace
         WHERE n.nspname = 'iam'
           AND t.relname = required.table_name
           AND c.conname = required.constraint_name
     );

    SELECT string_agg(required.index_name, ', ' ORDER BY required.index_name)
      INTO missing_indexes
      FROM (VALUES
        ('ix_identifier_lookup'),('ix_global_users_guest_expiry'),('ix_identifier_bindings_identifier'),
        ('ix_auth_challenges_expiry'),('ix_authenticators_user'),('ix_user_profiles_primary_contact'),
        ('ix_sessions_user_state'),('ix_sessions_consent'),('ix_sessions_policy_versions_gin'),
        ('ix_access_token_jti'),('ix_access_tokens_actor'),('ix_access_tokens_delegation'),
        ('ix_access_tokens_consent'),('ix_access_tokens_decision'),('ix_access_tokens_policy_versions_gin'),
        ('ix_operations_queue'),('ix_operations_capability'),('ix_operations_policy_versions_gin'),
        ('ix_outbox_publish_queue'),('ix_inbox_state'),
        ('ix_authorization_decisions_validity'),('ix_authorization_decisions_decision_id'),
        ('ix_authorization_decisions_policy_versions_gin'),('ix_risk_signals_signal_id'),
        ('ix_risk_signals_subject'),
        ('ix_webhook_deliveries_queue'),('ix_webhook_attempts_delivery'),
        ('ix_webhook_deliveries_delivery_id'),('ix_webhook_deliveries_event_subscription'),
        ('ix_message_requests_queue'),('ix_message_attempts_request'),('ix_message_requests_request_id'),
        ('ix_risk_assessment_signals_signal'),('ix_memberships_user'),
        ('ix_user_role_assignments_effective'),('ix_relationship_tuples_resource'),
        ('ix_user_role_assignments_role'),('ix_group_role_assignments_role'),('ix_machine_role_assignments_role'),
        ('ix_directory_sync_batches_queue'),('ix_migration_items_queue'),
        ('ix_configuration_release_items_version'),('ix_identifiers_key'),('ix_credential_materials_key'),
        ('ix_data_export_artifacts_key'),('ix_jwks_release_keys_key'),('ix_certificates_key'),
        ('ix_machine_credentials_key'),('ix_machine_credentials_certificate'),('ix_webhook_signing_keys_key'),
        ('ix_outbox_recorded_brin'),('ix_inbox_received_brin')
      ) AS required(index_name)
     WHERE NOT EXISTS (
        SELECT 1
          FROM pg_class c
          JOIN pg_namespace n ON n.oid = c.relnamespace
         WHERE n.nspname = 'iam' AND c.relkind = 'i' AND c.relname = required.index_name
     );

    SELECT count(*) INTO partition_parent_count
      FROM pg_partitioned_table p
      JOIN pg_class c ON c.oid = p.partrelid
      JOIN pg_namespace n ON n.oid = c.relnamespace
     WHERE n.nspname = 'iam';

    SELECT string_agg(c.relname, ', ' ORDER BY c.relname)
      INTO parent_without_child
      FROM pg_partitioned_table p
      JOIN pg_class c ON c.oid = p.partrelid
      JOIN pg_namespace n ON n.oid = c.relnamespace
     WHERE n.nspname = 'iam'
       AND NOT EXISTS (SELECT 1 FROM pg_inherits i WHERE i.inhparent = c.oid);

    WITH expected(table_name, strategy, key_definition) AS (
        VALUES
            ('outbox_events','h','HASH (event_id)'),
            ('inbox_messages','h','HASH (consumer_id, event_id)'),
            ('audit_events','r','RANGE (recorded_at)'),
            ('authentication_attempts','r','RANGE (occurred_at)'),
            ('access_token_records','r','RANGE (issued_at)'),
            ('authorization_decisions','r','RANGE (decided_at)'),
            ('risk_signals','r','RANGE (occurred_at)'),
            ('workload_attestations','r','RANGE (received_at)'),
            ('webhook_deliveries','r','RANGE (created_at)'),
            ('webhook_delivery_attempts','r','RANGE (created_at)'),
            ('message_requests','r','RANGE (created_at)'),
            ('message_delivery_attempts','r','RANGE (created_at)'),
            ('migration_change_logs','r','RANGE (recorded_at)')
    )
    SELECT string_agg(format('%s expected %s/%s got %s/%s', expected.table_name, expected.strategy, expected.key_definition, p.partstrat, pg_get_partkeydef(c.oid)), ', ' ORDER BY expected.table_name)
      INTO invalid_partition_contract
      FROM expected
      LEFT JOIN (
        SELECT relation.oid, relation.relname
          FROM pg_class relation
          JOIN pg_namespace namespace ON namespace.oid = relation.relnamespace
         WHERE namespace.nspname = 'iam'
      ) c ON c.relname = expected.table_name
      LEFT JOIN pg_partitioned_table p ON p.partrelid = c.oid
     WHERE c.oid IS NULL
        OR p.partstrat::text IS DISTINCT FROM expected.strategy
        OR pg_get_partkeydef(c.oid) IS DISTINCT FROM expected.key_definition;

    WITH range_parent(table_name) AS (
        VALUES
            ('audit_events'),('authentication_attempts'),('access_token_records'),('authorization_decisions'),
            ('risk_signals'),('workload_attestations'),('webhook_deliveries'),('webhook_delivery_attempts'),
            ('message_requests'),('message_delivery_attempts'),('migration_change_logs')
    ), expected_child AS (
        SELECT table_name || '_' || to_char(date_trunc('month', CURRENT_DATE) + make_interval(months => offset_no), 'YYYYMM') AS child_name
          FROM range_parent
          CROSS JOIN generate_series(0, 12) AS offsets(offset_no)
    )
    SELECT string_agg(child_name, ', ' ORDER BY child_name)
      INTO missing_future_partitions
      FROM expected_child
     WHERE NOT EXISTS (
        SELECT 1
          FROM pg_class c
          JOIN pg_namespace n ON n.oid = c.relnamespace
         WHERE n.nspname = 'iam' AND c.relname = expected_child.child_name AND c.relispartition
     );

    FOR default_item IN
        SELECT c.relname
          FROM pg_class c
          JOIN pg_namespace n ON n.oid = c.relnamespace
         WHERE n.nspname = 'iam'
           AND c.relispartition
           AND c.relname ~ '_default$'
    LOOP
        EXECUTE format('SELECT count(*) FROM iam.%I', default_item.relname) INTO default_count;
        default_partition_rows := default_partition_rows + default_count;
    END LOOP;

    IF missing_primary_keys IS NOT NULL OR missing_constraints IS NOT NULL OR missing_indexes IS NOT NULL OR partition_parent_count <> 13
       OR parent_without_child IS NOT NULL OR invalid_partition_contract IS NOT NULL OR missing_future_partitions IS NOT NULL OR default_partition_rows <> 0 THEN
        RAISE EXCEPTION '索引约束门禁失败：missing_pk=%, missing_unique=%, missing_indexes=%, partition_parents=%, no_child=%, invalid_partition=%, missing_future=%, default_rows=%',
            coalesce(missing_primary_keys, '<none>'), coalesce(missing_constraints, '<none>'), coalesce(missing_indexes, '<none>'),
            partition_parent_count, coalesce(parent_without_child, '<none>'), coalesce(invalid_partition_contract, '<none>'),
            coalesce(missing_future_partitions, '<none>'), default_partition_rows;
    END IF;
END
$index_contract$;

SELECT 'PASS: 主键、关键唯一性、索引及分区契约完整' AS result;
