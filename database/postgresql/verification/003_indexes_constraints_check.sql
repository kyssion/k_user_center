\set ON_ERROR_STOP on

DO $index_contract$
DECLARE
    missing_primary_keys text;
    missing_constraints text;
    missing_indexes text;
    partition_parent_count integer;
    parent_without_child text;
    invalid_partition_contract text;
    missing_hash_partitions text;
    invalid_hash_partition_count text;
    missing_future_partitions text;
    missing_range_defaults text;
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

    SELECT string_agg(required.constraint_name, ', ' ORDER BY required.constraint_name)
      INTO missing_constraints
      FROM (VALUES
        ('global_users','uq_global_users_public','u'),
        ('user_subjects','uq_user_subject_client_subject','u'),('user_subjects','uq_user_subject_current','u'),('user_subjects','ck_user_subject_current_slot','c'),
        ('identifier_claims','uq_identifier_claim','u'),
        ('oauth_clients','uq_oauth_clients_client_id','u'),('api_resources','uq_api_resources_audience','u'),('oauth_scopes','uq_oauth_scopes_code','u'),
        ('idempotency_records','uq_idempotency_caller_key','u'),('outbox_events','uq_outbox_event_id','u'),('inbox_messages','uq_inbox_consumer_event','u'),
        ('operations','uq_operations_caller_key','u'),('approval_cases','uq_approval_cases_execution_id','u'),
        ('operations','ck_operations_actor_pair','c'),('operations','ck_operations_subject_pair','c'),
        ('operation_steps','ck_operation_step_time','c'),('outbox_events','ck_outbox_actor_reference','c'),
        ('audit_events','ck_audit_actor_pair','c'),('audit_events','ck_audit_subject_pair','c'),
        ('operation_policy_versions','uq_operation_policy_order','u'),('operation_policy_versions','ck_operation_policy_order','c'),
        ('configuration_versions','uq_configuration_version','u'),('policy_versions','uq_policy_versions','u'),('event_schema_versions','uq_event_schema_version','u'),
        ('legacy_id_mappings','uq_legacy_external_mapping','u'),('refresh_token_instances','uq_refresh_token_hash','u'),
        ('refresh_token_instances','uq_refresh_token_sequence','u'),('auth_challenges','uq_auth_challenge_token','u'),('authorization_codes','uq_authorization_codes_hash','u'),
        ('auth_challenges','ck_auth_challenge_subject_pair','c'),
        ('access_token_records','uq_access_token_jti','u'),('audit_events','uq_audit_events_event_id','u'),
        ('sessions','ck_sessions_consent_reference','c'),('sessions','ck_sessions_tenant_epoch','c'),
        ('refresh_token_instances','ck_refresh_token_used_time','c'),
        ('session_policy_versions','uq_session_policy_order','u'),('session_policy_versions','ck_session_policy_order','c'),
        ('access_token_records','ck_access_token_actor_pair','c'),('access_token_records','ck_access_token_sender_constraint','c'),('access_token_records','ck_access_token_revocation_time','c'),
        ('access_token_records','ck_access_token_tenant_epoch','c'),('access_token_records','ck_access_token_consent_reference','c'),
        ('access_token_policy_versions','uq_access_token_policy_order','u'),('access_token_policy_versions','ck_access_token_policy_order','c'),
        ('authorization_decisions','uq_authorization_decisions_decision_id','u'),('risk_signals','uq_risk_signals_signal_id','u'),
        ('authorization_decisions','ck_authorization_decision_actor_pair','c'),('authorization_decisions','ck_authorization_decision_consent_reference','c'),('authorization_decisions','ck_authorization_decision_context_epochs','c'),('authorization_decisions','ck_authorization_decision_epochs','c'),
        ('authorization_decision_policy_versions','uq_authorization_decision_policy_order','u'),('authorization_decision_policy_versions','ck_authorization_decision_policy_order','c'),
        ('risk_signals','ck_risk_signal_subject_pair','c'),('risk_signals','ck_risk_signal_object_pair','c'),('risk_signals','ck_risk_signal_retention','c'),
        ('risk_assessments','ck_risk_assessment_subject_pair','c'),('risk_cases','ck_risk_case_subject_pair','c'),('risk_cases','ck_risk_case_owner_pair','c'),('risk_cases','ck_risk_case_time','c'),
        ('privacy_requests','ck_privacy_request_agent_pair','c'),('privacy_requests','ck_privacy_request_completion','c'),('legal_holds','ck_legal_hold_release','c'),
        ('webhook_deliveries','uq_webhook_deliveries_delivery_id','u'),('message_requests','uq_message_requests_request_id','u'),
        ('memberships','uq_memberships_current','u'),('memberships','ck_memberships_current_slot','c'),
        ('user_identities','ck_user_identity_target','c'),('auth_challenges','ck_auth_challenge_attempts','c'),('sessions','ck_sessions_expiry','c'),
        ('directory_sync_batches','ck_directory_sync_counts','c'),('delegations','ck_delegation_depth','c'),('migration_batches','ck_migration_batch_counts','c'),
        ('machine_credentials','uq_machine_credential_replacement','u'),('authorization_grants','ck_authorization_grants_granted_at','c')
      ) AS required(table_name, constraint_name, constraint_type)
     WHERE NOT EXISTS (
        SELECT 1
          FROM pg_constraint constraint_object
          JOIN pg_class relation ON relation.oid = constraint_object.conrelid
          JOIN pg_namespace namespace ON namespace.oid = relation.relnamespace
         WHERE namespace.nspname = 'iam'
           AND relation.relname = required.table_name
           AND constraint_object.conname = required.constraint_name
           AND constraint_object.contype::text = required.constraint_type
     );

    SELECT string_agg(required.index_name, ', ' ORDER BY required.index_name)
      INTO missing_indexes
      FROM (VALUES
        ('global_users','ix_global_users_guest_expiry','(user_type, guest_expires_at)','guest_expires_at IS NOT NULL'),
        ('user_profiles','ix_user_profiles_primary_contact','(primary_contact_identifier_id)','primary_contact_identifier_id IS NOT NULL'),
        ('identifiers','ix_identifier_lookup','(scope_type, scope_id, identifier_type, blind_index)',NULL),
        ('identifier_bindings','ix_identifier_bindings_identifier','(identifier_id, bound_at DESC)',NULL),
        ('identifiers','ix_identifiers_key','(key_id)','key_id IS NOT NULL'),
        ('credential_materials','ix_credential_materials_key','(key_id)','key_id IS NOT NULL'),
        ('auth_challenges','ix_auth_challenges_expiry','(state, expires_at)',NULL),
        ('authenticators','ix_authenticators_user','(user_id, state, authenticator_type)',NULL),
        ('sessions','ix_sessions_user_state','(user_id, state, absolute_expires_at)',NULL),
        ('operations','ix_operations_queue','(state, updated_at)',NULL),
        ('operations','ix_operations_capability','(capability_code, state, created_at DESC)',NULL),
        ('operation_policy_versions','ix_operation_policy_versions_policy','(policy_version_id, operation_id)',NULL),
        ('outbox_events','ix_outbox_publish_queue','(publish_state, next_attempt_at, recorded_at)',NULL),
        ('inbox_messages','ix_inbox_state','(consumer_id, state, received_at)',NULL),
        ('webhook_deliveries','ix_webhook_deliveries_queue','(state, next_attempt_at, created_at)',NULL),
        ('webhook_delivery_attempts','ix_webhook_attempts_delivery','(delivery_id, attempt_no, created_at)',NULL),
        ('message_requests','ix_message_requests_queue','(state, scheduled_at, priority DESC, created_at)',NULL),
        ('message_delivery_attempts','ix_message_attempts_request','(request_id, attempt_no, created_at)',NULL),
        ('risk_signals','ix_risk_signals_subject','(subject_type, subject_id, occurred_at DESC)',NULL),
        ('memberships','ix_memberships_user','(user_id, state, tenant_id)',NULL),
        ('user_role_assignments','ix_user_role_assignments_effective','(user_id, scope_type, scope_id, state, valid_until)',NULL),
        ('relationship_tuples','ix_relationship_tuples_resource','(resource_type, resource_id, relation, state)',NULL),
        ('directory_sync_batches','ix_directory_sync_batches_queue','(state, updated_at)',NULL),
        ('migration_items','ix_migration_items_queue','(state, next_attempt_at, updated_at)',NULL),
        ('sessions','ix_sessions_consent','(consent_id, consent_epoch)','consent_id IS NOT NULL'),
        ('session_policy_versions','ix_session_policy_versions_policy','(policy_version_id, session_id)',NULL),
        ('access_token_records','ix_access_tokens_actor','(actor_type, actor_id, issued_at DESC)','actor_id IS NOT NULL'),
        ('access_token_records','ix_access_tokens_delegation','(delegation_id, issued_at DESC)','delegation_id IS NOT NULL'),
        ('access_token_records','ix_access_tokens_consent','(consent_id, consent_epoch, issued_at DESC)','consent_id IS NOT NULL'),
        ('access_token_records','ix_access_tokens_decision','(authorization_decision_id, issued_at DESC)','authorization_decision_id IS NOT NULL'),
        ('access_token_records','ix_access_token_tenant','(tenant_id, issued_at DESC)','tenant_id IS NOT NULL'),
        ('access_token_policy_versions','ix_access_token_policy_versions_policy','(policy_version_id, token_jti)',NULL),
        ('authorization_decisions','ix_authorization_decisions_validity','(valid_until, decided_at DESC)',NULL),
        ('authorization_decisions','ix_authorization_decisions_client','(client_id, decided_at DESC)','client_id IS NOT NULL'),
        ('authorization_decisions','ix_authorization_decisions_risk','(risk_assessment_id, decided_at DESC)','risk_assessment_id IS NOT NULL'),
        ('authorization_decision_policy_versions','ix_authorization_decision_policy_versions_policy','(policy_version_id, decision_id)',NULL),
        ('risk_assessments','ix_risk_assessments_policy','(risk_policy_version_id, assessed_at DESC)','risk_policy_version_id IS NOT NULL'),
        ('risk_assessments','ix_risk_assessments_model','(model_version_id, assessed_at DESC)','model_version_id IS NOT NULL'),
        ('approval_cases','ix_approval_cases_policy','(policy_version_id, created_at DESC)','policy_version_id IS NOT NULL'),
        ('webhook_deliveries','ix_webhook_deliveries_event_subscription','(event_source_code, event_id, subscription_id, created_at DESC)',NULL),
        ('data_export_artifacts','ix_data_export_artifacts_key','(key_id)',NULL),
        ('jwks_release_keys','ix_jwks_release_keys_key','(key_id)',NULL),
        ('certificates','ix_certificates_key','(key_id)','key_id IS NOT NULL'),
        ('machine_credentials','ix_machine_credentials_key','(key_id)','key_id IS NOT NULL'),
        ('machine_credentials','ix_machine_credentials_certificate','(certificate_id)','certificate_id IS NOT NULL'),
        ('webhook_signing_keys','ix_webhook_signing_keys_key','(key_id)',NULL),
        ('cryptographic_keys','uq_cryptographic_key_kid','(owner_type, owner_id, purpose, kid) NULLS NOT DISTINCT','kid IS NOT NULL'),
        ('outbox_events','ix_outbox_recorded_brin','USING brin (recorded_at)',NULL),
        ('inbox_messages','ix_inbox_received_brin','USING brin (received_at)',NULL)
      ) AS required(table_name, index_name, key_fragment, predicate_fragment)
     WHERE NOT EXISTS (
        SELECT 1
          FROM pg_class index_relation
          JOIN pg_namespace namespace ON namespace.oid = index_relation.relnamespace
          JOIN pg_index index_object ON index_object.indexrelid = index_relation.oid
          JOIN pg_class table_relation ON table_relation.oid = index_object.indrelid
         WHERE namespace.nspname = 'iam'
           AND index_relation.relkind IN ('i', 'I')
           AND index_relation.relname = required.index_name
           AND table_relation.relname = required.table_name
           AND lower(regexp_replace(pg_get_indexdef(index_relation.oid), '\s+', ' ', 'g'))
               LIKE '%' || lower(required.key_fragment) || '%'
           AND (
               (required.predicate_fragment IS NULL AND index_object.indpred IS NULL)
               OR (required.predicate_fragment IS NOT NULL
                   AND lower(pg_get_expr(index_object.indpred, index_object.indrelid))
                       LIKE '%' || lower(required.predicate_fragment) || '%')
           )
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
            ('access_token_records','h','HASH (jti)'),
            ('audit_events','h','HASH (event_id)'),
            ('authentication_attempts','r','RANGE (occurred_at)'),
            ('authorization_decisions','h','HASH (decision_id)'),
            ('risk_signals','h','HASH (signal_id)'),
            ('workload_attestations','r','RANGE (received_at)'),
            ('webhook_deliveries','h','HASH (delivery_id)'),
            ('webhook_delivery_attempts','r','RANGE (created_at)'),
            ('message_requests','h','HASH (request_id)'),
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

    WITH hash_parent(table_name) AS (
        VALUES
            ('outbox_events'),('inbox_messages'),('access_token_records'),('audit_events'),
            ('authorization_decisions'),('risk_signals'),('webhook_deliveries'),('message_requests')
    ), expected_child AS (
        SELECT table_name,
               remainder_no,
               table_name || '_h' || lpad(remainder_no::text, 2, '0') AS child_name
          FROM hash_parent
          CROSS JOIN generate_series(0, 7) AS remainders(remainder_no)
    )
    SELECT string_agg(format('%s remainder %s', table_name, remainder_no), ', ' ORDER BY table_name, remainder_no)
      INTO missing_hash_partitions
      FROM expected_child
     WHERE NOT EXISTS (
        SELECT 1
          FROM pg_inherits inheritance
          JOIN pg_class parent ON parent.oid = inheritance.inhparent
          JOIN pg_class child ON child.oid = inheritance.inhrelid
          JOIN pg_namespace namespace ON namespace.oid = parent.relnamespace
         WHERE namespace.nspname = 'iam'
           AND parent.relname = expected_child.table_name
           AND child.relname = expected_child.child_name
           AND lower(pg_get_expr(child.relpartbound, child.oid)) =
               lower(format('FOR VALUES WITH (modulus 8, remainder %s)', expected_child.remainder_no))
     );

    WITH hash_parent(table_name) AS (
        VALUES
            ('outbox_events'),('inbox_messages'),('access_token_records'),('audit_events'),
            ('authorization_decisions'),('risk_signals'),('webhook_deliveries'),('message_requests')
    ), actual_count AS (
        SELECT hash_parent.table_name,
               count(inheritance.inhrelid) FILTER (WHERE namespace.nspname = 'iam') AS child_count
          FROM hash_parent
          LEFT JOIN pg_class parent ON parent.relname = hash_parent.table_name
          LEFT JOIN pg_namespace namespace ON namespace.oid = parent.relnamespace AND namespace.nspname = 'iam'
          LEFT JOIN pg_inherits inheritance ON inheritance.inhparent = parent.oid
         GROUP BY hash_parent.table_name
    )
    SELECT string_agg(format('%s=%s', table_name, child_count), ', ' ORDER BY table_name)
      INTO invalid_hash_partition_count
      FROM actual_count
     WHERE child_count <> 8;

    WITH range_parent(table_name) AS (
        VALUES
            ('authentication_attempts'),('workload_attestations'),('webhook_delivery_attempts'),
            ('message_delivery_attempts'),('migration_change_logs')
    ), expected_child AS (
        SELECT table_name,
               table_name || '_' || to_char(date_trunc('month', CURRENT_DATE) + make_interval(months => offset_no), 'YYYYMM') AS child_name
          FROM range_parent
          CROSS JOIN generate_series(0, 12) AS offsets(offset_no)
    )
    SELECT string_agg(child_name, ', ' ORDER BY child_name)
      INTO missing_future_partitions
      FROM expected_child
     WHERE NOT EXISTS (
         SELECT 1
           FROM pg_inherits inheritance
           JOIN pg_class parent ON parent.oid = inheritance.inhparent
           JOIN pg_class child ON child.oid = inheritance.inhrelid
           JOIN pg_namespace namespace ON namespace.oid = parent.relnamespace
          WHERE namespace.nspname = 'iam'
            AND parent.relname = expected_child.table_name
            AND child.relname = expected_child.child_name
            AND child.relispartition
      );

    WITH range_parent(table_name) AS (
        VALUES
            ('authentication_attempts'),('workload_attestations'),('webhook_delivery_attempts'),
            ('message_delivery_attempts'),('migration_change_logs')
    )
    SELECT string_agg(table_name, ', ' ORDER BY table_name)
      INTO missing_range_defaults
      FROM range_parent
     WHERE NOT EXISTS (
        SELECT 1
          FROM pg_inherits inheritance
          JOIN pg_class parent ON parent.oid = inheritance.inhparent
          JOIN pg_class child ON child.oid = inheritance.inhrelid
          JOIN pg_namespace namespace ON namespace.oid = parent.relnamespace
         WHERE namespace.nspname = 'iam'
           AND parent.relname = range_parent.table_name
           AND child.relname = range_parent.table_name || '_default'
           AND upper(pg_get_expr(child.relpartbound, child.oid)) = 'DEFAULT'
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
       OR parent_without_child IS NOT NULL OR invalid_partition_contract IS NOT NULL
       OR missing_hash_partitions IS NOT NULL OR invalid_hash_partition_count IS NOT NULL
       OR missing_future_partitions IS NOT NULL OR missing_range_defaults IS NOT NULL OR default_partition_rows <> 0 THEN
        RAISE EXCEPTION '索引约束门禁失败：missing_pk=%, missing_unique=%, missing_indexes=%, partition_parents=%, no_child=%, invalid_partition=%, missing_hash=%, hash_count=%, missing_future=%, missing_defaults=%, default_rows=%',
            coalesce(missing_primary_keys, '<none>'), coalesce(missing_constraints, '<none>'), coalesce(missing_indexes, '<none>'),
            partition_parent_count, coalesce(parent_without_child, '<none>'), coalesce(invalid_partition_contract, '<none>'),
            coalesce(missing_hash_partitions, '<none>'), coalesce(invalid_hash_partition_count, '<none>'),
            coalesce(missing_future_partitions, '<none>'), coalesce(missing_range_defaults, '<none>'), default_partition_rows;
    END IF;
END
$index_contract$;

SELECT 'PASS: 主键、关键唯一性、索引及分区契约完整' AS result;
