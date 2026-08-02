\set ON_ERROR_STOP on

DO $index_contract$
DECLARE
    missing_primary_keys text;
    missing_constraints text;
    partition_parent_count integer;
    parent_without_child text;
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
        ('uq_global_users_public'),('uq_user_subject_client_subject'),('uq_identifier_claim'),
        ('uq_oauth_clients_client_id'),('uq_api_resources_audience'),('uq_oauth_scopes_code'),
        ('uq_idempotency_caller_key'),('uq_outbox_event_id'),('uq_inbox_consumer_event'),
        ('uq_configuration_version'),('uq_policy_versions'),('uq_event_schema_version'),
        ('uq_legacy_external_mapping'),('uq_refresh_token_hash'),('uq_authorization_codes_hash')
      ) AS required(constraint_name)
     WHERE NOT EXISTS (SELECT 1 FROM pg_constraint c WHERE c.conname = required.constraint_name);

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

    IF missing_primary_keys IS NOT NULL OR missing_constraints IS NOT NULL OR partition_parent_count <> 13 OR parent_without_child IS NOT NULL THEN
        RAISE EXCEPTION '索引约束门禁失败：missing_pk=%, missing_unique=%, partition_parents=%, no_child=%',
            coalesce(missing_primary_keys, '<none>'), coalesce(missing_constraints, '<none>'), partition_parent_count, coalesce(parent_without_child, '<none>');
    END IF;
END
$index_contract$;

SELECT 'PASS: 主键、关键唯一性和 13 个分区父表完整' AS result;

