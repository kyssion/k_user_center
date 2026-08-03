\set ON_ERROR_STOP on

SET ROLE iam_owner;

REVOKE ALL ON ALL TABLES IN SCHEMA iam FROM PUBLIC;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA iam FROM PUBLIC;

GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA iam TO iam_app_rw;
GRANT SELECT ON ALL TABLES IN SCHEMA iam TO iam_app_ro;

-- 运维角色只处理运行队列、投递、同步和迁移状态，不得修改用户、租户、权限、策略、审批或配置等权威业务表。
GRANT SELECT ON iam.event_schema_versions, iam.webhook_signing_keys,
    iam.message_providers, iam.message_template_versions, iam.legacy_systems
TO iam_ops;
GRANT SELECT, INSERT, UPDATE, DELETE ON iam.operations, iam.operation_steps,
    iam.outbox_events, iam.inbox_messages,
    iam.directory_sync_cursors, iam.directory_sync_batches,
    iam.migration_batches, iam.migration_items,
    iam.webhook_deliveries, iam.event_replay_requests, iam.consumer_checkpoints,
    iam.message_requests
TO iam_ops;
GRANT SELECT, INSERT ON iam.webhook_delivery_attempts, iam.message_delivery_attempts, iam.migration_change_logs
TO iam_ops;

-- 敏感表从普通角色收回，再授予专用角色。
REVOKE ALL ON iam.credential_materials, iam.password_history, iam.machine_credentials FROM iam_app_rw, iam_app_ro, iam_ops;
GRANT SELECT, INSERT, UPDATE, DELETE ON iam.credential_materials, iam.password_history, iam.machine_credentials TO iam_sensitive_rw;

REVOKE SELECT ON iam.recovery_codes, iam.auth_challenges, iam.authorization_codes,
    iam.refresh_token_instances, iam.access_token_records
FROM iam_app_rw, iam_app_ro, iam_ops;
GRANT SELECT ON iam.recovery_codes, iam.auth_challenges, iam.authorization_codes,
    iam.refresh_token_instances, iam.access_token_records
TO iam_sensitive_rw;

-- 含可恢复标识、Webhook Endpoint、消息目标和迁移原文的列只允许专用角色访问。
REVOKE SELECT ON iam.identifiers, iam.webhook_subscriptions, iam.message_requests, iam.legacy_id_mappings, iam.migration_change_logs FROM iam_app_rw, iam_app_ro, iam_ops;
GRANT SELECT (
    id, identifier_type, scope_type, scope_id, blind_index, value_fingerprint,
    normalization_version, verification_state, verified_at, created_at, updated_at, row_version
) ON iam.identifiers TO iam_app_ro;
GRANT SELECT (
    id, subscription_id, owner_type, owner_id, client_id, tenant_id, endpoint_host_hash,
    event_filter, state, active_configuration_id, created_at, updated_at, row_version
) ON iam.webhook_subscriptions TO iam_app_ro;
GRANT SELECT (
    id, request_id, purpose, channel, target_digest, identifier_id, template_version_id,
    parameter_digest, caller_scope, idempotency_key, state, priority, scheduled_at,
    expires_at, created_at, completed_at
) ON iam.message_requests TO iam_app_ro;
GRANT SELECT (
    id, system_id, external_type, external_id_digest, platform_type, platform_id,
    mapping_version, state, first_mapped_at, last_verified_at, created_at, updated_at, row_version
) ON iam.legacy_id_mappings TO iam_app_ro;
GRANT SELECT (
    id, system_id, external_object_type, external_object_id_digest, sequence_no,
    source_version, idempotency_key, change_type, payload_digest, state, occurred_at, recorded_at
) ON iam.migration_change_logs TO iam_app_ro;
GRANT SELECT ON iam.identifiers, iam.webhook_subscriptions, iam.message_requests, iam.legacy_id_mappings, iam.migration_change_logs TO iam_sensitive_rw;

-- 审计表只允许专用 Writer 追加，Reader 只读；普通读写角色无权修改。
REVOKE ALL ON iam.audit_events FROM iam_app_rw, iam_app_ro, iam_sensitive_rw, iam_ops;
GRANT INSERT ON iam.audit_events TO iam_audit_writer;
GRANT SELECT ON iam.audit_events TO iam_audit_reader;

-- 追加型证据表禁止普通角色更新和删除。
REVOKE UPDATE, DELETE ON iam.authentication_attempts, iam.authorization_decisions, iam.risk_signals,
    iam.workload_attestations, iam.webhook_delivery_attempts, iam.message_delivery_attempts,
    iam.agreement_acceptances, iam.approval_actions, iam.deletion_proofs, iam.migration_change_logs
FROM iam_app_rw, iam_ops;

-- ALL TABLES 包含当前分区，必须同步收回直接访问分区的越权权限。
DO $partition_permissions$
DECLARE
    child record;
BEGIN
    FOR child IN
        SELECT child_ns.nspname AS schema_name, child.relname AS table_name, parent.relname AS parent_name
        FROM pg_inherits
        JOIN pg_class parent ON parent.oid = pg_inherits.inhparent
        JOIN pg_class child ON child.oid = pg_inherits.inhrelid
        JOIN pg_namespace parent_ns ON parent_ns.oid = parent.relnamespace
        JOIN pg_namespace child_ns ON child_ns.oid = child.relnamespace
        WHERE parent_ns.nspname = 'iam'
    LOOP
        IF child.parent_name = 'audit_events' THEN
            EXECUTE format('REVOKE ALL ON TABLE %I.%I FROM iam_app_rw, iam_app_ro, iam_sensitive_rw, iam_ops', child.schema_name, child.table_name);
            EXECUTE format('GRANT SELECT ON TABLE %I.%I TO iam_audit_reader', child.schema_name, child.table_name);
        END IF;

        IF child.parent_name IN ('access_token_records', 'message_requests', 'migration_change_logs') THEN
            EXECUTE format('REVOKE SELECT ON TABLE %I.%I FROM iam_app_rw, iam_app_ro, iam_ops', child.schema_name, child.table_name);
        END IF;

        IF child.parent_name IN (
            'authentication_attempts', 'authorization_decisions', 'risk_signals',
            'workload_attestations', 'webhook_delivery_attempts',
            'message_delivery_attempts', 'migration_change_logs'
        ) THEN
            EXECUTE format('REVOKE UPDATE, DELETE ON TABLE %I.%I FROM iam_app_rw, iam_ops', child.schema_name, child.table_name);
        END IF;
    END LOOP;
END
$partition_permissions$;

-- 不为未来表设置宽泛默认 Grant；新增表或分区必须在后续版本化 Migration 中显式授权。
