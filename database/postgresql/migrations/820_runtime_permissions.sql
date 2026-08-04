\set ON_ERROR_STOP on

SET ROLE iam_owner;

REVOKE ALL ON ALL TABLES IN SCHEMA iam FROM PUBLIC;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA iam FROM PUBLIC;

-- 先清空所有运行时角色的直接对象权限，保证本文件可重复执行且不会遗留旧的宽权限。
DO $runtime_permission_reset$
DECLARE
    runtime_roles text[] := ARRAY[
        'iam_app_rw', 'iam_app_ro',
        'iam_id_rw', 'iam_auth_rw', 'iam_plt_rw', 'iam_tenant_rw', 'iam_oap_rw',
        'iam_session_rw', 'iam_profile_rw', 'iam_priv_rw', 'iam_authz_rw', 'iam_fed_rw',
        'iam_risk_rw', 'iam_machine_rw', 'iam_ctrl_rw', 'iam_key_rw', 'iam_event_rw',
        'iam_msg_rw', 'iam_mig_rw',
        'iam_identifier_reader', 'iam_auth_secret_reader', 'iam_token_secret_reader',
        'iam_machine_secret_reader', 'iam_delivery_secret_reader', 'iam_migration_secret_reader',
        'iam_audit_writer', 'iam_audit_reader', 'iam_ops'
    ];
    runtime_role text;
    column_permission record;
BEGIN
    FOREACH runtime_role IN ARRAY runtime_roles
    LOOP
        EXECUTE format('REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA iam FROM %I', runtime_role);
        EXECUTE format('REVOKE ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA iam FROM %I', runtime_role);
    END LOOP;

    -- 表级 REVOKE 不依赖实现细节推断列 ACL；显式清理历史列授权后再按下文重授。
    FOR column_permission IN
        SELECT namespace.nspname AS schema_name,
               relation.relname AS table_name,
               attribute.attname AS column_name,
               grantee.rolname AS role_name,
               permission.privilege_type
        FROM pg_attribute attribute
        JOIN pg_class relation ON relation.oid = attribute.attrelid
        JOIN pg_namespace namespace ON namespace.oid = relation.relnamespace
        CROSS JOIN LATERAL aclexplode(attribute.attacl) permission
        JOIN pg_roles grantee ON grantee.oid = permission.grantee
        WHERE namespace.nspname = 'iam'
          AND attribute.attnum > 0
          AND NOT attribute.attisdropped
          AND (grantee.rolname = ANY(runtime_roles) OR grantee.rolname = 'iam_sensitive_rw')
    LOOP
        EXECUTE format(
            'REVOKE %s (%I) ON TABLE %I.%I FROM %I',
            column_permission.privilege_type,
            column_permission.column_name,
            column_permission.schema_name,
            column_permission.table_name,
            column_permission.role_name
        );
    END LOOP;

    -- 兼容旧基线：若历史 iam_sensitive_rw 仍存在，撤销其对象权限，后续不再使用该角色。
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'iam_sensitive_rw') THEN
        EXECUTE 'REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA iam FROM iam_sensitive_rw';
        EXECUTE 'REVOKE ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA iam FROM iam_sensitive_rw';
        EXECUTE 'REVOKE USAGE ON SCHEMA iam FROM iam_sensitive_rw';
    END IF;
END
$runtime_permission_reset$;

-- 跨领域技术表能力。iam_app_rw 只供领域写角色继承，禁止直接配置为登录身份。
GRANT SELECT, INSERT ON
    iam.idempotency_records, iam.operations, iam.operation_steps, iam.inbox_messages
TO iam_app_rw;
GRANT SELECT, INSERT ON iam.outbox_events TO iam_app_rw;

-- ID：标识密文读取与领域写入拆分。
GRANT SELECT, INSERT ON
    iam.global_users, iam.user_subjects, iam.identifier_claims,
    iam.identifier_bindings, iam.user_identities, iam.user_aliases
TO iam_id_rw;
GRANT INSERT ON iam.identifiers TO iam_id_rw;
GRANT SELECT ON iam.identifiers TO iam_identifier_reader;

-- AUTH：历史/尝试事实仅追加；秘密读取由 iam_auth_secret_reader 提供。
GRANT SELECT, INSERT ON
    iam.authenticators, iam.recovery_code_batches, iam.login_transactions,
    iam.login_transaction_steps, iam.authentication_contexts
TO iam_auth_rw;
GRANT INSERT ON iam.credential_materials, iam.recovery_codes, iam.auth_challenges TO iam_auth_rw;
GRANT INSERT ON iam.password_history TO iam_auth_rw;
GRANT SELECT, INSERT ON iam.authentication_attempts TO iam_auth_rw;
GRANT SELECT ON
    iam.credential_materials, iam.password_history, iam.recovery_codes, iam.auth_challenges
TO iam_auth_secret_reader;

-- PLT / TENANT。
GRANT SELECT, INSERT ON iam.applications, iam.resource_quotas TO iam_plt_rw;
GRANT SELECT, INSERT ON iam.usage_records TO iam_plt_rw;
GRANT SELECT, INSERT ON
    iam.business_lines, iam.tenants, iam.tenant_domains, iam.organizations,
    iam.memberships, iam.invitations, iam.groups, iam.group_members
TO iam_tenant_rw;

-- OAP：授权码和 Token 摘要读取与写入拆分。
GRANT SELECT, INSERT ON
    iam.oauth_clients, iam.api_resources, iam.oauth_scopes,
    iam.authorization_grants, iam.token_families
TO iam_oap_rw;
GRANT INSERT ON
    iam.authorization_codes, iam.refresh_token_instances, iam.access_token_records
TO iam_oap_rw;
GRANT SELECT ON
    iam.authorization_codes, iam.refresh_token_instances, iam.access_token_records
TO iam_token_secret_reader;

-- SESSION：撤销记录是仅追加事实。
GRANT SELECT, INSERT ON iam.devices, iam.sessions, iam.session_participants TO iam_session_rw;
GRANT SELECT, INSERT ON iam.revocation_entries TO iam_session_rw;

-- PROFILE。
GRANT SELECT, INSERT ON
    iam.user_profiles, iam.profile_documents, iam.identity_assurance_assertions
TO iam_profile_rw;

-- PRIV：不可变内容/事实只允许 INSERT；版本发布元数据使用列级 CAS 更新。
GRANT SELECT, INSERT ON iam.agreement_versions TO iam_priv_rw;
GRANT SELECT, INSERT ON iam.agreement_acceptances, iam.consents, iam.deletion_proofs TO iam_priv_rw;
GRANT SELECT, INSERT ON
    iam.consent_aggregates, iam.privacy_requests, iam.legal_holds, iam.data_export_artifacts
TO iam_priv_rw;

-- AUTHZ：策略载荷和决策事实不可修改；发布元数据使用列级 CAS 更新。
GRANT SELECT, INSERT ON
    iam.permissions, iam.roles, iam.role_permissions, iam.user_role_assignments,
    iam.group_role_assignments, iam.machine_role_assignments, iam.data_scope_definitions,
    iam.policy_bindings, iam.relationship_tuples
TO iam_authz_rw;
GRANT SELECT, INSERT ON iam.policy_versions TO iam_authz_rw;
GRANT SELECT, INSERT ON iam.authorization_decisions TO iam_authz_rw;

-- FED。
GRANT SELECT, INSERT ON
    iam.identity_providers, iam.directory_connectors, iam.directory_sync_cursors,
    iam.directory_sync_batches, iam.directory_object_mappings
TO iam_fed_rw;

-- RISK：原始信号、评估及其输入关系是仅追加事实。
GRANT SELECT, INSERT ON iam.risk_signals, iam.risk_assessments, iam.risk_assessment_signals TO iam_risk_rw;
GRANT SELECT, INSERT ON
    iam.risk_cases, iam.security_signals, iam.restriction_entries, iam.risk_entity_links
TO iam_risk_rw;

-- MACHINE：凭证读取拆分；信任包内容和证明事实不可修改。
GRANT SELECT, INSERT ON iam.machine_principals, iam.delegations TO iam_machine_rw;
GRANT INSERT ON iam.machine_credentials TO iam_machine_rw;
GRANT SELECT ON iam.machine_credentials TO iam_machine_secret_reader;
GRANT SELECT, INSERT ON iam.workload_trust_bundle_versions TO iam_machine_rw;
GRANT SELECT, INSERT ON iam.workload_attestations TO iam_machine_rw;

-- CTRL：审批动作和发布项仅追加；配置内容不可修改。
GRANT SELECT, INSERT ON
    iam.approval_cases, iam.configuration_releases, iam.security_exceptions
TO iam_ctrl_rw;
GRANT SELECT, INSERT ON iam.approval_actions, iam.configuration_release_items TO iam_ctrl_rw;
GRANT SELECT, INSERT ON iam.configuration_versions TO iam_ctrl_rw;

-- KEY：JWKS 内容由不可变 Release/Key 关系表达，仅生命周期元数据可更新。
GRANT SELECT, INSERT ON iam.cryptographic_keys, iam.certificates TO iam_key_rw;
GRANT SELECT, INSERT ON iam.jwks_releases, iam.jwks_release_keys TO iam_key_rw;

-- EVENT：Schema 内容和投递尝试不可修改；Endpoint 读取拆分。
GRANT SELECT, INSERT ON iam.event_schema_versions TO iam_event_rw;
GRANT INSERT ON iam.webhook_subscriptions TO iam_event_rw;
GRANT SELECT ON iam.webhook_subscriptions TO iam_delivery_secret_reader;
GRANT SELECT, INSERT ON
    iam.webhook_signing_keys, iam.webhook_deliveries,
    iam.event_replay_requests, iam.consumer_checkpoints
TO iam_event_rw;
GRANT SELECT, INSERT ON iam.webhook_delivery_attempts TO iam_event_rw;

-- MSG：模板内容和投递尝试不可修改；消息目标读取拆分。
GRANT SELECT, INSERT ON
    iam.message_providers, iam.contact_reachability, iam.message_suppressions
TO iam_msg_rw;
GRANT SELECT, INSERT ON iam.message_template_versions TO iam_msg_rw;
GRANT INSERT ON iam.message_requests TO iam_msg_rw;
GRANT SELECT ON iam.message_requests TO iam_delivery_secret_reader;
GRANT SELECT, INSERT ON iam.message_delivery_attempts TO iam_msg_rw;

-- MIG：迁移原文读取拆分；Change Log 是仅追加事实。
GRANT SELECT, INSERT ON iam.legacy_systems, iam.migration_batches, iam.migration_items TO iam_mig_rw;
GRANT INSERT ON iam.legacy_id_mappings TO iam_mig_rw;
GRANT INSERT ON iam.migration_change_logs TO iam_mig_rw;
GRANT SELECT ON iam.legacy_id_mappings, iam.migration_change_logs TO iam_migration_secret_reader;

-- 运维角色仅处理明确登记的运行队列和状态；不获得 DELETE，也不修改权威配置内容。
GRANT SELECT ON
    iam.event_schema_versions, iam.webhook_signing_keys,
    iam.message_providers, iam.message_template_versions, iam.legacy_systems
TO iam_ops;
GRANT SELECT, INSERT ON
    iam.operations, iam.operation_steps, iam.outbox_events, iam.inbox_messages,
    iam.directory_sync_cursors, iam.directory_sync_batches,
    iam.migration_batches, iam.migration_items,
    iam.webhook_deliveries, iam.event_replay_requests, iam.consumer_checkpoints
TO iam_ops;
GRANT INSERT ON iam.message_requests TO iam_ops;
GRANT SELECT, INSERT ON iam.webhook_delivery_attempts, iam.message_delivery_attempts TO iam_ops;
GRANT INSERT ON iam.migration_change_logs TO iam_ops;

-- 受控只读角色默认可读非敏感表；敏感表改为无权限或脱敏列级读取。
GRANT SELECT ON ALL TABLES IN SCHEMA iam TO iam_app_ro;
REVOKE ALL ON
    iam.credential_materials, iam.password_history, iam.recovery_codes, iam.auth_challenges,
    iam.authorization_codes, iam.refresh_token_instances, iam.access_token_records,
    iam.machine_credentials, iam.identifiers, iam.webhook_subscriptions,
    iam.message_requests, iam.legacy_id_mappings, iam.migration_change_logs
FROM iam_app_ro;
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

-- 审计事实只允许专用 Writer 追加、Reader 读取。
REVOKE ALL ON iam.audit_events FROM iam_app_ro;
GRANT INSERT ON iam.audit_events TO iam_audit_writer;
GRANT SELECT ON iam.audit_events TO iam_audit_reader;

-- 禁止通过分区子表绕过父表权限；所有运行时访问都必须从分区父表进入。
DO $partition_permissions$
DECLARE
    child record;
    runtime_role text;
BEGIN
    FOR child IN
        SELECT child_ns.nspname AS schema_name, child.relname AS table_name
        FROM pg_inherits
        JOIN pg_class parent ON parent.oid = pg_inherits.inhparent
        JOIN pg_class child ON child.oid = pg_inherits.inhrelid
        JOIN pg_namespace parent_ns ON parent_ns.oid = parent.relnamespace
        JOIN pg_namespace child_ns ON child_ns.oid = child.relnamespace
        WHERE parent_ns.nspname = 'iam'
    LOOP
        FOREACH runtime_role IN ARRAY ARRAY[
            'iam_app_rw', 'iam_app_ro',
            'iam_id_rw', 'iam_auth_rw', 'iam_plt_rw', 'iam_tenant_rw', 'iam_oap_rw',
            'iam_session_rw', 'iam_profile_rw', 'iam_priv_rw', 'iam_authz_rw', 'iam_fed_rw',
            'iam_risk_rw', 'iam_machine_rw', 'iam_ctrl_rw', 'iam_key_rw', 'iam_event_rw',
            'iam_msg_rw', 'iam_mig_rw',
            'iam_identifier_reader', 'iam_auth_secret_reader', 'iam_token_secret_reader',
            'iam_machine_secret_reader', 'iam_delivery_secret_reader', 'iam_migration_secret_reader',
            'iam_audit_writer', 'iam_audit_reader', 'iam_ops'
        ]
        LOOP
            EXECUTE format(
                'REVOKE ALL PRIVILEGES ON TABLE %I.%I FROM %I',
                child.schema_name, child.table_name, runtime_role
            );
        END LOOP;
    END LOOP;
END
$partition_permissions$;

-- 不设置宽泛默认 Grant；新增表和分区必须在版本化 Migration 中显式授权。
