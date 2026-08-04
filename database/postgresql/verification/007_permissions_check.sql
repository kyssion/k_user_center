\set ON_ERROR_STOP on

DO $permissions_check$
DECLARE
    errors text[] := ARRAY[]::text[];
    missing_roles text[];
    runtime_role text;
    domain_role text;
    child record;
BEGIN
    SELECT array_agg(expected_role ORDER BY expected_role)
    INTO missing_roles
    FROM unnest(ARRAY[
        'iam_owner', 'iam_migrator', 'iam_app_rw', 'iam_app_ro',
        'iam_id_rw', 'iam_auth_rw', 'iam_plt_rw', 'iam_tenant_rw', 'iam_oap_rw',
        'iam_session_rw', 'iam_profile_rw', 'iam_priv_rw', 'iam_authz_rw', 'iam_fed_rw',
        'iam_risk_rw', 'iam_machine_rw', 'iam_ctrl_rw', 'iam_key_rw', 'iam_event_rw',
        'iam_msg_rw', 'iam_mig_rw',
        'iam_identifier_reader', 'iam_auth_secret_reader', 'iam_token_secret_reader',
        'iam_machine_secret_reader', 'iam_delivery_secret_reader', 'iam_migration_secret_reader',
        'iam_audit_writer', 'iam_audit_reader', 'iam_ops'
    ]) AS expected(expected_role)
    WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = expected_role);

    IF array_length(missing_roles, 1) IS NOT NULL THEN
        errors := array_append(errors, format('缺少运行时角色：%s', array_to_string(missing_roles, ', ')));
    END IF;

    FOREACH domain_role IN ARRAY ARRAY[
        'iam_id_rw', 'iam_auth_rw', 'iam_plt_rw', 'iam_tenant_rw', 'iam_oap_rw',
        'iam_session_rw', 'iam_profile_rw', 'iam_priv_rw', 'iam_authz_rw', 'iam_fed_rw',
        'iam_risk_rw', 'iam_machine_rw', 'iam_ctrl_rw', 'iam_key_rw', 'iam_event_rw',
        'iam_msg_rw', 'iam_mig_rw'
    ]
    LOOP
        IF NOT pg_has_role(domain_role, 'iam_app_rw', 'MEMBER') THEN
            errors := array_append(errors, format('%s 未继承跨领域技术表能力', domain_role));
        END IF;
        IF NOT has_database_privilege(domain_role, current_database(), 'CONNECT') THEN
            errors := array_append(errors, format('%s 缺少数据库 CONNECT', domain_role));
        END IF;
    END LOOP;

    IF has_database_privilege('iam_app_rw', current_database(), 'CONNECT')
       OR has_database_privilege('iam_auth_secret_reader', current_database(), 'CONNECT')
       OR has_database_privilege('iam_token_secret_reader', current_database(), 'CONNECT')
       OR has_database_privilege('iam_audit_writer', current_database(), 'CONNECT') THEN
        errors := array_append(errors, '可组合能力角色可单独连接数据库');
    END IF;

    -- iam_app_rw 只承载技术表，不得直接扩散到领域权威表。
    IF NOT has_table_privilege('iam_app_rw', 'iam.idempotency_records', 'SELECT')
       OR NOT has_table_privilege('iam_app_rw', 'iam.idempotency_records', 'INSERT')
       OR has_table_privilege('iam_app_rw', 'iam.idempotency_records', 'UPDATE')
       OR NOT has_column_privilege('iam_app_rw', 'iam.idempotency_records', 'state', 'UPDATE')
       OR has_column_privilege('iam_app_rw', 'iam.idempotency_records', 'request_hash', 'UPDATE')
       OR NOT has_table_privilege('iam_app_rw', 'iam.outbox_events', 'INSERT') THEN
        errors := array_append(errors, 'iam_app_rw 缺少公共技术表能力');
    END IF;
    IF has_table_privilege('iam_app_rw', 'iam.global_users', 'SELECT')
       OR has_table_privilege('iam_app_rw', 'iam.tenants', 'INSERT')
       OR has_table_privilege('iam_app_rw', 'iam.roles', 'UPDATE') THEN
        errors := array_append(errors, 'iam_app_rw 越权访问领域权威表');
    END IF;

    -- 领域正向能力与跨领域隔离抽样。
    IF NOT has_table_privilege('iam_id_rw', 'iam.global_users', 'SELECT')
       OR NOT has_table_privilege('iam_id_rw', 'iam.global_users', 'INSERT')
       OR NOT has_column_privilege('iam_id_rw', 'iam.global_users', 'lifecycle_state', 'UPDATE')
       OR has_column_privilege('iam_id_rw', 'iam.global_users', 'global_user_id', 'UPDATE')
       OR has_any_column_privilege('iam_id_rw', 'iam.tenants', 'UPDATE') THEN
        errors := array_append(errors, 'iam_id_rw 领域边界错误');
    END IF;
    IF NOT has_table_privilege('iam_tenant_rw', 'iam.memberships', 'SELECT')
       OR NOT has_table_privilege('iam_tenant_rw', 'iam.memberships', 'INSERT')
       OR NOT has_column_privilege('iam_tenant_rw', 'iam.memberships', 'state', 'UPDATE')
       OR has_column_privilege('iam_tenant_rw', 'iam.memberships', 'user_id', 'UPDATE')
       OR has_table_privilege('iam_tenant_rw', 'iam.policy_versions', 'INSERT') THEN
        errors := array_append(errors, 'iam_tenant_rw 领域边界错误');
    END IF;
    IF NOT has_table_privilege('iam_authz_rw', 'iam.roles', 'SELECT')
       OR NOT has_table_privilege('iam_authz_rw', 'iam.roles', 'INSERT')
       OR NOT has_column_privilege('iam_authz_rw', 'iam.roles', 'state', 'UPDATE')
       OR has_column_privilege('iam_authz_rw', 'iam.roles', 'role_code', 'UPDATE')
       OR has_any_column_privilege('iam_authz_rw', 'iam.configuration_releases', 'UPDATE') THEN
        errors := array_append(errors, 'iam_authz_rw 领域边界错误');
    END IF;

    -- 敏感读取与领域写入必须组合，Reader 自身不可改写。
    IF has_table_privilege('iam_id_rw', 'iam.identifiers', 'SELECT')
       OR NOT has_table_privilege('iam_id_rw', 'iam.identifiers', 'INSERT')
       OR NOT has_column_privilege('iam_id_rw', 'iam.identifiers', 'verification_state', 'UPDATE')
       OR has_column_privilege('iam_id_rw', 'iam.identifiers', 'blind_index', 'UPDATE')
       OR NOT has_table_privilege('iam_identifier_reader', 'iam.identifiers', 'SELECT')
       OR has_table_privilege('iam_identifier_reader', 'iam.identifiers', 'INSERT') THEN
        errors := array_append(errors, 'Identifier 敏感读写拆分错误');
    END IF;
    IF has_table_privilege('iam_auth_rw', 'iam.credential_materials', 'SELECT')
       OR NOT has_table_privilege('iam_auth_rw', 'iam.credential_materials', 'INSERT')
       OR NOT has_column_privilege('iam_auth_rw', 'iam.credential_materials', 'usage_counter', 'UPDATE')
       OR has_column_privilege('iam_auth_rw', 'iam.credential_materials', 'secret_hash', 'UPDATE')
       OR NOT has_table_privilege('iam_auth_secret_reader', 'iam.credential_materials', 'SELECT')
       OR has_table_privilege('iam_auth_secret_reader', 'iam.credential_materials', 'UPDATE') THEN
        errors := array_append(errors, 'AUTH 敏感读写拆分错误');
    END IF;
    IF has_table_privilege('iam_oap_rw', 'iam.access_token_records', 'SELECT')
       OR NOT has_table_privilege('iam_oap_rw', 'iam.access_token_records', 'INSERT')
       OR NOT has_column_privilege('iam_oap_rw', 'iam.access_token_records', 'revoked_at', 'UPDATE')
       OR has_column_privilege('iam_oap_rw', 'iam.access_token_records', 'token_hash', 'UPDATE')
       OR NOT has_table_privilege('iam_token_secret_reader', 'iam.access_token_records', 'SELECT')
       OR has_table_privilege('iam_token_secret_reader', 'iam.access_token_records', 'UPDATE') THEN
        errors := array_append(errors, 'OAP Token 敏感读写拆分错误');
    END IF;
    IF has_table_privilege('iam_machine_rw', 'iam.machine_credentials', 'SELECT')
       OR NOT has_column_privilege('iam_machine_rw', 'iam.machine_credentials', 'state', 'UPDATE')
       OR has_column_privilege('iam_machine_rw', 'iam.machine_credentials', 'fingerprint', 'UPDATE')
       OR NOT has_table_privilege('iam_machine_secret_reader', 'iam.machine_credentials', 'SELECT') THEN
        errors := array_append(errors, 'MACHINE 凭证敏感读写拆分错误');
    END IF;
    IF has_table_privilege('iam_event_rw', 'iam.webhook_subscriptions', 'SELECT')
       OR has_table_privilege('iam_msg_rw', 'iam.message_requests', 'SELECT')
       OR NOT has_column_privilege('iam_event_rw', 'iam.webhook_deliveries', 'state', 'UPDATE')
       OR has_column_privilege('iam_event_rw', 'iam.webhook_deliveries', 'event_source_code', 'UPDATE')
       OR has_column_privilege('iam_event_rw', 'iam.webhook_deliveries', 'payload_digest', 'UPDATE')
       OR NOT has_column_privilege('iam_msg_rw', 'iam.message_requests', 'state', 'UPDATE')
       OR has_column_privilege('iam_msg_rw', 'iam.message_requests', 'parameters', 'UPDATE')
       OR NOT has_table_privilege('iam_delivery_secret_reader', 'iam.webhook_subscriptions', 'SELECT')
       OR NOT has_table_privilege('iam_delivery_secret_reader', 'iam.message_requests', 'SELECT') THEN
        errors := array_append(errors, '投递目标敏感读写拆分错误');
    END IF;
    IF has_table_privilege('iam_mig_rw', 'iam.legacy_id_mappings', 'SELECT')
       OR NOT has_table_privilege('iam_migration_secret_reader', 'iam.legacy_id_mappings', 'SELECT')
       OR has_table_privilege('iam_migration_secret_reader', 'iam.legacy_id_mappings', 'UPDATE') THEN
        errors := array_append(errors, '迁移原文敏感读写拆分错误');
    END IF;

    -- 受控只读角色不能看到密文列，但保留必要的非敏感定位列。
    IF has_column_privilege('iam_app_ro', 'iam.identifiers', 'value_ciphertext', 'SELECT')
       OR NOT has_column_privilege('iam_app_ro', 'iam.identifiers', 'blind_index', 'SELECT')
       OR has_column_privilege('iam_app_ro', 'iam.webhook_subscriptions', 'endpoint_ciphertext', 'SELECT')
       OR has_column_privilege('iam_app_ro', 'iam.message_requests', 'target_ciphertext', 'SELECT') THEN
        errors := array_append(errors, 'iam_app_ro 敏感列隔离错误');
    END IF;

    -- 内容不可变版本表只允许更新生命周期元数据，不允许整行或内容字段 UPDATE。
    IF has_table_privilege('iam_priv_rw', 'iam.agreement_versions', 'UPDATE')
       OR NOT has_column_privilege('iam_priv_rw', 'iam.agreement_versions', 'state', 'UPDATE')
       OR has_column_privilege('iam_priv_rw', 'iam.agreement_versions', 'content_digest', 'UPDATE')
       OR has_table_privilege('iam_authz_rw', 'iam.policy_versions', 'UPDATE')
       OR NOT has_column_privilege('iam_authz_rw', 'iam.policy_versions', 'row_version', 'UPDATE')
       OR has_column_privilege('iam_authz_rw', 'iam.policy_versions', 'payload', 'UPDATE')
       OR has_table_privilege('iam_ctrl_rw', 'iam.configuration_versions', 'UPDATE')
       OR has_column_privilege('iam_ctrl_rw', 'iam.configuration_versions', 'payload_digest', 'UPDATE')
       OR has_table_privilege('iam_event_rw', 'iam.event_schema_versions', 'UPDATE')
       OR has_column_privilege('iam_event_rw', 'iam.event_schema_versions', 'json_schema', 'UPDATE')
       OR has_table_privilege('iam_msg_rw', 'iam.message_template_versions', 'UPDATE')
       OR has_column_privilege('iam_msg_rw', 'iam.message_template_versions', 'content_template', 'UPDATE') THEN
        errors := array_append(errors, '不可变版本内容的列级 UPDATE 边界错误');
    END IF;

    -- 所有运行时写角色都只能获得列级 UPDATE，禁止重新出现整表 UPDATE。
    FOREACH runtime_role IN ARRAY ARRAY[
        'iam_app_rw',
        'iam_id_rw', 'iam_auth_rw', 'iam_plt_rw', 'iam_tenant_rw', 'iam_oap_rw',
        'iam_session_rw', 'iam_profile_rw', 'iam_priv_rw', 'iam_authz_rw', 'iam_fed_rw',
        'iam_risk_rw', 'iam_machine_rw', 'iam_ctrl_rw', 'iam_key_rw', 'iam_event_rw',
        'iam_msg_rw', 'iam_mig_rw', 'iam_ops'
    ]
    LOOP
        IF EXISTS (
            SELECT 1
            FROM pg_tables
            WHERE schemaname = 'iam'
              AND has_table_privilege(runtime_role, format('%I.%I', schemaname, tablename), 'UPDATE')
        ) THEN
            errors := array_append(errors, format('%s 仍持有整表 UPDATE', runtime_role));
        END IF;
    END LOOP;

    -- 稳定标识、创建时间、请求摘要和证据内容不得更新；生命周期字段必须可推进。
    IF has_column_privilege('iam_id_rw', 'iam.user_subjects', 'subject_id', 'UPDATE')
       OR NOT has_column_privilege('iam_id_rw', 'iam.user_subjects', 'current_subject_slot', 'UPDATE')
       OR has_column_privilege('iam_profile_rw', 'iam.identity_assurance_assertions', 'evidence_digest', 'UPDATE')
       OR NOT has_column_privilege('iam_profile_rw', 'iam.identity_assurance_assertions', 'state', 'UPDATE')
       OR has_column_privilege('iam_oap_rw', 'iam.authorization_codes', 'code_hash', 'UPDATE')
       OR NOT has_column_privilege('iam_oap_rw', 'iam.authorization_codes', 'state', 'UPDATE')
       OR has_column_privilege('iam_app_rw', 'iam.operations', 'created_at', 'UPDATE')
       OR has_column_privilege('iam_app_rw', 'iam.operations', 'request_digest', 'UPDATE') THEN
        errors := array_append(errors, '稳定标识、请求快照或证据内容的列级 UPDATE 边界错误');
    END IF;

    -- 审计与追加型事实禁止历史改写。
    IF NOT has_table_privilege('iam_audit_writer', 'iam.audit_events', 'INSERT')
       OR has_table_privilege('iam_audit_writer', 'iam.audit_events', 'UPDATE')
       OR has_table_privilege('iam_audit_writer', 'iam.audit_events', 'DELETE')
       OR has_table_privilege('iam_app_ro', 'iam.audit_events', 'SELECT') THEN
        errors := array_append(errors, '审计表最小权限错误');
    END IF;
    IF has_any_column_privilege('iam_auth_rw', 'iam.authentication_attempts', 'UPDATE')
       OR has_any_column_privilege('iam_priv_rw', 'iam.consents', 'UPDATE')
       OR has_any_column_privilege('iam_authz_rw', 'iam.authorization_decisions', 'UPDATE')
       OR has_any_column_privilege('iam_risk_rw', 'iam.risk_assessments', 'UPDATE')
       OR has_any_column_privilege('iam_machine_rw', 'iam.workload_attestations', 'UPDATE')
       OR has_any_column_privilege('iam_ctrl_rw', 'iam.approval_actions', 'UPDATE')
       OR has_any_column_privilege('iam_event_rw', 'iam.webhook_delivery_attempts', 'UPDATE')
       OR has_any_column_privilege('iam_msg_rw', 'iam.message_delivery_attempts', 'UPDATE')
       OR has_any_column_privilege('iam_mig_rw', 'iam.migration_change_logs', 'UPDATE') THEN
        errors := array_append(errors, '追加型事实存在 UPDATE 权限');
    END IF;

    -- 所有运行时角色都不得 DELETE；物理清理由受控维护流程执行。
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
        IF EXISTS (
            SELECT 1
            FROM pg_tables
            WHERE schemaname = 'iam'
              AND has_table_privilege(runtime_role, format('%I.%I', schemaname, tablename), 'DELETE')
        ) THEN
            errors := array_append(errors, format('%s 获得运行时 DELETE 权限', runtime_role));
        END IF;
    END LOOP;

    -- iam_ops 只能操作明确登记的运行队列，不得越权修改权威业务表或读取迁移原文。
    IF has_any_column_privilege('iam_ops', 'iam.global_users', 'UPDATE')
       OR has_any_column_privilege('iam_ops', 'iam.roles', 'UPDATE')
       OR has_any_column_privilege('iam_ops', 'iam.policy_versions', 'UPDATE')
       OR has_any_column_privilege('iam_ops', 'iam.configuration_versions', 'UPDATE')
       OR has_any_column_privilege('iam_ops', 'iam.approval_cases', 'UPDATE')
       OR has_table_privilege('iam_ops', 'iam.message_requests', 'SELECT')
       OR has_table_privilege('iam_ops', 'iam.migration_change_logs', 'SELECT') THEN
        errors := array_append(errors, 'iam_ops 越过运行队列边界');
    END IF;

    -- 任何角色都不得直接访问分区子表，避免绕过父表的敏感列和不可变约束授权。
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
            IF has_table_privilege(runtime_role, format('%I.%I', child.schema_name, child.table_name), 'SELECT')
               OR has_table_privilege(runtime_role, format('%I.%I', child.schema_name, child.table_name), 'INSERT')
               OR has_table_privilege(runtime_role, format('%I.%I', child.schema_name, child.table_name), 'UPDATE')
               OR has_any_column_privilege(runtime_role, format('%I.%I', child.schema_name, child.table_name), 'UPDATE')
               OR has_table_privilege(runtime_role, format('%I.%I', child.schema_name, child.table_name), 'DELETE') THEN
                errors := array_append(errors, format('%s 可直接访问分区 %s.%s', runtime_role, child.schema_name, child.table_name));
            END IF;
        END LOOP;
    END LOOP;

    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'iam_sensitive_rw')
       AND (
           EXISTS (
               SELECT 1
               FROM pg_tables
               WHERE schemaname = 'iam'
                 AND (
                     has_table_privilege('iam_sensitive_rw', format('%I.%I', schemaname, tablename), 'SELECT')
                     OR has_table_privilege('iam_sensitive_rw', format('%I.%I', schemaname, tablename), 'INSERT')
                     OR has_table_privilege('iam_sensitive_rw', format('%I.%I', schemaname, tablename), 'UPDATE')
                     OR has_table_privilege('iam_sensitive_rw', format('%I.%I', schemaname, tablename), 'DELETE')
                 )
           )
           OR EXISTS (
               SELECT 1
               FROM pg_attribute attribute
               JOIN pg_class relation ON relation.oid = attribute.attrelid
               JOIN pg_namespace namespace ON namespace.oid = relation.relnamespace
               WHERE namespace.nspname = 'iam'
                 AND attribute.attnum > 0
                 AND NOT attribute.attisdropped
                 AND (
                     has_column_privilege('iam_sensitive_rw', relation.oid, attribute.attnum, 'SELECT')
                     OR has_column_privilege('iam_sensitive_rw', relation.oid, attribute.attnum, 'INSERT')
                     OR has_column_privilege('iam_sensitive_rw', relation.oid, attribute.attnum, 'UPDATE')
                     OR has_column_privilege('iam_sensitive_rw', relation.oid, attribute.attnum, 'REFERENCES')
                 )
           )
       ) THEN
        errors := array_append(errors, '旧 iam_sensitive_rw 仍持有对象权限');
    END IF;

    IF array_length(errors, 1) IS NOT NULL THEN
        RAISE EXCEPTION '权限门禁失败：%', array_to_string(errors, '; ');
    END IF;
END
$permissions_check$;

SELECT 'PASS: 领域写入、敏感读取、不可变事实和分区访问均满足最小权限' AS result;
