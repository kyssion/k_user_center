\set ON_ERROR_STOP on

DO $permissions_check$
DECLARE
    errors text[] := ARRAY[]::text[];
BEGIN
    IF has_table_privilege('iam_app_rw', 'iam.audit_events', 'UPDATE') OR has_table_privilege('iam_app_rw', 'iam.audit_events', 'DELETE') THEN
        errors := array_append(errors, 'iam_app_rw 可修改 audit_events');
    END IF;
    IF NOT has_table_privilege('iam_audit_writer', 'iam.audit_events', 'INSERT') THEN
        errors := array_append(errors, 'iam_audit_writer 无 audit_events INSERT');
    END IF;
    IF has_table_privilege('iam_audit_writer', 'iam.audit_events', 'UPDATE') OR has_table_privilege('iam_audit_writer', 'iam.audit_events', 'DELETE') THEN
        errors := array_append(errors, 'iam_audit_writer 可修改审计历史');
    END IF;
    IF has_column_privilege('iam_app_ro', 'iam.identifiers', 'value_ciphertext', 'SELECT') THEN
        errors := array_append(errors, 'iam_app_ro 可读 identifier 密文');
    END IF;
    IF has_column_privilege('iam_app_ro', 'iam.webhook_subscriptions', 'endpoint_ciphertext', 'SELECT') THEN
        errors := array_append(errors, 'iam_app_ro 可读 Webhook Endpoint 密文');
    END IF;
    IF has_column_privilege('iam_app_ro', 'iam.message_requests', 'target_ciphertext', 'SELECT') THEN
        errors := array_append(errors, 'iam_app_ro 可读消息目标密文');
    END IF;
    IF has_table_privilege('iam_app_rw', 'iam.credential_materials', 'SELECT') THEN
        errors := array_append(errors, 'iam_app_rw 可读凭证材料');
    END IF;
    IF has_table_privilege('iam_ops', 'iam.global_users', 'INSERT')
       OR has_table_privilege('iam_ops', 'iam.global_users', 'UPDATE')
       OR has_table_privilege('iam_ops', 'iam.global_users', 'DELETE')
       OR has_table_privilege('iam_ops', 'iam.roles', 'UPDATE')
       OR has_table_privilege('iam_ops', 'iam.policy_versions', 'UPDATE')
       OR has_table_privilege('iam_ops', 'iam.configuration_versions', 'UPDATE')
       OR has_table_privilege('iam_ops', 'iam.approval_cases', 'UPDATE') THEN
        errors := array_append(errors, 'iam_ops 可修改非运维权威业务表');
    END IF;
    IF has_table_privilege('iam_ops', 'iam.authorization_decisions', 'UPDATE')
       OR has_table_privilege('iam_ops', 'iam.authorization_decisions', 'DELETE')
       OR has_table_privilege('iam_ops', 'iam.webhook_delivery_attempts', 'UPDATE')
       OR has_table_privilege('iam_ops', 'iam.message_delivery_attempts', 'DELETE')
       OR has_table_privilege('iam_ops', 'iam.migration_change_logs', 'UPDATE') THEN
        errors := array_append(errors, 'iam_ops 可改写追加型证据');
    END IF;
    IF array_length(errors, 1) IS NOT NULL THEN
        RAISE EXCEPTION '权限门禁失败：%', array_to_string(errors, '; ');
    END IF;
END
$permissions_check$;

SELECT 'PASS: 运行时角色满足敏感数据、运维范围和追加写最小权限' AS result;
