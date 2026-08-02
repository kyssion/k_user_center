\set ON_ERROR_STOP on

-- 返回 orphan_count > 0 的逻辑关系。允许的历史墓碑例外必须登记后扩展 WHERE 条件，禁止静默忽略。
CREATE TEMP TABLE iam_orphan_scan AS
WITH orphan_scan(relation_name, orphan_count) AS (
    SELECT 'user_subjects.user_id -> global_users.id', count(*) FROM iam.user_subjects s LEFT JOIN iam.global_users t ON t.id = s.user_id WHERE t.id IS NULL
    UNION ALL SELECT 'identifier_bindings.identifier_id -> identifiers.id', count(*) FROM iam.identifier_bindings s LEFT JOIN iam.identifiers t ON t.id = s.identifier_id WHERE t.id IS NULL
    UNION ALL SELECT 'identifier_bindings.user_id -> global_users.id', count(*) FROM iam.identifier_bindings s LEFT JOIN iam.global_users t ON t.id = s.user_id WHERE t.id IS NULL
    UNION ALL SELECT 'authenticators.user_id -> global_users.id', count(*) FROM iam.authenticators s LEFT JOIN iam.global_users t ON t.id = s.user_id WHERE t.id IS NULL
    UNION ALL SELECT 'operation_steps.operation_id -> operations.id', count(*) FROM iam.operation_steps s LEFT JOIN iam.operations t ON t.id = s.operation_id WHERE t.id IS NULL
    UNION ALL SELECT 'applications.business_line_id -> business_lines.id', count(*) FROM iam.applications s LEFT JOIN iam.business_lines t ON t.id = s.business_line_id WHERE t.id IS NULL
    UNION ALL SELECT 'tenants.business_line_id -> business_lines.id', count(*) FROM iam.tenants s LEFT JOIN iam.business_lines t ON t.id = s.business_line_id WHERE t.id IS NULL
    UNION ALL SELECT 'memberships.user_id -> global_users.id', count(*) FROM iam.memberships s LEFT JOIN iam.global_users t ON t.id = s.user_id WHERE t.id IS NULL
    UNION ALL SELECT 'sessions.user_id -> global_users.id', count(*) FROM iam.sessions s LEFT JOIN iam.global_users t ON t.id = s.user_id WHERE t.id IS NULL
    UNION ALL SELECT 'sessions.client_id -> oauth_clients.id', count(*) FROM iam.sessions s LEFT JOIN iam.oauth_clients t ON t.id = s.client_id WHERE t.id IS NULL
    UNION ALL SELECT 'authorization_grants.user_id -> global_users.id', count(*) FROM iam.authorization_grants s LEFT JOIN iam.global_users t ON t.id = s.user_id WHERE t.id IS NULL
    UNION ALL SELECT 'consents.aggregate_id -> consent_aggregates.id', count(*) FROM iam.consents s LEFT JOIN iam.consent_aggregates t ON t.id = s.aggregate_id WHERE t.id IS NULL
    UNION ALL SELECT 'role_permissions.role_id -> roles.id', count(*) FROM iam.role_permissions s LEFT JOIN iam.roles t ON t.id = s.role_id WHERE t.id IS NULL
    UNION ALL SELECT 'role_permissions.permission_id -> permissions.id', count(*) FROM iam.role_permissions s LEFT JOIN iam.permissions t ON t.id = s.permission_id WHERE t.id IS NULL
    UNION ALL SELECT 'directory_sync_batches.connector_id -> directory_connectors.id', count(*) FROM iam.directory_sync_batches s LEFT JOIN iam.directory_connectors t ON t.id = s.connector_id WHERE t.id IS NULL
    UNION ALL SELECT 'risk_assessment_signals.assessment_id -> risk_assessments.id', count(*) FROM iam.risk_assessment_signals s LEFT JOIN iam.risk_assessments t ON t.id = s.assessment_id WHERE t.id IS NULL
    UNION ALL SELECT 'machine_credentials.machine_principal_id -> machine_principals.id', count(*) FROM iam.machine_credentials s LEFT JOIN iam.machine_principals t ON t.id = s.machine_principal_id WHERE t.id IS NULL
    UNION ALL SELECT 'approval_actions.approval_case_id -> approval_cases.id', count(*) FROM iam.approval_actions s LEFT JOIN iam.approval_cases t ON t.id = s.approval_case_id WHERE t.id IS NULL
    UNION ALL SELECT 'configuration_release_items.release_id -> configuration_releases.id', count(*) FROM iam.configuration_release_items s LEFT JOIN iam.configuration_releases t ON t.id = s.release_id WHERE t.id IS NULL
    UNION ALL SELECT 'legacy_id_mappings.system_id -> legacy_systems.id', count(*) FROM iam.legacy_id_mappings s LEFT JOIN iam.legacy_systems t ON t.id = s.system_id WHERE t.id IS NULL
)
SELECT relation_name, orphan_count
FROM orphan_scan
WHERE orphan_count > 0
ORDER BY relation_name;

DO $orphan_gate$
DECLARE
    details text;
BEGIN
    SELECT string_agg(format('%s=%s', relation_name, orphan_count), '; ' ORDER BY relation_name)
      INTO details
      FROM iam_orphan_scan;
    IF details IS NOT NULL THEN
        RAISE EXCEPTION '逻辑关系孤儿门禁失败：%', details;
    END IF;
END
$orphan_gate$;

SELECT 'PASS: 已登记的关键逻辑关系无孤儿记录' AS result;
DROP TABLE iam_orphan_scan;
