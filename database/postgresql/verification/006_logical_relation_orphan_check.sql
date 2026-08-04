\set ON_ERROR_STOP on

-- 本文件由 Generate-DatabaseDocs.ps1 从 Column Comment 中的精确逻辑引用生成，请勿手工维护。
CREATE TEMP TABLE iam_orphan_scan AS
WITH orphan_scan(relation_name, orphan_count) AS (
    SELECT 'access_token_records.policy_version_ids -> policy_versions.id', count(*) FROM iam.access_token_records s CROSS JOIN LATERAL unnest(s.policy_version_ids) AS v(value) LEFT JOIN iam.policy_versions t ON t.id = v.value WHERE t.id IS NULL
    UNION ALL SELECT 'authorization_decisions.policy_version_ids -> policy_versions.id', count(*) FROM iam.authorization_decisions s CROSS JOIN LATERAL unnest(s.policy_version_ids) AS v(value) LEFT JOIN iam.policy_versions t ON t.id = v.value WHERE t.id IS NULL
    UNION ALL SELECT 'operations.policy_version_ids -> policy_versions.id', count(*) FROM iam.operations s CROSS JOIN LATERAL unnest(s.policy_version_ids) AS v(value) LEFT JOIN iam.policy_versions t ON t.id = v.value WHERE t.id IS NULL
    UNION ALL SELECT 'sessions.policy_version_ids -> policy_versions.id', count(*) FROM iam.sessions s CROSS JOIN LATERAL unnest(s.policy_version_ids) AS v(value) LEFT JOIN iam.policy_versions t ON t.id = v.value WHERE t.id IS NULL
)
SELECT relation_name, orphan_count FROM orphan_scan WHERE orphan_count > 0 ORDER BY relation_name;

DO $orphan_gate$
DECLARE details text;
BEGIN
    SELECT string_agg(format('%s=%s', relation_name, orphan_count), '; ' ORDER BY relation_name) INTO details FROM iam_orphan_scan;
    IF details IS NOT NULL THEN RAISE EXCEPTION '逻辑关系孤儿门禁失败：%', details; END IF;
END
$orphan_gate$;

SELECT 'PASS: 全部可解析逻辑引用无孤儿记录' AS result;
DROP TABLE iam_orphan_scan;
