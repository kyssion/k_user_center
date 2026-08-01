-- =============================================================================
-- 999_rollback_all.sql
-- 仅用于空环境/演练环境的全量破坏性回滚；不会删除集群级 kuc_* 角色。
-- 执行前必须：SET kuc.allow_destructive_rollback = 'YES';
-- =============================================================================

DO $$
BEGIN
    IF current_setting('kuc.allow_destructive_rollback', true) IS DISTINCT FROM 'YES' THEN
        RAISE EXCEPTION '拒绝破坏性回滚：请显式 SET kuc.allow_destructive_rollback = ''YES''';
    END IF;
END;
$$;

BEGIN;
DROP SCHEMA IF EXISTS migration CASCADE;
DROP SCHEMA IF EXISTS messaging CASCADE;
DROP SCHEMA IF EXISTS audit CASCADE;
DROP SCHEMA IF EXISTS integration CASCADE;
DROP SCHEMA IF EXISTS control CASCADE;
DROP SCHEMA IF EXISTS crypto CASCADE;
DROP SCHEMA IF EXISTS assurance CASCADE;
DROP SCHEMA IF EXISTS workload CASCADE;
DROP SCHEMA IF EXISTS risk CASCADE;
DROP SCHEMA IF EXISTS federation CASCADE;
DROP SCHEMA IF EXISTS privacy CASCADE;
DROP SCHEMA IF EXISTS profile CASCADE;
DROP SCHEMA IF EXISTS authz CASCADE;
DROP SCHEMA IF EXISTS org CASCADE;
DROP SCHEMA IF EXISTS oauth CASCADE;
DROP SCHEMA IF EXISTS authn CASCADE;
DROP SCHEMA IF EXISTS iam CASCADE;
DROP SCHEMA IF EXISTS core CASCADE;
COMMIT;
