\set ON_ERROR_STOP on

-- 角色只在不存在时创建；密码、登录属性和连接来源由部署平台管理。
DO $bootstrap$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'iam_owner') THEN CREATE ROLE iam_owner NOLOGIN; END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'iam_migrator') THEN CREATE ROLE iam_migrator NOLOGIN; END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'iam_app_rw') THEN CREATE ROLE iam_app_rw NOLOGIN; END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'iam_app_ro') THEN CREATE ROLE iam_app_ro NOLOGIN; END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'iam_sensitive_rw') THEN CREATE ROLE iam_sensitive_rw NOLOGIN; END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'iam_audit_writer') THEN CREATE ROLE iam_audit_writer NOLOGIN; END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'iam_audit_reader') THEN CREATE ROLE iam_audit_reader NOLOGIN; END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'iam_ops') THEN CREATE ROLE iam_ops NOLOGIN; END IF;
END
$bootstrap$;

COMMENT ON ROLE iam_owner IS 'IAM 数据库对象所有者；应用运行时禁止使用。';
COMMENT ON ROLE iam_migrator IS 'IAM 版本化迁移执行角色；登录身份由部署平台授予该角色。';
COMMENT ON ROLE iam_app_rw IS 'IAM 普通业务表运行时读写角色。';
COMMENT ON ROLE iam_app_ro IS 'IAM 受控只读查询角色。';
COMMENT ON ROLE iam_sensitive_rw IS 'IAM 凭证材料和机器凭证等敏感表受控读写角色。';
COMMENT ON ROLE iam_audit_writer IS 'IAM 审计事件仅追加写入角色。';
COMMENT ON ROLE iam_audit_reader IS 'IAM 审计事件受控读取角色。';
COMMENT ON ROLE iam_ops IS 'IAM 队列、投递、分区、迁移和运行维护角色。';

GRANT iam_owner TO iam_migrator;
