\set ON_ERROR_STOP on

-- 技术组角色只在不存在时创建；部署平台另建登录身份、管理凭据与连接来源，并按最小职责授予组角色。
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

-- 技术角色是部署平台授予登录身份的组角色；即使同名角色已存在，也重申安全属性。
ALTER ROLE iam_owner NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
ALTER ROLE iam_migrator NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
ALTER ROLE iam_app_rw NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
ALTER ROLE iam_app_ro NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
ALTER ROLE iam_sensitive_rw NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
ALTER ROLE iam_audit_writer NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
ALTER ROLE iam_audit_reader NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
ALTER ROLE iam_ops NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;

COMMENT ON ROLE iam_owner IS 'IAM 数据库对象所有者；应用运行时禁止使用。';
COMMENT ON ROLE iam_migrator IS 'IAM 版本化迁移执行角色；登录身份由部署平台授予该角色。';
COMMENT ON ROLE iam_app_rw IS 'IAM 普通业务表运行时读写角色。';
COMMENT ON ROLE iam_app_ro IS 'IAM 受控只读查询角色。';
COMMENT ON ROLE iam_sensitive_rw IS 'IAM 凭证材料和机器凭证等敏感表受控读写角色。';
COMMENT ON ROLE iam_audit_writer IS 'IAM 审计事件仅追加写入角色。';
COMMENT ON ROLE iam_audit_reader IS 'IAM 审计事件受控读取角色。';
COMMENT ON ROLE iam_ops IS 'IAM 队列、投递、分区、迁移和运行维护角色。';

GRANT iam_owner TO iam_migrator;
