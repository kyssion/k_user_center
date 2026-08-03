\set ON_ERROR_STOP on

-- 在目标数据库内执行。数据库 CONNECT 权限由环境变量和平台账号策略控制。
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
REVOKE ALL ON DATABASE :"DBNAME" FROM PUBLIC;

-- 能力角色不能单独建立连接，必须由领域写角色或受控查询/运维角色提供 CONNECT。
REVOKE CONNECT ON DATABASE :"DBNAME" FROM
    iam_app_rw, iam_identifier_reader, iam_auth_secret_reader, iam_token_secret_reader,
    iam_machine_secret_reader, iam_delivery_secret_reader, iam_migration_secret_reader,
    iam_audit_writer;

DO $retire_legacy_role$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'iam_sensitive_rw') THEN
        EXECUTE format('REVOKE CONNECT ON DATABASE %I FROM iam_sensitive_rw', current_database());
    END IF;
END
$retire_legacy_role$;

-- iam Schema 在首个 Migration 中创建；本文件只声明数据库级最小权限。
-- iam_app_rw 和敏感 Reader 是可组合能力角色，不单独获得 CONNECT。
GRANT CONNECT ON DATABASE :"DBNAME" TO
    iam_migrator, iam_app_ro, iam_audit_reader, iam_ops,
    iam_id_rw, iam_auth_rw, iam_plt_rw, iam_tenant_rw, iam_oap_rw,
    iam_session_rw, iam_profile_rw, iam_priv_rw, iam_authz_rw, iam_fed_rw,
    iam_risk_rw, iam_machine_rw, iam_ctrl_rw, iam_key_rw, iam_event_rw,
    iam_msg_rw, iam_mig_rw;
