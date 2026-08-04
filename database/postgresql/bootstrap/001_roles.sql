\set ON_ERROR_STOP on

-- 角色只在不存在时创建；密码、登录属性和连接来源由部署平台管理。
DO $bootstrap$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'iam_owner') THEN CREATE ROLE iam_owner NOLOGIN; END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'iam_migrator') THEN CREATE ROLE iam_migrator NOLOGIN; END IF;

    -- iam_app_rw 仅承载跨领域技术表权限，不得直接作为运行时登录身份使用。
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'iam_app_rw') THEN CREATE ROLE iam_app_rw NOLOGIN; END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'iam_app_ro') THEN CREATE ROLE iam_app_ro NOLOGIN; END IF;

    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'iam_id_rw') THEN CREATE ROLE iam_id_rw NOLOGIN; END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'iam_auth_rw') THEN CREATE ROLE iam_auth_rw NOLOGIN; END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'iam_plt_rw') THEN CREATE ROLE iam_plt_rw NOLOGIN; END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'iam_tenant_rw') THEN CREATE ROLE iam_tenant_rw NOLOGIN; END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'iam_oap_rw') THEN CREATE ROLE iam_oap_rw NOLOGIN; END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'iam_session_rw') THEN CREATE ROLE iam_session_rw NOLOGIN; END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'iam_profile_rw') THEN CREATE ROLE iam_profile_rw NOLOGIN; END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'iam_priv_rw') THEN CREATE ROLE iam_priv_rw NOLOGIN; END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'iam_authz_rw') THEN CREATE ROLE iam_authz_rw NOLOGIN; END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'iam_fed_rw') THEN CREATE ROLE iam_fed_rw NOLOGIN; END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'iam_risk_rw') THEN CREATE ROLE iam_risk_rw NOLOGIN; END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'iam_machine_rw') THEN CREATE ROLE iam_machine_rw NOLOGIN; END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'iam_ctrl_rw') THEN CREATE ROLE iam_ctrl_rw NOLOGIN; END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'iam_key_rw') THEN CREATE ROLE iam_key_rw NOLOGIN; END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'iam_event_rw') THEN CREATE ROLE iam_event_rw NOLOGIN; END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'iam_msg_rw') THEN CREATE ROLE iam_msg_rw NOLOGIN; END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'iam_mig_rw') THEN CREATE ROLE iam_mig_rw NOLOGIN; END IF;

    -- 敏感读取与领域写入拆分；登录身份仅在确有需要时组合。
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'iam_identifier_reader') THEN CREATE ROLE iam_identifier_reader NOLOGIN; END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'iam_auth_secret_reader') THEN CREATE ROLE iam_auth_secret_reader NOLOGIN; END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'iam_token_secret_reader') THEN CREATE ROLE iam_token_secret_reader NOLOGIN; END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'iam_machine_secret_reader') THEN CREATE ROLE iam_machine_secret_reader NOLOGIN; END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'iam_delivery_secret_reader') THEN CREATE ROLE iam_delivery_secret_reader NOLOGIN; END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'iam_migration_secret_reader') THEN CREATE ROLE iam_migration_secret_reader NOLOGIN; END IF;

    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'iam_audit_writer') THEN CREATE ROLE iam_audit_writer NOLOGIN; END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'iam_audit_reader') THEN CREATE ROLE iam_audit_reader NOLOGIN; END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'iam_ops') THEN CREATE ROLE iam_ops NOLOGIN; END IF;
END
$bootstrap$;

-- 角色脚本可重复执行时也必须收敛已有同名角色的安全属性，不能只依赖首次 CREATE ROLE。
DO $harden_roles$
DECLARE
    role_name text;
    runtime_role text;
BEGIN
    FOREACH role_name IN ARRAY ARRAY[
        'iam_owner', 'iam_migrator', 'iam_app_rw', 'iam_app_ro',
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
            'ALTER ROLE %I WITH NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS INHERIT',
            role_name
        );
    END LOOP;

    -- 运行时能力角色不得直接继承对象所有者或迁移角色；未知的间接继承由 Verification 阻断。
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
            FROM pg_auth_members membership
            JOIN pg_roles granted_role ON granted_role.oid = membership.roleid
            JOIN pg_roles member_role ON member_role.oid = membership.member
            WHERE member_role.rolname = runtime_role
              AND granted_role.rolname IN ('iam_owner', 'iam_migrator')
        ) THEN
            EXECUTE format('REVOKE iam_owner, iam_migrator FROM %I', runtime_role);
        END IF;
    END LOOP;
END
$harden_roles$;

COMMENT ON ROLE iam_owner IS 'IAM 数据库对象所有者；应用运行时禁止使用。';
COMMENT ON ROLE iam_migrator IS 'IAM 版本化迁移执行角色；登录身份由部署平台授予该角色。';
COMMENT ON ROLE iam_app_rw IS 'IAM 跨领域技术表能力角色；仅供领域写角色继承，不得直接授予登录身份。';
COMMENT ON ROLE iam_app_ro IS 'IAM 受控只读查询角色；敏感列另行收回。';

COMMENT ON ROLE iam_id_rw IS 'ID 领域最小读写角色。';
COMMENT ON ROLE iam_auth_rw IS 'AUTH 领域最小读写角色；敏感值读取需叠加专用 Reader。';
COMMENT ON ROLE iam_plt_rw IS 'PLT 领域最小读写角色。';
COMMENT ON ROLE iam_tenant_rw IS 'TENANT 领域最小读写角色。';
COMMENT ON ROLE iam_oap_rw IS 'OAP 领域最小读写角色；Token 摘要读取需叠加专用 Reader。';
COMMENT ON ROLE iam_session_rw IS 'SESSION 领域最小读写角色。';
COMMENT ON ROLE iam_profile_rw IS 'PROFILE 领域最小读写角色。';
COMMENT ON ROLE iam_priv_rw IS 'PRIV 领域最小读写角色。';
COMMENT ON ROLE iam_authz_rw IS 'AUTHZ 领域最小读写角色。';
COMMENT ON ROLE iam_fed_rw IS 'FED 领域最小读写角色。';
COMMENT ON ROLE iam_risk_rw IS 'RISK 领域最小读写角色。';
COMMENT ON ROLE iam_machine_rw IS 'MACHINE 领域最小读写角色；凭证读取需叠加专用 Reader。';
COMMENT ON ROLE iam_ctrl_rw IS 'CTRL 领域最小读写角色。';
COMMENT ON ROLE iam_key_rw IS 'KEY 领域最小读写角色。';
COMMENT ON ROLE iam_event_rw IS 'EVENT 领域最小读写角色；Endpoint 读取需叠加专用 Reader。';
COMMENT ON ROLE iam_msg_rw IS 'MSG 领域最小读写角色；消息目标读取需叠加专用 Reader。';
COMMENT ON ROLE iam_mig_rw IS 'MIG 领域最小读写角色；迁移原文读取需叠加专用 Reader。';

COMMENT ON ROLE iam_identifier_reader IS '可恢复用户标识密文受控读取角色。';
COMMENT ON ROLE iam_auth_secret_reader IS '认证凭证、恢复码和 Challenge 敏感值受控读取角色。';
COMMENT ON ROLE iam_token_secret_reader IS '授权码和 Token 摘要受控读取角色。';
COMMENT ON ROLE iam_machine_secret_reader IS '机器凭证敏感值受控读取角色。';
COMMENT ON ROLE iam_delivery_secret_reader IS 'Webhook Endpoint 和消息目标密文受控读取角色。';
COMMENT ON ROLE iam_migration_secret_reader IS '遗留映射和迁移原文受控读取角色。';
COMMENT ON ROLE iam_audit_writer IS 'IAM 审计事件仅追加写入角色。';
COMMENT ON ROLE iam_audit_reader IS 'IAM 审计事件受控读取角色。';
COMMENT ON ROLE iam_ops IS 'IAM 队列、投递、同步、迁移和运行维护角色。';

GRANT iam_owner TO iam_migrator;
GRANT iam_app_rw TO
    iam_id_rw, iam_auth_rw, iam_plt_rw, iam_tenant_rw, iam_oap_rw,
    iam_session_rw, iam_profile_rw, iam_priv_rw, iam_authz_rw, iam_fed_rw,
    iam_risk_rw, iam_machine_rw, iam_ctrl_rw, iam_key_rw, iam_event_rw,
    iam_msg_rw, iam_mig_rw;
