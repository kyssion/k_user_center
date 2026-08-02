\set ON_ERROR_STOP on
-- =============================================================================
-- baseline/roles.sql
-- 数据库 NOLOGIN 角色、平台对象所有权与全局默认权限；对象权限在各 Schema/security.sql
-- =============================================================================

BEGIN;
SET LOCAL lock_timeout = '10s';

DO $$
DECLARE v_role text;
BEGIN
    FOREACH v_role IN ARRAY ARRAY[
        'kuc_owner', 'kuc_migrator', 'kuc_app', 'kuc_authn_writer',
        'kuc_control_writer', 'kuc_outbox_dispatcher', 'kuc_message_dispatcher',
        'kuc_audit_writer', 'kuc_auditor', 'kuc_readonly'
    ]
    LOOP
        IF to_regrole(v_role) IS NULL THEN
            EXECUTE format('CREATE ROLE %I NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS', v_role);
        END IF;
    END LOOP;
END;
$$;

COMMENT ON ROLE kuc_owner IS '统一身份与访问平台数据库对象的 NOLOGIN 所有者；仅供受控迁移 SET ROLE。';
COMMENT ON ROLE kuc_migrator IS '统一身份与访问平台迁移执行角色；负责 DDL、注释和结构验收。';
COMMENT ON ROLE kuc_app IS '普通领域应用角色；仅访问获准业务表，不得写控制面或读取凭证密文。';
COMMENT ON ROLE kuc_authn_writer IS '认证数据面写角色；负责认证、会话、Token 与联合运行态。';
COMMENT ON ROLE kuc_control_writer IS '控制面写角色；负责审批、策略、密钥、联合与隐私配置。';
COMMENT ON ROLE kuc_outbox_dispatcher IS '事件与 Webhook 投递角色；仅推进投递状态、尝试记录和消费水位。';
COMMENT ON ROLE kuc_message_dispatcher IS '消息投递角色；仅推进发送状态、回执、可达性和供应商指标。';
COMMENT ON ROLE kuc_audit_writer IS '独立审计写角色；负责 Audit Outbox、审计事件和数据访问审计。';
COMMENT ON ROLE kuc_auditor IS '审计与控制面只读角色；用于合规检查和证据查询。';
COMMENT ON ROLE kuc_readonly IS '受控运维只读角色；生产环境应继续按人员和环境收窄。';

GRANT kuc_owner TO kuc_migrator;

REVOKE CREATE ON SCHEMA public FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA public FROM PUBLIC;

-- 将平台对象从构建登录用户转交统一 NOLOGIN owner，RLS 才不会被应用角色以 owner 身份绕过。
DO $$
DECLARE r record;
BEGIN
    FOR r IN
        SELECT nspname FROM pg_namespace
         WHERE nspname = ANY(ARRAY['core','iam','authn','oauth','org','authz','profile','privacy','federation','risk','workload','assurance','crypto','control','integration','audit','messaging','migration'])
    LOOP
        EXECUTE format('ALTER SCHEMA %I OWNER TO kuc_owner', r.nspname);
    END LOOP;

    FOR r IN
        SELECT c.oid::regclass AS object_name, c.relkind
          FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
         WHERE n.nspname = ANY(ARRAY['core','iam','authn','oauth','org','authz','profile','privacy','federation','risk','workload','assurance','crypto','control','integration','audit','messaging','migration'])
           AND c.relkind IN ('r','p','v','m','S','f')
    LOOP
        EXECUTE CASE r.relkind
            WHEN 'v' THEN format('ALTER VIEW %s OWNER TO kuc_owner', r.object_name)
            WHEN 'm' THEN format('ALTER MATERIALIZED VIEW %s OWNER TO kuc_owner', r.object_name)
            WHEN 'S' THEN format('ALTER SEQUENCE %s OWNER TO kuc_owner', r.object_name)
            WHEN 'f' THEN format('ALTER FOREIGN TABLE %s OWNER TO kuc_owner', r.object_name)
            ELSE format('ALTER TABLE %s OWNER TO kuc_owner', r.object_name)
        END;
    END LOOP;

    FOR r IN
        SELECT n.nspname, p.proname, p.prokind, pg_get_function_identity_arguments(p.oid) AS identity_arguments
          FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
         WHERE n.nspname = ANY(ARRAY['core','iam','authn','oauth','org','authz','profile','privacy','federation','risk','workload','assurance','crypto','control','integration','audit','messaging','migration'])
    LOOP
        IF r.prokind = 'p' THEN
            EXECUTE format('ALTER PROCEDURE %I.%I(%s) OWNER TO kuc_owner', r.nspname, r.proname, r.identity_arguments);
        ELSIF r.prokind = 'a' THEN
            EXECUTE format('ALTER AGGREGATE %I.%I(%s) OWNER TO kuc_owner', r.nspname, r.proname, r.identity_arguments);
        ELSE
            EXECUTE format('ALTER FUNCTION %I.%I(%s) OWNER TO kuc_owner', r.nspname, r.proname, r.identity_arguments);
        END IF;
    END LOOP;
END;
$$;

SET LOCAL ROLE kuc_owner;

ALTER DEFAULT PRIVILEGES FOR ROLE kuc_owner
    REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
ALTER DEFAULT PRIVILEGES FOR ROLE kuc_owner IN SCHEMA core, iam, authn, oauth, org, authz, profile, privacy, federation, risk, workload, assurance, crypto, control, integration, audit, messaging, migration
    GRANT ALL PRIVILEGES ON TABLES TO kuc_migrator;
ALTER DEFAULT PRIVILEGES FOR ROLE kuc_owner IN SCHEMA core, iam, authn, oauth, org, authz, profile, privacy, federation, risk, workload, assurance, crypto, control, integration, audit, messaging, migration
    GRANT EXECUTE ON FUNCTIONS TO kuc_migrator;

SELECT core.fn_register_migration('baseline:roles', '统一对象所有者、职责分离角色与全局默认权限');
COMMIT;
