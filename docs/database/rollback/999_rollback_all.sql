-- =============================================================================
-- rollback/999_rollback_all.sql
-- 初始 Schema 整体回滚
--
-- 【适用边界】
--   仅在阶段 1a 正式上线前、库中没有生产数据时可用。
--   一旦承载生产数据，按蓝图 REQ-MIG-008 与构建文档 §7.3：越过不可逆边界后
--   只允许前向修复，禁止执行本脚本。
--
-- 【使用前必须确认】
--   1. 目标库不是生产库（检查连接串与 current_database()）；
--   2. 已确认无需保留 obs.audit_event 中的审计证据；
--   3. 执行人已获得审批（本脚本删除审计域，属于 CAP-CTRL-003 双人复核范围）。
--
-- 用法：
--   psql "$PGURL" -v ON_ERROR_STOP=1 -v confirm_drop=YES -f rollback/999_rollback_all.sql
-- =============================================================================

\set ON_ERROR_STOP on

-- 未显式传入 confirm_drop=YES 时立即失败，避免误执行
DO $$
BEGIN
    IF current_setting('server_version_num')::int < 160000 THEN
        RAISE NOTICE '目标实例版本低于 PostgreSQL 16，回滚仍可执行但请核对语法差异';
    END IF;
END;
$$;

\if :{?confirm_drop}
\else
  \echo '拒绝执行：必须显式传入 -v confirm_drop=YES'
  \quit 1
\endif

DO $$
DECLARE
    v_schemas text[] := ARRAY[
        'mig','asr','msg','obs','event','ctrl','kms','machine','risk','fed',
        'priv','profile','authz','tenant','session','oap','auth','cred','id','core'
    ];
    v_schema text;
BEGIN
    FOREACH v_schema IN ARRAY v_schemas LOOP
        EXECUTE format('DROP SCHEMA IF EXISTS %I CASCADE', v_schema);
        RAISE NOTICE '已删除 schema %', v_schema;
    END LOOP;
END;
$$;

-- 角色不随 schema 删除，需显式清理（如该实例还有其他库使用同名角色则跳过）
DO $$
DECLARE
    v_role text;
BEGIN
    FOREACH v_role IN ARRAY ARRAY['uc_app','uc_cred_app','uc_audit_writer','uc_auditor','uc_readonly','uc_migrator'] LOOP
        IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = v_role) THEN
            BEGIN
                EXECUTE format('DROP ROLE %I', v_role);
                RAISE NOTICE '已删除角色 %', v_role;
            EXCEPTION WHEN dependent_objects_still_exist THEN
                RAISE NOTICE '角色 % 仍被其他对象依赖，已跳过', v_role;
            END;
        END IF;
    END LOOP;
END;
$$;

\echo '回滚完成。重新部署请按顺序执行 migrations/*.sql 后运行 verify.sql。'
