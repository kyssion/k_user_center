-- =============================================================================
-- optional/910_rls_optional.sql
-- 可选：为租户内表启用行级安全（RLS）
-- 依据：REQ-TENANT-003、INV-G-015；构建文档 §9 三层隔离的第三层
--
-- 【本文件不在默认迁移序列中】
-- 启用前置条件：
--   1. AT-TENANT-001 至 AT-TENANT-007 全套负向用例通过；
--   2. 连接池已确认每次取用连接后立即执行 SET LOCAL app.current_tenant_id；
--   3. 已完成一次演练：故意不设置 GUC，确认得到空结果而不是跨租户数据。
-- 风险提示：GUC 未设置时策略求值为 NULL，查询返回空集。这是"失败关闭"，
--           但排障成本高，因此默认不启用，由应用层过滤器作为主控制。
-- 回滚：对每张表执行 ALTER TABLE ... DISABLE ROW LEVEL SECURITY 并 DROP POLICY。
-- =============================================================================

SET client_min_messages = warning;

DO $$
DECLARE
    v_tables text[][] := ARRAY[
        ['tenant','membership'],['tenant','invitation'],['tenant','organization'],
        ['tenant','user_group'],['tenant','user_group_member'],['tenant','usage_metering'],
        ['oap','client'],['auth','login_transaction'],['session','user_session'],
        ['session','authorization_grant'],['session','token_family'],['session','access_token_reference'],
        ['authz','role'],['authz','role_assignment'],
        ['profile','business_profile'],['risk','risk_assessment'],['risk','risk_case'],
        ['machine','machine_principal'],['ctrl','approval_case'],['event','outbox'],
        ['event','webhook_endpoint'],['asr','delegation'],['fed','directory_sync_state']
    ];
    v_item text[];
BEGIN
    FOREACH v_item SLICE 1 IN ARRAY v_tables LOOP
        -- 平台级数据使用全零租户，必须始终可见，否则平台自身功能不可用
        -- 不使用 FORCE ROW LEVEL SECURITY：表 owner（uc_migrator）需要跨租户视图做对账与修复
        EXECUTE format('ALTER TABLE %I.%I ENABLE ROW LEVEL SECURITY', v_item[1], v_item[2]);

        IF NOT EXISTS (
            SELECT 1 FROM pg_policies
            WHERE schemaname = v_item[1] AND tablename = v_item[2] AND policyname = 'p_tenant_isolation'
        ) THEN
            EXECUTE format($f$
                CREATE POLICY p_tenant_isolation ON %I.%I
                    USING (
                        tenant_id = '00000000-0000-0000-0000-000000000000'::uuid
                        OR tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid
                    )
                    WITH CHECK (
                        tenant_id = '00000000-0000-0000-0000-000000000000'::uuid
                        OR tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid
                    );
            $f$, v_item[1], v_item[2]);
        END IF;

        -- 迁移与运维角色绕过 RLS（对账、修复与批处理需要跨租户视图）
        EXECUTE format('ALTER TABLE %I.%I OWNER TO uc_migrator', v_item[1], v_item[2]);
    END LOOP;
END;
$$;

-- 使用方式（应用侧，每次从连接池取用后立即执行）：
--   SET LOCAL app.current_tenant_id = '<tenant uuid>';
-- 平台级操作（无租户上下文）不设置该变量，只能访问全零租户数据。

SELECT core.fn_migration_apply('910', 'rls_optional：租户内表行级安全策略（可选，需显式启用）');
