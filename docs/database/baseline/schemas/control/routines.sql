-- =============================================================================
-- baseline/schemas/control/routines.sql
-- control Schema 的最终函数、过程、局部触发器及内联 COMMENT
-- PostgreSQL 16+；应用技术栈：.NET 10 + SqlSugar
-- =============================================================================

CREATE OR REPLACE FUNCTION control.fn_active_approval_binding_guard()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    v_old jsonb := to_jsonb(OLD);
    v_new jsonb := to_jsonb(NEW);
BEGIN
    IF (v_old ->> TG_ARGV[0]) = TG_ARGV[1]
       AND ((v_old -> TG_ARGV[2]) IS DISTINCT FROM (v_new -> TG_ARGV[2])
            OR (v_old -> TG_ARGV[3]) IS DISTINCT FROM (v_new -> TG_ARGV[3])) THEN
        RAISE EXCEPTION 'ACTIVE_APPROVAL_BINDING_IMMUTABLE' USING ERRCODE = '55000';
    END IF;
    RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION control.fn_release_guard()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    v_state_column text := TG_ARGV[0];
    v_old_state text;
    v_new_state text;
    v_old jsonb := to_jsonb(OLD);
    v_new jsonb := to_jsonb(NEW);
    i integer;
BEGIN
    EXECUTE format('SELECT ($1).%I::text, ($2).%I::text', v_state_column, v_state_column)
       INTO v_old_state, v_new_state USING OLD, NEW;

    IF v_old_state IN ('DEPRECATED', 'SUPERSEDED', 'REVOKED')
       AND v_new_state IS DISTINCT FROM v_old_state THEN
        RAISE EXCEPTION 'TERMINAL_STATE_IMMUTABLE: %.%=%',
            TG_TABLE_SCHEMA || '.' || TG_TABLE_NAME, v_state_column, v_old_state
            USING ERRCODE = '23514';
    END IF;

    IF v_old_state <> 'DRAFT' THEN
        FOR i IN 0..TG_NARGS - 1 LOOP
            v_old := v_old - TG_ARGV[i];
            v_new := v_new - TG_ARGV[i];
        END LOOP;
        IF v_old IS DISTINCT FROM v_new THEN
            RAISE EXCEPTION 'RELEASE_CONTENT_IMMUTABLE: %',
                TG_TABLE_SCHEMA || '.' || TG_TABLE_NAME USING ERRCODE = '55000';
        END IF;
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_approval_case_public_id BEFORE INSERT ON control.approval_case FOR EACH ROW EXECUTE FUNCTION core.fn_register_public_id('APPROVAL_CASE');

CREATE TRIGGER trg_approval_case_touch BEFORE UPDATE ON control.approval_case FOR EACH ROW EXECUTE FUNCTION core.fn_touch_updated_at();

CREATE TRIGGER trg_approval_case_version BEFORE UPDATE ON control.approval_case FOR EACH ROW EXECUTE FUNCTION core.fn_increment_row_version();

CREATE TRIGGER trg_approval_decision_append_only BEFORE UPDATE OR DELETE ON control.approval_decision FOR EACH STATEMENT EXECUTE FUNCTION core.fn_append_only();

CREATE TRIGGER trg_config_release_public_id BEFORE INSERT ON control.config_release FOR EACH ROW EXECUTE FUNCTION core.fn_register_public_id('CONFIG_RELEASE');

CREATE TRIGGER trg_security_exception_public_id BEFORE INSERT ON control.security_exception FOR EACH ROW EXECUTE FUNCTION core.fn_register_public_id('SECURITY_EXCEPTION');

CREATE TRIGGER trg_security_exception_touch BEFORE UPDATE ON control.security_exception FOR EACH ROW EXECUTE FUNCTION core.fn_touch_updated_at();

CREATE TRIGGER trg_security_exception_version BEFORE UPDATE ON control.security_exception FOR EACH ROW EXECUTE FUNCTION core.fn_increment_row_version();

CREATE TRIGGER trg_break_glass_public_id BEFORE INSERT ON control.break_glass_grant FOR EACH ROW EXECUTE FUNCTION core.fn_register_public_id('BREAK_GLASS');

CREATE TRIGGER trg_client_certification_public_id BEFORE INSERT ON control.client_certification_run FOR EACH ROW EXECUTE FUNCTION core.fn_register_public_id('CLIENT_CERTIFICATION');

CREATE TRIGGER trg_config_release_guard BEFORE UPDATE ON control.config_release FOR EACH ROW
    EXECUTE FUNCTION control.fn_release_guard('release_state', 'staged_at', 'activated_at', 'deprecated_at', 'revoked_at',
        'approval_case_id', 'approval_execution_id');

CREATE TRIGGER trg_config_release_binding_immutable BEFORE UPDATE ON control.config_release FOR EACH ROW
    EXECUTE FUNCTION control.fn_active_approval_binding_guard('release_state', 'ACTIVE', 'approval_case_id', 'approval_execution_id');

CREATE TRIGGER trg_approval_case_request_immutable
    BEFORE UPDATE OR DELETE ON control.approval_case
    FOR EACH ROW EXECUTE FUNCTION core.fn_immutable_after_draft(
        'approval_state', 'approval_state', 'submitted_at', 'approved_at', 'rejected_at',
        'executed_at', 'execution_id', 'cancelled_at', 'expired_at', 'updated_at', 'row_version'
    );

CREATE TRIGGER trg_approval_case_terminal BEFORE UPDATE ON control.approval_case FOR EACH ROW
    EXECUTE FUNCTION core.fn_terminal_state_guard('approval_state', 'EXECUTED', 'REJECTED', 'CANCELLED', 'EXPIRED');

CREATE TRIGGER trg_security_exception_terminal BEFORE UPDATE ON control.security_exception FOR EACH ROW
    EXECUTE FUNCTION core.fn_terminal_state_guard('exception_state', 'EXPIRED', 'REVOKED', 'TIGHTENED');

CREATE TRIGGER trg_break_glass_terminal BEFORE UPDATE ON control.break_glass_grant FOR EACH ROW
    EXECUTE FUNCTION core.fn_terminal_state_guard('grant_state', 'EXPIRED', 'REVOKED');

COMMENT ON FUNCTION control.fn_active_approval_binding_guard() IS '资源处于 ACTIVE 时不得替换 approval_case_id 或 approval_execution_id；暂停后可准备新的再激活审批。';

COMMENT ON FUNCTION control.fn_release_guard() IS 'Release 合法转换、审批匹配和状态时间由 .NET 负责；数据库仅冻结离开 DRAFT 后的内容并阻止终态恢复。';

COMMENT ON TRIGGER trg_approval_case_public_id ON control.approval_case IS '触发器：调用 core.fn_register_public_id 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_approval_case_touch ON control.approval_case IS '触发器：调用 core.fn_touch_updated_at 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_approval_case_version ON control.approval_case IS '触发器：调用 core.fn_increment_row_version 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_approval_decision_append_only ON control.approval_decision IS '触发器：调用 core.fn_append_only 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_config_release_public_id ON control.config_release IS '触发器：调用 core.fn_register_public_id 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_security_exception_public_id ON control.security_exception IS '触发器：调用 core.fn_register_public_id 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_security_exception_touch ON control.security_exception IS '触发器：调用 core.fn_touch_updated_at 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_security_exception_version ON control.security_exception IS '触发器：调用 core.fn_increment_row_version 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_break_glass_public_id ON control.break_glass_grant IS '触发器：调用 core.fn_register_public_id 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_client_certification_public_id ON control.client_certification_run IS '触发器：调用 core.fn_register_public_id 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_config_release_guard ON control.config_release IS '触发器：调用 control.fn_release_guard 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_config_release_binding_immutable ON control.config_release IS '触发器：调用 control.fn_active_approval_binding_guard 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_approval_case_request_immutable ON control.approval_case IS '触发器：调用 core.fn_immutable_after_draft 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_approval_case_terminal ON control.approval_case IS '触发器：调用 core.fn_terminal_state_guard 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_security_exception_terminal ON control.security_exception IS '触发器：调用 core.fn_terminal_state_guard 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_break_glass_terminal ON control.break_glass_grant IS '触发器：调用 core.fn_terminal_state_guard 维护数据库结构完整性、不可变证据或关键原子安全底线。';

