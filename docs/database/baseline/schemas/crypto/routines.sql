-- =============================================================================
-- baseline/schemas/crypto/routines.sql
-- crypto Schema 的最终函数、过程、局部触发器及内联 COMMENT
-- PostgreSQL 16+；应用技术栈：.NET 10 + SqlSugar
-- =============================================================================

CREATE OR REPLACE FUNCTION crypto.fn_key_approval_binding_guard()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF OLD.key_state NOT IN ('GENERATED', 'PUBLISHED')
       AND (NEW.approval_case_id IS DISTINCT FROM OLD.approval_case_id
            OR NEW.approval_execution_id IS DISTINCT FROM OLD.approval_execution_id) THEN
        RAISE EXCEPTION 'KEY_APPROVAL_BINDING_IMMUTABLE' USING ERRCODE = '55000';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_key_asset_public_id BEFORE INSERT ON crypto.key_asset FOR EACH ROW EXECUTE FUNCTION core.fn_register_public_id('KEY_ASSET');

CREATE TRIGGER trg_key_asset_touch BEFORE UPDATE ON crypto.key_asset FOR EACH ROW EXECUTE FUNCTION core.fn_touch_updated_at();

CREATE TRIGGER trg_key_asset_version BEFORE UPDATE ON crypto.key_asset FOR EACH ROW EXECUTE FUNCTION core.fn_increment_row_version();

CREATE TRIGGER trg_certificate_public_id BEFORE INSERT ON crypto.certificate_asset FOR EACH ROW EXECUTE FUNCTION core.fn_register_public_id('CERTIFICATE');

CREATE TRIGGER trg_jwks_public_id BEFORE INSERT ON crypto.jwks_release FOR EACH ROW EXECUTE FUNCTION core.fn_register_public_id('JWKS_RELEASE');

CREATE TRIGGER trg_key_asset_approval_binding BEFORE UPDATE ON crypto.key_asset FOR EACH ROW
    EXECUTE FUNCTION crypto.fn_key_approval_binding_guard();

CREATE TRIGGER trg_key_asset_identity_immutable BEFORE UPDATE OR DELETE ON crypto.key_asset FOR EACH ROW
    EXECUTE FUNCTION core.fn_immutable_except('key_state', 'published_at', 'signing_started_at', 'activated_at',
        'verify_only_at', 'compromised_at', 'revoked_at', 'retired_at', 'destroyed_at',
        'approval_case_id', 'approval_execution_id', 'updated_at', 'row_version');

CREATE TRIGGER trg_key_asset_terminal BEFORE UPDATE ON crypto.key_asset FOR EACH ROW
    EXECUTE FUNCTION core.fn_terminal_state_guard('key_state', 'DESTROYED');

CREATE TRIGGER trg_certificate_terminal BEFORE UPDATE ON crypto.certificate_asset FOR EACH ROW
    EXECUTE FUNCTION core.fn_terminal_state_guard('certificate_state', 'EXPIRED', 'REVOKED');

CREATE TRIGGER trg_jwks_terminal BEFORE UPDATE ON crypto.jwks_release FOR EACH ROW
    EXECUTE FUNCTION core.fn_terminal_state_guard('release_state', 'SUPERSEDED', 'REVOKED');

COMMENT ON FUNCTION crypto.fn_key_approval_binding_guard() IS 'Key Asset 仅可在生成或发布阶段准备激活审批；开始签名、加密、验证或进入终态后审批绑定不可替换。';

COMMENT ON TRIGGER trg_key_asset_public_id ON crypto.key_asset IS '触发器：调用 core.fn_register_public_id 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_key_asset_touch ON crypto.key_asset IS '触发器：调用 core.fn_touch_updated_at 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_key_asset_version ON crypto.key_asset IS '触发器：调用 core.fn_increment_row_version 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_certificate_public_id ON crypto.certificate_asset IS '触发器：调用 core.fn_register_public_id 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_jwks_public_id ON crypto.jwks_release IS '触发器：调用 core.fn_register_public_id 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_key_asset_approval_binding ON crypto.key_asset IS '触发器：调用 crypto.fn_key_approval_binding_guard 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_key_asset_identity_immutable ON crypto.key_asset IS '触发器：调用 core.fn_immutable_except 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_key_asset_terminal ON crypto.key_asset IS '触发器：调用 core.fn_terminal_state_guard 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_certificate_terminal ON crypto.certificate_asset IS '触发器：调用 core.fn_terminal_state_guard 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_jwks_terminal ON crypto.jwks_release IS '触发器：调用 core.fn_terminal_state_guard 维护数据库结构完整性、不可变证据或关键原子安全底线。';

