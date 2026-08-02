-- =============================================================================
-- baseline/schemas/risk/routines.sql
-- risk Schema 的最终函数、过程、局部触发器及内联 COMMENT
-- PostgreSQL 16+；应用技术栈：.NET 10 + SqlSugar
-- =============================================================================

CREATE TRIGGER trg_risk_policy_public_id BEFORE INSERT ON risk.risk_policy_release FOR EACH ROW EXECUTE FUNCTION core.fn_register_public_id('RISK_POLICY');

CREATE TRIGGER trg_risk_signal_append_only BEFORE UPDATE OR DELETE ON risk.risk_signal FOR EACH STATEMENT EXECUTE FUNCTION core.fn_append_only();

CREATE TRIGGER trg_risk_assessment_public_id BEFORE INSERT ON risk.risk_assessment FOR EACH ROW EXECUTE FUNCTION core.fn_register_public_id('RISK_ASSESSMENT');

CREATE TRIGGER trg_risk_assessment_append_only BEFORE UPDATE OR DELETE ON risk.risk_assessment FOR EACH STATEMENT EXECUTE FUNCTION core.fn_append_only();

CREATE TRIGGER trg_security_case_public_id BEFORE INSERT ON risk.security_case FOR EACH ROW EXECUTE FUNCTION core.fn_register_public_id('SECURITY_CASE');

CREATE TRIGGER trg_security_case_touch BEFORE UPDATE ON risk.security_case FOR EACH ROW EXECUTE FUNCTION core.fn_touch_updated_at();

CREATE TRIGGER trg_security_case_version BEFORE UPDATE ON risk.security_case FOR EACH ROW EXECUTE FUNCTION core.fn_increment_row_version();

COMMENT ON TRIGGER trg_risk_policy_public_id ON risk.risk_policy_release IS '触发器：调用 core.fn_register_public_id 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_risk_signal_append_only ON risk.risk_signal IS '触发器：调用 core.fn_append_only 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_risk_assessment_public_id ON risk.risk_assessment IS '触发器：调用 core.fn_register_public_id 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_risk_assessment_append_only ON risk.risk_assessment IS '触发器：调用 core.fn_append_only 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_security_case_public_id ON risk.security_case IS '触发器：调用 core.fn_register_public_id 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_security_case_touch ON risk.security_case IS '触发器：调用 core.fn_touch_updated_at 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_security_case_version ON risk.security_case IS '触发器：调用 core.fn_increment_row_version 维护数据库结构完整性、不可变证据或关键原子安全底线。';

