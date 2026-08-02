-- =============================================================================
-- baseline/schemas/assurance/routines.sql
-- assurance Schema 的最终函数、过程、局部触发器及内联 COMMENT
-- PostgreSQL 16+；应用技术栈：.NET 10 + SqlSugar
-- =============================================================================

CREATE TRIGGER trg_assurance_assertion_append_only BEFORE UPDATE OR DELETE ON assurance.identity_assurance_assertion FOR EACH STATEMENT EXECUTE FUNCTION core.fn_append_only();

CREATE TRIGGER trg_recovery_public_id BEFORE INSERT ON assurance.recovery_request FOR EACH ROW EXECUTE FUNCTION core.fn_register_public_id('RECOVERY_REQUEST');

CREATE TRIGGER trg_recovery_touch BEFORE UPDATE ON assurance.recovery_request FOR EACH ROW EXECUTE FUNCTION core.fn_touch_updated_at();

CREATE TRIGGER trg_recovery_version BEFORE UPDATE ON assurance.recovery_request FOR EACH ROW EXECUTE FUNCTION core.fn_increment_row_version();

CREATE TRIGGER trg_delegation_public_id BEFORE INSERT ON assurance.delegation FOR EACH ROW EXECUTE FUNCTION core.fn_register_public_id('DELEGATION');

CREATE TRIGGER trg_delegation_touch BEFORE UPDATE ON assurance.delegation FOR EACH ROW EXECUTE FUNCTION core.fn_touch_updated_at();

CREATE TRIGGER trg_delegation_version BEFORE UPDATE ON assurance.delegation FOR EACH ROW EXECUTE FUNCTION core.fn_increment_row_version();

CREATE TRIGGER trg_delegation_terminal BEFORE UPDATE ON assurance.delegation FOR EACH ROW EXECUTE FUNCTION core.fn_terminal_state_guard('delegation_state', 'REJECTED', 'REVOKED', 'EXPIRED');

COMMENT ON TRIGGER trg_assurance_assertion_append_only ON assurance.identity_assurance_assertion IS '触发器：调用 core.fn_append_only 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_recovery_public_id ON assurance.recovery_request IS '触发器：调用 core.fn_register_public_id 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_recovery_touch ON assurance.recovery_request IS '触发器：调用 core.fn_touch_updated_at 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_recovery_version ON assurance.recovery_request IS '触发器：调用 core.fn_increment_row_version 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_delegation_public_id ON assurance.delegation IS '触发器：调用 core.fn_register_public_id 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_delegation_touch ON assurance.delegation IS '触发器：调用 core.fn_touch_updated_at 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_delegation_version ON assurance.delegation IS '触发器：调用 core.fn_increment_row_version 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_delegation_terminal ON assurance.delegation IS '触发器：调用 core.fn_terminal_state_guard 维护数据库结构完整性、不可变证据或关键原子安全底线。';

