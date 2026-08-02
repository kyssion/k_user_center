-- =============================================================================
-- baseline/schemas/authz/routines.sql
-- authz Schema 的最终函数、过程、局部触发器及内联 COMMENT
-- PostgreSQL 16+；应用技术栈：.NET 10 + SqlSugar
-- =============================================================================

CREATE TRIGGER trg_role_public_id BEFORE INSERT ON authz.role FOR EACH ROW EXECUTE FUNCTION core.fn_register_public_id('ROLE');

CREATE TRIGGER trg_role_touch BEFORE UPDATE ON authz.role FOR EACH ROW EXECUTE FUNCTION core.fn_touch_updated_at();

CREATE TRIGGER trg_role_version BEFORE UPDATE ON authz.role FOR EACH ROW EXECUTE FUNCTION core.fn_increment_row_version();

CREATE TRIGGER trg_role_assignment_touch BEFORE UPDATE ON authz.role_assignment FOR EACH ROW EXECUTE FUNCTION core.fn_touch_updated_at();

CREATE TRIGGER trg_role_assignment_version BEFORE UPDATE ON authz.role_assignment FOR EACH ROW EXECUTE FUNCTION core.fn_increment_row_version();

CREATE TRIGGER trg_policy_release_public_id BEFORE INSERT ON authz.policy_release FOR EACH ROW EXECUTE FUNCTION core.fn_register_public_id('POLICY_RELEASE');

CREATE TRIGGER trg_authorization_decision_public_id BEFORE INSERT ON authz.authorization_decision FOR EACH ROW EXECUTE FUNCTION core.fn_register_public_id('AUTHZ_DECISION');

CREATE TRIGGER trg_authorization_decision_append_only BEFORE UPDATE OR DELETE ON authz.authorization_decision FOR EACH STATEMENT EXECUTE FUNCTION core.fn_append_only();

CREATE TRIGGER trg_relationship_tuple_touch BEFORE UPDATE ON authz.relationship_tuple FOR EACH ROW EXECUTE FUNCTION core.fn_touch_updated_at();

CREATE TRIGGER trg_relationship_tuple_version BEFORE UPDATE ON authz.relationship_tuple FOR EACH ROW EXECUTE FUNCTION core.fn_increment_row_version();

CREATE TRIGGER trg_access_review_public_id BEFORE INSERT ON authz.access_review FOR EACH ROW EXECUTE FUNCTION core.fn_register_public_id('ACCESS_REVIEW');

CREATE TRIGGER trg_access_review_touch BEFORE UPDATE ON authz.access_review FOR EACH ROW EXECUTE FUNCTION core.fn_touch_updated_at();

CREATE TRIGGER trg_access_review_version BEFORE UPDATE ON authz.access_review FOR EACH ROW EXECUTE FUNCTION core.fn_increment_row_version();

CREATE TRIGGER trg_permission_simulation_public_id BEFORE INSERT ON authz.permission_simulation FOR EACH ROW EXECUTE FUNCTION core.fn_register_public_id('PERMISSION_SIMULATION');

CREATE TRIGGER trg_permission_simulation_append_only BEFORE UPDATE OR DELETE ON authz.permission_simulation FOR EACH STATEMENT EXECUTE FUNCTION core.fn_append_only();

CREATE TRIGGER trg_role_assignment_terminal BEFORE UPDATE ON authz.role_assignment FOR EACH ROW EXECUTE FUNCTION core.fn_terminal_state_guard('assignment_state', 'REVOKED', 'EXPIRED');

COMMENT ON TRIGGER trg_role_public_id ON authz.role IS '触发器：调用 core.fn_register_public_id 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_role_touch ON authz.role IS '触发器：调用 core.fn_touch_updated_at 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_role_version ON authz.role IS '触发器：调用 core.fn_increment_row_version 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_role_assignment_touch ON authz.role_assignment IS '触发器：调用 core.fn_touch_updated_at 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_role_assignment_version ON authz.role_assignment IS '触发器：调用 core.fn_increment_row_version 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_policy_release_public_id ON authz.policy_release IS '触发器：调用 core.fn_register_public_id 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_authorization_decision_public_id ON authz.authorization_decision IS '触发器：调用 core.fn_register_public_id 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_authorization_decision_append_only ON authz.authorization_decision IS '触发器：调用 core.fn_append_only 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_relationship_tuple_touch ON authz.relationship_tuple IS '触发器：调用 core.fn_touch_updated_at 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_relationship_tuple_version ON authz.relationship_tuple IS '触发器：调用 core.fn_increment_row_version 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_access_review_public_id ON authz.access_review IS '触发器：调用 core.fn_register_public_id 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_access_review_touch ON authz.access_review IS '触发器：调用 core.fn_touch_updated_at 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_access_review_version ON authz.access_review IS '触发器：调用 core.fn_increment_row_version 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_permission_simulation_public_id ON authz.permission_simulation IS '触发器：调用 core.fn_register_public_id 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_permission_simulation_append_only ON authz.permission_simulation IS '触发器：调用 core.fn_append_only 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_role_assignment_terminal ON authz.role_assignment IS '触发器：调用 core.fn_terminal_state_guard 维护数据库结构完整性、不可变证据或关键原子安全底线。';

