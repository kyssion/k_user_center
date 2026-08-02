-- =============================================================================
-- baseline/schemas/iam/routines.sql
-- iam Schema 的最终函数、过程、局部触发器及内联 COMMENT
-- PostgreSQL 16+；应用技术栈：.NET 10 + SqlSugar
-- =============================================================================

CREATE TRIGGER trg_user_account_touch BEFORE UPDATE ON iam.user_account FOR EACH ROW EXECUTE FUNCTION core.fn_touch_updated_at();

CREATE TRIGGER trg_user_account_version BEFORE UPDATE ON iam.user_account FOR EACH ROW EXECUTE FUNCTION core.fn_increment_row_version();

CREATE TRIGGER trg_user_account_epoch BEFORE UPDATE ON iam.user_account FOR EACH ROW EXECUTE FUNCTION core.fn_forbid_epoch_decrease('user_security_epoch');

CREATE TRIGGER trg_user_account_public_id BEFORE INSERT ON iam.user_account FOR EACH ROW EXECUTE FUNCTION core.fn_register_public_id('GLOBAL_USER');

CREATE TRIGGER trg_user_account_terminal BEFORE UPDATE ON iam.user_account FOR EACH ROW EXECUTE FUNCTION core.fn_terminal_state_guard('lifecycle_state', 'ANONYMIZED', 'ERASED', 'MERGED');

CREATE TRIGGER trg_subject_assignment_public_id BEFORE INSERT ON iam.subject_assignment FOR EACH ROW EXECUTE FUNCTION core.fn_register_public_id('SUBJECT');

CREATE TRIGGER trg_identifier_touch BEFORE UPDATE ON iam.identifier FOR EACH ROW EXECUTE FUNCTION core.fn_touch_updated_at();

CREATE TRIGGER trg_identifier_version BEFORE UPDATE ON iam.identifier FOR EACH ROW EXECUTE FUNCTION core.fn_increment_row_version();

CREATE TRIGGER trg_account_merge_touch BEFORE UPDATE ON iam.account_merge FOR EACH ROW EXECUTE FUNCTION core.fn_touch_updated_at();

CREATE TRIGGER trg_account_merge_version BEFORE UPDATE ON iam.account_merge FOR EACH ROW EXECUTE FUNCTION core.fn_increment_row_version();

CREATE TRIGGER trg_account_merge_public_id BEFORE INSERT ON iam.account_merge FOR EACH ROW EXECUTE FUNCTION core.fn_register_public_id('ACCOUNT_MERGE');

CREATE TRIGGER trg_account_deletion_touch BEFORE UPDATE ON iam.account_deletion FOR EACH ROW EXECUTE FUNCTION core.fn_touch_updated_at();

CREATE TRIGGER trg_account_deletion_version BEFORE UPDATE ON iam.account_deletion FOR EACH ROW EXECUTE FUNCTION core.fn_increment_row_version();

CREATE TRIGGER trg_identifier_terminal BEFORE UPDATE ON iam.identifier FOR EACH ROW
    EXECUTE FUNCTION core.fn_terminal_state_guard('identifier_state', 'RELEASED');

COMMENT ON TRIGGER trg_user_account_touch ON iam.user_account IS '触发器：调用 core.fn_touch_updated_at 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_user_account_version ON iam.user_account IS '触发器：调用 core.fn_increment_row_version 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_user_account_epoch ON iam.user_account IS '触发器：调用 core.fn_forbid_epoch_decrease 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_user_account_public_id ON iam.user_account IS '触发器：调用 core.fn_register_public_id 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_user_account_terminal ON iam.user_account IS '触发器：调用 core.fn_terminal_state_guard 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_subject_assignment_public_id ON iam.subject_assignment IS '触发器：调用 core.fn_register_public_id 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_identifier_touch ON iam.identifier IS '触发器：调用 core.fn_touch_updated_at 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_identifier_version ON iam.identifier IS '触发器：调用 core.fn_increment_row_version 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_account_merge_touch ON iam.account_merge IS '触发器：调用 core.fn_touch_updated_at 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_account_merge_version ON iam.account_merge IS '触发器：调用 core.fn_increment_row_version 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_account_merge_public_id ON iam.account_merge IS '触发器：调用 core.fn_register_public_id 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_account_deletion_touch ON iam.account_deletion IS '触发器：调用 core.fn_touch_updated_at 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_account_deletion_version ON iam.account_deletion IS '触发器：调用 core.fn_increment_row_version 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_identifier_terminal ON iam.identifier IS '触发器：调用 core.fn_terminal_state_guard 维护数据库结构完整性、不可变证据或关键原子安全底线。';

