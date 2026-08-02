-- =============================================================================
-- baseline/schemas/authn/routines.sql
-- authn Schema 的最终函数、过程、局部触发器及内联 COMMENT
-- PostgreSQL 16+；应用技术栈：.NET 10 + SqlSugar
-- =============================================================================

CREATE TRIGGER trg_authenticator_touch BEFORE UPDATE ON authn.authenticator FOR EACH ROW EXECUTE FUNCTION core.fn_touch_updated_at();

CREATE TRIGGER trg_authenticator_version BEFORE UPDATE ON authn.authenticator FOR EACH ROW EXECUTE FUNCTION core.fn_increment_row_version();

CREATE TRIGGER trg_authenticator_terminal BEFORE UPDATE ON authn.authenticator FOR EACH ROW EXECUTE FUNCTION core.fn_terminal_state_guard('authenticator_state', 'REVOKED', 'REPLACED');

CREATE TRIGGER trg_password_touch BEFORE UPDATE ON authn.password_credential FOR EACH ROW EXECUTE FUNCTION core.fn_touch_updated_at();

CREATE TRIGGER trg_password_version BEFORE UPDATE ON authn.password_credential FOR EACH ROW EXECUTE FUNCTION core.fn_increment_row_version();

CREATE TRIGGER trg_login_transaction_touch BEFORE UPDATE ON authn.login_transaction FOR EACH ROW EXECUTE FUNCTION core.fn_touch_updated_at();

CREATE TRIGGER trg_login_transaction_version BEFORE UPDATE ON authn.login_transaction FOR EACH ROW EXECUTE FUNCTION core.fn_increment_row_version();

CREATE TRIGGER trg_login_transaction_public_id BEFORE INSERT ON authn.login_transaction FOR EACH ROW EXECUTE FUNCTION core.fn_register_public_id('LOGIN_TRANSACTION');

CREATE TRIGGER trg_login_transaction_terminal BEFORE UPDATE ON authn.login_transaction FOR EACH ROW EXECUTE FUNCTION core.fn_terminal_state_guard('login_transaction_state', 'COMPLETED', 'EXPIRED', 'ABANDONED');

CREATE TRIGGER trg_challenge_touch BEFORE UPDATE ON authn.verification_challenge FOR EACH ROW EXECUTE FUNCTION core.fn_touch_updated_at();

CREATE TRIGGER trg_challenge_version BEFORE UPDATE ON authn.verification_challenge FOR EACH ROW EXECUTE FUNCTION core.fn_increment_row_version();

CREATE TRIGGER trg_challenge_public_id BEFORE INSERT ON authn.verification_challenge FOR EACH ROW EXECUTE FUNCTION core.fn_register_public_id('CHALLENGE');

CREATE TRIGGER trg_device_authorization_touch BEFORE UPDATE ON authn.device_authorization FOR EACH ROW EXECUTE FUNCTION core.fn_touch_updated_at();

CREATE TRIGGER trg_device_authorization_version BEFORE UPDATE ON authn.device_authorization FOR EACH ROW EXECUTE FUNCTION core.fn_increment_row_version();

CREATE TRIGGER trg_challenge_terminal BEFORE UPDATE ON authn.verification_challenge FOR EACH ROW
    EXECUTE FUNCTION core.fn_terminal_state_guard('challenge_state', 'CONSUMED', 'EXPIRED', 'LOCKED', 'CANCELLED');

COMMENT ON TRIGGER trg_authenticator_touch ON authn.authenticator IS '触发器：调用 core.fn_touch_updated_at 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_authenticator_version ON authn.authenticator IS '触发器：调用 core.fn_increment_row_version 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_authenticator_terminal ON authn.authenticator IS '触发器：调用 core.fn_terminal_state_guard 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_password_touch ON authn.password_credential IS '触发器：调用 core.fn_touch_updated_at 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_password_version ON authn.password_credential IS '触发器：调用 core.fn_increment_row_version 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_login_transaction_touch ON authn.login_transaction IS '触发器：调用 core.fn_touch_updated_at 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_login_transaction_version ON authn.login_transaction IS '触发器：调用 core.fn_increment_row_version 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_login_transaction_public_id ON authn.login_transaction IS '触发器：调用 core.fn_register_public_id 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_login_transaction_terminal ON authn.login_transaction IS '触发器：调用 core.fn_terminal_state_guard 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_challenge_touch ON authn.verification_challenge IS '触发器：调用 core.fn_touch_updated_at 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_challenge_version ON authn.verification_challenge IS '触发器：调用 core.fn_increment_row_version 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_challenge_public_id ON authn.verification_challenge IS '触发器：调用 core.fn_register_public_id 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_device_authorization_touch ON authn.device_authorization IS '触发器：调用 core.fn_touch_updated_at 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_device_authorization_version ON authn.device_authorization IS '触发器：调用 core.fn_increment_row_version 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_challenge_terminal ON authn.verification_challenge IS '触发器：调用 core.fn_terminal_state_guard 维护数据库结构完整性、不可变证据或关键原子安全底线。';

