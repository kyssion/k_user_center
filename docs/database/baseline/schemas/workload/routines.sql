-- =============================================================================
-- baseline/schemas/workload/routines.sql
-- workload Schema 的最终函数、过程、局部触发器及内联 COMMENT
-- PostgreSQL 16+；应用技术栈：.NET 10 + SqlSugar
-- =============================================================================

CREATE TRIGGER trg_machine_public_id BEFORE INSERT ON workload.machine_principal FOR EACH ROW EXECUTE FUNCTION core.fn_register_public_id('MACHINE_PRINCIPAL');

CREATE TRIGGER trg_machine_touch BEFORE UPDATE ON workload.machine_principal FOR EACH ROW EXECUTE FUNCTION core.fn_touch_updated_at();

CREATE TRIGGER trg_machine_version BEFORE UPDATE ON workload.machine_principal FOR EACH ROW EXECUTE FUNCTION core.fn_increment_row_version();

CREATE TRIGGER trg_machine_epoch BEFORE UPDATE ON workload.machine_principal FOR EACH ROW EXECUTE FUNCTION core.fn_forbid_epoch_decrease('principal_security_epoch');

CREATE TRIGGER trg_machine_credential_touch BEFORE UPDATE ON workload.machine_credential FOR EACH ROW EXECUTE FUNCTION core.fn_touch_updated_at();

CREATE TRIGGER trg_machine_credential_version BEFORE UPDATE ON workload.machine_credential FOR EACH ROW EXECUTE FUNCTION core.fn_increment_row_version();

CREATE TRIGGER trg_trust_bundle_public_id BEFORE INSERT ON workload.trust_bundle FOR EACH ROW EXECUTE FUNCTION core.fn_register_public_id('TRUST_BUNDLE');

CREATE TRIGGER trg_attestation_public_id BEFORE INSERT ON workload.workload_attestation FOR EACH ROW EXECUTE FUNCTION core.fn_register_public_id('WORKLOAD_ATTESTATION');

CREATE TRIGGER trg_attestation_terminal BEFORE UPDATE ON workload.workload_attestation FOR EACH ROW EXECUTE FUNCTION core.fn_terminal_state_guard('attestation_state', 'EXPIRED', 'REVOKED', 'REJECTED');

CREATE TRIGGER trg_token_exchange_public_id BEFORE INSERT ON workload.token_exchange FOR EACH ROW EXECUTE FUNCTION core.fn_register_public_id('TOKEN_EXCHANGE');

CREATE TRIGGER trg_machine_terminal BEFORE UPDATE ON workload.machine_principal FOR EACH ROW
    EXECUTE FUNCTION core.fn_terminal_state_guard('principal_state', 'RETIRED');

CREATE TRIGGER trg_machine_credential_terminal BEFORE UPDATE ON workload.machine_credential FOR EACH ROW
    EXECUTE FUNCTION core.fn_terminal_state_guard('credential_state', 'EXPIRED', 'REVOKED');

CREATE TRIGGER trg_trust_bundle_terminal BEFORE UPDATE ON workload.trust_bundle FOR EACH ROW
    EXECUTE FUNCTION core.fn_terminal_state_guard('bundle_state', 'RETIRED', 'REVOKED');

COMMENT ON TRIGGER trg_machine_public_id ON workload.machine_principal IS '触发器：调用 core.fn_register_public_id 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_machine_touch ON workload.machine_principal IS '触发器：调用 core.fn_touch_updated_at 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_machine_version ON workload.machine_principal IS '触发器：调用 core.fn_increment_row_version 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_machine_epoch ON workload.machine_principal IS '触发器：调用 core.fn_forbid_epoch_decrease 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_machine_credential_touch ON workload.machine_credential IS '触发器：调用 core.fn_touch_updated_at 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_machine_credential_version ON workload.machine_credential IS '触发器：调用 core.fn_increment_row_version 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_trust_bundle_public_id ON workload.trust_bundle IS '触发器：调用 core.fn_register_public_id 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_attestation_public_id ON workload.workload_attestation IS '触发器：调用 core.fn_register_public_id 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_attestation_terminal ON workload.workload_attestation IS '触发器：调用 core.fn_terminal_state_guard 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_token_exchange_public_id ON workload.token_exchange IS '触发器：调用 core.fn_register_public_id 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_machine_terminal ON workload.machine_principal IS '触发器：调用 core.fn_terminal_state_guard 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_machine_credential_terminal ON workload.machine_credential IS '触发器：调用 core.fn_terminal_state_guard 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_trust_bundle_terminal ON workload.trust_bundle IS '触发器：调用 core.fn_terminal_state_guard 维护数据库结构完整性、不可变证据或关键原子安全底线。';

