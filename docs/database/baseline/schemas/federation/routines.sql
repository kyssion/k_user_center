-- =============================================================================
-- baseline/schemas/federation/routines.sql
-- federation Schema 的最终函数、过程、局部触发器及内联 COMMENT
-- PostgreSQL 16+；应用技术栈：.NET 10 + SqlSugar
-- =============================================================================

CREATE TRIGGER trg_identity_provider_public_id BEFORE INSERT ON federation.identity_provider FOR EACH ROW EXECUTE FUNCTION core.fn_register_public_id('IDENTITY_PROVIDER');

CREATE TRIGGER trg_identity_provider_touch BEFORE UPDATE ON federation.identity_provider FOR EACH ROW EXECUTE FUNCTION core.fn_touch_updated_at();

CREATE TRIGGER trg_identity_provider_version BEFORE UPDATE ON federation.identity_provider FOR EACH ROW EXECUTE FUNCTION core.fn_increment_row_version();

CREATE TRIGGER trg_external_identity_public_id BEFORE INSERT ON federation.external_identity FOR EACH ROW EXECUTE FUNCTION core.fn_register_public_id('EXTERNAL_IDENTITY');

CREATE TRIGGER trg_external_identity_touch BEFORE UPDATE ON federation.external_identity FOR EACH ROW EXECUTE FUNCTION core.fn_touch_updated_at();

CREATE TRIGGER trg_external_identity_version BEFORE UPDATE ON federation.external_identity FOR EACH ROW EXECUTE FUNCTION core.fn_increment_row_version();

CREATE TRIGGER trg_directory_connection_public_id BEFORE INSERT ON federation.directory_connection FOR EACH ROW EXECUTE FUNCTION core.fn_register_public_id('DIRECTORY_CONNECTION');

CREATE TRIGGER trg_directory_connection_touch BEFORE UPDATE ON federation.directory_connection FOR EACH ROW EXECUTE FUNCTION core.fn_touch_updated_at();

CREATE TRIGGER trg_directory_connection_version BEFORE UPDATE ON federation.directory_connection FOR EACH ROW EXECUTE FUNCTION core.fn_increment_row_version();

CREATE TRIGGER trg_directory_object_touch BEFORE UPDATE ON federation.directory_object FOR EACH ROW EXECUTE FUNCTION core.fn_touch_updated_at();

CREATE TRIGGER trg_directory_object_version BEFORE UPDATE ON federation.directory_object FOR EACH ROW EXECUTE FUNCTION core.fn_increment_row_version();

CREATE TRIGGER trg_directory_sync_public_id BEFORE INSERT ON federation.directory_sync_run FOR EACH ROW EXECUTE FUNCTION core.fn_register_public_id('DIRECTORY_SYNC_RUN');

CREATE TRIGGER trg_assertion_replay_append_only BEFORE UPDATE OR DELETE ON federation.assertion_replay FOR EACH STATEMENT EXECUTE FUNCTION core.fn_append_only();

CREATE TRIGGER trg_federation_migration_touch BEFORE UPDATE ON federation.federation_migration FOR EACH ROW EXECUTE FUNCTION core.fn_touch_updated_at();

CREATE TRIGGER trg_federation_migration_version BEFORE UPDATE ON federation.federation_migration FOR EACH ROW EXECUTE FUNCTION core.fn_increment_row_version();

CREATE TRIGGER trg_identity_provider_configuration_immutable BEFORE UPDATE OR DELETE ON federation.identity_provider FOR EACH ROW
    EXECUTE FUNCTION core.fn_immutable_after_draft('provider_state', 'approval_case_id', 'approval_execution_id',
        'activated_at', 'last_activation_execution_id', 'updated_at', 'row_version');

CREATE TRIGGER trg_identity_provider_terminal BEFORE UPDATE ON federation.identity_provider FOR EACH ROW
    EXECUTE FUNCTION core.fn_terminal_state_guard('provider_state', 'RETIRED');

COMMENT ON TRIGGER trg_identity_provider_public_id ON federation.identity_provider IS '触发器：调用 core.fn_register_public_id 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_identity_provider_touch ON federation.identity_provider IS '触发器：调用 core.fn_touch_updated_at 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_identity_provider_version ON federation.identity_provider IS '触发器：调用 core.fn_increment_row_version 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_external_identity_public_id ON federation.external_identity IS '触发器：调用 core.fn_register_public_id 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_external_identity_touch ON federation.external_identity IS '触发器：调用 core.fn_touch_updated_at 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_external_identity_version ON federation.external_identity IS '触发器：调用 core.fn_increment_row_version 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_directory_connection_public_id ON federation.directory_connection IS '触发器：调用 core.fn_register_public_id 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_directory_connection_touch ON federation.directory_connection IS '触发器：调用 core.fn_touch_updated_at 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_directory_connection_version ON federation.directory_connection IS '触发器：调用 core.fn_increment_row_version 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_directory_object_touch ON federation.directory_object IS '触发器：调用 core.fn_touch_updated_at 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_directory_object_version ON federation.directory_object IS '触发器：调用 core.fn_increment_row_version 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_directory_sync_public_id ON federation.directory_sync_run IS '触发器：调用 core.fn_register_public_id 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_assertion_replay_append_only ON federation.assertion_replay IS '触发器：调用 core.fn_append_only 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_federation_migration_touch ON federation.federation_migration IS '触发器：调用 core.fn_touch_updated_at 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_federation_migration_version ON federation.federation_migration IS '触发器：调用 core.fn_increment_row_version 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_identity_provider_configuration_immutable ON federation.identity_provider IS '触发器：调用 core.fn_immutable_after_draft 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_identity_provider_terminal ON federation.identity_provider IS '触发器：调用 core.fn_terminal_state_guard 维护数据库结构完整性、不可变证据或关键原子安全底线。';

