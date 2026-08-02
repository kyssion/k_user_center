-- =============================================================================
-- baseline/schemas/migration/routines.sql
-- migration Schema 的最终函数、过程、局部触发器及内联 COMMENT
-- PostgreSQL 16+；应用技术栈：.NET 10 + SqlSugar
-- =============================================================================

CREATE OR REPLACE FUNCTION migration.fn_batch_state_guard()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF OLD.migration_batch_state = 'COMPLETE' AND NEW.migration_batch_state <> 'COMPLETE' THEN
        RAISE EXCEPTION 'INVALID_STATE_TRANSITION: COMPLETE migration batch 不得恢复' USING ERRCODE = '23514';
    END IF;
    IF OLD.irreversible_at IS NOT NULL AND NEW.migration_batch_state = 'ROLLED_BACK' THEN
        RAISE EXCEPTION 'FORWARD_FIX_REQUIRED: 已越过不可逆边界' USING ERRCODE = '23514';
    END IF;
    IF NEW.migration_batch_state IN ('CUTOVER', 'OBSERVING', 'COMPLETE') AND NEW.authority_side <> 'PLATFORM' THEN
        RAISE EXCEPTION 'MIGRATION_AUTHORITY_NOT_PLATFORM' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION migration.fn_change_log_immutable_guard()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN RAISE EXCEPTION 'MIGRATION_CHANGE_DELETE_FORBIDDEN' USING ERRCODE = '55000'; END IF;
    IF NEW.migration_batch_id <> OLD.migration_batch_id OR NEW.change_sequence <> OLD.change_sequence
       OR NEW.authority_side <> OLD.authority_side OR NEW.object_kind <> OLD.object_kind OR NEW.object_ref <> OLD.object_ref
       OR NEW.object_version <> OLD.object_version OR NEW.change_kind <> OLD.change_kind
       OR NEW.idempotency_key <> OLD.idempotency_key OR NEW.change_payload_ciphertext <> OLD.change_payload_ciphertext
       OR NEW.change_hash <> OLD.change_hash OR NEW.previous_change_hash IS DISTINCT FROM OLD.previous_change_hash THEN
        RAISE EXCEPTION 'MIGRATION_CHANGE_IMMUTABLE' USING ERRCODE = '55000';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_migration_batch_public_id BEFORE INSERT ON migration.migration_batch FOR EACH ROW EXECUTE FUNCTION core.fn_register_public_id('MIGRATION_BATCH');

CREATE TRIGGER trg_migration_batch_guard BEFORE UPDATE ON migration.migration_batch FOR EACH ROW EXECUTE FUNCTION migration.fn_batch_state_guard();

CREATE TRIGGER trg_migration_batch_touch BEFORE UPDATE ON migration.migration_batch FOR EACH ROW EXECUTE FUNCTION core.fn_touch_updated_at();

CREATE TRIGGER trg_migration_batch_version BEFORE UPDATE ON migration.migration_batch FOR EACH ROW EXECUTE FUNCTION core.fn_increment_row_version();

CREATE TRIGGER trg_legacy_mapping_append_only BEFORE UPDATE OR DELETE ON migration.legacy_id_mapping FOR EACH STATEMENT EXECUTE FUNCTION core.fn_append_only();

CREATE TRIGGER trg_change_log_immutable BEFORE UPDATE OR DELETE ON migration.change_log FOR EACH ROW EXECUTE FUNCTION migration.fn_change_log_immutable_guard();

CREATE TRIGGER trg_reconciliation_public_id BEFORE INSERT ON migration.reconciliation_run FOR EACH ROW EXECUTE FUNCTION core.fn_register_public_id('RECONCILIATION_RUN');

CREATE TRIGGER trg_rollback_public_id BEFORE INSERT ON migration.rollback_execution FOR EACH ROW EXECUTE FUNCTION core.fn_register_public_id('ROLLBACK_EXECUTION');

COMMENT ON FUNCTION migration.fn_batch_state_guard() IS '迁移完成不可恢复、不可逆边界后禁止伪回滚，切换后平台必须成为权威写入方。';

COMMENT ON FUNCTION migration.fn_change_log_immutable_guard() IS '迁移变更内容、顺序、版本、幂等键和哈希链不可修改；仅允许推进应用结果。';

COMMENT ON TRIGGER trg_migration_batch_public_id ON migration.migration_batch IS '触发器：调用 core.fn_register_public_id 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_migration_batch_guard ON migration.migration_batch IS '触发器：调用 migration.fn_batch_state_guard 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_migration_batch_touch ON migration.migration_batch IS '触发器：调用 core.fn_touch_updated_at 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_migration_batch_version ON migration.migration_batch IS '触发器：调用 core.fn_increment_row_version 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_legacy_mapping_append_only ON migration.legacy_id_mapping IS '触发器：调用 core.fn_append_only 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_change_log_immutable ON migration.change_log IS '触发器：调用 migration.fn_change_log_immutable_guard 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_reconciliation_public_id ON migration.reconciliation_run IS '触发器：调用 core.fn_register_public_id 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_rollback_public_id ON migration.rollback_execution IS '触发器：调用 core.fn_register_public_id 维护数据库结构完整性、不可变证据或关键原子安全底线。';

