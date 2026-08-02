-- =============================================================================
-- baseline/schemas/audit/routines.sql
-- audit Schema 的最终函数、过程、局部触发器及内联 COMMENT
-- PostgreSQL 16+；应用技术栈：.NET 10 + SqlSugar
-- =============================================================================

CREATE OR REPLACE FUNCTION audit.fn_audit_chain_guard()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    v_previous bytea;
    v_sequence bigint;
BEGIN
    PERFORM pg_advisory_xact_lock(hashtextextended(NEW.chain_partition, 0));
    SELECT event_hash, chain_sequence
      INTO v_previous, v_sequence
      FROM audit.audit_event
     WHERE chain_partition = NEW.chain_partition
     ORDER BY chain_sequence DESC
     LIMIT 1;

    IF NOT FOUND THEN
        NEW.chain_sequence := 1;
        NEW.previous_event_hash := NULL;
    ELSE
        NEW.chain_sequence := v_sequence + 1;
        NEW.previous_event_hash := v_previous;
    END IF;
    NEW.event_hash := core.fn_hash_jsonb(to_jsonb(NEW) - 'event_hash');
    RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION audit.fn_audit_outbox_immutable_guard()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN RAISE EXCEPTION 'AUDIT_OUTBOX_DELETE_FORBIDDEN' USING ERRCODE = '55000'; END IF;
    IF NOT (
        NEW.persistence_state = OLD.persistence_state
        OR (OLD.persistence_state = 'PERSISTED' AND NEW.persistence_state IN ('DELIVERING', 'FAILED'))
        OR (OLD.persistence_state = 'DELIVERING' AND NEW.persistence_state IN ('REMOTE_PERSISTED', 'FAILED'))
        OR (OLD.persistence_state = 'FAILED' AND NEW.persistence_state = 'DELIVERING')
    ) THEN
        RAISE EXCEPTION 'INVALID_STATE_TRANSITION: Audit Outbox % -> %', OLD.persistence_state, NEW.persistence_state USING ERRCODE = '23514';
    END IF;
    IF OLD.persistence_state = 'DELIVERING' AND NEW.persistence_state = 'REMOTE_PERSISTED' THEN
        NEW.remote_persisted_at := clock_timestamp();
    END IF;
    IF OLD.persistence_state = 'REMOTE_PERSISTED' AND to_jsonb(NEW) IS DISTINCT FROM to_jsonb(OLD) THEN
        RAISE EXCEPTION 'AUDIT_OUTBOX_TERMINAL_EVIDENCE_IMMUTABLE' USING ERRCODE = '55000';
    END IF;
    IF (to_jsonb(NEW) - ARRAY['persistence_state','remote_persisted_at'])
       IS DISTINCT FROM
       (to_jsonb(OLD) - ARRAY['persistence_state','remote_persisted_at']) THEN
        RAISE EXCEPTION 'AUDIT_OUTBOX_PAYLOAD_IMMUTABLE' USING ERRCODE = '55000';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_audit_outbox_immutable BEFORE UPDATE OR DELETE ON audit.audit_outbox FOR EACH ROW EXECUTE FUNCTION audit.fn_audit_outbox_immutable_guard();

CREATE TRIGGER trg_audit_event_chain BEFORE INSERT ON audit.audit_event FOR EACH ROW EXECUTE FUNCTION audit.fn_audit_chain_guard();

CREATE TRIGGER trg_audit_event_append_only BEFORE UPDATE OR DELETE ON audit.audit_event FOR EACH STATEMENT EXECUTE FUNCTION core.fn_append_only();

CREATE TRIGGER trg_audit_seal_append_only BEFORE UPDATE OR DELETE ON audit.audit_seal FOR EACH STATEMENT EXECUTE FUNCTION core.fn_append_only();

CREATE TRIGGER trg_data_access_append_only BEFORE UPDATE OR DELETE ON audit.data_access_event FOR EACH STATEMENT EXECUTE FUNCTION core.fn_append_only();

COMMENT ON FUNCTION audit.fn_audit_chain_guard() IS '按 chain_partition 使用事务级 advisory lock 串行分配序号和 previous hash，并由数据库重新计算完整事件摘要。';

COMMENT ON FUNCTION audit.fn_audit_outbox_immutable_guard() IS '本地审计 Outbox 只允许单向推进远端持久化状态；事件身份、证据密文、摘要、密钥引用和创建时间不可改删。';

COMMENT ON TRIGGER trg_audit_outbox_immutable ON audit.audit_outbox IS '触发器：调用 audit.fn_audit_outbox_immutable_guard 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_audit_event_chain ON audit.audit_event IS '触发器：调用 audit.fn_audit_chain_guard 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_audit_event_append_only ON audit.audit_event IS '触发器：调用 core.fn_append_only 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_audit_seal_append_only ON audit.audit_seal IS '触发器：调用 core.fn_append_only 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_data_access_append_only ON audit.data_access_event IS '触发器：调用 core.fn_append_only 维护数据库结构完整性、不可变证据或关键原子安全底线。';

