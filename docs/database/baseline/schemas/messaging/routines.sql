-- =============================================================================
-- baseline/schemas/messaging/routines.sql
-- messaging Schema 的最终函数、过程、局部触发器及内联 COMMENT
-- PostgreSQL 16+；应用技术栈：.NET 10 + SqlSugar
-- =============================================================================

CREATE OR REPLACE FUNCTION messaging.fn_message_send_immutable_guard()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN RAISE EXCEPTION 'MESSAGE_SEND_DELETE_FORBIDDEN' USING ERRCODE = '55000'; END IF;
    IF NOT (
        NEW.send_state = OLD.send_state
        OR (OLD.send_state = 'PENDING' AND NEW.send_state IN ('SENDING', 'CANCELLED', 'EXPIRED'))
        OR (OLD.send_state = 'SENDING' AND NEW.send_state IN ('SENT', 'DELIVERED', 'FAILED', 'EXPIRED'))
        OR (OLD.send_state = 'SENT' AND NEW.send_state IN ('DELIVERED', 'FAILED'))
        OR (OLD.send_state = 'FAILED' AND NEW.send_state IN ('SENDING', 'CANCELLED', 'EXPIRED'))
    ) THEN
        RAISE EXCEPTION 'INVALID_STATE_TRANSITION: Message Send % -> %', OLD.send_state, NEW.send_state USING ERRCODE = '23514';
    END IF;
    IF OLD.send_state = 'FAILED' AND NEW.send_state = 'SENDING' THEN
        NEW.failed_at := NULL;
        NEW.failure_code := NULL;
    ELSIF NEW.send_state = 'SENT' AND OLD.send_state <> 'SENT' THEN
        NEW.sent_at := clock_timestamp();
    ELSIF NEW.send_state = 'DELIVERED' AND OLD.send_state <> 'DELIVERED' THEN
        NEW.sent_at := COALESCE(OLD.sent_at, clock_timestamp());
        NEW.delivered_at := clock_timestamp();
    ELSIF NEW.send_state = 'FAILED' AND OLD.send_state <> 'FAILED' THEN
        IF NULLIF(btrim(NEW.failure_code), '') IS NULL THEN
            RAISE EXCEPTION 'MESSAGE_FAILURE_CODE_REQUIRED' USING ERRCODE = '23514';
        END IF;
        NEW.failed_at := clock_timestamp();
    END IF;
    IF OLD.send_state IN ('DELIVERED', 'EXPIRED', 'CANCELLED')
       AND to_jsonb(NEW) IS DISTINCT FROM to_jsonb(OLD) THEN
        RAISE EXCEPTION 'MESSAGE_SEND_TERMINAL_EVIDENCE_IMMUTABLE' USING ERRCODE = '55000';
    END IF;
    IF (to_jsonb(NEW) - ARRAY['send_state','provider_id','provider_message_ref_hash','attempt_count','next_attempt_at','sent_at','delivered_at','failed_at','failure_code','updated_at','row_version'])
       IS DISTINCT FROM
       (to_jsonb(OLD) - ARRAY['send_state','provider_id','provider_message_ref_hash','attempt_count','next_attempt_at','sent_at','delivered_at','failed_at','failure_code','updated_at','row_version']) THEN
        RAISE EXCEPTION 'MESSAGE_SEND_CONTENT_IMMUTABLE' USING ERRCODE = '55000';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_provider_touch BEFORE UPDATE ON messaging.provider FOR EACH ROW EXECUTE FUNCTION core.fn_touch_updated_at();

CREATE TRIGGER trg_provider_version BEFORE UPDATE ON messaging.provider FOR EACH ROW EXECUTE FUNCTION core.fn_increment_row_version();

CREATE TRIGGER trg_message_send_public_id BEFORE INSERT ON messaging.message_send FOR EACH ROW EXECUTE FUNCTION core.fn_register_public_id('MESSAGE_SEND');

CREATE TRIGGER trg_message_send_touch BEFORE UPDATE ON messaging.message_send FOR EACH ROW EXECUTE FUNCTION core.fn_touch_updated_at();

CREATE TRIGGER trg_message_send_version BEFORE UPDATE ON messaging.message_send FOR EACH ROW EXECUTE FUNCTION core.fn_increment_row_version();

CREATE TRIGGER trg_delivery_receipt_append_only BEFORE UPDATE OR DELETE ON messaging.delivery_receipt FOR EACH STATEMENT EXECUTE FUNCTION core.fn_append_only();

CREATE TRIGGER trg_reachability_touch BEFORE UPDATE ON messaging.reachability FOR EACH ROW EXECUTE FUNCTION core.fn_touch_updated_at();

CREATE TRIGGER trg_reachability_version BEFORE UPDATE ON messaging.reachability FOR EACH ROW EXECUTE FUNCTION core.fn_increment_row_version();

CREATE TRIGGER trg_provider_metric_append_only BEFORE UPDATE OR DELETE ON messaging.provider_metric FOR EACH STATEMENT EXECUTE FUNCTION core.fn_append_only();

CREATE TRIGGER trg_route_policy_immutable BEFORE UPDATE OR DELETE ON messaging.route_policy FOR EACH ROW
    EXECUTE FUNCTION core.fn_immutable_except('is_active');

CREATE TRIGGER trg_message_template_immutable BEFORE UPDATE OR DELETE ON messaging.message_template FOR EACH ROW
    EXECUTE FUNCTION core.fn_immutable_except('is_active');

CREATE TRIGGER trg_content_rule_immutable BEFORE UPDATE OR DELETE ON messaging.content_compliance_rule FOR EACH ROW
    EXECUTE FUNCTION core.fn_immutable_except('is_active', 'retired_at');

CREATE TRIGGER trg_zz_message_send_immutable BEFORE UPDATE OR DELETE ON messaging.message_send FOR EACH ROW
    EXECUTE FUNCTION messaging.fn_message_send_immutable_guard();

COMMENT ON FUNCTION messaging.fn_message_send_immutable_guard() IS 'Message Send 只允许推进供应商、重试和发送结果；目标、模板、路由、变量摘要、租户和幂等身份不可修改或删除。';

COMMENT ON TRIGGER trg_provider_touch ON messaging.provider IS '触发器：调用 core.fn_touch_updated_at 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_provider_version ON messaging.provider IS '触发器：调用 core.fn_increment_row_version 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_message_send_public_id ON messaging.message_send IS '触发器：调用 core.fn_register_public_id 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_message_send_touch ON messaging.message_send IS '触发器：调用 core.fn_touch_updated_at 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_message_send_version ON messaging.message_send IS '触发器：调用 core.fn_increment_row_version 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_delivery_receipt_append_only ON messaging.delivery_receipt IS '触发器：调用 core.fn_append_only 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_reachability_touch ON messaging.reachability IS '触发器：调用 core.fn_touch_updated_at 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_reachability_version ON messaging.reachability IS '触发器：调用 core.fn_increment_row_version 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_provider_metric_append_only ON messaging.provider_metric IS '触发器：调用 core.fn_append_only 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_route_policy_immutable ON messaging.route_policy IS '触发器：调用 core.fn_immutable_except 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_message_template_immutable ON messaging.message_template IS '触发器：调用 core.fn_immutable_except 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_content_rule_immutable ON messaging.content_compliance_rule IS '触发器：调用 core.fn_immutable_except 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_zz_message_send_immutable ON messaging.message_send IS '触发器：调用 messaging.fn_message_send_immutable_guard 维护数据库结构完整性、不可变证据或关键原子安全底线。';

