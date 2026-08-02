-- =============================================================================
-- baseline/schemas/integration/routines.sql
-- integration Schema 的最终函数、过程、局部触发器及内联 COMMENT
-- PostgreSQL 16+；应用技术栈：.NET 10 + SqlSugar
-- =============================================================================

CREATE OR REPLACE FUNCTION integration.fn_outbox_immutable_guard()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'OUTBOX_DELETE_FORBIDDEN' USING ERRCODE = '55000';
    END IF;
    IF NOT (
        NEW.publish_state = OLD.publish_state
        OR (OLD.publish_state = 'PENDING' AND NEW.publish_state IN ('PUBLISHING', 'DEAD_LETTER'))
        OR (OLD.publish_state = 'PUBLISHING' AND NEW.publish_state IN ('PUBLISHED', 'FAILED', 'DEAD_LETTER'))
        OR (OLD.publish_state = 'FAILED' AND NEW.publish_state IN ('PUBLISHING', 'DEAD_LETTER'))
    ) THEN
        RAISE EXCEPTION 'INVALID_STATE_TRANSITION: Outbox % -> %', OLD.publish_state, NEW.publish_state USING ERRCODE = '23514';
    END IF;
    IF OLD.publish_state = 'PUBLISHING' AND NEW.publish_state = 'PUBLISHED' THEN
        NEW.published_at := clock_timestamp();
    END IF;
    IF OLD.publish_state IN ('PUBLISHED', 'DEAD_LETTER') AND to_jsonb(NEW) IS DISTINCT FROM to_jsonb(OLD) THEN
        RAISE EXCEPTION 'OUTBOX_TERMINAL_EVIDENCE_IMMUTABLE' USING ERRCODE = '55000';
    END IF;
    IF (to_jsonb(NEW) - ARRAY['publish_state','attempt_count','next_attempt_at','published_at','broker_partition','broker_offset','last_error_code'])
       IS DISTINCT FROM
       (to_jsonb(OLD) - ARRAY['publish_state','attempt_count','next_attempt_at','published_at','broker_partition','broker_offset','last_error_code']) THEN
        RAISE EXCEPTION 'OUTBOX_EVENT_IMMUTABLE' USING ERRCODE = '55000';
    END IF;
    RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION integration.fn_webhook_delivery_immutable_guard()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN RAISE EXCEPTION 'WEBHOOK_DELIVERY_DELETE_FORBIDDEN' USING ERRCODE = '55000'; END IF;
    IF NOT (
        NEW.delivery_state = OLD.delivery_state
        OR (OLD.delivery_state = 'PENDING' AND NEW.delivery_state IN ('SENDING', 'CANCELLED', 'DEAD_LETTER'))
        OR (OLD.delivery_state = 'SENDING' AND NEW.delivery_state IN ('DELIVERED', 'FAILED', 'DEAD_LETTER'))
    ) THEN
        RAISE EXCEPTION 'INVALID_STATE_TRANSITION: Webhook Delivery % -> %', OLD.delivery_state, NEW.delivery_state USING ERRCODE = '23514';
    END IF;
    IF OLD.delivery_state = 'PENDING' AND NEW.delivery_state = 'SENDING' THEN
        NEW.first_attempt_at := clock_timestamp();
    ELSIF OLD.delivery_state = 'SENDING' AND NEW.delivery_state = 'DELIVERED' THEN
        NEW.delivered_at := clock_timestamp();
    ELSIF NEW.delivery_state = 'DEAD_LETTER' AND OLD.delivery_state <> 'DEAD_LETTER' THEN
        NEW.dead_lettered_at := clock_timestamp();
    END IF;
    IF OLD.delivery_state IN ('DELIVERED', 'FAILED', 'DEAD_LETTER', 'CANCELLED')
       AND to_jsonb(NEW) IS DISTINCT FROM to_jsonb(OLD) THEN
        RAISE EXCEPTION 'WEBHOOK_DELIVERY_TERMINAL_EVIDENCE_IMMUTABLE' USING ERRCODE = '55000';
    END IF;
    IF (to_jsonb(NEW) - ARRAY['delivery_state','response_status','response_body_hash','next_attempt_at','first_attempt_at','delivered_at','dead_lettered_at'])
       IS DISTINCT FROM
       (to_jsonb(OLD) - ARRAY['delivery_state','response_status','response_body_hash','next_attempt_at','first_attempt_at','delivered_at','dead_lettered_at']) THEN
        RAISE EXCEPTION 'WEBHOOK_DELIVERY_EVIDENCE_IMMUTABLE' USING ERRCODE = '55000';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_outbox_immutable BEFORE UPDATE OR DELETE ON integration.outbox_event FOR EACH ROW EXECUTE FUNCTION integration.fn_outbox_immutable_guard();

CREATE TRIGGER trg_webhook_subscription_public_id BEFORE INSERT ON integration.webhook_subscription FOR EACH ROW EXECUTE FUNCTION core.fn_register_public_id('WEBHOOK_SUBSCRIPTION');

CREATE TRIGGER trg_webhook_subscription_touch BEFORE UPDATE ON integration.webhook_subscription FOR EACH ROW EXECUTE FUNCTION core.fn_touch_updated_at();

CREATE TRIGGER trg_webhook_subscription_version BEFORE UPDATE ON integration.webhook_subscription FOR EACH ROW EXECUTE FUNCTION core.fn_increment_row_version();

CREATE TRIGGER trg_webhook_delivery_public_id BEFORE INSERT ON integration.webhook_delivery FOR EACH ROW EXECUTE FUNCTION core.fn_register_public_id('WEBHOOK_DELIVERY');

CREATE TRIGGER trg_replay_public_id BEFORE INSERT ON integration.event_replay_request FOR EACH ROW EXECUTE FUNCTION core.fn_register_public_id('EVENT_REPLAY');

CREATE TRIGGER trg_consumer_watermark_touch BEFORE UPDATE ON integration.consumer_watermark FOR EACH ROW EXECUTE FUNCTION core.fn_touch_updated_at();

CREATE TRIGGER trg_consumer_watermark_version BEFORE UPDATE ON integration.consumer_watermark FOR EACH ROW EXECUTE FUNCTION core.fn_increment_row_version();

CREATE TRIGGER trg_event_schema_immutable BEFORE UPDATE OR DELETE ON integration.event_schema FOR EACH ROW
    EXECUTE FUNCTION core.fn_immutable_except('is_active');

CREATE TRIGGER trg_webhook_delivery_immutable BEFORE UPDATE OR DELETE ON integration.webhook_delivery FOR EACH ROW
    EXECUTE FUNCTION integration.fn_webhook_delivery_immutable_guard();

COMMENT ON FUNCTION integration.fn_outbox_immutable_guard() IS 'Outbox 只允许推进发布状态、重试和 Broker 回执；租户、Subject、Actor、追踪、正文、摘要和事件身份均不可改删。';

COMMENT ON FUNCTION integration.fn_webhook_delivery_immutable_guard() IS 'Webhook Delivery 只允许推进尝试、响应和终态元数据；订阅、事件、接收者、Payload 与签名证据不可修改或删除。';

COMMENT ON TRIGGER trg_outbox_immutable ON integration.outbox_event IS '触发器：调用 integration.fn_outbox_immutable_guard 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_webhook_subscription_public_id ON integration.webhook_subscription IS '触发器：调用 core.fn_register_public_id 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_webhook_subscription_touch ON integration.webhook_subscription IS '触发器：调用 core.fn_touch_updated_at 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_webhook_subscription_version ON integration.webhook_subscription IS '触发器：调用 core.fn_increment_row_version 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_webhook_delivery_public_id ON integration.webhook_delivery IS '触发器：调用 core.fn_register_public_id 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_replay_public_id ON integration.event_replay_request IS '触发器：调用 core.fn_register_public_id 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_consumer_watermark_touch ON integration.consumer_watermark IS '触发器：调用 core.fn_touch_updated_at 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_consumer_watermark_version ON integration.consumer_watermark IS '触发器：调用 core.fn_increment_row_version 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_event_schema_immutable ON integration.event_schema IS '触发器：调用 core.fn_immutable_except 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_webhook_delivery_immutable ON integration.webhook_delivery IS '触发器：调用 integration.fn_webhook_delivery_immutable_guard 维护数据库结构完整性、不可变证据或关键原子安全底线。';

