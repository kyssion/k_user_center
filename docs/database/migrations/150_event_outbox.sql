-- =============================================================================
-- 150_event_outbox.sql
-- EVENT 域：Outbox、事件 Schema 注册、发布者 ACL、Webhook 端点与订阅、投递记录、消费方水位
-- 依据：能力地图 §4.17；蓝图 §5.3（EVT-G-001 至 011）、§16（INV-G-010）
-- 关键：Outbox 与业务状态同事务写入；Webhook 出站受 allowlist 与私网阻断约束
-- =============================================================================

SET client_min_messages = warning;

-- -----------------------------------------------------------------------------
-- 1. 事件 Schema 注册（EVT-G-007、CAP-EVENT-006）
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS event.event_schema (
    event_type          text        NOT NULL,
    schema_version      integer     NOT NULL,
    json_schema          jsonb      NOT NULL,
    compatibility_state text        NOT NULL DEFAULT 'ACTIVE',
    data_classification text        NOT NULL DEFAULT 'INTERNAL',
    pii_field_allowlist text[]      NOT NULL DEFAULT '{}',
    ordering_key_field  text        NOT NULL DEFAULT 'aggregate_id',
    published_at        timestamptz NOT NULL DEFAULT now(),
    deprecated_at       timestamptz NULL,
    sunset_at           timestamptz NULL,
    CONSTRAINT pk_event_schema PRIMARY KEY (event_type, schema_version),
    CONSTRAINT fk_event_schema_classification FOREIGN KEY (data_classification) REFERENCES core.data_classification (classification_code),
    CONSTRAINT ck_event_schema_state CHECK (compatibility_state IN ('ACTIVE', 'DEPRECATED', 'SUNSET')),
    CONSTRAINT ck_event_schema_type CHECK (event_type ~ '^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$'),
    CONSTRAINT ck_event_schema_version CHECK (schema_version >= 1),
    -- EVT-G-006：默认不携带 PII，确需携带时必须使用字段白名单
    CONSTRAINT ck_event_schema_pii CHECK (
        data_classification IN ('PUBLIC', 'INTERNAL') OR array_length(pii_field_allowlist, 1) >= 1
    ),
    CONSTRAINT ck_event_schema_sunset CHECK (sunset_at IS NULL OR deprecated_at IS NOT NULL)
);
COMMENT ON TABLE event.event_schema IS 'EVT-G-007：删除、改义或改类型必须升级主版本；CAP-EVENT-008 按数据分级决定可订阅范围';

-- 发布者授权（EVT-G-009：producer principal → event type/tenant ACL）
CREATE TABLE IF NOT EXISTS event.producer_acl (
    id                 uuid        NOT NULL DEFAULT core.uuid_generate_v7(),
    producer_ref       text        NOT NULL,
    producer_kind      text        NOT NULL,
    event_type_pattern text        NOT NULL,
    tenant_id          uuid        NOT NULL DEFAULT '00000000-0000-0000-0000-000000000000',
    is_allowed         boolean     NOT NULL DEFAULT true,
    created_at         timestamptz NOT NULL DEFAULT now(),
    created_by_ref     text        NOT NULL,
    CONSTRAINT pk_producer_acl PRIMARY KEY (id),
    CONSTRAINT uq_producer_acl UNIQUE (producer_ref, event_type_pattern, tenant_id),
    CONSTRAINT ck_producer_acl_kind CHECK (producer_kind IN ('MACHINE_PRINCIPAL', 'INTERNAL_SERVICE'))
);
COMMENT ON TABLE event.producer_acl IS 'EVT-G-009：每个 Producer 使用机器主体认证并按事件类型与租户授权；未授权发布必须被拒并告警（AT-EVENT-001）';

-- -----------------------------------------------------------------------------
-- 2. Outbox（INV-G-010：与业务状态同事务写入）
-- 字段与蓝图 §5.3 事件信封逐项对应
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS event.outbox (
    id                  uuid        NOT NULL DEFAULT core.uuid_generate_v7(),
    event_id            text        NOT NULL,
    event_type          text        NOT NULL,
    schema_version      integer     NOT NULL,
    aggregate_type      text        NOT NULL,
    aggregate_id        text        NOT NULL,
    aggregate_version   bigint      NOT NULL,
    subject_id          text        NULL,
    tenant_id           uuid        NOT NULL DEFAULT '00000000-0000-0000-0000-000000000000',
    business_line_id    uuid        NULL,
    actor_kind          text        NOT NULL,
    actor_ref           text        NULL,
    occurred_at         timestamptz NOT NULL,
    recorded_at         timestamptz NOT NULL DEFAULT now(),
    trace_id            text        NULL,
    correlation_id      text        NULL,
    causation_id        text        NULL,
    data_classification text        NOT NULL DEFAULT 'INTERNAL',
    ordering_key        text        NOT NULL,
    payload             jsonb       NOT NULL DEFAULT '{}'::jsonb,
    -- 投递状态
    dispatch_state      text        NOT NULL DEFAULT 'PENDING',
    attempt_count       integer     NOT NULL DEFAULT 0,
    next_attempt_at     timestamptz NOT NULL DEFAULT now(),
    published_at        timestamptz NULL,
    dead_lettered_at    timestamptz NULL,
    last_error_code     text        NULL,
    prunable_after      timestamptz NULL,
    CONSTRAINT pk_outbox PRIMARY KEY (id),
    CONSTRAINT uq_outbox_event_id UNIQUE (event_id),
    CONSTRAINT fk_outbox_schema FOREIGN KEY (event_type, schema_version) REFERENCES event.event_schema (event_type, schema_version),
    CONSTRAINT fk_outbox_classification FOREIGN KEY (data_classification) REFERENCES core.data_classification (classification_code),
    CONSTRAINT ck_outbox_actor CHECK (actor_kind IN ('USER', 'ADMIN', 'CLIENT', 'SYSTEM', 'MACHINE')),
    CONSTRAINT ck_outbox_dispatch_state CHECK (dispatch_state IN ('PENDING', 'DISPATCHING', 'PUBLISHED', 'DEAD_LETTER')),
    CONSTRAINT ck_outbox_published CHECK ((dispatch_state = 'PUBLISHED') = (published_at IS NOT NULL)),
    CONSTRAINT ck_outbox_dead_letter CHECK ((dispatch_state = 'DEAD_LETTER') = (dead_lettered_at IS NOT NULL)),
    -- EVT-G-002：单 aggregate 版本单调
    CONSTRAINT ck_outbox_aggregate_version CHECK (aggregate_version >= 1),
    CONSTRAINT ck_outbox_event_id_format CHECK (event_id ~ '^evt_[A-Za-z0-9]{16,32}$'),
    -- 事件载荷最小化：超过 64KB 说明被当成了数据同步通道（能力地图 §4.17 约束）
    CONSTRAINT ck_outbox_payload_size CHECK (length(payload::text) <= 65536)
);
COMMENT ON TABLE event.outbox IS 'INV-G-010：权威状态写入与领域事件通过同一事务提交；字段与蓝图 §5.3 事件信封一一对应';
COMMENT ON COLUMN event.outbox.ordering_key IS 'EVT-G-002 / CAP-EVENT-007：单主体顺序键，同一 key 的事件必须串行投递';
COMMENT ON COLUMN event.outbox.payload IS 'EVT-G-006：默认不携带 PII；确需携带时字段必须在 event_schema.pii_field_allowlist 内';

-- 投递器扫描索引：按顺序键串行、按时间重试
CREATE INDEX IF NOT EXISTS ix_outbox_dispatch
    ON event.outbox (next_attempt_at, id) WHERE dispatch_state IN ('PENDING', 'DISPATCHING');
CREATE INDEX IF NOT EXISTS ix_outbox_ordering
    ON event.outbox (ordering_key, aggregate_version) WHERE dispatch_state <> 'PUBLISHED';
CREATE INDEX IF NOT EXISTS ix_outbox_dead_letter
    ON event.outbox (dead_lettered_at DESC) WHERE dispatch_state = 'DEAD_LETTER';
CREATE INDEX IF NOT EXISTS ix_outbox_prune ON event.outbox (prunable_after) WHERE dispatch_state = 'PUBLISHED';
CREATE INDEX IF NOT EXISTS ix_outbox_subject ON event.outbox (subject_id, occurred_at DESC);

-- -----------------------------------------------------------------------------
-- 3. Webhook 端点与订阅（CAP-API-011、CAP-EVENT-004/005、EVT-G-010/011）
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS event.webhook_endpoint (
    id                     uuid        NOT NULL DEFAULT core.uuid_generate_v7(),
    public_id              text        NOT NULL,
    subscriber_client_id   uuid        NOT NULL,
    tenant_id              uuid        NOT NULL DEFAULT '00000000-0000-0000-0000-000000000000',
    target_url             text        NOT NULL,
    endpoint_state         text        NOT NULL DEFAULT 'PENDING_VERIFICATION',
    ownership_verified_at  timestamptz NULL,
    verification_token_hash bytea      NULL,
    -- EVT-G-011：签名契约版本化
    signature_algorithm    text        NOT NULL DEFAULT 'HMAC_SHA256',
    canonicalization       text        NOT NULL DEFAULT 'RAW_BYTES_V1',
    current_key_id         text        NOT NULL,
    next_key_id            text        NULL,
    max_clock_skew_seconds integer     NOT NULL DEFAULT 300,
    replay_window_seconds  integer     NOT NULL DEFAULT 300,
    max_data_classification text       NOT NULL DEFAULT 'INTERNAL',
    rate_limit_per_minute  integer     NOT NULL DEFAULT 600,
    consecutive_failures   integer     NOT NULL DEFAULT 0,
    disabled_at            timestamptz NULL,
    owner_ref              text        NOT NULL,
    created_at             timestamptz NOT NULL DEFAULT now(),
    updated_at             timestamptz NOT NULL DEFAULT now(),
    row_version            bigint      NOT NULL DEFAULT 1,
    CONSTRAINT pk_webhook_endpoint PRIMARY KEY (id),
    CONSTRAINT uq_webhook_endpoint_public_id UNIQUE (public_id),
    CONSTRAINT uq_webhook_endpoint_target UNIQUE (subscriber_client_id, target_url),
    CONSTRAINT fk_webhook_endpoint_client FOREIGN KEY (subscriber_client_id) REFERENCES oap.client (id),
    CONSTRAINT fk_webhook_endpoint_classification FOREIGN KEY (max_data_classification) REFERENCES core.data_classification (classification_code),
    CONSTRAINT ck_webhook_endpoint_state CHECK (endpoint_state IN ('PENDING_VERIFICATION', 'ACTIVE', 'SUSPENDED', 'DISABLED')),
    CONSTRAINT ck_webhook_endpoint_signature CHECK (signature_algorithm IN ('HMAC_SHA256', 'ES256', 'SM3_HMAC')),
    -- EVT-G-010：必须 HTTPS，且结构性阻断明显的私网与回环目标
    CONSTRAINT ck_webhook_endpoint_https CHECK (target_url ~ '^https://'),
    CONSTRAINT ck_webhook_endpoint_no_private CHECK (
        target_url !~* '^https://(localhost|127\.|10\.|192\.168\.|169\.254\.|\[::1\]|172\.(1[6-9]|2[0-9]|3[01])\.)'
    ),
    -- 未验证所有权不得启用（EVT-G-010）
    CONSTRAINT ck_webhook_endpoint_verified CHECK (
        endpoint_state <> 'ACTIVE' OR ownership_verified_at IS NOT NULL
    ),
    CONSTRAINT ck_webhook_endpoint_skew CHECK (max_clock_skew_seconds BETWEEN 30 AND 600),
    CONSTRAINT ck_webhook_endpoint_replay CHECK (replay_window_seconds BETWEEN 60 AND 900),
    -- 密钥双轮换：next_key_id 不得与当前相同
    CONSTRAINT ck_webhook_endpoint_key_rotation CHECK (next_key_id IS NULL OR next_key_id <> current_key_id)
);
COMMENT ON TABLE event.webhook_endpoint IS 'EVT-G-010/011：出站前验证域名所有权、阻断私网与回环、版本化签名契约与密钥双轮换（AT-EVENT-003）';
COMMENT ON COLUMN event.webhook_endpoint.max_data_classification IS 'CAP-EVENT-008：订阅方可接收的最高敏感级别，高于该级别的事件不投递';

CREATE OR REPLACE TRIGGER trg_webhook_endpoint_touch
    BEFORE UPDATE ON event.webhook_endpoint
    FOR EACH ROW EXECUTE FUNCTION core.fn_touch_updated_at();

CREATE TABLE IF NOT EXISTS event.webhook_subscription (
    id                uuid        NOT NULL DEFAULT core.uuid_generate_v7(),
    endpoint_id       uuid        NOT NULL,
    event_type        text        NOT NULL,
    min_schema_version integer    NOT NULL DEFAULT 1,
    filter_expression jsonb       NULL,
    is_active         boolean     NOT NULL DEFAULT true,
    created_at        timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT pk_webhook_subscription PRIMARY KEY (id),
    CONSTRAINT uq_webhook_subscription UNIQUE (endpoint_id, event_type),
    CONSTRAINT fk_webhook_subscription_endpoint FOREIGN KEY (endpoint_id) REFERENCES event.webhook_endpoint (id) ON DELETE CASCADE
);
COMMENT ON TABLE event.webhook_subscription IS 'CAP-API-011：业务订阅指定事件；事件清单与语义由 event.event_schema 定义，本表只管订阅关系';

-- 投递记录（按月分区，EVT-G-004：重试、死信、受控回放）
CREATE TABLE IF NOT EXISTS event.webhook_delivery (
    id                uuid        NOT NULL DEFAULT core.uuid_generate_v7(),
    occurred_at       timestamptz NOT NULL DEFAULT now(),
    endpoint_id       uuid        NOT NULL,
    event_id          text        NOT NULL,
    event_type        text        NOT NULL,
    delivery_state    text        NOT NULL DEFAULT 'PENDING',
    attempt_count     integer     NOT NULL DEFAULT 0,
    next_attempt_at   timestamptz NULL,
    signature_key_id  text        NULL,
    response_status   integer     NULL,
    response_latency_ms integer   NULL,
    last_error_code   text        NULL,
    delivered_at      timestamptz NULL,
    dead_lettered_at  timestamptz NULL,
    is_replay         boolean     NOT NULL DEFAULT false,
    replay_approval_ref text      NULL,
    CONSTRAINT pk_webhook_delivery PRIMARY KEY (id, occurred_at),
    CONSTRAINT ck_webhook_delivery_state CHECK (delivery_state IN ('PENDING', 'DELIVERED', 'FAILED', 'DEAD_LETTER', 'SKIPPED_CLASSIFICATION')),
    CONSTRAINT ck_webhook_delivery_delivered CHECK ((delivery_state = 'DELIVERED') = (delivered_at IS NOT NULL)),
    -- EVT-G-008：回放需要审批与范围
    CONSTRAINT ck_webhook_delivery_replay CHECK (NOT is_replay OR replay_approval_ref IS NOT NULL)
) PARTITION BY RANGE (occurred_at);
COMMENT ON TABLE event.webhook_delivery IS 'EVT-G-004/008：投递、重试、死信与受控回放记录；回放必须有审批且不得重复触发不可逆副作用';

SELECT core.fn_ensure_monthly_partitions('event', 'webhook_delivery', 3);
SELECT core.fn_ensure_default_partition('event', 'webhook_delivery');

CREATE INDEX IF NOT EXISTS ix_webhook_delivery_endpoint ON event.webhook_delivery (endpoint_id, occurred_at DESC);
CREATE INDEX IF NOT EXISTS ix_webhook_delivery_retry ON event.webhook_delivery (next_attempt_at) WHERE delivery_state IN ('PENDING', 'FAILED');

-- -----------------------------------------------------------------------------
-- 4. 消费方水位与合规度（CAP-EVENT-010/012、REQ-SESSION-012）
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS event.consumer_watermark (
    id                     uuid        NOT NULL DEFAULT core.uuid_generate_v7(),
    consumer_ref           text        NOT NULL,
    consumer_kind          text        NOT NULL,
    watermark_kind         text        NOT NULL,
    last_event_id          text        NULL,
    last_aggregate_version bigint      NULL,
    known_security_epoch   bigint      NULL,
    known_policy_version   bigint      NULL,
    revocation_watermark_at timestamptz NULL,
    reported_at            timestamptz NOT NULL DEFAULT now(),
    lag_seconds            integer     NULL,
    compliance_state       text        NOT NULL DEFAULT 'COMPLIANT',
    breach_count           integer     NOT NULL DEFAULT 0,
    updated_at             timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT pk_consumer_watermark PRIMARY KEY (id),
    CONSTRAINT uq_consumer_watermark UNIQUE (consumer_ref, watermark_kind),
    CONSTRAINT ck_consumer_watermark_kind CHECK (watermark_kind IN (
        'EVENT_STREAM', 'USER_SECURITY_EPOCH', 'CLIENT_SECURITY_EPOCH', 'TENANT_SECURITY_EPOCH',
        'POLICY_VERSION', 'REVOCATION', 'CONSENT_EPOCH'
    )),
    CONSTRAINT ck_consumer_watermark_consumer CHECK (consumer_kind IN ('API_RESOURCE', 'CLIENT', 'INTERNAL_SERVICE', 'WEBHOOK_ENDPOINT')),
    CONSTRAINT ck_consumer_watermark_compliance CHECK (compliance_state IN ('COMPLIANT', 'LAGGING', 'BREACHED', 'DISCONNECTED')),
    CONSTRAINT ck_consumer_watermark_lag CHECK (lag_seconds IS NULL OR lag_seconds >= 0)
);
COMMENT ON TABLE event.consumer_watermark IS 'CAP-EVENT-010/012：水位下发与确认；超时未确认即 BREACHED 并告警，消费方在水位不可确认时必须失败关闭（AT-SESSION-009）';

CREATE OR REPLACE TRIGGER trg_consumer_watermark_touch
    BEFORE UPDATE ON event.consumer_watermark
    FOR EACH ROW EXECUTE FUNCTION core.fn_touch_updated_at();

CREATE INDEX IF NOT EXISTS ix_consumer_watermark_breach ON event.consumer_watermark (compliance_state, reported_at DESC)
    WHERE compliance_state <> 'COMPLIANT';

SELECT core.fn_apply_standard_grants('event');

SELECT core.fn_migration_apply('150', 'event_outbox：事件 Schema、发布者 ACL、Outbox、Webhook 端点与订阅、投递记录、消费方水位');
