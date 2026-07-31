-- =============================================================================
-- 170_message.sql
-- MSG 域：供应商、模板、发送记录、投递回执、可达性
-- 依据：能力地图 §4.18；蓝图 §15.4 故障语义
-- 关键：验证码与链接内容不落库（CAP-MSG-009）；可达性回写到 id.identifier（CAP-MSG-007）
-- =============================================================================

SET client_min_messages = warning;

-- -----------------------------------------------------------------------------
-- 1. 供应商（CAP-MSG-002/003：多供应商路由与降级链）
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS msg.provider (
    id                  uuid        NOT NULL DEFAULT core.uuid_generate_v7(),
    provider_code       text        NOT NULL,
    channel             text        NOT NULL,
    display_name        text        NOT NULL,
    provider_state      text        NOT NULL DEFAULT 'ACTIVE',
    region_scope        text[]      NOT NULL DEFAULT '{}',
    routing_priority    smallint    NOT NULL DEFAULT 100,
    fallback_provider_id uuid       NULL,
    unit_cost_micros    bigint      NULL,
    success_rate_7d_bps integer     NULL,
    circuit_state       text        NOT NULL DEFAULT 'CLOSED',
    circuit_opened_at   timestamptz NULL,
    credential_ref      text        NOT NULL,
    created_at          timestamptz NOT NULL DEFAULT now(),
    updated_at          timestamptz NOT NULL DEFAULT now(),
    row_version         bigint      NOT NULL DEFAULT 1,
    CONSTRAINT pk_provider PRIMARY KEY (id),
    CONSTRAINT uq_provider_code UNIQUE (provider_code, channel),
    CONSTRAINT fk_provider_fallback FOREIGN KEY (fallback_provider_id) REFERENCES msg.provider (id),
    CONSTRAINT ck_provider_channel CHECK (channel IN ('SMS', 'EMAIL', 'VOICE', 'PUSH', 'IN_APP')),
    CONSTRAINT ck_provider_state CHECK (provider_state IN ('ACTIVE', 'DEGRADED', 'SUSPENDED', 'RETIRED')),
    CONSTRAINT ck_provider_circuit CHECK (circuit_state IN ('CLOSED', 'HALF_OPEN', 'OPEN')),
    CONSTRAINT ck_provider_success_rate CHECK (success_rate_7d_bps IS NULL OR success_rate_7d_bps BETWEEN 0 AND 10000),
    CONSTRAINT ck_provider_no_self_fallback CHECK (fallback_provider_id IS NULL OR fallback_provider_id <> id),
    -- 供应商凭据只存引用，实际密钥在 KMS（REQ-KEY-001）
    CONSTRAINT ck_provider_credential CHECK (length(credential_ref) > 0)
);
COMMENT ON TABLE msg.provider IS 'CAP-MSG-002/003：按地区、类型、成本与成功率路由；fallback_provider_id 构成 CAP-PLT-012 要求的逐依赖降级链';
COMMENT ON COLUMN msg.provider.circuit_state IS 'CAP-MSG-003：断路后自动切换；验证码通道不可用等价于登录不可用，故计入 SLO-AUTH-001 错误预算';

CREATE OR REPLACE TRIGGER trg_provider_touch
    BEFORE UPDATE ON msg.provider
    FOR EACH ROW EXECUTE FUNCTION core.fn_touch_updated_at();

CREATE INDEX IF NOT EXISTS ix_provider_routing ON msg.provider (channel, routing_priority) WHERE provider_state = 'ACTIVE';

-- -----------------------------------------------------------------------------
-- 2. 模板（CAP-MSG-005/006：版本、审批、变量校验、多语言、报备与退订标识）
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS msg.template (
    id                  uuid        NOT NULL DEFAULT core.uuid_generate_v7(),
    template_code       text        NOT NULL,
    channel             text        NOT NULL,
    locale              text        NOT NULL,
    template_version    integer     NOT NULL,
    category            text        NOT NULL,
    approval_state      text        NOT NULL DEFAULT 'DRAFT',
    body_hash           bytea       NOT NULL,
    body_uri            text        NOT NULL,
    variable_schema     jsonb       NOT NULL DEFAULT '{}'::jsonb,
    regulatory_filing_ref text      NULL,
    sender_identity_ref text        NULL,
    has_unsubscribe_notice boolean  NOT NULL DEFAULT false,
    approved_by_ref     text        NULL,
    approved_at         timestamptz NULL,
    deprecated_at       timestamptz NULL,
    created_at          timestamptz NOT NULL DEFAULT now(),
    updated_at          timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT pk_template PRIMARY KEY (id),
    CONSTRAINT uq_template_version UNIQUE (template_code, channel, locale, template_version),
    CONSTRAINT ck_template_channel CHECK (channel IN ('SMS', 'EMAIL', 'VOICE', 'PUSH', 'IN_APP')),
    CONSTRAINT ck_template_category CHECK (category IN ('SECURITY', 'TRANSACTIONAL', 'MARKETING', 'PRODUCT_UPDATE')),
    CONSTRAINT ck_template_approval CHECK (approval_state IN ('DRAFT', 'PENDING_APPROVAL', 'APPROVED', 'DEPRECATED')),
    CONSTRAINT ck_template_hash CHECK (octet_length(body_hash) = 32),
    -- CAP-MSG-006：营销类必须带退订标识；境内短信必须有报备信息与发送方标识
    CONSTRAINT ck_template_marketing_unsubscribe CHECK (category <> 'MARKETING' OR has_unsubscribe_notice),
    CONSTRAINT ck_template_sms_filing CHECK (channel <> 'SMS' OR approval_state <> 'APPROVED' OR sender_identity_ref IS NOT NULL),
    CONSTRAINT ck_template_approved CHECK (
        approval_state <> 'APPROVED' OR (approved_at IS NOT NULL AND approved_by_ref IS NOT NULL)
    )
);
COMMENT ON TABLE msg.template IS 'CAP-MSG-005/006：模板版本与审批；营销类必须带退订标识，短信必须有发送方标识与报备信息';

CREATE OR REPLACE TRIGGER trg_template_touch
    BEFORE UPDATE ON msg.template
    FOR EACH ROW EXECUTE FUNCTION core.fn_touch_updated_at();

CREATE UNIQUE INDEX IF NOT EXISTS ux_template_approved
    ON msg.template (template_code, channel, locale) WHERE approval_state = 'APPROVED';

-- -----------------------------------------------------------------------------
-- 3. 发送记录（CAP-MSG-010，按月分区）
-- 结构性保证：本表没有任何"内容"列，验证码与链接不落库（CAP-MSG-009）
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS msg.message_send (
    id                  uuid        NOT NULL DEFAULT core.uuid_generate_v7(),
    occurred_at         timestamptz NOT NULL DEFAULT now(),
    channel             text        NOT NULL,
    provider_id         uuid        NULL,
    template_code       text        NOT NULL,
    template_version    integer     NOT NULL,
    category            text        NOT NULL,
    purpose_code        text        NOT NULL,
    target_blind_index  bytea       NOT NULL,
    target_masked       text        NOT NULL,
    target_region       text        NULL,
    user_id             uuid        NULL,
    tenant_id           uuid        NOT NULL DEFAULT '00000000-0000-0000-0000-000000000000',
    challenge_id        uuid        NULL,
    send_state          text        NOT NULL DEFAULT 'QUEUED',
    provider_message_id text        NULL,
    submitted_at        timestamptz NULL,
    delivered_at        timestamptz NULL,
    failed_at           timestamptz NULL,
    failure_code        text        NULL,
    fallback_of_id      uuid        NULL,
    attempt_no          smallint    NOT NULL DEFAULT 1,
    cost_micros         bigint      NULL,
    trace_id            text        NULL,
    CONSTRAINT pk_message_send PRIMARY KEY (id, occurred_at),
    CONSTRAINT ck_message_send_channel CHECK (channel IN ('SMS', 'EMAIL', 'VOICE', 'PUSH', 'IN_APP')),
    CONSTRAINT ck_message_send_category CHECK (category IN ('SECURITY', 'TRANSACTIONAL', 'MARKETING', 'PRODUCT_UPDATE')),
    CONSTRAINT ck_message_send_state CHECK (send_state IN ('QUEUED', 'SUBMITTED', 'DELIVERED', 'FAILED', 'EXPIRED', 'SUPPRESSED')),
    CONSTRAINT ck_message_send_blind_index CHECK (octet_length(target_blind_index) = 32),
    CONSTRAINT ck_message_send_delivered CHECK ((send_state = 'DELIVERED') = (delivered_at IS NOT NULL)),
    CONSTRAINT ck_message_send_failed CHECK (send_state <> 'FAILED' OR (failed_at IS NOT NULL AND failure_code IS NOT NULL)),
    CONSTRAINT ck_message_send_attempt CHECK (attempt_no BETWEEN 1 AND 10)
) PARTITION BY RANGE (occurred_at);
COMMENT ON TABLE msg.message_send IS 'CAP-MSG-010 发送审计：谁在何时向哪个标识发送了哪类消息。CAP-MSG-009：本表结构上不含消息内容列，验证码与链接不落库不入日志';
COMMENT ON COLUMN msg.message_send.target_blind_index IS '收件目标只存盲索引与掩码，禁止明文（REQ-KEY-008）';
COMMENT ON COLUMN msg.message_send.fallback_of_id IS 'CAP-MSG-003：降级链上的后继发送指向被降级的原发送记录';

SELECT core.fn_ensure_monthly_partitions('msg', 'message_send', 3, true);
SELECT core.fn_ensure_default_partition('msg', 'message_send', true);

CREATE INDEX IF NOT EXISTS ix_message_send_target ON msg.message_send (target_blind_index, occurred_at DESC);
CREATE INDEX IF NOT EXISTS ix_message_send_user ON msg.message_send (user_id, occurred_at DESC);
CREATE INDEX IF NOT EXISTS ix_message_send_provider ON msg.message_send (provider_id, send_state, occurred_at DESC);
CREATE INDEX IF NOT EXISTS ix_message_send_challenge ON msg.message_send (challenge_id) WHERE challenge_id IS NOT NULL;

-- 投递回执（CAP-MSG-004：提交、送达、失败、超时状态统一归集）
CREATE TABLE IF NOT EXISTS msg.delivery_receipt (
    id                  uuid        NOT NULL DEFAULT core.uuid_generate_v7(),
    provider_message_id text        NOT NULL,
    provider_id         uuid        NOT NULL,
    receipt_state       text        NOT NULL,
    provider_status_code text       NULL,
    received_at         timestamptz NOT NULL DEFAULT now(),
    reported_at         timestamptz NULL,
    payload             jsonb       NULL,
    CONSTRAINT pk_delivery_receipt PRIMARY KEY (id),
    -- 回执不保证顺序且可能重复，按供应商消息 ID + 状态去重（EVT-G-003 幂等原则）
    CONSTRAINT uq_delivery_receipt UNIQUE (provider_id, provider_message_id, receipt_state),
    CONSTRAINT fk_delivery_receipt_provider FOREIGN KEY (provider_id) REFERENCES msg.provider (id),
    CONSTRAINT ck_delivery_receipt_state CHECK (receipt_state IN ('SUBMITTED', 'DELIVERED', 'FAILED', 'EXPIRED', 'REJECTED', 'HARD_BOUNCE', 'SOFT_BOUNCE'))
);
COMMENT ON TABLE msg.delivery_receipt IS 'CAP-MSG-004：回执归集；回调不保证顺序也可能重复，唯一键提供幂等';

CREATE INDEX IF NOT EXISTS ix_delivery_receipt_recent ON msg.delivery_receipt (received_at DESC);

-- -----------------------------------------------------------------------------
-- 4. 可达性（CAP-MSG-007：硬退信标记回写，影响恢复渠道选择）
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS msg.reachability (
    target_blind_index  bytea       NOT NULL,
    channel             text        NOT NULL,
    reachability_state  text        NOT NULL DEFAULT 'UNKNOWN',
    last_success_at     timestamptz NULL,
    last_failure_at     timestamptz NULL,
    hard_bounce_at      timestamptz NULL,
    consecutive_failures integer    NOT NULL DEFAULT 0,
    suppressed_until    timestamptz NULL,
    updated_at          timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT pk_reachability PRIMARY KEY (target_blind_index, channel),
    CONSTRAINT ck_reachability_channel CHECK (channel IN ('SMS', 'EMAIL', 'VOICE', 'PUSH')),
    CONSTRAINT ck_reachability_state CHECK (reachability_state IN ('UNKNOWN', 'REACHABLE', 'SOFT_BOUNCE', 'HARD_BOUNCE', 'SUPPRESSED')),
    CONSTRAINT ck_reachability_hard_bounce CHECK ((reachability_state = 'HARD_BOUNCE') = (hard_bounce_at IS NOT NULL))
);
COMMENT ON TABLE msg.reachability IS 'CAP-MSG-007：可达性状态回写到 id.identifier.reachability_state；已确认不可达的标识不得继续作为唯一恢复渠道';

CREATE OR REPLACE TRIGGER trg_reachability_touch
    BEFORE UPDATE ON msg.reachability
    FOR EACH ROW EXECUTE FUNCTION core.fn_touch_updated_at();

SELECT core.fn_apply_standard_grants('msg');
SELECT core.fn_apply_append_only_grants('msg', 'delivery_receipt');

SELECT core.fn_migration_apply('170', 'message：供应商与降级链、模板审批、发送记录（分区）、投递回执、可达性');
