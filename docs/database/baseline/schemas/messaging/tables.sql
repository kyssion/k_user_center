-- =============================================================================
-- baseline/schemas/messaging/tables.sql
-- messaging Schema 的最终基表、同 Schema 约束、索引及内联 COMMENT
-- PostgreSQL 16+；应用技术栈：.NET 10 + SqlSugar
-- =============================================================================

CREATE TABLE messaging.provider (
    id uuid        NOT NULL DEFAULT gen_random_uuid(),
    provider_code text        NOT NULL,
    channel_code text        NOT NULL,
    provider_state text        NOT NULL DEFAULT 'DRAFT',
    endpoint_uri text        NOT NULL,
    credential_key_ref text        NOT NULL,
    region_code text        NOT NULL,
    supports_idempotency boolean     NOT NULL DEFAULT false,
    rate_limit_per_second integer     NOT NULL,
    owner_ref text        NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    row_version bigint      NOT NULL DEFAULT 1,
    CONSTRAINT pk_messaging_provider PRIMARY KEY (id),
    CONSTRAINT uq_messaging_provider_code UNIQUE (provider_code),
    CONSTRAINT ck_messaging_provider_channel CHECK (channel_code IN ('SMS', 'EMAIL', 'VOICE', 'PUSH', 'IN_APP')),
    CONSTRAINT ck_messaging_provider_state CHECK (provider_state IN ('DRAFT', 'ACTIVE', 'DEGRADED', 'SUSPENDED', 'RETIRED')),
    CONSTRAINT ck_messaging_provider_rate CHECK (rate_limit_per_second > 0)
);

COMMENT ON TABLE messaging.provider IS 'CAP-MSG-001/003：消息供应商、通道、凭证引用、区域、幂等和限流能力。';

CREATE TABLE messaging.route_policy (
    id uuid        NOT NULL DEFAULT gen_random_uuid(),
    route_code text        NOT NULL,
    route_version integer     NOT NULL,
    channel_code text        NOT NULL,
    purpose_code text        NOT NULL,
    region_code text        NOT NULL,
    provider_ids uuid[]      NOT NULL,
    fallback_channels text[]      NOT NULL DEFAULT '{}',
    max_attempts integer     NOT NULL,
    fail_closed boolean     NOT NULL DEFAULT true,
    is_active boolean     NOT NULL DEFAULT false,
    effective_at timestamptz NOT NULL,
    CONSTRAINT pk_route_policy PRIMARY KEY (id),
    CONSTRAINT uq_route_policy_version UNIQUE (route_code, route_version),
    CONSTRAINT ck_route_policy_channel CHECK (channel_code IN ('SMS', 'EMAIL', 'VOICE', 'PUSH', 'IN_APP')),
    CONSTRAINT ck_route_policy_providers CHECK (cardinality(provider_ids) > 0),
    CONSTRAINT ck_route_policy_attempt CHECK (max_attempts BETWEEN 1 AND 10)
);

COMMENT ON TABLE messaging.route_policy IS 'CAP-MSG-003：按用途/地区的多供应商路由、已批准备用认证通道和失败关闭策略。';

CREATE TABLE messaging.message_template (
    id uuid        NOT NULL DEFAULT gen_random_uuid(),
    template_code text        NOT NULL,
    template_version integer     NOT NULL,
    channel_code text        NOT NULL,
    locale text        NOT NULL,
    purpose_code text        NOT NULL,
    subject_template text        NULL,
    body_template text        NOT NULL,
    variable_schema jsonb       NOT NULL,
    content_hash bytea       NOT NULL,
    release_id uuid        NOT NULL,
    is_active boolean     NOT NULL DEFAULT false,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT pk_message_template PRIMARY KEY (id),
    CONSTRAINT uq_message_template_version UNIQUE (template_code, template_version, channel_code, locale),
    CONSTRAINT ck_message_template_channel CHECK (channel_code IN ('SMS', 'EMAIL', 'VOICE', 'PUSH', 'IN_APP')),
    CONSTRAINT ck_message_template_hash CHECK (octet_length(content_hash) = 32)
);

COMMENT ON TABLE messaging.message_template IS 'CAP-MSG-002：版本化、多语言、变量 Schema 校验且经控制面发布的消息模板。';

CREATE TABLE messaging.message_send (
    id uuid        NOT NULL DEFAULT gen_random_uuid(),
    public_id text        NOT NULL,
    message_purpose text        NOT NULL,
    channel_code text        NOT NULL,
    template_id uuid        NOT NULL,
    route_policy_id uuid        NOT NULL,
    target_identifier_id uuid        NULL,
    target_address_ciphertext bytea   NULL,
    target_blind_index bytea       NOT NULL,
    user_id uuid        NULL,
    tenant_id uuid        NOT NULL DEFAULT '00000000-0000-0000-0000-000000000000',
    client_id uuid        NULL,
    challenge_id uuid        NULL,
    idempotency_key text        NOT NULL,
    variable_hash bytea       NOT NULL,
    send_state text        NOT NULL DEFAULT 'PENDING',
    provider_id uuid        NULL,
    provider_message_ref_hash bytea   NULL,
    attempt_count integer     NOT NULL DEFAULT 0,
    next_attempt_at timestamptz NULL,
    sent_at timestamptz NULL,
    delivered_at timestamptz NULL,
    failed_at timestamptz NULL,
    failure_code text        NULL,
    expires_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    row_version bigint      NOT NULL DEFAULT 1,
    CONSTRAINT pk_message_send PRIMARY KEY (id),
    CONSTRAINT uq_message_send_public_id UNIQUE (public_id),
    CONSTRAINT uq_message_send_idempotency UNIQUE (message_purpose, idempotency_key),
    CONSTRAINT fk_message_send_template FOREIGN KEY (template_id) REFERENCES messaging.message_template(id),
    CONSTRAINT fk_message_send_route FOREIGN KEY (route_policy_id) REFERENCES messaging.route_policy(id),
    CONSTRAINT fk_message_send_provider FOREIGN KEY (provider_id) REFERENCES messaging.provider(id),
    CONSTRAINT ck_message_send_channel CHECK (channel_code IN ('SMS', 'EMAIL', 'VOICE', 'PUSH', 'IN_APP')),
    CONSTRAINT ck_message_send_target CHECK (target_identifier_id IS NOT NULL OR target_address_ciphertext IS NOT NULL),
    CONSTRAINT ck_message_send_hash CHECK (octet_length(target_blind_index) = 32 AND octet_length(variable_hash) = 32),
    CONSTRAINT ck_message_send_state CHECK (send_state IN ('PENDING', 'SENDING', 'SENT', 'DELIVERED', 'FAILED', 'EXPIRED', 'CANCELLED')),
    CONSTRAINT ck_message_send_attempt CHECK (attempt_count >= 0),
    CONSTRAINT ck_message_send_delivery CHECK (send_state <> 'DELIVERED' OR delivered_at IS NOT NULL),
    CONSTRAINT ck_message_send_failure CHECK (send_state <> 'FAILED' OR (failed_at IS NOT NULL AND failure_code IS NOT NULL)),
    CONSTRAINT ck_message_send_expiry CHECK (expires_at > created_at)
);

COMMENT ON TABLE messaging.message_send IS 'CAP-MSG-004/005：不含验证码/正文秘密的幂等消息发送、加密目标、盲索引、供应商尝试和结果。';

CREATE TABLE messaging.delivery_receipt (
    id uuid        NOT NULL DEFAULT gen_random_uuid(),
    message_send_id uuid        NOT NULL,
    provider_id uuid        NOT NULL,
    provider_event_id_hash bytea      NOT NULL,
    receipt_kind text        NOT NULL,
    provider_occurred_at timestamptz NULL,
    payload_hash bytea       NOT NULL,
    received_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT pk_delivery_receipt PRIMARY KEY (id),
    CONSTRAINT uq_delivery_receipt UNIQUE (provider_id, provider_event_id_hash),
    CONSTRAINT fk_delivery_receipt_message FOREIGN KEY (message_send_id) REFERENCES messaging.message_send(id),
    CONSTRAINT fk_delivery_receipt_provider FOREIGN KEY (provider_id) REFERENCES messaging.provider(id),
    CONSTRAINT ck_delivery_receipt_kind CHECK (receipt_kind IN ('ACCEPTED', 'SENT', 'DELIVERED', 'BOUNCED', 'REJECTED', 'COMPLAINT', 'UNSUBSCRIBED')),
    CONSTRAINT ck_delivery_receipt_hash CHECK (octet_length(provider_event_id_hash) = 32 AND octet_length(payload_hash) = 32)
);

COMMENT ON TABLE messaging.delivery_receipt IS '消息供应商回执的幂等摘要、类型和源端时间；原始回执按数据目录另行受控保留。';

CREATE TABLE messaging.reachability (
    identifier_id uuid        NOT NULL,
    channel_code text        NOT NULL,
    reachability_state text        NOT NULL DEFAULT 'UNKNOWN',
    hard_failure_count integer     NOT NULL DEFAULT 0,
    soft_failure_count integer     NOT NULL DEFAULT 0,
    last_success_at timestamptz NULL,
    last_failure_at timestamptz NULL,
    suppressed_until timestamptz NULL,
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    row_version bigint      NOT NULL DEFAULT 1,
    CONSTRAINT pk_reachability PRIMARY KEY (identifier_id, channel_code),
    CONSTRAINT ck_reachability_channel CHECK (channel_code IN ('SMS', 'EMAIL', 'VOICE', 'PUSH')),
    CONSTRAINT ck_reachability_state CHECK (reachability_state IN ('UNKNOWN', 'REACHABLE', 'SOFT_BOUNCE', 'HARD_BOUNCE', 'COMPLAINT', 'SUPPRESSED')),
    CONSTRAINT ck_reachability_count CHECK (hard_failure_count >= 0 AND soft_failure_count >= 0)
);

COMMENT ON TABLE messaging.reachability IS 'CAP-MSG-006：标识通道可达性、退信、投诉和抑制水位；不改变 Identifier 所有权状态。';

CREATE TABLE messaging.content_compliance_rule (
    id uuid        NOT NULL DEFAULT gen_random_uuid(),
    rule_code text        NOT NULL,
    rule_version integer     NOT NULL,
    channel_code text        NOT NULL,
    region_code text        NOT NULL,
    message_purpose text        NOT NULL,
    prohibited_patterns_hash bytea    NOT NULL,
    required_sender_identity text     NULL,
    required_unsubscribe_marker boolean NOT NULL DEFAULT false,
    regulatory_filing_ref text        NULL,
    release_id uuid        NOT NULL,
    is_active boolean     NOT NULL DEFAULT false,
    effective_at timestamptz NOT NULL,
    retired_at timestamptz NULL,
    CONSTRAINT pk_content_compliance_rule PRIMARY KEY (id),
    CONSTRAINT uq_content_compliance_rule_version UNIQUE (rule_code, rule_version),
    CONSTRAINT ck_content_compliance_rule_channel CHECK (channel_code IN ('SMS', 'EMAIL', 'VOICE', 'PUSH', 'IN_APP')),
    CONSTRAINT ck_content_compliance_rule_hash CHECK (octet_length(prohibited_patterns_hash) = 32),
    CONSTRAINT ck_content_compliance_rule_window CHECK (retired_at IS NULL OR retired_at > effective_at)
);

COMMENT ON TABLE messaging.content_compliance_rule IS 'CAP-MSG-006/011：按通道、地区、用途执行敏感词、发送方、退订标识和监管报备的版本化规则。';

CREATE TABLE messaging.provider_metric (
    id uuid        NOT NULL DEFAULT gen_random_uuid(),
    provider_id uuid        NOT NULL,
    channel_code text        NOT NULL,
    region_code text        NOT NULL,
    template_code text        NULL,
    metric_window_start timestamptz NOT NULL,
    metric_window_end timestamptz NOT NULL,
    submitted_count bigint      NOT NULL DEFAULT 0,
    delivered_count bigint      NOT NULL DEFAULT 0,
    failed_count bigint      NOT NULL DEFAULT 0,
    latency_p95_ms numeric(12,3) NULL,
    unit_cost numeric(18,6) NULL,
    currency_code text        NULL,
    calculated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT pk_provider_metric PRIMARY KEY (id),
    CONSTRAINT uq_provider_metric UNIQUE NULLS NOT DISTINCT (provider_id, region_code, template_code, metric_window_start, metric_window_end),
    CONSTRAINT fk_provider_metric_provider FOREIGN KEY (provider_id) REFERENCES messaging.provider(id),
    CONSTRAINT ck_provider_metric_channel CHECK (channel_code IN ('SMS', 'EMAIL', 'VOICE', 'PUSH', 'IN_APP')),
    CONSTRAINT ck_provider_metric_window CHECK (metric_window_end > metric_window_start),
    CONSTRAINT ck_provider_metric_count CHECK (submitted_count >= 0 AND delivered_count >= 0 AND failed_count >= 0 AND delivered_count + failed_count <= submitted_count),
    CONSTRAINT ck_provider_metric_latency CHECK (latency_p95_ms IS NULL OR latency_p95_ms >= 0),
    CONSTRAINT ck_provider_metric_cost CHECK ((unit_cost IS NULL) = (currency_code IS NULL) AND (unit_cost IS NULL OR unit_cost >= 0))
);

COMMENT ON TABLE messaging.provider_metric IS 'CAP-MSG-008 / CAP-OBS-016：供应商、地区、模板维度的送达率、P95 时延、单价和成本归属聚合。';

CREATE INDEX ix_message_send_retry ON messaging.message_send(next_attempt_at) WHERE send_state IN ('PENDING', 'FAILED');

CREATE INDEX ix_message_target ON messaging.message_send(target_blind_index, created_at DESC);

CREATE INDEX ix_provider_metric_window ON messaging.provider_metric(provider_id, metric_window_start DESC);

CREATE INDEX ix_fk_message_send_template_id ON messaging.message_send (template_id);

CREATE INDEX ix_fk_message_send_route_policy_id ON messaging.message_send (route_policy_id);

CREATE INDEX ix_fk_message_send_provider_id ON messaging.message_send (provider_id);

CREATE INDEX ix_fk_delivery_receipt_message_send_id ON messaging.delivery_receipt (message_send_id);

COMMENT ON COLUMN messaging.provider.id IS '内部 UUID 主键；仅用于数据库关系，不作为跨域公开标识。';
COMMENT ON COLUMN messaging.provider.provider_code IS '稳定机器可读代码；展示文本由资源或目录解析。';
COMMENT ON COLUMN messaging.provider.channel_code IS '稳定机器可读代码；展示文本由资源或目录解析。';
COMMENT ON COLUMN messaging.provider.provider_state IS '显式状态当前值；合法取值见 CHECK，完整状态转换由 .NET 领域策略执行。';
COMMENT ON COLUMN messaging.provider.endpoint_uri IS '受控 URI；写入前必须执行协议、主机、重定向与 SSRF 安全校验。';
COMMENT ON COLUMN messaging.provider.credential_key_ref IS '外部 KMS/HSM 或受控密钥资产引用；不得保存私钥或 Secret 明文。';
COMMENT ON COLUMN messaging.provider.region_code IS '稳定机器可读代码；展示文本由资源或目录解析。';
COMMENT ON COLUMN messaging.provider.supports_idempotency IS 'messaging.provider.supports_idempotency 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN messaging.provider.rate_limit_per_second IS 'messaging.provider.rate_limit_per_second 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN messaging.provider.owner_ref IS '不透明对象引用；不得从格式推断手机号、邮箱或其他业务事实。';
COMMENT ON COLUMN messaging.provider.created_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN messaging.provider.updated_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN messaging.provider.row_version IS '乐观并发版本；更新必须使用原值 compare-and-set，成功后由数据库单调递增。';
COMMENT ON COLUMN messaging.route_policy.id IS '内部 UUID 主键；仅用于数据库关系，不作为跨域公开标识。';
COMMENT ON COLUMN messaging.route_policy.route_code IS '稳定机器可读代码；展示文本由资源或目录解析。';
COMMENT ON COLUMN messaging.route_policy.route_version IS '对象、策略或源数据的显式版本；不得以不可信客户端时间戳替代。';
COMMENT ON COLUMN messaging.route_policy.channel_code IS '稳定机器可读代码；展示文本由资源或目录解析。';
COMMENT ON COLUMN messaging.route_policy.purpose_code IS '稳定机器可读代码；展示文本由资源或目录解析。';
COMMENT ON COLUMN messaging.route_policy.region_code IS '稳定机器可读代码；展示文本由资源或目录解析。';
COMMENT ON COLUMN messaging.route_policy.provider_ids IS '代码或引用集合；写入前去重、校验 allowlist，并满足表约束。';
COMMENT ON COLUMN messaging.route_policy.fallback_channels IS '代码或引用集合；写入前去重、校验 allowlist，并满足表约束。';
COMMENT ON COLUMN messaging.route_policy.max_attempts IS '非负计数器；并发更新使用原子 SQL 或乐观并发控制。';
COMMENT ON COLUMN messaging.route_policy.fail_closed IS 'messaging.route_policy.fail_closed 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN messaging.route_policy.is_active IS '显式布尔开关；启用前置条件与失效行为由约束和版本化策略控制。';
COMMENT ON COLUMN messaging.route_policy.effective_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN messaging.message_template.id IS '内部 UUID 主键；仅用于数据库关系，不作为跨域公开标识。';
COMMENT ON COLUMN messaging.message_template.template_code IS '稳定机器可读代码；展示文本由资源或目录解析。';
COMMENT ON COLUMN messaging.message_template.template_version IS '对象、策略或源数据的显式版本；不得以不可信客户端时间戳替代。';
COMMENT ON COLUMN messaging.message_template.channel_code IS '稳定机器可读代码；展示文本由资源或目录解析。';
COMMENT ON COLUMN messaging.message_template.locale IS 'messaging.message_template.locale 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN messaging.message_template.purpose_code IS '稳定机器可读代码；展示文本由资源或目录解析。';
COMMENT ON COLUMN messaging.message_template.subject_template IS 'messaging.message_template.subject_template 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN messaging.message_template.body_template IS 'messaging.message_template.body_template 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN messaging.message_template.variable_schema IS '版本化结构化扩展数据；必须由 .NET 按对应 JSON Schema 校验，不得替代核心状态或外键。';
COMMENT ON COLUMN messaging.message_template.content_hash IS '不可逆摘要；用于等值匹配、幂等、完整性或最小化证据，不保存原始敏感值。';
COMMENT ON COLUMN messaging.message_template.release_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN messaging.message_template.is_active IS '显式布尔开关；启用前置条件与失效行为由约束和版本化策略控制。';
COMMENT ON COLUMN messaging.message_template.created_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN messaging.message_send.id IS '内部 UUID 主键；仅用于数据库关系，不作为跨域公开标识。';
COMMENT ON COLUMN messaging.message_send.public_id IS '不可复用的公开稳定标识；插入时登记到 core.public_id_ledger。';
COMMENT ON COLUMN messaging.message_send.message_purpose IS 'messaging.message_send.message_purpose 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN messaging.message_send.channel_code IS '稳定机器可读代码；展示文本由资源或目录解析。';
COMMENT ON COLUMN messaging.message_send.template_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN messaging.message_send.route_policy_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN messaging.message_send.target_identifier_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN messaging.message_send.target_address_ciphertext IS '随机化加密密文；解密密钥由独立 KMS/HSM 引用管理。';
COMMENT ON COLUMN messaging.message_send.target_blind_index IS '带版本的密钥化盲索引；只用于受控等值检索。';
COMMENT ON COLUMN messaging.message_send.user_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN messaging.message_send.tenant_id IS '租户隔离键；全零 UUID 表示平台范围，应用查询必须显式携带可信租户上下文。';
COMMENT ON COLUMN messaging.message_send.client_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN messaging.message_send.challenge_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN messaging.message_send.idempotency_key IS 'messaging.message_send.idempotency_key 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN messaging.message_send.variable_hash IS '不可逆摘要；用于等值匹配、幂等、完整性或最小化证据，不保存原始敏感值。';
COMMENT ON COLUMN messaging.message_send.send_state IS '显式状态当前值；合法取值见 CHECK，完整状态转换由 .NET 领域策略执行。';
COMMENT ON COLUMN messaging.message_send.provider_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN messaging.message_send.provider_message_ref_hash IS '不可逆摘要；用于等值匹配、幂等、完整性或最小化证据，不保存原始敏感值。';
COMMENT ON COLUMN messaging.message_send.attempt_count IS '非负计数器；并发更新使用原子 SQL 或乐观并发控制。';
COMMENT ON COLUMN messaging.message_send.next_attempt_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN messaging.message_send.sent_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN messaging.message_send.delivered_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN messaging.message_send.failed_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN messaging.message_send.failure_code IS '稳定机器可读代码；展示文本由资源或目录解析。';
COMMENT ON COLUMN messaging.message_send.expires_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN messaging.message_send.created_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN messaging.message_send.updated_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN messaging.message_send.row_version IS '乐观并发版本；更新必须使用原值 compare-and-set，成功后由数据库单调递增。';
COMMENT ON COLUMN messaging.delivery_receipt.id IS '内部 UUID 主键；仅用于数据库关系，不作为跨域公开标识。';
COMMENT ON COLUMN messaging.delivery_receipt.message_send_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN messaging.delivery_receipt.provider_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN messaging.delivery_receipt.provider_event_id_hash IS '不可逆摘要；用于等值匹配、幂等、完整性或最小化证据，不保存原始敏感值。';
COMMENT ON COLUMN messaging.delivery_receipt.receipt_kind IS '对象类别判别字段；允许值由 CHECK 或对应注册表限定。';
COMMENT ON COLUMN messaging.delivery_receipt.provider_occurred_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN messaging.delivery_receipt.payload_hash IS '不可逆摘要；用于等值匹配、幂等、完整性或最小化证据，不保存原始敏感值。';
COMMENT ON COLUMN messaging.delivery_receipt.received_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN messaging.reachability.identifier_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN messaging.reachability.channel_code IS '稳定机器可读代码；展示文本由资源或目录解析。';
COMMENT ON COLUMN messaging.reachability.reachability_state IS '显式状态当前值；合法取值见 CHECK，完整状态转换由 .NET 领域策略执行。';
COMMENT ON COLUMN messaging.reachability.hard_failure_count IS '非负计数器；并发更新使用原子 SQL 或乐观并发控制。';
COMMENT ON COLUMN messaging.reachability.soft_failure_count IS '非负计数器；并发更新使用原子 SQL 或乐观并发控制。';
COMMENT ON COLUMN messaging.reachability.last_success_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN messaging.reachability.last_failure_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN messaging.reachability.suppressed_until IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN messaging.reachability.updated_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN messaging.reachability.row_version IS '乐观并发版本；更新必须使用原值 compare-and-set，成功后由数据库单调递增。';
COMMENT ON COLUMN messaging.content_compliance_rule.id IS '内部 UUID 主键；仅用于数据库关系，不作为跨域公开标识。';
COMMENT ON COLUMN messaging.content_compliance_rule.rule_code IS '稳定机器可读代码；展示文本由资源或目录解析。';
COMMENT ON COLUMN messaging.content_compliance_rule.rule_version IS '对象、策略或源数据的显式版本；不得以不可信客户端时间戳替代。';
COMMENT ON COLUMN messaging.content_compliance_rule.channel_code IS '稳定机器可读代码；展示文本由资源或目录解析。';
COMMENT ON COLUMN messaging.content_compliance_rule.region_code IS '稳定机器可读代码；展示文本由资源或目录解析。';
COMMENT ON COLUMN messaging.content_compliance_rule.message_purpose IS 'messaging.content_compliance_rule.message_purpose 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN messaging.content_compliance_rule.prohibited_patterns_hash IS '不可逆摘要；用于等值匹配、幂等、完整性或最小化证据，不保存原始敏感值。';
COMMENT ON COLUMN messaging.content_compliance_rule.required_sender_identity IS 'messaging.content_compliance_rule.required_sender_identity 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN messaging.content_compliance_rule.required_unsubscribe_marker IS 'messaging.content_compliance_rule.required_unsubscribe_marker 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN messaging.content_compliance_rule.regulatory_filing_ref IS '不透明对象引用；不得从格式推断手机号、邮箱或其他业务事实。';
COMMENT ON COLUMN messaging.content_compliance_rule.release_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN messaging.content_compliance_rule.is_active IS '显式布尔开关；启用前置条件与失效行为由约束和版本化策略控制。';
COMMENT ON COLUMN messaging.content_compliance_rule.effective_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN messaging.content_compliance_rule.retired_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN messaging.provider_metric.id IS '内部 UUID 主键；仅用于数据库关系，不作为跨域公开标识。';
COMMENT ON COLUMN messaging.provider_metric.provider_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN messaging.provider_metric.channel_code IS '稳定机器可读代码；展示文本由资源或目录解析。';
COMMENT ON COLUMN messaging.provider_metric.region_code IS '稳定机器可读代码；展示文本由资源或目录解析。';
COMMENT ON COLUMN messaging.provider_metric.template_code IS '稳定机器可读代码；展示文本由资源或目录解析。';
COMMENT ON COLUMN messaging.provider_metric.metric_window_start IS 'messaging.provider_metric.metric_window_start 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN messaging.provider_metric.metric_window_end IS 'messaging.provider_metric.metric_window_end 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN messaging.provider_metric.submitted_count IS '非负计数器；并发更新使用原子 SQL 或乐观并发控制。';
COMMENT ON COLUMN messaging.provider_metric.delivered_count IS '非负计数器；并发更新使用原子 SQL 或乐观并发控制。';
COMMENT ON COLUMN messaging.provider_metric.failed_count IS '非负计数器；并发更新使用原子 SQL 或乐观并发控制。';
COMMENT ON COLUMN messaging.provider_metric.latency_p95_ms IS 'messaging.provider_metric.latency_p95_ms 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN messaging.provider_metric.unit_cost IS 'messaging.provider_metric.unit_cost 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN messaging.provider_metric.currency_code IS '稳定机器可读代码；展示文本由资源或目录解析。';
COMMENT ON COLUMN messaging.provider_metric.calculated_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';

COMMENT ON CONSTRAINT pk_messaging_provider ON messaging.provider IS '主键约束：唯一标识 messaging.provider 记录。';
COMMENT ON CONSTRAINT uq_messaging_provider_code ON messaging.provider IS '唯一约束：保证 provider_code 在 messaging.provider 范围内不重复。';
COMMENT ON CONSTRAINT ck_messaging_provider_channel ON messaging.provider IS '检查约束：限制 messaging.provider 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_messaging_provider_state ON messaging.provider IS '检查约束：限制 messaging.provider 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_messaging_provider_rate ON messaging.provider IS '检查约束：限制 messaging.provider 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT pk_route_policy ON messaging.route_policy IS '主键约束：唯一标识 messaging.route_policy 记录。';
COMMENT ON CONSTRAINT uq_route_policy_version ON messaging.route_policy IS '唯一约束：保证 route_code、route_version 在 messaging.route_policy 范围内不重复。';
COMMENT ON CONSTRAINT ck_route_policy_channel ON messaging.route_policy IS '检查约束：限制 messaging.route_policy 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_route_policy_providers ON messaging.route_policy IS '检查约束：限制 messaging.route_policy 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_route_policy_attempt ON messaging.route_policy IS '检查约束：限制 messaging.route_policy 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT pk_message_template ON messaging.message_template IS '主键约束：唯一标识 messaging.message_template 记录。';
COMMENT ON CONSTRAINT uq_message_template_version ON messaging.message_template IS '唯一约束：保证 template_code、template_version、channel_code、locale 在 messaging.message_template 范围内不重复。';
COMMENT ON CONSTRAINT ck_message_template_channel ON messaging.message_template IS '检查约束：限制 messaging.message_template 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_message_template_hash ON messaging.message_template IS '检查约束：限制 messaging.message_template 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT pk_message_send ON messaging.message_send IS '主键约束：唯一标识 messaging.message_send 记录。';
COMMENT ON CONSTRAINT uq_message_send_public_id ON messaging.message_send IS '唯一约束：保证 public_id 在 messaging.message_send 范围内不重复。';
COMMENT ON CONSTRAINT uq_message_send_idempotency ON messaging.message_send IS '唯一约束：保证 message_purpose、idempotency_key 在 messaging.message_send 范围内不重复。';
COMMENT ON CONSTRAINT fk_message_send_template ON messaging.message_send IS '外键约束：messaging.message_send 的 template_id 必须引用 messaging.message_template；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT fk_message_send_route ON messaging.message_send IS '外键约束：messaging.message_send 的 route_policy_id 必须引用 messaging.route_policy；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT fk_message_send_provider ON messaging.message_send IS '外键约束：messaging.message_send 的 provider_id 必须引用 messaging.provider；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT ck_message_send_channel ON messaging.message_send IS '检查约束：限制 messaging.message_send 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_message_send_target ON messaging.message_send IS '检查约束：限制 messaging.message_send 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_message_send_hash ON messaging.message_send IS '检查约束：限制 messaging.message_send 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_message_send_state ON messaging.message_send IS '检查约束：限制 messaging.message_send 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_message_send_attempt ON messaging.message_send IS '检查约束：限制 messaging.message_send 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_message_send_delivery ON messaging.message_send IS '检查约束：限制 messaging.message_send 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_message_send_failure ON messaging.message_send IS '检查约束：限制 messaging.message_send 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_message_send_expiry ON messaging.message_send IS '检查约束：限制 messaging.message_send 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT pk_delivery_receipt ON messaging.delivery_receipt IS '主键约束：唯一标识 messaging.delivery_receipt 记录。';
COMMENT ON CONSTRAINT uq_delivery_receipt ON messaging.delivery_receipt IS '唯一约束：保证 provider_id、provider_event_id_hash 在 messaging.delivery_receipt 范围内不重复。';
COMMENT ON CONSTRAINT fk_delivery_receipt_message ON messaging.delivery_receipt IS '外键约束：messaging.delivery_receipt 的 message_send_id 必须引用 messaging.message_send；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT fk_delivery_receipt_provider ON messaging.delivery_receipt IS '外键约束：messaging.delivery_receipt 的 provider_id 必须引用 messaging.provider；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT ck_delivery_receipt_kind ON messaging.delivery_receipt IS '检查约束：限制 messaging.delivery_receipt 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_delivery_receipt_hash ON messaging.delivery_receipt IS '检查约束：限制 messaging.delivery_receipt 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT pk_reachability ON messaging.reachability IS '主键约束：唯一标识 messaging.reachability 记录。';
COMMENT ON CONSTRAINT ck_reachability_channel ON messaging.reachability IS '检查约束：限制 messaging.reachability 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_reachability_state ON messaging.reachability IS '检查约束：限制 messaging.reachability 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_reachability_count ON messaging.reachability IS '检查约束：限制 messaging.reachability 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT pk_content_compliance_rule ON messaging.content_compliance_rule IS '主键约束：唯一标识 messaging.content_compliance_rule 记录。';
COMMENT ON CONSTRAINT uq_content_compliance_rule_version ON messaging.content_compliance_rule IS '唯一约束：保证 rule_code、rule_version 在 messaging.content_compliance_rule 范围内不重复。';
COMMENT ON CONSTRAINT ck_content_compliance_rule_channel ON messaging.content_compliance_rule IS '检查约束：限制 messaging.content_compliance_rule 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_content_compliance_rule_hash ON messaging.content_compliance_rule IS '检查约束：限制 messaging.content_compliance_rule 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_content_compliance_rule_window ON messaging.content_compliance_rule IS '检查约束：限制 messaging.content_compliance_rule 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT pk_provider_metric ON messaging.provider_metric IS '主键约束：唯一标识 messaging.provider_metric 记录。';
COMMENT ON CONSTRAINT uq_provider_metric ON messaging.provider_metric IS '唯一约束：保证 provider_id、region_code、template_code、metric_window_start、metric_window_end 在 messaging.provider_metric 范围内不重复。';
COMMENT ON CONSTRAINT fk_provider_metric_provider ON messaging.provider_metric IS '外键约束：messaging.provider_metric 的 provider_id 必须引用 messaging.provider；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT ck_provider_metric_channel ON messaging.provider_metric IS '检查约束：限制 messaging.provider_metric 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_provider_metric_window ON messaging.provider_metric IS '检查约束：限制 messaging.provider_metric 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_provider_metric_count ON messaging.provider_metric IS '检查约束：限制 messaging.provider_metric 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_provider_metric_latency ON messaging.provider_metric IS '检查约束：限制 messaging.provider_metric 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_provider_metric_cost ON messaging.provider_metric IS '检查约束：限制 messaging.provider_metric 的字段取值或组合满足结构与安全底线。';

COMMENT ON INDEX messaging.ix_message_send_retry IS '查询索引：优化 messaging.message_send 按 next_attempt_at 的访问，仅覆盖 WHERE 条件命中的记录。';
COMMENT ON INDEX messaging.ix_message_target IS '查询索引：优化 messaging.message_send 按 target_blind_index、created_at 的访问。';
COMMENT ON INDEX messaging.ix_provider_metric_window IS '查询索引：优化 messaging.provider_metric 按 provider_id、metric_window_start 的访问。';
COMMENT ON INDEX messaging.pk_messaging_provider IS '约束 pk_messaging_provider 的支撑唯一索引。';
COMMENT ON INDEX messaging.uq_messaging_provider_code IS '约束 uq_messaging_provider_code 的支撑唯一索引。';
COMMENT ON INDEX messaging.pk_route_policy IS '约束 pk_route_policy 的支撑唯一索引。';
COMMENT ON INDEX messaging.uq_route_policy_version IS '约束 uq_route_policy_version 的支撑唯一索引。';
COMMENT ON INDEX messaging.pk_message_template IS '约束 pk_message_template 的支撑唯一索引。';
COMMENT ON INDEX messaging.uq_message_template_version IS '约束 uq_message_template_version 的支撑唯一索引。';
COMMENT ON INDEX messaging.pk_message_send IS '约束 pk_message_send 的支撑唯一索引。';
COMMENT ON INDEX messaging.uq_message_send_public_id IS '约束 uq_message_send_public_id 的支撑唯一索引。';
COMMENT ON INDEX messaging.uq_message_send_idempotency IS '约束 uq_message_send_idempotency 的支撑唯一索引。';
COMMENT ON INDEX messaging.pk_delivery_receipt IS '约束 pk_delivery_receipt 的支撑唯一索引。';
COMMENT ON INDEX messaging.uq_delivery_receipt IS '约束 uq_delivery_receipt 的支撑唯一索引。';
COMMENT ON INDEX messaging.pk_reachability IS '约束 pk_reachability 的支撑唯一索引。';
COMMENT ON INDEX messaging.pk_content_compliance_rule IS '约束 pk_content_compliance_rule 的支撑唯一索引。';
COMMENT ON INDEX messaging.uq_content_compliance_rule_version IS '约束 uq_content_compliance_rule_version 的支撑唯一索引。';
COMMENT ON INDEX messaging.pk_provider_metric IS '约束 pk_provider_metric 的支撑唯一索引。';
COMMENT ON INDEX messaging.uq_provider_metric IS '约束 uq_provider_metric 的支撑唯一索引。';
COMMENT ON INDEX messaging.ix_fk_message_send_template_id IS '查询索引：优化 messaging.message_send 按 template_id 的访问。';
COMMENT ON INDEX messaging.ix_fk_message_send_route_policy_id IS '查询索引：优化 messaging.message_send 按 route_policy_id 的访问。';
COMMENT ON INDEX messaging.ix_fk_message_send_provider_id IS '查询索引：优化 messaging.message_send 按 provider_id 的访问。';
COMMENT ON INDEX messaging.ix_fk_delivery_receipt_message_send_id IS '查询索引：优化 messaging.delivery_receipt 按 message_send_id 的访问。';

