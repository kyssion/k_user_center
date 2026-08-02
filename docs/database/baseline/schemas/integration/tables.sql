-- =============================================================================
-- baseline/schemas/integration/tables.sql
-- integration Schema 的最终基表、同 Schema 约束、索引及内联 COMMENT
-- PostgreSQL 16+；应用技术栈：.NET 10 + SqlSugar
-- =============================================================================

CREATE TABLE integration.event_schema (
    event_type text        NOT NULL,
    schema_version integer     NOT NULL,
    compatibility_mode text        NOT NULL DEFAULT 'BACKWARD',
    json_schema jsonb       NOT NULL,
    schema_hash bytea       NOT NULL,
    maximum_classification text       NOT NULL,
    owner_ref text        NOT NULL,
    release_id uuid        NULL,
    is_active boolean     NOT NULL DEFAULT false,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT pk_event_schema PRIMARY KEY (event_type, schema_version),
    CONSTRAINT ck_event_schema_type CHECK (event_type ~ '^[a-z][a-z0-9_.-]{2,127}$'),
    CONSTRAINT ck_event_schema_compat CHECK (compatibility_mode IN ('BACKWARD', 'FORWARD', 'FULL', 'NONE')),
    CONSTRAINT ck_event_schema_hash CHECK (octet_length(schema_hash) = 32),
    CONSTRAINT ck_event_schema_active CHECK (NOT is_active OR release_id IS NOT NULL)
);

COMMENT ON TABLE integration.event_schema IS 'EVT-G-001/005：事件类型、Schema 版本、兼容模式、分类上限和受控发布记录。';

CREATE TABLE integration.outbox_event (
    id uuid        NOT NULL DEFAULT gen_random_uuid(),
    event_id uuid        NOT NULL DEFAULT gen_random_uuid(),
    event_type text        NOT NULL,
    schema_version integer     NOT NULL,
    aggregate_kind text        NOT NULL,
    aggregate_ref text        NOT NULL,
    aggregate_version bigint      NOT NULL,
    subject_ref_type text        NULL,
    subject_ref text        NULL,
    actor_ref_type text        NULL,
    actor_ref text        NULL,
    tenant_id uuid        NOT NULL DEFAULT '00000000-0000-0000-0000-000000000000',
    business_line_id uuid        NULL,
    payload jsonb       NOT NULL,
    payload_hash bytea       NOT NULL,
    trace_id text        NULL,
    correlation_id text        NOT NULL,
    causation_id uuid        NULL,
    occurred_at timestamptz NOT NULL,
    available_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    publish_state text        NOT NULL DEFAULT 'PENDING',
    attempt_count integer     NOT NULL DEFAULT 0,
    next_attempt_at timestamptz NULL,
    published_at timestamptz NULL,
    broker_partition text        NULL,
    broker_offset text        NULL,
    last_error_code text        NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT pk_outbox_event PRIMARY KEY (id),
    CONSTRAINT uq_outbox_event_id UNIQUE (event_id),
    CONSTRAINT fk_outbox_event_schema FOREIGN KEY (event_type, schema_version) REFERENCES integration.event_schema(event_type, schema_version),
    CONSTRAINT ck_outbox_event_subject CHECK ((subject_ref_type IS NULL) = (subject_ref IS NULL)),
    CONSTRAINT ck_outbox_event_actor CHECK ((actor_ref_type IS NULL) = (actor_ref IS NULL)),
    CONSTRAINT ck_outbox_event_subject_type CHECK (subject_ref_type IS NULL OR subject_ref_type IN ('GLOBAL_USER', 'PAIRWISE_SUBJECT', 'MEMBERSHIP', 'CLIENT', 'MACHINE', 'TOMBSTONE')),
    CONSTRAINT ck_outbox_event_actor_type CHECK (actor_ref_type IS NULL OR actor_ref_type IN ('GLOBAL_USER', 'PAIRWISE_SUBJECT', 'MEMBERSHIP', 'CLIENT', 'MACHINE', 'SYSTEM')),
    CONSTRAINT ck_outbox_event_version CHECK (aggregate_version >= 1),
    CONSTRAINT ck_outbox_event_hash CHECK (octet_length(payload_hash) = 32),
    CONSTRAINT ck_outbox_event_state CHECK (publish_state IN ('PENDING', 'PUBLISHING', 'PUBLISHED', 'FAILED', 'DEAD_LETTER')),
    CONSTRAINT ck_outbox_event_attempt CHECK (attempt_count >= 0),
    CONSTRAINT ck_outbox_event_published CHECK ((publish_state = 'PUBLISHED') = (published_at IS NOT NULL))
);

COMMENT ON TABLE integration.outbox_event IS 'INV-G-010 / EVT-G-001 至 004：与领域状态同事务提交的标准事件信封、版本、顺序、幂等与发布水位。';

CREATE TABLE integration.webhook_subscription (
    id uuid        NOT NULL DEFAULT gen_random_uuid(),
    public_id text        NOT NULL,
    client_id uuid        NOT NULL,
    tenant_id uuid        NOT NULL DEFAULT '00000000-0000-0000-0000-000000000000',
    subscription_state text        NOT NULL DEFAULT 'PENDING_VERIFICATION',
    callback_uri text        NOT NULL,
    resolved_address_hash bytea       NOT NULL,
    tls_certificate_pin bytea       NULL,
    signing_key_ref text        NOT NULL,
    event_types text[]      NOT NULL,
    maximum_classification text       NOT NULL,
    consent_purpose_code text        NULL,
    consent_aggregate_id uuid        NULL,
    consent_epoch bigint      NULL,
    verification_challenge_hash bytea NOT NULL,
    verified_at timestamptz NULL,
    expires_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    row_version bigint      NOT NULL DEFAULT 1,
    CONSTRAINT pk_webhook_subscription PRIMARY KEY (id),
    CONSTRAINT uq_webhook_subscription_public_id UNIQUE (public_id),
    CONSTRAINT uq_webhook_subscription_uri UNIQUE (client_id, callback_uri),
    CONSTRAINT ck_webhook_subscription_state CHECK (subscription_state IN ('PENDING_VERIFICATION', 'ACTIVE', 'SUSPENDED', 'REVOKED', 'EXPIRED')),
    CONSTRAINT ck_webhook_subscription_uri CHECK (callback_uri ~ '^https://'),
    CONSTRAINT ck_webhook_subscription_events CHECK (cardinality(event_types) > 0),
    CONSTRAINT ck_webhook_subscription_hash CHECK (octet_length(resolved_address_hash) = 32 AND octet_length(verification_challenge_hash) = 32),
    CONSTRAINT ck_webhook_subscription_consent CHECK (
    (consent_aggregate_id IS NULL AND consent_epoch IS NULL AND consent_purpose_code IS NULL)
    OR (consent_aggregate_id IS NOT NULL AND consent_epoch IS NOT NULL AND consent_purpose_code IS NOT NULL)
    ),
    CONSTRAINT ck_webhook_subscription_active CHECK (subscription_state <> 'ACTIVE' OR verified_at IS NOT NULL),
    CONSTRAINT ck_webhook_subscription_expiry CHECK (expires_at > created_at)
);

COMMENT ON TABLE integration.webhook_subscription IS 'CAP-EVENT-003/004：HTTPS、SSRF 校验、签名密钥、事件范围、分类上限和可选 Consent 水位的 Webhook 订阅。';

CREATE TABLE integration.webhook_delivery (
    id uuid        NOT NULL DEFAULT gen_random_uuid(),
    public_id text        NOT NULL,
    subscription_id uuid        NOT NULL,
    event_id uuid        NOT NULL,
    delivery_state text        NOT NULL DEFAULT 'PENDING',
    delivery_attempt integer     NOT NULL DEFAULT 0,
    contains_personal_subject boolean NOT NULL DEFAULT false,
    recipient_subject_ref_type text   NULL,
    recipient_subject_ref text        NULL,
    recipient_actor_ref_type text     NULL,
    recipient_actor_ref text        NULL,
    payload_hash bytea       NOT NULL,
    signature_key_ref text        NOT NULL,
    signature_hash bytea       NOT NULL,
    response_status integer     NULL,
    response_body_hash bytea       NULL,
    next_attempt_at timestamptz NULL,
    first_attempt_at timestamptz NULL,
    delivered_at timestamptz NULL,
    dead_lettered_at timestamptz NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT pk_webhook_delivery PRIMARY KEY (id),
    CONSTRAINT uq_webhook_delivery_public_id UNIQUE (public_id),
    CONSTRAINT uq_webhook_delivery_attempt UNIQUE (subscription_id, event_id, delivery_attempt),
    CONSTRAINT fk_webhook_delivery_subscription FOREIGN KEY (subscription_id) REFERENCES integration.webhook_subscription(id),
    CONSTRAINT fk_webhook_delivery_event FOREIGN KEY (event_id) REFERENCES integration.outbox_event(event_id),
    CONSTRAINT ck_webhook_delivery_state CHECK (delivery_state IN ('PENDING', 'SENDING', 'DELIVERED', 'FAILED', 'DEAD_LETTER', 'CANCELLED')),
    CONSTRAINT ck_webhook_delivery_attempt CHECK (delivery_attempt >= 0),
    CONSTRAINT ck_webhook_delivery_subject CHECK (
    (NOT contains_personal_subject AND recipient_subject_ref_type IS NULL AND recipient_subject_ref IS NULL)
    OR (contains_personal_subject AND recipient_subject_ref_type = 'PAIRWISE_SUBJECT' AND recipient_subject_ref IS NOT NULL)
    ),
    CONSTRAINT ck_webhook_delivery_actor CHECK ((recipient_actor_ref_type IS NULL) = (recipient_actor_ref IS NULL)),
    CONSTRAINT ck_webhook_delivery_no_global_actor CHECK (recipient_actor_ref_type IS NULL OR recipient_actor_ref_type IN ('PAIRWISE_SUBJECT', 'CLIENT', 'MACHINE', 'SYSTEM')),
    CONSTRAINT ck_webhook_delivery_hash CHECK (octet_length(payload_hash) = 32 AND octet_length(signature_hash) = 32),
    CONSTRAINT ck_webhook_delivery_delivered CHECK ((delivery_state = 'DELIVERED') = (delivered_at IS NOT NULL)),
    CONSTRAINT ck_webhook_delivery_dead CHECK ((delivery_state = 'DEAD_LETTER') = (dead_lettered_at IS NOT NULL))
);

COMMENT ON TABLE integration.webhook_delivery IS 'CAP-EVENT-005/012/015：签名、防重放、逐次重试/死信证据；个人事件对每个 Client 仅使用 pairwise Subject。';

CREATE TABLE integration.consumer_watermark (
    consumer_code text        NOT NULL,
    tenant_id uuid        NOT NULL DEFAULT '00000000-0000-0000-0000-000000000000',
    event_type text        NOT NULL,
    last_event_id uuid        NULL,
    last_aggregate_version bigint     NOT NULL DEFAULT 0,
    security_epochs jsonb       NOT NULL DEFAULT '{}',
    consent_epochs jsonb       NOT NULL DEFAULT '{}',
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    row_version bigint      NOT NULL DEFAULT 1,
    CONSTRAINT pk_consumer_watermark PRIMARY KEY (consumer_code, tenant_id, event_type),
    CONSTRAINT ck_consumer_watermark_version CHECK (last_aggregate_version >= 0)
);

COMMENT ON TABLE integration.consumer_watermark IS 'CAP-EVENT-007/009：消费方事件版本、security epoch 和 consent epoch 水位及断档补拉起点。';

CREATE TABLE integration.event_replay_request (
    id uuid        NOT NULL DEFAULT gen_random_uuid(),
    public_id text        NOT NULL,
    operation_id uuid        NOT NULL,
    approval_case_id uuid        NOT NULL,
    requested_by_ref text        NOT NULL,
    event_type_patterns text[]      NOT NULL,
    tenant_ids uuid[]      NOT NULL DEFAULT '{}',
    occurred_from timestamptz NOT NULL,
    occurred_until timestamptz NOT NULL,
    replay_state text        NOT NULL DEFAULT 'PENDING',
    suppress_irreversible_side_effects boolean NOT NULL DEFAULT true,
    replayed_count bigint      NOT NULL DEFAULT 0,
    failed_count bigint      NOT NULL DEFAULT 0,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    completed_at timestamptz NULL,
    CONSTRAINT pk_event_replay_request PRIMARY KEY (id),
    CONSTRAINT uq_event_replay_request_public_id UNIQUE (public_id),
    CONSTRAINT uq_event_replay_request_operation UNIQUE (operation_id),
    CONSTRAINT ck_event_replay_state CHECK (replay_state IN ('PENDING', 'RUNNING', 'PARTIAL', 'COMPLETED', 'FAILED', 'CANCELLED')),
    CONSTRAINT ck_event_replay_window CHECK (occurred_until > occurred_from),
    CONSTRAINT ck_event_replay_count CHECK (replayed_count >= 0 AND failed_count >= 0)
);

COMMENT ON TABLE integration.event_replay_request IS 'EVT-G-008：审批、时间/租户/类型范围、审计和不可逆副作用抑制明确的事件回放 Operation。';

CREATE UNIQUE INDEX ux_event_schema_active ON integration.event_schema(event_type) WHERE is_active;

CREATE INDEX ix_outbox_publish ON integration.outbox_event(available_at, id) WHERE publish_state IN ('PENDING', 'FAILED');

CREATE INDEX ix_outbox_aggregate ON integration.outbox_event(aggregate_kind, aggregate_ref, aggregate_version);

CREATE INDEX ix_webhook_delivery_retry ON integration.webhook_delivery(next_attempt_at) WHERE delivery_state IN ('PENDING', 'FAILED');

CREATE INDEX ix_fk_outbox_event_event_type_schema_version ON integration.outbox_event (event_type, schema_version);

CREATE INDEX ix_fk_webhook_delivery_event_id ON integration.webhook_delivery (event_id);

COMMENT ON COLUMN integration.event_schema.event_type IS '对象类别判别字段；允许值由 CHECK 或对应注册表限定。';
COMMENT ON COLUMN integration.event_schema.schema_version IS '对象、策略或源数据的显式版本；不得以不可信客户端时间戳替代。';
COMMENT ON COLUMN integration.event_schema.compatibility_mode IS 'integration.event_schema.compatibility_mode 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN integration.event_schema.json_schema IS '版本化结构化扩展数据；必须由 .NET 按对应 JSON Schema 校验，不得替代核心状态或外键。';
COMMENT ON COLUMN integration.event_schema.schema_hash IS '不可逆摘要；用于等值匹配、幂等、完整性或最小化证据，不保存原始敏感值。';
COMMENT ON COLUMN integration.event_schema.maximum_classification IS 'integration.event_schema.maximum_classification 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN integration.event_schema.owner_ref IS '不透明对象引用；不得从格式推断手机号、邮箱或其他业务事实。';
COMMENT ON COLUMN integration.event_schema.release_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN integration.event_schema.is_active IS '显式布尔开关；启用前置条件与失效行为由约束和版本化策略控制。';
COMMENT ON COLUMN integration.event_schema.created_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN integration.outbox_event.id IS '内部 UUID 主键；仅用于数据库关系，不作为跨域公开标识。';
COMMENT ON COLUMN integration.outbox_event.event_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN integration.outbox_event.event_type IS '对象类别判别字段；允许值由 CHECK 或对应注册表限定。';
COMMENT ON COLUMN integration.outbox_event.schema_version IS '对象、策略或源数据的显式版本；不得以不可信客户端时间戳替代。';
COMMENT ON COLUMN integration.outbox_event.aggregate_kind IS '对象类别判别字段；允许值由 CHECK 或对应注册表限定。';
COMMENT ON COLUMN integration.outbox_event.aggregate_ref IS '不透明对象引用；不得从格式推断手机号、邮箱或其他业务事实。';
COMMENT ON COLUMN integration.outbox_event.aggregate_version IS '对象、策略或源数据的显式版本；不得以不可信客户端时间戳替代。';
COMMENT ON COLUMN integration.outbox_event.subject_ref_type IS '对象类别判别字段；允许值由 CHECK 或对应注册表限定。';
COMMENT ON COLUMN integration.outbox_event.subject_ref IS '不透明对象引用；不得从格式推断手机号、邮箱或其他业务事实。';
COMMENT ON COLUMN integration.outbox_event.actor_ref_type IS '对象类别判别字段；允许值由 CHECK 或对应注册表限定。';
COMMENT ON COLUMN integration.outbox_event.actor_ref IS '不透明对象引用；不得从格式推断手机号、邮箱或其他业务事实。';
COMMENT ON COLUMN integration.outbox_event.tenant_id IS '租户隔离键；全零 UUID 表示平台范围，应用查询必须显式携带可信租户上下文。';
COMMENT ON COLUMN integration.outbox_event.business_line_id IS '业务线隔离键；关联 org.business_line，用于业务线范围隔离。';
COMMENT ON COLUMN integration.outbox_event.payload IS '版本化结构化扩展数据；必须由 .NET 按对应 JSON Schema 校验，不得替代核心状态或外键。';
COMMENT ON COLUMN integration.outbox_event.payload_hash IS '不可逆摘要；用于等值匹配、幂等、完整性或最小化证据，不保存原始敏感值。';
COMMENT ON COLUMN integration.outbox_event.trace_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN integration.outbox_event.correlation_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN integration.outbox_event.causation_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN integration.outbox_event.occurred_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN integration.outbox_event.available_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN integration.outbox_event.publish_state IS '显式状态当前值；合法取值见 CHECK，完整状态转换由 .NET 领域策略执行。';
COMMENT ON COLUMN integration.outbox_event.attempt_count IS '非负计数器；并发更新使用原子 SQL 或乐观并发控制。';
COMMENT ON COLUMN integration.outbox_event.next_attempt_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN integration.outbox_event.published_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN integration.outbox_event.broker_partition IS 'integration.outbox_event.broker_partition 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN integration.outbox_event.broker_offset IS 'integration.outbox_event.broker_offset 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN integration.outbox_event.last_error_code IS '稳定机器可读代码；展示文本由资源或目录解析。';
COMMENT ON COLUMN integration.outbox_event.created_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN integration.webhook_subscription.id IS '内部 UUID 主键；仅用于数据库关系，不作为跨域公开标识。';
COMMENT ON COLUMN integration.webhook_subscription.public_id IS '不可复用的公开稳定标识；插入时登记到 core.public_id_ledger。';
COMMENT ON COLUMN integration.webhook_subscription.client_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN integration.webhook_subscription.tenant_id IS '租户隔离键；全零 UUID 表示平台范围，应用查询必须显式携带可信租户上下文。';
COMMENT ON COLUMN integration.webhook_subscription.subscription_state IS '显式状态当前值；合法取值见 CHECK，完整状态转换由 .NET 领域策略执行。';
COMMENT ON COLUMN integration.webhook_subscription.callback_uri IS '受控 URI；写入前必须执行协议、主机、重定向与 SSRF 安全校验。';
COMMENT ON COLUMN integration.webhook_subscription.resolved_address_hash IS '不可逆摘要；用于等值匹配、幂等、完整性或最小化证据，不保存原始敏感值。';
COMMENT ON COLUMN integration.webhook_subscription.tls_certificate_pin IS 'integration.webhook_subscription.tls_certificate_pin 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN integration.webhook_subscription.signing_key_ref IS '外部 KMS/HSM 或受控密钥资产引用；不得保存私钥或 Secret 明文。';
COMMENT ON COLUMN integration.webhook_subscription.event_types IS '代码或引用集合；写入前去重、校验 allowlist，并满足表约束。';
COMMENT ON COLUMN integration.webhook_subscription.maximum_classification IS 'integration.webhook_subscription.maximum_classification 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN integration.webhook_subscription.consent_purpose_code IS '稳定机器可读代码；展示文本由资源或目录解析。';
COMMENT ON COLUMN integration.webhook_subscription.consent_aggregate_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN integration.webhook_subscription.consent_epoch IS '安全或同意水位版本；只能单调递增，用于令牌、缓存与撤销新鲜度校验。';
COMMENT ON COLUMN integration.webhook_subscription.verification_challenge_hash IS '不可逆摘要；用于等值匹配、幂等、完整性或最小化证据，不保存原始敏感值。';
COMMENT ON COLUMN integration.webhook_subscription.verified_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN integration.webhook_subscription.expires_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN integration.webhook_subscription.created_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN integration.webhook_subscription.updated_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN integration.webhook_subscription.row_version IS '乐观并发版本；更新必须使用原值 compare-and-set，成功后由数据库单调递增。';
COMMENT ON COLUMN integration.webhook_delivery.id IS '内部 UUID 主键；仅用于数据库关系，不作为跨域公开标识。';
COMMENT ON COLUMN integration.webhook_delivery.public_id IS '不可复用的公开稳定标识；插入时登记到 core.public_id_ledger。';
COMMENT ON COLUMN integration.webhook_delivery.subscription_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN integration.webhook_delivery.event_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN integration.webhook_delivery.delivery_state IS '显式状态当前值；合法取值见 CHECK，完整状态转换由 .NET 领域策略执行。';
COMMENT ON COLUMN integration.webhook_delivery.delivery_attempt IS '非负计数器；并发更新使用原子 SQL 或乐观并发控制。';
COMMENT ON COLUMN integration.webhook_delivery.contains_personal_subject IS 'integration.webhook_delivery.contains_personal_subject 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN integration.webhook_delivery.recipient_subject_ref_type IS '对象类别判别字段；允许值由 CHECK 或对应注册表限定。';
COMMENT ON COLUMN integration.webhook_delivery.recipient_subject_ref IS '不透明对象引用；不得从格式推断手机号、邮箱或其他业务事实。';
COMMENT ON COLUMN integration.webhook_delivery.recipient_actor_ref_type IS '对象类别判别字段；允许值由 CHECK 或对应注册表限定。';
COMMENT ON COLUMN integration.webhook_delivery.recipient_actor_ref IS '不透明对象引用；不得从格式推断手机号、邮箱或其他业务事实。';
COMMENT ON COLUMN integration.webhook_delivery.payload_hash IS '不可逆摘要；用于等值匹配、幂等、完整性或最小化证据，不保存原始敏感值。';
COMMENT ON COLUMN integration.webhook_delivery.signature_key_ref IS '外部 KMS/HSM 或受控密钥资产引用；不得保存私钥或 Secret 明文。';
COMMENT ON COLUMN integration.webhook_delivery.signature_hash IS '不可逆摘要；用于等值匹配、幂等、完整性或最小化证据，不保存原始敏感值。';
COMMENT ON COLUMN integration.webhook_delivery.response_status IS 'integration.webhook_delivery.response_status 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN integration.webhook_delivery.response_body_hash IS '不可逆摘要；用于等值匹配、幂等、完整性或最小化证据，不保存原始敏感值。';
COMMENT ON COLUMN integration.webhook_delivery.next_attempt_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN integration.webhook_delivery.first_attempt_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN integration.webhook_delivery.delivered_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN integration.webhook_delivery.dead_lettered_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN integration.webhook_delivery.created_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN integration.consumer_watermark.consumer_code IS '稳定机器可读代码；展示文本由资源或目录解析。';
COMMENT ON COLUMN integration.consumer_watermark.tenant_id IS '租户隔离键；全零 UUID 表示平台范围，应用查询必须显式携带可信租户上下文。';
COMMENT ON COLUMN integration.consumer_watermark.event_type IS '对象类别判别字段；允许值由 CHECK 或对应注册表限定。';
COMMENT ON COLUMN integration.consumer_watermark.last_event_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN integration.consumer_watermark.last_aggregate_version IS '对象、策略或源数据的显式版本；不得以不可信客户端时间戳替代。';
COMMENT ON COLUMN integration.consumer_watermark.security_epochs IS '版本化结构化扩展数据；必须由 .NET 按对应 JSON Schema 校验，不得替代核心状态或外键。';
COMMENT ON COLUMN integration.consumer_watermark.consent_epochs IS '版本化结构化扩展数据；必须由 .NET 按对应 JSON Schema 校验，不得替代核心状态或外键。';
COMMENT ON COLUMN integration.consumer_watermark.updated_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN integration.consumer_watermark.row_version IS '乐观并发版本；更新必须使用原值 compare-and-set，成功后由数据库单调递增。';
COMMENT ON COLUMN integration.event_replay_request.id IS '内部 UUID 主键；仅用于数据库关系，不作为跨域公开标识。';
COMMENT ON COLUMN integration.event_replay_request.public_id IS '不可复用的公开稳定标识；插入时登记到 core.public_id_ledger。';
COMMENT ON COLUMN integration.event_replay_request.operation_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN integration.event_replay_request.approval_case_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN integration.event_replay_request.requested_by_ref IS '不透明对象引用；不得从格式推断手机号、邮箱或其他业务事实。';
COMMENT ON COLUMN integration.event_replay_request.event_type_patterns IS '代码或引用集合；写入前去重、校验 allowlist，并满足表约束。';
COMMENT ON COLUMN integration.event_replay_request.tenant_ids IS '代码或引用集合；写入前去重、校验 allowlist，并满足表约束。';
COMMENT ON COLUMN integration.event_replay_request.occurred_from IS 'integration.event_replay_request.occurred_from 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN integration.event_replay_request.occurred_until IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN integration.event_replay_request.replay_state IS '显式状态当前值；合法取值见 CHECK，完整状态转换由 .NET 领域策略执行。';
COMMENT ON COLUMN integration.event_replay_request.suppress_irreversible_side_effects IS 'integration.event_replay_request.suppress_irreversible_side_effects 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN integration.event_replay_request.replayed_count IS '非负计数器；并发更新使用原子 SQL 或乐观并发控制。';
COMMENT ON COLUMN integration.event_replay_request.failed_count IS '非负计数器；并发更新使用原子 SQL 或乐观并发控制。';
COMMENT ON COLUMN integration.event_replay_request.created_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN integration.event_replay_request.completed_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';

COMMENT ON CONSTRAINT pk_event_schema ON integration.event_schema IS '主键约束：唯一标识 integration.event_schema 记录。';
COMMENT ON CONSTRAINT ck_event_schema_type ON integration.event_schema IS '检查约束：限制 integration.event_schema 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_event_schema_compat ON integration.event_schema IS '检查约束：限制 integration.event_schema 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_event_schema_hash ON integration.event_schema IS '检查约束：限制 integration.event_schema 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_event_schema_active ON integration.event_schema IS '检查约束：限制 integration.event_schema 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT pk_outbox_event ON integration.outbox_event IS '主键约束：唯一标识 integration.outbox_event 记录。';
COMMENT ON CONSTRAINT uq_outbox_event_id ON integration.outbox_event IS '唯一约束：保证 event_id 在 integration.outbox_event 范围内不重复。';
COMMENT ON CONSTRAINT fk_outbox_event_schema ON integration.outbox_event IS '外键约束：integration.outbox_event 的 event_type、schema_version 必须引用 integration.event_schema；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT ck_outbox_event_subject ON integration.outbox_event IS '检查约束：限制 integration.outbox_event 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_outbox_event_actor ON integration.outbox_event IS '检查约束：限制 integration.outbox_event 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_outbox_event_subject_type ON integration.outbox_event IS '检查约束：限制 integration.outbox_event 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_outbox_event_actor_type ON integration.outbox_event IS '检查约束：限制 integration.outbox_event 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_outbox_event_version ON integration.outbox_event IS '检查约束：限制 integration.outbox_event 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_outbox_event_hash ON integration.outbox_event IS '检查约束：限制 integration.outbox_event 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_outbox_event_state ON integration.outbox_event IS '检查约束：限制 integration.outbox_event 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_outbox_event_attempt ON integration.outbox_event IS '检查约束：限制 integration.outbox_event 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_outbox_event_published ON integration.outbox_event IS '检查约束：限制 integration.outbox_event 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT pk_webhook_subscription ON integration.webhook_subscription IS '主键约束：唯一标识 integration.webhook_subscription 记录。';
COMMENT ON CONSTRAINT uq_webhook_subscription_public_id ON integration.webhook_subscription IS '唯一约束：保证 public_id 在 integration.webhook_subscription 范围内不重复。';
COMMENT ON CONSTRAINT uq_webhook_subscription_uri ON integration.webhook_subscription IS '唯一约束：保证 client_id、callback_uri 在 integration.webhook_subscription 范围内不重复。';
COMMENT ON CONSTRAINT ck_webhook_subscription_state ON integration.webhook_subscription IS '检查约束：限制 integration.webhook_subscription 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_webhook_subscription_uri ON integration.webhook_subscription IS '检查约束：限制 integration.webhook_subscription 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_webhook_subscription_events ON integration.webhook_subscription IS '检查约束：限制 integration.webhook_subscription 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_webhook_subscription_hash ON integration.webhook_subscription IS '检查约束：限制 integration.webhook_subscription 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_webhook_subscription_consent ON integration.webhook_subscription IS '检查约束：限制 integration.webhook_subscription 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_webhook_subscription_active ON integration.webhook_subscription IS '检查约束：限制 integration.webhook_subscription 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_webhook_subscription_expiry ON integration.webhook_subscription IS '检查约束：限制 integration.webhook_subscription 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT pk_webhook_delivery ON integration.webhook_delivery IS '主键约束：唯一标识 integration.webhook_delivery 记录。';
COMMENT ON CONSTRAINT uq_webhook_delivery_public_id ON integration.webhook_delivery IS '唯一约束：保证 public_id 在 integration.webhook_delivery 范围内不重复。';
COMMENT ON CONSTRAINT uq_webhook_delivery_attempt ON integration.webhook_delivery IS '唯一约束：保证 subscription_id、event_id、delivery_attempt 在 integration.webhook_delivery 范围内不重复。';
COMMENT ON CONSTRAINT fk_webhook_delivery_subscription ON integration.webhook_delivery IS '外键约束：integration.webhook_delivery 的 subscription_id 必须引用 integration.webhook_subscription；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT fk_webhook_delivery_event ON integration.webhook_delivery IS '外键约束：integration.webhook_delivery 的 event_id 必须引用 integration.outbox_event；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT ck_webhook_delivery_state ON integration.webhook_delivery IS '检查约束：限制 integration.webhook_delivery 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_webhook_delivery_attempt ON integration.webhook_delivery IS '检查约束：限制 integration.webhook_delivery 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_webhook_delivery_subject ON integration.webhook_delivery IS '检查约束：限制 integration.webhook_delivery 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_webhook_delivery_actor ON integration.webhook_delivery IS '检查约束：限制 integration.webhook_delivery 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_webhook_delivery_no_global_actor ON integration.webhook_delivery IS '检查约束：限制 integration.webhook_delivery 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_webhook_delivery_hash ON integration.webhook_delivery IS '检查约束：限制 integration.webhook_delivery 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_webhook_delivery_delivered ON integration.webhook_delivery IS '检查约束：限制 integration.webhook_delivery 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_webhook_delivery_dead ON integration.webhook_delivery IS '检查约束：限制 integration.webhook_delivery 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT pk_consumer_watermark ON integration.consumer_watermark IS '主键约束：唯一标识 integration.consumer_watermark 记录。';
COMMENT ON CONSTRAINT ck_consumer_watermark_version ON integration.consumer_watermark IS '检查约束：限制 integration.consumer_watermark 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT pk_event_replay_request ON integration.event_replay_request IS '主键约束：唯一标识 integration.event_replay_request 记录。';
COMMENT ON CONSTRAINT uq_event_replay_request_public_id ON integration.event_replay_request IS '唯一约束：保证 public_id 在 integration.event_replay_request 范围内不重复。';
COMMENT ON CONSTRAINT uq_event_replay_request_operation ON integration.event_replay_request IS '唯一约束：保证 operation_id 在 integration.event_replay_request 范围内不重复。';
COMMENT ON CONSTRAINT ck_event_replay_state ON integration.event_replay_request IS '检查约束：限制 integration.event_replay_request 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_event_replay_window ON integration.event_replay_request IS '检查约束：限制 integration.event_replay_request 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_event_replay_count ON integration.event_replay_request IS '检查约束：限制 integration.event_replay_request 的字段取值或组合满足结构与安全底线。';

COMMENT ON INDEX integration.ux_event_schema_active IS '查询索引：优化 integration.event_schema 按 event_type 的访问，仅覆盖 WHERE 条件命中的记录。';
COMMENT ON INDEX integration.ix_outbox_publish IS '查询索引：优化 integration.outbox_event 按 available_at、id 的访问，仅覆盖 WHERE 条件命中的记录。';
COMMENT ON INDEX integration.ix_outbox_aggregate IS '查询索引：优化 integration.outbox_event 按 aggregate_kind、aggregate_ref、aggregate_version 的访问。';
COMMENT ON INDEX integration.ix_webhook_delivery_retry IS '查询索引：优化 integration.webhook_delivery 按 next_attempt_at 的访问，仅覆盖 WHERE 条件命中的记录。';
COMMENT ON INDEX integration.pk_event_schema IS '约束 pk_event_schema 的支撑唯一索引。';
COMMENT ON INDEX integration.pk_outbox_event IS '约束 pk_outbox_event 的支撑唯一索引。';
COMMENT ON INDEX integration.uq_outbox_event_id IS '约束 uq_outbox_event_id 的支撑唯一索引。';
COMMENT ON INDEX integration.pk_webhook_subscription IS '约束 pk_webhook_subscription 的支撑唯一索引。';
COMMENT ON INDEX integration.uq_webhook_subscription_public_id IS '约束 uq_webhook_subscription_public_id 的支撑唯一索引。';
COMMENT ON INDEX integration.uq_webhook_subscription_uri IS '约束 uq_webhook_subscription_uri 的支撑唯一索引。';
COMMENT ON INDEX integration.pk_webhook_delivery IS '约束 pk_webhook_delivery 的支撑唯一索引。';
COMMENT ON INDEX integration.uq_webhook_delivery_public_id IS '约束 uq_webhook_delivery_public_id 的支撑唯一索引。';
COMMENT ON INDEX integration.uq_webhook_delivery_attempt IS '约束 uq_webhook_delivery_attempt 的支撑唯一索引。';
COMMENT ON INDEX integration.pk_consumer_watermark IS '约束 pk_consumer_watermark 的支撑唯一索引。';
COMMENT ON INDEX integration.pk_event_replay_request IS '约束 pk_event_replay_request 的支撑唯一索引。';
COMMENT ON INDEX integration.uq_event_replay_request_public_id IS '约束 uq_event_replay_request_public_id 的支撑唯一索引。';
COMMENT ON INDEX integration.uq_event_replay_request_operation IS '约束 uq_event_replay_request_operation 的支撑唯一索引。';
COMMENT ON INDEX integration.ix_fk_outbox_event_event_type_schema_version IS '查询索引：优化 integration.outbox_event 按 event_type、schema_version 的访问。';
COMMENT ON INDEX integration.ix_fk_webhook_delivery_event_id IS '查询索引：优化 integration.webhook_delivery 按 event_id 的访问。';

