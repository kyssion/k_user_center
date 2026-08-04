\set ON_ERROR_STOP on

SET ROLE iam_owner;

-- 事件契约、Webhook 投递和消费者水位。

CREATE TABLE iam.event_schema_versions (
    id uuid PRIMARY KEY,
    event_type varchar(160) NOT NULL,
    schema_version integer NOT NULL,
    compatibility_mode varchar(40) NOT NULL,
    json_schema jsonb NOT NULL,
    schema_digest char(64) NOT NULL,
    approval_case_id uuid,
    state varchar(40) NOT NULL,
    published_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    row_version bigint NOT NULL DEFAULT 0,
    CONSTRAINT uq_event_schema_version UNIQUE (event_type, schema_version),
    CONSTRAINT ck_event_schema_version CHECK (schema_version > 0 AND row_version >= 0)
);
COMMENT ON TABLE iam.event_schema_versions IS '不可变事件 JSON Schema 版本；兼容性验证、发布和生成代码由 EVENT 控制面执行。';
COMMENT ON COLUMN iam.event_schema_versions.id IS '应用生成的事件 Schema UUIDv7。';
COMMENT ON COLUMN iam.event_schema_versions.event_type IS '稳定事件类型名称。';
COMMENT ON COLUMN iam.event_schema_versions.schema_version IS '事件类型内正整数 Schema 版本。';
COMMENT ON COLUMN iam.event_schema_versions.compatibility_mode IS '兼容性模式声明；具体检查由代码执行。';
COMMENT ON COLUMN iam.event_schema_versions.json_schema IS '事件 JSON Schema 文档。';
COMMENT ON COLUMN iam.event_schema_versions.schema_digest IS '规范化 Schema SHA-256 摘要。';
COMMENT ON COLUMN iam.event_schema_versions.approval_case_id IS '可空；发布审批逻辑引用 iam.approval_cases.id。';
COMMENT ON COLUMN iam.event_schema_versions.state IS 'Schema 版本状态。';
COMMENT ON COLUMN iam.event_schema_versions.published_at IS '可空；发布时间。';
COMMENT ON COLUMN iam.event_schema_versions.created_at IS '数据库插入时间。';
COMMENT ON COLUMN iam.event_schema_versions.row_version IS '审批和发布生命周期元数据的乐观锁版本；Schema 内容字段不可更新。';

CREATE TABLE iam.webhook_subscriptions (
    id uuid PRIMARY KEY,
    subscription_id varchar(128) NOT NULL,
    owner_type varchar(40) NOT NULL,
    owner_id uuid NOT NULL,
    client_id uuid,
    tenant_id uuid,
    endpoint_ciphertext text NOT NULL,
    endpoint_host_hash varchar(256) NOT NULL,
    event_filter jsonb NOT NULL,
    state varchar(40) NOT NULL,
    active_configuration_id uuid,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    row_version bigint NOT NULL DEFAULT 0,
    CONSTRAINT uq_webhook_subscription_public UNIQUE (subscription_id),
    CONSTRAINT ck_webhook_subscription_version CHECK (row_version >= 0)
);
COMMENT ON TABLE iam.webhook_subscriptions IS 'Webhook 订阅；Endpoint 加密保存，SSRF 校验、事件过滤和权限由 EVENT 代码执行。';
COMMENT ON COLUMN iam.webhook_subscriptions.id IS '应用生成的订阅 UUIDv7。';
COMMENT ON COLUMN iam.webhook_subscriptions.subscription_id IS '对订阅所有者公开的高熵订阅 ID。';
COMMENT ON COLUMN iam.webhook_subscriptions.owner_type IS '订阅所有者类型。';
COMMENT ON COLUMN iam.webhook_subscriptions.owner_id IS '订阅所有者逻辑 ID。';
COMMENT ON COLUMN iam.webhook_subscriptions.client_id IS '可空；逻辑引用 iam.oauth_clients.id。';
COMMENT ON COLUMN iam.webhook_subscriptions.tenant_id IS '可空；逻辑引用 iam.tenants.id。';
COMMENT ON COLUMN iam.webhook_subscriptions.endpoint_ciphertext IS 'Webhook Endpoint 应用密文，普通只读角色不可访问。';
COMMENT ON COLUMN iam.webhook_subscriptions.endpoint_host_hash IS '规范化 Endpoint Host 的 HMAC 摘要，用于安全策略查询。';
COMMENT ON COLUMN iam.webhook_subscriptions.event_filter IS '事件类型和条件过滤快照；代码按 Schema 校验。';
COMMENT ON COLUMN iam.webhook_subscriptions.state IS '订阅状态。';
COMMENT ON COLUMN iam.webhook_subscriptions.active_configuration_id IS '可空；逻辑引用 iam.configuration_versions.id。';
COMMENT ON COLUMN iam.webhook_subscriptions.created_at IS '数据库插入时间。';
COMMENT ON COLUMN iam.webhook_subscriptions.updated_at IS '数据库更新时间；由技术 Trigger 自动刷新。';
COMMENT ON COLUMN iam.webhook_subscriptions.row_version IS '乐观锁版本。';

CREATE TABLE iam.webhook_signing_keys (
    id uuid PRIMARY KEY,
    subscription_id uuid NOT NULL,
    receiver_key_id varchar(256) NOT NULL,
    key_id uuid NOT NULL,
    algorithm varchar(80) NOT NULL,
    state varchar(40) NOT NULL,
    valid_from timestamptz NOT NULL,
    valid_until timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    row_version bigint NOT NULL DEFAULT 0,
    CONSTRAINT uq_webhook_signing_key UNIQUE (subscription_id, receiver_key_id),
    CONSTRAINT ck_webhook_signing_validity CHECK (valid_until > valid_from),
    CONSTRAINT ck_webhook_signing_version CHECK (row_version >= 0)
);
COMMENT ON TABLE iam.webhook_signing_keys IS 'Webhook 签名 Key 引用；Secret 和私钥保存在 KMS，轮换与重叠由 EVENT/KEY 代码处理。';
COMMENT ON COLUMN iam.webhook_signing_keys.id IS '应用生成的签名 Key 关系 UUIDv7。';
COMMENT ON COLUMN iam.webhook_signing_keys.subscription_id IS '逻辑引用 iam.webhook_subscriptions.id。';
COMMENT ON COLUMN iam.webhook_signing_keys.receiver_key_id IS '接收方可见的 Key ID。';
COMMENT ON COLUMN iam.webhook_signing_keys.key_id IS '逻辑引用 iam.cryptographic_keys.id。';
COMMENT ON COLUMN iam.webhook_signing_keys.algorithm IS '签名算法，必须由代码对照 Allowlist。';
COMMENT ON COLUMN iam.webhook_signing_keys.state IS '签名 Key 关系状态。';
COMMENT ON COLUMN iam.webhook_signing_keys.valid_from IS '开始签名或验证时间。';
COMMENT ON COLUMN iam.webhook_signing_keys.valid_until IS '停止验证时间。';
COMMENT ON COLUMN iam.webhook_signing_keys.created_at IS '数据库插入时间。';
COMMENT ON COLUMN iam.webhook_signing_keys.updated_at IS '数据库更新时间；由技术 Trigger 自动刷新。';
COMMENT ON COLUMN iam.webhook_signing_keys.row_version IS '乐观锁版本。';

CREATE TABLE iam.webhook_deliveries (
    id uuid NOT NULL,
    delivery_id uuid NOT NULL,
    event_source_code varchar(100) NOT NULL,
    event_id uuid NOT NULL,
    event_type varchar(160) NOT NULL,
    subscription_id uuid NOT NULL,
    payload_schema_version integer NOT NULL,
    payload_digest char(64) NOT NULL,
    state varchar(40) NOT NULL,
    attempt_count integer NOT NULL DEFAULT 0,
    next_attempt_at timestamptz,
    final_result varchar(80),
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    completed_at timestamptz,
    CONSTRAINT pk_webhook_deliveries PRIMARY KEY (id, delivery_id),
    CONSTRAINT uq_webhook_deliveries_delivery_id UNIQUE (delivery_id),
    CONSTRAINT ck_webhook_delivery_schema CHECK (payload_schema_version > 0),
    CONSTRAINT ck_webhook_delivery_attempt CHECK (attempt_count >= 0)
) PARTITION BY HASH (delivery_id);
COMMENT ON TABLE iam.webhook_deliveries IS '单个事件到订阅的投递任务；按 delivery_id Hash 分区并由数据库保证投递 ID 全局唯一，签名、重试、退避和终态由 EVENT 代码维护。';
COMMENT ON COLUMN iam.webhook_deliveries.id IS '应用生成的记录 UUIDv7。';
COMMENT ON COLUMN iam.webhook_deliveries.delivery_id IS '对外追踪的全局投递 UUID；数据库全局唯一。';
COMMENT ON COLUMN iam.webhook_deliveries.event_source_code IS '稳定事件来源代码；区分本库 Outbox 与外部事件总线，合法值和来源注册由 EVENT 代码维护。';
COMMENT ON COLUMN iam.webhook_deliveries.event_id IS '按 event_source_code 逻辑引用 iam.outbox_events.event_id 或外部事件总线事件 ID。';
COMMENT ON COLUMN iam.webhook_deliveries.event_type IS '事件类型。';
COMMENT ON COLUMN iam.webhook_deliveries.subscription_id IS '逻辑引用 iam.webhook_subscriptions.id。';
COMMENT ON COLUMN iam.webhook_deliveries.payload_schema_version IS '投递载荷事件 Schema 版本。';
COMMENT ON COLUMN iam.webhook_deliveries.payload_digest IS '实际投递载荷 SHA-256 摘要。';
COMMENT ON COLUMN iam.webhook_deliveries.state IS '投递状态。';
COMMENT ON COLUMN iam.webhook_deliveries.attempt_count IS 'HTTP 投递尝试次数。';
COMMENT ON COLUMN iam.webhook_deliveries.next_attempt_at IS '可空；代码计算的下次重试时间。';
COMMENT ON COLUMN iam.webhook_deliveries.final_result IS '可空；终态结果码。';
COMMENT ON COLUMN iam.webhook_deliveries.created_at IS '数据库插入时间；用于队列排序、审计和归档查询。';
COMMENT ON COLUMN iam.webhook_deliveries.completed_at IS '可空；进入终态时间。';
COMMENT ON CONSTRAINT uq_webhook_deliveries_delivery_id ON iam.webhook_deliveries IS '保证投递 ID 在数据库内全局唯一并可被尝试事实稳定引用；因此按 delivery_id Hash 分区。';

CREATE TABLE iam.webhook_delivery_attempts (
    id uuid NOT NULL,
    delivery_id uuid NOT NULL,
    attempt_no integer NOT NULL,
    signing_key_id uuid NOT NULL,
    request_digest char(64) NOT NULL,
    response_status integer,
    response_digest char(64),
    latency_ms integer,
    error_code varchar(100),
    retry_at timestamptz,
    started_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT pk_webhook_delivery_attempts PRIMARY KEY (id, created_at),
    CONSTRAINT ck_webhook_attempt_no CHECK (attempt_no > 0),
    CONSTRAINT ck_webhook_attempt_latency CHECK (latency_ms IS NULL OR latency_ms >= 0)
) PARTITION BY RANGE (created_at);
COMMENT ON TABLE iam.webhook_delivery_attempts IS 'Webhook HTTP 尝试事实；按 created_at 月度分区，不保存完整请求或响应正文。';
COMMENT ON COLUMN iam.webhook_delivery_attempts.id IS '应用生成的尝试 UUIDv7。';
COMMENT ON COLUMN iam.webhook_delivery_attempts.delivery_id IS '逻辑引用 iam.webhook_deliveries.delivery_id。';
COMMENT ON COLUMN iam.webhook_delivery_attempts.attempt_no IS '投递内正整数尝试序号。';
COMMENT ON COLUMN iam.webhook_delivery_attempts.signing_key_id IS '逻辑引用 iam.webhook_signing_keys.id。';
COMMENT ON COLUMN iam.webhook_delivery_attempts.request_digest IS '规范化 HTTP 请求摘要。';
COMMENT ON COLUMN iam.webhook_delivery_attempts.response_status IS '可空；接收方 HTTP 状态码。';
COMMENT ON COLUMN iam.webhook_delivery_attempts.response_digest IS '可空；受限响应摘要。';
COMMENT ON COLUMN iam.webhook_delivery_attempts.latency_ms IS '可空；非负投递耗时毫秒数。';
COMMENT ON COLUMN iam.webhook_delivery_attempts.error_code IS '可空；稳定传输错误码。';
COMMENT ON COLUMN iam.webhook_delivery_attempts.retry_at IS '可空；代码计算的下次重试时间。';
COMMENT ON COLUMN iam.webhook_delivery_attempts.started_at IS 'HTTP 请求开始时间。';
COMMENT ON COLUMN iam.webhook_delivery_attempts.created_at IS '数据库插入时间和月度分区键。';

CREATE TABLE iam.event_replay_requests (
    id uuid PRIMARY KEY,
    requester_type varchar(40) NOT NULL,
    requester_id uuid NOT NULL,
    event_type_filter text[] NOT NULL DEFAULT ARRAY[]::text[],
    range_start timestamptz NOT NULL,
    range_end timestamptz NOT NULL,
    reason text NOT NULL,
    approval_case_id uuid NOT NULL,
    operation_id uuid NOT NULL,
    state varchar(40) NOT NULL,
    max_event_count bigint NOT NULL,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    row_version bigint NOT NULL DEFAULT 0,
    CONSTRAINT uq_event_replay_operation UNIQUE (operation_id),
    CONSTRAINT ck_event_replay_range CHECK (range_end > range_start),
    CONSTRAINT ck_event_replay_count CHECK (max_event_count > 0),
    CONSTRAINT ck_event_replay_version CHECK (row_version >= 0)
);
COMMENT ON TABLE iam.event_replay_requests IS '受控事件回放请求；权限、审批、范围限制、速率和重放标记由 EVENT 代码执行。';
COMMENT ON COLUMN iam.event_replay_requests.id IS '应用生成的回放请求 UUIDv7。';
COMMENT ON COLUMN iam.event_replay_requests.requester_type IS '请求者类型。';
COMMENT ON COLUMN iam.event_replay_requests.requester_id IS '请求者逻辑 ID。';
COMMENT ON COLUMN iam.event_replay_requests.event_type_filter IS '允许回放的事件类型过滤。';
COMMENT ON COLUMN iam.event_replay_requests.range_start IS '事件时间范围开始。';
COMMENT ON COLUMN iam.event_replay_requests.range_end IS '事件时间范围结束。';
COMMENT ON COLUMN iam.event_replay_requests.reason IS '受控回放理由。';
COMMENT ON COLUMN iam.event_replay_requests.approval_case_id IS '逻辑引用 iam.approval_cases.id。';
COMMENT ON COLUMN iam.event_replay_requests.operation_id IS '逻辑引用 iam.operations.id。';
COMMENT ON COLUMN iam.event_replay_requests.state IS '回放请求状态。';
COMMENT ON COLUMN iam.event_replay_requests.max_event_count IS '批准的最大事件数量。';
COMMENT ON COLUMN iam.event_replay_requests.created_at IS '数据库插入时间。';
COMMENT ON COLUMN iam.event_replay_requests.updated_at IS '数据库更新时间；由技术 Trigger 自动刷新。';
COMMENT ON COLUMN iam.event_replay_requests.row_version IS '乐观锁版本。';

CREATE TABLE iam.consumer_checkpoints (
    id uuid PRIMARY KEY,
    consumer_id varchar(200) NOT NULL,
    stream_code varchar(160) NOT NULL,
    partition_key varchar(160) NOT NULL,
    last_event_id uuid,
    aggregate_version bigint,
    security_watermark bigint,
    checkpoint jsonb NOT NULL DEFAULT '{}'::jsonb,
    updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    row_version bigint NOT NULL DEFAULT 0,
    CONSTRAINT uq_consumer_checkpoint UNIQUE (consumer_id, stream_code, partition_key),
    CONSTRAINT ck_consumer_checkpoint_versions CHECK ((aggregate_version IS NULL OR aggregate_version >= 0) AND (security_watermark IS NULL OR security_watermark >= 0) AND row_version >= 0)
);
COMMENT ON TABLE iam.consumer_checkpoints IS '消费者流位置、聚合版本和安全水位；乱序、失败关闭和原子推进由消费代码实现。';
COMMENT ON COLUMN iam.consumer_checkpoints.id IS '应用生成的检查点 UUIDv7。';
COMMENT ON COLUMN iam.consumer_checkpoints.consumer_id IS '稳定消费者标识。';
COMMENT ON COLUMN iam.consumer_checkpoints.stream_code IS '事件流或类型代码。';
COMMENT ON COLUMN iam.consumer_checkpoints.partition_key IS '消息系统分区或业务分片键。';
COMMENT ON COLUMN iam.consumer_checkpoints.last_event_id IS '可空；最近提交的全局事件 ID。';
COMMENT ON COLUMN iam.consumer_checkpoints.aggregate_version IS '可空；最近处理的聚合版本。';
COMMENT ON COLUMN iam.consumer_checkpoints.security_watermark IS '可空；最近应用的撤销或安全水位。';
COMMENT ON COLUMN iam.consumer_checkpoints.checkpoint IS '消息系统专用检查点，不由数据库解释。';
COMMENT ON COLUMN iam.consumer_checkpoints.updated_at IS '数据库更新时间；由技术 Trigger 自动刷新。';
COMMENT ON COLUMN iam.consumer_checkpoints.row_version IS '乐观锁版本。';

CREATE INDEX ix_webhook_subscriptions_owner ON iam.webhook_subscriptions (owner_type, owner_id, state);
CREATE INDEX ix_webhook_deliveries_queue ON iam.webhook_deliveries (state, next_attempt_at, created_at);
CREATE INDEX ix_webhook_deliveries_subscription ON iam.webhook_deliveries (subscription_id, created_at DESC);
CREATE INDEX ix_webhook_attempts_delivery ON iam.webhook_delivery_attempts (delivery_id, attempt_no, created_at);
CREATE INDEX ix_event_replay_requests_queue ON iam.event_replay_requests (state, created_at);
COMMENT ON INDEX iam.ix_webhook_deliveries_queue IS 'Webhook 工作者按状态和下次重试时间领取投递。';
