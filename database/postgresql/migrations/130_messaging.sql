\set ON_ERROR_STOP on

SET ROLE iam_owner;

-- 短信、邮件、推送等消息投递事实。路由、模板渲染、限速和合规由 MSG 代码执行。

CREATE TABLE iam.message_providers (
    id uuid PRIMARY KEY,
    provider_code varchar(128) NOT NULL,
    channel varchar(40) NOT NULL,
    region_code varchar(20) NOT NULL,
    owner_type varchar(40) NOT NULL,
    owner_id uuid NOT NULL,
    state varchar(40) NOT NULL,
    active_configuration_id uuid NOT NULL,
    priority_hint integer NOT NULL DEFAULT 0,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    row_version bigint NOT NULL DEFAULT 0,
    CONSTRAINT uq_message_provider_code UNIQUE (provider_code),
    CONSTRAINT ck_message_provider_priority CHECK (priority_hint >= 0),
    CONSTRAINT ck_message_provider_version CHECK (row_version >= 0)
);
COMMENT ON TABLE iam.message_providers IS '短信、邮件和推送供应商登记；秘密保存在密钥系统，路由、熔断和降级由 MSG 代码执行。';
COMMENT ON COLUMN iam.message_providers.id IS '应用生成的供应商 UUIDv7。';
COMMENT ON COLUMN iam.message_providers.provider_code IS '稳定供应商代码。';
COMMENT ON COLUMN iam.message_providers.channel IS '消息渠道类型。';
COMMENT ON COLUMN iam.message_providers.region_code IS '供应商服务地区代码。';
COMMENT ON COLUMN iam.message_providers.owner_type IS '供应商配置所有者类型。';
COMMENT ON COLUMN iam.message_providers.owner_id IS '供应商配置所有者逻辑 ID。';
COMMENT ON COLUMN iam.message_providers.state IS '供应商状态。';
COMMENT ON COLUMN iam.message_providers.active_configuration_id IS '逻辑引用 iam.configuration_versions.id。';
COMMENT ON COLUMN iam.message_providers.priority_hint IS '非负静态排序提示；实际路由由代码策略决定。';
COMMENT ON COLUMN iam.message_providers.created_at IS '数据库插入时间。';
COMMENT ON COLUMN iam.message_providers.updated_at IS '数据库更新时间；由技术 Trigger 自动刷新。';
COMMENT ON COLUMN iam.message_providers.row_version IS '乐观锁版本。';

CREATE TABLE iam.message_template_versions (
    id uuid PRIMARY KEY,
    template_code varchar(160) NOT NULL,
    channel varchar(40) NOT NULL,
    locale varchar(35) NOT NULL,
    version integer NOT NULL,
    subject_template text,
    content_template text NOT NULL,
    variable_schema jsonb NOT NULL,
    content_digest char(64) NOT NULL,
    approval_case_id uuid,
    state varchar(40) NOT NULL,
    published_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    row_version bigint NOT NULL DEFAULT 0,
    CONSTRAINT uq_message_template_version UNIQUE (template_code, channel, locale, version),
    CONSTRAINT ck_message_template_version CHECK (version > 0 AND row_version >= 0)
);
COMMENT ON TABLE iam.message_template_versions IS '消息模板不可变版本；变量校验、转义、敏感信息控制和审批由 MSG/CTRL 代码执行。';
COMMENT ON COLUMN iam.message_template_versions.id IS '应用生成的模板版本 UUIDv7。';
COMMENT ON COLUMN iam.message_template_versions.template_code IS '稳定模板代码。';
COMMENT ON COLUMN iam.message_template_versions.channel IS '模板渠道。';
COMMENT ON COLUMN iam.message_template_versions.locale IS 'BCP 47 语言区域。';
COMMENT ON COLUMN iam.message_template_versions.version IS '模板键内正整数版本。';
COMMENT ON COLUMN iam.message_template_versions.subject_template IS '可空；邮件等渠道标题模板。';
COMMENT ON COLUMN iam.message_template_versions.content_template IS '模板正文；代码使用安全模板引擎渲染。';
COMMENT ON COLUMN iam.message_template_versions.variable_schema IS '允许变量及敏感级别 JSON Schema。';
COMMENT ON COLUMN iam.message_template_versions.content_digest IS '规范化模板内容 SHA-256 摘要。';
COMMENT ON COLUMN iam.message_template_versions.approval_case_id IS '可空；逻辑引用 iam.approval_cases.id。';
COMMENT ON COLUMN iam.message_template_versions.state IS '模板版本状态。';
COMMENT ON COLUMN iam.message_template_versions.published_at IS '可空；发布时间。';
COMMENT ON COLUMN iam.message_template_versions.created_at IS '数据库插入时间。';
COMMENT ON COLUMN iam.message_template_versions.row_version IS '审批和发布生命周期元数据的乐观锁版本；模板内容字段不可更新。';

CREATE TABLE iam.message_requests (
    id uuid NOT NULL,
    request_id uuid NOT NULL,
    purpose varchar(100) NOT NULL,
    channel varchar(40) NOT NULL,
    target_digest varchar(256) NOT NULL,
    target_ciphertext text,
    identifier_id uuid,
    template_version_id uuid NOT NULL,
    parameters jsonb NOT NULL,
    parameter_digest char(64) NOT NULL,
    caller_scope varchar(200) NOT NULL,
    idempotency_key varchar(200) NOT NULL,
    state varchar(40) NOT NULL,
    priority integer NOT NULL DEFAULT 0,
    scheduled_at timestamptz,
    expires_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    completed_at timestamptz,
    CONSTRAINT pk_message_requests PRIMARY KEY (id, request_id),
    CONSTRAINT uq_message_requests_request_id UNIQUE (request_id),
    CONSTRAINT ck_message_request_priority CHECK (priority >= 0),
    CONSTRAINT ck_message_request_expiry CHECK (expires_at > created_at)
) PARTITION BY HASH (request_id);
COMMENT ON TABLE iam.message_requests IS '消息发送请求；按 request_id Hash 分区并由数据库保证请求 ID 全局唯一，目标可为密文，限速、抑制、路由和模板渲染由 MSG 代码处理。';
COMMENT ON COLUMN iam.message_requests.id IS '应用生成的记录 UUIDv7。';
COMMENT ON COLUMN iam.message_requests.request_id IS '全局消息请求 UUID；数据库全局唯一。';
COMMENT ON COLUMN iam.message_requests.purpose IS '发送目的代码，例如 LOGIN_OTP、SECURITY_ALERT。';
COMMENT ON COLUMN iam.message_requests.channel IS '发送渠道。';
COMMENT ON COLUMN iam.message_requests.target_digest IS '目标联系方式 HMAC 摘要，用于限速和抑制查询。';
COMMENT ON COLUMN iam.message_requests.target_ciphertext IS '可空；目标联系方式应用密文，普通角色不可读取。';
COMMENT ON COLUMN iam.message_requests.identifier_id IS '可空；逻辑引用 iam.identifiers.id。';
COMMENT ON COLUMN iam.message_requests.template_version_id IS '逻辑引用 iam.message_template_versions.id。';
COMMENT ON COLUMN iam.message_requests.parameters IS '模板变量；代码按变量 Schema 校验并禁止秘密。';
COMMENT ON COLUMN iam.message_requests.parameter_digest IS '规范化变量 SHA-256 摘要。';
COMMENT ON COLUMN iam.message_requests.caller_scope IS '发送请求调用方作用域。';
COMMENT ON COLUMN iam.message_requests.idempotency_key IS '调用方幂等键；跨分区唯一性由 iam.idempotency_records 保证。';
COMMENT ON COLUMN iam.message_requests.state IS '消息请求状态。';
COMMENT ON COLUMN iam.message_requests.priority IS '非负队列优先级提示。';
COMMENT ON COLUMN iam.message_requests.scheduled_at IS '可空；计划最早发送时间。';
COMMENT ON COLUMN iam.message_requests.expires_at IS '超过后不再发送的时间。';
COMMENT ON COLUMN iam.message_requests.created_at IS '数据库插入时间；用于队列排序、审计和归档查询。';
COMMENT ON COLUMN iam.message_requests.completed_at IS '可空；进入终态时间。';
COMMENT ON CONSTRAINT uq_message_requests_request_id ON iam.message_requests IS '保证消息请求 ID 在数据库内全局唯一并可被投递尝试稳定引用；因此按 request_id Hash 分区。';

CREATE TABLE iam.message_delivery_attempts (
    id uuid NOT NULL,
    request_id uuid NOT NULL,
    provider_id uuid NOT NULL,
    attempt_no integer NOT NULL,
    provider_message_id varchar(256),
    request_digest char(64) NOT NULL,
    response_code varchar(100),
    response_digest char(64),
    delivery_state varchar(40) NOT NULL,
    failure_type varchar(80),
    cost_amount numeric(20,6),
    cost_currency char(3),
    retry_at timestamptz,
    started_at timestamptz NOT NULL,
    completed_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT pk_message_delivery_attempts PRIMARY KEY (id, created_at),
    CONSTRAINT ck_message_attempt_no CHECK (attempt_no > 0),
    CONSTRAINT ck_message_attempt_cost CHECK (cost_amount IS NULL OR cost_amount >= 0)
) PARTITION BY RANGE (created_at);
COMMENT ON TABLE iam.message_delivery_attempts IS '供应商发送和回执尝试事实；按 created_at 月度分区，不保存消息秘密或完整供应商响应。';
COMMENT ON COLUMN iam.message_delivery_attempts.id IS '应用生成的尝试 UUIDv7。';
COMMENT ON COLUMN iam.message_delivery_attempts.request_id IS '逻辑引用 iam.message_requests.request_id。';
COMMENT ON COLUMN iam.message_delivery_attempts.provider_id IS '逻辑引用 iam.message_providers.id。';
COMMENT ON COLUMN iam.message_delivery_attempts.attempt_no IS '请求内正整数尝试序号。';
COMMENT ON COLUMN iam.message_delivery_attempts.provider_message_id IS '可空；供应商返回的消息 ID。';
COMMENT ON COLUMN iam.message_delivery_attempts.request_digest IS '实际供应商请求规范化摘要。';
COMMENT ON COLUMN iam.message_delivery_attempts.response_code IS '可空；供应商结果代码。';
COMMENT ON COLUMN iam.message_delivery_attempts.response_digest IS '可空；受控供应商响应摘要。';
COMMENT ON COLUMN iam.message_delivery_attempts.delivery_state IS '当次投递状态。';
COMMENT ON COLUMN iam.message_delivery_attempts.failure_type IS '可空；规范化失败类型。';
COMMENT ON COLUMN iam.message_delivery_attempts.cost_amount IS '可空；非负供应商成本。';
COMMENT ON COLUMN iam.message_delivery_attempts.cost_currency IS '可空；ISO 4217 三字符币种。';
COMMENT ON COLUMN iam.message_delivery_attempts.retry_at IS '可空；代码计算的下次重试时间。';
COMMENT ON COLUMN iam.message_delivery_attempts.started_at IS '发送开始时间。';
COMMENT ON COLUMN iam.message_delivery_attempts.completed_at IS '可空；供应商调用完成时间。';
COMMENT ON COLUMN iam.message_delivery_attempts.created_at IS '数据库插入时间和月度分区键。';

CREATE TABLE iam.contact_reachability (
    id uuid PRIMARY KEY,
    identifier_id uuid NOT NULL,
    channel varchar(40) NOT NULL,
    reachability_state varchar(40) NOT NULL,
    failure_type varchar(80),
    consecutive_failure_count integer NOT NULL DEFAULT 0,
    last_success_at timestamptz,
    last_failure_at timestamptz,
    verified_at timestamptz,
    updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    row_version bigint NOT NULL DEFAULT 0,
    CONSTRAINT uq_contact_reachability UNIQUE (identifier_id, channel),
    CONSTRAINT ck_contact_failure_count CHECK (consecutive_failure_count >= 0),
    CONSTRAINT ck_contact_reachability_version CHECK (row_version >= 0)
);
COMMENT ON TABLE iam.contact_reachability IS '联系方式按渠道的可达性汇总；状态演进、恢复和是否影响认证由 MSG/AUTH 代码判断。';
COMMENT ON COLUMN iam.contact_reachability.id IS '应用生成的可达性 UUIDv7。';
COMMENT ON COLUMN iam.contact_reachability.identifier_id IS '逻辑引用 iam.identifiers.id。';
COMMENT ON COLUMN iam.contact_reachability.channel IS '消息渠道。';
COMMENT ON COLUMN iam.contact_reachability.reachability_state IS '可达性状态。';
COMMENT ON COLUMN iam.contact_reachability.failure_type IS '可空；最近规范化失败类型。';
COMMENT ON COLUMN iam.contact_reachability.consecutive_failure_count IS '连续失败次数。';
COMMENT ON COLUMN iam.contact_reachability.last_success_at IS '可空；最近投递成功时间。';
COMMENT ON COLUMN iam.contact_reachability.last_failure_at IS '可空；最近投递失败时间。';
COMMENT ON COLUMN iam.contact_reachability.verified_at IS '可空；最近通过独立验证确认时间。';
COMMENT ON COLUMN iam.contact_reachability.updated_at IS '数据库更新时间；由技术 Trigger 自动刷新。';
COMMENT ON COLUMN iam.contact_reachability.row_version IS '乐观锁版本。';

CREATE TABLE iam.message_suppressions (
    id uuid PRIMARY KEY,
    target_digest varchar(256) NOT NULL,
    channel varchar(40) NOT NULL,
    reason_code varchar(100) NOT NULL,
    scope_type varchar(40) NOT NULL,
    scope_id uuid,
    state varchar(40) NOT NULL,
    effective_at timestamptz NOT NULL,
    expires_at timestamptz,
    source_type varchar(40) NOT NULL,
    source_id uuid,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    row_version bigint NOT NULL DEFAULT 0,
    CONSTRAINT uq_message_suppression UNIQUE NULLS NOT DISTINCT (target_digest, channel, scope_type, scope_id, reason_code, effective_at),
    CONSTRAINT ck_message_suppression_expiry CHECK (expires_at IS NULL OR expires_at > effective_at),
    CONSTRAINT ck_message_suppression_version CHECK (row_version >= 0)
);
COMMENT ON TABLE iam.message_suppressions IS '退订、投诉、硬退信和合规限制事实；优先级、渠道例外和安全消息豁免由 MSG 代码执行。';
COMMENT ON COLUMN iam.message_suppressions.id IS '应用生成的抑制记录 UUIDv7。';
COMMENT ON COLUMN iam.message_suppressions.target_digest IS '目标联系方式 HMAC 摘要。';
COMMENT ON COLUMN iam.message_suppressions.channel IS '抑制渠道。';
COMMENT ON COLUMN iam.message_suppressions.reason_code IS '稳定抑制原因码。';
COMMENT ON COLUMN iam.message_suppressions.scope_type IS '抑制作用域类型。';
COMMENT ON COLUMN iam.message_suppressions.scope_id IS '可空；抑制作用域逻辑 ID。';
COMMENT ON COLUMN iam.message_suppressions.state IS '抑制状态。';
COMMENT ON COLUMN iam.message_suppressions.effective_at IS '抑制生效时间。';
COMMENT ON COLUMN iam.message_suppressions.expires_at IS '可空；抑制失效时间。';
COMMENT ON COLUMN iam.message_suppressions.source_type IS '抑制来源类型。';
COMMENT ON COLUMN iam.message_suppressions.source_id IS '可空；来源对象逻辑 ID。';
COMMENT ON COLUMN iam.message_suppressions.created_at IS '数据库插入时间。';
COMMENT ON COLUMN iam.message_suppressions.updated_at IS '数据库更新时间；由技术 Trigger 自动刷新。';
COMMENT ON COLUMN iam.message_suppressions.row_version IS '乐观锁版本。';

CREATE INDEX ix_message_providers_route ON iam.message_providers (channel, region_code, state, priority_hint);
CREATE INDEX ix_message_templates_lookup ON iam.message_template_versions (template_code, channel, locale, state, version DESC);
CREATE INDEX ix_message_requests_queue ON iam.message_requests (state, scheduled_at, priority DESC, created_at);
CREATE INDEX ix_message_requests_target ON iam.message_requests (target_digest, purpose, created_at DESC);
CREATE INDEX ix_message_attempts_request ON iam.message_delivery_attempts (request_id, attempt_no, created_at);
CREATE INDEX ix_message_suppressions_lookup ON iam.message_suppressions (target_digest, channel, state, expires_at);
COMMENT ON INDEX iam.ix_message_requests_queue IS '消息工作者按状态、计划时间和优先级领取请求。';
