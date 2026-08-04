\set ON_ERROR_STOP on

SET ROLE iam_owner;

-- 通用技术设施：幂等、操作编排存储、事务 Outbox、消费 Inbox 和审计。

CREATE TABLE iam.idempotency_records (
    id uuid PRIMARY KEY,
    caller_scope varchar(200) NOT NULL,
    idempotency_key varchar(200) NOT NULL,
    request_hash char(64) NOT NULL,
    operation_id uuid,
    state varchar(40) NOT NULL,
    response_status integer,
    response_body jsonb,
    expires_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    row_version bigint NOT NULL DEFAULT 0,
    CONSTRAINT uq_idempotency_caller_key UNIQUE (caller_scope, idempotency_key),
    CONSTRAINT ck_idempotency_version CHECK (row_version >= 0),
    CONSTRAINT ck_idempotency_expiry CHECK (expires_at > created_at)
);
COMMENT ON TABLE iam.idempotency_records IS 'API 幂等记录；数据库维持调用方与幂等键唯一，是否同请求及结果复用由应用代码判断。';
COMMENT ON COLUMN iam.idempotency_records.id IS '应用生成的 UUIDv7 内部主键，不对外表达业务语义。';
COMMENT ON COLUMN iam.idempotency_records.caller_scope IS '调用方稳定作用域，由 API 基础设施代码构造并限制长度。';
COMMENT ON COLUMN iam.idempotency_records.idempotency_key IS '调用方提供的幂等键；不得包含敏感数据。';
COMMENT ON COLUMN iam.idempotency_records.request_hash IS '规范化请求的 SHA-256 十六进制摘要，用于识别同键不同请求。';
COMMENT ON COLUMN iam.idempotency_records.operation_id IS '可空；逻辑引用 iam.operations.id；数据库 FK 校验存在性，OPS 代码校验状态和事务归属。';
COMMENT ON COLUMN iam.idempotency_records.state IS '幂等处理状态字符串；合法值与转换由 API 代码维护。';
COMMENT ON COLUMN iam.idempotency_records.response_status IS '可空；首次处理完成后的 HTTP 状态码快照。';
COMMENT ON COLUMN iam.idempotency_records.response_body IS '可空；可安全复用的响应快照，代码负责脱敏和容量限制。';
COMMENT ON COLUMN iam.idempotency_records.expires_at IS '幂等记录技术过期时间，由代码按接口策略计算。';
COMMENT ON COLUMN iam.idempotency_records.created_at IS '数据库插入时间。';
COMMENT ON COLUMN iam.idempotency_records.updated_at IS '数据库更新时间；由技术 Trigger 自动刷新。';
COMMENT ON COLUMN iam.idempotency_records.row_version IS '乐观锁版本；应用使用 expected version 条件更新，成功更新时由技术 Trigger 自动递增。';
COMMENT ON CONSTRAINT uq_idempotency_caller_key ON iam.idempotency_records IS '维持同一调用作用域内幂等键唯一。';

CREATE TABLE iam.operations (
    id uuid PRIMARY KEY,
    operation_type varchar(80) NOT NULL,
    state varchar(40) NOT NULL,
    caller_scope varchar(200) NOT NULL,
    idempotency_key varchar(200) NOT NULL,
    request_digest char(64) NOT NULL,
    capability_code varchar(80) NOT NULL,
    saga_type varchar(80) NOT NULL,
    actor_type varchar(40),
    actor_id uuid,
    subject_type varchar(40),
    subject_id uuid,
    tenant_id uuid,
    current_step varchar(80),
    irreversible_at timestamptz,
    request_payload jsonb NOT NULL DEFAULT '{}'::jsonb,
    result_payload jsonb,
    error_code varchar(100),
    expires_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    completed_at timestamptz,
    row_version bigint NOT NULL DEFAULT 0,
    CONSTRAINT uq_operations_caller_key UNIQUE (caller_scope, idempotency_key),
    CONSTRAINT ck_operations_version CHECK (row_version >= 0),
    CONSTRAINT ck_operations_expiry CHECK (expires_at IS NULL OR expires_at > created_at),
    CONSTRAINT ck_operations_actor_pair CHECK ((actor_type IS NULL) = (actor_id IS NULL)),
    CONSTRAINT ck_operations_subject_pair CHECK ((subject_type IS NULL) = (subject_id IS NULL))
);
COMMENT ON TABLE iam.operations IS '跨域或异步操作的持久化载体；数据库只保存权威状态、检查点、结果和证据，步骤编排、补偿、不可逆边界判断与状态机属于非数据库职责。';
COMMENT ON COLUMN iam.operations.id IS '应用生成的 Operation UUIDv7，可作为 API 查询标识。';
COMMENT ON COLUMN iam.operations.operation_type IS '操作类型代码；代码注册表维护定义，不使用数据库状态字典。';
COMMENT ON COLUMN iam.operations.state IS '操作状态；合法转换由 OPS 状态机维护。';
COMMENT ON COLUMN iam.operations.caller_scope IS '原始调用方稳定作用域快照；与幂等键共同限定 Operation。';
COMMENT ON COLUMN iam.operations.idempotency_key IS '原始幂等键快照；不得包含敏感数据。';
COMMENT ON COLUMN iam.operations.request_digest IS '规范化原始请求的 SHA-256 十六进制摘要。';
COMMENT ON COLUMN iam.operations.capability_code IS '创建 Operation 的能力编号或稳定能力代码，例如 CAP-API-018。';
COMMENT ON COLUMN iam.operations.saga_type IS 'Saga 或长事务编排类型；步骤和补偿规则由代码注册表解释。';
COMMENT ON COLUMN iam.operations.actor_type IS '可空；发起者类型，例如 USER、MACHINE、ADMIN。';
COMMENT ON COLUMN iam.operations.actor_id IS '可空；按 actor_type 逻辑引用主体表，数据库不创建外键。';
COMMENT ON COLUMN iam.operations.subject_type IS '可空；被操作主体类型。';
COMMENT ON COLUMN iam.operations.subject_id IS '可空；按 subject_type 逻辑引用目标表，由代码校验作用域。';
COMMENT ON COLUMN iam.operations.tenant_id IS '可空；逻辑引用 iam.tenants.id，平台级操作为空。';
COMMENT ON COLUMN iam.operations.current_step IS '可空；当前步骤代码快照，不作为数据库流程规则。';
COMMENT ON COLUMN iam.operations.irreversible_at IS '可空；操作越过不可逆边界的业务时间。';
COMMENT ON COLUMN iam.operations.request_payload IS '操作输入快照；代码负责 JSON Schema 校验、脱敏与版本兼容。';
COMMENT ON COLUMN iam.operations.result_payload IS '可空；操作结果快照，禁止写入凭证或完整 Token。';
COMMENT ON COLUMN iam.operations.error_code IS '可空；稳定错误码，解释文本由代码和本地化资源提供。';
COMMENT ON COLUMN iam.operations.expires_at IS '可空；操作等待或查询过期时间，由代码计算。';
COMMENT ON COLUMN iam.operations.created_at IS '数据库插入时间。';
COMMENT ON COLUMN iam.operations.updated_at IS '数据库更新时间；由技术 Trigger 自动刷新。';
COMMENT ON COLUMN iam.operations.completed_at IS '可空；操作进入终态的业务时间。';
COMMENT ON COLUMN iam.operations.row_version IS '数据库自动递增的乐观锁版本；代码只在 WHERE 条件中传入 expected version。';
COMMENT ON CONSTRAINT uq_operations_caller_key ON iam.operations IS '保证同一调用作用域和幂等键只绑定一个 Operation。';

CREATE TABLE iam.operation_steps (
    id uuid PRIMARY KEY,
    operation_id uuid NOT NULL,
    step_code varchar(80) NOT NULL,
    state varchar(40) NOT NULL,
    attempt_count integer NOT NULL DEFAULT 0,
    checkpoint jsonb NOT NULL DEFAULT '{}'::jsonb,
    input_digest char(64),
    output_digest char(64),
    error_code varchar(100),
    next_attempt_at timestamptz,
    started_at timestamptz,
    completed_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    row_version bigint NOT NULL DEFAULT 0,
    CONSTRAINT uq_operation_step UNIQUE (operation_id, step_code),
    CONSTRAINT ck_operation_step_attempt CHECK (attempt_count >= 0),
    CONSTRAINT ck_operation_step_version CHECK (row_version >= 0),
    CONSTRAINT ck_operation_step_time CHECK (
        completed_at IS NULL OR started_at IS NULL OR completed_at >= started_at
    )
);
COMMENT ON TABLE iam.operation_steps IS 'Operation 从属步骤状态和检查点；数据库不执行工作流。';
COMMENT ON COLUMN iam.operation_steps.id IS '应用生成的步骤 UUIDv7。';
COMMENT ON COLUMN iam.operation_steps.operation_id IS '逻辑引用 iam.operations.id；数据库 FK 校验存在性，OPS 仓储校验步骤归属和状态。';
COMMENT ON COLUMN iam.operation_steps.step_code IS '操作类型内稳定步骤代码。';
COMMENT ON COLUMN iam.operation_steps.state IS '步骤状态；合法转换由代码维护。';
COMMENT ON COLUMN iam.operation_steps.attempt_count IS '已执行尝试次数，非负。';
COMMENT ON COLUMN iam.operation_steps.checkpoint IS '幂等恢复检查点；内容由对应步骤处理器定义。';
COMMENT ON COLUMN iam.operation_steps.input_digest IS '可空；步骤输入 SHA-256 摘要。';
COMMENT ON COLUMN iam.operation_steps.output_digest IS '可空；步骤输出 SHA-256 摘要。';
COMMENT ON COLUMN iam.operation_steps.error_code IS '可空；最近一次稳定错误码。';
COMMENT ON COLUMN iam.operation_steps.next_attempt_at IS '可空；代码计算的下次可重试时间。';
COMMENT ON COLUMN iam.operation_steps.started_at IS '可空；本步骤首次开始业务时间。';
COMMENT ON COLUMN iam.operation_steps.completed_at IS '可空；本步骤完成业务时间。';
COMMENT ON COLUMN iam.operation_steps.created_at IS '数据库插入时间。';
COMMENT ON COLUMN iam.operation_steps.updated_at IS '数据库更新时间；由技术 Trigger 自动刷新。';
COMMENT ON COLUMN iam.operation_steps.row_version IS '数据库自动递增的乐观锁版本；代码只在 WHERE 条件中传入 expected version。';

CREATE TABLE iam.operation_policy_versions (
    operation_id uuid NOT NULL,
    policy_version_id uuid NOT NULL,
    apply_order integer NOT NULL,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT pk_operation_policy_versions PRIMARY KEY (operation_id, policy_version_id),
    CONSTRAINT uq_operation_policy_order UNIQUE (operation_id, apply_order),
    CONSTRAINT ck_operation_policy_order CHECK (apply_order >= 0)
);
COMMENT ON TABLE iam.operation_policy_versions IS 'Operation 创建时采用的策略版本快照关系；数据库保护版本存在性和顺序唯一，策略适用性仍由代码判定。';
COMMENT ON COLUMN iam.operation_policy_versions.operation_id IS '逻辑引用 iam.operations.id。';
COMMENT ON COLUMN iam.operation_policy_versions.policy_version_id IS '逻辑引用 iam.policy_versions.id。';
COMMENT ON COLUMN iam.operation_policy_versions.apply_order IS '创建快照中的稳定非负顺序。';
COMMENT ON COLUMN iam.operation_policy_versions.created_at IS '数据库记录时间。';

CREATE TABLE iam.outbox_events (
    id uuid NOT NULL,
    event_id uuid NOT NULL,
    event_type varchar(160) NOT NULL,
    schema_version integer NOT NULL,
    aggregate_type varchar(80) NOT NULL,
    aggregate_id uuid NOT NULL,
    aggregate_version bigint,
    tenant_id uuid,
    business_line_id uuid,
    producer_type varchar(40) NOT NULL,
    producer_id uuid NOT NULL,
    subject_ref_type varchar(40) NOT NULL,
    subject_ref_id varchar(160) NOT NULL,
    actor_type varchar(40),
    actor_id_type varchar(40),
    actor_id varchar(160),
    occurred_at timestamptz NOT NULL,
    data_version bigint,
    trace_id varchar(128) NOT NULL,
    correlation_id varchar(128),
    causation_id varchar(128),
    data_classification varchar(40) NOT NULL,
    payload jsonb NOT NULL,
    headers jsonb NOT NULL DEFAULT '{}'::jsonb,
    publish_state varchar(40) NOT NULL,
    attempt_count integer NOT NULL DEFAULT 0,
    next_attempt_at timestamptz,
    published_at timestamptz,
    recorded_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT pk_outbox_events PRIMARY KEY (id, event_id),
    CONSTRAINT uq_outbox_event_id UNIQUE (event_id),
    CONSTRAINT ck_outbox_schema_version CHECK (schema_version > 0),
    CONSTRAINT ck_outbox_data_version CHECK (data_version IS NULL OR data_version >= 0),
    CONSTRAINT ck_outbox_attempt CHECK (attempt_count >= 0),
    CONSTRAINT ck_outbox_actor_reference CHECK (
        (actor_type IS NULL AND actor_id_type IS NULL AND actor_id IS NULL)
        OR (actor_type IS NOT NULL AND actor_id_type IS NOT NULL AND actor_id IS NOT NULL)
    )
) PARTITION BY HASH (event_id);
COMMENT ON TABLE iam.outbox_events IS '与领域变更同事务写入的事件 Outbox；按 event_id Hash 分区以同时维持全局事件唯一性。发布和重试由 EVENT 代码处理。';
COMMENT ON COLUMN iam.outbox_events.id IS '应用生成的内部记录 UUIDv7；分区主键组成部分。';
COMMENT ON COLUMN iam.outbox_events.event_id IS '应用生成的全局事件 UUID；数据库唯一且为 Hash 分区键。';
COMMENT ON COLUMN iam.outbox_events.event_type IS '稳定事件类型名称。';
COMMENT ON COLUMN iam.outbox_events.schema_version IS '事件契约正整数版本。';
COMMENT ON COLUMN iam.outbox_events.aggregate_type IS '事件聚合类型。';
COMMENT ON COLUMN iam.outbox_events.aggregate_id IS '聚合逻辑 ID；目标表由 aggregate_type 决定，数据库不创建外键。';
COMMENT ON COLUMN iam.outbox_events.aggregate_version IS '可空；领域聚合提交后的版本。';
COMMENT ON COLUMN iam.outbox_events.tenant_id IS '可空；逻辑引用 iam.tenants.id，平台级事件为空。';
COMMENT ON COLUMN iam.outbox_events.business_line_id IS '可空；逻辑引用 iam.business_lines.id，用于业务线隔离和路由。';
COMMENT ON COLUMN iam.outbox_events.producer_type IS '事件生产者主体类型，例如 MACHINE、SERVICE 或 SYSTEM。';
COMMENT ON COLUMN iam.outbox_events.producer_id IS '按 producer_type 逻辑引用机器主体、Client 或系统主体；由代码解析和鉴权。';
COMMENT ON COLUMN iam.outbox_events.subject_ref_type IS '事件主体引用的显式标识类型，例如 GLOBAL_USER_ID、PAIRWISE_SUBJECT 或 RESOURCE_ID。';
COMMENT ON COLUMN iam.outbox_events.subject_ref_id IS '事件主体稳定引用；对外投递前由代码按接收方改写。';
COMMENT ON COLUMN iam.outbox_events.actor_type IS '可空；触发事件的 Actor 类型。';
COMMENT ON COLUMN iam.outbox_events.actor_id_type IS '可空；Actor 标识类型；数据库保证与 actor_type、actor_id 成组为空或成组存在。';
COMMENT ON COLUMN iam.outbox_events.actor_id IS '可空；按 actor_type 与 actor_id_type 逻辑引用自然人、机器主体或 Client；对外事件由代码执行 pairwise 改写或移除。';
COMMENT ON COLUMN iam.outbox_events.occurred_at IS '领域事实实际发生时间，由生产者代码传入。';
COMMENT ON COLUMN iam.outbox_events.data_version IS '可空；事件主体数据版本，用于消费者拒绝旧版本覆盖新版本。';
COMMENT ON COLUMN iam.outbox_events.trace_id IS '端到端追踪 ID。';
COMMENT ON COLUMN iam.outbox_events.correlation_id IS '可空；关联同一业务流程的相关 ID。';
COMMENT ON COLUMN iam.outbox_events.causation_id IS '可空；直接导致本事件的命令或事件 ID。';
COMMENT ON COLUMN iam.outbox_events.data_classification IS '事件载荷敏感级别；订阅、脱敏和加密由代码执行。';
COMMENT ON COLUMN iam.outbox_events.payload IS '事件载荷；代码按事件 Schema 生成并禁止敏感明文。';
COMMENT ON COLUMN iam.outbox_events.headers IS '扩展路由头；核心事件信封字段使用独立列，不得在此隐藏或覆盖。';
COMMENT ON COLUMN iam.outbox_events.publish_state IS '发布状态；状态机由事件发布器维护。';
COMMENT ON COLUMN iam.outbox_events.attempt_count IS '发布尝试次数，非负。';
COMMENT ON COLUMN iam.outbox_events.next_attempt_at IS '可空；代码计算的下次重试时间。';
COMMENT ON COLUMN iam.outbox_events.published_at IS '可空；消息系统确认发布时间。';
COMMENT ON COLUMN iam.outbox_events.recorded_at IS '数据库记录时间，用于审计和保留。';
COMMENT ON CONSTRAINT uq_outbox_event_id ON iam.outbox_events IS '保证事件 ID 全局唯一；因此采用 Hash 而非月度 Range 分区。';

CREATE TABLE iam.inbox_messages (
    id uuid NOT NULL,
    consumer_id varchar(200) NOT NULL,
    event_id uuid NOT NULL,
    event_type varchar(160) NOT NULL,
    aggregate_id uuid,
    aggregate_version bigint,
    state varchar(40) NOT NULL,
    result_digest char(64),
    error_code varchar(100),
    received_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    processed_at timestamptz,
    CONSTRAINT pk_inbox_messages PRIMARY KEY (id, consumer_id, event_id),
    CONSTRAINT uq_inbox_consumer_event UNIQUE (consumer_id, event_id)
) PARTITION BY HASH (consumer_id, event_id);
COMMENT ON TABLE iam.inbox_messages IS '事件消费者幂等记录；按消费者和事件 Hash 分区以维持全局去重，处理语义由消费者代码实现。';
COMMENT ON COLUMN iam.inbox_messages.id IS '应用生成的内部记录 UUIDv7。';
COMMENT ON COLUMN iam.inbox_messages.consumer_id IS '稳定消费者标识，不是数据库账号。';
COMMENT ON COLUMN iam.inbox_messages.event_id IS '消费事件的全局 ID。';
COMMENT ON COLUMN iam.inbox_messages.event_type IS '消费事件类型。';
COMMENT ON COLUMN iam.inbox_messages.aggregate_id IS '可空；事件聚合逻辑 ID。';
COMMENT ON COLUMN iam.inbox_messages.aggregate_version IS '可空；用于代码处理乱序的聚合版本。';
COMMENT ON COLUMN iam.inbox_messages.state IS '处理状态；合法转换由消费代码维护。';
COMMENT ON COLUMN iam.inbox_messages.result_digest IS '可空；处理结果摘要。';
COMMENT ON COLUMN iam.inbox_messages.error_code IS '可空；最近稳定错误码。';
COMMENT ON COLUMN iam.inbox_messages.received_at IS '数据库接收记录时间。';
COMMENT ON COLUMN iam.inbox_messages.processed_at IS '可空；处理完成业务时间。';
COMMENT ON CONSTRAINT uq_inbox_consumer_event ON iam.inbox_messages IS '保证同一消费者只接收一次同一事件；因此采用 Hash 分区。';

CREATE TABLE iam.audit_events (
    id uuid NOT NULL,
    event_id uuid NOT NULL,
    actor_type varchar(40),
    actor_id uuid,
    subject_type varchar(40),
    subject_id uuid,
    tenant_id uuid,
    action varchar(160) NOT NULL,
    object_type varchar(80) NOT NULL,
    object_id uuid,
    outcome varchar(40) NOT NULL,
    reason_code varchar(100),
    before_digest char(64),
    after_digest char(64),
    approval_case_id uuid,
    trace_id varchar(64),
    source_ip inet,
    attributes jsonb NOT NULL DEFAULT '{}'::jsonb,
    occurred_at timestamptz NOT NULL,
    recorded_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT pk_audit_events PRIMARY KEY (id, event_id),
    CONSTRAINT uq_audit_events_event_id UNIQUE (event_id),
    CONSTRAINT ck_audit_actor_pair CHECK ((actor_type IS NULL) = (actor_id IS NULL)),
    CONSTRAINT ck_audit_subject_pair CHECK ((subject_type IS NULL) = (subject_id IS NULL))
) PARTITION BY HASH (event_id);
COMMENT ON TABLE iam.audit_events IS '不可变追加审计事件；按 event_id Hash 分区并由数据库保证事件 ID 全局唯一，禁止应用角色更新或删除。';
COMMENT ON COLUMN iam.audit_events.id IS '应用生成的审计记录 UUIDv7；与 event_id 组成分区主键。';
COMMENT ON COLUMN iam.audit_events.event_id IS '应用生成的审计事件 ID；数据库全局唯一。';
COMMENT ON COLUMN iam.audit_events.actor_type IS '可空；操作者类型，系统自动动作可为空。';
COMMENT ON COLUMN iam.audit_events.actor_id IS '可空；按 actor_type 逻辑引用主体表，数据库不创建外键。';
COMMENT ON COLUMN iam.audit_events.subject_type IS '可空；被影响主体类型。';
COMMENT ON COLUMN iam.audit_events.subject_id IS '可空；按 subject_type 逻辑引用主体表。';
COMMENT ON COLUMN iam.audit_events.tenant_id IS '可空；逻辑引用 iam.tenants.id。';
COMMENT ON COLUMN iam.audit_events.action IS '稳定审计动作代码。';
COMMENT ON COLUMN iam.audit_events.object_type IS '被操作对象类型。';
COMMENT ON COLUMN iam.audit_events.object_id IS '可空；被操作对象逻辑 ID。';
COMMENT ON COLUMN iam.audit_events.outcome IS '动作结果代码；枚举由 OBS 代码定义。';
COMMENT ON COLUMN iam.audit_events.reason_code IS '可空；稳定原因码。';
COMMENT ON COLUMN iam.audit_events.before_digest IS '可空；变更前规范化数据摘要，不保存敏感明文。';
COMMENT ON COLUMN iam.audit_events.after_digest IS '可空；变更后规范化数据摘要。';
COMMENT ON COLUMN iam.audit_events.approval_case_id IS '可空；逻辑引用 iam.approval_cases.id。';
COMMENT ON COLUMN iam.audit_events.trace_id IS '可空；跨服务追踪 ID。';
COMMENT ON COLUMN iam.audit_events.source_ip IS '可空；来源 IP，属于受限个人数据。';
COMMENT ON COLUMN iam.audit_events.attributes IS '扩展审计属性；代码执行白名单和脱敏。';
COMMENT ON COLUMN iam.audit_events.occurred_at IS '动作实际发生时间，由代码传入。';
COMMENT ON COLUMN iam.audit_events.recorded_at IS '数据库落库时间；用于时间范围查询、归档和留存判断。';
COMMENT ON CONSTRAINT uq_audit_events_event_id ON iam.audit_events IS '保证审计事件 ID 在数据库内全局唯一；因此按 event_id Hash 分区。';

CREATE INDEX ix_idempotency_expiry ON iam.idempotency_records (expires_at);
CREATE INDEX ix_operations_queue ON iam.operations (state, updated_at);
CREATE INDEX ix_operations_subject ON iam.operations (subject_type, subject_id, created_at DESC);
CREATE INDEX ix_operation_steps_queue ON iam.operation_steps (state, next_attempt_at);
CREATE INDEX ix_operation_policy_versions_policy ON iam.operation_policy_versions (policy_version_id, operation_id);
CREATE INDEX ix_outbox_publish_queue ON iam.outbox_events (publish_state, next_attempt_at, recorded_at);
CREATE INDEX ix_inbox_state ON iam.inbox_messages (consumer_id, state, received_at);
CREATE INDEX ix_audit_subject_time ON iam.audit_events (subject_type, subject_id, occurred_at DESC);
CREATE INDEX ix_audit_tenant_time ON iam.audit_events (tenant_id, occurred_at DESC);
COMMENT ON INDEX iam.ix_outbox_publish_queue IS '事件发布器按状态和下次重试时间领取任务。';
COMMENT ON INDEX iam.ix_audit_subject_time IS '按主体追溯审计事件的分区索引。';
