-- =============================================================================
-- baseline/schemas/core/tables.sql
-- core Schema 的最终基表、同 Schema 约束、索引及内联 COMMENT
-- PostgreSQL 16+；应用技术栈：.NET 10 + SqlSugar
-- =============================================================================

CREATE TABLE core.security_profile (
    profile_code text        NOT NULL,
    profile_version integer     NOT NULL,
    display_name text        NOT NULL,
    applicability text        NOT NULL,
    minimum_controls jsonb       NOT NULL,
    is_active boolean     NOT NULL DEFAULT true,
    effective_at timestamptz NOT NULL,
    retired_at timestamptz NULL,
    CONSTRAINT pk_security_profile PRIMARY KEY (profile_code, profile_version),
    CONSTRAINT ck_security_profile_code CHECK (profile_code IN ('SP1', 'SP1-D', 'SP2', 'SP3', 'SP4', 'SP5')),
    CONSTRAINT ck_security_profile_window CHECK (retired_at IS NULL OR retired_at > effective_at)
);

COMMENT ON TABLE core.security_profile IS 'REQ-OAP-001/003：Client 安全 Profile 的版本化最小控制集合，含输入受限设备 SP1-D。';

CREATE TABLE core.duration_policy (
    policy_code text        NOT NULL,
    profile_code text        NOT NULL,
    duration_seconds bigint      NOT NULL,
    max_attempts integer     NULL,
    description text        NOT NULL,
    effective_at timestamptz NOT NULL,
    retired_at timestamptz NULL,
    CONSTRAINT pk_duration_policy PRIMARY KEY (policy_code, profile_code, effective_at),
    CONSTRAINT ck_duration_policy_value CHECK (duration_seconds > 0),
    CONSTRAINT ck_duration_policy_attempts CHECK (max_attempts IS NULL OR max_attempts > 0)
);

COMMENT ON TABLE core.duration_policy IS 'TTL-* / TERM-*：登录事务、Challenge、Token、Device Code、冷静期与下载链接等时长基线。';

CREATE TABLE core.data_classification (
    classification_code text     NOT NULL,
    display_name text     NOT NULL,
    sensitivity_rank smallint NOT NULL,
    handling_rules jsonb    NOT NULL,
    CONSTRAINT pk_data_classification PRIMARY KEY (classification_code),
    CONSTRAINT uq_data_classification_rank UNIQUE (sensitivity_rank),
    CONSTRAINT ck_data_classification_rank CHECK (sensitivity_rank BETWEEN 0 AND 9)
);

COMMENT ON TABLE core.data_classification IS 'CAP-PRIV-005：数据分类分级与默认处理要求。';

CREATE TABLE core.error_registry (
    error_code text        NOT NULL,
    contract_kind text        NOT NULL,
    http_status integer     NULL,
    protocol_error text        NULL,
    retryable boolean     NOT NULL,
    user_visible boolean     NOT NULL,
    description text        NOT NULL,
    introduced_version integer     NOT NULL DEFAULT 1,
    deprecated_at timestamptz NULL,
    CONSTRAINT pk_error_registry PRIMARY KEY (error_code),
    CONSTRAINT ck_error_registry_contract CHECK (contract_kind IN ('DOMAIN_API', 'OAUTH', 'OIDC', 'SCIM', 'SAML', 'OPERATION_REASON')),
    CONSTRAINT ck_error_registry_http CHECK (http_status IS NULL OR http_status BETWEEN 400 AND 599)
);

COMMENT ON TABLE core.error_registry IS 'API-G-006/011/019：领域错误、协议错误和 Operation reason_code 的机器可解析注册表。';

CREATE TABLE core.requirement_trace (
    requirement_id text        NOT NULL,
    capability_id text        NOT NULL,
    owner_code text        NOT NULL,
    profile_codes text[]      NOT NULL DEFAULT '{}',
    phase_code text        NOT NULL,
    invariant_ids text[]      NOT NULL DEFAULT '{}',
    api_event_ids text[]      NOT NULL DEFAULT '{}',
    test_ids text[]      NOT NULL DEFAULT '{}',
    slo_ids text[]      NOT NULL DEFAULT '{}',
    evidence_uri text        NULL,
    exception_id uuid        NULL,
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    row_version bigint      NOT NULL DEFAULT 1,
    CONSTRAINT pk_requirement_trace PRIMARY KEY (requirement_id, capability_id, phase_code),
    CONSTRAINT ck_requirement_trace_cap CHECK (capability_id ~ '^CAP-[A-Z]+-[0-9]{3}$'),
    CONSTRAINT ck_requirement_trace_req CHECK (requirement_id ~ '^(REQ|API|EVT|INV)-[A-Z0-9-]+$')
);

COMMENT ON TABLE core.requirement_trace IS '蓝图 §18.4：需求到能力、阶段、测试、SLO、证据与例外的机器可解析追踪矩阵。';

CREATE TABLE core.async_operation (
    id uuid        NOT NULL DEFAULT gen_random_uuid(),
    public_id text        NOT NULL,
    capability_id text        NOT NULL,
    operation_type text        NOT NULL,
    operation_state text        NOT NULL DEFAULT 'PENDING',
    request_hash bytea       NOT NULL,
    idempotency_key text        NOT NULL,
    subject_kind text        NULL,
    subject_ref text        NULL,
    actor_kind text        NOT NULL,
    actor_ref text        NOT NULL,
    tenant_id uuid        NOT NULL DEFAULT '00000000-0000-0000-0000-000000000000',
    business_line_id uuid        NULL,
    saga_type text        NOT NULL,
    current_step integer     NOT NULL DEFAULT 0,
    total_steps integer     NOT NULL DEFAULT 0,
    progress_percent numeric(5,2) NOT NULL DEFAULT 0,
    can_cancel boolean     NOT NULL DEFAULT true,
    requires_human_action boolean     NOT NULL DEFAULT false,
    reason_code text        NULL,
    reason_detail jsonb       NULL,
    policy_version bigint      NULL,
    irreversible_at timestamptz NULL,
    result_ref text        NULL,
    result_payload jsonb       NULL,
    failure_code text        NULL,
    retry_count integer     NOT NULL DEFAULT 0,
    next_retry_at timestamptz NULL,
    trace_id text        NULL,
    correlation_id text        NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    started_at timestamptz NULL,
    completed_at timestamptz NULL,
    cancelled_at timestamptz NULL,
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    row_version bigint      NOT NULL DEFAULT 1,
    blocked_at timestamptz NULL,
    partial_at timestamptz NULL,
    CONSTRAINT pk_async_operation PRIMARY KEY (id),
    CONSTRAINT uq_async_operation_public_id UNIQUE (public_id),
    CONSTRAINT uq_async_operation_idempotency UNIQUE (actor_kind, actor_ref, tenant_id, idempotency_key),
    CONSTRAINT ck_async_operation_capability CHECK (capability_id ~ '^CAP-[A-Z]+-[0-9]{3}$'),
    CONSTRAINT ck_async_operation_state CHECK (operation_state IN ('PENDING', 'RUNNING', 'BLOCKED', 'PARTIAL', 'COMPLETED', 'FAILED', 'CANCELLED')),
    CONSTRAINT ck_async_operation_actor CHECK (actor_kind IN ('USER', 'ADMIN', 'CLIENT', 'MACHINE', 'SYSTEM')),
    CONSTRAINT ck_async_operation_subject CHECK ((subject_kind IS NULL) = (subject_ref IS NULL)),
    CONSTRAINT ck_async_operation_progress CHECK (current_step >= 0 AND total_steps >= 0 AND current_step <= total_steps AND progress_percent BETWEEN 0 AND 100),
    CONSTRAINT ck_async_operation_blocked CHECK (operation_state <> 'BLOCKED' OR (reason_code IS NOT NULL AND requires_human_action)),
    CONSTRAINT ck_async_operation_terminal CHECK (
    (operation_state IN ('COMPLETED', 'FAILED') AND completed_at IS NOT NULL)
    OR (operation_state = 'CANCELLED' AND cancelled_at IS NOT NULL)
    OR operation_state NOT IN ('COMPLETED', 'FAILED', 'CANCELLED')
    ),
    CONSTRAINT ck_async_operation_cancel CHECK (irreversible_at IS NULL OR NOT can_cancel),
    CONSTRAINT ck_async_operation_hash CHECK (octet_length(request_hash) = 32),
    CONSTRAINT ck_async_operation_started CHECK (operation_state NOT IN ('RUNNING', 'BLOCKED', 'PARTIAL', 'COMPLETED', 'FAILED') OR started_at IS NOT NULL),
    CONSTRAINT ck_async_operation_blocked_time CHECK (operation_state <> 'BLOCKED' OR blocked_at IS NOT NULL),
    CONSTRAINT ck_async_operation_partial_time CHECK (operation_state <> 'PARTIAL' OR partial_at IS NOT NULL),
    CONSTRAINT ck_async_operation_failed CHECK (operation_state <> 'FAILED' OR failure_code IS NOT NULL)
);

COMMENT ON TABLE core.async_operation IS 'CAP-API-018 / API-G-013 至 019：跨事务边界操作的统一状态、幂等、权限上下文、检查点、取消边界和最终结果。';

CREATE TABLE core.async_operation_step (
    id uuid        NOT NULL DEFAULT gen_random_uuid(),
    operation_id uuid        NOT NULL,
    step_no integer     NOT NULL,
    step_code text        NOT NULL,
    authority_domain text        NOT NULL,
    step_state text        NOT NULL DEFAULT 'PENDING',
    idempotency_key text        NOT NULL,
    request_hash bytea       NOT NULL,
    compensatable boolean     NOT NULL DEFAULT true,
    irreversible_step boolean     NOT NULL DEFAULT false,
    attempt_count integer     NOT NULL DEFAULT 0,
    last_error_code text        NULL,
    checkpoint jsonb       NULL,
    evidence jsonb       NULL,
    started_at timestamptz NULL,
    completed_at timestamptz NULL,
    next_retry_at timestamptz NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    row_version bigint      NOT NULL DEFAULT 1,
    CONSTRAINT pk_async_operation_step PRIMARY KEY (id),
    CONSTRAINT uq_async_operation_step_no UNIQUE (operation_id, step_no),
    CONSTRAINT uq_async_operation_step_key UNIQUE (operation_id, idempotency_key),
    CONSTRAINT fk_async_operation_step_operation FOREIGN KEY (operation_id) REFERENCES core.async_operation(id) ON DELETE CASCADE,
    CONSTRAINT ck_async_operation_step_state CHECK (step_state IN ('PENDING', 'RUNNING', 'BLOCKED', 'SUCCEEDED', 'FAILED', 'COMPENSATING', 'COMPENSATED', 'SKIPPED', 'MANUAL')),
    CONSTRAINT ck_async_operation_step_hash CHECK (octet_length(request_hash) = 32),
    CONSTRAINT ck_async_operation_step_attempt CHECK (attempt_count >= 0)
);

COMMENT ON TABLE core.async_operation_step IS 'API-G-003/017：Operation 的幂等步骤、权威域、检查点、补偿与不可逆边界证据。';

CREATE TABLE core.idempotency_request (
    id uuid        NOT NULL DEFAULT gen_random_uuid(),
    scope_code text        NOT NULL,
    actor_kind text        NOT NULL,
    actor_ref text        NOT NULL,
    tenant_id uuid        NOT NULL DEFAULT '00000000-0000-0000-0000-000000000000',
    idempotency_key text        NOT NULL,
    request_hash bytea       NOT NULL,
    operation_id uuid        NULL,
    response_status integer     NULL,
    response_headers jsonb       NULL,
    response_body jsonb       NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    completed_at timestamptz NULL,
    expires_at timestamptz NOT NULL,
    CONSTRAINT pk_idempotency_request PRIMARY KEY (id),
    CONSTRAINT uq_idempotency_request UNIQUE (scope_code, actor_kind, actor_ref, tenant_id, idempotency_key),
    CONSTRAINT fk_idempotency_request_operation FOREIGN KEY (operation_id) REFERENCES core.async_operation(id),
    CONSTRAINT ck_idempotency_request_actor CHECK (actor_kind IN ('USER', 'ADMIN', 'CLIENT', 'MACHINE', 'SYSTEM')),
    CONSTRAINT ck_idempotency_request_hash CHECK (octet_length(request_hash) = 32),
    CONSTRAINT ck_idempotency_request_expiry CHECK (expires_at > created_at)
);

COMMENT ON TABLE core.idempotency_request IS 'API-G-001 / INV-G-012：相同幂等键和请求摘要返回原结果，不同请求摘要冲突。';

CREATE INDEX ix_operation_actor ON core.async_operation(actor_kind, actor_ref, created_at DESC);

CREATE INDEX ix_operation_subject ON core.async_operation(subject_kind, subject_ref, created_at DESC);

CREATE INDEX ix_operation_tenant_state ON core.async_operation(tenant_id, operation_state, updated_at DESC);

CREATE INDEX ix_operation_retry ON core.async_operation(next_retry_at) WHERE operation_state IN ('RUNNING', 'BLOCKED', 'PARTIAL');

CREATE INDEX ix_idempotency_expiry ON core.idempotency_request(expires_at);

CREATE INDEX ix_fk_idempotency_request_operation_id ON core.idempotency_request (operation_id);

COMMENT ON COLUMN core.security_profile.profile_code IS '稳定机器可读代码；展示文本由资源或目录解析。';
COMMENT ON COLUMN core.security_profile.profile_version IS '对象、策略或源数据的显式版本；不得以不可信客户端时间戳替代。';
COMMENT ON COLUMN core.security_profile.display_name IS 'core.security_profile.display_name 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN core.security_profile.applicability IS 'core.security_profile.applicability 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN core.security_profile.minimum_controls IS '版本化结构化扩展数据；必须由 .NET 按对应 JSON Schema 校验，不得替代核心状态或外键。';
COMMENT ON COLUMN core.security_profile.is_active IS '显式布尔开关；启用前置条件与失效行为由约束和版本化策略控制。';
COMMENT ON COLUMN core.security_profile.effective_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN core.security_profile.retired_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN core.duration_policy.policy_code IS '稳定机器可读代码；展示文本由资源或目录解析。';
COMMENT ON COLUMN core.duration_policy.profile_code IS '稳定机器可读代码；展示文本由资源或目录解析。';
COMMENT ON COLUMN core.duration_policy.duration_seconds IS '以秒为单位的显式时长；有效范围由安全策略及表约束限制。';
COMMENT ON COLUMN core.duration_policy.max_attempts IS '非负计数器；并发更新使用原子 SQL 或乐观并发控制。';
COMMENT ON COLUMN core.duration_policy.description IS 'core.duration_policy.description 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN core.duration_policy.effective_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN core.duration_policy.retired_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN core.data_classification.classification_code IS '稳定机器可读代码；展示文本由资源或目录解析。';
COMMENT ON COLUMN core.data_classification.display_name IS 'core.data_classification.display_name 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN core.data_classification.sensitivity_rank IS 'core.data_classification.sensitivity_rank 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN core.data_classification.handling_rules IS '版本化结构化扩展数据；必须由 .NET 按对应 JSON Schema 校验，不得替代核心状态或外键。';
COMMENT ON COLUMN core.error_registry.error_code IS '稳定机器可读代码；展示文本由资源或目录解析。';
COMMENT ON COLUMN core.error_registry.contract_kind IS '对象类别判别字段；允许值由 CHECK 或对应注册表限定。';
COMMENT ON COLUMN core.error_registry.http_status IS 'core.error_registry.http_status 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN core.error_registry.protocol_error IS 'core.error_registry.protocol_error 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN core.error_registry.retryable IS 'core.error_registry.retryable 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN core.error_registry.user_visible IS 'core.error_registry.user_visible 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN core.error_registry.description IS 'core.error_registry.description 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN core.error_registry.introduced_version IS '对象、策略或源数据的显式版本；不得以不可信客户端时间戳替代。';
COMMENT ON COLUMN core.error_registry.deprecated_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN core.requirement_trace.requirement_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN core.requirement_trace.capability_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN core.requirement_trace.owner_code IS '稳定机器可读代码；展示文本由资源或目录解析。';
COMMENT ON COLUMN core.requirement_trace.profile_codes IS '代码或引用集合；写入前去重、校验 allowlist，并满足表约束。';
COMMENT ON COLUMN core.requirement_trace.phase_code IS '稳定机器可读代码；展示文本由资源或目录解析。';
COMMENT ON COLUMN core.requirement_trace.invariant_ids IS '代码或引用集合；写入前去重、校验 allowlist，并满足表约束。';
COMMENT ON COLUMN core.requirement_trace.api_event_ids IS '代码或引用集合；写入前去重、校验 allowlist，并满足表约束。';
COMMENT ON COLUMN core.requirement_trace.test_ids IS '代码或引用集合；写入前去重、校验 allowlist，并满足表约束。';
COMMENT ON COLUMN core.requirement_trace.slo_ids IS '代码或引用集合；写入前去重、校验 allowlist，并满足表约束。';
COMMENT ON COLUMN core.requirement_trace.evidence_uri IS '受控 URI；写入前必须执行协议、主机、重定向与 SSRF 安全校验。';
COMMENT ON COLUMN core.requirement_trace.exception_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN core.requirement_trace.updated_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN core.requirement_trace.row_version IS '乐观并发版本；更新必须使用原值 compare-and-set，成功后由数据库单调递增。';
COMMENT ON COLUMN core.async_operation.id IS '内部 UUID 主键；仅用于数据库关系，不作为跨域公开标识。';
COMMENT ON COLUMN core.async_operation.public_id IS '不可复用的公开稳定标识；插入时登记到 core.public_id_ledger。';
COMMENT ON COLUMN core.async_operation.capability_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN core.async_operation.operation_type IS '对象类别判别字段；允许值由 CHECK 或对应注册表限定。';
COMMENT ON COLUMN core.async_operation.operation_state IS '显式状态当前值；合法取值见 CHECK，完整状态转换由 .NET 领域策略执行。';
COMMENT ON COLUMN core.async_operation.request_hash IS '不可逆摘要；用于等值匹配、幂等、完整性或最小化证据，不保存原始敏感值。';
COMMENT ON COLUMN core.async_operation.idempotency_key IS 'core.async_operation.idempotency_key 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN core.async_operation.subject_kind IS '对象类别判别字段；允许值由 CHECK 或对应注册表限定。';
COMMENT ON COLUMN core.async_operation.subject_ref IS '不透明对象引用；不得从格式推断手机号、邮箱或其他业务事实。';
COMMENT ON COLUMN core.async_operation.actor_kind IS '对象类别判别字段；允许值由 CHECK 或对应注册表限定。';
COMMENT ON COLUMN core.async_operation.actor_ref IS '不透明对象引用；不得从格式推断手机号、邮箱或其他业务事实。';
COMMENT ON COLUMN core.async_operation.tenant_id IS '租户隔离键；全零 UUID 表示平台范围，应用查询必须显式携带可信租户上下文。';
COMMENT ON COLUMN core.async_operation.business_line_id IS '业务线隔离键；关联 org.business_line，用于业务线范围隔离。';
COMMENT ON COLUMN core.async_operation.saga_type IS '对象类别判别字段；允许值由 CHECK 或对应注册表限定。';
COMMENT ON COLUMN core.async_operation.current_step IS 'core.async_operation.current_step 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN core.async_operation.total_steps IS 'core.async_operation.total_steps 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN core.async_operation.progress_percent IS 'core.async_operation.progress_percent 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN core.async_operation.can_cancel IS 'core.async_operation.can_cancel 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN core.async_operation.requires_human_action IS 'core.async_operation.requires_human_action 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN core.async_operation.reason_code IS '稳定机器可读代码；展示文本由资源或目录解析。';
COMMENT ON COLUMN core.async_operation.reason_detail IS '版本化结构化扩展数据；必须由 .NET 按对应 JSON Schema 校验，不得替代核心状态或外键。';
COMMENT ON COLUMN core.async_operation.policy_version IS '对象、策略或源数据的显式版本；不得以不可信客户端时间戳替代。';
COMMENT ON COLUMN core.async_operation.irreversible_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN core.async_operation.result_ref IS '不透明对象引用；不得从格式推断手机号、邮箱或其他业务事实。';
COMMENT ON COLUMN core.async_operation.result_payload IS '版本化结构化扩展数据；必须由 .NET 按对应 JSON Schema 校验，不得替代核心状态或外键。';
COMMENT ON COLUMN core.async_operation.failure_code IS '稳定机器可读代码；展示文本由资源或目录解析。';
COMMENT ON COLUMN core.async_operation.retry_count IS '非负计数器；并发更新使用原子 SQL 或乐观并发控制。';
COMMENT ON COLUMN core.async_operation.next_retry_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN core.async_operation.trace_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN core.async_operation.correlation_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN core.async_operation.created_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN core.async_operation.started_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN core.async_operation.completed_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN core.async_operation.cancelled_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN core.async_operation.updated_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN core.async_operation.row_version IS '乐观并发版本；更新必须使用原值 compare-and-set，成功后由数据库单调递增。';
COMMENT ON COLUMN core.async_operation.blocked_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN core.async_operation.partial_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN core.async_operation_step.id IS '内部 UUID 主键；仅用于数据库关系，不作为跨域公开标识。';
COMMENT ON COLUMN core.async_operation_step.operation_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN core.async_operation_step.step_no IS 'core.async_operation_step.step_no 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN core.async_operation_step.step_code IS '稳定机器可读代码；展示文本由资源或目录解析。';
COMMENT ON COLUMN core.async_operation_step.authority_domain IS 'core.async_operation_step.authority_domain 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN core.async_operation_step.step_state IS '显式状态当前值；合法取值见 CHECK，完整状态转换由 .NET 领域策略执行。';
COMMENT ON COLUMN core.async_operation_step.idempotency_key IS 'core.async_operation_step.idempotency_key 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN core.async_operation_step.request_hash IS '不可逆摘要；用于等值匹配、幂等、完整性或最小化证据，不保存原始敏感值。';
COMMENT ON COLUMN core.async_operation_step.compensatable IS 'core.async_operation_step.compensatable 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN core.async_operation_step.irreversible_step IS 'core.async_operation_step.irreversible_step 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN core.async_operation_step.attempt_count IS '非负计数器；并发更新使用原子 SQL 或乐观并发控制。';
COMMENT ON COLUMN core.async_operation_step.last_error_code IS '稳定机器可读代码；展示文本由资源或目录解析。';
COMMENT ON COLUMN core.async_operation_step.checkpoint IS '版本化结构化扩展数据；必须由 .NET 按对应 JSON Schema 校验，不得替代核心状态或外键。';
COMMENT ON COLUMN core.async_operation_step.evidence IS '版本化结构化扩展数据；必须由 .NET 按对应 JSON Schema 校验，不得替代核心状态或外键。';
COMMENT ON COLUMN core.async_operation_step.started_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN core.async_operation_step.completed_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN core.async_operation_step.next_retry_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN core.async_operation_step.created_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN core.async_operation_step.updated_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN core.async_operation_step.row_version IS '乐观并发版本；更新必须使用原值 compare-and-set，成功后由数据库单调递增。';
COMMENT ON COLUMN core.idempotency_request.id IS '内部 UUID 主键；仅用于数据库关系，不作为跨域公开标识。';
COMMENT ON COLUMN core.idempotency_request.scope_code IS '稳定机器可读代码；展示文本由资源或目录解析。';
COMMENT ON COLUMN core.idempotency_request.actor_kind IS '对象类别判别字段；允许值由 CHECK 或对应注册表限定。';
COMMENT ON COLUMN core.idempotency_request.actor_ref IS '不透明对象引用；不得从格式推断手机号、邮箱或其他业务事实。';
COMMENT ON COLUMN core.idempotency_request.tenant_id IS '租户隔离键；全零 UUID 表示平台范围，应用查询必须显式携带可信租户上下文。';
COMMENT ON COLUMN core.idempotency_request.idempotency_key IS 'core.idempotency_request.idempotency_key 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN core.idempotency_request.request_hash IS '不可逆摘要；用于等值匹配、幂等、完整性或最小化证据，不保存原始敏感值。';
COMMENT ON COLUMN core.idempotency_request.operation_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN core.idempotency_request.response_status IS 'core.idempotency_request.response_status 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN core.idempotency_request.response_headers IS '版本化结构化扩展数据；必须由 .NET 按对应 JSON Schema 校验，不得替代核心状态或外键。';
COMMENT ON COLUMN core.idempotency_request.response_body IS '版本化结构化扩展数据；必须由 .NET 按对应 JSON Schema 校验，不得替代核心状态或外键。';
COMMENT ON COLUMN core.idempotency_request.created_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN core.idempotency_request.completed_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN core.idempotency_request.expires_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';

COMMENT ON CONSTRAINT pk_security_profile ON core.security_profile IS '主键约束：唯一标识 core.security_profile 记录。';
COMMENT ON CONSTRAINT ck_security_profile_code ON core.security_profile IS '检查约束：限制 core.security_profile 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_security_profile_window ON core.security_profile IS '检查约束：限制 core.security_profile 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT pk_duration_policy ON core.duration_policy IS '主键约束：唯一标识 core.duration_policy 记录。';
COMMENT ON CONSTRAINT ck_duration_policy_value ON core.duration_policy IS '检查约束：限制 core.duration_policy 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_duration_policy_attempts ON core.duration_policy IS '检查约束：限制 core.duration_policy 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT pk_data_classification ON core.data_classification IS '主键约束：唯一标识 core.data_classification 记录。';
COMMENT ON CONSTRAINT uq_data_classification_rank ON core.data_classification IS '唯一约束：保证 sensitivity_rank 在 core.data_classification 范围内不重复。';
COMMENT ON CONSTRAINT ck_data_classification_rank ON core.data_classification IS '检查约束：限制 core.data_classification 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT pk_error_registry ON core.error_registry IS '主键约束：唯一标识 core.error_registry 记录。';
COMMENT ON CONSTRAINT ck_error_registry_contract ON core.error_registry IS '检查约束：限制 core.error_registry 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_error_registry_http ON core.error_registry IS '检查约束：限制 core.error_registry 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT pk_requirement_trace ON core.requirement_trace IS '主键约束：唯一标识 core.requirement_trace 记录。';
COMMENT ON CONSTRAINT ck_requirement_trace_cap ON core.requirement_trace IS '检查约束：限制 core.requirement_trace 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_requirement_trace_req ON core.requirement_trace IS '检查约束：限制 core.requirement_trace 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT pk_async_operation ON core.async_operation IS '主键约束：唯一标识 core.async_operation 记录。';
COMMENT ON CONSTRAINT uq_async_operation_public_id ON core.async_operation IS '唯一约束：保证 public_id 在 core.async_operation 范围内不重复。';
COMMENT ON CONSTRAINT uq_async_operation_idempotency ON core.async_operation IS '唯一约束：保证 actor_kind、actor_ref、tenant_id、idempotency_key 在 core.async_operation 范围内不重复。';
COMMENT ON CONSTRAINT ck_async_operation_capability ON core.async_operation IS '检查约束：限制 core.async_operation 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_async_operation_state ON core.async_operation IS '检查约束：限制 core.async_operation 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_async_operation_actor ON core.async_operation IS '检查约束：限制 core.async_operation 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_async_operation_subject ON core.async_operation IS '检查约束：限制 core.async_operation 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_async_operation_progress ON core.async_operation IS '检查约束：限制 core.async_operation 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_async_operation_blocked ON core.async_operation IS '检查约束：限制 core.async_operation 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_async_operation_terminal ON core.async_operation IS '检查约束：限制 core.async_operation 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_async_operation_cancel ON core.async_operation IS '检查约束：限制 core.async_operation 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_async_operation_hash ON core.async_operation IS '检查约束：限制 core.async_operation 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_async_operation_started ON core.async_operation IS '检查约束：限制 core.async_operation 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_async_operation_blocked_time ON core.async_operation IS '检查约束：限制 core.async_operation 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_async_operation_partial_time ON core.async_operation IS '检查约束：限制 core.async_operation 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_async_operation_failed ON core.async_operation IS '检查约束：限制 core.async_operation 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT pk_async_operation_step ON core.async_operation_step IS '主键约束：唯一标识 core.async_operation_step 记录。';
COMMENT ON CONSTRAINT uq_async_operation_step_no ON core.async_operation_step IS '唯一约束：保证 operation_id、step_no 在 core.async_operation_step 范围内不重复。';
COMMENT ON CONSTRAINT uq_async_operation_step_key ON core.async_operation_step IS '唯一约束：保证 operation_id、idempotency_key 在 core.async_operation_step 范围内不重复。';
COMMENT ON CONSTRAINT fk_async_operation_step_operation ON core.async_operation_step IS '外键约束：core.async_operation_step 的 operation_id 必须引用 core.async_operation；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT ck_async_operation_step_state ON core.async_operation_step IS '检查约束：限制 core.async_operation_step 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_async_operation_step_hash ON core.async_operation_step IS '检查约束：限制 core.async_operation_step 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_async_operation_step_attempt ON core.async_operation_step IS '检查约束：限制 core.async_operation_step 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT pk_idempotency_request ON core.idempotency_request IS '主键约束：唯一标识 core.idempotency_request 记录。';
COMMENT ON CONSTRAINT uq_idempotency_request ON core.idempotency_request IS '唯一约束：保证 scope_code、actor_kind、actor_ref、tenant_id、idempotency_key 在 core.idempotency_request 范围内不重复。';
COMMENT ON CONSTRAINT fk_idempotency_request_operation ON core.idempotency_request IS '外键约束：core.idempotency_request 的 operation_id 必须引用 core.async_operation；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT ck_idempotency_request_actor ON core.idempotency_request IS '检查约束：限制 core.idempotency_request 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_idempotency_request_hash ON core.idempotency_request IS '检查约束：限制 core.idempotency_request 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_idempotency_request_expiry ON core.idempotency_request IS '检查约束：限制 core.idempotency_request 的字段取值或组合满足结构与安全底线。';

COMMENT ON INDEX core.ix_operation_actor IS '查询索引：优化 core.async_operation 按 actor_kind、actor_ref、created_at 的访问。';
COMMENT ON INDEX core.ix_operation_subject IS '查询索引：优化 core.async_operation 按 subject_kind、subject_ref、created_at 的访问。';
COMMENT ON INDEX core.ix_operation_tenant_state IS '查询索引：优化 core.async_operation 按 tenant_id、operation_state、updated_at 的访问。';
COMMENT ON INDEX core.ix_operation_retry IS '查询索引：优化 core.async_operation 按 next_retry_at 的访问，仅覆盖 WHERE 条件命中的记录。';
COMMENT ON INDEX core.ix_idempotency_expiry IS '查询索引：优化 core.idempotency_request 按 expires_at 的访问。';
COMMENT ON INDEX core.pk_security_profile IS '约束 pk_security_profile 的支撑唯一索引。';
COMMENT ON INDEX core.pk_duration_policy IS '约束 pk_duration_policy 的支撑唯一索引。';
COMMENT ON INDEX core.pk_data_classification IS '约束 pk_data_classification 的支撑唯一索引。';
COMMENT ON INDEX core.uq_data_classification_rank IS '约束 uq_data_classification_rank 的支撑唯一索引。';
COMMENT ON INDEX core.pk_error_registry IS '约束 pk_error_registry 的支撑唯一索引。';
COMMENT ON INDEX core.pk_requirement_trace IS '约束 pk_requirement_trace 的支撑唯一索引。';
COMMENT ON INDEX core.pk_async_operation IS '约束 pk_async_operation 的支撑唯一索引。';
COMMENT ON INDEX core.uq_async_operation_public_id IS '约束 uq_async_operation_public_id 的支撑唯一索引。';
COMMENT ON INDEX core.uq_async_operation_idempotency IS '约束 uq_async_operation_idempotency 的支撑唯一索引。';
COMMENT ON INDEX core.pk_async_operation_step IS '约束 pk_async_operation_step 的支撑唯一索引。';
COMMENT ON INDEX core.uq_async_operation_step_no IS '约束 uq_async_operation_step_no 的支撑唯一索引。';
COMMENT ON INDEX core.uq_async_operation_step_key IS '约束 uq_async_operation_step_key 的支撑唯一索引。';
COMMENT ON INDEX core.pk_idempotency_request IS '约束 pk_idempotency_request 的支撑唯一索引。';
COMMENT ON INDEX core.uq_idempotency_request IS '约束 uq_idempotency_request 的支撑唯一索引。';
COMMENT ON INDEX core.ix_fk_idempotency_request_operation_id IS '查询索引：优化 core.idempotency_request 按 operation_id 的访问。';

