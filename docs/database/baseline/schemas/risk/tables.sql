-- =============================================================================
-- baseline/schemas/risk/tables.sql
-- risk Schema 的最终基表、同 Schema 约束、索引及内联 COMMENT
-- PostgreSQL 16+；应用技术栈：.NET 10 + SqlSugar
-- =============================================================================

CREATE TABLE risk.risk_policy_release (
    id uuid        NOT NULL DEFAULT gen_random_uuid(),
    public_id text        NOT NULL,
    policy_code text        NOT NULL,
    policy_version bigint      NOT NULL,
    policy_state text        NOT NULL DEFAULT 'DRAFT',
    content_hash bytea       NOT NULL,
    model_version text        NULL,
    owner_ref text        NOT NULL,
    approval_case_id uuid        NULL,
    rollout_percentage numeric(5,2) NOT NULL DEFAULT 0,
    emergency_disabled boolean     NOT NULL DEFAULT false,
    activated_at timestamptz NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    approval_execution_id uuid NULL,
    retired_at timestamptz NULL,
    revoked_at timestamptz NULL,
    CONSTRAINT pk_risk_policy_release PRIMARY KEY (id),
    CONSTRAINT uq_risk_policy_release_public_id UNIQUE (public_id),
    CONSTRAINT uq_risk_policy_release_version UNIQUE (policy_code, policy_version),
    CONSTRAINT ck_risk_policy_release_state CHECK (policy_state IN ('DRAFT', 'VALIDATED', 'APPROVED', 'STAGED', 'ACTIVE', 'DEPRECATED', 'REVOKED')),
    CONSTRAINT ck_risk_policy_release_hash CHECK (octet_length(content_hash) = 32),
    CONSTRAINT ck_risk_policy_release_rollout CHECK (rollout_percentage BETWEEN 0 AND 100),
    CONSTRAINT ck_risk_policy_release_state_times CHECK (
    (activated_at IS NULL OR policy_state IN ('ACTIVE', 'DEPRECATED', 'REVOKED'))
    AND (retired_at IS NULL OR policy_state = 'DEPRECATED')
    AND (revoked_at IS NULL OR policy_state = 'REVOKED')
    AND (policy_state <> 'ACTIVE' OR activated_at IS NOT NULL)
    AND (policy_state <> 'DEPRECATED' OR (activated_at IS NOT NULL AND retired_at IS NOT NULL))
    AND ((policy_state = 'REVOKED') = (revoked_at IS NOT NULL))
    )
);

COMMENT ON TABLE risk.risk_policy_release IS 'REQ-RISK-002：可解释、灰度、回滚和紧急关闭的不可变风险策略/模型版本。';

CREATE TABLE risk.risk_signal (
    id uuid        NOT NULL DEFAULT gen_random_uuid(),
    signal_type text        NOT NULL,
    source_kind text        NOT NULL,
    source_ref text        NOT NULL,
    subject_kind text        NOT NULL,
    subject_ref text        NOT NULL,
    actor_kind text        NULL,
    actor_ref text        NULL,
    tenant_id uuid        NOT NULL DEFAULT '00000000-0000-0000-0000-000000000000',
    confidence numeric(5,4) NOT NULL,
    signal_value jsonb       NOT NULL,
    signal_hash bytea       NOT NULL,
    observed_at timestamptz NOT NULL,
    received_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    retain_until timestamptz NOT NULL,
    correlation_id text        NULL,
    CONSTRAINT pk_risk_signal PRIMARY KEY (id),
    CONSTRAINT ck_risk_signal_actor CHECK ((actor_kind IS NULL) = (actor_ref IS NULL)),
    CONSTRAINT ck_risk_signal_confidence CHECK (confidence BETWEEN 0 AND 1),
    CONSTRAINT ck_risk_signal_hash CHECK (octet_length(signal_hash) = 32),
    CONSTRAINT ck_risk_signal_retention CHECK (retain_until > received_at)
);

COMMENT ON TABLE risk.risk_signal IS 'REQ-RISK-001/007：来源、时间、置信度、主体、最小化值和保留期明确的追加型安全信号。';

CREATE TABLE risk.risk_assessment (
    id uuid        NOT NULL DEFAULT gen_random_uuid(),
    public_id text        NOT NULL,
    assessment_kind text        NOT NULL,
    subject_kind text        NOT NULL,
    subject_ref text        NOT NULL,
    actor_kind text        NULL,
    actor_ref text        NULL,
    tenant_id uuid        NOT NULL DEFAULT '00000000-0000-0000-0000-000000000000',
    input_hash bytea       NOT NULL,
    risk_level text        NOT NULL,
    disposition text        NOT NULL,
    reason_codes text[]      NOT NULL DEFAULT '{}',
    evidence_freshness jsonb       NOT NULL,
    policy_id uuid        NOT NULL,
    policy_version bigint      NOT NULL,
    supersedes_id uuid        NULL,
    manual_override boolean     NOT NULL DEFAULT false,
    override_reason text        NULL,
    assessed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    valid_until timestamptz NOT NULL,
    CONSTRAINT pk_risk_assessment PRIMARY KEY (id),
    CONSTRAINT uq_risk_assessment_public_id UNIQUE (public_id),
    CONSTRAINT fk_risk_assessment_policy FOREIGN KEY (policy_id) REFERENCES risk.risk_policy_release(id),
    CONSTRAINT fk_risk_assessment_supersedes FOREIGN KEY (supersedes_id) REFERENCES risk.risk_assessment(id),
    CONSTRAINT ck_risk_assessment_actor CHECK ((actor_kind IS NULL) = (actor_ref IS NULL)),
    CONSTRAINT ck_risk_assessment_level CHECK (risk_level IN ('UNKNOWN', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    CONSTRAINT ck_risk_assessment_disposition CHECK (disposition IN ('ALLOW', 'CHALLENGE', 'STEP_UP', 'WAIT', 'REVIEW', 'DENY', 'FREEZE')),
    CONSTRAINT ck_risk_assessment_hash CHECK (octet_length(input_hash) = 32),
    CONSTRAINT ck_risk_assessment_override CHECK ((manual_override AND override_reason IS NOT NULL) OR (NOT manual_override AND override_reason IS NULL)),
    CONSTRAINT ck_risk_assessment_ttl CHECK (valid_until >= assessed_at)
);

COMMENT ON TABLE risk.risk_assessment IS 'REQ-RISK-009：不可变 risk_level 与独立 disposition、策略版本、输入摘要、新鲜度及人工改判证据。';

CREATE TABLE risk.security_case (
    id uuid        NOT NULL DEFAULT gen_random_uuid(),
    public_id text        NOT NULL,
    case_type text        NOT NULL,
    case_state text        NOT NULL DEFAULT 'OPEN',
    severity text        NOT NULL,
    subject_refs jsonb       NOT NULL,
    related_assessment_ids uuid[]     NOT NULL DEFAULT '{}',
    owner_ref text        NOT NULL,
    evidence_hold_id uuid        NULL,
    resolution_code text        NULL,
    opened_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    resolved_at timestamptz NULL,
    closed_at timestamptz NULL,
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    row_version bigint      NOT NULL DEFAULT 1,
    CONSTRAINT pk_security_case PRIMARY KEY (id),
    CONSTRAINT uq_security_case_public_id UNIQUE (public_id),
    CONSTRAINT ck_security_case_state CHECK (case_state IN ('OPEN', 'INVESTIGATING', 'CONTAINED', 'RESOLVED', 'CLOSED')),
    CONSTRAINT ck_security_case_severity CHECK (severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    CONSTRAINT ck_security_case_resolved CHECK (case_state NOT IN ('RESOLVED', 'CLOSED') OR resolved_at IS NOT NULL),
    CONSTRAINT ck_security_case_closed CHECK ((case_state = 'CLOSED') = (closed_at IS NOT NULL))
);

COMMENT ON TABLE risk.security_case IS 'REQ-RISK-008：账号接管、Client 失陷、异常管理员等安全案件的调查、证据保全、处置与复盘。';

CREATE TABLE risk.denylist_entry (
    id uuid        NOT NULL DEFAULT gen_random_uuid(),
    entry_kind text        NOT NULL,
    value_hash bytea       NOT NULL,
    scope_kind text        NOT NULL,
    scope_ref text        NULL,
    reason_code text        NOT NULL,
    source_case_id uuid        NULL,
    starts_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    expires_at timestamptz NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT pk_denylist_entry PRIMARY KEY (id),
    CONSTRAINT uq_denylist_entry UNIQUE NULLS NOT DISTINCT (entry_kind, value_hash, scope_kind, scope_ref),
    CONSTRAINT fk_denylist_entry_case FOREIGN KEY (source_case_id) REFERENCES risk.security_case(id),
    CONSTRAINT ck_denylist_entry_kind CHECK (entry_kind IN ('IP', 'DEVICE', 'IDENTIFIER', 'JTI', 'CLIENT', 'KEY', 'DOMAIN')),
    CONSTRAINT ck_denylist_entry_scope CHECK (scope_kind IN ('GLOBAL', 'BUSINESS_LINE', 'TENANT', 'CLIENT')),
    CONSTRAINT ck_denylist_entry_hash CHECK (octet_length(value_hash) = 32),
    CONSTRAINT ck_denylist_entry_window CHECK (expires_at IS NULL OR expires_at > starts_at)
);

COMMENT ON TABLE risk.denylist_entry IS '风险处置使用的范围化摘要拒绝名单；不保存原始 IP、标识或 Token。';

CREATE INDEX ix_risk_signal_subject ON risk.risk_signal(subject_kind, subject_ref, observed_at DESC);

CREATE INDEX ix_risk_assessment_subject ON risk.risk_assessment(subject_kind, subject_ref, assessed_at DESC);

CREATE UNIQUE INDEX ux_risk_policy_active ON risk.risk_policy_release(policy_code) WHERE policy_state = 'ACTIVE';

CREATE INDEX ix_fk_risk_assessment_policy_id ON risk.risk_assessment (policy_id);

CREATE INDEX ix_fk_risk_assessment_supersedes_id ON risk.risk_assessment (supersedes_id);

CREATE INDEX ix_fk_denylist_entry_source_case_id ON risk.denylist_entry (source_case_id);

COMMENT ON COLUMN risk.risk_policy_release.id IS '内部 UUID 主键；仅用于数据库关系，不作为跨域公开标识。';
COMMENT ON COLUMN risk.risk_policy_release.public_id IS '不可复用的公开稳定标识；插入时登记到 core.public_id_ledger。';
COMMENT ON COLUMN risk.risk_policy_release.policy_code IS '稳定机器可读代码；展示文本由资源或目录解析。';
COMMENT ON COLUMN risk.risk_policy_release.policy_version IS '对象、策略或源数据的显式版本；不得以不可信客户端时间戳替代。';
COMMENT ON COLUMN risk.risk_policy_release.policy_state IS '显式状态当前值；合法取值见 CHECK，完整状态转换由 .NET 领域策略执行。';
COMMENT ON COLUMN risk.risk_policy_release.content_hash IS '不可逆摘要；用于等值匹配、幂等、完整性或最小化证据，不保存原始敏感值。';
COMMENT ON COLUMN risk.risk_policy_release.model_version IS '对象、策略或源数据的显式版本；不得以不可信客户端时间戳替代。';
COMMENT ON COLUMN risk.risk_policy_release.owner_ref IS '不透明对象引用；不得从格式推断手机号、邮箱或其他业务事实。';
COMMENT ON COLUMN risk.risk_policy_release.approval_case_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN risk.risk_policy_release.rollout_percentage IS 'risk.risk_policy_release.rollout_percentage 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN risk.risk_policy_release.emergency_disabled IS 'risk.risk_policy_release.emergency_disabled 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN risk.risk_policy_release.activated_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN risk.risk_policy_release.created_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN risk.risk_policy_release.approval_execution_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN risk.risk_policy_release.retired_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN risk.risk_policy_release.revoked_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN risk.risk_signal.id IS '内部 UUID 主键；仅用于数据库关系，不作为跨域公开标识。';
COMMENT ON COLUMN risk.risk_signal.signal_type IS '对象类别判别字段；允许值由 CHECK 或对应注册表限定。';
COMMENT ON COLUMN risk.risk_signal.source_kind IS '对象类别判别字段；允许值由 CHECK 或对应注册表限定。';
COMMENT ON COLUMN risk.risk_signal.source_ref IS '不透明对象引用；不得从格式推断手机号、邮箱或其他业务事实。';
COMMENT ON COLUMN risk.risk_signal.subject_kind IS '对象类别判别字段；允许值由 CHECK 或对应注册表限定。';
COMMENT ON COLUMN risk.risk_signal.subject_ref IS '不透明对象引用；不得从格式推断手机号、邮箱或其他业务事实。';
COMMENT ON COLUMN risk.risk_signal.actor_kind IS '对象类别判别字段；允许值由 CHECK 或对应注册表限定。';
COMMENT ON COLUMN risk.risk_signal.actor_ref IS '不透明对象引用；不得从格式推断手机号、邮箱或其他业务事实。';
COMMENT ON COLUMN risk.risk_signal.tenant_id IS '租户隔离键；全零 UUID 表示平台范围，应用查询必须显式携带可信租户上下文。';
COMMENT ON COLUMN risk.risk_signal.confidence IS 'risk.risk_signal.confidence 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN risk.risk_signal.signal_value IS '版本化结构化扩展数据；必须由 .NET 按对应 JSON Schema 校验，不得替代核心状态或外键。';
COMMENT ON COLUMN risk.risk_signal.signal_hash IS '不可逆摘要；用于等值匹配、幂等、完整性或最小化证据，不保存原始敏感值。';
COMMENT ON COLUMN risk.risk_signal.observed_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN risk.risk_signal.received_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN risk.risk_signal.retain_until IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN risk.risk_signal.correlation_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN risk.risk_assessment.id IS '内部 UUID 主键；仅用于数据库关系，不作为跨域公开标识。';
COMMENT ON COLUMN risk.risk_assessment.public_id IS '不可复用的公开稳定标识；插入时登记到 core.public_id_ledger。';
COMMENT ON COLUMN risk.risk_assessment.assessment_kind IS '对象类别判别字段；允许值由 CHECK 或对应注册表限定。';
COMMENT ON COLUMN risk.risk_assessment.subject_kind IS '对象类别判别字段；允许值由 CHECK 或对应注册表限定。';
COMMENT ON COLUMN risk.risk_assessment.subject_ref IS '不透明对象引用；不得从格式推断手机号、邮箱或其他业务事实。';
COMMENT ON COLUMN risk.risk_assessment.actor_kind IS '对象类别判别字段；允许值由 CHECK 或对应注册表限定。';
COMMENT ON COLUMN risk.risk_assessment.actor_ref IS '不透明对象引用；不得从格式推断手机号、邮箱或其他业务事实。';
COMMENT ON COLUMN risk.risk_assessment.tenant_id IS '租户隔离键；全零 UUID 表示平台范围，应用查询必须显式携带可信租户上下文。';
COMMENT ON COLUMN risk.risk_assessment.input_hash IS '不可逆摘要；用于等值匹配、幂等、完整性或最小化证据，不保存原始敏感值。';
COMMENT ON COLUMN risk.risk_assessment.risk_level IS 'risk.risk_assessment.risk_level 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN risk.risk_assessment.disposition IS 'risk.risk_assessment.disposition 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN risk.risk_assessment.reason_codes IS '代码或引用集合；写入前去重、校验 allowlist，并满足表约束。';
COMMENT ON COLUMN risk.risk_assessment.evidence_freshness IS '版本化结构化扩展数据；必须由 .NET 按对应 JSON Schema 校验，不得替代核心状态或外键。';
COMMENT ON COLUMN risk.risk_assessment.policy_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN risk.risk_assessment.policy_version IS '对象、策略或源数据的显式版本；不得以不可信客户端时间戳替代。';
COMMENT ON COLUMN risk.risk_assessment.supersedes_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN risk.risk_assessment.manual_override IS 'risk.risk_assessment.manual_override 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN risk.risk_assessment.override_reason IS 'risk.risk_assessment.override_reason 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN risk.risk_assessment.assessed_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN risk.risk_assessment.valid_until IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN risk.security_case.id IS '内部 UUID 主键；仅用于数据库关系，不作为跨域公开标识。';
COMMENT ON COLUMN risk.security_case.public_id IS '不可复用的公开稳定标识；插入时登记到 core.public_id_ledger。';
COMMENT ON COLUMN risk.security_case.case_type IS '对象类别判别字段；允许值由 CHECK 或对应注册表限定。';
COMMENT ON COLUMN risk.security_case.case_state IS '显式状态当前值；合法取值见 CHECK，完整状态转换由 .NET 领域策略执行。';
COMMENT ON COLUMN risk.security_case.severity IS 'risk.security_case.severity 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN risk.security_case.subject_refs IS '版本化结构化扩展数据；必须由 .NET 按对应 JSON Schema 校验，不得替代核心状态或外键。';
COMMENT ON COLUMN risk.security_case.related_assessment_ids IS '代码或引用集合；写入前去重、校验 allowlist，并满足表约束。';
COMMENT ON COLUMN risk.security_case.owner_ref IS '不透明对象引用；不得从格式推断手机号、邮箱或其他业务事实。';
COMMENT ON COLUMN risk.security_case.evidence_hold_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN risk.security_case.resolution_code IS '稳定机器可读代码；展示文本由资源或目录解析。';
COMMENT ON COLUMN risk.security_case.opened_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN risk.security_case.resolved_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN risk.security_case.closed_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN risk.security_case.updated_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN risk.security_case.row_version IS '乐观并发版本；更新必须使用原值 compare-and-set，成功后由数据库单调递增。';
COMMENT ON COLUMN risk.denylist_entry.id IS '内部 UUID 主键；仅用于数据库关系，不作为跨域公开标识。';
COMMENT ON COLUMN risk.denylist_entry.entry_kind IS '对象类别判别字段；允许值由 CHECK 或对应注册表限定。';
COMMENT ON COLUMN risk.denylist_entry.value_hash IS '不可逆摘要；用于等值匹配、幂等、完整性或最小化证据，不保存原始敏感值。';
COMMENT ON COLUMN risk.denylist_entry.scope_kind IS '对象类别判别字段；允许值由 CHECK 或对应注册表限定。';
COMMENT ON COLUMN risk.denylist_entry.scope_ref IS '不透明对象引用；不得从格式推断手机号、邮箱或其他业务事实。';
COMMENT ON COLUMN risk.denylist_entry.reason_code IS '稳定机器可读代码；展示文本由资源或目录解析。';
COMMENT ON COLUMN risk.denylist_entry.source_case_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN risk.denylist_entry.starts_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN risk.denylist_entry.expires_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN risk.denylist_entry.created_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';

COMMENT ON CONSTRAINT pk_risk_policy_release ON risk.risk_policy_release IS '主键约束：唯一标识 risk.risk_policy_release 记录。';
COMMENT ON CONSTRAINT uq_risk_policy_release_public_id ON risk.risk_policy_release IS '唯一约束：保证 public_id 在 risk.risk_policy_release 范围内不重复。';
COMMENT ON CONSTRAINT uq_risk_policy_release_version ON risk.risk_policy_release IS '唯一约束：保证 policy_code、policy_version 在 risk.risk_policy_release 范围内不重复。';
COMMENT ON CONSTRAINT ck_risk_policy_release_state ON risk.risk_policy_release IS '检查约束：限制 risk.risk_policy_release 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_risk_policy_release_hash ON risk.risk_policy_release IS '检查约束：限制 risk.risk_policy_release 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_risk_policy_release_rollout ON risk.risk_policy_release IS '检查约束：限制 risk.risk_policy_release 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_risk_policy_release_state_times ON risk.risk_policy_release IS '检查约束：限制 risk.risk_policy_release 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT pk_risk_signal ON risk.risk_signal IS '主键约束：唯一标识 risk.risk_signal 记录。';
COMMENT ON CONSTRAINT ck_risk_signal_actor ON risk.risk_signal IS '检查约束：限制 risk.risk_signal 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_risk_signal_confidence ON risk.risk_signal IS '检查约束：限制 risk.risk_signal 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_risk_signal_hash ON risk.risk_signal IS '检查约束：限制 risk.risk_signal 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_risk_signal_retention ON risk.risk_signal IS '检查约束：限制 risk.risk_signal 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT pk_risk_assessment ON risk.risk_assessment IS '主键约束：唯一标识 risk.risk_assessment 记录。';
COMMENT ON CONSTRAINT uq_risk_assessment_public_id ON risk.risk_assessment IS '唯一约束：保证 public_id 在 risk.risk_assessment 范围内不重复。';
COMMENT ON CONSTRAINT fk_risk_assessment_policy ON risk.risk_assessment IS '外键约束：risk.risk_assessment 的 policy_id 必须引用 risk.risk_policy_release；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT fk_risk_assessment_supersedes ON risk.risk_assessment IS '外键约束：risk.risk_assessment 的 supersedes_id 必须引用 risk.risk_assessment；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT ck_risk_assessment_actor ON risk.risk_assessment IS '检查约束：限制 risk.risk_assessment 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_risk_assessment_level ON risk.risk_assessment IS '检查约束：限制 risk.risk_assessment 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_risk_assessment_disposition ON risk.risk_assessment IS '检查约束：限制 risk.risk_assessment 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_risk_assessment_hash ON risk.risk_assessment IS '检查约束：限制 risk.risk_assessment 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_risk_assessment_override ON risk.risk_assessment IS '检查约束：限制 risk.risk_assessment 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_risk_assessment_ttl ON risk.risk_assessment IS '检查约束：限制 risk.risk_assessment 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT pk_security_case ON risk.security_case IS '主键约束：唯一标识 risk.security_case 记录。';
COMMENT ON CONSTRAINT uq_security_case_public_id ON risk.security_case IS '唯一约束：保证 public_id 在 risk.security_case 范围内不重复。';
COMMENT ON CONSTRAINT ck_security_case_state ON risk.security_case IS '检查约束：限制 risk.security_case 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_security_case_severity ON risk.security_case IS '检查约束：限制 risk.security_case 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_security_case_resolved ON risk.security_case IS '检查约束：限制 risk.security_case 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_security_case_closed ON risk.security_case IS '检查约束：限制 risk.security_case 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT pk_denylist_entry ON risk.denylist_entry IS '主键约束：唯一标识 risk.denylist_entry 记录。';
COMMENT ON CONSTRAINT uq_denylist_entry ON risk.denylist_entry IS '唯一约束：保证 entry_kind、value_hash、scope_kind、scope_ref 在 risk.denylist_entry 范围内不重复。';
COMMENT ON CONSTRAINT fk_denylist_entry_case ON risk.denylist_entry IS '外键约束：risk.denylist_entry 的 source_case_id 必须引用 risk.security_case；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT ck_denylist_entry_kind ON risk.denylist_entry IS '检查约束：限制 risk.denylist_entry 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_denylist_entry_scope ON risk.denylist_entry IS '检查约束：限制 risk.denylist_entry 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_denylist_entry_hash ON risk.denylist_entry IS '检查约束：限制 risk.denylist_entry 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_denylist_entry_window ON risk.denylist_entry IS '检查约束：限制 risk.denylist_entry 的字段取值或组合满足结构与安全底线。';

COMMENT ON INDEX risk.ix_risk_signal_subject IS '查询索引：优化 risk.risk_signal 按 subject_kind、subject_ref、observed_at 的访问。';
COMMENT ON INDEX risk.ix_risk_assessment_subject IS '查询索引：优化 risk.risk_assessment 按 subject_kind、subject_ref、assessed_at 的访问。';
COMMENT ON INDEX risk.ux_risk_policy_active IS '查询索引：优化 risk.risk_policy_release 按 policy_code 的访问，仅覆盖 WHERE 条件命中的记录。';
COMMENT ON INDEX risk.pk_risk_policy_release IS '约束 pk_risk_policy_release 的支撑唯一索引。';
COMMENT ON INDEX risk.uq_risk_policy_release_public_id IS '约束 uq_risk_policy_release_public_id 的支撑唯一索引。';
COMMENT ON INDEX risk.uq_risk_policy_release_version IS '约束 uq_risk_policy_release_version 的支撑唯一索引。';
COMMENT ON INDEX risk.pk_risk_signal IS '约束 pk_risk_signal 的支撑唯一索引。';
COMMENT ON INDEX risk.pk_risk_assessment IS '约束 pk_risk_assessment 的支撑唯一索引。';
COMMENT ON INDEX risk.uq_risk_assessment_public_id IS '约束 uq_risk_assessment_public_id 的支撑唯一索引。';
COMMENT ON INDEX risk.pk_security_case IS '约束 pk_security_case 的支撑唯一索引。';
COMMENT ON INDEX risk.uq_security_case_public_id IS '约束 uq_security_case_public_id 的支撑唯一索引。';
COMMENT ON INDEX risk.pk_denylist_entry IS '约束 pk_denylist_entry 的支撑唯一索引。';
COMMENT ON INDEX risk.uq_denylist_entry IS '约束 uq_denylist_entry 的支撑唯一索引。';
COMMENT ON INDEX risk.ix_fk_risk_assessment_policy_id IS '查询索引：优化 risk.risk_assessment 按 policy_id 的访问。';
COMMENT ON INDEX risk.ix_fk_risk_assessment_supersedes_id IS '查询索引：优化 risk.risk_assessment 按 supersedes_id 的访问。';
COMMENT ON INDEX risk.ix_fk_denylist_entry_source_case_id IS '查询索引：优化 risk.denylist_entry 按 source_case_id 的访问。';

