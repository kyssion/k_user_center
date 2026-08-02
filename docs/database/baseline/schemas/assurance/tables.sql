-- =============================================================================
-- baseline/schemas/assurance/tables.sql
-- assurance Schema 的最终基表、同 Schema 约束、索引及内联 COMMENT
-- PostgreSQL 16+；应用技术栈：.NET 10 + SqlSugar
-- =============================================================================

CREATE TABLE assurance.assurance_policy (
    id uuid        NOT NULL DEFAULT gen_random_uuid(),
    policy_code text        NOT NULL,
    policy_version integer     NOT NULL,
    operation_code text        NOT NULL,
    required_ial text        NOT NULL,
    required_aal text        NOT NULL,
    required_fal text        NOT NULL,
    max_auth_age_seconds integer     NOT NULL,
    require_phishing_resistant boolean NOT NULL DEFAULT false,
    require_hardware_protected boolean NOT NULL DEFAULT false,
    prohibited_delegation boolean     NOT NULL DEFAULT false,
    effective_at timestamptz NOT NULL,
    CONSTRAINT pk_assurance_policy PRIMARY KEY (id),
    CONSTRAINT uq_assurance_policy_version UNIQUE (policy_code, policy_version, operation_code),
    CONSTRAINT ck_assurance_policy_ial CHECK (required_ial IN ('IAL1', 'IAL2', 'IAL3')),
    CONSTRAINT ck_assurance_policy_aal CHECK (required_aal IN ('AAL1', 'AAL2', 'AAL3')),
    CONSTRAINT ck_assurance_policy_fal CHECK (required_fal IN ('FAL1', 'FAL2', 'FAL3')),
    CONSTRAINT ck_assurance_policy_age CHECK (max_auth_age_seconds BETWEEN 0 AND 86400)
);

COMMENT ON TABLE assurance.assurance_policy IS 'CAP-ASR-001/002：敏感操作对 IAL/AAL/FAL、认证年龄、抗钓鱼/硬件与委托限制的版本化要求。';

CREATE TABLE assurance.identity_assurance_assertion (
    id uuid        NOT NULL DEFAULT gen_random_uuid(),
    user_id uuid        NOT NULL,
    assertion_kind text        NOT NULL,
    ial_level text        NOT NULL,
    source_provider_code text        NOT NULL,
    evidence_hash bytea       NOT NULL,
    evidence_key_ref text        NULL,
    assertion_state text        NOT NULL DEFAULT 'ACTIVE',
    verified_at timestamptz NOT NULL,
    expires_at timestamptz NULL,
    revoked_at timestamptz NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT pk_identity_assurance_assertion PRIMARY KEY (id),
    CONSTRAINT ck_identity_assurance_kind CHECK (assertion_kind IN ('DOCUMENT', 'DATABASE', 'IN_PERSON', 'REMOTE_VIDEO', 'GUARDIAN', 'ENTERPRISE_ATTESTATION')),
    CONSTRAINT ck_identity_assurance_ial CHECK (ial_level IN ('IAL1', 'IAL2', 'IAL3')),
    CONSTRAINT ck_identity_assurance_state CHECK (assertion_state IN ('ACTIVE', 'EXPIRED', 'REVOKED', 'SUPERSEDED')),
    CONSTRAINT ck_identity_assurance_hash CHECK (octet_length(evidence_hash) = 32),
    CONSTRAINT ck_identity_assurance_window CHECK (expires_at IS NULL OR expires_at > verified_at)
);

COMMENT ON TABLE assurance.identity_assurance_assertion IS '身份核验来源、IAL、最小化证据摘要、有效期和撤销状态；原始材料由受控证据库保存。';

CREATE TABLE assurance.recovery_request (
    id uuid        NOT NULL DEFAULT gen_random_uuid(),
    public_id text        NOT NULL,
    user_id uuid        NOT NULL,
    operation_id uuid        NOT NULL,
    recovery_state text        NOT NULL DEFAULT 'SUBMITTED',
    target_aal text        NOT NULL,
    previous_max_aal text        NULL,
    risk_assessment_id uuid        NOT NULL,
    approval_case_id uuid        NULL,
    waiting_until timestamptz NOT NULL,
    observation_until timestamptz NULL,
    completed_at timestamptz NULL,
    rejected_at timestamptz NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    row_version bigint      NOT NULL DEFAULT 1,
    CONSTRAINT pk_recovery_request PRIMARY KEY (id),
    CONSTRAINT uq_recovery_request_public_id UNIQUE (public_id),
    CONSTRAINT uq_recovery_request_operation UNIQUE (operation_id),
    CONSTRAINT ck_recovery_request_state CHECK (recovery_state IN ('SUBMITTED', 'EVIDENCE_COLLECTED', 'WAITING', 'APPROVED', 'COMPLETED', 'REJECTED', 'CANCELLED', 'EXPIRED')),
    CONSTRAINT ck_recovery_request_aal CHECK (target_aal IN ('AAL1', 'AAL2', 'AAL3') AND (previous_max_aal IS NULL OR previous_max_aal IN ('AAL1', 'AAL2', 'AAL3'))),
    CONSTRAINT ck_recovery_request_wait CHECK (waiting_until >= created_at + interval '24 hours' AND waiting_until <= created_at + interval '72 hours'),
    CONSTRAINT ck_recovery_request_complete CHECK (recovery_state <> 'COMPLETED' OR completed_at IS NOT NULL),
    CONSTRAINT ck_recovery_request_observe CHECK (observation_until IS NULL OR (completed_at IS NOT NULL AND observation_until >= completed_at + interval '7 days'))
);

COMMENT ON TABLE assurance.recovery_request IS 'CAP-ASR-003/007：高保证恢复的证据、风险、审批、24–72 小时等待和至少七天观察期。';

CREATE TABLE assurance.delegation (
    id uuid        NOT NULL DEFAULT gen_random_uuid(),
    public_id text        NOT NULL,
    subject_user_id uuid        NOT NULL,
    actor_user_id uuid        NOT NULL,
    tenant_id uuid        NOT NULL,
    delegation_state text        NOT NULL DEFAULT 'PENDING',
    allowed_actions text[]      NOT NULL,
    resource_scope jsonb       NOT NULL,
    prohibited_operations text[]      NOT NULL DEFAULT '{}',
    max_depth smallint    NOT NULL DEFAULT 1,
    parent_delegation_id uuid        NULL,
    approval_case_id uuid        NULL,
    risk_assessment_id uuid        NOT NULL,
    subject_assurance_hash bytea      NOT NULL,
    actor_assurance_hash bytea       NOT NULL,
    valid_from timestamptz NOT NULL,
    valid_until timestamptz NOT NULL,
    activated_at timestamptz NULL,
    revoked_at timestamptz NULL,
    expired_at timestamptz NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    row_version bigint      NOT NULL DEFAULT 1,
    delegation_context_hash bytea NOT NULL,
    revoked_by_ref text NULL,
    revoke_reason_code text NULL,
    CONSTRAINT pk_delegation PRIMARY KEY (id),
    CONSTRAINT uq_delegation_public_id UNIQUE (public_id),
    CONSTRAINT fk_delegation_parent FOREIGN KEY (parent_delegation_id) REFERENCES assurance.delegation(id),
    CONSTRAINT ck_delegation_parties CHECK (subject_user_id <> actor_user_id),
    CONSTRAINT ck_delegation_state CHECK (delegation_state IN ('PENDING', 'ACTIVE', 'REJECTED', 'REVOKED', 'EXPIRED')),
    CONSTRAINT ck_delegation_actions CHECK (cardinality(allowed_actions) > 0),
    CONSTRAINT ck_delegation_depth CHECK (max_depth BETWEEN 1 AND 3),
    CONSTRAINT ck_delegation_hash CHECK (octet_length(subject_assurance_hash) = 32 AND octet_length(actor_assurance_hash) = 32),
    CONSTRAINT ck_delegation_window CHECK (valid_until > valid_from),
    CONSTRAINT ck_delegation_active CHECK (delegation_state <> 'ACTIVE' OR activated_at IS NOT NULL),
    CONSTRAINT ck_delegation_revoked CHECK ((delegation_state = 'REVOKED') = (revoked_at IS NOT NULL)),
    CONSTRAINT ck_delegation_expired CHECK ((delegation_state = 'EXPIRED') = (expired_at IS NOT NULL)),
    CONSTRAINT ck_delegation_context_hash CHECK (octet_length(delegation_context_hash) = 32),
    CONSTRAINT ck_delegation_revoke_evidence CHECK (
    (revoked_at IS NULL) = (revoked_by_ref IS NULL)
    AND (revoked_at IS NULL) = (revoke_reason_code IS NULL)
    )
);

COMMENT ON TABLE assurance.delegation IS 'INV-G-018 / REQ-ASR-001 至 003：Subject、Actor、允许动作、租户/资源范围、链深、保证、风险和撤销的自然人委托。';

CREATE INDEX ix_delegation_subject ON assurance.delegation(subject_user_id, tenant_id, delegation_state);

CREATE INDEX ix_delegation_actor ON assurance.delegation(actor_user_id, tenant_id, delegation_state);

CREATE INDEX ix_fk_delegation_parent_delegation_id ON assurance.delegation (parent_delegation_id);

COMMENT ON COLUMN assurance.assurance_policy.id IS '内部 UUID 主键；仅用于数据库关系，不作为跨域公开标识。';
COMMENT ON COLUMN assurance.assurance_policy.policy_code IS '稳定机器可读代码；展示文本由资源或目录解析。';
COMMENT ON COLUMN assurance.assurance_policy.policy_version IS '对象、策略或源数据的显式版本；不得以不可信客户端时间戳替代。';
COMMENT ON COLUMN assurance.assurance_policy.operation_code IS '稳定机器可读代码；展示文本由资源或目录解析。';
COMMENT ON COLUMN assurance.assurance_policy.required_ial IS 'assurance.assurance_policy.required_ial 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN assurance.assurance_policy.required_aal IS 'assurance.assurance_policy.required_aal 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN assurance.assurance_policy.required_fal IS 'assurance.assurance_policy.required_fal 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN assurance.assurance_policy.max_auth_age_seconds IS '以秒为单位的显式时长；有效范围由安全策略及表约束限制。';
COMMENT ON COLUMN assurance.assurance_policy.require_phishing_resistant IS 'assurance.assurance_policy.require_phishing_resistant 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN assurance.assurance_policy.require_hardware_protected IS 'assurance.assurance_policy.require_hardware_protected 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN assurance.assurance_policy.prohibited_delegation IS 'assurance.assurance_policy.prohibited_delegation 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN assurance.assurance_policy.effective_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN assurance.identity_assurance_assertion.id IS '内部 UUID 主键；仅用于数据库关系，不作为跨域公开标识。';
COMMENT ON COLUMN assurance.identity_assurance_assertion.user_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN assurance.identity_assurance_assertion.assertion_kind IS '对象类别判别字段；允许值由 CHECK 或对应注册表限定。';
COMMENT ON COLUMN assurance.identity_assurance_assertion.ial_level IS 'assurance.identity_assurance_assertion.ial_level 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN assurance.identity_assurance_assertion.source_provider_code IS '稳定机器可读代码；展示文本由资源或目录解析。';
COMMENT ON COLUMN assurance.identity_assurance_assertion.evidence_hash IS '不可逆摘要；用于等值匹配、幂等、完整性或最小化证据，不保存原始敏感值。';
COMMENT ON COLUMN assurance.identity_assurance_assertion.evidence_key_ref IS '外部 KMS/HSM 或受控密钥资产引用；不得保存私钥或 Secret 明文。';
COMMENT ON COLUMN assurance.identity_assurance_assertion.assertion_state IS '显式状态当前值；合法取值见 CHECK，完整状态转换由 .NET 领域策略执行。';
COMMENT ON COLUMN assurance.identity_assurance_assertion.verified_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN assurance.identity_assurance_assertion.expires_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN assurance.identity_assurance_assertion.revoked_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN assurance.identity_assurance_assertion.created_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN assurance.recovery_request.id IS '内部 UUID 主键；仅用于数据库关系，不作为跨域公开标识。';
COMMENT ON COLUMN assurance.recovery_request.public_id IS '不可复用的公开稳定标识；插入时登记到 core.public_id_ledger。';
COMMENT ON COLUMN assurance.recovery_request.user_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN assurance.recovery_request.operation_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN assurance.recovery_request.recovery_state IS '显式状态当前值；合法取值见 CHECK，完整状态转换由 .NET 领域策略执行。';
COMMENT ON COLUMN assurance.recovery_request.target_aal IS 'assurance.recovery_request.target_aal 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN assurance.recovery_request.previous_max_aal IS 'assurance.recovery_request.previous_max_aal 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN assurance.recovery_request.risk_assessment_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN assurance.recovery_request.approval_case_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN assurance.recovery_request.waiting_until IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN assurance.recovery_request.observation_until IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN assurance.recovery_request.completed_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN assurance.recovery_request.rejected_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN assurance.recovery_request.created_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN assurance.recovery_request.updated_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN assurance.recovery_request.row_version IS '乐观并发版本；更新必须使用原值 compare-and-set，成功后由数据库单调递增。';
COMMENT ON COLUMN assurance.delegation.id IS '内部 UUID 主键；仅用于数据库关系，不作为跨域公开标识。';
COMMENT ON COLUMN assurance.delegation.public_id IS '不可复用的公开稳定标识；插入时登记到 core.public_id_ledger。';
COMMENT ON COLUMN assurance.delegation.subject_user_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN assurance.delegation.actor_user_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN assurance.delegation.tenant_id IS '租户隔离键；全零 UUID 表示平台范围，应用查询必须显式携带可信租户上下文。';
COMMENT ON COLUMN assurance.delegation.delegation_state IS '显式状态当前值；合法取值见 CHECK，完整状态转换由 .NET 领域策略执行。';
COMMENT ON COLUMN assurance.delegation.allowed_actions IS '代码或引用集合；写入前去重、校验 allowlist，并满足表约束。';
COMMENT ON COLUMN assurance.delegation.resource_scope IS '版本化结构化扩展数据；必须由 .NET 按对应 JSON Schema 校验，不得替代核心状态或外键。';
COMMENT ON COLUMN assurance.delegation.prohibited_operations IS '代码或引用集合；写入前去重、校验 allowlist，并满足表约束。';
COMMENT ON COLUMN assurance.delegation.max_depth IS 'assurance.delegation.max_depth 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN assurance.delegation.parent_delegation_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN assurance.delegation.approval_case_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN assurance.delegation.risk_assessment_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN assurance.delegation.subject_assurance_hash IS '不可逆摘要；用于等值匹配、幂等、完整性或最小化证据，不保存原始敏感值。';
COMMENT ON COLUMN assurance.delegation.actor_assurance_hash IS '不可逆摘要；用于等值匹配、幂等、完整性或最小化证据，不保存原始敏感值。';
COMMENT ON COLUMN assurance.delegation.valid_from IS 'assurance.delegation.valid_from 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN assurance.delegation.valid_until IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN assurance.delegation.activated_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN assurance.delegation.revoked_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN assurance.delegation.expired_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN assurance.delegation.created_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN assurance.delegation.updated_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN assurance.delegation.row_version IS '乐观并发版本；更新必须使用原值 compare-and-set，成功后由数据库单调递增。';
COMMENT ON COLUMN assurance.delegation.delegation_context_hash IS '不可逆摘要；用于等值匹配、幂等、完整性或最小化证据，不保存原始敏感值。';
COMMENT ON COLUMN assurance.delegation.revoked_by_ref IS '不透明对象引用；不得从格式推断手机号、邮箱或其他业务事实。';
COMMENT ON COLUMN assurance.delegation.revoke_reason_code IS '稳定机器可读代码；展示文本由资源或目录解析。';

COMMENT ON CONSTRAINT pk_assurance_policy ON assurance.assurance_policy IS '主键约束：唯一标识 assurance.assurance_policy 记录。';
COMMENT ON CONSTRAINT uq_assurance_policy_version ON assurance.assurance_policy IS '唯一约束：保证 policy_code、policy_version、operation_code 在 assurance.assurance_policy 范围内不重复。';
COMMENT ON CONSTRAINT ck_assurance_policy_ial ON assurance.assurance_policy IS '检查约束：限制 assurance.assurance_policy 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_assurance_policy_aal ON assurance.assurance_policy IS '检查约束：限制 assurance.assurance_policy 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_assurance_policy_fal ON assurance.assurance_policy IS '检查约束：限制 assurance.assurance_policy 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_assurance_policy_age ON assurance.assurance_policy IS '检查约束：限制 assurance.assurance_policy 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT pk_identity_assurance_assertion ON assurance.identity_assurance_assertion IS '主键约束：唯一标识 assurance.identity_assurance_assertion 记录。';
COMMENT ON CONSTRAINT ck_identity_assurance_kind ON assurance.identity_assurance_assertion IS '检查约束：限制 assurance.identity_assurance_assertion 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_identity_assurance_ial ON assurance.identity_assurance_assertion IS '检查约束：限制 assurance.identity_assurance_assertion 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_identity_assurance_state ON assurance.identity_assurance_assertion IS '检查约束：限制 assurance.identity_assurance_assertion 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_identity_assurance_hash ON assurance.identity_assurance_assertion IS '检查约束：限制 assurance.identity_assurance_assertion 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_identity_assurance_window ON assurance.identity_assurance_assertion IS '检查约束：限制 assurance.identity_assurance_assertion 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT pk_recovery_request ON assurance.recovery_request IS '主键约束：唯一标识 assurance.recovery_request 记录。';
COMMENT ON CONSTRAINT uq_recovery_request_public_id ON assurance.recovery_request IS '唯一约束：保证 public_id 在 assurance.recovery_request 范围内不重复。';
COMMENT ON CONSTRAINT uq_recovery_request_operation ON assurance.recovery_request IS '唯一约束：保证 operation_id 在 assurance.recovery_request 范围内不重复。';
COMMENT ON CONSTRAINT ck_recovery_request_state ON assurance.recovery_request IS '检查约束：限制 assurance.recovery_request 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_recovery_request_aal ON assurance.recovery_request IS '检查约束：限制 assurance.recovery_request 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_recovery_request_wait ON assurance.recovery_request IS '检查约束：限制 assurance.recovery_request 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_recovery_request_complete ON assurance.recovery_request IS '检查约束：限制 assurance.recovery_request 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_recovery_request_observe ON assurance.recovery_request IS '检查约束：限制 assurance.recovery_request 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT pk_delegation ON assurance.delegation IS '主键约束：唯一标识 assurance.delegation 记录。';
COMMENT ON CONSTRAINT uq_delegation_public_id ON assurance.delegation IS '唯一约束：保证 public_id 在 assurance.delegation 范围内不重复。';
COMMENT ON CONSTRAINT fk_delegation_parent ON assurance.delegation IS '外键约束：assurance.delegation 的 parent_delegation_id 必须引用 assurance.delegation；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT ck_delegation_parties ON assurance.delegation IS '检查约束：限制 assurance.delegation 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_delegation_state ON assurance.delegation IS '检查约束：限制 assurance.delegation 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_delegation_actions ON assurance.delegation IS '检查约束：限制 assurance.delegation 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_delegation_depth ON assurance.delegation IS '检查约束：限制 assurance.delegation 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_delegation_hash ON assurance.delegation IS '检查约束：限制 assurance.delegation 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_delegation_window ON assurance.delegation IS '检查约束：限制 assurance.delegation 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_delegation_active ON assurance.delegation IS '检查约束：限制 assurance.delegation 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_delegation_revoked ON assurance.delegation IS '检查约束：限制 assurance.delegation 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_delegation_expired ON assurance.delegation IS '检查约束：限制 assurance.delegation 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_delegation_context_hash ON assurance.delegation IS '检查约束：限制 assurance.delegation 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_delegation_revoke_evidence ON assurance.delegation IS '检查约束：限制 assurance.delegation 的字段取值或组合满足结构与安全底线。';

COMMENT ON INDEX assurance.ix_delegation_subject IS '查询索引：优化 assurance.delegation 按 subject_user_id、tenant_id、delegation_state 的访问。';
COMMENT ON INDEX assurance.ix_delegation_actor IS '查询索引：优化 assurance.delegation 按 actor_user_id、tenant_id、delegation_state 的访问。';
COMMENT ON INDEX assurance.pk_assurance_policy IS '约束 pk_assurance_policy 的支撑唯一索引。';
COMMENT ON INDEX assurance.uq_assurance_policy_version IS '约束 uq_assurance_policy_version 的支撑唯一索引。';
COMMENT ON INDEX assurance.pk_identity_assurance_assertion IS '约束 pk_identity_assurance_assertion 的支撑唯一索引。';
COMMENT ON INDEX assurance.pk_recovery_request IS '约束 pk_recovery_request 的支撑唯一索引。';
COMMENT ON INDEX assurance.uq_recovery_request_public_id IS '约束 uq_recovery_request_public_id 的支撑唯一索引。';
COMMENT ON INDEX assurance.uq_recovery_request_operation IS '约束 uq_recovery_request_operation 的支撑唯一索引。';
COMMENT ON INDEX assurance.pk_delegation IS '约束 pk_delegation 的支撑唯一索引。';
COMMENT ON INDEX assurance.uq_delegation_public_id IS '约束 uq_delegation_public_id 的支撑唯一索引。';
COMMENT ON INDEX assurance.ix_fk_delegation_parent_delegation_id IS '查询索引：优化 assurance.delegation 按 parent_delegation_id 的访问。';

