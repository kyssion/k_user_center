-- =============================================================================
-- baseline/schemas/authz/tables.sql
-- authz Schema 的最终基表、同 Schema 约束、索引及内联 COMMENT
-- PostgreSQL 16+；应用技术栈：.NET 10 + SqlSugar
-- =============================================================================

CREATE TABLE authz.permission (
    id uuid        NOT NULL DEFAULT gen_random_uuid(),
    permission_code text        NOT NULL,
    resource_type text        NOT NULL,
    action_code text        NOT NULL,
    risk_tier text        NOT NULL DEFAULT 'NORMAL',
    required_profile_code text        NOT NULL DEFAULT 'SP1',
    description text        NOT NULL,
    is_active boolean     NOT NULL DEFAULT true,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT pk_permission PRIMARY KEY (id),
    CONSTRAINT uq_permission_code UNIQUE (permission_code),
    CONSTRAINT uq_permission_tuple UNIQUE (resource_type, action_code),
    CONSTRAINT ck_permission_code CHECK (permission_code ~ '^[a-z][a-z0-9_.:-]{2,127}$'),
    CONSTRAINT ck_permission_risk CHECK (risk_tier IN ('LOW', 'NORMAL', 'HIGH', 'CRITICAL'))
);

COMMENT ON TABLE authz.permission IS 'CAP-AUTHZ-002：版本外稳定的原子资源动作权限目录。';

CREATE TABLE authz.role (
    id uuid        NOT NULL DEFAULT gen_random_uuid(),
    public_id text        NOT NULL,
    role_code text        NOT NULL,
    display_name text        NOT NULL,
    scope_kind text        NOT NULL,
    business_line_id uuid        NULL,
    tenant_id uuid        NULL,
    role_state text        NOT NULL DEFAULT 'DRAFT',
    privilege_tier text        NOT NULL DEFAULT 'STANDARD',
    owner_ref text        NOT NULL,
    expires_at timestamptz NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    row_version bigint      NOT NULL DEFAULT 1,
    organization_id uuid NULL,
    CONSTRAINT pk_role PRIMARY KEY (id),
    CONSTRAINT uq_role_public_id UNIQUE (public_id),
    CONSTRAINT ck_role_scope CHECK (scope_kind IN ('PLATFORM', 'BUSINESS_LINE', 'TENANT', 'ORGANIZATION')),
    CONSTRAINT ck_role_state CHECK (role_state IN ('DRAFT', 'ACTIVE', 'SUSPENDED', 'RETIRED')),
    CONSTRAINT ck_role_tier CHECK (privilege_tier IN ('STANDARD', 'ELEVATED', 'PRIVILEGED', 'BREAK_GLASS')),
    CONSTRAINT uq_role_code_scope UNIQUE NULLS NOT DISTINCT (role_code, scope_kind, business_line_id, tenant_id, organization_id),
    CONSTRAINT ck_role_scope_value CHECK (
    (scope_kind = 'PLATFORM' AND business_line_id IS NULL AND tenant_id IS NULL AND organization_id IS NULL)
    OR (scope_kind = 'BUSINESS_LINE' AND business_line_id IS NOT NULL AND tenant_id IS NULL AND organization_id IS NULL)
    OR (scope_kind = 'TENANT' AND business_line_id IS NOT NULL AND tenant_id IS NOT NULL AND organization_id IS NULL)
    OR (scope_kind = 'ORGANIZATION' AND business_line_id IS NOT NULL AND tenant_id IS NOT NULL AND organization_id IS NOT NULL)
    )
);

COMMENT ON TABLE authz.role IS 'CAP-AUTHZ-003：平台、业务线、租户或组织作用域角色与权限级别。';

CREATE TABLE authz.role_permission (
    role_id uuid        NOT NULL,
    permission_id uuid        NOT NULL,
    effect text        NOT NULL DEFAULT 'ALLOW',
    data_scope_expression jsonb       NULL,
    obligation_codes text[]      NOT NULL DEFAULT '{}',
    valid_from timestamptz NOT NULL DEFAULT clock_timestamp(),
    valid_until timestamptz NULL,
    CONSTRAINT pk_role_permission PRIMARY KEY (role_id, permission_id),
    CONSTRAINT fk_role_permission_role FOREIGN KEY (role_id) REFERENCES authz.role(id) ON DELETE CASCADE,
    CONSTRAINT fk_role_permission_permission FOREIGN KEY (permission_id) REFERENCES authz.permission(id),
    CONSTRAINT ck_role_permission_effect CHECK (effect IN ('ALLOW', 'DENY')),
    CONSTRAINT ck_role_permission_window CHECK (valid_until IS NULL OR valid_until > valid_from)
);

COMMENT ON TABLE authz.role_permission IS 'CAP-AUTHZ-004/005：角色的允许/显式拒绝、数据范围及强制义务；拒绝优先。';

CREATE TABLE authz.role_exclusion (
    role_id uuid        NOT NULL,
    excluded_role_id uuid        NOT NULL,
    exclusion_reason text        NOT NULL,
    CONSTRAINT pk_role_exclusion PRIMARY KEY (role_id, excluded_role_id),
    CONSTRAINT fk_role_exclusion_role FOREIGN KEY (role_id) REFERENCES authz.role(id),
    CONSTRAINT fk_role_exclusion_other FOREIGN KEY (excluded_role_id) REFERENCES authz.role(id),
    CONSTRAINT ck_role_exclusion_self CHECK (role_id <> excluded_role_id)
);

COMMENT ON TABLE authz.role_exclusion IS '职责分离与互斥角色约束目录；双向完整性由发布校验保证。';

CREATE TABLE authz.role_assignment (
    id uuid        NOT NULL DEFAULT gen_random_uuid(),
    role_id uuid        NOT NULL,
    subject_kind text        NOT NULL,
    subject_id uuid        NOT NULL,
    business_line_id uuid        NULL,
    tenant_id uuid        NULL,
    organization_id uuid        NULL,
    assignment_state text        NOT NULL DEFAULT 'ACTIVE',
    granted_by_ref text        NOT NULL,
    approval_case_id uuid        NULL,
    valid_from timestamptz NOT NULL DEFAULT clock_timestamp(),
    valid_until timestamptz NULL,
    revoked_at timestamptz NULL,
    revoke_reason_code text        NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    row_version bigint      NOT NULL DEFAULT 1,
    approval_execution_id uuid NULL,
    last_activation_execution_id uuid NULL,
    CONSTRAINT pk_role_assignment PRIMARY KEY (id),
    CONSTRAINT fk_role_assignment_role FOREIGN KEY (role_id) REFERENCES authz.role(id),
    CONSTRAINT ck_role_assignment_subject CHECK (subject_kind IN ('USER', 'MEMBERSHIP', 'GROUP', 'CLIENT', 'MACHINE')),
    CONSTRAINT ck_role_assignment_state CHECK (assignment_state IN ('ACTIVE', 'SUSPENDED', 'REVOKED', 'EXPIRED')),
    CONSTRAINT ck_role_assignment_window CHECK (valid_until IS NULL OR valid_until > valid_from),
    CONSTRAINT ck_role_assignment_revoked CHECK ((assignment_state = 'REVOKED') = (revoked_at IS NOT NULL)),
    CONSTRAINT ck_role_assignment_revoke_reason CHECK (
    assignment_state <> 'REVOKED' OR NULLIF(btrim(revoke_reason_code), '') IS NOT NULL
    )
);

COMMENT ON TABLE authz.role_assignment IS 'CAP-AUTHZ-006/016：主体在明确范围内的角色授予、临时有效期、审批与撤回证据。';

CREATE TABLE authz.policy_release (
    id uuid        NOT NULL DEFAULT gen_random_uuid(),
    public_id text        NOT NULL,
    policy_code text        NOT NULL,
    policy_version bigint      NOT NULL,
    policy_state text        NOT NULL DEFAULT 'DRAFT',
    policy_language text        NOT NULL,
    content_hash bytea       NOT NULL,
    content_uri text        NOT NULL,
    owner_ref text        NOT NULL,
    approval_case_id uuid        NULL,
    activated_at timestamptz NULL,
    retired_at timestamptz NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    approval_execution_id uuid NULL,
    revoked_at timestamptz NULL,
    CONSTRAINT pk_policy_release PRIMARY KEY (id),
    CONSTRAINT uq_policy_release_public_id UNIQUE (public_id),
    CONSTRAINT uq_policy_release_version UNIQUE (policy_code, policy_version),
    CONSTRAINT ck_policy_release_state CHECK (policy_state IN ('DRAFT', 'VALIDATED', 'APPROVED', 'STAGED', 'ACTIVE', 'DEPRECATED', 'REVOKED')),
    CONSTRAINT ck_policy_release_language CHECK (policy_language IN ('CEL', 'REGO', 'CEDAR', 'CUSTOM_IR')),
    CONSTRAINT ck_policy_release_hash CHECK (octet_length(content_hash) = 32),
    CONSTRAINT ck_policy_release_active CHECK (policy_state <> 'ACTIVE' OR (approval_case_id IS NOT NULL AND activated_at IS NOT NULL)),
    CONSTRAINT ck_policy_release_state_times CHECK (
    (activated_at IS NULL OR policy_state IN ('ACTIVE', 'DEPRECATED', 'REVOKED'))
    AND (retired_at IS NULL OR policy_state IN ('DEPRECATED', 'REVOKED'))
    AND (revoked_at IS NULL OR policy_state = 'REVOKED')
    AND (policy_state <> 'ACTIVE' OR activated_at IS NOT NULL)
    AND (policy_state <> 'DEPRECATED' OR (activated_at IS NOT NULL AND retired_at IS NOT NULL))
    AND ((policy_state = 'REVOKED') = (revoked_at IS NOT NULL))
    )
);

COMMENT ON TABLE authz.policy_release IS 'REQ-AUTHZ-010 / INV-G-011：不可变、测试、审批、灰度和发布的 PDP 策略版本。';

CREATE TABLE authz.obligation_type (
    obligation_code text        NOT NULL,
    schema_version integer     NOT NULL,
    display_name text        NOT NULL,
    parameter_schema jsonb       NOT NULL,
    execution_point text        NOT NULL,
    is_mandatory boolean     NOT NULL DEFAULT true,
    is_active boolean     NOT NULL DEFAULT true,
    CONSTRAINT pk_obligation_type PRIMARY KEY (obligation_code, schema_version),
    CONSTRAINT ck_obligation_execution CHECK (execution_point IN ('BEFORE_QUERY', 'QUERY_FILTER', 'BEFORE_COMMIT', 'RESPONSE_TRANSFORM', 'AFTER_COMMIT'))
);

COMMENT ON TABLE authz.obligation_type IS 'REQ-AUTHZ-014：Step-up、脱敏、行过滤、水印和附加审计等版本化义务 Schema。';

CREATE TABLE authz.pep_capability (
    pep_id text        NOT NULL,
    environment text        NOT NULL,
    supported_obligations jsonb       NOT NULL,
    capability_version bigint      NOT NULL,
    last_reported_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    CONSTRAINT pk_pep_capability PRIMARY KEY (pep_id, environment),
    CONSTRAINT ck_pep_capability_version CHECK (capability_version >= 1),
    CONSTRAINT ck_pep_capability_expiry CHECK (expires_at > last_reported_at)
);

COMMENT ON TABLE authz.pep_capability IS 'REQ-AUTHZ-015/016：PEP 声明可执行义务与新鲜度，能力缺失时 PDP 不得允许。';

CREATE TABLE authz.authorization_decision (
    id uuid        NOT NULL DEFAULT gen_random_uuid(),
    public_id text        NOT NULL,
    subject_kind text        NOT NULL,
    subject_ref text        NOT NULL,
    actor_kind text        NULL,
    actor_ref text        NULL,
    resource_type text        NOT NULL,
    resource_ref text        NULL,
    resource_version text        NULL,
    action_code text        NOT NULL,
    tenant_id uuid        NOT NULL DEFAULT '00000000-0000-0000-0000-000000000000',
    environment text        NOT NULL,
    risk_level text        NOT NULL,
    achieved_aal text        NULL,
    input_hash bytea       NOT NULL,
    decision_effect text        NOT NULL,
    reason_codes text[]      NOT NULL DEFAULT '{}',
    obligations jsonb       NOT NULL DEFAULT '[]',
    policy_version bigint      NOT NULL,
    pip_versions jsonb       NOT NULL,
    security_epochs jsonb       NOT NULL,
    valid_until timestamptz NOT NULL,
    decided_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    trace_id text        NULL,
    CONSTRAINT pk_authorization_decision PRIMARY KEY (id),
    CONSTRAINT uq_authorization_decision_public_id UNIQUE (public_id),
    CONSTRAINT ck_authorization_decision_actor CHECK ((actor_kind IS NULL) = (actor_ref IS NULL)),
    CONSTRAINT ck_authorization_decision_risk CHECK (risk_level IN ('UNKNOWN', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    CONSTRAINT ck_authorization_decision_aal CHECK (achieved_aal IS NULL OR achieved_aal IN ('AAL1', 'AAL2', 'AAL3')),
    CONSTRAINT ck_authorization_decision_effect CHECK (decision_effect IN ('ALLOW', 'DENY')),
    CONSTRAINT ck_authorization_decision_hash CHECK (octet_length(input_hash) = 32),
    CONSTRAINT ck_authorization_decision_ttl CHECK (valid_until >= decided_at)
);

COMMENT ON TABLE authz.authorization_decision IS 'REQ-AUTHZ-002/007/011：不可变授权决策证据，含完整输入摘要、原因、义务、策略/PIP/security epoch 与有效期。';

CREATE TABLE authz.relationship_tuple (
    id uuid        NOT NULL DEFAULT gen_random_uuid(),
    tenant_id uuid        NOT NULL,
    subject_kind text        NOT NULL,
    subject_ref text        NOT NULL,
    relation_code text        NOT NULL,
    object_kind text        NOT NULL,
    object_ref text        NOT NULL,
    relationship_state text        NOT NULL DEFAULT 'ACTIVE',
    source_kind text        NOT NULL,
    source_ref text        NULL,
    valid_from timestamptz NOT NULL DEFAULT clock_timestamp(),
    valid_until timestamptz NULL,
    revoked_at timestamptz NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    row_version bigint      NOT NULL DEFAULT 1,
    CONSTRAINT pk_relationship_tuple PRIMARY KEY (id),
    CONSTRAINT ck_relationship_tuple_subject CHECK (subject_kind IN ('USER', 'MEMBERSHIP', 'GROUP', 'CLIENT', 'MACHINE')),
    CONSTRAINT ck_relationship_tuple_state CHECK (relationship_state IN ('ACTIVE', 'SUSPENDED', 'REVOKED', 'EXPIRED')),
    CONSTRAINT ck_relationship_tuple_source CHECK (source_kind IN ('PLATFORM', 'BUSINESS_DOMAIN', 'DIRECTORY', 'MIGRATION')),
    CONSTRAINT ck_relationship_tuple_window CHECK (valid_until IS NULL OR valid_until > valid_from),
    CONSTRAINT ck_relationship_tuple_revoked CHECK ((relationship_state = 'REVOKED') = (revoked_at IS NOT NULL))
);

COMMENT ON TABLE authz.relationship_tuple IS 'CAP-AUTHZ-023：Owner、Member、Collaborator、Parent 等租户内关系型授权元组。';

CREATE TABLE authz.access_review (
    id uuid        NOT NULL DEFAULT gen_random_uuid(),
    public_id text        NOT NULL,
    review_kind text        NOT NULL,
    scope_definition jsonb       NOT NULL,
    review_state text        NOT NULL DEFAULT 'DRAFT',
    owner_ref text        NOT NULL,
    operation_id uuid        NOT NULL,
    due_at timestamptz NOT NULL,
    reviewed_count bigint      NOT NULL DEFAULT 0,
    retained_count bigint      NOT NULL DEFAULT 0,
    revoked_count bigint      NOT NULL DEFAULT 0,
    completed_at timestamptz NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    row_version bigint      NOT NULL DEFAULT 1,
    CONSTRAINT pk_access_review PRIMARY KEY (id),
    CONSTRAINT uq_access_review_public_id UNIQUE (public_id),
    CONSTRAINT uq_access_review_operation UNIQUE (operation_id),
    CONSTRAINT ck_access_review_kind CHECK (review_kind IN ('ROLE_ASSIGNMENT', 'PRIVILEGED_ACCESS', 'MACHINE_PERMISSION', 'CLIENT_SCOPE', 'RELATIONSHIP')),
    CONSTRAINT ck_access_review_state CHECK (review_state IN ('DRAFT', 'RUNNING', 'BLOCKED', 'COMPLETED', 'CANCELLED')),
    CONSTRAINT ck_access_review_counts CHECK (reviewed_count >= 0 AND retained_count >= 0 AND revoked_count >= 0 AND retained_count + revoked_count <= reviewed_count),
    CONSTRAINT ck_access_review_complete CHECK ((review_state = 'COMPLETED') = (completed_at IS NOT NULL))
);

COMMENT ON TABLE authz.access_review IS 'CAP-AUTHZ-024：角色、特权、机器权限、Client scope 与关系授权的定期复核和自动回收 Operation。';

CREATE TABLE authz.permission_simulation (
    id uuid        NOT NULL DEFAULT gen_random_uuid(),
    public_id text        NOT NULL,
    requested_by_ref text        NOT NULL,
    input_hash bytea       NOT NULL,
    policy_version bigint      NOT NULL,
    simulation_result jsonb       NOT NULL,
    result_hash bytea       NOT NULL,
    trace_id text        NULL,
    simulated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    expires_at timestamptz NOT NULL,
    CONSTRAINT pk_permission_simulation PRIMARY KEY (id),
    CONSTRAINT uq_permission_simulation_public_id UNIQUE (public_id),
    CONSTRAINT ck_permission_simulation_hash CHECK (octet_length(input_hash) = 32 AND octet_length(result_hash) = 32),
    CONSTRAINT ck_permission_simulation_expiry CHECK (expires_at > simulated_at)
);

COMMENT ON TABLE authz.permission_simulation IS 'CAP-AUTHZ-020：上线前权限模拟的规范化输入、策略版本、结果与短期证据，不产生真实授权。';

CREATE INDEX ix_role_assignment_subject ON authz.role_assignment(subject_kind, subject_id, assignment_state);

CREATE INDEX ix_role_assignment_scope ON authz.role_assignment(tenant_id, organization_id) WHERE assignment_state = 'ACTIVE';

CREATE UNIQUE INDEX ux_policy_release_active ON authz.policy_release(policy_code) WHERE policy_state = 'ACTIVE';

CREATE INDEX ix_authorization_decision_lookup ON authz.authorization_decision(subject_kind, subject_ref, action_code, decided_at DESC);

CREATE UNIQUE INDEX ux_relationship_tuple_active ON authz.relationship_tuple(tenant_id, subject_kind, subject_ref, relation_code, object_kind, object_ref) WHERE relationship_state = 'ACTIVE';

CREATE INDEX ix_access_review_due ON authz.access_review(due_at) WHERE review_state IN ('DRAFT', 'RUNNING', 'BLOCKED');

CREATE UNIQUE INDEX ux_role_assignment_effective
    ON authz.role_assignment(
        role_id,
        subject_kind,
        subject_id,
        COALESCE(business_line_id, '00000000-0000-0000-0000-000000000000'::uuid),
        COALESCE(tenant_id, '00000000-0000-0000-0000-000000000000'::uuid),
        COALESCE(organization_id, '00000000-0000-0000-0000-000000000000'::uuid)
    )
    WHERE assignment_state IN ('ACTIVE', 'SUSPENDED');

CREATE INDEX ix_fk_role_permission_permission_id ON authz.role_permission (permission_id);

CREATE INDEX ix_fk_role_exclusion_excluded_role_id ON authz.role_exclusion (excluded_role_id);

CREATE INDEX ix_fk_role_assignment_role_id ON authz.role_assignment (role_id);

COMMENT ON COLUMN authz.permission.id IS '内部 UUID 主键；仅用于数据库关系，不作为跨域公开标识。';
COMMENT ON COLUMN authz.permission.permission_code IS '稳定机器可读代码；展示文本由资源或目录解析。';
COMMENT ON COLUMN authz.permission.resource_type IS '对象类别判别字段；允许值由 CHECK 或对应注册表限定。';
COMMENT ON COLUMN authz.permission.action_code IS '稳定机器可读代码；展示文本由资源或目录解析。';
COMMENT ON COLUMN authz.permission.risk_tier IS 'authz.permission.risk_tier 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN authz.permission.required_profile_code IS '稳定机器可读代码；展示文本由资源或目录解析。';
COMMENT ON COLUMN authz.permission.description IS 'authz.permission.description 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN authz.permission.is_active IS '显式布尔开关；启用前置条件与失效行为由约束和版本化策略控制。';
COMMENT ON COLUMN authz.permission.created_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN authz.role.id IS '内部 UUID 主键；仅用于数据库关系，不作为跨域公开标识。';
COMMENT ON COLUMN authz.role.public_id IS '不可复用的公开稳定标识；插入时登记到 core.public_id_ledger。';
COMMENT ON COLUMN authz.role.role_code IS '稳定机器可读代码；展示文本由资源或目录解析。';
COMMENT ON COLUMN authz.role.display_name IS 'authz.role.display_name 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN authz.role.scope_kind IS '对象类别判别字段；允许值由 CHECK 或对应注册表限定。';
COMMENT ON COLUMN authz.role.business_line_id IS '业务线隔离键；关联 org.business_line，用于业务线范围隔离。';
COMMENT ON COLUMN authz.role.tenant_id IS '租户隔离键；全零 UUID 表示平台范围，应用查询必须显式携带可信租户上下文。';
COMMENT ON COLUMN authz.role.role_state IS '显式状态当前值；合法取值见 CHECK，完整状态转换由 .NET 领域策略执行。';
COMMENT ON COLUMN authz.role.privilege_tier IS 'authz.role.privilege_tier 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN authz.role.owner_ref IS '不透明对象引用；不得从格式推断手机号、邮箱或其他业务事实。';
COMMENT ON COLUMN authz.role.expires_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN authz.role.created_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN authz.role.updated_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN authz.role.row_version IS '乐观并发版本；更新必须使用原值 compare-and-set，成功后由数据库单调递增。';
COMMENT ON COLUMN authz.role.organization_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN authz.role_permission.role_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN authz.role_permission.permission_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN authz.role_permission.effect IS 'authz.role_permission.effect 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN authz.role_permission.data_scope_expression IS '版本化结构化扩展数据；必须由 .NET 按对应 JSON Schema 校验，不得替代核心状态或外键。';
COMMENT ON COLUMN authz.role_permission.obligation_codes IS '代码或引用集合；写入前去重、校验 allowlist，并满足表约束。';
COMMENT ON COLUMN authz.role_permission.valid_from IS 'authz.role_permission.valid_from 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN authz.role_permission.valid_until IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN authz.role_exclusion.role_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN authz.role_exclusion.excluded_role_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN authz.role_exclusion.exclusion_reason IS 'authz.role_exclusion.exclusion_reason 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN authz.role_assignment.id IS '内部 UUID 主键；仅用于数据库关系，不作为跨域公开标识。';
COMMENT ON COLUMN authz.role_assignment.role_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN authz.role_assignment.subject_kind IS '对象类别判别字段；允许值由 CHECK 或对应注册表限定。';
COMMENT ON COLUMN authz.role_assignment.subject_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN authz.role_assignment.business_line_id IS '业务线隔离键；关联 org.business_line，用于业务线范围隔离。';
COMMENT ON COLUMN authz.role_assignment.tenant_id IS '租户隔离键；全零 UUID 表示平台范围，应用查询必须显式携带可信租户上下文。';
COMMENT ON COLUMN authz.role_assignment.organization_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN authz.role_assignment.assignment_state IS '显式状态当前值；合法取值见 CHECK，完整状态转换由 .NET 领域策略执行。';
COMMENT ON COLUMN authz.role_assignment.granted_by_ref IS '不透明对象引用；不得从格式推断手机号、邮箱或其他业务事实。';
COMMENT ON COLUMN authz.role_assignment.approval_case_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN authz.role_assignment.valid_from IS 'authz.role_assignment.valid_from 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN authz.role_assignment.valid_until IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN authz.role_assignment.revoked_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN authz.role_assignment.revoke_reason_code IS '稳定机器可读代码；展示文本由资源或目录解析。';
COMMENT ON COLUMN authz.role_assignment.created_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN authz.role_assignment.updated_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN authz.role_assignment.row_version IS '乐观并发版本；更新必须使用原值 compare-and-set，成功后由数据库单调递增。';
COMMENT ON COLUMN authz.role_assignment.approval_execution_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN authz.role_assignment.last_activation_execution_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN authz.policy_release.id IS '内部 UUID 主键；仅用于数据库关系，不作为跨域公开标识。';
COMMENT ON COLUMN authz.policy_release.public_id IS '不可复用的公开稳定标识；插入时登记到 core.public_id_ledger。';
COMMENT ON COLUMN authz.policy_release.policy_code IS '稳定机器可读代码；展示文本由资源或目录解析。';
COMMENT ON COLUMN authz.policy_release.policy_version IS '对象、策略或源数据的显式版本；不得以不可信客户端时间戳替代。';
COMMENT ON COLUMN authz.policy_release.policy_state IS '显式状态当前值；合法取值见 CHECK，完整状态转换由 .NET 领域策略执行。';
COMMENT ON COLUMN authz.policy_release.policy_language IS 'authz.policy_release.policy_language 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN authz.policy_release.content_hash IS '不可逆摘要；用于等值匹配、幂等、完整性或最小化证据，不保存原始敏感值。';
COMMENT ON COLUMN authz.policy_release.content_uri IS '受控 URI；写入前必须执行协议、主机、重定向与 SSRF 安全校验。';
COMMENT ON COLUMN authz.policy_release.owner_ref IS '不透明对象引用；不得从格式推断手机号、邮箱或其他业务事实。';
COMMENT ON COLUMN authz.policy_release.approval_case_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN authz.policy_release.activated_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN authz.policy_release.retired_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN authz.policy_release.created_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN authz.policy_release.approval_execution_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN authz.policy_release.revoked_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN authz.obligation_type.obligation_code IS '稳定机器可读代码；展示文本由资源或目录解析。';
COMMENT ON COLUMN authz.obligation_type.schema_version IS '对象、策略或源数据的显式版本；不得以不可信客户端时间戳替代。';
COMMENT ON COLUMN authz.obligation_type.display_name IS 'authz.obligation_type.display_name 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN authz.obligation_type.parameter_schema IS '版本化结构化扩展数据；必须由 .NET 按对应 JSON Schema 校验，不得替代核心状态或外键。';
COMMENT ON COLUMN authz.obligation_type.execution_point IS 'authz.obligation_type.execution_point 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN authz.obligation_type.is_mandatory IS '显式布尔开关；启用前置条件与失效行为由约束和版本化策略控制。';
COMMENT ON COLUMN authz.obligation_type.is_active IS '显式布尔开关；启用前置条件与失效行为由约束和版本化策略控制。';
COMMENT ON COLUMN authz.pep_capability.pep_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN authz.pep_capability.environment IS 'authz.pep_capability.environment 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN authz.pep_capability.supported_obligations IS '版本化结构化扩展数据；必须由 .NET 按对应 JSON Schema 校验，不得替代核心状态或外键。';
COMMENT ON COLUMN authz.pep_capability.capability_version IS '对象、策略或源数据的显式版本；不得以不可信客户端时间戳替代。';
COMMENT ON COLUMN authz.pep_capability.last_reported_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN authz.pep_capability.expires_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN authz.authorization_decision.id IS '内部 UUID 主键；仅用于数据库关系，不作为跨域公开标识。';
COMMENT ON COLUMN authz.authorization_decision.public_id IS '不可复用的公开稳定标识；插入时登记到 core.public_id_ledger。';
COMMENT ON COLUMN authz.authorization_decision.subject_kind IS '对象类别判别字段；允许值由 CHECK 或对应注册表限定。';
COMMENT ON COLUMN authz.authorization_decision.subject_ref IS '不透明对象引用；不得从格式推断手机号、邮箱或其他业务事实。';
COMMENT ON COLUMN authz.authorization_decision.actor_kind IS '对象类别判别字段；允许值由 CHECK 或对应注册表限定。';
COMMENT ON COLUMN authz.authorization_decision.actor_ref IS '不透明对象引用；不得从格式推断手机号、邮箱或其他业务事实。';
COMMENT ON COLUMN authz.authorization_decision.resource_type IS '对象类别判别字段；允许值由 CHECK 或对应注册表限定。';
COMMENT ON COLUMN authz.authorization_decision.resource_ref IS '不透明对象引用；不得从格式推断手机号、邮箱或其他业务事实。';
COMMENT ON COLUMN authz.authorization_decision.resource_version IS '对象、策略或源数据的显式版本；不得以不可信客户端时间戳替代。';
COMMENT ON COLUMN authz.authorization_decision.action_code IS '稳定机器可读代码；展示文本由资源或目录解析。';
COMMENT ON COLUMN authz.authorization_decision.tenant_id IS '租户隔离键；全零 UUID 表示平台范围，应用查询必须显式携带可信租户上下文。';
COMMENT ON COLUMN authz.authorization_decision.environment IS 'authz.authorization_decision.environment 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN authz.authorization_decision.risk_level IS 'authz.authorization_decision.risk_level 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN authz.authorization_decision.achieved_aal IS 'authz.authorization_decision.achieved_aal 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN authz.authorization_decision.input_hash IS '不可逆摘要；用于等值匹配、幂等、完整性或最小化证据，不保存原始敏感值。';
COMMENT ON COLUMN authz.authorization_decision.decision_effect IS 'authz.authorization_decision.decision_effect 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN authz.authorization_decision.reason_codes IS '代码或引用集合；写入前去重、校验 allowlist，并满足表约束。';
COMMENT ON COLUMN authz.authorization_decision.obligations IS '代码或引用集合；写入前去重、校验 allowlist，并满足表约束。';
COMMENT ON COLUMN authz.authorization_decision.policy_version IS '对象、策略或源数据的显式版本；不得以不可信客户端时间戳替代。';
COMMENT ON COLUMN authz.authorization_decision.pip_versions IS '版本化结构化扩展数据；必须由 .NET 按对应 JSON Schema 校验，不得替代核心状态或外键。';
COMMENT ON COLUMN authz.authorization_decision.security_epochs IS '版本化结构化扩展数据；必须由 .NET 按对应 JSON Schema 校验，不得替代核心状态或外键。';
COMMENT ON COLUMN authz.authorization_decision.valid_until IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN authz.authorization_decision.decided_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN authz.authorization_decision.trace_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN authz.relationship_tuple.id IS '内部 UUID 主键；仅用于数据库关系，不作为跨域公开标识。';
COMMENT ON COLUMN authz.relationship_tuple.tenant_id IS '租户隔离键；全零 UUID 表示平台范围，应用查询必须显式携带可信租户上下文。';
COMMENT ON COLUMN authz.relationship_tuple.subject_kind IS '对象类别判别字段；允许值由 CHECK 或对应注册表限定。';
COMMENT ON COLUMN authz.relationship_tuple.subject_ref IS '不透明对象引用；不得从格式推断手机号、邮箱或其他业务事实。';
COMMENT ON COLUMN authz.relationship_tuple.relation_code IS '稳定机器可读代码；展示文本由资源或目录解析。';
COMMENT ON COLUMN authz.relationship_tuple.object_kind IS '对象类别判别字段；允许值由 CHECK 或对应注册表限定。';
COMMENT ON COLUMN authz.relationship_tuple.object_ref IS '不透明对象引用；不得从格式推断手机号、邮箱或其他业务事实。';
COMMENT ON COLUMN authz.relationship_tuple.relationship_state IS '显式状态当前值；合法取值见 CHECK，完整状态转换由 .NET 领域策略执行。';
COMMENT ON COLUMN authz.relationship_tuple.source_kind IS '对象类别判别字段；允许值由 CHECK 或对应注册表限定。';
COMMENT ON COLUMN authz.relationship_tuple.source_ref IS '不透明对象引用；不得从格式推断手机号、邮箱或其他业务事实。';
COMMENT ON COLUMN authz.relationship_tuple.valid_from IS 'authz.relationship_tuple.valid_from 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN authz.relationship_tuple.valid_until IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN authz.relationship_tuple.revoked_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN authz.relationship_tuple.created_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN authz.relationship_tuple.updated_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN authz.relationship_tuple.row_version IS '乐观并发版本；更新必须使用原值 compare-and-set，成功后由数据库单调递增。';
COMMENT ON COLUMN authz.access_review.id IS '内部 UUID 主键；仅用于数据库关系，不作为跨域公开标识。';
COMMENT ON COLUMN authz.access_review.public_id IS '不可复用的公开稳定标识；插入时登记到 core.public_id_ledger。';
COMMENT ON COLUMN authz.access_review.review_kind IS '对象类别判别字段；允许值由 CHECK 或对应注册表限定。';
COMMENT ON COLUMN authz.access_review.scope_definition IS '版本化结构化扩展数据；必须由 .NET 按对应 JSON Schema 校验，不得替代核心状态或外键。';
COMMENT ON COLUMN authz.access_review.review_state IS '显式状态当前值；合法取值见 CHECK，完整状态转换由 .NET 领域策略执行。';
COMMENT ON COLUMN authz.access_review.owner_ref IS '不透明对象引用；不得从格式推断手机号、邮箱或其他业务事实。';
COMMENT ON COLUMN authz.access_review.operation_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN authz.access_review.due_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN authz.access_review.reviewed_count IS '非负计数器；并发更新使用原子 SQL 或乐观并发控制。';
COMMENT ON COLUMN authz.access_review.retained_count IS '非负计数器；并发更新使用原子 SQL 或乐观并发控制。';
COMMENT ON COLUMN authz.access_review.revoked_count IS '非负计数器；并发更新使用原子 SQL 或乐观并发控制。';
COMMENT ON COLUMN authz.access_review.completed_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN authz.access_review.created_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN authz.access_review.updated_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN authz.access_review.row_version IS '乐观并发版本；更新必须使用原值 compare-and-set，成功后由数据库单调递增。';
COMMENT ON COLUMN authz.permission_simulation.id IS '内部 UUID 主键；仅用于数据库关系，不作为跨域公开标识。';
COMMENT ON COLUMN authz.permission_simulation.public_id IS '不可复用的公开稳定标识；插入时登记到 core.public_id_ledger。';
COMMENT ON COLUMN authz.permission_simulation.requested_by_ref IS '不透明对象引用；不得从格式推断手机号、邮箱或其他业务事实。';
COMMENT ON COLUMN authz.permission_simulation.input_hash IS '不可逆摘要；用于等值匹配、幂等、完整性或最小化证据，不保存原始敏感值。';
COMMENT ON COLUMN authz.permission_simulation.policy_version IS '对象、策略或源数据的显式版本；不得以不可信客户端时间戳替代。';
COMMENT ON COLUMN authz.permission_simulation.simulation_result IS '版本化结构化扩展数据；必须由 .NET 按对应 JSON Schema 校验，不得替代核心状态或外键。';
COMMENT ON COLUMN authz.permission_simulation.result_hash IS '不可逆摘要；用于等值匹配、幂等、完整性或最小化证据，不保存原始敏感值。';
COMMENT ON COLUMN authz.permission_simulation.trace_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN authz.permission_simulation.simulated_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN authz.permission_simulation.expires_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';

COMMENT ON CONSTRAINT pk_permission ON authz.permission IS '主键约束：唯一标识 authz.permission 记录。';
COMMENT ON CONSTRAINT uq_permission_code ON authz.permission IS '唯一约束：保证 permission_code 在 authz.permission 范围内不重复。';
COMMENT ON CONSTRAINT uq_permission_tuple ON authz.permission IS '唯一约束：保证 resource_type、action_code 在 authz.permission 范围内不重复。';
COMMENT ON CONSTRAINT ck_permission_code ON authz.permission IS '检查约束：限制 authz.permission 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_permission_risk ON authz.permission IS '检查约束：限制 authz.permission 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT pk_role ON authz.role IS '主键约束：唯一标识 authz.role 记录。';
COMMENT ON CONSTRAINT uq_role_public_id ON authz.role IS '唯一约束：保证 public_id 在 authz.role 范围内不重复。';
COMMENT ON CONSTRAINT ck_role_scope ON authz.role IS '检查约束：限制 authz.role 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_role_state ON authz.role IS '检查约束：限制 authz.role 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_role_tier ON authz.role IS '检查约束：限制 authz.role 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT uq_role_code_scope ON authz.role IS '唯一约束：保证 role_code、scope_kind、business_line_id、tenant_id、organization_id 在 authz.role 范围内不重复。';
COMMENT ON CONSTRAINT ck_role_scope_value ON authz.role IS '检查约束：限制 authz.role 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT pk_role_permission ON authz.role_permission IS '主键约束：唯一标识 authz.role_permission 记录。';
COMMENT ON CONSTRAINT fk_role_permission_role ON authz.role_permission IS '外键约束：authz.role_permission 的 role_id 必须引用 authz.role；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT fk_role_permission_permission ON authz.role_permission IS '外键约束：authz.role_permission 的 permission_id 必须引用 authz.permission；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT ck_role_permission_effect ON authz.role_permission IS '检查约束：限制 authz.role_permission 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_role_permission_window ON authz.role_permission IS '检查约束：限制 authz.role_permission 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT pk_role_exclusion ON authz.role_exclusion IS '主键约束：唯一标识 authz.role_exclusion 记录。';
COMMENT ON CONSTRAINT fk_role_exclusion_role ON authz.role_exclusion IS '外键约束：authz.role_exclusion 的 role_id 必须引用 authz.role；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT fk_role_exclusion_other ON authz.role_exclusion IS '外键约束：authz.role_exclusion 的 excluded_role_id 必须引用 authz.role；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT ck_role_exclusion_self ON authz.role_exclusion IS '检查约束：限制 authz.role_exclusion 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT pk_role_assignment ON authz.role_assignment IS '主键约束：唯一标识 authz.role_assignment 记录。';
COMMENT ON CONSTRAINT fk_role_assignment_role ON authz.role_assignment IS '外键约束：authz.role_assignment 的 role_id 必须引用 authz.role；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT ck_role_assignment_subject ON authz.role_assignment IS '检查约束：限制 authz.role_assignment 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_role_assignment_state ON authz.role_assignment IS '检查约束：限制 authz.role_assignment 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_role_assignment_window ON authz.role_assignment IS '检查约束：限制 authz.role_assignment 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_role_assignment_revoked ON authz.role_assignment IS '检查约束：限制 authz.role_assignment 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_role_assignment_revoke_reason ON authz.role_assignment IS '检查约束：限制 authz.role_assignment 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT pk_policy_release ON authz.policy_release IS '主键约束：唯一标识 authz.policy_release 记录。';
COMMENT ON CONSTRAINT uq_policy_release_public_id ON authz.policy_release IS '唯一约束：保证 public_id 在 authz.policy_release 范围内不重复。';
COMMENT ON CONSTRAINT uq_policy_release_version ON authz.policy_release IS '唯一约束：保证 policy_code、policy_version 在 authz.policy_release 范围内不重复。';
COMMENT ON CONSTRAINT ck_policy_release_state ON authz.policy_release IS '检查约束：限制 authz.policy_release 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_policy_release_language ON authz.policy_release IS '检查约束：限制 authz.policy_release 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_policy_release_hash ON authz.policy_release IS '检查约束：限制 authz.policy_release 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_policy_release_active ON authz.policy_release IS '检查约束：限制 authz.policy_release 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_policy_release_state_times ON authz.policy_release IS '检查约束：限制 authz.policy_release 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT pk_obligation_type ON authz.obligation_type IS '主键约束：唯一标识 authz.obligation_type 记录。';
COMMENT ON CONSTRAINT ck_obligation_execution ON authz.obligation_type IS '检查约束：限制 authz.obligation_type 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT pk_pep_capability ON authz.pep_capability IS '主键约束：唯一标识 authz.pep_capability 记录。';
COMMENT ON CONSTRAINT ck_pep_capability_version ON authz.pep_capability IS '检查约束：限制 authz.pep_capability 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_pep_capability_expiry ON authz.pep_capability IS '检查约束：限制 authz.pep_capability 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT pk_authorization_decision ON authz.authorization_decision IS '主键约束：唯一标识 authz.authorization_decision 记录。';
COMMENT ON CONSTRAINT uq_authorization_decision_public_id ON authz.authorization_decision IS '唯一约束：保证 public_id 在 authz.authorization_decision 范围内不重复。';
COMMENT ON CONSTRAINT ck_authorization_decision_actor ON authz.authorization_decision IS '检查约束：限制 authz.authorization_decision 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_authorization_decision_risk ON authz.authorization_decision IS '检查约束：限制 authz.authorization_decision 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_authorization_decision_aal ON authz.authorization_decision IS '检查约束：限制 authz.authorization_decision 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_authorization_decision_effect ON authz.authorization_decision IS '检查约束：限制 authz.authorization_decision 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_authorization_decision_hash ON authz.authorization_decision IS '检查约束：限制 authz.authorization_decision 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_authorization_decision_ttl ON authz.authorization_decision IS '检查约束：限制 authz.authorization_decision 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT pk_relationship_tuple ON authz.relationship_tuple IS '主键约束：唯一标识 authz.relationship_tuple 记录。';
COMMENT ON CONSTRAINT ck_relationship_tuple_subject ON authz.relationship_tuple IS '检查约束：限制 authz.relationship_tuple 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_relationship_tuple_state ON authz.relationship_tuple IS '检查约束：限制 authz.relationship_tuple 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_relationship_tuple_source ON authz.relationship_tuple IS '检查约束：限制 authz.relationship_tuple 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_relationship_tuple_window ON authz.relationship_tuple IS '检查约束：限制 authz.relationship_tuple 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_relationship_tuple_revoked ON authz.relationship_tuple IS '检查约束：限制 authz.relationship_tuple 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT pk_access_review ON authz.access_review IS '主键约束：唯一标识 authz.access_review 记录。';
COMMENT ON CONSTRAINT uq_access_review_public_id ON authz.access_review IS '唯一约束：保证 public_id 在 authz.access_review 范围内不重复。';
COMMENT ON CONSTRAINT uq_access_review_operation ON authz.access_review IS '唯一约束：保证 operation_id 在 authz.access_review 范围内不重复。';
COMMENT ON CONSTRAINT ck_access_review_kind ON authz.access_review IS '检查约束：限制 authz.access_review 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_access_review_state ON authz.access_review IS '检查约束：限制 authz.access_review 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_access_review_counts ON authz.access_review IS '检查约束：限制 authz.access_review 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_access_review_complete ON authz.access_review IS '检查约束：限制 authz.access_review 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT pk_permission_simulation ON authz.permission_simulation IS '主键约束：唯一标识 authz.permission_simulation 记录。';
COMMENT ON CONSTRAINT uq_permission_simulation_public_id ON authz.permission_simulation IS '唯一约束：保证 public_id 在 authz.permission_simulation 范围内不重复。';
COMMENT ON CONSTRAINT ck_permission_simulation_hash ON authz.permission_simulation IS '检查约束：限制 authz.permission_simulation 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_permission_simulation_expiry ON authz.permission_simulation IS '检查约束：限制 authz.permission_simulation 的字段取值或组合满足结构与安全底线。';

COMMENT ON INDEX authz.ix_role_assignment_subject IS '查询索引：优化 authz.role_assignment 按 subject_kind、subject_id、assignment_state 的访问。';
COMMENT ON INDEX authz.ix_role_assignment_scope IS '查询索引：优化 authz.role_assignment 按 tenant_id、organization_id 的访问，仅覆盖 WHERE 条件命中的记录。';
COMMENT ON INDEX authz.ux_policy_release_active IS '查询索引：优化 authz.policy_release 按 policy_code 的访问，仅覆盖 WHERE 条件命中的记录。';
COMMENT ON INDEX authz.ix_authorization_decision_lookup IS '查询索引：优化 authz.authorization_decision 按 subject_kind、subject_ref、action_code、decided_at 的访问。';
COMMENT ON INDEX authz.ux_relationship_tuple_active IS '查询索引：优化 authz.relationship_tuple 按 tenant_id、subject_kind、subject_ref、relation_code、object_kind、object_ref 的访问，仅覆盖 WHERE 条件命中的记录。';
COMMENT ON INDEX authz.ix_access_review_due IS '查询索引：优化 authz.access_review 按 due_at 的访问，仅覆盖 WHERE 条件命中的记录。';
COMMENT ON INDEX authz.ux_role_assignment_effective IS '查询索引：优化 authz.role_assignment 按 role_id、subject_kind、subject_id 的访问，仅覆盖 WHERE 条件命中的记录。';
COMMENT ON INDEX authz.pk_permission IS '约束 pk_permission 的支撑唯一索引。';
COMMENT ON INDEX authz.uq_permission_code IS '约束 uq_permission_code 的支撑唯一索引。';
COMMENT ON INDEX authz.uq_permission_tuple IS '约束 uq_permission_tuple 的支撑唯一索引。';
COMMENT ON INDEX authz.pk_role IS '约束 pk_role 的支撑唯一索引。';
COMMENT ON INDEX authz.uq_role_public_id IS '约束 uq_role_public_id 的支撑唯一索引。';
COMMENT ON INDEX authz.uq_role_code_scope IS '约束 uq_role_code_scope 的支撑唯一索引。';
COMMENT ON INDEX authz.pk_role_permission IS '约束 pk_role_permission 的支撑唯一索引。';
COMMENT ON INDEX authz.pk_role_exclusion IS '约束 pk_role_exclusion 的支撑唯一索引。';
COMMENT ON INDEX authz.pk_role_assignment IS '约束 pk_role_assignment 的支撑唯一索引。';
COMMENT ON INDEX authz.pk_policy_release IS '约束 pk_policy_release 的支撑唯一索引。';
COMMENT ON INDEX authz.uq_policy_release_public_id IS '约束 uq_policy_release_public_id 的支撑唯一索引。';
COMMENT ON INDEX authz.uq_policy_release_version IS '约束 uq_policy_release_version 的支撑唯一索引。';
COMMENT ON INDEX authz.pk_obligation_type IS '约束 pk_obligation_type 的支撑唯一索引。';
COMMENT ON INDEX authz.pk_pep_capability IS '约束 pk_pep_capability 的支撑唯一索引。';
COMMENT ON INDEX authz.pk_authorization_decision IS '约束 pk_authorization_decision 的支撑唯一索引。';
COMMENT ON INDEX authz.uq_authorization_decision_public_id IS '约束 uq_authorization_decision_public_id 的支撑唯一索引。';
COMMENT ON INDEX authz.pk_relationship_tuple IS '约束 pk_relationship_tuple 的支撑唯一索引。';
COMMENT ON INDEX authz.pk_access_review IS '约束 pk_access_review 的支撑唯一索引。';
COMMENT ON INDEX authz.uq_access_review_public_id IS '约束 uq_access_review_public_id 的支撑唯一索引。';
COMMENT ON INDEX authz.uq_access_review_operation IS '约束 uq_access_review_operation 的支撑唯一索引。';
COMMENT ON INDEX authz.pk_permission_simulation IS '约束 pk_permission_simulation 的支撑唯一索引。';
COMMENT ON INDEX authz.uq_permission_simulation_public_id IS '约束 uq_permission_simulation_public_id 的支撑唯一索引。';
COMMENT ON INDEX authz.ix_fk_role_permission_permission_id IS '查询索引：优化 authz.role_permission 按 permission_id 的访问。';
COMMENT ON INDEX authz.ix_fk_role_exclusion_excluded_role_id IS '查询索引：优化 authz.role_exclusion 按 excluded_role_id 的访问。';
COMMENT ON INDEX authz.ix_fk_role_assignment_role_id IS '查询索引：优化 authz.role_assignment 按 role_id 的访问。';

