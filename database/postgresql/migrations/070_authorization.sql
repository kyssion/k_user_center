\set ON_ERROR_STOP on

SET ROLE iam_owner;

-- 授权目录、角色关系、策略版本和决策证据。数据库保存事实，不执行 PDP/PEP。

CREATE TABLE iam.permissions (
    id uuid PRIMARY KEY,
    permission_code varchar(200) NOT NULL,
    resource_type varchar(100) NOT NULL,
    action varchar(100) NOT NULL,
    sensitivity varchar(40) NOT NULL,
    description text,
    state varchar(40) NOT NULL,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    row_version bigint NOT NULL DEFAULT 0,
    CONSTRAINT uq_permissions_code UNIQUE (permission_code),
    CONSTRAINT ck_permissions_version CHECK (row_version >= 0)
);
COMMENT ON TABLE iam.permissions IS '稳定权限目录；权限组合、互斥和决策由 AUTHZ 代码处理。';
COMMENT ON COLUMN iam.permissions.id IS '应用生成的权限 UUIDv7。';
COMMENT ON COLUMN iam.permissions.permission_code IS '全局稳定权限代码。';
COMMENT ON COLUMN iam.permissions.resource_type IS '权限适用资源类型。';
COMMENT ON COLUMN iam.permissions.action IS '受控动作代码。';
COMMENT ON COLUMN iam.permissions.sensitivity IS '权限敏感级别。';
COMMENT ON COLUMN iam.permissions.description IS '可空；管理员说明。';
COMMENT ON COLUMN iam.permissions.state IS '权限目录状态。';
COMMENT ON COLUMN iam.permissions.created_at IS '数据库插入时间。';
COMMENT ON COLUMN iam.permissions.updated_at IS '数据库更新时间；应用显式刷新。';
COMMENT ON COLUMN iam.permissions.row_version IS '乐观锁版本。';

CREATE TABLE iam.roles (
    id uuid PRIMARY KEY,
    role_code varchar(160) NOT NULL,
    scope_type varchar(40) NOT NULL,
    owner_type varchar(40) NOT NULL,
    owner_id uuid,
    display_name varchar(200) NOT NULL,
    description text,
    state varchar(40) NOT NULL,
    role_version bigint NOT NULL DEFAULT 0,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    row_version bigint NOT NULL DEFAULT 0,
    CONSTRAINT uq_roles_code UNIQUE NULLS NOT DISTINCT (owner_type, owner_id, scope_type, role_code),
    CONSTRAINT ck_roles_versions CHECK (role_version >= 0 AND row_version >= 0)
);
COMMENT ON TABLE iam.roles IS '作用域化角色定义；继承、互斥、最大权限和发布规则由 AUTHZ 代码维护。';
COMMENT ON COLUMN iam.roles.id IS '应用生成的角色 UUIDv7。';
COMMENT ON COLUMN iam.roles.role_code IS '所有者和作用域内稳定角色代码。';
COMMENT ON COLUMN iam.roles.scope_type IS '角色可授予的作用域类型。';
COMMENT ON COLUMN iam.roles.owner_type IS '角色定义所有者类型。';
COMMENT ON COLUMN iam.roles.owner_id IS '可空；平台内置角色为空，其他按 owner_type 逻辑引用。';
COMMENT ON COLUMN iam.roles.display_name IS '角色展示名称。';
COMMENT ON COLUMN iam.roles.description IS '可空；角色说明。';
COMMENT ON COLUMN iam.roles.state IS '角色状态。';
COMMENT ON COLUMN iam.roles.role_version IS '角色语义版本。';
COMMENT ON COLUMN iam.roles.created_at IS '数据库插入时间。';
COMMENT ON COLUMN iam.roles.updated_at IS '数据库更新时间；应用显式刷新。';
COMMENT ON COLUMN iam.roles.row_version IS '乐观锁版本。';

CREATE TABLE iam.role_permissions (
    id uuid PRIMARY KEY,
    role_id uuid NOT NULL,
    permission_id uuid NOT NULL,
    condition_snapshot jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_by_type varchar(40) NOT NULL,
    created_by_id uuid NOT NULL,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    removed_at timestamptz,
    CONSTRAINT uq_role_permissions UNIQUE (role_id, permission_id)
);
COMMENT ON TABLE iam.role_permissions IS '角色到权限的关系事实；发布和权限组合由 AUTHZ 代码校验。';
COMMENT ON COLUMN iam.role_permissions.id IS '应用生成的关系 UUIDv7。';
COMMENT ON COLUMN iam.role_permissions.role_id IS '逻辑引用 iam.roles.id。';
COMMENT ON COLUMN iam.role_permissions.permission_id IS '逻辑引用 iam.permissions.id。';
COMMENT ON COLUMN iam.role_permissions.condition_snapshot IS '可选附加条件快照；由策略引擎解释。';
COMMENT ON COLUMN iam.role_permissions.created_by_type IS '创建者类型。';
COMMENT ON COLUMN iam.role_permissions.created_by_id IS '创建者逻辑 ID。';
COMMENT ON COLUMN iam.role_permissions.created_at IS '数据库插入时间。';
COMMENT ON COLUMN iam.role_permissions.removed_at IS '可空；关系停止生效时间。';

CREATE TABLE iam.user_role_assignments (
    id uuid PRIMARY KEY,
    user_id uuid NOT NULL,
    role_id uuid NOT NULL,
    scope_type varchar(40) NOT NULL,
    scope_id uuid NOT NULL,
    granted_by_type varchar(40) NOT NULL,
    granted_by_id uuid NOT NULL,
    reason_code varchar(100),
    valid_from timestamptz NOT NULL,
    valid_until timestamptz,
    state varchar(40) NOT NULL,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    row_version bigint NOT NULL DEFAULT 0,
    CONSTRAINT uq_user_role_assignment UNIQUE (user_id, role_id, scope_type, scope_id, valid_from),
    CONSTRAINT ck_user_role_validity CHECK (valid_until IS NULL OR valid_until > valid_from),
    CONSTRAINT ck_user_role_version CHECK (row_version >= 0)
);
COMMENT ON TABLE iam.user_role_assignments IS '用户角色授予事实；作用域包含、权限上界、审批和有效性由 AUTHZ 代码检查。';
COMMENT ON COLUMN iam.user_role_assignments.id IS '应用生成的授予 UUIDv7。';
COMMENT ON COLUMN iam.user_role_assignments.user_id IS '逻辑引用 iam.global_users.id。';
COMMENT ON COLUMN iam.user_role_assignments.role_id IS '逻辑引用 iam.roles.id。';
COMMENT ON COLUMN iam.user_role_assignments.scope_type IS '授权作用域类型。';
COMMENT ON COLUMN iam.user_role_assignments.scope_id IS '授权作用域逻辑 ID。';
COMMENT ON COLUMN iam.user_role_assignments.granted_by_type IS '授予者类型。';
COMMENT ON COLUMN iam.user_role_assignments.granted_by_id IS '授予者逻辑 ID。';
COMMENT ON COLUMN iam.user_role_assignments.reason_code IS '可空；授予原因码。';
COMMENT ON COLUMN iam.user_role_assignments.valid_from IS '授权生效时间。';
COMMENT ON COLUMN iam.user_role_assignments.valid_until IS '可空；授权失效时间。';
COMMENT ON COLUMN iam.user_role_assignments.state IS '授予状态。';
COMMENT ON COLUMN iam.user_role_assignments.created_at IS '数据库插入时间。';
COMMENT ON COLUMN iam.user_role_assignments.updated_at IS '数据库更新时间；应用显式刷新。';
COMMENT ON COLUMN iam.user_role_assignments.row_version IS '乐观锁版本。';

CREATE TABLE iam.group_role_assignments (
    id uuid PRIMARY KEY,
    group_id uuid NOT NULL,
    role_id uuid NOT NULL,
    scope_type varchar(40) NOT NULL,
    scope_id uuid NOT NULL,
    valid_from timestamptz NOT NULL,
    valid_until timestamptz,
    state varchar(40) NOT NULL,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    row_version bigint NOT NULL DEFAULT 0,
    CONSTRAINT uq_group_role_assignment UNIQUE (group_id, role_id, scope_type, scope_id, valid_from),
    CONSTRAINT ck_group_role_validity CHECK (valid_until IS NULL OR valid_until > valid_from),
    CONSTRAINT ck_group_role_version CHECK (row_version >= 0)
);
COMMENT ON TABLE iam.group_role_assignments IS '用户组角色授予事实；成员展开和作用域检查由 AUTHZ 代码执行。';
COMMENT ON COLUMN iam.group_role_assignments.id IS '应用生成的授予 UUIDv7。';
COMMENT ON COLUMN iam.group_role_assignments.group_id IS '逻辑引用 iam.groups.id。';
COMMENT ON COLUMN iam.group_role_assignments.role_id IS '逻辑引用 iam.roles.id。';
COMMENT ON COLUMN iam.group_role_assignments.scope_type IS '授权作用域类型。';
COMMENT ON COLUMN iam.group_role_assignments.scope_id IS '授权作用域逻辑 ID。';
COMMENT ON COLUMN iam.group_role_assignments.valid_from IS '授权生效时间。';
COMMENT ON COLUMN iam.group_role_assignments.valid_until IS '可空；授权失效时间。';
COMMENT ON COLUMN iam.group_role_assignments.state IS '授予状态。';
COMMENT ON COLUMN iam.group_role_assignments.created_at IS '数据库插入时间。';
COMMENT ON COLUMN iam.group_role_assignments.updated_at IS '数据库更新时间；应用显式刷新。';
COMMENT ON COLUMN iam.group_role_assignments.row_version IS '乐观锁版本。';

CREATE TABLE iam.machine_role_assignments (
    id uuid PRIMARY KEY,
    machine_principal_id uuid NOT NULL,
    role_id uuid NOT NULL,
    scope_type varchar(40) NOT NULL,
    scope_id uuid NOT NULL,
    valid_from timestamptz NOT NULL,
    valid_until timestamptz,
    state varchar(40) NOT NULL,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    row_version bigint NOT NULL DEFAULT 0,
    CONSTRAINT uq_machine_role_assignment UNIQUE (machine_principal_id, role_id, scope_type, scope_id, valid_from),
    CONSTRAINT ck_machine_role_validity CHECK (valid_until IS NULL OR valid_until > valid_from),
    CONSTRAINT ck_machine_role_version CHECK (row_version >= 0)
);
COMMENT ON TABLE iam.machine_role_assignments IS '机器主体角色授予事实；环境、用途和最小权限由 MACHINE/AUTHZ 代码校验。';
COMMENT ON COLUMN iam.machine_role_assignments.id IS '应用生成的授予 UUIDv7。';
COMMENT ON COLUMN iam.machine_role_assignments.machine_principal_id IS '逻辑引用 iam.machine_principals.id。';
COMMENT ON COLUMN iam.machine_role_assignments.role_id IS '逻辑引用 iam.roles.id。';
COMMENT ON COLUMN iam.machine_role_assignments.scope_type IS '授权作用域类型。';
COMMENT ON COLUMN iam.machine_role_assignments.scope_id IS '授权作用域逻辑 ID。';
COMMENT ON COLUMN iam.machine_role_assignments.valid_from IS '授权生效时间。';
COMMENT ON COLUMN iam.machine_role_assignments.valid_until IS '可空；授权失效时间。';
COMMENT ON COLUMN iam.machine_role_assignments.state IS '授予状态。';
COMMENT ON COLUMN iam.machine_role_assignments.created_at IS '数据库插入时间。';
COMMENT ON COLUMN iam.machine_role_assignments.updated_at IS '数据库更新时间；应用显式刷新。';
COMMENT ON COLUMN iam.machine_role_assignments.row_version IS '乐观锁版本。';

CREATE TABLE iam.data_scope_definitions (
    id uuid PRIMARY KEY,
    scope_code varchar(160) NOT NULL,
    scope_type varchar(40) NOT NULL,
    owner_type varchar(40) NOT NULL,
    owner_id uuid,
    schema_version integer NOT NULL,
    definition jsonb NOT NULL,
    definition_digest char(64) NOT NULL,
    state varchar(40) NOT NULL,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    row_version bigint NOT NULL DEFAULT 0,
    CONSTRAINT uq_data_scope_code UNIQUE NULLS NOT DISTINCT (owner_type, owner_id, scope_code),
    CONSTRAINT ck_data_scope_schema CHECK (schema_version > 0),
    CONSTRAINT ck_data_scope_version CHECK (row_version >= 0)
);
COMMENT ON TABLE iam.data_scope_definitions IS '数据范围定义；表达式 Schema、求值和资源适配由 AUTHZ 代码负责。';
COMMENT ON COLUMN iam.data_scope_definitions.id IS '应用生成的数据范围 UUIDv7。';
COMMENT ON COLUMN iam.data_scope_definitions.scope_code IS '所有者内稳定数据范围代码。';
COMMENT ON COLUMN iam.data_scope_definitions.scope_type IS '数据范围类型。';
COMMENT ON COLUMN iam.data_scope_definitions.owner_type IS '定义所有者类型。';
COMMENT ON COLUMN iam.data_scope_definitions.owner_id IS '可空；按 owner_type 逻辑引用所有者对象，平台定义为空。';
COMMENT ON COLUMN iam.data_scope_definitions.schema_version IS '定义 JSON Schema 正整数版本。';
COMMENT ON COLUMN iam.data_scope_definitions.definition IS '数据范围定义载荷；数据库不解释。';
COMMENT ON COLUMN iam.data_scope_definitions.definition_digest IS '规范化定义 SHA-256 摘要。';
COMMENT ON COLUMN iam.data_scope_definitions.state IS '定义状态。';
COMMENT ON COLUMN iam.data_scope_definitions.created_at IS '数据库插入时间。';
COMMENT ON COLUMN iam.data_scope_definitions.updated_at IS '数据库更新时间；应用显式刷新。';
COMMENT ON COLUMN iam.data_scope_definitions.row_version IS '乐观锁版本。';

CREATE TABLE iam.policy_versions (
    id uuid PRIMARY KEY,
    policy_code varchar(160) NOT NULL,
    scope_type varchar(40) NOT NULL,
    scope_id uuid,
    version integer NOT NULL,
    schema_version integer NOT NULL,
    payload jsonb NOT NULL,
    payload_digest char(64) NOT NULL,
    state varchar(40) NOT NULL,
    published_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    row_version bigint NOT NULL DEFAULT 0,
    CONSTRAINT uq_policy_versions UNIQUE NULLS NOT DISTINCT (policy_code, scope_type, scope_id, version),
    CONSTRAINT ck_policy_versions_numbers CHECK (version > 0 AND schema_version > 0 AND row_version >= 0)
);
COMMENT ON TABLE iam.policy_versions IS '不可变授权策略版本；编译、测试、发布和求值由 AUTHZ 控制面及 PDP 代码完成。';
COMMENT ON COLUMN iam.policy_versions.id IS '应用生成的策略版本 UUIDv7。';
COMMENT ON COLUMN iam.policy_versions.policy_code IS '稳定策略代码。';
COMMENT ON COLUMN iam.policy_versions.scope_type IS '策略定义作用域类型。';
COMMENT ON COLUMN iam.policy_versions.scope_id IS '可空；作用域逻辑 ID。';
COMMENT ON COLUMN iam.policy_versions.version IS '同策略作用域内正整数版本。';
COMMENT ON COLUMN iam.policy_versions.schema_version IS '策略载荷 Schema 版本。';
COMMENT ON COLUMN iam.policy_versions.payload IS '策略源或中间表示；数据库不执行。';
COMMENT ON COLUMN iam.policy_versions.payload_digest IS '规范化策略 SHA-256 摘要。';
COMMENT ON COLUMN iam.policy_versions.state IS '策略版本状态。';
COMMENT ON COLUMN iam.policy_versions.published_at IS '可空；发布业务时间。';
COMMENT ON COLUMN iam.policy_versions.created_at IS '数据库插入时间。';
COMMENT ON COLUMN iam.policy_versions.row_version IS '发布生命周期元数据的乐观锁版本；策略载荷字段不可更新。';

CREATE TABLE iam.policy_bindings (
    id uuid PRIMARY KEY,
    policy_version_id uuid NOT NULL,
    target_type varchar(40) NOT NULL,
    target_id uuid NOT NULL,
    scope_type varchar(40) NOT NULL,
    scope_id uuid,
    priority integer NOT NULL DEFAULT 0,
    state varchar(40) NOT NULL,
    effective_at timestamptz NOT NULL,
    expires_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    row_version bigint NOT NULL DEFAULT 0,
    CONSTRAINT uq_policy_binding UNIQUE NULLS NOT DISTINCT (policy_version_id, target_type, target_id, scope_type, scope_id),
    CONSTRAINT ck_policy_binding_expiry CHECK (expires_at IS NULL OR expires_at > effective_at),
    CONSTRAINT ck_policy_binding_version CHECK (row_version >= 0)
);
COMMENT ON TABLE iam.policy_bindings IS '策略版本到 Client、资源、租户或动作的绑定；优先级冲突和有效集合由 AUTHZ 代码解析。';
COMMENT ON COLUMN iam.policy_bindings.id IS '应用生成的绑定 UUIDv7。';
COMMENT ON COLUMN iam.policy_bindings.policy_version_id IS '逻辑引用 iam.policy_versions.id。';
COMMENT ON COLUMN iam.policy_bindings.target_type IS '绑定目标类型。';
COMMENT ON COLUMN iam.policy_bindings.target_id IS '绑定目标逻辑 ID。';
COMMENT ON COLUMN iam.policy_bindings.scope_type IS '绑定作用域类型。';
COMMENT ON COLUMN iam.policy_bindings.scope_id IS '可空；绑定作用域逻辑 ID。';
COMMENT ON COLUMN iam.policy_bindings.priority IS '候选策略排序值；合并语义由代码定义。';
COMMENT ON COLUMN iam.policy_bindings.state IS '绑定状态。';
COMMENT ON COLUMN iam.policy_bindings.effective_at IS '绑定生效时间。';
COMMENT ON COLUMN iam.policy_bindings.expires_at IS '可空；绑定失效时间。';
COMMENT ON COLUMN iam.policy_bindings.created_at IS '数据库插入时间。';
COMMENT ON COLUMN iam.policy_bindings.updated_at IS '数据库更新时间；应用显式刷新。';
COMMENT ON COLUMN iam.policy_bindings.row_version IS '乐观锁版本。';

CREATE TABLE iam.authorization_decisions (
    id uuid NOT NULL,
    decision_id uuid NOT NULL,
    subject_type varchar(40) NOT NULL,
    subject_id uuid NOT NULL,
    actor_type varchar(40),
    actor_id uuid,
    delegation_id uuid,
    delegation_chain_snapshot jsonb NOT NULL DEFAULT '[]'::jsonb,
    action varchar(160) NOT NULL,
    resource_type varchar(100) NOT NULL,
    resource_id varchar(256) NOT NULL,
    tenant_id uuid,
    input_digest char(64) NOT NULL,
    decision varchar(20) NOT NULL,
    reason_codes text[] NOT NULL DEFAULT ARRAY[]::text[],
    obligations jsonb NOT NULL DEFAULT '[]'::jsonb,
    security_profile_code varchar(40) NOT NULL,
    security_profile_version integer NOT NULL,
    policy_version_ids uuid[] NOT NULL DEFAULT ARRAY[]::uuid[],
    policy_set_digest char(64) NOT NULL,
    context_version_snapshot jsonb NOT NULL DEFAULT '{}'::jsonb,
    consent_id uuid,
    consent_epoch bigint,
    latency_ms integer,
    decided_at timestamptz NOT NULL,
    valid_until timestamptz NOT NULL,
    CONSTRAINT pk_authorization_decisions PRIMARY KEY (id, decided_at),
    CONSTRAINT ck_authorization_decision_profile_version CHECK (security_profile_version > 0),
    CONSTRAINT ck_authorization_decision_consent_epoch CHECK (consent_epoch IS NULL OR consent_epoch >= 0),
    CONSTRAINT ck_authorization_decision_latency CHECK (latency_ms IS NULL OR latency_ms >= 0),
    CONSTRAINT ck_authorization_decision_validity CHECK (valid_until >= decided_at)
) PARTITION BY RANGE (decided_at);
COMMENT ON TABLE iam.authorization_decisions IS 'PDP 授权决策证据；按 decided_at 月度分区，数据库不重算或解释允许、拒绝与 Obligation。';
COMMENT ON COLUMN iam.authorization_decisions.id IS '应用生成的记录 UUIDv7。';
COMMENT ON COLUMN iam.authorization_decisions.decision_id IS '对外追踪的全局决策 UUID；跨分区唯一性由 PDP 保证。';
COMMENT ON COLUMN iam.authorization_decisions.subject_type IS '决策主体类型。';
COMMENT ON COLUMN iam.authorization_decisions.subject_id IS '主体逻辑 ID。';
COMMENT ON COLUMN iam.authorization_decisions.actor_type IS '可空；代理、管理或 Token Exchange 场景中的 Actor 类型。';
COMMENT ON COLUMN iam.authorization_decisions.actor_id IS '可空；按 actor_type 逻辑引用自然人、机器主体或 Client。';
COMMENT ON COLUMN iam.authorization_decisions.delegation_id IS '可空；逻辑引用 iam.delegations.id。';
COMMENT ON COLUMN iam.authorization_decisions.delegation_chain_snapshot IS '参与决策的完整委托链快照；代码负责校验范围、深度、撤销和不扩权。';
COMMENT ON COLUMN iam.authorization_decisions.action IS '请求动作。';
COMMENT ON COLUMN iam.authorization_decisions.resource_type IS '资源类型。';
COMMENT ON COLUMN iam.authorization_decisions.resource_id IS '资源稳定 ID 或规范化标识。';
COMMENT ON COLUMN iam.authorization_decisions.tenant_id IS '可空；逻辑引用 iam.tenants.id。';
COMMENT ON COLUMN iam.authorization_decisions.input_digest IS '规范化决策输入摘要。';
COMMENT ON COLUMN iam.authorization_decisions.decision IS 'ALLOW 或 DENY 等决策结果；值域由 PDP 代码定义。';
COMMENT ON COLUMN iam.authorization_decisions.reason_codes IS '稳定原因码列表。';
COMMENT ON COLUMN iam.authorization_decisions.obligations IS 'PEP 必须执行的 Obligation 快照。';
COMMENT ON COLUMN iam.authorization_decisions.security_profile_code IS '决策时适用的 Security Profile 稳定代码。';
COMMENT ON COLUMN iam.authorization_decisions.security_profile_version IS '决策时适用的 Security Profile 正整数版本。';
COMMENT ON COLUMN iam.authorization_decisions.policy_version_ids IS '参与决策的 iam.policy_versions.id 逻辑引用数组。';
COMMENT ON COLUMN iam.authorization_decisions.policy_set_digest IS '实际策略集合摘要。';
COMMENT ON COLUMN iam.authorization_decisions.context_version_snapshot IS '资源版本、PIP 属性版本和新鲜度、风险、保证等级及安全水位等缓存上下文快照。';
COMMENT ON COLUMN iam.authorization_decisions.consent_id IS '可空；以 Consent 为依据时逻辑引用 iam.consents.id。';
COMMENT ON COLUMN iam.authorization_decisions.consent_epoch IS '可空；决策时适用的 Consent 安全水位。';
COMMENT ON COLUMN iam.authorization_decisions.latency_ms IS '可空；PDP 非负处理耗时毫秒数。';
COMMENT ON COLUMN iam.authorization_decisions.decided_at IS '决策时间和月度分区键。';
COMMENT ON COLUMN iam.authorization_decisions.valid_until IS '本决策和缓存结果最晚可复用时间；是否允许复用仍由 PDP/PEP 代码判断。';

CREATE TABLE iam.relationship_tuples (
    id uuid PRIMARY KEY,
    subject_type varchar(40) NOT NULL,
    subject_id uuid NOT NULL,
    relation varchar(100) NOT NULL,
    resource_type varchar(100) NOT NULL,
    resource_id varchar(256) NOT NULL,
    tenant_id uuid,
    source_type varchar(40) NOT NULL,
    source_id uuid,
    valid_from timestamptz NOT NULL,
    valid_until timestamptz,
    state varchar(40) NOT NULL,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    row_version bigint NOT NULL DEFAULT 0,
    CONSTRAINT uq_relationship_tuple UNIQUE NULLS NOT DISTINCT (subject_type, subject_id, relation, resource_type, resource_id, tenant_id, valid_from),
    CONSTRAINT ck_relationship_tuple_validity CHECK (valid_until IS NULL OR valid_until > valid_from),
    CONSTRAINT ck_relationship_tuple_version CHECK (row_version >= 0)
);
COMMENT ON TABLE iam.relationship_tuples IS '关系型授权事实；图遍历、层级继承、循环防护和一致性由 AUTHZ 代码执行。';
COMMENT ON COLUMN iam.relationship_tuples.id IS '应用生成的关系 UUIDv7。';
COMMENT ON COLUMN iam.relationship_tuples.subject_type IS '关系主体类型。';
COMMENT ON COLUMN iam.relationship_tuples.subject_id IS '主体逻辑 ID。';
COMMENT ON COLUMN iam.relationship_tuples.relation IS '稳定关系代码。';
COMMENT ON COLUMN iam.relationship_tuples.resource_type IS '资源类型。';
COMMENT ON COLUMN iam.relationship_tuples.resource_id IS '资源稳定 ID。';
COMMENT ON COLUMN iam.relationship_tuples.tenant_id IS '可空；逻辑引用 iam.tenants.id。';
COMMENT ON COLUMN iam.relationship_tuples.source_type IS '关系来源类型。';
COMMENT ON COLUMN iam.relationship_tuples.source_id IS '可空；关系来源逻辑 ID。';
COMMENT ON COLUMN iam.relationship_tuples.valid_from IS '关系生效时间。';
COMMENT ON COLUMN iam.relationship_tuples.valid_until IS '可空；关系失效时间。';
COMMENT ON COLUMN iam.relationship_tuples.state IS '关系状态。';
COMMENT ON COLUMN iam.relationship_tuples.created_at IS '数据库插入时间。';
COMMENT ON COLUMN iam.relationship_tuples.updated_at IS '数据库更新时间；应用显式刷新。';
COMMENT ON COLUMN iam.relationship_tuples.row_version IS '乐观锁版本。';

CREATE INDEX ix_role_permissions_permission ON iam.role_permissions (permission_id, removed_at);
CREATE INDEX ix_user_role_assignments_effective ON iam.user_role_assignments (user_id, scope_type, scope_id, state, valid_until);
CREATE INDEX ix_group_role_assignments_effective ON iam.group_role_assignments (group_id, state, valid_until);
CREATE INDEX ix_machine_role_assignments_effective ON iam.machine_role_assignments (machine_principal_id, state, valid_until);
CREATE INDEX ix_policy_bindings_target ON iam.policy_bindings (target_type, target_id, state, priority DESC);
CREATE INDEX ix_authorization_decisions_subject ON iam.authorization_decisions (subject_type, subject_id, decided_at DESC);
CREATE INDEX ix_authorization_decisions_resource ON iam.authorization_decisions (resource_type, resource_id, decided_at DESC);
CREATE INDEX ix_relationship_tuples_subject ON iam.relationship_tuples (subject_type, subject_id, relation, state);
CREATE INDEX ix_relationship_tuples_resource ON iam.relationship_tuples (resource_type, resource_id, relation, state);
COMMENT ON INDEX iam.ix_policy_bindings_target IS 'PDP 按目标和优先级加载候选策略绑定。';
