\set ON_ERROR_STOP on

SET ROLE iam_owner;

-- 机器身份、工作负载证明、委托和通用高风险审批。

CREATE TABLE iam.machine_principals (
    id uuid PRIMARY KEY,
    principal_id varchar(128) NOT NULL,
    principal_type varchar(40) NOT NULL,
    owner_type varchar(40) NOT NULL,
    owner_id uuid NOT NULL,
    purpose varchar(200) NOT NULL,
    environment varchar(40) NOT NULL,
    tenant_id uuid,
    state varchar(40) NOT NULL,
    security_epoch bigint NOT NULL DEFAULT 0,
    expires_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    row_version bigint NOT NULL DEFAULT 0,
    CONSTRAINT uq_machine_principals_public UNIQUE (principal_id),
    CONSTRAINT ck_machine_principals_epoch CHECK (security_epoch >= 0),
    CONSTRAINT ck_machine_principals_version CHECK (row_version >= 0),
    CONSTRAINT ck_machine_principals_expiry CHECK (expires_at IS NULL OR expires_at > created_at)
);
COMMENT ON TABLE iam.machine_principals IS '服务账号、工作负载、机器人等机器主体；用途、环境、到期和生命周期由 MACHINE 代码强制。';
COMMENT ON COLUMN iam.machine_principals.id IS '应用生成的机器主体 UUIDv7。';
COMMENT ON COLUMN iam.machine_principals.principal_id IS '协议和审计使用的不可推断机器主体 ID。';
COMMENT ON COLUMN iam.machine_principals.principal_type IS '机器主体类型。';
COMMENT ON COLUMN iam.machine_principals.owner_type IS '责任所有者类型。';
COMMENT ON COLUMN iam.machine_principals.owner_id IS '责任所有者逻辑 ID。';
COMMENT ON COLUMN iam.machine_principals.purpose IS '经批准的用途说明。';
COMMENT ON COLUMN iam.machine_principals.environment IS '环境边界，例如 PROD、TEST。';
COMMENT ON COLUMN iam.machine_principals.tenant_id IS '可空；逻辑引用 iam.tenants.id。';
COMMENT ON COLUMN iam.machine_principals.state IS '机器主体状态。';
COMMENT ON COLUMN iam.machine_principals.security_epoch IS '机器主体安全水位。';
COMMENT ON COLUMN iam.machine_principals.expires_at IS '可空；主体计划到期时间。';
COMMENT ON COLUMN iam.machine_principals.created_at IS '数据库插入时间。';
COMMENT ON COLUMN iam.machine_principals.updated_at IS '数据库更新时间；应用显式刷新。';
COMMENT ON COLUMN iam.machine_principals.row_version IS '乐观锁版本。';

CREATE TABLE iam.machine_credentials (
    id uuid PRIMARY KEY,
    machine_principal_id uuid NOT NULL,
    client_id uuid,
    credential_type varchar(40) NOT NULL,
    fingerprint varchar(256) NOT NULL,
    key_id uuid,
    certificate_id uuid,
    replaces_credential_id uuid,
    secret_hash varchar(256),
    state varchar(40) NOT NULL,
    valid_from timestamptz NOT NULL,
    valid_until timestamptz NOT NULL,
    last_used_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    row_version bigint NOT NULL DEFAULT 0,
    CONSTRAINT uq_machine_credential_fingerprint UNIQUE (credential_type, fingerprint),
    CONSTRAINT uq_machine_credential_replacement UNIQUE (replaces_credential_id),
    CONSTRAINT ck_machine_credential_material CHECK (key_id IS NOT NULL OR certificate_id IS NOT NULL OR secret_hash IS NOT NULL),
    CONSTRAINT ck_machine_credential_not_self_replacement CHECK (replaces_credential_id IS NULL OR replaces_credential_id <> id),
    CONSTRAINT ck_machine_credential_validity CHECK (valid_until > valid_from),
    CONSTRAINT ck_machine_credential_version CHECK (row_version >= 0)
);
COMMENT ON TABLE iam.machine_credentials IS '机器凭证元数据；私钥和 Secret 原文不落库，数据库保存唯一替代链，轮换、重叠窗口和认证判断属于非数据库职责。';
COMMENT ON COLUMN iam.machine_credentials.id IS '应用生成的机器凭证 UUIDv7。';
COMMENT ON COLUMN iam.machine_credentials.machine_principal_id IS '逻辑引用 iam.machine_principals.id。';
COMMENT ON COLUMN iam.machine_credentials.client_id IS '可空；逻辑引用 iam.oauth_clients.id。';
COMMENT ON COLUMN iam.machine_credentials.credential_type IS '凭证类型，例如 CERTIFICATE、PRIVATE_KEY_JWT、SECRET_HASH。';
COMMENT ON COLUMN iam.machine_credentials.fingerprint IS '凭证公有指纹或 Secret 安全摘要。';
COMMENT ON COLUMN iam.machine_credentials.key_id IS '可空；逻辑引用 iam.cryptographic_keys.id。';
COMMENT ON COLUMN iam.machine_credentials.certificate_id IS '可空；逻辑引用 iam.certificates.id。';
COMMENT ON COLUMN iam.machine_credentials.replaces_credential_id IS '可空；逻辑引用 iam.machine_credentials.id；记录本凭证唯一替代的旧凭证，数据库不判断旧凭证状态和轮换窗口。';
COMMENT ON COLUMN iam.machine_credentials.secret_hash IS '可空；Client Secret 自适应或 HMAC 摘要，不保存原文。';
COMMENT ON COLUMN iam.machine_credentials.state IS '凭证状态。';
COMMENT ON COLUMN iam.machine_credentials.valid_from IS '凭证生效时间。';
COMMENT ON COLUMN iam.machine_credentials.valid_until IS '凭证失效时间。';
COMMENT ON COLUMN iam.machine_credentials.last_used_at IS '可空；最近成功使用时间。';
COMMENT ON COLUMN iam.machine_credentials.created_at IS '数据库插入时间。';
COMMENT ON COLUMN iam.machine_credentials.updated_at IS '数据库更新时间；应用显式刷新。';
COMMENT ON COLUMN iam.machine_credentials.row_version IS '乐观锁版本。';

CREATE TABLE iam.workload_trust_bundle_versions (
    id uuid PRIMARY KEY,
    trust_domain varchar(253) NOT NULL,
    version integer NOT NULL,
    schema_version integer NOT NULL,
    payload jsonb NOT NULL,
    payload_digest char(64) NOT NULL,
    state varchar(40) NOT NULL,
    valid_from timestamptz NOT NULL,
    valid_until timestamptz NOT NULL,
    published_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    row_version bigint NOT NULL DEFAULT 0,
    CONSTRAINT uq_workload_trust_bundle UNIQUE (trust_domain, version),
    CONSTRAINT ck_workload_trust_versions CHECK (version > 0 AND schema_version > 0 AND row_version >= 0),
    CONSTRAINT ck_workload_trust_validity CHECK (valid_until > valid_from)
);
COMMENT ON TABLE iam.workload_trust_bundle_versions IS '工作负载信任域的不可变 Trust Bundle 版本；发布、重叠和验证由 MACHINE 代码执行。';
COMMENT ON COLUMN iam.workload_trust_bundle_versions.id IS '应用生成的 Trust Bundle UUIDv7。';
COMMENT ON COLUMN iam.workload_trust_bundle_versions.trust_domain IS '规范化信任域名称。';
COMMENT ON COLUMN iam.workload_trust_bundle_versions.version IS '信任域内正整数版本。';
COMMENT ON COLUMN iam.workload_trust_bundle_versions.schema_version IS '载荷 Schema 版本。';
COMMENT ON COLUMN iam.workload_trust_bundle_versions.payload IS '公开信任锚和验证参数，不含私钥。';
COMMENT ON COLUMN iam.workload_trust_bundle_versions.payload_digest IS '规范化载荷 SHA-256 摘要。';
COMMENT ON COLUMN iam.workload_trust_bundle_versions.state IS '版本发布状态。';
COMMENT ON COLUMN iam.workload_trust_bundle_versions.valid_from IS '验证生效时间。';
COMMENT ON COLUMN iam.workload_trust_bundle_versions.valid_until IS '验证失效时间。';
COMMENT ON COLUMN iam.workload_trust_bundle_versions.published_at IS '可空；发布时间。';
COMMENT ON COLUMN iam.workload_trust_bundle_versions.created_at IS '数据库插入时间。';
COMMENT ON COLUMN iam.workload_trust_bundle_versions.row_version IS '发布生命周期元数据的乐观锁版本；信任包载荷字段不可更新。';

CREATE TABLE iam.workload_attestations (
    id uuid NOT NULL,
    machine_principal_id uuid,
    trust_domain varchar(253) NOT NULL,
    issuer varchar(512) NOT NULL,
    audience varchar(512) NOT NULL,
    nonce_digest varchar(256),
    jti_digest varchar(256),
    evidence_digest char(64) NOT NULL,
    trust_bundle_version_id uuid NOT NULL,
    result varchar(40) NOT NULL,
    reason_codes text[] NOT NULL DEFAULT ARRAY[]::text[],
    expires_at timestamptz NOT NULL,
    received_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT pk_workload_attestations PRIMARY KEY (id, received_at)
) PARTITION BY RANGE (received_at);
COMMENT ON TABLE iam.workload_attestations IS '工作负载证明验证事实；按 received_at 月度分区，证明格式、信任链和重放校验由 MACHINE 代码执行。';
COMMENT ON COLUMN iam.workload_attestations.id IS '应用生成的证明记录 UUIDv7。';
COMMENT ON COLUMN iam.workload_attestations.machine_principal_id IS '可空；验证识别后逻辑引用 iam.machine_principals.id。';
COMMENT ON COLUMN iam.workload_attestations.trust_domain IS '声明的信任域。';
COMMENT ON COLUMN iam.workload_attestations.issuer IS '证明签发者。';
COMMENT ON COLUMN iam.workload_attestations.audience IS '证明目标 Audience。';
COMMENT ON COLUMN iam.workload_attestations.nonce_digest IS '可空；Nonce 安全摘要。';
COMMENT ON COLUMN iam.workload_attestations.jti_digest IS '可空；证明 JTI 安全摘要。';
COMMENT ON COLUMN iam.workload_attestations.evidence_digest IS '完整证明规范化摘要，不保存原始秘密。';
COMMENT ON COLUMN iam.workload_attestations.trust_bundle_version_id IS '逻辑引用 iam.workload_trust_bundle_versions.id。';
COMMENT ON COLUMN iam.workload_attestations.result IS '验证结果代码。';
COMMENT ON COLUMN iam.workload_attestations.reason_codes IS '稳定原因码列表。';
COMMENT ON COLUMN iam.workload_attestations.expires_at IS '证明声明的过期时间。';
COMMENT ON COLUMN iam.workload_attestations.received_at IS '数据库接收时间和月度分区键。';

CREATE TABLE iam.delegations (
    id uuid PRIMARY KEY,
    subject_user_id uuid NOT NULL,
    actor_user_id uuid NOT NULL,
    tenant_id uuid,
    scope_snapshot jsonb NOT NULL,
    max_depth integer NOT NULL,
    current_depth integer NOT NULL DEFAULT 1,
    state varchar(40) NOT NULL,
    valid_from timestamptz NOT NULL,
    valid_until timestamptz NOT NULL,
    reason_code varchar(100) NOT NULL,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    row_version bigint NOT NULL DEFAULT 0,
    CONSTRAINT ck_delegation_depth CHECK (max_depth >= 1 AND current_depth >= 1 AND current_depth <= max_depth),
    CONSTRAINT ck_delegation_validity CHECK (valid_until > valid_from),
    CONSTRAINT ck_delegation_version CHECK (row_version >= 0)
);
COMMENT ON TABLE iam.delegations IS '自然人委托关系；权限上界、链深、循环、再委托和敏感操作限制由 AUTHZ 代码执行。';
COMMENT ON COLUMN iam.delegations.id IS '应用生成的委托 UUIDv7。';
COMMENT ON COLUMN iam.delegations.subject_user_id IS '被代表人，逻辑引用 iam.global_users.id。';
COMMENT ON COLUMN iam.delegations.actor_user_id IS '代理人，逻辑引用 iam.global_users.id。';
COMMENT ON COLUMN iam.delegations.tenant_id IS '可空；逻辑引用 iam.tenants.id。';
COMMENT ON COLUMN iam.delegations.scope_snapshot IS '委托允许的权限和资源范围快照。';
COMMENT ON COLUMN iam.delegations.max_depth IS '允许委托链最大深度。';
COMMENT ON COLUMN iam.delegations.current_depth IS '当前委托链深度快照。';
COMMENT ON COLUMN iam.delegations.state IS '委托状态。';
COMMENT ON COLUMN iam.delegations.valid_from IS '委托生效时间。';
COMMENT ON COLUMN iam.delegations.valid_until IS '委托失效时间。';
COMMENT ON COLUMN iam.delegations.reason_code IS '委托原因码。';
COMMENT ON COLUMN iam.delegations.created_at IS '数据库插入时间。';
COMMENT ON COLUMN iam.delegations.updated_at IS '数据库更新时间；应用显式刷新。';
COMMENT ON COLUMN iam.delegations.row_version IS '乐观锁版本。';

CREATE TABLE iam.approval_cases (
    id uuid PRIMARY KEY,
    request_type varchar(100) NOT NULL,
    initiator_type varchar(40) NOT NULL,
    initiator_id uuid NOT NULL,
    tenant_id uuid,
    request_digest char(64) NOT NULL,
    request_snapshot jsonb NOT NULL,
    policy_version_id uuid,
    resource_version bigint,
    required_approvals integer NOT NULL,
    state varchar(40) NOT NULL,
    expires_at timestamptz NOT NULL,
    execution_id uuid,
    executed_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    row_version bigint NOT NULL DEFAULT 0,
    CONSTRAINT uq_approval_cases_execution_id UNIQUE (execution_id),
    CONSTRAINT ck_approval_required CHECK (required_approvals > 0),
    CONSTRAINT ck_approval_expiry CHECK (expires_at > created_at),
    CONSTRAINT ck_approval_version CHECK (row_version >= 0)
);
COMMENT ON TABLE iam.approval_cases IS '通用高风险审批单；审批人资格、职责分离、法定人数、资源版本和执行前复核由 CTRL 代码处理。';
COMMENT ON COLUMN iam.approval_cases.id IS '应用生成的审批单 UUIDv7。';
COMMENT ON COLUMN iam.approval_cases.request_type IS '审批请求类型。';
COMMENT ON COLUMN iam.approval_cases.initiator_type IS '发起者类型。';
COMMENT ON COLUMN iam.approval_cases.initiator_id IS '发起者逻辑 ID。';
COMMENT ON COLUMN iam.approval_cases.tenant_id IS '可空；逻辑引用 iam.tenants.id。';
COMMENT ON COLUMN iam.approval_cases.request_digest IS '规范化请求 SHA-256 摘要。';
COMMENT ON COLUMN iam.approval_cases.request_snapshot IS '待审批请求快照；代码脱敏和版本化。';
COMMENT ON COLUMN iam.approval_cases.policy_version_id IS '可空；逻辑引用审批策略版本。';
COMMENT ON COLUMN iam.approval_cases.resource_version IS '可空；发起时目标资源版本，用于执行前防 TOCTOU。';
COMMENT ON COLUMN iam.approval_cases.required_approvals IS '策略快照要求的最少批准数。';
COMMENT ON COLUMN iam.approval_cases.state IS '审批单状态。';
COMMENT ON COLUMN iam.approval_cases.expires_at IS '审批请求过期时间。';
COMMENT ON COLUMN iam.approval_cases.execution_id IS '可空；批准动作执行时生成的全局唯一执行 UUID，用于并发防重和执行绑定。';
COMMENT ON COLUMN iam.approval_cases.executed_at IS '可空；批准动作实际执行时间。';
COMMENT ON COLUMN iam.approval_cases.created_at IS '数据库插入时间。';
COMMENT ON COLUMN iam.approval_cases.updated_at IS '数据库更新时间；应用显式刷新。';
COMMENT ON COLUMN iam.approval_cases.row_version IS '乐观锁版本。';
COMMENT ON CONSTRAINT uq_approval_cases_execution_id ON iam.approval_cases IS '数据库保证一个执行标识最多绑定一个审批单；执行资格和状态由代码校验。';

CREATE TABLE iam.approval_actions (
    id uuid PRIMARY KEY,
    approval_case_id uuid NOT NULL,
    reviewer_type varchar(40) NOT NULL,
    reviewer_id uuid NOT NULL,
    decision varchar(40) NOT NULL,
    reason_code varchar(100),
    evidence_digest char(64) NOT NULL,
    reviewer_context jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT uq_approval_action_reviewer UNIQUE (approval_case_id, reviewer_type, reviewer_id)
);
COMMENT ON TABLE iam.approval_actions IS '审批人的不可变动作证据；达到阈值和是否可执行由 CTRL 代码判断。';
COMMENT ON COLUMN iam.approval_actions.id IS '应用生成的审批动作 UUIDv7。';
COMMENT ON COLUMN iam.approval_actions.approval_case_id IS '逻辑引用 iam.approval_cases.id。';
COMMENT ON COLUMN iam.approval_actions.reviewer_type IS '审批人类型。';
COMMENT ON COLUMN iam.approval_actions.reviewer_id IS '审批人逻辑 ID。';
COMMENT ON COLUMN iam.approval_actions.decision IS '批准、拒绝或撤回等决策代码。';
COMMENT ON COLUMN iam.approval_actions.reason_code IS '可空；稳定原因码。';
COMMENT ON COLUMN iam.approval_actions.evidence_digest IS '审批证据包摘要。';
COMMENT ON COLUMN iam.approval_actions.reviewer_context IS '脱敏审批上下文，例如认证保证和权限版本。';
COMMENT ON COLUMN iam.approval_actions.created_at IS '数据库插入时间和动作时间。';

CREATE INDEX ix_machine_principals_owner ON iam.machine_principals (owner_type, owner_id, state);
CREATE INDEX ix_machine_credentials_principal ON iam.machine_credentials (machine_principal_id, state, valid_until);
CREATE INDEX ix_workload_attestations_principal ON iam.workload_attestations (machine_principal_id, received_at DESC);
CREATE INDEX ix_delegations_actor ON iam.delegations (actor_user_id, state, valid_until);
CREATE INDEX ix_delegations_subject ON iam.delegations (subject_user_id, state, valid_until);
CREATE INDEX ix_approval_cases_queue ON iam.approval_cases (state, expires_at, created_at);
CREATE INDEX ix_approval_actions_case ON iam.approval_actions (approval_case_id, created_at);
COMMENT ON INDEX iam.ix_approval_cases_queue IS '审批处理器按状态和过期时间查询待办。';
