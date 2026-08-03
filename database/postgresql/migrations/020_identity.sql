\set ON_ERROR_STOP on

SET ROLE iam_owner;

-- 身份主体与标识。所有关联均为逻辑引用，归属、换绑、合并和隔离期由 ID 领域代码处理。

CREATE TABLE iam.global_users (
    id uuid PRIMARY KEY,
    global_user_id varchar(64) NOT NULL,
    user_type varchar(40) NOT NULL,
    lifecycle_state varchar(40) NOT NULL,
    lifecycle_reason varchar(100),
    authentication_lock_state varchar(40) NOT NULL,
    authentication_locked_until timestamptz,
    security_freeze_state varchar(40) NOT NULL,
    security_frozen_at timestamptz,
    guest_expires_at timestamptz,
    user_security_epoch bigint NOT NULL DEFAULT 0,
    state_changed_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    row_version bigint NOT NULL DEFAULT 0,
    CONSTRAINT uq_global_users_public UNIQUE (global_user_id),
    CONSTRAINT ck_global_users_epoch CHECK (user_security_epoch >= 0),
    CONSTRAINT ck_global_users_version CHECK (row_version >= 0)
);
COMMENT ON TABLE iam.global_users IS '全局用户主体；只保存身份生命周期和安全水位，不保存业务会员状态。';
COMMENT ON COLUMN iam.global_users.id IS '应用生成的 UUIDv7 内部主键。';
COMMENT ON COLUMN iam.global_users.global_user_id IS '对内跨系统稳定且不可推断的用户标识，可受控对外暴露。';
COMMENT ON COLUMN iam.global_users.user_type IS '用户主体类型，例如 REGISTERED 或 GUEST；合法值和升级规则由 ID 代码维护。';
COMMENT ON COLUMN iam.global_users.lifecycle_state IS '用户生命周期状态；转换由 ID 领域状态机负责。';
COMMENT ON COLUMN iam.global_users.lifecycle_reason IS '可空；最近状态变化原因码。';
COMMENT ON COLUMN iam.global_users.authentication_lock_state IS '独立认证锁定维度；ENABLED 与 LOCKED 转换由 AUTH/RISK 代码维护。';
COMMENT ON COLUMN iam.global_users.authentication_locked_until IS '可空；认证临时锁定截止时间，风险策略决定其值。';
COMMENT ON COLUMN iam.global_users.security_freeze_state IS '独立全局安全冻结维度；CLEAR 与 FROZEN 转换由 ID/RISK 代码维护。';
COMMENT ON COLUMN iam.global_users.security_frozen_at IS '可空；安全冻结开始时间。';
COMMENT ON COLUMN iam.global_users.guest_expires_at IS '可空；Guest 身份到期业务时间；到期、续期和升级由 ID 代码处理。';
COMMENT ON COLUMN iam.global_users.user_security_epoch IS '用户安全水位；撤销和敏感变更时由代码原子递增。';
COMMENT ON COLUMN iam.global_users.state_changed_at IS '生命周期状态最近变化业务时间。';
COMMENT ON COLUMN iam.global_users.created_at IS '数据库插入时间。';
COMMENT ON COLUMN iam.global_users.updated_at IS '数据库更新时间；应用显式刷新。';
COMMENT ON COLUMN iam.global_users.row_version IS '聚合乐观锁版本。';

CREATE TABLE iam.user_subjects (
    id uuid PRIMARY KEY,
    user_id uuid NOT NULL,
    client_id uuid NOT NULL,
    subject_id varchar(128) NOT NULL,
    subject_type varchar(40) NOT NULL,
    generation_version integer NOT NULL,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT uq_user_subject_client_subject UNIQUE (client_id, subject_id),
    CONSTRAINT uq_user_subject_user_client UNIQUE (user_id, client_id),
    CONSTRAINT ck_user_subject_version CHECK (generation_version > 0)
);
COMMENT ON TABLE iam.user_subjects IS '用户面向 Client 的公开 Subject 映射；Pairwise 算法和轮换规则由 ID 代码实现。';
COMMENT ON COLUMN iam.user_subjects.id IS '应用生成的内部 UUIDv7。';
COMMENT ON COLUMN iam.user_subjects.user_id IS '逻辑引用 iam.global_users.id；数据库不创建外键。';
COMMENT ON COLUMN iam.user_subjects.client_id IS '逻辑引用 iam.oauth_clients.id；写入前校验 Client 状态和业务线。';
COMMENT ON COLUMN iam.user_subjects.subject_id IS '对当前 Client 唯一的不可推断 Subject，可写入 Token。';
COMMENT ON COLUMN iam.user_subjects.subject_type IS 'Subject 类型，例如 PUBLIC 或 PAIRWISE；代码维护合法值。';
COMMENT ON COLUMN iam.user_subjects.generation_version IS 'Subject 生成方案正整数版本。';
COMMENT ON COLUMN iam.user_subjects.created_at IS '数据库插入时间。';

CREATE TABLE iam.identifiers (
    id uuid PRIMARY KEY,
    identifier_type varchar(40) NOT NULL,
    scope_type varchar(40) NOT NULL,
    scope_id uuid,
    value_ciphertext text,
    blind_index varchar(128) NOT NULL,
    value_fingerprint varchar(128),
    normalization_version integer NOT NULL,
    encryption_algorithm varchar(40),
    encryption_version integer,
    key_id uuid,
    verification_state varchar(40) NOT NULL,
    verified_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    row_version bigint NOT NULL DEFAULT 0,
    CONSTRAINT ck_identifiers_normalization CHECK (normalization_version > 0),
    CONSTRAINT ck_identifiers_version CHECK (row_version >= 0)
);
COMMENT ON TABLE iam.identifiers IS '手机、邮箱、用户名等标识事实；可检索值使用密文与 HMAC 盲索引，验证规则由 ID 代码处理。';
COMMENT ON COLUMN iam.identifiers.id IS '应用生成的标识 UUIDv7。';
COMMENT ON COLUMN iam.identifiers.identifier_type IS '标识类型代码，例如 PHONE、EMAIL、USERNAME。';
COMMENT ON COLUMN iam.identifiers.scope_type IS '唯一性作用域类型，例如 GLOBAL、BUSINESS_LINE、TENANT。';
COMMENT ON COLUMN iam.identifiers.scope_id IS '可空；按 scope_type 逻辑引用作用域对象，全局作用域为空。';
COMMENT ON COLUMN iam.identifiers.value_ciphertext IS '可空；随机化加密后的原始标识，敏感数据，不对普通读角色开放。';
COMMENT ON COLUMN iam.identifiers.blind_index IS '规范化值的 HMAC 盲索引，用于等值查询，不可直接还原。';
COMMENT ON COLUMN iam.identifiers.value_fingerprint IS '可空；受控去重或审计指纹，不对外暴露。';
COMMENT ON COLUMN iam.identifiers.normalization_version IS '规范化算法正整数版本。';
COMMENT ON COLUMN iam.identifiers.encryption_algorithm IS '可空；密文算法标识；无可恢复值时为空。';
COMMENT ON COLUMN iam.identifiers.encryption_version IS '可空；密文封装版本。';
COMMENT ON COLUMN iam.identifiers.key_id IS '可空；逻辑引用 iam.cryptographic_keys.id 或外部 KMS Key 元数据。';
COMMENT ON COLUMN iam.identifiers.verification_state IS '验证状态；Challenge 和状态转换由代码控制。';
COMMENT ON COLUMN iam.identifiers.verified_at IS '可空；最近验证成功业务时间。';
COMMENT ON COLUMN iam.identifiers.created_at IS '数据库插入时间。';
COMMENT ON COLUMN iam.identifiers.updated_at IS '数据库更新时间；应用显式刷新。';
COMMENT ON COLUMN iam.identifiers.row_version IS '乐观锁版本。';

CREATE TABLE iam.identifier_claims (
    id uuid PRIMARY KEY,
    scope_type varchar(40) NOT NULL,
    scope_id uuid,
    identifier_type varchar(40) NOT NULL,
    blind_index varchar(128) NOT NULL,
    identifier_id uuid NOT NULL,
    owner_user_id uuid NOT NULL,
    claim_state varchar(40) NOT NULL,
    claimed_at timestamptz NOT NULL,
    released_at timestamptz,
    isolation_until timestamptz,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    row_version bigint NOT NULL DEFAULT 0,
    CONSTRAINT uq_identifier_claim UNIQUE NULLS NOT DISTINCT (scope_type, scope_id, identifier_type, blind_index),
    CONSTRAINT ck_identifier_claim_version CHECK (row_version >= 0)
);
COMMENT ON TABLE iam.identifier_claims IS '当前标识唯一性占用；数据库维持作用域、类型和盲索引唯一，释放和隔离期判断由 ID 代码负责。';
COMMENT ON COLUMN iam.identifier_claims.id IS '应用生成的占用记录 UUIDv7。';
COMMENT ON COLUMN iam.identifier_claims.scope_type IS '唯一性作用域类型。';
COMMENT ON COLUMN iam.identifier_claims.scope_id IS '可空；作用域逻辑 ID；NULL 与 NULL 按唯一值处理。';
COMMENT ON COLUMN iam.identifier_claims.identifier_type IS '标识类型代码。';
COMMENT ON COLUMN iam.identifier_claims.blind_index IS '标识规范化值 HMAC 盲索引。';
COMMENT ON COLUMN iam.identifier_claims.identifier_id IS '逻辑引用 iam.identifiers.id；数据库不创建外键。';
COMMENT ON COLUMN iam.identifier_claims.owner_user_id IS '逻辑引用 iam.global_users.id；代码校验归属与状态。';
COMMENT ON COLUMN iam.identifier_claims.claim_state IS '占用状态；状态机由 ID 领域维护。';
COMMENT ON COLUMN iam.identifier_claims.claimed_at IS '占用生效业务时间。';
COMMENT ON COLUMN iam.identifier_claims.released_at IS '可空；释放业务时间。';
COMMENT ON COLUMN iam.identifier_claims.isolation_until IS '可空；释放后的安全隔离截止时间。';
COMMENT ON COLUMN iam.identifier_claims.created_at IS '数据库插入时间。';
COMMENT ON COLUMN iam.identifier_claims.updated_at IS '数据库更新时间；应用显式刷新。';
COMMENT ON COLUMN iam.identifier_claims.row_version IS '乐观锁版本。';
COMMENT ON CONSTRAINT uq_identifier_claim ON iam.identifier_claims IS '维持同一作用域内标识盲索引只有一个占用记录。';

CREATE TABLE iam.identifier_bindings (
    id uuid PRIMARY KEY,
    identifier_id uuid NOT NULL,
    user_id uuid NOT NULL,
    binding_state varchar(40) NOT NULL,
    source_type varchar(40) NOT NULL,
    source_id uuid,
    reason_code varchar(100),
    bound_at timestamptz NOT NULL,
    unbound_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    row_version bigint NOT NULL DEFAULT 0,
    CONSTRAINT ck_identifier_binding_version CHECK (row_version >= 0)
);
COMMENT ON TABLE iam.identifier_bindings IS '标识与用户的历史绑定事实；保留解绑和墓碑，不使用级联删除。';
COMMENT ON COLUMN iam.identifier_bindings.id IS '应用生成的绑定 UUIDv7。';
COMMENT ON COLUMN iam.identifier_bindings.identifier_id IS '逻辑引用 iam.identifiers.id。';
COMMENT ON COLUMN iam.identifier_bindings.user_id IS '逻辑引用 iam.global_users.id。';
COMMENT ON COLUMN iam.identifier_bindings.binding_state IS '绑定状态；换绑、合并和隔离规则由 ID 代码维护。';
COMMENT ON COLUMN iam.identifier_bindings.source_type IS '绑定来源类型，例如 REGISTER、ADMIN、MIGRATION。';
COMMENT ON COLUMN iam.identifier_bindings.source_id IS '可空；来源对象逻辑 ID。';
COMMENT ON COLUMN iam.identifier_bindings.reason_code IS '可空；绑定或解绑稳定原因码。';
COMMENT ON COLUMN iam.identifier_bindings.bound_at IS '绑定生效业务时间。';
COMMENT ON COLUMN iam.identifier_bindings.unbound_at IS '可空；解绑业务时间。';
COMMENT ON COLUMN iam.identifier_bindings.created_at IS '数据库插入时间。';
COMMENT ON COLUMN iam.identifier_bindings.row_version IS '乐观锁版本。';

CREATE TABLE iam.user_identities (
    id uuid PRIMARY KEY,
    user_id uuid NOT NULL,
    identity_type varchar(40) NOT NULL,
    identifier_id uuid,
    provider_id uuid,
    external_subject_digest varchar(128),
    state varchar(40) NOT NULL,
    assurance_level varchar(40),
    linked_at timestamptz NOT NULL,
    unlinked_at timestamptz,
    metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    row_version bigint NOT NULL DEFAULT 0,
    CONSTRAINT uq_user_identity_external UNIQUE (provider_id, external_subject_digest),
    CONSTRAINT ck_user_identity_target CHECK (identifier_id IS NOT NULL OR external_subject_digest IS NOT NULL),
    CONSTRAINT ck_user_identity_version CHECK (row_version >= 0)
);
COMMENT ON TABLE iam.user_identities IS '用户可登录身份，包括本地标识、社交和企业联合身份；链接生命周期由 ID 领域持有，FED 提供外部身份源事实。';
COMMENT ON COLUMN iam.user_identities.id IS '应用生成的身份 UUIDv7。';
COMMENT ON COLUMN iam.user_identities.user_id IS '逻辑引用 iam.global_users.id。';
COMMENT ON COLUMN iam.user_identities.identity_type IS '身份类型，例如 LOCAL、OIDC、SAML、SOCIAL。';
COMMENT ON COLUMN iam.user_identities.identifier_id IS '可空；本地身份逻辑引用 iam.identifiers.id。';
COMMENT ON COLUMN iam.user_identities.provider_id IS '可空；联合身份逻辑引用 iam.identity_providers.id。';
COMMENT ON COLUMN iam.user_identities.external_subject_digest IS '可空；外部稳定 Subject 的 HMAC 摘要，不保存可枚举明文。';
COMMENT ON COLUMN iam.user_identities.state IS '身份状态；链接、禁用和解绑状态机由代码维护。';
COMMENT ON COLUMN iam.user_identities.assurance_level IS '可空；身份源保证等级快照。';
COMMENT ON COLUMN iam.user_identities.linked_at IS '身份链接生效业务时间。';
COMMENT ON COLUMN iam.user_identities.unlinked_at IS '可空；身份解绑业务时间。';
COMMENT ON COLUMN iam.user_identities.metadata IS '非秘密身份元数据；代码按类型 Schema 校验。';
COMMENT ON COLUMN iam.user_identities.created_at IS '数据库插入时间。';
COMMENT ON COLUMN iam.user_identities.updated_at IS '数据库更新时间；应用显式刷新。';
COMMENT ON COLUMN iam.user_identities.row_version IS '乐观锁版本。';

CREATE TABLE iam.user_aliases (
    id uuid PRIMARY KEY,
    alias_type varchar(40) NOT NULL,
    alias_value_digest varchar(128) NOT NULL,
    canonical_user_id uuid NOT NULL,
    source_system_id uuid,
    state varchar(40) NOT NULL,
    effective_at timestamptz NOT NULL,
    expires_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT uq_user_alias UNIQUE (alias_type, alias_value_digest),
    CONSTRAINT ck_user_alias_expiry CHECK (expires_at IS NULL OR expires_at > effective_at)
);
COMMENT ON TABLE iam.user_aliases IS '合并账号、旧 UID 和历史主体到当前用户的别名映射。';
COMMENT ON COLUMN iam.user_aliases.id IS '应用生成的别名 UUIDv7。';
COMMENT ON COLUMN iam.user_aliases.alias_type IS '别名类型代码。';
COMMENT ON COLUMN iam.user_aliases.alias_value_digest IS '别名规范化值的不可逆摘要，避免保存旧标识明文。';
COMMENT ON COLUMN iam.user_aliases.canonical_user_id IS '逻辑引用 iam.global_users.id；代码防止循环和跨租户错误。';
COMMENT ON COLUMN iam.user_aliases.source_system_id IS '可空；逻辑引用 iam.legacy_systems.id。';
COMMENT ON COLUMN iam.user_aliases.state IS '别名状态；有效性由 ID/MIG 代码维护。';
COMMENT ON COLUMN iam.user_aliases.effective_at IS '映射生效业务时间。';
COMMENT ON COLUMN iam.user_aliases.expires_at IS '可空；映射失效时间。';
COMMENT ON COLUMN iam.user_aliases.created_at IS '数据库插入时间。';

CREATE INDEX ix_identifier_lookup ON iam.identifiers (scope_type, scope_id, identifier_type, blind_index);
CREATE INDEX ix_global_users_guest_expiry ON iam.global_users (user_type, guest_expires_at) WHERE guest_expires_at IS NOT NULL;
CREATE INDEX ix_identifier_bindings_user ON iam.identifier_bindings (user_id, binding_state, bound_at DESC);
CREATE INDEX ix_user_identities_user ON iam.user_identities (user_id, state, identity_type);
CREATE INDEX ix_user_aliases_canonical ON iam.user_aliases (canonical_user_id, state);
COMMENT ON INDEX iam.ix_identifier_lookup IS '按作用域、类型和盲索引定位标识；不暴露原始值。';
COMMENT ON INDEX iam.ix_global_users_guest_expiry IS '扫描待过期 Guest 身份；是否到期和如何处置由代码判断。';
