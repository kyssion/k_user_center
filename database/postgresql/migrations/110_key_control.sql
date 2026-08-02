\set ON_ERROR_STOP on

SET ROLE iam_owner;

-- 密钥元数据、证书、JWKS、版本化配置和安全例外。

CREATE TABLE iam.cryptographic_keys (
    id uuid PRIMARY KEY,
    key_ref varchar(512) NOT NULL,
    purpose varchar(80) NOT NULL,
    algorithm varchar(80) NOT NULL,
    kid varchar(256),
    owner_type varchar(40) NOT NULL,
    owner_id uuid,
    state varchar(40) NOT NULL,
    valid_from timestamptz NOT NULL,
    valid_until timestamptz,
    public_material jsonb,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    row_version bigint NOT NULL DEFAULT 0,
    CONSTRAINT uq_cryptographic_key_ref UNIQUE (key_ref),
    CONSTRAINT ck_cryptographic_key_validity CHECK (valid_until IS NULL OR valid_until > valid_from),
    CONSTRAINT ck_cryptographic_key_version CHECK (row_version >= 0)
);
COMMENT ON TABLE iam.cryptographic_keys IS 'KMS/HSM 密钥元数据；仅保存不可导出 Key 引用和公有材料，私钥绝不落库。';
COMMENT ON COLUMN iam.cryptographic_keys.id IS '应用生成的密钥元数据 UUIDv7。';
COMMENT ON COLUMN iam.cryptographic_keys.key_ref IS 'KMS/HSM 中不可导出 Key 的受控引用，全局唯一。';
COMMENT ON COLUMN iam.cryptographic_keys.purpose IS '密钥用途，例如 TOKEN_SIGNING、DATA_ENCRYPTION。';
COMMENT ON COLUMN iam.cryptographic_keys.algorithm IS '算法标识，必须由代码对照 Allowlist。';
COMMENT ON COLUMN iam.cryptographic_keys.kid IS '可空；协议公开 Key ID。';
COMMENT ON COLUMN iam.cryptographic_keys.owner_type IS '密钥所有者类型。';
COMMENT ON COLUMN iam.cryptographic_keys.owner_id IS '可空；平台密钥为空，其他按类型逻辑引用。';
COMMENT ON COLUMN iam.cryptographic_keys.state IS '密钥元数据状态；生成、激活、轮换和销毁由 KEY 代码及 KMS 执行。';
COMMENT ON COLUMN iam.cryptographic_keys.valid_from IS '验证或加密生效时间。';
COMMENT ON COLUMN iam.cryptographic_keys.valid_until IS '可空；停止使用或验证的时间。';
COMMENT ON COLUMN iam.cryptographic_keys.public_material IS '可空；JWK 等公开材料，禁止写入私钥参数。';
COMMENT ON COLUMN iam.cryptographic_keys.created_at IS '数据库插入时间。';
COMMENT ON COLUMN iam.cryptographic_keys.updated_at IS '数据库更新时间；应用显式刷新。';
COMMENT ON COLUMN iam.cryptographic_keys.row_version IS '乐观锁版本。';

CREATE TABLE iam.certificates (
    id uuid PRIMARY KEY,
    serial_number varchar(256) NOT NULL,
    issuer_dn text NOT NULL,
    subject_dn text NOT NULL,
    fingerprint_sha256 char(64) NOT NULL,
    public_certificate text NOT NULL,
    key_id uuid,
    state varchar(40) NOT NULL,
    valid_from timestamptz NOT NULL,
    valid_until timestamptz NOT NULL,
    revoked_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    row_version bigint NOT NULL DEFAULT 0,
    CONSTRAINT uq_certificates_fingerprint UNIQUE (fingerprint_sha256),
    CONSTRAINT ck_certificates_validity CHECK (valid_until > valid_from),
    CONSTRAINT ck_certificates_version CHECK (row_version >= 0)
);
COMMENT ON TABLE iam.certificates IS '证书公有内容和生命周期元数据；链验证、吊销检查和用途约束由 KEY/MACHINE 代码执行。';
COMMENT ON COLUMN iam.certificates.id IS '应用生成的证书 UUIDv7。';
COMMENT ON COLUMN iam.certificates.serial_number IS '证书序列号文本。';
COMMENT ON COLUMN iam.certificates.issuer_dn IS '证书颁发者 DN。';
COMMENT ON COLUMN iam.certificates.subject_dn IS '证书主体 DN。';
COMMENT ON COLUMN iam.certificates.fingerprint_sha256 IS 'DER 证书 SHA-256 指纹。';
COMMENT ON COLUMN iam.certificates.public_certificate IS 'PEM 或标准编码的公有证书，不含私钥。';
COMMENT ON COLUMN iam.certificates.key_id IS '可空；逻辑引用 iam.cryptographic_keys.id。';
COMMENT ON COLUMN iam.certificates.state IS '证书状态。';
COMMENT ON COLUMN iam.certificates.valid_from IS '证书有效期开始。';
COMMENT ON COLUMN iam.certificates.valid_until IS '证书有效期结束。';
COMMENT ON COLUMN iam.certificates.revoked_at IS '可空；平台记录的撤销时间。';
COMMENT ON COLUMN iam.certificates.created_at IS '数据库插入时间。';
COMMENT ON COLUMN iam.certificates.updated_at IS '数据库更新时间；应用显式刷新。';
COMMENT ON COLUMN iam.certificates.row_version IS '乐观锁版本。';

CREATE TABLE iam.jwks_releases (
    id uuid PRIMARY KEY,
    owner_type varchar(40) NOT NULL,
    owner_id uuid,
    version integer NOT NULL,
    payload_digest char(64) NOT NULL,
    state varchar(40) NOT NULL,
    published_at timestamptz,
    active_from timestamptz,
    retired_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT uq_jwks_release_version UNIQUE NULLS NOT DISTINCT (owner_type, owner_id, version),
    CONSTRAINT ck_jwks_release_version CHECK (version > 0)
);
COMMENT ON TABLE iam.jwks_releases IS 'JWKS 发布版本元数据；内容由关联 Key 生成，重叠和缓存窗口由 KEY 代码控制。';
COMMENT ON COLUMN iam.jwks_releases.id IS '应用生成的 JWKS Release UUIDv7。';
COMMENT ON COLUMN iam.jwks_releases.owner_type IS 'JWKS 所有者类型。';
COMMENT ON COLUMN iam.jwks_releases.owner_id IS '可空；平台所有者为空。';
COMMENT ON COLUMN iam.jwks_releases.version IS '所有者内正整数发布版本。';
COMMENT ON COLUMN iam.jwks_releases.payload_digest IS '规范化 JWKS SHA-256 摘要。';
COMMENT ON COLUMN iam.jwks_releases.state IS '发布状态。';
COMMENT ON COLUMN iam.jwks_releases.published_at IS '可空；对外发布时间。';
COMMENT ON COLUMN iam.jwks_releases.active_from IS '可空；开始用于签名或验证的时间。';
COMMENT ON COLUMN iam.jwks_releases.retired_at IS '可空；退出发布的时间。';
COMMENT ON COLUMN iam.jwks_releases.created_at IS '数据库插入时间。';

CREATE TABLE iam.jwks_release_keys (
    id uuid PRIMARY KEY,
    jwks_release_id uuid NOT NULL,
    key_id uuid NOT NULL,
    usage varchar(40) NOT NULL,
    display_order integer NOT NULL DEFAULT 0,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT uq_jwks_release_key UNIQUE (jwks_release_id, key_id, usage),
    CONSTRAINT ck_jwks_release_key_order CHECK (display_order >= 0)
);
COMMENT ON TABLE iam.jwks_release_keys IS 'JWKS 发布版本包含的公钥关系。';
COMMENT ON COLUMN iam.jwks_release_keys.id IS '应用生成的关系 UUIDv7。';
COMMENT ON COLUMN iam.jwks_release_keys.jwks_release_id IS '逻辑引用 iam.jwks_releases.id。';
COMMENT ON COLUMN iam.jwks_release_keys.key_id IS '逻辑引用 iam.cryptographic_keys.id。';
COMMENT ON COLUMN iam.jwks_release_keys.usage IS 'Key 在发布中的用途，例如 SIGNING、VERIFY_ONLY。';
COMMENT ON COLUMN iam.jwks_release_keys.display_order IS '确定性输出顺序，不表达优先级业务规则。';
COMMENT ON COLUMN iam.jwks_release_keys.created_at IS '数据库插入时间。';

CREATE TABLE iam.configuration_versions (
    id uuid PRIMARY KEY,
    config_type varchar(100) NOT NULL,
    config_code varchar(160) NOT NULL,
    scope_type varchar(40) NOT NULL,
    scope_id uuid,
    version integer NOT NULL,
    schema_version integer NOT NULL,
    payload jsonb NOT NULL,
    payload_digest char(64) NOT NULL,
    state varchar(40) NOT NULL,
    created_by_type varchar(40) NOT NULL,
    created_by_id uuid NOT NULL,
    approved_by_case_id uuid,
    published_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT uq_configuration_version UNIQUE NULLS NOT DISTINCT (config_type, config_code, scope_type, scope_id, version),
    CONSTRAINT ck_configuration_version_numbers CHECK (version > 0 AND schema_version > 0)
);
COMMENT ON TABLE iam.configuration_versions IS '通用不可变配置版本；Schema 校验、语义校验、差异、审批和运行时解释由 CTRL 代码执行。';
COMMENT ON COLUMN iam.configuration_versions.id IS '应用生成的配置版本 UUIDv7。';
COMMENT ON COLUMN iam.configuration_versions.config_type IS '配置类型代码，例如 SECURITY_PROFILE、RISK_POLICY。';
COMMENT ON COLUMN iam.configuration_versions.config_code IS '同类型和作用域内稳定配置代码。';
COMMENT ON COLUMN iam.configuration_versions.scope_type IS '配置作用域类型。';
COMMENT ON COLUMN iam.configuration_versions.scope_id IS '可空；按 scope_type 逻辑引用作用域对象，平台级配置为空。';
COMMENT ON COLUMN iam.configuration_versions.version IS '同配置键内正整数版本。';
COMMENT ON COLUMN iam.configuration_versions.schema_version IS '配置 JSON Schema 正整数版本。';
COMMENT ON COLUMN iam.configuration_versions.payload IS '配置载荷；数据库不解释业务语义，秘密只保存 Key 引用。';
COMMENT ON COLUMN iam.configuration_versions.payload_digest IS '规范化载荷 SHA-256 摘要。';
COMMENT ON COLUMN iam.configuration_versions.state IS '配置版本状态。';
COMMENT ON COLUMN iam.configuration_versions.created_by_type IS '创建者类型。';
COMMENT ON COLUMN iam.configuration_versions.created_by_id IS '创建者逻辑 ID。';
COMMENT ON COLUMN iam.configuration_versions.approved_by_case_id IS '可空；逻辑引用 iam.approval_cases.id。';
COMMENT ON COLUMN iam.configuration_versions.published_at IS '可空；发布业务时间。';
COMMENT ON COLUMN iam.configuration_versions.created_at IS '数据库插入时间。';

CREATE TABLE iam.configuration_releases (
    id uuid PRIMARY KEY,
    environment varchar(40) NOT NULL,
    release_code varchar(160) NOT NULL,
    state varchar(40) NOT NULL,
    content_digest char(64) NOT NULL,
    approval_case_id uuid,
    requested_by_type varchar(40) NOT NULL,
    requested_by_id uuid NOT NULL,
    activated_at timestamptz,
    rolled_back_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    row_version bigint NOT NULL DEFAULT 0,
    CONSTRAINT uq_configuration_release_code UNIQUE (environment, release_code),
    CONSTRAINT ck_configuration_release_version CHECK (row_version >= 0)
);
COMMENT ON TABLE iam.configuration_releases IS '环境配置发布单；一致性、审批、灰度、激活和回滚由 CTRL 代码执行。';
COMMENT ON COLUMN iam.configuration_releases.id IS '应用生成的配置发布 UUIDv7。';
COMMENT ON COLUMN iam.configuration_releases.environment IS '目标环境代码。';
COMMENT ON COLUMN iam.configuration_releases.release_code IS '环境内稳定发布编号。';
COMMENT ON COLUMN iam.configuration_releases.state IS '发布状态。';
COMMENT ON COLUMN iam.configuration_releases.content_digest IS '发布项有序集合 SHA-256 摘要。';
COMMENT ON COLUMN iam.configuration_releases.approval_case_id IS '可空；逻辑引用 iam.approval_cases.id。';
COMMENT ON COLUMN iam.configuration_releases.requested_by_type IS '发布申请者类型。';
COMMENT ON COLUMN iam.configuration_releases.requested_by_id IS '发布申请者逻辑 ID。';
COMMENT ON COLUMN iam.configuration_releases.activated_at IS '可空；正式激活时间。';
COMMENT ON COLUMN iam.configuration_releases.rolled_back_at IS '可空；回滚时间。';
COMMENT ON COLUMN iam.configuration_releases.created_at IS '数据库插入时间。';
COMMENT ON COLUMN iam.configuration_releases.updated_at IS '数据库更新时间；应用显式刷新。';
COMMENT ON COLUMN iam.configuration_releases.row_version IS '乐观锁版本。';

CREATE TABLE iam.configuration_release_items (
    id uuid PRIMARY KEY,
    release_id uuid NOT NULL,
    configuration_version_id uuid NOT NULL,
    apply_order integer NOT NULL,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT uq_configuration_release_item UNIQUE (release_id, configuration_version_id),
    CONSTRAINT uq_configuration_release_order UNIQUE (release_id, apply_order),
    CONSTRAINT ck_configuration_release_order CHECK (apply_order >= 0)
);
COMMENT ON TABLE iam.configuration_release_items IS '配置发布单包含的不可变配置版本和确定性应用顺序。';
COMMENT ON COLUMN iam.configuration_release_items.id IS '应用生成的发布项 UUIDv7。';
COMMENT ON COLUMN iam.configuration_release_items.release_id IS '逻辑引用 iam.configuration_releases.id。';
COMMENT ON COLUMN iam.configuration_release_items.configuration_version_id IS '逻辑引用 iam.configuration_versions.id。';
COMMENT ON COLUMN iam.configuration_release_items.apply_order IS '发布内非负确定性顺序。';
COMMENT ON COLUMN iam.configuration_release_items.created_at IS '数据库插入时间。';

CREATE TABLE iam.security_exceptions (
    id uuid PRIMARY KEY,
    exception_type varchar(100) NOT NULL,
    scope_type varchar(40) NOT NULL,
    scope_id uuid NOT NULL,
    risk_owner_type varchar(40) NOT NULL,
    risk_owner_id uuid NOT NULL,
    compensating_controls jsonb NOT NULL,
    reason text NOT NULL,
    approval_case_id uuid NOT NULL,
    state varchar(40) NOT NULL,
    effective_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    closed_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    row_version bigint NOT NULL DEFAULT 0,
    CONSTRAINT ck_security_exception_expiry CHECK (expires_at > effective_at),
    CONSTRAINT ck_security_exception_version CHECK (row_version >= 0)
);
COMMENT ON TABLE iam.security_exceptions IS '有期限且经批准的安全例外台账；不得由数据库自动放宽安全控制。';
COMMENT ON COLUMN iam.security_exceptions.id IS '应用生成的安全例外 UUIDv7。';
COMMENT ON COLUMN iam.security_exceptions.exception_type IS '安全例外类型。';
COMMENT ON COLUMN iam.security_exceptions.scope_type IS '例外作用域类型。';
COMMENT ON COLUMN iam.security_exceptions.scope_id IS '例外作用域逻辑 ID。';
COMMENT ON COLUMN iam.security_exceptions.risk_owner_type IS '风险接受责任人类型。';
COMMENT ON COLUMN iam.security_exceptions.risk_owner_id IS '风险接受责任人逻辑 ID。';
COMMENT ON COLUMN iam.security_exceptions.compensating_controls IS '经批准的补偿控制快照。';
COMMENT ON COLUMN iam.security_exceptions.reason IS '例外理由；属于受控审计数据。';
COMMENT ON COLUMN iam.security_exceptions.approval_case_id IS '逻辑引用 iam.approval_cases.id。';
COMMENT ON COLUMN iam.security_exceptions.state IS '例外状态。';
COMMENT ON COLUMN iam.security_exceptions.effective_at IS '例外生效时间。';
COMMENT ON COLUMN iam.security_exceptions.expires_at IS '强制到期时间。';
COMMENT ON COLUMN iam.security_exceptions.closed_at IS '可空；例外提前关闭时间。';
COMMENT ON COLUMN iam.security_exceptions.created_at IS '数据库插入时间。';
COMMENT ON COLUMN iam.security_exceptions.updated_at IS '数据库更新时间；应用显式刷新。';
COMMENT ON COLUMN iam.security_exceptions.row_version IS '乐观锁版本。';

CREATE INDEX ix_cryptographic_keys_owner ON iam.cryptographic_keys (owner_type, owner_id, purpose, state);
CREATE UNIQUE INDEX uq_cryptographic_key_kid ON iam.cryptographic_keys (owner_type, owner_id, purpose, kid) WHERE kid IS NOT NULL;
CREATE INDEX ix_certificates_validity ON iam.certificates (state, valid_until);
CREATE INDEX ix_configuration_versions_lookup ON iam.configuration_versions (config_type, config_code, scope_type, scope_id, state, version DESC);
CREATE INDEX ix_configuration_releases_queue ON iam.configuration_releases (environment, state, created_at);
CREATE INDEX ix_security_exceptions_expiry ON iam.security_exceptions (state, expires_at);
COMMENT ON INDEX iam.ix_configuration_versions_lookup IS '控制面按配置键和状态定位候选版本。';
COMMENT ON INDEX iam.uq_cryptographic_key_kid IS '仅对非空协议 kid 维持同一 Owner 和用途内唯一；无 kid 的数据加密 Key 可多版本并存。';
