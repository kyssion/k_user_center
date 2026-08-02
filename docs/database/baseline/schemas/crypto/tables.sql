-- =============================================================================
-- baseline/schemas/crypto/tables.sql
-- crypto Schema 的最终基表、同 Schema 约束、索引及内联 COMMENT
-- PostgreSQL 16+；应用技术栈：.NET 10 + SqlSugar
-- =============================================================================

CREATE TABLE crypto.key_asset (
    id uuid        NOT NULL DEFAULT gen_random_uuid(),
    public_id text        NOT NULL,
    key_id text        NOT NULL,
    key_kind text        NOT NULL,
    key_use text        NOT NULL,
    algorithm text        NOT NULL,
    environment text        NOT NULL,
    owner_ref text        NOT NULL,
    kms_provider text        NOT NULL,
    kms_key_ref text        NOT NULL,
    public_material jsonb       NULL,
    key_state text        NOT NULL DEFAULT 'GENERATED',
    key_version bigint      NOT NULL DEFAULT 1,
    not_before timestamptz NOT NULL,
    not_after timestamptz NOT NULL,
    published_at timestamptz NULL,
    signing_started_at timestamptz NULL,
    verify_only_at timestamptz NULL,
    compromised_at timestamptz NULL,
    revoked_at timestamptz NULL,
    retired_at timestamptz NULL,
    destroyed_at timestamptz NULL,
    approval_case_id uuid        NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    row_version bigint      NOT NULL DEFAULT 1,
    asset_metadata_hash bytea NOT NULL,
    activated_at timestamptz NULL,
    approval_execution_id uuid NULL,
    CONSTRAINT pk_key_asset PRIMARY KEY (id),
    CONSTRAINT uq_key_asset_public_id UNIQUE (public_id),
    CONSTRAINT uq_key_asset_kid UNIQUE (environment, key_use, key_id, key_version),
    CONSTRAINT ck_key_asset_kind CHECK (key_kind IN ('ASYMMETRIC', 'SYMMETRIC', 'HMAC', 'DATA_ENCRYPTION', 'BLIND_INDEX')),
    CONSTRAINT ck_key_asset_use CHECK (key_use IN ('TOKEN_SIGNING', 'TOKEN_ENCRYPTION', 'DATA_ENCRYPTION', 'BLIND_INDEX', 'WEBHOOK_SIGNING', 'AUDIT_SEAL', 'MTLS_CA')),
    CONSTRAINT ck_key_asset_algorithm CHECK (algorithm <> 'none' AND algorithm <> ''),
    CONSTRAINT ck_key_asset_window CHECK (not_after > not_before),
    CONSTRAINT ck_key_asset_reference CHECK (kms_key_ref <> ''),
    CONSTRAINT ck_key_asset_destroyed CHECK ((key_state = 'DESTROYED') = (destroyed_at IS NOT NULL)),
    CONSTRAINT ck_key_asset_metadata_hash CHECK (octet_length(asset_metadata_hash) = 32),
    CONSTRAINT ck_key_asset_state CHECK (key_state IN ('GENERATED', 'PUBLISHED', 'SIGNING_AND_VERIFYING', 'ACTIVE', 'VERIFY_ONLY', 'COMPROMISED', 'REVOKED', 'RETIRED', 'DESTROYED')),
    CONSTRAINT ck_key_asset_state_use CHECK (
    (key_use IN ('TOKEN_SIGNING', 'WEBHOOK_SIGNING', 'AUDIT_SEAL') AND key_state <> 'ACTIVE')
    OR (key_use NOT IN ('TOKEN_SIGNING', 'WEBHOOK_SIGNING', 'AUDIT_SEAL') AND key_state NOT IN ('PUBLISHED', 'SIGNING_AND_VERIFYING', 'VERIFY_ONLY'))
    ),
    CONSTRAINT ck_key_asset_state_time CHECK (
    (key_state NOT IN ('PUBLISHED', 'SIGNING_AND_VERIFYING', 'VERIFY_ONLY') OR published_at IS NOT NULL)
    AND (key_state NOT IN ('SIGNING_AND_VERIFYING', 'VERIFY_ONLY') OR signing_started_at IS NOT NULL)
    AND (key_state <> 'ACTIVE' OR activated_at IS NOT NULL)
    AND (key_state <> 'VERIFY_ONLY' OR verify_only_at IS NOT NULL)
    AND (key_state <> 'COMPROMISED' OR compromised_at IS NOT NULL)
    AND (key_state <> 'REVOKED' OR revoked_at IS NOT NULL)
    AND (key_state <> 'RETIRED' OR retired_at IS NOT NULL)
    )
);

COMMENT ON TABLE crypto.key_asset IS 'REQ-KEY-001 至 007：KMS/HSM 引用、用途隔离、算法、kid、轮换、失陷、撤销与销毁证据；不保存私钥明文。';

CREATE TABLE crypto.certificate_asset (
    id uuid        NOT NULL DEFAULT gen_random_uuid(),
    public_id text        NOT NULL,
    certificate_kind text        NOT NULL,
    serial_number text        NOT NULL,
    thumbprint_sha256 bytea       NOT NULL,
    subject_dn text        NOT NULL,
    issuer_dn text        NOT NULL,
    san_values text[]      NOT NULL DEFAULT '{}',
    public_certificate_pem text       NOT NULL,
    private_key_asset_id uuid        NULL,
    certificate_state text        NOT NULL DEFAULT 'ISSUED',
    owner_ref text        NOT NULL,
    environment text        NOT NULL,
    issued_at timestamptz NOT NULL,
    not_before timestamptz NOT NULL,
    not_after timestamptz NOT NULL,
    grace_until timestamptz NULL,
    revoked_at timestamptz NULL,
    revoke_reason_code text        NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    activated_at timestamptz NULL,
    expired_at timestamptz NULL,
    CONSTRAINT pk_certificate_asset PRIMARY KEY (id),
    CONSTRAINT uq_certificate_asset_public_id UNIQUE (public_id),
    CONSTRAINT uq_certificate_asset_serial UNIQUE (issuer_dn, serial_number),
    CONSTRAINT uq_certificate_asset_thumbprint UNIQUE (thumbprint_sha256),
    CONSTRAINT fk_certificate_asset_key FOREIGN KEY (private_key_asset_id) REFERENCES crypto.key_asset(id),
    CONSTRAINT ck_certificate_asset_kind CHECK (certificate_kind IN ('TLS_SERVER', 'MTLS_CLIENT', 'SAML_SIGNING', 'WEBHOOK_SIGNING', 'CA')),
    CONSTRAINT ck_certificate_asset_state CHECK (certificate_state IN ('ISSUED', 'ACTIVE', 'GRACE', 'EXPIRED', 'REVOKED')),
    CONSTRAINT ck_certificate_asset_hash CHECK (octet_length(thumbprint_sha256) = 32),
    CONSTRAINT ck_certificate_asset_window CHECK (not_after > not_before),
    CONSTRAINT ck_certificate_asset_revoked CHECK ((certificate_state = 'REVOKED') = (revoked_at IS NOT NULL)),
    CONSTRAINT ck_certificate_active CHECK (certificate_state NOT IN ('ACTIVE', 'GRACE') OR activated_at IS NOT NULL),
    CONSTRAINT ck_certificate_expired CHECK ((certificate_state = 'EXPIRED') = (expired_at IS NOT NULL))
);

COMMENT ON TABLE crypto.certificate_asset IS '证书独立生命周期、序列号、SHA-256 指纹、公钥证书、私钥引用、有效期和吊销原因。';

CREATE TABLE crypto.jwks_release (
    id uuid        NOT NULL DEFAULT gen_random_uuid(),
    public_id text        NOT NULL,
    issuer text        NOT NULL,
    environment text        NOT NULL,
    jwks_version bigint      NOT NULL,
    release_state text        NOT NULL DEFAULT 'DRAFT',
    key_asset_ids uuid[]      NOT NULL,
    document_hash bytea       NOT NULL,
    cache_max_age_seconds integer     NOT NULL,
    clock_skew_seconds integer     NOT NULL,
    published_at timestamptz NULL,
    expires_at timestamptz NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    activated_at timestamptz NULL,
    superseded_at timestamptz NULL,
    revoked_at timestamptz NULL,
    revoke_reason_code text NULL,
    CONSTRAINT pk_jwks_release PRIMARY KEY (id),
    CONSTRAINT uq_jwks_release_public_id UNIQUE (public_id),
    CONSTRAINT uq_jwks_release_version UNIQUE (issuer, environment, jwks_version),
    CONSTRAINT ck_jwks_release_state CHECK (release_state IN ('DRAFT', 'PUBLISHED', 'ACTIVE', 'SUPERSEDED', 'REVOKED')),
    CONSTRAINT ck_jwks_release_keys CHECK (cardinality(key_asset_ids) > 0),
    CONSTRAINT ck_jwks_release_hash CHECK (octet_length(document_hash) = 32),
    CONSTRAINT ck_jwks_release_cache CHECK (cache_max_age_seconds BETWEEN 30 AND 86400 AND clock_skew_seconds BETWEEN 0 AND 300),
    CONSTRAINT ck_jwks_release_state_times CHECK (
    (published_at IS NULL OR release_state IN ('PUBLISHED', 'ACTIVE', 'SUPERSEDED', 'REVOKED'))
    AND (release_state NOT IN ('PUBLISHED', 'ACTIVE', 'SUPERSEDED') OR published_at IS NOT NULL)
    AND (expires_at IS NULL OR (published_at IS NOT NULL AND expires_at > published_at))
    ),
    CONSTRAINT ck_jwks_release_published CHECK (release_state IN ('DRAFT', 'REVOKED') OR published_at IS NOT NULL),
    CONSTRAINT ck_jwks_release_active CHECK (release_state <> 'ACTIVE' OR activated_at IS NOT NULL),
    CONSTRAINT ck_jwks_release_superseded CHECK ((release_state = 'SUPERSEDED') = (superseded_at IS NOT NULL)),
    CONSTRAINT ck_jwks_release_revoked CHECK (
    (release_state = 'REVOKED') = (revoked_at IS NOT NULL)
    AND (release_state <> 'REVOKED' OR revoke_reason_code IS NOT NULL)
    )
);

COMMENT ON TABLE crypto.jwks_release IS 'REQ-KEY-002/003：先发布后签名、双钥重叠、缓存与时钟偏差窗口明确的 JWKS 版本。';

CREATE INDEX ix_key_asset_rotation ON crypto.key_asset(not_after) WHERE key_state IN ('PUBLISHED', 'SIGNING_AND_VERIFYING', 'ACTIVE', 'VERIFY_ONLY');

CREATE INDEX ix_fk_certificate_asset_private_key_asset_id ON crypto.certificate_asset (private_key_asset_id);

COMMENT ON COLUMN crypto.key_asset.id IS '内部 UUID 主键；仅用于数据库关系，不作为跨域公开标识。';
COMMENT ON COLUMN crypto.key_asset.public_id IS '不可复用的公开稳定标识；插入时登记到 core.public_id_ledger。';
COMMENT ON COLUMN crypto.key_asset.key_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN crypto.key_asset.key_kind IS '对象类别判别字段；允许值由 CHECK 或对应注册表限定。';
COMMENT ON COLUMN crypto.key_asset.key_use IS 'crypto.key_asset.key_use 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN crypto.key_asset.algorithm IS 'crypto.key_asset.algorithm 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN crypto.key_asset.environment IS 'crypto.key_asset.environment 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN crypto.key_asset.owner_ref IS '不透明对象引用；不得从格式推断手机号、邮箱或其他业务事实。';
COMMENT ON COLUMN crypto.key_asset.kms_provider IS 'crypto.key_asset.kms_provider 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN crypto.key_asset.kms_key_ref IS '外部 KMS/HSM 或受控密钥资产引用；不得保存私钥或 Secret 明文。';
COMMENT ON COLUMN crypto.key_asset.public_material IS '版本化结构化扩展数据；必须由 .NET 按对应 JSON Schema 校验，不得替代核心状态或外键。';
COMMENT ON COLUMN crypto.key_asset.key_state IS '显式状态当前值；合法取值见 CHECK，完整状态转换由 .NET 领域策略执行。';
COMMENT ON COLUMN crypto.key_asset.key_version IS '对象、策略或源数据的显式版本；不得以不可信客户端时间戳替代。';
COMMENT ON COLUMN crypto.key_asset.not_before IS 'crypto.key_asset.not_before 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN crypto.key_asset.not_after IS 'crypto.key_asset.not_after 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN crypto.key_asset.published_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN crypto.key_asset.signing_started_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN crypto.key_asset.verify_only_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN crypto.key_asset.compromised_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN crypto.key_asset.revoked_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN crypto.key_asset.retired_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN crypto.key_asset.destroyed_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN crypto.key_asset.approval_case_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN crypto.key_asset.created_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN crypto.key_asset.updated_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN crypto.key_asset.row_version IS '乐观并发版本；更新必须使用原值 compare-and-set，成功后由数据库单调递增。';
COMMENT ON COLUMN crypto.key_asset.asset_metadata_hash IS '不可逆摘要；用于等值匹配、幂等、完整性或最小化证据，不保存原始敏感值。';
COMMENT ON COLUMN crypto.key_asset.activated_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN crypto.key_asset.approval_execution_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN crypto.certificate_asset.id IS '内部 UUID 主键；仅用于数据库关系，不作为跨域公开标识。';
COMMENT ON COLUMN crypto.certificate_asset.public_id IS '不可复用的公开稳定标识；插入时登记到 core.public_id_ledger。';
COMMENT ON COLUMN crypto.certificate_asset.certificate_kind IS '对象类别判别字段；允许值由 CHECK 或对应注册表限定。';
COMMENT ON COLUMN crypto.certificate_asset.serial_number IS 'crypto.certificate_asset.serial_number 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN crypto.certificate_asset.thumbprint_sha256 IS 'crypto.certificate_asset.thumbprint_sha256 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN crypto.certificate_asset.subject_dn IS 'crypto.certificate_asset.subject_dn 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN crypto.certificate_asset.issuer_dn IS 'crypto.certificate_asset.issuer_dn 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN crypto.certificate_asset.san_values IS '代码或引用集合；写入前去重、校验 allowlist，并满足表约束。';
COMMENT ON COLUMN crypto.certificate_asset.public_certificate_pem IS 'crypto.certificate_asset.public_certificate_pem 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN crypto.certificate_asset.private_key_asset_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN crypto.certificate_asset.certificate_state IS '显式状态当前值；合法取值见 CHECK，完整状态转换由 .NET 领域策略执行。';
COMMENT ON COLUMN crypto.certificate_asset.owner_ref IS '不透明对象引用；不得从格式推断手机号、邮箱或其他业务事实。';
COMMENT ON COLUMN crypto.certificate_asset.environment IS 'crypto.certificate_asset.environment 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN crypto.certificate_asset.issued_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN crypto.certificate_asset.not_before IS 'crypto.certificate_asset.not_before 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN crypto.certificate_asset.not_after IS 'crypto.certificate_asset.not_after 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN crypto.certificate_asset.grace_until IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN crypto.certificate_asset.revoked_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN crypto.certificate_asset.revoke_reason_code IS '稳定机器可读代码；展示文本由资源或目录解析。';
COMMENT ON COLUMN crypto.certificate_asset.created_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN crypto.certificate_asset.activated_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN crypto.certificate_asset.expired_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN crypto.jwks_release.id IS '内部 UUID 主键；仅用于数据库关系，不作为跨域公开标识。';
COMMENT ON COLUMN crypto.jwks_release.public_id IS '不可复用的公开稳定标识；插入时登记到 core.public_id_ledger。';
COMMENT ON COLUMN crypto.jwks_release.issuer IS 'crypto.jwks_release.issuer 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN crypto.jwks_release.environment IS 'crypto.jwks_release.environment 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN crypto.jwks_release.jwks_version IS '对象、策略或源数据的显式版本；不得以不可信客户端时间戳替代。';
COMMENT ON COLUMN crypto.jwks_release.release_state IS '显式状态当前值；合法取值见 CHECK，完整状态转换由 .NET 领域策略执行。';
COMMENT ON COLUMN crypto.jwks_release.key_asset_ids IS '代码或引用集合；写入前去重、校验 allowlist，并满足表约束。';
COMMENT ON COLUMN crypto.jwks_release.document_hash IS '不可逆摘要；用于等值匹配、幂等、完整性或最小化证据，不保存原始敏感值。';
COMMENT ON COLUMN crypto.jwks_release.cache_max_age_seconds IS '以秒为单位的显式时长；有效范围由安全策略及表约束限制。';
COMMENT ON COLUMN crypto.jwks_release.clock_skew_seconds IS '以秒为单位的显式时长；有效范围由安全策略及表约束限制。';
COMMENT ON COLUMN crypto.jwks_release.published_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN crypto.jwks_release.expires_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN crypto.jwks_release.created_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN crypto.jwks_release.activated_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN crypto.jwks_release.superseded_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN crypto.jwks_release.revoked_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN crypto.jwks_release.revoke_reason_code IS '稳定机器可读代码；展示文本由资源或目录解析。';

COMMENT ON CONSTRAINT pk_key_asset ON crypto.key_asset IS '主键约束：唯一标识 crypto.key_asset 记录。';
COMMENT ON CONSTRAINT uq_key_asset_public_id ON crypto.key_asset IS '唯一约束：保证 public_id 在 crypto.key_asset 范围内不重复。';
COMMENT ON CONSTRAINT uq_key_asset_kid ON crypto.key_asset IS '唯一约束：保证 environment、key_use、key_id、key_version 在 crypto.key_asset 范围内不重复。';
COMMENT ON CONSTRAINT ck_key_asset_kind ON crypto.key_asset IS '检查约束：限制 crypto.key_asset 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_key_asset_use ON crypto.key_asset IS '检查约束：限制 crypto.key_asset 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_key_asset_algorithm ON crypto.key_asset IS '检查约束：限制 crypto.key_asset 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_key_asset_window ON crypto.key_asset IS '检查约束：限制 crypto.key_asset 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_key_asset_reference ON crypto.key_asset IS '检查约束：限制 crypto.key_asset 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_key_asset_destroyed ON crypto.key_asset IS '检查约束：限制 crypto.key_asset 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_key_asset_metadata_hash ON crypto.key_asset IS '检查约束：限制 crypto.key_asset 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_key_asset_state ON crypto.key_asset IS '检查约束：限制 crypto.key_asset 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_key_asset_state_use ON crypto.key_asset IS '检查约束：限制 crypto.key_asset 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_key_asset_state_time ON crypto.key_asset IS '检查约束：限制 crypto.key_asset 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT pk_certificate_asset ON crypto.certificate_asset IS '主键约束：唯一标识 crypto.certificate_asset 记录。';
COMMENT ON CONSTRAINT uq_certificate_asset_public_id ON crypto.certificate_asset IS '唯一约束：保证 public_id 在 crypto.certificate_asset 范围内不重复。';
COMMENT ON CONSTRAINT uq_certificate_asset_serial ON crypto.certificate_asset IS '唯一约束：保证 issuer_dn、serial_number 在 crypto.certificate_asset 范围内不重复。';
COMMENT ON CONSTRAINT uq_certificate_asset_thumbprint ON crypto.certificate_asset IS '唯一约束：保证 thumbprint_sha256 在 crypto.certificate_asset 范围内不重复。';
COMMENT ON CONSTRAINT fk_certificate_asset_key ON crypto.certificate_asset IS '外键约束：crypto.certificate_asset 的 private_key_asset_id 必须引用 crypto.key_asset；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT ck_certificate_asset_kind ON crypto.certificate_asset IS '检查约束：限制 crypto.certificate_asset 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_certificate_asset_state ON crypto.certificate_asset IS '检查约束：限制 crypto.certificate_asset 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_certificate_asset_hash ON crypto.certificate_asset IS '检查约束：限制 crypto.certificate_asset 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_certificate_asset_window ON crypto.certificate_asset IS '检查约束：限制 crypto.certificate_asset 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_certificate_asset_revoked ON crypto.certificate_asset IS '检查约束：限制 crypto.certificate_asset 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_certificate_active ON crypto.certificate_asset IS '检查约束：限制 crypto.certificate_asset 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_certificate_expired ON crypto.certificate_asset IS '检查约束：限制 crypto.certificate_asset 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT pk_jwks_release ON crypto.jwks_release IS '主键约束：唯一标识 crypto.jwks_release 记录。';
COMMENT ON CONSTRAINT uq_jwks_release_public_id ON crypto.jwks_release IS '唯一约束：保证 public_id 在 crypto.jwks_release 范围内不重复。';
COMMENT ON CONSTRAINT uq_jwks_release_version ON crypto.jwks_release IS '唯一约束：保证 issuer、environment、jwks_version 在 crypto.jwks_release 范围内不重复。';
COMMENT ON CONSTRAINT ck_jwks_release_state ON crypto.jwks_release IS '检查约束：限制 crypto.jwks_release 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_jwks_release_keys ON crypto.jwks_release IS '检查约束：限制 crypto.jwks_release 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_jwks_release_hash ON crypto.jwks_release IS '检查约束：限制 crypto.jwks_release 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_jwks_release_cache ON crypto.jwks_release IS '检查约束：限制 crypto.jwks_release 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_jwks_release_state_times ON crypto.jwks_release IS '检查约束：限制 crypto.jwks_release 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_jwks_release_published ON crypto.jwks_release IS '检查约束：限制 crypto.jwks_release 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_jwks_release_active ON crypto.jwks_release IS '检查约束：限制 crypto.jwks_release 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_jwks_release_superseded ON crypto.jwks_release IS '检查约束：限制 crypto.jwks_release 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_jwks_release_revoked ON crypto.jwks_release IS '检查约束：限制 crypto.jwks_release 的字段取值或组合满足结构与安全底线。';

COMMENT ON INDEX crypto.ix_key_asset_rotation IS '查询索引：优化 crypto.key_asset 按 not_after 的访问，仅覆盖 WHERE 条件命中的记录。';
COMMENT ON INDEX crypto.pk_key_asset IS '约束 pk_key_asset 的支撑唯一索引。';
COMMENT ON INDEX crypto.uq_key_asset_public_id IS '约束 uq_key_asset_public_id 的支撑唯一索引。';
COMMENT ON INDEX crypto.uq_key_asset_kid IS '约束 uq_key_asset_kid 的支撑唯一索引。';
COMMENT ON INDEX crypto.pk_certificate_asset IS '约束 pk_certificate_asset 的支撑唯一索引。';
COMMENT ON INDEX crypto.uq_certificate_asset_public_id IS '约束 uq_certificate_asset_public_id 的支撑唯一索引。';
COMMENT ON INDEX crypto.uq_certificate_asset_serial IS '约束 uq_certificate_asset_serial 的支撑唯一索引。';
COMMENT ON INDEX crypto.uq_certificate_asset_thumbprint IS '约束 uq_certificate_asset_thumbprint 的支撑唯一索引。';
COMMENT ON INDEX crypto.pk_jwks_release IS '约束 pk_jwks_release 的支撑唯一索引。';
COMMENT ON INDEX crypto.uq_jwks_release_public_id IS '约束 uq_jwks_release_public_id 的支撑唯一索引。';
COMMENT ON INDEX crypto.uq_jwks_release_version IS '约束 uq_jwks_release_version 的支撑唯一索引。';
COMMENT ON INDEX crypto.ix_fk_certificate_asset_private_key_asset_id IS '查询索引：优化 crypto.certificate_asset 按 private_key_asset_id 的访问。';

