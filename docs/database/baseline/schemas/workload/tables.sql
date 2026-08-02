-- =============================================================================
-- baseline/schemas/workload/tables.sql
-- workload Schema 的最终基表、同 Schema 约束、索引及内联 COMMENT
-- PostgreSQL 16+；应用技术栈：.NET 10 + SqlSugar
-- =============================================================================

CREATE TABLE workload.machine_principal (
    id uuid        NOT NULL DEFAULT gen_random_uuid(),
    public_id text        NOT NULL,
    principal_code text        NOT NULL,
    principal_state text        NOT NULL DEFAULT 'PROVISIONING',
    business_line_id uuid        NOT NULL,
    tenant_id uuid        NOT NULL DEFAULT '00000000-0000-0000-0000-000000000000',
    environment text        NOT NULL,
    owner_ref text        NOT NULL,
    purpose text        NOT NULL,
    permission_baseline_hash bytea    NOT NULL,
    rotation_policy_code text        NOT NULL,
    trust_domain text        NULL,
    token_audiences text[]      NOT NULL,
    max_token_ttl_seconds integer     NOT NULL DEFAULT 300,
    principal_security_epoch bigint   NOT NULL DEFAULT 1,
    expires_at timestamptz NOT NULL,
    last_used_at timestamptz NULL,
    suspended_at timestamptz NULL,
    compromised_at timestamptz NULL,
    retired_at timestamptz NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    row_version bigint      NOT NULL DEFAULT 1,
    last_revalidated_at timestamptz NULL,
    last_revalidation_evidence_hash bytea NULL,
    state_reason_code text NULL,
    CONSTRAINT pk_machine_principal PRIMARY KEY (id),
    CONSTRAINT uq_machine_principal_public_id UNIQUE (public_id),
    CONSTRAINT uq_machine_principal_code UNIQUE (business_line_id, environment, principal_code),
    CONSTRAINT ck_machine_principal_state CHECK (principal_state IN ('PROVISIONING', 'ACTIVE', 'SUSPENDED', 'COMPROMISED', 'RETIRED')),
    CONSTRAINT ck_machine_principal_environment CHECK (environment IN ('DEV', 'TEST', 'STAGING', 'PRODUCTION')),
    CONSTRAINT ck_machine_principal_hash CHECK (octet_length(permission_baseline_hash) = 32),
    CONSTRAINT ck_machine_principal_audience CHECK (cardinality(token_audiences) > 0),
    CONSTRAINT ck_machine_principal_ttl CHECK (max_token_ttl_seconds BETWEEN 30 AND 300),
    CONSTRAINT ck_machine_principal_epoch CHECK (principal_security_epoch >= 1),
    CONSTRAINT ck_machine_principal_expiry CHECK (expires_at > created_at),
    CONSTRAINT ck_machine_principal_active CHECK (principal_state <> 'ACTIVE' OR (owner_ref <> '' AND purpose <> '' AND rotation_policy_code <> '')),
    CONSTRAINT ck_machine_revalidation_hash CHECK (last_revalidation_evidence_hash IS NULL OR octet_length(last_revalidation_evidence_hash) = 32),
    CONSTRAINT ck_machine_active_revalidation CHECK (
    principal_state <> 'ACTIVE' OR (last_revalidated_at IS NOT NULL AND last_revalidation_evidence_hash IS NOT NULL)
    )
);

COMMENT ON TABLE workload.machine_principal IS 'REQ-MACHINE-001/006/017/018：Owner、用途、环境、最小权限基线、到期、轮换和 security epoch 完整的机器主体。';

CREATE TABLE workload.machine_credential (
    id uuid        NOT NULL DEFAULT gen_random_uuid(),
    machine_principal_id uuid        NOT NULL,
    credential_kind text        NOT NULL,
    credential_state text        NOT NULL DEFAULT 'PENDING',
    key_id text        NULL,
    certificate_thumbprint bytea      NULL,
    secret_hash bytea       NULL,
    public_material jsonb       NULL,
    key_asset_id uuid        NULL,
    issued_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    activates_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    rotate_before timestamptz NOT NULL,
    revoked_at timestamptz NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    row_version bigint      NOT NULL DEFAULT 1,
    replaces_credential_id uuid NULL,
    compromised_at timestamptz NULL,
    state_reason_code text NULL,
    CONSTRAINT pk_machine_credential PRIMARY KEY (id),
    CONSTRAINT fk_machine_credential_principal FOREIGN KEY (machine_principal_id) REFERENCES workload.machine_principal(id),
    CONSTRAINT ck_machine_credential_kind CHECK (credential_kind IN ('PRIVATE_KEY_JWT', 'MTLS', 'WORKLOAD_FEDERATION', 'SECRET')),
    CONSTRAINT ck_machine_credential_state CHECK (credential_state IN ('PENDING', 'ACTIVE', 'ROTATING', 'EXPIRED', 'REVOKED', 'COMPROMISED')),
    CONSTRAINT ck_machine_credential_window CHECK (expires_at > activates_at AND rotate_before > activates_at AND rotate_before < expires_at),
    CONSTRAINT uq_machine_credential_replaces UNIQUE (replaces_credential_id),
    CONSTRAINT fk_machine_credential_replaces FOREIGN KEY (replaces_credential_id) REFERENCES workload.machine_credential(id),
    CONSTRAINT ck_machine_credential_not_self_replacing CHECK (replaces_credential_id IS NULL OR replaces_credential_id <> id),
    CONSTRAINT ck_machine_credential_material_by_kind CHECK (
    (credential_kind = 'PRIVATE_KEY_JWT' AND key_asset_id IS NOT NULL
    AND certificate_thumbprint IS NULL AND secret_hash IS NULL)
    OR (credential_kind = 'MTLS' AND certificate_thumbprint IS NOT NULL
    AND secret_hash IS NULL AND public_material IS NULL)
    OR (credential_kind = 'WORKLOAD_FEDERATION' AND public_material IS NOT NULL
    AND certificate_thumbprint IS NULL AND secret_hash IS NULL AND key_asset_id IS NULL)
    OR (credential_kind = 'SECRET' AND secret_hash IS NOT NULL
    AND certificate_thumbprint IS NULL AND public_material IS NULL AND key_asset_id IS NULL)
    ),
    CONSTRAINT ck_machine_credential_material_hashes CHECK (
    (certificate_thumbprint IS NULL OR octet_length(certificate_thumbprint) = 32)
    AND (secret_hash IS NULL OR octet_length(secret_hash) >= 32)
    ),
    CONSTRAINT ck_machine_credential_key_id CHECK (
    credential_kind <> 'PRIVATE_KEY_JWT' OR NULLIF(btrim(key_id), '') IS NOT NULL
    ),
    CONSTRAINT ck_machine_credential_usable CHECK (
    credential_state NOT IN ('ACTIVE', 'ROTATING') OR (revoked_at IS NULL AND compromised_at IS NULL)
    ),
    CONSTRAINT ck_machine_credential_compromised CHECK (credential_state <> 'COMPROMISED' OR compromised_at IS NOT NULL),
    CONSTRAINT ck_machine_credential_revoked CHECK (credential_state <> 'REVOKED' OR revoked_at IS NOT NULL)
);

COMMENT ON TABLE workload.machine_credential IS '机器主体的引用式密钥、mTLS、工作负载联合或兼容 Secret 凭证；不保存私钥/Secret 明文。';

CREATE TABLE workload.trust_bundle (
    id uuid        NOT NULL DEFAULT gen_random_uuid(),
    public_id text        NOT NULL,
    trust_domain text        NOT NULL,
    bundle_version bigint      NOT NULL,
    bundle_state text        NOT NULL DEFAULT 'DRAFT',
    issuer text        NOT NULL,
    allowed_audiences text[]      NOT NULL,
    environment text        NOT NULL,
    selector_schema jsonb       NOT NULL,
    public_material jsonb       NOT NULL,
    max_attestation_age_seconds integer NOT NULL,
    approval_case_id uuid,
    active_from timestamptz NULL,
    active_until timestamptz NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    bundle_context_hash bytea NOT NULL,
    validated_at timestamptz NULL,
    approved_at timestamptz NULL,
    verify_only_at timestamptz NULL,
    revoked_at timestamptz NULL,
    retired_at timestamptz NULL,
    state_reason_code text NULL,
    CONSTRAINT pk_trust_bundle PRIMARY KEY (id),
    CONSTRAINT uq_trust_bundle_public_id UNIQUE (public_id),
    CONSTRAINT uq_trust_bundle_version UNIQUE (trust_domain, environment, bundle_version),
    CONSTRAINT ck_trust_bundle_state CHECK (bundle_state IN ('DRAFT', 'VALIDATED', 'APPROVED', 'ACTIVE', 'VERIFY_ONLY', 'REVOKED', 'RETIRED')),
    CONSTRAINT ck_trust_bundle_audience CHECK (cardinality(allowed_audiences) > 0),
    CONSTRAINT ck_trust_bundle_age CHECK (max_attestation_age_seconds BETWEEN 10 AND 600),
    CONSTRAINT ck_trust_bundle_context_hash CHECK (octet_length(bundle_context_hash) = 32),
    CONSTRAINT ck_trust_bundle_approval CHECK (
    bundle_state NOT IN ('APPROVED', 'ACTIVE', 'VERIFY_ONLY', 'RETIRED') OR approval_case_id IS NOT NULL
    ),
    CONSTRAINT ck_trust_bundle_active CHECK (
    bundle_state NOT IN ('ACTIVE', 'VERIFY_ONLY', 'RETIRED') OR active_from IS NOT NULL
    ),
    CONSTRAINT ck_trust_bundle_window CHECK (
    active_from IS NULL OR active_until IS NULL OR active_until > active_from
    ),
    CONSTRAINT ck_trust_bundle_revoked CHECK (bundle_state <> 'REVOKED' OR revoked_at IS NOT NULL),
    CONSTRAINT ck_trust_bundle_retired CHECK (bundle_state <> 'RETIRED' OR retired_at IS NOT NULL)
);

COMMENT ON TABLE workload.trust_bundle IS 'REQ-MACHINE-012/014：工作负载 trust domain、issuer、audience、环境、选择器和轮换公钥包。';

CREATE TABLE workload.workload_attestation (
    id uuid        NOT NULL DEFAULT gen_random_uuid(),
    public_id text        NOT NULL,
    machine_principal_id uuid        NOT NULL,
    trust_bundle_id uuid        NOT NULL,
    attestation_state text        NOT NULL DEFAULT 'ATTESTATION_RECEIVED',
    issuer text        NOT NULL,
    audience text        NOT NULL,
    nonce_hash bytea       NOT NULL,
    jti_hash bytea       NOT NULL,
    selector_hash bytea       NOT NULL,
    evidence_hash bytea       NOT NULL,
    environment text        NOT NULL,
    received_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    verified_at timestamptz NULL,
    credential_issued_at timestamptz NULL,
    expires_at timestamptz NOT NULL,
    revoked_at timestamptz NULL,
    rejection_reason_code text        NULL,
    expired_at timestamptz NULL,
    revoke_reason_code text NULL,
    CONSTRAINT pk_workload_attestation PRIMARY KEY (id),
    CONSTRAINT uq_workload_attestation_public_id UNIQUE (public_id),
    CONSTRAINT uq_workload_attestation_jti UNIQUE (trust_bundle_id, jti_hash),
    CONSTRAINT fk_workload_attestation_principal FOREIGN KEY (machine_principal_id) REFERENCES workload.machine_principal(id),
    CONSTRAINT fk_workload_attestation_bundle FOREIGN KEY (trust_bundle_id) REFERENCES workload.trust_bundle(id),
    CONSTRAINT ck_workload_attestation_state CHECK (attestation_state IN ('ATTESTATION_RECEIVED', 'VERIFIED', 'CREDENTIAL_ISSUED', 'EXPIRED', 'REVOKED', 'REJECTED')),
    CONSTRAINT ck_workload_attestation_hash CHECK (octet_length(nonce_hash) = 32 AND octet_length(jti_hash) = 32 AND octet_length(selector_hash) = 32 AND octet_length(evidence_hash) = 32),
    CONSTRAINT ck_workload_attestation_expiry CHECK (expires_at > received_at),
    CONSTRAINT ck_workload_attestation_rejected CHECK (attestation_state <> 'REJECTED' OR rejection_reason_code IS NOT NULL),
    CONSTRAINT ck_workload_attestation_verified CHECK (
    attestation_state NOT IN ('VERIFIED', 'CREDENTIAL_ISSUED', 'EXPIRED', 'REVOKED') OR verified_at IS NOT NULL
    ),
    CONSTRAINT ck_workload_attestation_issued CHECK (
    attestation_state NOT IN ('CREDENTIAL_ISSUED', 'EXPIRED', 'REVOKED') OR credential_issued_at IS NOT NULL
    ),
    CONSTRAINT ck_workload_attestation_expired_state CHECK ((attestation_state = 'EXPIRED') = (expired_at IS NOT NULL)),
    CONSTRAINT ck_workload_attestation_revoked_state CHECK ((attestation_state = 'REVOKED') = (revoked_at IS NOT NULL))
);

COMMENT ON TABLE workload.workload_attestation IS 'REQ-MACHINE-013：签名、issuer、audience、时间、nonce/jti、环境和选择器验证的一次性短期工作负载证明。';

CREATE TABLE workload.token_exchange (
    id uuid        NOT NULL DEFAULT gen_random_uuid(),
    public_id text        NOT NULL,
    subject_kind text        NOT NULL,
    subject_ref text        NOT NULL,
    actor_kind text        NOT NULL,
    actor_ref text        NOT NULL,
    delegation_id uuid        NULL,
    source_token_hash bytea       NOT NULL,
    requested_audiences text[]      NOT NULL,
    requested_scopes text[]      NOT NULL DEFAULT '{}',
    granted_audiences text[]      NOT NULL,
    granted_scopes text[]      NOT NULL DEFAULT '{}',
    tenant_id uuid        NOT NULL DEFAULT '00000000-0000-0000-0000-000000000000',
    exchange_state text        NOT NULL DEFAULT 'PENDING',
    policy_version bigint      NOT NULL,
    issued_token_jti uuid        NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    completed_at timestamptz NULL,
    CONSTRAINT pk_token_exchange PRIMARY KEY (id),
    CONSTRAINT uq_token_exchange_public_id UNIQUE (public_id),
    CONSTRAINT ck_token_exchange_subject CHECK (subject_kind IN ('USER', 'MACHINE')),
    CONSTRAINT ck_token_exchange_actor CHECK (actor_kind IN ('CLIENT', 'MACHINE', 'USER')),
    CONSTRAINT ck_token_exchange_hash CHECK (octet_length(source_token_hash) = 32),
    CONSTRAINT ck_token_exchange_scope CHECK (granted_scopes <@ requested_scopes AND granted_audiences <@ requested_audiences),
    CONSTRAINT ck_token_exchange_state CHECK (exchange_state IN ('PENDING', 'ISSUED', 'DENIED', 'EXPIRED')),
    CONSTRAINT ck_token_exchange_complete CHECK ((exchange_state = 'ISSUED') = (completed_at IS NOT NULL AND issued_token_jti IS NOT NULL))
);

COMMENT ON TABLE workload.token_exchange IS 'REQ-MACHINE-007/008：保留 Subject、Actor、委托链、目标 audience/scope 且不得扩权的 Token Exchange 证据。';

CREATE INDEX ix_machine_owner_review ON workload.machine_principal(owner_ref, expires_at) WHERE principal_state = 'ACTIVE';

CREATE INDEX ix_machine_credential_rotation ON workload.machine_credential(rotate_before) WHERE credential_state IN ('ACTIVE', 'ROTATING');

CREATE INDEX ix_fk_machine_credential_machine_principal_id ON workload.machine_credential (machine_principal_id);

CREATE INDEX ix_fk_workload_attestation_machine_principal_id ON workload.workload_attestation (machine_principal_id);

COMMENT ON COLUMN workload.machine_principal.id IS '内部 UUID 主键；仅用于数据库关系，不作为跨域公开标识。';
COMMENT ON COLUMN workload.machine_principal.public_id IS '不可复用的公开稳定标识；插入时登记到 core.public_id_ledger。';
COMMENT ON COLUMN workload.machine_principal.principal_code IS '稳定机器可读代码；展示文本由资源或目录解析。';
COMMENT ON COLUMN workload.machine_principal.principal_state IS '显式状态当前值；合法取值见 CHECK，完整状态转换由 .NET 领域策略执行。';
COMMENT ON COLUMN workload.machine_principal.business_line_id IS '业务线隔离键；关联 org.business_line，用于业务线范围隔离。';
COMMENT ON COLUMN workload.machine_principal.tenant_id IS '租户隔离键；全零 UUID 表示平台范围，应用查询必须显式携带可信租户上下文。';
COMMENT ON COLUMN workload.machine_principal.environment IS 'workload.machine_principal.environment 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN workload.machine_principal.owner_ref IS '不透明对象引用；不得从格式推断手机号、邮箱或其他业务事实。';
COMMENT ON COLUMN workload.machine_principal.purpose IS 'workload.machine_principal.purpose 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN workload.machine_principal.permission_baseline_hash IS '不可逆摘要；用于等值匹配、幂等、完整性或最小化证据，不保存原始敏感值。';
COMMENT ON COLUMN workload.machine_principal.rotation_policy_code IS '稳定机器可读代码；展示文本由资源或目录解析。';
COMMENT ON COLUMN workload.machine_principal.trust_domain IS 'workload.machine_principal.trust_domain 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN workload.machine_principal.token_audiences IS '代码或引用集合；写入前去重、校验 allowlist，并满足表约束。';
COMMENT ON COLUMN workload.machine_principal.max_token_ttl_seconds IS '以秒为单位的显式时长；有效范围由安全策略及表约束限制。';
COMMENT ON COLUMN workload.machine_principal.principal_security_epoch IS '安全或同意水位版本；只能单调递增，用于令牌、缓存与撤销新鲜度校验。';
COMMENT ON COLUMN workload.machine_principal.expires_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN workload.machine_principal.last_used_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN workload.machine_principal.suspended_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN workload.machine_principal.compromised_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN workload.machine_principal.retired_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN workload.machine_principal.created_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN workload.machine_principal.updated_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN workload.machine_principal.row_version IS '乐观并发版本；更新必须使用原值 compare-and-set，成功后由数据库单调递增。';
COMMENT ON COLUMN workload.machine_principal.last_revalidated_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN workload.machine_principal.last_revalidation_evidence_hash IS '不可逆摘要；用于等值匹配、幂等、完整性或最小化证据，不保存原始敏感值。';
COMMENT ON COLUMN workload.machine_principal.state_reason_code IS '稳定机器可读代码；展示文本由资源或目录解析。';
COMMENT ON COLUMN workload.machine_credential.id IS '内部 UUID 主键；仅用于数据库关系，不作为跨域公开标识。';
COMMENT ON COLUMN workload.machine_credential.machine_principal_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN workload.machine_credential.credential_kind IS '对象类别判别字段；允许值由 CHECK 或对应注册表限定。';
COMMENT ON COLUMN workload.machine_credential.credential_state IS '显式状态当前值；合法取值见 CHECK，完整状态转换由 .NET 领域策略执行。';
COMMENT ON COLUMN workload.machine_credential.key_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN workload.machine_credential.certificate_thumbprint IS 'workload.machine_credential.certificate_thumbprint 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN workload.machine_credential.secret_hash IS '不可逆摘要；用于等值匹配、幂等、完整性或最小化证据，不保存原始敏感值。';
COMMENT ON COLUMN workload.machine_credential.public_material IS '版本化结构化扩展数据；必须由 .NET 按对应 JSON Schema 校验，不得替代核心状态或外键。';
COMMENT ON COLUMN workload.machine_credential.key_asset_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN workload.machine_credential.issued_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN workload.machine_credential.activates_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN workload.machine_credential.expires_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN workload.machine_credential.rotate_before IS 'workload.machine_credential.rotate_before 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN workload.machine_credential.revoked_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN workload.machine_credential.created_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN workload.machine_credential.updated_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN workload.machine_credential.row_version IS '乐观并发版本；更新必须使用原值 compare-and-set，成功后由数据库单调递增。';
COMMENT ON COLUMN workload.machine_credential.replaces_credential_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN workload.machine_credential.compromised_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN workload.machine_credential.state_reason_code IS '稳定机器可读代码；展示文本由资源或目录解析。';
COMMENT ON COLUMN workload.trust_bundle.id IS '内部 UUID 主键；仅用于数据库关系，不作为跨域公开标识。';
COMMENT ON COLUMN workload.trust_bundle.public_id IS '不可复用的公开稳定标识；插入时登记到 core.public_id_ledger。';
COMMENT ON COLUMN workload.trust_bundle.trust_domain IS 'workload.trust_bundle.trust_domain 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN workload.trust_bundle.bundle_version IS '对象、策略或源数据的显式版本；不得以不可信客户端时间戳替代。';
COMMENT ON COLUMN workload.trust_bundle.bundle_state IS '显式状态当前值；合法取值见 CHECK，完整状态转换由 .NET 领域策略执行。';
COMMENT ON COLUMN workload.trust_bundle.issuer IS 'workload.trust_bundle.issuer 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN workload.trust_bundle.allowed_audiences IS '代码或引用集合；写入前去重、校验 allowlist，并满足表约束。';
COMMENT ON COLUMN workload.trust_bundle.environment IS 'workload.trust_bundle.environment 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN workload.trust_bundle.selector_schema IS '版本化结构化扩展数据；必须由 .NET 按对应 JSON Schema 校验，不得替代核心状态或外键。';
COMMENT ON COLUMN workload.trust_bundle.public_material IS '版本化结构化扩展数据；必须由 .NET 按对应 JSON Schema 校验，不得替代核心状态或外键。';
COMMENT ON COLUMN workload.trust_bundle.max_attestation_age_seconds IS '以秒为单位的显式时长；有效范围由安全策略及表约束限制。';
COMMENT ON COLUMN workload.trust_bundle.approval_case_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN workload.trust_bundle.active_from IS 'workload.trust_bundle.active_from 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN workload.trust_bundle.active_until IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN workload.trust_bundle.created_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN workload.trust_bundle.bundle_context_hash IS '不可逆摘要；用于等值匹配、幂等、完整性或最小化证据，不保存原始敏感值。';
COMMENT ON COLUMN workload.trust_bundle.validated_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN workload.trust_bundle.approved_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN workload.trust_bundle.verify_only_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN workload.trust_bundle.revoked_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN workload.trust_bundle.retired_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN workload.trust_bundle.state_reason_code IS '稳定机器可读代码；展示文本由资源或目录解析。';
COMMENT ON COLUMN workload.workload_attestation.id IS '内部 UUID 主键；仅用于数据库关系，不作为跨域公开标识。';
COMMENT ON COLUMN workload.workload_attestation.public_id IS '不可复用的公开稳定标识；插入时登记到 core.public_id_ledger。';
COMMENT ON COLUMN workload.workload_attestation.machine_principal_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN workload.workload_attestation.trust_bundle_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN workload.workload_attestation.attestation_state IS '显式状态当前值；合法取值见 CHECK，完整状态转换由 .NET 领域策略执行。';
COMMENT ON COLUMN workload.workload_attestation.issuer IS 'workload.workload_attestation.issuer 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN workload.workload_attestation.audience IS 'workload.workload_attestation.audience 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN workload.workload_attestation.nonce_hash IS '不可逆摘要；用于等值匹配、幂等、完整性或最小化证据，不保存原始敏感值。';
COMMENT ON COLUMN workload.workload_attestation.jti_hash IS '不可逆摘要；用于等值匹配、幂等、完整性或最小化证据，不保存原始敏感值。';
COMMENT ON COLUMN workload.workload_attestation.selector_hash IS '不可逆摘要；用于等值匹配、幂等、完整性或最小化证据，不保存原始敏感值。';
COMMENT ON COLUMN workload.workload_attestation.evidence_hash IS '不可逆摘要；用于等值匹配、幂等、完整性或最小化证据，不保存原始敏感值。';
COMMENT ON COLUMN workload.workload_attestation.environment IS 'workload.workload_attestation.environment 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN workload.workload_attestation.received_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN workload.workload_attestation.verified_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN workload.workload_attestation.credential_issued_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN workload.workload_attestation.expires_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN workload.workload_attestation.revoked_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN workload.workload_attestation.rejection_reason_code IS '稳定机器可读代码；展示文本由资源或目录解析。';
COMMENT ON COLUMN workload.workload_attestation.expired_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN workload.workload_attestation.revoke_reason_code IS '稳定机器可读代码；展示文本由资源或目录解析。';
COMMENT ON COLUMN workload.token_exchange.id IS '内部 UUID 主键；仅用于数据库关系，不作为跨域公开标识。';
COMMENT ON COLUMN workload.token_exchange.public_id IS '不可复用的公开稳定标识；插入时登记到 core.public_id_ledger。';
COMMENT ON COLUMN workload.token_exchange.subject_kind IS '对象类别判别字段；允许值由 CHECK 或对应注册表限定。';
COMMENT ON COLUMN workload.token_exchange.subject_ref IS '不透明对象引用；不得从格式推断手机号、邮箱或其他业务事实。';
COMMENT ON COLUMN workload.token_exchange.actor_kind IS '对象类别判别字段；允许值由 CHECK 或对应注册表限定。';
COMMENT ON COLUMN workload.token_exchange.actor_ref IS '不透明对象引用；不得从格式推断手机号、邮箱或其他业务事实。';
COMMENT ON COLUMN workload.token_exchange.delegation_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN workload.token_exchange.source_token_hash IS '不可逆摘要；用于等值匹配、幂等、完整性或最小化证据，不保存原始敏感值。';
COMMENT ON COLUMN workload.token_exchange.requested_audiences IS '代码或引用集合；写入前去重、校验 allowlist，并满足表约束。';
COMMENT ON COLUMN workload.token_exchange.requested_scopes IS '代码或引用集合；写入前去重、校验 allowlist，并满足表约束。';
COMMENT ON COLUMN workload.token_exchange.granted_audiences IS '代码或引用集合；写入前去重、校验 allowlist，并满足表约束。';
COMMENT ON COLUMN workload.token_exchange.granted_scopes IS '代码或引用集合；写入前去重、校验 allowlist，并满足表约束。';
COMMENT ON COLUMN workload.token_exchange.tenant_id IS '租户隔离键；全零 UUID 表示平台范围，应用查询必须显式携带可信租户上下文。';
COMMENT ON COLUMN workload.token_exchange.exchange_state IS '显式状态当前值；合法取值见 CHECK，完整状态转换由 .NET 领域策略执行。';
COMMENT ON COLUMN workload.token_exchange.policy_version IS '对象、策略或源数据的显式版本；不得以不可信客户端时间戳替代。';
COMMENT ON COLUMN workload.token_exchange.issued_token_jti IS 'workload.token_exchange.issued_token_jti 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN workload.token_exchange.created_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN workload.token_exchange.completed_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';

COMMENT ON CONSTRAINT pk_machine_principal ON workload.machine_principal IS '主键约束：唯一标识 workload.machine_principal 记录。';
COMMENT ON CONSTRAINT uq_machine_principal_public_id ON workload.machine_principal IS '唯一约束：保证 public_id 在 workload.machine_principal 范围内不重复。';
COMMENT ON CONSTRAINT uq_machine_principal_code ON workload.machine_principal IS '唯一约束：保证 business_line_id、environment、principal_code 在 workload.machine_principal 范围内不重复。';
COMMENT ON CONSTRAINT ck_machine_principal_state ON workload.machine_principal IS '检查约束：限制 workload.machine_principal 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_machine_principal_environment ON workload.machine_principal IS '检查约束：限制 workload.machine_principal 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_machine_principal_hash ON workload.machine_principal IS '检查约束：限制 workload.machine_principal 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_machine_principal_audience ON workload.machine_principal IS '检查约束：限制 workload.machine_principal 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_machine_principal_ttl ON workload.machine_principal IS '检查约束：限制 workload.machine_principal 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_machine_principal_epoch ON workload.machine_principal IS '检查约束：限制 workload.machine_principal 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_machine_principal_expiry ON workload.machine_principal IS '检查约束：限制 workload.machine_principal 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_machine_principal_active ON workload.machine_principal IS '检查约束：限制 workload.machine_principal 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_machine_revalidation_hash ON workload.machine_principal IS '检查约束：限制 workload.machine_principal 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_machine_active_revalidation ON workload.machine_principal IS '检查约束：限制 workload.machine_principal 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT pk_machine_credential ON workload.machine_credential IS '主键约束：唯一标识 workload.machine_credential 记录。';
COMMENT ON CONSTRAINT fk_machine_credential_principal ON workload.machine_credential IS '外键约束：workload.machine_credential 的 machine_principal_id 必须引用 workload.machine_principal；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT ck_machine_credential_kind ON workload.machine_credential IS '检查约束：限制 workload.machine_credential 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_machine_credential_state ON workload.machine_credential IS '检查约束：限制 workload.machine_credential 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_machine_credential_window ON workload.machine_credential IS '检查约束：限制 workload.machine_credential 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT uq_machine_credential_replaces ON workload.machine_credential IS '唯一约束：保证 replaces_credential_id 在 workload.machine_credential 范围内不重复。';
COMMENT ON CONSTRAINT fk_machine_credential_replaces ON workload.machine_credential IS '外键约束：workload.machine_credential 的 replaces_credential_id 必须引用 workload.machine_credential；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT ck_machine_credential_not_self_replacing ON workload.machine_credential IS '检查约束：限制 workload.machine_credential 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_machine_credential_material_by_kind ON workload.machine_credential IS '检查约束：限制 workload.machine_credential 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_machine_credential_material_hashes ON workload.machine_credential IS '检查约束：限制 workload.machine_credential 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_machine_credential_key_id ON workload.machine_credential IS '检查约束：限制 workload.machine_credential 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_machine_credential_usable ON workload.machine_credential IS '检查约束：限制 workload.machine_credential 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_machine_credential_compromised ON workload.machine_credential IS '检查约束：限制 workload.machine_credential 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_machine_credential_revoked ON workload.machine_credential IS '检查约束：限制 workload.machine_credential 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT pk_trust_bundle ON workload.trust_bundle IS '主键约束：唯一标识 workload.trust_bundle 记录。';
COMMENT ON CONSTRAINT uq_trust_bundle_public_id ON workload.trust_bundle IS '唯一约束：保证 public_id 在 workload.trust_bundle 范围内不重复。';
COMMENT ON CONSTRAINT uq_trust_bundle_version ON workload.trust_bundle IS '唯一约束：保证 trust_domain、environment、bundle_version 在 workload.trust_bundle 范围内不重复。';
COMMENT ON CONSTRAINT ck_trust_bundle_state ON workload.trust_bundle IS '检查约束：限制 workload.trust_bundle 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_trust_bundle_audience ON workload.trust_bundle IS '检查约束：限制 workload.trust_bundle 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_trust_bundle_age ON workload.trust_bundle IS '检查约束：限制 workload.trust_bundle 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_trust_bundle_context_hash ON workload.trust_bundle IS '检查约束：限制 workload.trust_bundle 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_trust_bundle_approval ON workload.trust_bundle IS '检查约束：限制 workload.trust_bundle 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_trust_bundle_active ON workload.trust_bundle IS '检查约束：限制 workload.trust_bundle 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_trust_bundle_window ON workload.trust_bundle IS '检查约束：限制 workload.trust_bundle 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_trust_bundle_revoked ON workload.trust_bundle IS '检查约束：限制 workload.trust_bundle 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_trust_bundle_retired ON workload.trust_bundle IS '检查约束：限制 workload.trust_bundle 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT pk_workload_attestation ON workload.workload_attestation IS '主键约束：唯一标识 workload.workload_attestation 记录。';
COMMENT ON CONSTRAINT uq_workload_attestation_public_id ON workload.workload_attestation IS '唯一约束：保证 public_id 在 workload.workload_attestation 范围内不重复。';
COMMENT ON CONSTRAINT uq_workload_attestation_jti ON workload.workload_attestation IS '唯一约束：保证 trust_bundle_id、jti_hash 在 workload.workload_attestation 范围内不重复。';
COMMENT ON CONSTRAINT fk_workload_attestation_principal ON workload.workload_attestation IS '外键约束：workload.workload_attestation 的 machine_principal_id 必须引用 workload.machine_principal；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT fk_workload_attestation_bundle ON workload.workload_attestation IS '外键约束：workload.workload_attestation 的 trust_bundle_id 必须引用 workload.trust_bundle；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT ck_workload_attestation_state ON workload.workload_attestation IS '检查约束：限制 workload.workload_attestation 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_workload_attestation_hash ON workload.workload_attestation IS '检查约束：限制 workload.workload_attestation 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_workload_attestation_expiry ON workload.workload_attestation IS '检查约束：限制 workload.workload_attestation 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_workload_attestation_rejected ON workload.workload_attestation IS '检查约束：限制 workload.workload_attestation 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_workload_attestation_verified ON workload.workload_attestation IS '检查约束：限制 workload.workload_attestation 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_workload_attestation_issued ON workload.workload_attestation IS '检查约束：限制 workload.workload_attestation 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_workload_attestation_expired_state ON workload.workload_attestation IS '检查约束：限制 workload.workload_attestation 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_workload_attestation_revoked_state ON workload.workload_attestation IS '检查约束：限制 workload.workload_attestation 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT pk_token_exchange ON workload.token_exchange IS '主键约束：唯一标识 workload.token_exchange 记录。';
COMMENT ON CONSTRAINT uq_token_exchange_public_id ON workload.token_exchange IS '唯一约束：保证 public_id 在 workload.token_exchange 范围内不重复。';
COMMENT ON CONSTRAINT ck_token_exchange_subject ON workload.token_exchange IS '检查约束：限制 workload.token_exchange 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_token_exchange_actor ON workload.token_exchange IS '检查约束：限制 workload.token_exchange 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_token_exchange_hash ON workload.token_exchange IS '检查约束：限制 workload.token_exchange 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_token_exchange_scope ON workload.token_exchange IS '检查约束：限制 workload.token_exchange 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_token_exchange_state ON workload.token_exchange IS '检查约束：限制 workload.token_exchange 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_token_exchange_complete ON workload.token_exchange IS '检查约束：限制 workload.token_exchange 的字段取值或组合满足结构与安全底线。';

COMMENT ON INDEX workload.ix_machine_owner_review IS '查询索引：优化 workload.machine_principal 按 owner_ref、expires_at 的访问，仅覆盖 WHERE 条件命中的记录。';
COMMENT ON INDEX workload.ix_machine_credential_rotation IS '查询索引：优化 workload.machine_credential 按 rotate_before 的访问，仅覆盖 WHERE 条件命中的记录。';
COMMENT ON INDEX workload.pk_machine_principal IS '约束 pk_machine_principal 的支撑唯一索引。';
COMMENT ON INDEX workload.uq_machine_principal_public_id IS '约束 uq_machine_principal_public_id 的支撑唯一索引。';
COMMENT ON INDEX workload.uq_machine_principal_code IS '约束 uq_machine_principal_code 的支撑唯一索引。';
COMMENT ON INDEX workload.pk_machine_credential IS '约束 pk_machine_credential 的支撑唯一索引。';
COMMENT ON INDEX workload.uq_machine_credential_replaces IS '约束 uq_machine_credential_replaces 的支撑唯一索引。';
COMMENT ON INDEX workload.pk_trust_bundle IS '约束 pk_trust_bundle 的支撑唯一索引。';
COMMENT ON INDEX workload.uq_trust_bundle_public_id IS '约束 uq_trust_bundle_public_id 的支撑唯一索引。';
COMMENT ON INDEX workload.uq_trust_bundle_version IS '约束 uq_trust_bundle_version 的支撑唯一索引。';
COMMENT ON INDEX workload.pk_workload_attestation IS '约束 pk_workload_attestation 的支撑唯一索引。';
COMMENT ON INDEX workload.uq_workload_attestation_public_id IS '约束 uq_workload_attestation_public_id 的支撑唯一索引。';
COMMENT ON INDEX workload.uq_workload_attestation_jti IS '约束 uq_workload_attestation_jti 的支撑唯一索引。';
COMMENT ON INDEX workload.pk_token_exchange IS '约束 pk_token_exchange 的支撑唯一索引。';
COMMENT ON INDEX workload.uq_token_exchange_public_id IS '约束 uq_token_exchange_public_id 的支撑唯一索引。';
COMMENT ON INDEX workload.ix_fk_machine_credential_machine_principal_id IS '查询索引：优化 workload.machine_credential 按 machine_principal_id 的访问。';
COMMENT ON INDEX workload.ix_fk_workload_attestation_machine_principal_id IS '查询索引：优化 workload.workload_attestation 按 machine_principal_id 的访问。';

