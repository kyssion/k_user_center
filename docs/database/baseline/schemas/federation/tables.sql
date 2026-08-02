-- =============================================================================
-- baseline/schemas/federation/tables.sql
-- federation Schema 的最终基表、同 Schema 约束、索引及内联 COMMENT
-- PostgreSQL 16+；应用技术栈：.NET 10 + SqlSugar
-- =============================================================================

CREATE TABLE federation.identity_provider (
    id uuid        NOT NULL DEFAULT gen_random_uuid(),
    public_id text        NOT NULL,
    tenant_id uuid        NOT NULL,
    provider_code text        NOT NULL,
    protocol_kind text        NOT NULL,
    provider_state text        NOT NULL DEFAULT 'DRAFT',
    issuer_or_entity_id text        NOT NULL,
    metadata_source_uri text        NOT NULL,
    audience_values text[]      NOT NULL,
    callback_uri text        NOT NULL,
    allowed_algorithms text[]      NOT NULL,
    owner_ref text        NOT NULL,
    jit_enabled boolean     NOT NULL DEFAULT false,
    max_clock_skew_seconds integer    NOT NULL DEFAULT 120,
    metadata_version bigint      NOT NULL DEFAULT 1,
    approval_case_id uuid        NULL,
    activated_at timestamptz NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    row_version bigint      NOT NULL DEFAULT 1,
    configuration_hash bytea NOT NULL,
    approval_execution_id uuid NULL,
    last_activation_execution_id uuid NULL,
    CONSTRAINT pk_identity_provider PRIMARY KEY (id),
    CONSTRAINT uq_identity_provider_public_id UNIQUE (public_id),
    CONSTRAINT uq_identity_provider_issuer UNIQUE (tenant_id, protocol_kind, issuer_or_entity_id),
    CONSTRAINT ck_identity_provider_protocol CHECK (protocol_kind IN ('OIDC', 'SAML', 'SOCIAL', 'DIRECTORY')),
    CONSTRAINT ck_identity_provider_state CHECK (provider_state IN ('DRAFT', 'VALIDATED', 'APPROVED', 'ACTIVE', 'SUSPENDED', 'RETIRED', 'COMPROMISED')),
    CONSTRAINT ck_identity_provider_audience CHECK (cardinality(audience_values) > 0),
    CONSTRAINT ck_identity_provider_alg CHECK (cardinality(allowed_algorithms) > 0 AND NOT ('none' = ANY(allowed_algorithms))),
    CONSTRAINT ck_identity_provider_skew CHECK (max_clock_skew_seconds BETWEEN 0 AND 300),
    CONSTRAINT ck_identity_provider_configuration_hash CHECK (octet_length(configuration_hash) = 32)
);

COMMENT ON TABLE federation.identity_provider IS 'REQ-FED-001：租户联合 IdP 的 issuer/entityID、元数据、audience、回调、算法、Owner 与状态。';

CREATE TABLE federation.identity_provider_key (
    id uuid        NOT NULL DEFAULT gen_random_uuid(),
    identity_provider_id uuid        NOT NULL,
    key_id text        NOT NULL,
    key_kind text        NOT NULL,
    algorithm text        NOT NULL,
    public_material jsonb       NOT NULL,
    certificate_thumbprint bytea      NULL,
    key_state text        NOT NULL DEFAULT 'PUBLISHED',
    not_before timestamptz NOT NULL,
    not_after timestamptz NOT NULL,
    fetched_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT pk_identity_provider_key PRIMARY KEY (id),
    CONSTRAINT uq_identity_provider_key UNIQUE (identity_provider_id, key_id, not_before),
    CONSTRAINT fk_identity_provider_key_provider FOREIGN KEY (identity_provider_id) REFERENCES federation.identity_provider(id),
    CONSTRAINT ck_identity_provider_key_kind CHECK (key_kind IN ('JWK', 'X509')),
    CONSTRAINT ck_identity_provider_key_state CHECK (key_state IN ('PUBLISHED', 'ACTIVE', 'VERIFY_ONLY', 'REVOKED', 'EXPIRED')),
    CONSTRAINT ck_identity_provider_key_window CHECK (not_after > not_before)
);

COMMENT ON TABLE federation.identity_provider_key IS 'REQ-FED-003：IdP JWKS/证书双版本轮换窗口；未知或弱算法密钥不得接受。';

CREATE TABLE federation.external_identity (
    id uuid        NOT NULL DEFAULT gen_random_uuid(),
    public_id text        NOT NULL,
    identity_provider_id uuid        NOT NULL,
    user_id uuid        NOT NULL,
    protocol_kind text        NOT NULL,
    canonical_subject_hash bytea      NOT NULL,
    canonical_subject_ciphertext bytea NOT NULL,
    oidc_subject_hash bytea       NULL,
    saml_name_id_hash bytea       NULL,
    saml_name_id_format text        NULL,
    saml_name_qualifier_hash bytea    NULL,
    saml_sp_name_qualifier_hash bytea NULL,
    saml_sp_provided_id_hash bytea    NULL,
    saml_is_transient boolean     NULL,
    directory_object_id_hash bytea    NULL,
    binding_state text        NOT NULL DEFAULT 'PENDING',
    linked_at timestamptz NULL,
    unlinked_at timestamptz NULL,
    last_login_at timestamptz NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    row_version bigint      NOT NULL DEFAULT 1,
    CONSTRAINT pk_external_identity PRIMARY KEY (id),
    CONSTRAINT uq_external_identity_public_id UNIQUE (public_id),
    CONSTRAINT uq_external_identity_subject UNIQUE (identity_provider_id, canonical_subject_hash),
    CONSTRAINT fk_external_identity_provider FOREIGN KEY (identity_provider_id) REFERENCES federation.identity_provider(id),
    CONSTRAINT ck_external_identity_protocol CHECK (protocol_kind IN ('OIDC', 'SAML', 'SOCIAL', 'DIRECTORY')),
    CONSTRAINT ck_external_identity_hash CHECK (octet_length(canonical_subject_hash) = 32),
    CONSTRAINT ck_external_identity_protocol_key CHECK (
    (protocol_kind IN ('OIDC', 'SOCIAL') AND oidc_subject_hash IS NOT NULL AND saml_name_id_hash IS NULL AND directory_object_id_hash IS NULL)
    OR (protocol_kind = 'SAML' AND saml_name_id_hash IS NOT NULL AND oidc_subject_hash IS NULL AND directory_object_id_hash IS NULL AND saml_is_transient = false)
    OR (protocol_kind = 'DIRECTORY' AND directory_object_id_hash IS NOT NULL AND oidc_subject_hash IS NULL AND saml_name_id_hash IS NULL)
    ),
    CONSTRAINT ck_external_identity_state CHECK (binding_state IN ('PENDING', 'LINKED', 'CONFLICT', 'UNLINKED', 'TOMBSTONED')),
    CONSTRAINT ck_external_identity_linked CHECK (binding_state <> 'LINKED' OR linked_at IS NOT NULL),
    CONSTRAINT ck_external_identity_unlinked CHECK (binding_state NOT IN ('UNLINKED', 'TOMBSTONED') OR unlinked_at IS NOT NULL)
);

COMMENT ON TABLE federation.external_identity IS 'INV-G-004 / REQ-FED-004：按 OIDC sub 或完整 SAML NameID 限定元组等协议稳定键绑定；Transient NameID 禁止永久绑定。';

CREATE TABLE federation.attribute_mapping (
    id uuid        NOT NULL DEFAULT gen_random_uuid(),
    identity_provider_id uuid        NOT NULL,
    mapping_version integer     NOT NULL,
    source_attribute text        NOT NULL,
    target_namespace text        NOT NULL,
    target_field_code text        NOT NULL,
    transformation jsonb       NOT NULL,
    value_schema jsonb       NOT NULL,
    maximum_privilege_tier text       NOT NULL DEFAULT 'STANDARD',
    is_active boolean     NOT NULL DEFAULT true,
    CONSTRAINT pk_attribute_mapping PRIMARY KEY (id),
    CONSTRAINT uq_attribute_mapping UNIQUE (identity_provider_id, mapping_version, source_attribute, target_namespace, target_field_code),
    CONSTRAINT fk_attribute_mapping_provider FOREIGN KEY (identity_provider_id) REFERENCES federation.identity_provider(id),
    CONSTRAINT ck_attribute_mapping_tier CHECK (maximum_privilege_tier IN ('NONE', 'STANDARD', 'ELEVATED'))
);

COMMENT ON TABLE federation.attribute_mapping IS 'REQ-FED-005：外部属性到 Profile/角色输入的版本化转换、类型校验和权限上限。';

CREATE TABLE federation.directory_connection (
    id uuid        NOT NULL DEFAULT gen_random_uuid(),
    public_id text        NOT NULL,
    tenant_id uuid        NOT NULL,
    identity_provider_id uuid        NULL,
    directory_kind text        NOT NULL,
    connection_state text        NOT NULL DEFAULT 'DRAFT',
    base_uri text        NOT NULL,
    credential_key_ref text        NOT NULL,
    authority_mode text        NOT NULL,
    supports_sortable_version boolean NOT NULL DEFAULT false,
    owner_ref text        NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    row_version bigint      NOT NULL DEFAULT 1,
    CONSTRAINT pk_directory_connection PRIMARY KEY (id),
    CONSTRAINT uq_directory_connection_public_id UNIQUE (public_id),
    CONSTRAINT fk_directory_connection_provider FOREIGN KEY (identity_provider_id) REFERENCES federation.identity_provider(id),
    CONSTRAINT ck_directory_connection_kind CHECK (directory_kind IN ('SCIM', 'LDAP_BRIDGE', 'HR_CONNECTOR')),
    CONSTRAINT ck_directory_connection_state CHECK (connection_state IN ('DRAFT', 'VALIDATED', 'ACTIVE', 'SUSPENDED', 'RETIRED')),
    CONSTRAINT ck_directory_connection_mode CHECK (authority_mode IN ('DIRECTORY_AUTHORITATIVE', 'PLATFORM_AUTHORITATIVE', 'FIELD_LEVEL'))
);

COMMENT ON TABLE federation.directory_connection IS 'CAP-FED-009/010：SCIM/目录连接、凭证引用、权威模式和源版本能力。';

CREATE TABLE federation.directory_object (
    id uuid        NOT NULL DEFAULT gen_random_uuid(),
    directory_connection_id uuid      NOT NULL,
    object_kind text        NOT NULL,
    external_object_hash bytea       NOT NULL,
    platform_object_kind text        NULL,
    platform_object_id uuid        NULL,
    source_etag text        NULL,
    source_sortable_version bigint    NULL,
    source_modified_at timestamptz NULL,
    sync_state text        NOT NULL DEFAULT 'DISCOVERED',
    tombstone_version bigint      NULL,
    payload_hash bytea       NOT NULL,
    last_applied_at timestamptz NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    row_version bigint      NOT NULL DEFAULT 1,
    CONSTRAINT pk_directory_object PRIMARY KEY (id),
    CONSTRAINT uq_directory_object UNIQUE (directory_connection_id, object_kind, external_object_hash),
    CONSTRAINT fk_directory_object_connection FOREIGN KEY (directory_connection_id) REFERENCES federation.directory_connection(id),
    CONSTRAINT ck_directory_object_kind CHECK (object_kind IN ('USER', 'GROUP', 'ORGANIZATION')),
    CONSTRAINT ck_directory_object_platform CHECK ((platform_object_kind IS NULL) = (platform_object_id IS NULL)),
    CONSTRAINT ck_directory_object_state CHECK (sync_state IN ('DISCOVERED', 'LINKED', 'APPLIED', 'CONFLICT', 'DISABLED', 'TOMBSTONED')),
    CONSTRAINT ck_directory_object_hash CHECK (octet_length(external_object_hash) = 32 AND octet_length(payload_hash) = 32),
    CONSTRAINT ck_directory_object_tombstone CHECK (sync_state <> 'TOMBSTONED' OR tombstone_version IS NOT NULL)
);

COMMENT ON TABLE federation.directory_object IS 'REQ-FED-006/007：目录对象映射、不透明 ETag、可选可排序源版本和优先级更高的停用墓碑。';

CREATE TABLE federation.directory_sync_run (
    id uuid        NOT NULL DEFAULT gen_random_uuid(),
    public_id text        NOT NULL,
    directory_connection_id uuid      NOT NULL,
    operation_id uuid        NOT NULL,
    sync_run_state text        NOT NULL DEFAULT 'PENDING',
    source_cursor text        NULL,
    next_cursor text        NULL,
    discovered_count bigint      NOT NULL DEFAULT 0,
    applied_count bigint      NOT NULL DEFAULT 0,
    failed_count bigint      NOT NULL DEFAULT 0,
    started_at timestamptz NULL,
    completed_at timestamptz NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT pk_directory_sync_run PRIMARY KEY (id),
    CONSTRAINT uq_directory_sync_run_public_id UNIQUE (public_id),
    CONSTRAINT uq_directory_sync_run_operation UNIQUE (operation_id),
    CONSTRAINT fk_directory_sync_run_connection FOREIGN KEY (directory_connection_id) REFERENCES federation.directory_connection(id),
    CONSTRAINT ck_directory_sync_run_state CHECK (sync_run_state IN ('PENDING', 'RUNNING', 'PARTIAL', 'BLOCKED', 'COMPLETED', 'FAILED', 'CANCELLED')),
    CONSTRAINT ck_directory_sync_run_count CHECK (discovered_count >= 0 AND applied_count >= 0 AND failed_count >= 0 AND applied_count + failed_count <= discovered_count)
);

COMMENT ON TABLE federation.directory_sync_run IS 'REQ-FED-008：SCIM/目录分页、幂等、部分失败、限流与游标同步 Operation。';

CREATE TABLE federation.assertion_replay (
    replay_key_hash bytea       NOT NULL,
    protocol_kind text        NOT NULL,
    identity_provider_id uuid        NOT NULL,
    audience_hash bytea       NOT NULL,
    environment text        NOT NULL,
    first_seen_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    expires_at timestamptz NOT NULL,
    CONSTRAINT pk_assertion_replay PRIMARY KEY (replay_key_hash),
    CONSTRAINT fk_assertion_replay_provider FOREIGN KEY (identity_provider_id) REFERENCES federation.identity_provider(id),
    CONSTRAINT ck_assertion_replay_protocol CHECK (protocol_kind IN ('OIDC_NONCE', 'SAML_ASSERTION', 'CLIENT_ASSERTION', 'WORKLOAD_ATTESTATION')),
    CONSTRAINT ck_assertion_replay_hash CHECK (octet_length(replay_key_hash) = 32 AND octet_length(audience_hash) = 32),
    CONSTRAINT ck_assertion_replay_expiry CHECK (expires_at > first_seen_at)
);

COMMENT ON TABLE federation.assertion_replay IS 'REQ-FED-002 / REQ-MACHINE-016：nonce、Assertion ID、jti 的协议/Client/环境/audience 绑定防重放窗口。';

CREATE TABLE federation.federation_migration (
    id uuid        NOT NULL DEFAULT gen_random_uuid(),
    tenant_id uuid        NOT NULL,
    source_provider_id uuid        NOT NULL,
    target_provider_id uuid        NOT NULL,
    operation_id uuid        NOT NULL,
    migration_state text        NOT NULL DEFAULT 'DISCOVERED',
    dual_run_started_at timestamptz NULL,
    cutover_at timestamptz NULL,
    rollback_deadline_at timestamptz NULL,
    completed_at timestamptz NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    row_version bigint      NOT NULL DEFAULT 1,
    CONSTRAINT pk_federation_migration PRIMARY KEY (id),
    CONSTRAINT uq_federation_migration_operation UNIQUE (operation_id),
    CONSTRAINT fk_federation_migration_source FOREIGN KEY (source_provider_id) REFERENCES federation.identity_provider(id),
    CONSTRAINT fk_federation_migration_target FOREIGN KEY (target_provider_id) REFERENCES federation.identity_provider(id),
    CONSTRAINT ck_federation_migration_provider CHECK (source_provider_id <> target_provider_id),
    CONSTRAINT ck_federation_migration_state CHECK (migration_state IN ('DISCOVERED', 'SHADOW', 'DUAL_RUN', 'CANARY', 'CUTOVER', 'OBSERVING', 'COMPLETE', 'PAUSED', 'ROLLED_BACK'))
);

COMMENT ON TABLE federation.federation_migration IS 'CAP-FED-012/013：身份源双跑、逐用户审计、切换、回滚截止点与完成状态。';

CREATE INDEX ix_external_identity_user ON federation.external_identity(user_id, binding_state);

CREATE INDEX ix_directory_object_apply ON federation.directory_object(directory_connection_id, sync_state, source_sortable_version);

CREATE INDEX ix_fk_directory_connection_identity_provider_id ON federation.directory_connection (identity_provider_id);

CREATE INDEX ix_fk_directory_sync_run_directory_connection_id ON federation.directory_sync_run (directory_connection_id);

CREATE INDEX ix_fk_assertion_replay_identity_provider_id ON federation.assertion_replay (identity_provider_id);

CREATE INDEX ix_fk_federation_migration_source_provider_id ON federation.federation_migration (source_provider_id);

CREATE INDEX ix_fk_federation_migration_target_provider_id ON federation.federation_migration (target_provider_id);

COMMENT ON COLUMN federation.identity_provider.id IS '内部 UUID 主键；仅用于数据库关系，不作为跨域公开标识。';
COMMENT ON COLUMN federation.identity_provider.public_id IS '不可复用的公开稳定标识；插入时登记到 core.public_id_ledger。';
COMMENT ON COLUMN federation.identity_provider.tenant_id IS '租户隔离键；全零 UUID 表示平台范围，应用查询必须显式携带可信租户上下文。';
COMMENT ON COLUMN federation.identity_provider.provider_code IS '稳定机器可读代码；展示文本由资源或目录解析。';
COMMENT ON COLUMN federation.identity_provider.protocol_kind IS '对象类别判别字段；允许值由 CHECK 或对应注册表限定。';
COMMENT ON COLUMN federation.identity_provider.provider_state IS '显式状态当前值；合法取值见 CHECK，完整状态转换由 .NET 领域策略执行。';
COMMENT ON COLUMN federation.identity_provider.issuer_or_entity_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN federation.identity_provider.metadata_source_uri IS '受控 URI；写入前必须执行协议、主机、重定向与 SSRF 安全校验。';
COMMENT ON COLUMN federation.identity_provider.audience_values IS '代码或引用集合；写入前去重、校验 allowlist，并满足表约束。';
COMMENT ON COLUMN federation.identity_provider.callback_uri IS '受控 URI；写入前必须执行协议、主机、重定向与 SSRF 安全校验。';
COMMENT ON COLUMN federation.identity_provider.allowed_algorithms IS '代码或引用集合；写入前去重、校验 allowlist，并满足表约束。';
COMMENT ON COLUMN federation.identity_provider.owner_ref IS '不透明对象引用；不得从格式推断手机号、邮箱或其他业务事实。';
COMMENT ON COLUMN federation.identity_provider.jit_enabled IS '显式布尔开关；启用前置条件与失效行为由约束和版本化策略控制。';
COMMENT ON COLUMN federation.identity_provider.max_clock_skew_seconds IS '以秒为单位的显式时长；有效范围由安全策略及表约束限制。';
COMMENT ON COLUMN federation.identity_provider.metadata_version IS '对象、策略或源数据的显式版本；不得以不可信客户端时间戳替代。';
COMMENT ON COLUMN federation.identity_provider.approval_case_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN federation.identity_provider.activated_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN federation.identity_provider.created_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN federation.identity_provider.updated_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN federation.identity_provider.row_version IS '乐观并发版本；更新必须使用原值 compare-and-set，成功后由数据库单调递增。';
COMMENT ON COLUMN federation.identity_provider.configuration_hash IS '不可逆摘要；用于等值匹配、幂等、完整性或最小化证据，不保存原始敏感值。';
COMMENT ON COLUMN federation.identity_provider.approval_execution_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN federation.identity_provider.last_activation_execution_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN federation.identity_provider_key.id IS '内部 UUID 主键；仅用于数据库关系，不作为跨域公开标识。';
COMMENT ON COLUMN federation.identity_provider_key.identity_provider_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN federation.identity_provider_key.key_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN federation.identity_provider_key.key_kind IS '对象类别判别字段；允许值由 CHECK 或对应注册表限定。';
COMMENT ON COLUMN federation.identity_provider_key.algorithm IS 'federation.identity_provider_key.algorithm 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN federation.identity_provider_key.public_material IS '版本化结构化扩展数据；必须由 .NET 按对应 JSON Schema 校验，不得替代核心状态或外键。';
COMMENT ON COLUMN federation.identity_provider_key.certificate_thumbprint IS 'federation.identity_provider_key.certificate_thumbprint 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN federation.identity_provider_key.key_state IS '显式状态当前值；合法取值见 CHECK，完整状态转换由 .NET 领域策略执行。';
COMMENT ON COLUMN federation.identity_provider_key.not_before IS 'federation.identity_provider_key.not_before 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN federation.identity_provider_key.not_after IS 'federation.identity_provider_key.not_after 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN federation.identity_provider_key.fetched_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN federation.external_identity.id IS '内部 UUID 主键；仅用于数据库关系，不作为跨域公开标识。';
COMMENT ON COLUMN federation.external_identity.public_id IS '不可复用的公开稳定标识；插入时登记到 core.public_id_ledger。';
COMMENT ON COLUMN federation.external_identity.identity_provider_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN federation.external_identity.user_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN federation.external_identity.protocol_kind IS '对象类别判别字段；允许值由 CHECK 或对应注册表限定。';
COMMENT ON COLUMN federation.external_identity.canonical_subject_hash IS '不可逆摘要；用于等值匹配、幂等、完整性或最小化证据，不保存原始敏感值。';
COMMENT ON COLUMN federation.external_identity.canonical_subject_ciphertext IS '随机化加密密文；解密密钥由独立 KMS/HSM 引用管理。';
COMMENT ON COLUMN federation.external_identity.oidc_subject_hash IS '不可逆摘要；用于等值匹配、幂等、完整性或最小化证据，不保存原始敏感值。';
COMMENT ON COLUMN federation.external_identity.saml_name_id_hash IS '不可逆摘要；用于等值匹配、幂等、完整性或最小化证据，不保存原始敏感值。';
COMMENT ON COLUMN federation.external_identity.saml_name_id_format IS 'federation.external_identity.saml_name_id_format 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN federation.external_identity.saml_name_qualifier_hash IS '不可逆摘要；用于等值匹配、幂等、完整性或最小化证据，不保存原始敏感值。';
COMMENT ON COLUMN federation.external_identity.saml_sp_name_qualifier_hash IS '不可逆摘要；用于等值匹配、幂等、完整性或最小化证据，不保存原始敏感值。';
COMMENT ON COLUMN federation.external_identity.saml_sp_provided_id_hash IS '不可逆摘要；用于等值匹配、幂等、完整性或最小化证据，不保存原始敏感值。';
COMMENT ON COLUMN federation.external_identity.saml_is_transient IS 'federation.external_identity.saml_is_transient 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN federation.external_identity.directory_object_id_hash IS '不可逆摘要；用于等值匹配、幂等、完整性或最小化证据，不保存原始敏感值。';
COMMENT ON COLUMN federation.external_identity.binding_state IS '显式状态当前值；合法取值见 CHECK，完整状态转换由 .NET 领域策略执行。';
COMMENT ON COLUMN federation.external_identity.linked_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN federation.external_identity.unlinked_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN federation.external_identity.last_login_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN federation.external_identity.created_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN federation.external_identity.updated_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN federation.external_identity.row_version IS '乐观并发版本；更新必须使用原值 compare-and-set，成功后由数据库单调递增。';
COMMENT ON COLUMN federation.attribute_mapping.id IS '内部 UUID 主键；仅用于数据库关系，不作为跨域公开标识。';
COMMENT ON COLUMN federation.attribute_mapping.identity_provider_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN federation.attribute_mapping.mapping_version IS '对象、策略或源数据的显式版本；不得以不可信客户端时间戳替代。';
COMMENT ON COLUMN federation.attribute_mapping.source_attribute IS 'federation.attribute_mapping.source_attribute 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN federation.attribute_mapping.target_namespace IS 'federation.attribute_mapping.target_namespace 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN federation.attribute_mapping.target_field_code IS '稳定机器可读代码；展示文本由资源或目录解析。';
COMMENT ON COLUMN federation.attribute_mapping.transformation IS '版本化结构化扩展数据；必须由 .NET 按对应 JSON Schema 校验，不得替代核心状态或外键。';
COMMENT ON COLUMN federation.attribute_mapping.value_schema IS '版本化结构化扩展数据；必须由 .NET 按对应 JSON Schema 校验，不得替代核心状态或外键。';
COMMENT ON COLUMN federation.attribute_mapping.maximum_privilege_tier IS 'federation.attribute_mapping.maximum_privilege_tier 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN federation.attribute_mapping.is_active IS '显式布尔开关；启用前置条件与失效行为由约束和版本化策略控制。';
COMMENT ON COLUMN federation.directory_connection.id IS '内部 UUID 主键；仅用于数据库关系，不作为跨域公开标识。';
COMMENT ON COLUMN federation.directory_connection.public_id IS '不可复用的公开稳定标识；插入时登记到 core.public_id_ledger。';
COMMENT ON COLUMN federation.directory_connection.tenant_id IS '租户隔离键；全零 UUID 表示平台范围，应用查询必须显式携带可信租户上下文。';
COMMENT ON COLUMN federation.directory_connection.identity_provider_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN federation.directory_connection.directory_kind IS '对象类别判别字段；允许值由 CHECK 或对应注册表限定。';
COMMENT ON COLUMN federation.directory_connection.connection_state IS '显式状态当前值；合法取值见 CHECK，完整状态转换由 .NET 领域策略执行。';
COMMENT ON COLUMN federation.directory_connection.base_uri IS '受控 URI；写入前必须执行协议、主机、重定向与 SSRF 安全校验。';
COMMENT ON COLUMN federation.directory_connection.credential_key_ref IS '外部 KMS/HSM 或受控密钥资产引用；不得保存私钥或 Secret 明文。';
COMMENT ON COLUMN federation.directory_connection.authority_mode IS 'federation.directory_connection.authority_mode 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN federation.directory_connection.supports_sortable_version IS '对象、策略或源数据的显式版本；不得以不可信客户端时间戳替代。';
COMMENT ON COLUMN federation.directory_connection.owner_ref IS '不透明对象引用；不得从格式推断手机号、邮箱或其他业务事实。';
COMMENT ON COLUMN federation.directory_connection.created_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN federation.directory_connection.updated_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN federation.directory_connection.row_version IS '乐观并发版本；更新必须使用原值 compare-and-set，成功后由数据库单调递增。';
COMMENT ON COLUMN federation.directory_object.id IS '内部 UUID 主键；仅用于数据库关系，不作为跨域公开标识。';
COMMENT ON COLUMN federation.directory_object.directory_connection_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN federation.directory_object.object_kind IS '对象类别判别字段；允许值由 CHECK 或对应注册表限定。';
COMMENT ON COLUMN federation.directory_object.external_object_hash IS '不可逆摘要；用于等值匹配、幂等、完整性或最小化证据，不保存原始敏感值。';
COMMENT ON COLUMN federation.directory_object.platform_object_kind IS '对象类别判别字段；允许值由 CHECK 或对应注册表限定。';
COMMENT ON COLUMN federation.directory_object.platform_object_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN federation.directory_object.source_etag IS 'federation.directory_object.source_etag 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN federation.directory_object.source_sortable_version IS '对象、策略或源数据的显式版本；不得以不可信客户端时间戳替代。';
COMMENT ON COLUMN federation.directory_object.source_modified_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN federation.directory_object.sync_state IS '显式状态当前值；合法取值见 CHECK，完整状态转换由 .NET 领域策略执行。';
COMMENT ON COLUMN federation.directory_object.tombstone_version IS '对象、策略或源数据的显式版本；不得以不可信客户端时间戳替代。';
COMMENT ON COLUMN federation.directory_object.payload_hash IS '不可逆摘要；用于等值匹配、幂等、完整性或最小化证据，不保存原始敏感值。';
COMMENT ON COLUMN federation.directory_object.last_applied_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN federation.directory_object.created_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN federation.directory_object.updated_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN federation.directory_object.row_version IS '乐观并发版本；更新必须使用原值 compare-and-set，成功后由数据库单调递增。';
COMMENT ON COLUMN federation.directory_sync_run.id IS '内部 UUID 主键；仅用于数据库关系，不作为跨域公开标识。';
COMMENT ON COLUMN federation.directory_sync_run.public_id IS '不可复用的公开稳定标识；插入时登记到 core.public_id_ledger。';
COMMENT ON COLUMN federation.directory_sync_run.directory_connection_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN federation.directory_sync_run.operation_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN federation.directory_sync_run.sync_run_state IS '显式状态当前值；合法取值见 CHECK，完整状态转换由 .NET 领域策略执行。';
COMMENT ON COLUMN federation.directory_sync_run.source_cursor IS 'federation.directory_sync_run.source_cursor 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN federation.directory_sync_run.next_cursor IS 'federation.directory_sync_run.next_cursor 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN federation.directory_sync_run.discovered_count IS '非负计数器；并发更新使用原子 SQL 或乐观并发控制。';
COMMENT ON COLUMN federation.directory_sync_run.applied_count IS '非负计数器；并发更新使用原子 SQL 或乐观并发控制。';
COMMENT ON COLUMN federation.directory_sync_run.failed_count IS '非负计数器；并发更新使用原子 SQL 或乐观并发控制。';
COMMENT ON COLUMN federation.directory_sync_run.started_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN federation.directory_sync_run.completed_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN federation.directory_sync_run.created_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN federation.assertion_replay.replay_key_hash IS '不可逆摘要；用于等值匹配、幂等、完整性或最小化证据，不保存原始敏感值。';
COMMENT ON COLUMN federation.assertion_replay.protocol_kind IS '对象类别判别字段；允许值由 CHECK 或对应注册表限定。';
COMMENT ON COLUMN federation.assertion_replay.identity_provider_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN federation.assertion_replay.audience_hash IS '不可逆摘要；用于等值匹配、幂等、完整性或最小化证据，不保存原始敏感值。';
COMMENT ON COLUMN federation.assertion_replay.environment IS 'federation.assertion_replay.environment 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN federation.assertion_replay.first_seen_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN federation.assertion_replay.expires_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN federation.federation_migration.id IS '内部 UUID 主键；仅用于数据库关系，不作为跨域公开标识。';
COMMENT ON COLUMN federation.federation_migration.tenant_id IS '租户隔离键；全零 UUID 表示平台范围，应用查询必须显式携带可信租户上下文。';
COMMENT ON COLUMN federation.federation_migration.source_provider_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN federation.federation_migration.target_provider_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN federation.federation_migration.operation_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN federation.federation_migration.migration_state IS '显式状态当前值；合法取值见 CHECK，完整状态转换由 .NET 领域策略执行。';
COMMENT ON COLUMN federation.federation_migration.dual_run_started_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN federation.federation_migration.cutover_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN federation.federation_migration.rollback_deadline_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN federation.federation_migration.completed_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN federation.federation_migration.created_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN federation.federation_migration.updated_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN federation.federation_migration.row_version IS '乐观并发版本；更新必须使用原值 compare-and-set，成功后由数据库单调递增。';

COMMENT ON CONSTRAINT pk_identity_provider ON federation.identity_provider IS '主键约束：唯一标识 federation.identity_provider 记录。';
COMMENT ON CONSTRAINT uq_identity_provider_public_id ON federation.identity_provider IS '唯一约束：保证 public_id 在 federation.identity_provider 范围内不重复。';
COMMENT ON CONSTRAINT uq_identity_provider_issuer ON federation.identity_provider IS '唯一约束：保证 tenant_id、protocol_kind、issuer_or_entity_id 在 federation.identity_provider 范围内不重复。';
COMMENT ON CONSTRAINT ck_identity_provider_protocol ON federation.identity_provider IS '检查约束：限制 federation.identity_provider 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_identity_provider_state ON federation.identity_provider IS '检查约束：限制 federation.identity_provider 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_identity_provider_audience ON federation.identity_provider IS '检查约束：限制 federation.identity_provider 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_identity_provider_alg ON federation.identity_provider IS '检查约束：限制 federation.identity_provider 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_identity_provider_skew ON federation.identity_provider IS '检查约束：限制 federation.identity_provider 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_identity_provider_configuration_hash ON federation.identity_provider IS '检查约束：限制 federation.identity_provider 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT pk_identity_provider_key ON federation.identity_provider_key IS '主键约束：唯一标识 federation.identity_provider_key 记录。';
COMMENT ON CONSTRAINT uq_identity_provider_key ON federation.identity_provider_key IS '唯一约束：保证 identity_provider_id、key_id、not_before 在 federation.identity_provider_key 范围内不重复。';
COMMENT ON CONSTRAINT fk_identity_provider_key_provider ON federation.identity_provider_key IS '外键约束：federation.identity_provider_key 的 identity_provider_id 必须引用 federation.identity_provider；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT ck_identity_provider_key_kind ON federation.identity_provider_key IS '检查约束：限制 federation.identity_provider_key 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_identity_provider_key_state ON federation.identity_provider_key IS '检查约束：限制 federation.identity_provider_key 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_identity_provider_key_window ON federation.identity_provider_key IS '检查约束：限制 federation.identity_provider_key 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT pk_external_identity ON federation.external_identity IS '主键约束：唯一标识 federation.external_identity 记录。';
COMMENT ON CONSTRAINT uq_external_identity_public_id ON federation.external_identity IS '唯一约束：保证 public_id 在 federation.external_identity 范围内不重复。';
COMMENT ON CONSTRAINT uq_external_identity_subject ON federation.external_identity IS '唯一约束：保证 identity_provider_id、canonical_subject_hash 在 federation.external_identity 范围内不重复。';
COMMENT ON CONSTRAINT fk_external_identity_provider ON federation.external_identity IS '外键约束：federation.external_identity 的 identity_provider_id 必须引用 federation.identity_provider；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT ck_external_identity_protocol ON federation.external_identity IS '检查约束：限制 federation.external_identity 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_external_identity_hash ON federation.external_identity IS '检查约束：限制 federation.external_identity 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_external_identity_protocol_key ON federation.external_identity IS '检查约束：限制 federation.external_identity 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_external_identity_state ON federation.external_identity IS '检查约束：限制 federation.external_identity 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_external_identity_linked ON federation.external_identity IS '检查约束：限制 federation.external_identity 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_external_identity_unlinked ON federation.external_identity IS '检查约束：限制 federation.external_identity 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT pk_attribute_mapping ON federation.attribute_mapping IS '主键约束：唯一标识 federation.attribute_mapping 记录。';
COMMENT ON CONSTRAINT uq_attribute_mapping ON federation.attribute_mapping IS '唯一约束：保证 identity_provider_id、mapping_version、source_attribute、target_namespace、target_field_code 在 federation.attribute_mapping 范围内不重复。';
COMMENT ON CONSTRAINT fk_attribute_mapping_provider ON federation.attribute_mapping IS '外键约束：federation.attribute_mapping 的 identity_provider_id 必须引用 federation.identity_provider；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT ck_attribute_mapping_tier ON federation.attribute_mapping IS '检查约束：限制 federation.attribute_mapping 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT pk_directory_connection ON federation.directory_connection IS '主键约束：唯一标识 federation.directory_connection 记录。';
COMMENT ON CONSTRAINT uq_directory_connection_public_id ON federation.directory_connection IS '唯一约束：保证 public_id 在 federation.directory_connection 范围内不重复。';
COMMENT ON CONSTRAINT fk_directory_connection_provider ON federation.directory_connection IS '外键约束：federation.directory_connection 的 identity_provider_id 必须引用 federation.identity_provider；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT ck_directory_connection_kind ON federation.directory_connection IS '检查约束：限制 federation.directory_connection 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_directory_connection_state ON federation.directory_connection IS '检查约束：限制 federation.directory_connection 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_directory_connection_mode ON federation.directory_connection IS '检查约束：限制 federation.directory_connection 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT pk_directory_object ON federation.directory_object IS '主键约束：唯一标识 federation.directory_object 记录。';
COMMENT ON CONSTRAINT uq_directory_object ON federation.directory_object IS '唯一约束：保证 directory_connection_id、object_kind、external_object_hash 在 federation.directory_object 范围内不重复。';
COMMENT ON CONSTRAINT fk_directory_object_connection ON federation.directory_object IS '外键约束：federation.directory_object 的 directory_connection_id 必须引用 federation.directory_connection；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT ck_directory_object_kind ON federation.directory_object IS '检查约束：限制 federation.directory_object 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_directory_object_platform ON federation.directory_object IS '检查约束：限制 federation.directory_object 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_directory_object_state ON federation.directory_object IS '检查约束：限制 federation.directory_object 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_directory_object_hash ON federation.directory_object IS '检查约束：限制 federation.directory_object 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_directory_object_tombstone ON federation.directory_object IS '检查约束：限制 federation.directory_object 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT pk_directory_sync_run ON federation.directory_sync_run IS '主键约束：唯一标识 federation.directory_sync_run 记录。';
COMMENT ON CONSTRAINT uq_directory_sync_run_public_id ON federation.directory_sync_run IS '唯一约束：保证 public_id 在 federation.directory_sync_run 范围内不重复。';
COMMENT ON CONSTRAINT uq_directory_sync_run_operation ON federation.directory_sync_run IS '唯一约束：保证 operation_id 在 federation.directory_sync_run 范围内不重复。';
COMMENT ON CONSTRAINT fk_directory_sync_run_connection ON federation.directory_sync_run IS '外键约束：federation.directory_sync_run 的 directory_connection_id 必须引用 federation.directory_connection；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT ck_directory_sync_run_state ON federation.directory_sync_run IS '检查约束：限制 federation.directory_sync_run 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_directory_sync_run_count ON federation.directory_sync_run IS '检查约束：限制 federation.directory_sync_run 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT pk_assertion_replay ON federation.assertion_replay IS '主键约束：唯一标识 federation.assertion_replay 记录。';
COMMENT ON CONSTRAINT fk_assertion_replay_provider ON federation.assertion_replay IS '外键约束：federation.assertion_replay 的 identity_provider_id 必须引用 federation.identity_provider；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT ck_assertion_replay_protocol ON federation.assertion_replay IS '检查约束：限制 federation.assertion_replay 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_assertion_replay_hash ON federation.assertion_replay IS '检查约束：限制 federation.assertion_replay 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_assertion_replay_expiry ON federation.assertion_replay IS '检查约束：限制 federation.assertion_replay 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT pk_federation_migration ON federation.federation_migration IS '主键约束：唯一标识 federation.federation_migration 记录。';
COMMENT ON CONSTRAINT uq_federation_migration_operation ON federation.federation_migration IS '唯一约束：保证 operation_id 在 federation.federation_migration 范围内不重复。';
COMMENT ON CONSTRAINT fk_federation_migration_source ON federation.federation_migration IS '外键约束：federation.federation_migration 的 source_provider_id 必须引用 federation.identity_provider；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT fk_federation_migration_target ON federation.federation_migration IS '外键约束：federation.federation_migration 的 target_provider_id 必须引用 federation.identity_provider；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT ck_federation_migration_provider ON federation.federation_migration IS '检查约束：限制 federation.federation_migration 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_federation_migration_state ON federation.federation_migration IS '检查约束：限制 federation.federation_migration 的字段取值或组合满足结构与安全底线。';

COMMENT ON INDEX federation.ix_external_identity_user IS '查询索引：优化 federation.external_identity 按 user_id、binding_state 的访问。';
COMMENT ON INDEX federation.ix_directory_object_apply IS '查询索引：优化 federation.directory_object 按 directory_connection_id、sync_state、source_sortable_version 的访问。';
COMMENT ON INDEX federation.pk_identity_provider IS '约束 pk_identity_provider 的支撑唯一索引。';
COMMENT ON INDEX federation.uq_identity_provider_public_id IS '约束 uq_identity_provider_public_id 的支撑唯一索引。';
COMMENT ON INDEX federation.uq_identity_provider_issuer IS '约束 uq_identity_provider_issuer 的支撑唯一索引。';
COMMENT ON INDEX federation.pk_identity_provider_key IS '约束 pk_identity_provider_key 的支撑唯一索引。';
COMMENT ON INDEX federation.uq_identity_provider_key IS '约束 uq_identity_provider_key 的支撑唯一索引。';
COMMENT ON INDEX federation.pk_external_identity IS '约束 pk_external_identity 的支撑唯一索引。';
COMMENT ON INDEX federation.uq_external_identity_public_id IS '约束 uq_external_identity_public_id 的支撑唯一索引。';
COMMENT ON INDEX federation.uq_external_identity_subject IS '约束 uq_external_identity_subject 的支撑唯一索引。';
COMMENT ON INDEX federation.pk_attribute_mapping IS '约束 pk_attribute_mapping 的支撑唯一索引。';
COMMENT ON INDEX federation.uq_attribute_mapping IS '约束 uq_attribute_mapping 的支撑唯一索引。';
COMMENT ON INDEX federation.pk_directory_connection IS '约束 pk_directory_connection 的支撑唯一索引。';
COMMENT ON INDEX federation.uq_directory_connection_public_id IS '约束 uq_directory_connection_public_id 的支撑唯一索引。';
COMMENT ON INDEX federation.pk_directory_object IS '约束 pk_directory_object 的支撑唯一索引。';
COMMENT ON INDEX federation.uq_directory_object IS '约束 uq_directory_object 的支撑唯一索引。';
COMMENT ON INDEX federation.pk_directory_sync_run IS '约束 pk_directory_sync_run 的支撑唯一索引。';
COMMENT ON INDEX federation.uq_directory_sync_run_public_id IS '约束 uq_directory_sync_run_public_id 的支撑唯一索引。';
COMMENT ON INDEX federation.uq_directory_sync_run_operation IS '约束 uq_directory_sync_run_operation 的支撑唯一索引。';
COMMENT ON INDEX federation.pk_assertion_replay IS '约束 pk_assertion_replay 的支撑唯一索引。';
COMMENT ON INDEX federation.pk_federation_migration IS '约束 pk_federation_migration 的支撑唯一索引。';
COMMENT ON INDEX federation.uq_federation_migration_operation IS '约束 uq_federation_migration_operation 的支撑唯一索引。';
COMMENT ON INDEX federation.ix_fk_directory_connection_identity_provider_id IS '查询索引：优化 federation.directory_connection 按 identity_provider_id 的访问。';
COMMENT ON INDEX federation.ix_fk_directory_sync_run_directory_connection_id IS '查询索引：优化 federation.directory_sync_run 按 directory_connection_id 的访问。';
COMMENT ON INDEX federation.ix_fk_assertion_replay_identity_provider_id IS '查询索引：优化 federation.assertion_replay 按 identity_provider_id 的访问。';
COMMENT ON INDEX federation.ix_fk_federation_migration_source_provider_id IS '查询索引：优化 federation.federation_migration 按 source_provider_id 的访问。';
COMMENT ON INDEX federation.ix_fk_federation_migration_target_provider_id IS '查询索引：优化 federation.federation_migration 按 target_provider_id 的访问。';

