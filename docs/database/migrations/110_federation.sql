-- =============================================================================
-- 110_federation.sql
-- FED 域：身份源登记、身份源密钥、外部身份绑定、属性映射、目录同步状态
-- 依据：能力地图 §4.7、§5.12；蓝图 §10.5（REQ-FED-001 至 008）、INV-G-004
-- 关键：外部身份必须使用协议专用稳定键；transient NameID 不得持久链接
-- =============================================================================

SET client_min_messages = warning;

-- -----------------------------------------------------------------------------
-- 1. 身份源登记（CAP-FED-004：可信度、可达 IAL/AAL、属性权威度、负责人）
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fed.identity_provider (
    id                    uuid        NOT NULL DEFAULT core.uuid_generate_v7(),
    public_id             text        NOT NULL,
    tenant_id             uuid        NOT NULL DEFAULT '00000000-0000-0000-0000-000000000000',
    business_line_id      uuid        NULL,
    protocol              text        NOT NULL,
    display_name          text        NOT NULL,
    provider_state        text        NOT NULL DEFAULT 'DRAFT',
    health_state          text        NOT NULL DEFAULT 'UNKNOWN',
    -- OIDC 使用 issuer；SAML 使用 entity_id（INV-G-004 / REQ-ID-004）
    issuer                text        NULL,
    entity_id             text        NULL,
    metadata_source_uri   text        NULL,
    metadata_fetched_at   timestamptz NULL,
    audience_value        text        NULL,
    allowed_algorithms    text[]      NOT NULL DEFAULT '{}',
    max_reachable_ial     text        NOT NULL DEFAULT 'IAL1',
    max_reachable_aal     text        NOT NULL DEFAULT 'AAL1',
    max_reachable_fal     text        NOT NULL DEFAULT 'FAL1',
    trust_level           text        NOT NULL DEFAULT 'LOW',
    unique_key_kind       text        NOT NULL,
    allows_jit_provision  boolean     NOT NULL DEFAULT false,
    requires_directory_sync boolean   NOT NULL DEFAULT false,
    degradation_mode      text        NOT NULL DEFAULT 'FAIL_CLOSED',
    owner_ref             text        NOT NULL,
    migration_of_id       uuid        NULL,
    security_exception_ref text       NULL,
    created_at            timestamptz NOT NULL DEFAULT now(),
    updated_at            timestamptz NOT NULL DEFAULT now(),
    row_version           bigint      NOT NULL DEFAULT 1,
    CONSTRAINT pk_identity_provider PRIMARY KEY (id),
    CONSTRAINT uq_identity_provider_public_id UNIQUE (public_id),
    CONSTRAINT fk_identity_provider_migration FOREIGN KEY (migration_of_id) REFERENCES fed.identity_provider (id),
    CONSTRAINT ck_identity_provider_protocol CHECK (protocol IN ('OIDC', 'SAML2', 'OAUTH2_SOCIAL', 'WECHAT_OPEN', 'APPLE', 'LDAP', 'SCIM_ONLY')),
    CONSTRAINT ck_identity_provider_state CHECK (provider_state IN ('DRAFT', 'ACTIVE', 'SUSPENDED', 'READ_ONLY_OBSERVING', 'RETIRED')),
    CONSTRAINT ck_identity_provider_health CHECK (health_state IN ('UNKNOWN', 'HEALTHY', 'DEGRADED', 'CIRCUIT_OPEN')),
    CONSTRAINT ck_identity_provider_ial CHECK (max_reachable_ial IN ('IAL1', 'IAL2', 'IAL3')),
    CONSTRAINT ck_identity_provider_aal CHECK (max_reachable_aal IN ('AAL1', 'AAL2', 'AAL3')),
    CONSTRAINT ck_identity_provider_fal CHECK (max_reachable_fal IN ('FAL1', 'FAL2', 'FAL3')),
    CONSTRAINT ck_identity_provider_trust CHECK (trust_level IN ('LOW', 'MEDIUM', 'HIGH')),
    -- CAP-FED-015：唯一键作用域必须在登记时明确（微信 openid 仅应用内唯一）
    CONSTRAINT ck_identity_provider_key_kind CHECK (unique_key_kind IN (
        'OIDC_ISSUER_SUB', 'SAML_ENTITY_NAMEID', 'PLATFORM_UNIONID', 'PLATFORM_OPENID', 'DIRECTORY_EXTERNAL_ID'
    )),
    -- REQ-FED-001：OIDC 必须有 issuer，SAML 必须有 entity_id
    CONSTRAINT ck_identity_provider_identifier CHECK (
        (protocol = 'SAML2' AND entity_id IS NOT NULL) OR (protocol <> 'SAML2' AND issuer IS NOT NULL)
    ),
    -- CAP-FED-011：降级行为必须预先登记，不得运行时临时决定
    CONSTRAINT ck_identity_provider_degradation CHECK (degradation_mode IN ('FAIL_CLOSED', 'ALLOW_EXISTING_SESSION')),
    -- CAP-FED-006：JIT 必须配合目录同步或已验证域名，避免产生孤儿身份
    CONSTRAINT ck_identity_provider_jit CHECK (NOT allows_jit_provision OR trust_level <> 'LOW')
);
COMMENT ON TABLE fed.identity_provider IS 'CAP-FED-004：未登记可达保证等级的身份源不得用于敏感操作，也不得声明高于其实际能力的 acr';
COMMENT ON COLUMN fed.identity_provider.unique_key_kind IS 'CAP-FED-015：openid 仅单应用内唯一，跨应用识别必须使用 unionid；未取得 unionid 时不得跨应用合并主体';
COMMENT ON COLUMN fed.identity_provider.migration_of_id IS '能力地图 §5.12：外部主键不可变的唯一例外是登记在册的身份源迁移，须走 CAP-CTRL-006 例外登记';

CREATE OR REPLACE TRIGGER trg_identity_provider_touch
    BEFORE UPDATE ON fed.identity_provider
    FOR EACH ROW EXECUTE FUNCTION core.fn_touch_updated_at();
CREATE OR REPLACE TRIGGER trg_identity_provider_public_id
    BEFORE INSERT ON fed.identity_provider
    FOR EACH ROW EXECUTE FUNCTION core.fn_register_public_id('IDENTITY_PROVIDER');

CREATE UNIQUE INDEX IF NOT EXISTS ux_identity_provider_issuer
    ON fed.identity_provider (tenant_id, issuer) WHERE issuer IS NOT NULL AND provider_state <> 'RETIRED';
CREATE UNIQUE INDEX IF NOT EXISTS ux_identity_provider_entity
    ON fed.identity_provider (tenant_id, entity_id) WHERE entity_id IS NOT NULL AND provider_state <> 'RETIRED';

-- 身份源密钥（REQ-FED-003：受控双版本窗口，拉取失败不得接受未知密钥或弱算法）
CREATE TABLE IF NOT EXISTS fed.idp_key (
    id                 uuid        NOT NULL DEFAULT core.uuid_generate_v7(),
    idp_id             uuid        NOT NULL,
    key_id             text        NULL,
    key_state          text        NOT NULL DEFAULT 'ACTIVE',
    public_jwk         jsonb       NULL,
    certificate_pem    text        NULL,
    thumbprint_s256    bytea       NULL,
    algorithm          text        NOT NULL,
    not_before         timestamptz NOT NULL DEFAULT now(),
    not_after          timestamptz NULL,
    first_seen_at      timestamptz NOT NULL DEFAULT now(),
    retired_at         timestamptz NULL,
    CONSTRAINT pk_idp_key PRIMARY KEY (id),
    CONSTRAINT uq_idp_key UNIQUE (idp_id, key_id, thumbprint_s256),
    CONSTRAINT fk_idp_key_provider FOREIGN KEY (idp_id) REFERENCES fed.identity_provider (id) ON DELETE CASCADE,
    CONSTRAINT ck_idp_key_state CHECK (key_state IN ('ACTIVE', 'GRACE', 'RETIRED', 'REJECTED')),
    CONSTRAINT ck_idp_key_material CHECK (public_jwk IS NOT NULL OR certificate_pem IS NOT NULL),
    -- CAP-OAP-006：禁止 none 与弱算法
    CONSTRAINT ck_idp_key_algorithm CHECK (algorithm NOT IN ('none', 'HS256', 'RSA1_5'))
);
COMMENT ON TABLE fed.idp_key IS 'REQ-FED-003：身份源密钥与证书的双版本窗口；REJECTED 用于记录被拒的未知密钥以便告警';

-- -----------------------------------------------------------------------------
-- 2. 外部身份绑定（CAP-ID-007、CAP-FED-001/010、INV-G-004）
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fed.external_identity (
    id                       uuid        NOT NULL DEFAULT core.uuid_generate_v7(),
    user_id                  uuid        NOT NULL,
    idp_id                   uuid        NOT NULL,
    external_key_kind        text        NOT NULL,
    external_key_hash        bytea       NOT NULL,
    external_key_cipher      bytea       NOT NULL,
    cipher_key_version       smallint    NOT NULL,
    blind_index_key_version  smallint    NOT NULL,
    is_persistent_key        boolean     NOT NULL DEFAULT true,
    link_state               text        NOT NULL DEFAULT 'LINKED',
    link_evidence_kind       text        NOT NULL,
    subject_display_masked   text        NULL,
    needs_reauthorization    boolean     NOT NULL DEFAULT false,
    external_tenant_ref      text        NULL,
    linked_at                timestamptz NOT NULL DEFAULT now(),
    last_authenticated_at    timestamptz NULL,
    unlinked_at              timestamptz NULL,
    unlink_reason_code       text        NULL,
    rebound_from_idp_id      uuid        NULL,
    created_at               timestamptz NOT NULL DEFAULT now(),
    updated_at               timestamptz NOT NULL DEFAULT now(),
    row_version              bigint      NOT NULL DEFAULT 1,
    CONSTRAINT pk_external_identity PRIMARY KEY (id),
    CONSTRAINT fk_external_identity_user FOREIGN KEY (user_id) REFERENCES id.global_user (id),
    CONSTRAINT fk_external_identity_provider FOREIGN KEY (idp_id) REFERENCES fed.identity_provider (id),
    CONSTRAINT ck_external_identity_key_kind CHECK (external_key_kind IN (
        'OIDC_ISSUER_SUB', 'SAML_ENTITY_NAMEID', 'PLATFORM_UNIONID', 'PLATFORM_OPENID', 'DIRECTORY_EXTERNAL_ID'
    )),
    CONSTRAINT ck_external_identity_state CHECK (link_state IN ('LINKED', 'NEEDS_REAUTH', 'UNLINKED', 'REJECTED')),
    -- REQ-ID-004 / INV-G-004：不得仅凭邮箱静默关联
    CONSTRAINT ck_external_identity_evidence CHECK (link_evidence_kind IN (
        'FIRST_PARTY_LOGIN', 'VERIFIED_IDENTIFIER_PLUS_IDP_ASSERTION', 'DIRECTORY_SYNC', 'ADMIN_APPROVED', 'MIGRATION_REBIND'
    )),
    -- INV-G-004：transient NameID 不得作为永久账号键
    CONSTRAINT ck_external_identity_persistent CHECK (is_persistent_key),
    CONSTRAINT ck_external_identity_hash CHECK (octet_length(external_key_hash) = 32),
    CONSTRAINT ck_external_identity_unlinked CHECK ((link_state = 'UNLINKED') = (unlinked_at IS NOT NULL)),
    CONSTRAINT ck_external_identity_reauth CHECK (needs_reauthorization = (link_state = 'NEEDS_REAUTH'))
);
COMMENT ON TABLE fed.external_identity IS 'CAP-ID-007 / INV-G-004：外部身份按协议专用稳定键唯一关联；相同邮箱不同稳定键不得静默合并（AT-ID-003）';
COMMENT ON COLUMN fed.external_identity.external_key_cipher IS '外部主键原值随机化加密存储；等值查找只用 external_key_hash（REQ-KEY-008）';
COMMENT ON COLUMN fed.external_identity.needs_reauthorization IS 'CAP-FED-014：第三方 Token 失效或授权被撤回时进入需重新授权，不得静默视为正常也不得自动解绑';

CREATE UNIQUE INDEX IF NOT EXISTS ux_external_identity_key
    ON fed.external_identity (idp_id, external_key_hash)
    WHERE link_state IN ('LINKED', 'NEEDS_REAUTH');

CREATE INDEX IF NOT EXISTS ix_external_identity_user ON fed.external_identity (user_id, link_state);
CREATE INDEX IF NOT EXISTS ix_external_identity_lookup ON fed.external_identity (external_key_hash);

CREATE OR REPLACE TRIGGER trg_external_identity_touch
    BEFORE UPDATE ON fed.external_identity
    FOR EACH ROW EXECUTE FUNCTION core.fn_touch_updated_at();

-- -----------------------------------------------------------------------------
-- 3. 属性映射（CAP-FED-008、REQ-FED-005：逐字段权威方 + 权限上限）
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fed.attribute_mapping (
    id                  uuid        NOT NULL DEFAULT core.uuid_generate_v7(),
    idp_id              uuid        NOT NULL,
    mapping_version     integer     NOT NULL DEFAULT 1,
    external_attribute  text        NOT NULL,
    target_namespace    text        NOT NULL DEFAULT 'platform',
    target_field_code   text        NOT NULL,
    transform_kind      text        NOT NULL DEFAULT 'DIRECT',
    transform_config    jsonb       NULL,
    is_authoritative    boolean     NOT NULL DEFAULT false,
    max_granted_role_id uuid        NULL,
    is_active           boolean     NOT NULL DEFAULT true,
    created_at          timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT pk_attribute_mapping PRIMARY KEY (id),
    CONSTRAINT uq_attribute_mapping UNIQUE (idp_id, mapping_version, external_attribute, target_field_code),
    CONSTRAINT fk_attribute_mapping_provider FOREIGN KEY (idp_id) REFERENCES fed.identity_provider (id) ON DELETE CASCADE,
    CONSTRAINT fk_attribute_mapping_max_role FOREIGN KEY (max_granted_role_id) REFERENCES authz.role (id),
    CONSTRAINT ck_attribute_mapping_transform CHECK (transform_kind IN ('DIRECT', 'LOOKUP', 'REGEX', 'CONSTANT', 'ROLE_MAP', 'ORG_MAP'))
);
COMMENT ON TABLE fed.attribute_mapping IS 'CAP-FED-008 / REQ-FED-005：被身份源接管的字段禁止用户自改，未接管的字段禁止同步覆写；max_granted_role_id 限定外部属性可映射的最高权限（AT-FED-005）';

CREATE UNIQUE INDEX IF NOT EXISTS ux_attribute_mapping_active_field
    ON fed.attribute_mapping (idp_id, target_namespace, target_field_code)
    WHERE is_active AND is_authoritative;

-- -----------------------------------------------------------------------------
-- 4. 目录同步状态（CAP-FED-007/009、REQ-FED-006/007：源端单调版本 + 停用墓碑）
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fed.directory_sync_state (
    id                    uuid        NOT NULL DEFAULT core.uuid_generate_v7(),
    idp_id                uuid        NOT NULL,
    tenant_id             uuid        NOT NULL,
    resource_type         text        NOT NULL,
    external_ref          text        NOT NULL,
    local_ref             uuid        NULL,
    source_version        bigint      NOT NULL,
    source_etag           text        NULL,
    sync_state            text        NOT NULL DEFAULT 'ACTIVE',
    is_deactivation_tombstone boolean NOT NULL DEFAULT false,
    deactivated_at        timestamptz NULL,
    last_synced_at        timestamptz NOT NULL DEFAULT now(),
    last_payload_hash     bytea       NULL,
    updated_at            timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT pk_directory_sync_state PRIMARY KEY (id),
    CONSTRAINT uq_directory_sync_state UNIQUE (idp_id, resource_type, external_ref),
    CONSTRAINT fk_directory_sync_state_provider FOREIGN KEY (idp_id) REFERENCES fed.identity_provider (id) ON DELETE CASCADE,
    CONSTRAINT ck_directory_sync_state_resource CHECK (resource_type IN ('USER', 'GROUP', 'ORGANIZATION')),
    CONSTRAINT ck_directory_sync_state_state CHECK (sync_state IN ('ACTIVE', 'DEACTIVATED', 'CONFLICT', 'MANUAL')),
    CONSTRAINT ck_directory_sync_state_version CHECK (source_version >= 0),
    -- REQ-FED-007：停用墓碑优先级高于旧更新
    CONSTRAINT ck_directory_sync_state_tombstone CHECK (
        is_deactivation_tombstone = (sync_state = 'DEACTIVATED')
        AND (NOT is_deactivation_tombstone OR deactivated_at IS NOT NULL)
    )
);
COMMENT ON TABLE fed.directory_sync_state IS 'REQ-FED-006/007：只按源端单调版本或 ETag 拒绝旧状态覆盖；时间戳仅用于诊断（AT-FED-004）';

CREATE OR REPLACE TRIGGER trg_directory_sync_state_touch
    BEFORE UPDATE ON fed.directory_sync_state
    FOR EACH ROW EXECUTE FUNCTION core.fn_touch_updated_at();

-- 源版本单调：拒绝乱序 SCIM 更新回退版本号
CREATE OR REPLACE TRIGGER trg_directory_sync_state_version
    BEFORE UPDATE ON fed.directory_sync_state
    FOR EACH ROW EXECUTE FUNCTION core.fn_forbid_epoch_decrease('source_version');

CREATE INDEX IF NOT EXISTS ix_directory_sync_state_tenant ON fed.directory_sync_state (tenant_id, resource_type, sync_state);

SELECT core.fn_apply_standard_grants('fed');

SELECT core.fn_migration_apply('110', 'federation：身份源登记、身份源密钥、外部身份绑定、属性映射、目录同步状态');
