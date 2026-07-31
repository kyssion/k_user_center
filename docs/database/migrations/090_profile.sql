-- =============================================================================
-- 090_profile.sql
-- PROFILE 域：字段元数据、公共资料、敏感属性、业务扩展资料、变更历史、IAL 断言、通知偏好
-- 依据：能力地图 §4.4；蓝图 §11.2（REQ-PRIV-001/002）、§3.5 保证等级
-- 关键：公共资料与业务资料分命名空间与权威域；敏感属性单独加密存储
-- =============================================================================

SET client_min_messages = warning;

-- -----------------------------------------------------------------------------
-- 1. 字段元数据（CAP-PROFILE-005、REQ-PRIV-002）
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS profile.profile_field_metadata (
    field_code          text        NOT NULL,
    namespace           text        NOT NULL DEFAULT 'platform',
    data_type           text        NOT NULL,
    is_required         boolean     NOT NULL DEFAULT false,
    is_unique           boolean     NOT NULL DEFAULT false,
    authority_kind      text        NOT NULL,
    visibility          text        NOT NULL DEFAULT 'OWNER_AND_ADMIN',
    mutability          text        NOT NULL DEFAULT 'READ_WRITE',
    data_classification text        NOT NULL DEFAULT 'INTERNAL',
    requires_encryption boolean     NOT NULL DEFAULT false,
    retention_code      text        NULL,
    purpose_codes       text[]      NOT NULL DEFAULT '{}',
    created_at          timestamptz NOT NULL DEFAULT now(),
    updated_at          timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT pk_profile_field_metadata PRIMARY KEY (namespace, field_code),
    CONSTRAINT fk_profile_field_metadata_classification FOREIGN KEY (data_classification) REFERENCES core.data_classification (classification_code),
    CONSTRAINT ck_profile_field_metadata_type CHECK (data_type IN ('STRING', 'INTEGER', 'BOOLEAN', 'DATE', 'TIMESTAMP', 'ENUM', 'URL', 'JSON')),
    CONSTRAINT ck_profile_field_metadata_authority CHECK (authority_kind IN ('USER', 'ADMIN', 'IDENTITY_PROVIDER', 'SYSTEM', 'BUSINESS_LINE')),
    CONSTRAINT ck_profile_field_metadata_visibility CHECK (visibility IN ('PUBLIC', 'OWNER_ONLY', 'OWNER_AND_ADMIN', 'ADMIN_ONLY', 'INTERNAL_ONLY')),
    CONSTRAINT ck_profile_field_metadata_mutability CHECK (mutability IN ('READ_ONLY', 'READ_WRITE', 'WRITE_ONCE', 'IDP_MANAGED')),
    -- 严格敏感字段必须加密且不得对外公开（CAP-PRIV-005、REQ-KEY-008）
    CONSTRAINT ck_profile_field_metadata_strict CHECK (
        data_classification <> 'STRICT_SENSITIVE' OR (requires_encryption AND visibility <> 'PUBLIC')
    ),
    -- REQ-FED-005 / CAP-PROFILE-006：被身份源接管的字段禁止用户自改
    CONSTRAINT ck_profile_field_metadata_idp CHECK (
        authority_kind <> 'IDENTITY_PROVIDER' OR mutability = 'IDP_MANAGED'
    )
);
COMMENT ON TABLE profile.profile_field_metadata IS 'CAP-PROFILE-005 / REQ-PRIV-002：字段类型、来源、敏感级别、用途、可见性、可改性与保留期的唯一登记处';

CREATE OR REPLACE TRIGGER trg_profile_field_metadata_touch
    BEFORE UPDATE ON profile.profile_field_metadata
    FOR EACH ROW EXECUTE FUNCTION core.fn_touch_updated_at();

-- -----------------------------------------------------------------------------
-- 2. 公共资料（CAP-PROFILE-001、CAP-PROFILE-004）
-- 只放低敏感的通用字段；手机号邮箱在 id.identifier，敏感属性在 sensitive_attribute
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS profile.user_profile (
    user_id           uuid        NOT NULL,
    display_name      text        NULL,
    avatar_object_key text        NULL,
    avatar_state      text        NOT NULL DEFAULT 'NONE',
    locale            text        NULL,
    timezone          text        NULL,
    theme_preference  text        NULL,
    completeness_pct  smallint    NOT NULL DEFAULT 0,
    aggregate_version bigint      NOT NULL DEFAULT 1,
    created_at        timestamptz NOT NULL DEFAULT now(),
    updated_at        timestamptz NOT NULL DEFAULT now(),
    row_version       bigint      NOT NULL DEFAULT 1,
    CONSTRAINT pk_user_profile PRIMARY KEY (user_id),
    CONSTRAINT fk_user_profile_user FOREIGN KEY (user_id) REFERENCES id.global_user (id) ON DELETE CASCADE,
    CONSTRAINT ck_user_profile_avatar_state CHECK (avatar_state IN ('NONE', 'PENDING_REVIEW', 'ACTIVE', 'REJECTED', 'REMOVED')),
    CONSTRAINT ck_user_profile_completeness CHECK (completeness_pct BETWEEN 0 AND 100)
);
COMMENT ON TABLE profile.user_profile IS 'CAP-PROFILE-001 平台公共资料；CAP-PROFILE-004 头像只存对象存储键并经内容安全审核';

CREATE OR REPLACE TRIGGER trg_user_profile_touch
    BEFORE UPDATE ON profile.user_profile
    FOR EACH ROW EXECUTE FUNCTION core.fn_touch_updated_at();

-- 敏感属性（真实姓名、证件号、出生日期等）：随机化加密，不支持检索
CREATE TABLE IF NOT EXISTS profile.sensitive_attribute (
    id                 uuid        NOT NULL DEFAULT core.uuid_generate_v7(),
    user_id            uuid        NOT NULL,
    field_code         text        NOT NULL,
    value_cipher       bytea       NOT NULL,
    value_masked       text        NULL,
    cipher_key_version smallint    NOT NULL,
    source_kind        text        NOT NULL,
    purpose_codes      text[]      NOT NULL DEFAULT '{}',
    retention_until    timestamptz NULL,
    created_at         timestamptz NOT NULL DEFAULT now(),
    updated_at         timestamptz NOT NULL DEFAULT now(),
    row_version        bigint      NOT NULL DEFAULT 1,
    CONSTRAINT pk_sensitive_attribute PRIMARY KEY (id),
    CONSTRAINT uq_sensitive_attribute_field UNIQUE (user_id, field_code),
    CONSTRAINT fk_sensitive_attribute_user FOREIGN KEY (user_id) REFERENCES id.global_user (id) ON DELETE CASCADE,
    CONSTRAINT ck_sensitive_attribute_source CHECK (source_kind IN ('USER', 'ADMIN', 'IDENTITY_PROVIDER', 'VERIFICATION_SERVICE', 'MIGRATION')),
    CONSTRAINT ck_sensitive_attribute_cipher CHECK (octet_length(value_cipher) BETWEEN 16 AND 8192)
);
COMMENT ON TABLE profile.sensitive_attribute IS 'REQ-KEY-008：非检索类敏感字段一律随机化加密且不建盲索引；证件影像等原始材料不入本库（能力地图 §4.4 约束）';

CREATE OR REPLACE TRIGGER trg_sensitive_attribute_touch
    BEFORE UPDATE ON profile.sensitive_attribute
    FOR EACH ROW EXECUTE FUNCTION core.fn_touch_updated_at();

CREATE INDEX IF NOT EXISTS ix_sensitive_attribute_retention ON profile.sensitive_attribute (retention_until) WHERE retention_until IS NOT NULL;

-- -----------------------------------------------------------------------------
-- 3. 业务扩展资料（CAP-PROFILE-003：命名空间与访问边界）
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS profile.business_profile (
    id                uuid        NOT NULL DEFAULT core.uuid_generate_v7(),
    user_id           uuid        NOT NULL,
    business_line_id  uuid        NOT NULL,
    tenant_id         uuid        NOT NULL DEFAULT '00000000-0000-0000-0000-000000000000',
    namespace         text        NOT NULL,
    attributes        jsonb       NOT NULL DEFAULT '{}'::jsonb,
    aggregate_version bigint      NOT NULL DEFAULT 1,
    created_at        timestamptz NOT NULL DEFAULT now(),
    updated_at        timestamptz NOT NULL DEFAULT now(),
    row_version       bigint      NOT NULL DEFAULT 1,
    CONSTRAINT pk_business_profile PRIMARY KEY (id),
    CONSTRAINT uq_business_profile_namespace UNIQUE (user_id, business_line_id, namespace),
    CONSTRAINT fk_business_profile_user FOREIGN KEY (user_id) REFERENCES id.global_user (id) ON DELETE CASCADE,
    CONSTRAINT fk_business_profile_business_line FOREIGN KEY (business_line_id) REFERENCES tenant.business_line (id),
    CONSTRAINT ck_business_profile_namespace CHECK (namespace ~ '^[a-z][a-z0-9_]{1,40}$' AND namespace <> 'platform'),
    CONSTRAINT ck_business_profile_size CHECK (length(attributes::text) <= 65536)
);
COMMENT ON TABLE profile.business_profile IS 'CAP-PROFILE-003：业务私有字段按命名空间隔离；platform 命名空间保留给公共资料，业务不得写入';

CREATE OR REPLACE TRIGGER trg_business_profile_touch
    BEFORE UPDATE ON profile.business_profile
    FOR EACH ROW EXECUTE FUNCTION core.fn_touch_updated_at();

CREATE INDEX IF NOT EXISTS ix_business_profile_user ON profile.business_profile (user_id);
CREATE INDEX IF NOT EXISTS ix_business_profile_attributes ON profile.business_profile USING gin (attributes jsonb_path_ops);

-- -----------------------------------------------------------------------------
-- 4. 资料变更历史（CAP-PROFILE-007，字段级、追加型）
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS profile.profile_change_log (
    id                uuid        NOT NULL DEFAULT core.uuid_generate_v7(),
    user_id           uuid        NOT NULL,
    namespace         text        NOT NULL,
    field_code        text        NOT NULL,
    old_value_masked  text        NULL,
    new_value_masked  text        NULL,
    source_kind       text        NOT NULL,
    actor_kind        text        NOT NULL,
    actor_ref         text        NOT NULL,
    reason            text        NULL,
    changed_at        timestamptz NOT NULL DEFAULT now(),
    trace_id          text        NULL,
    CONSTRAINT pk_profile_change_log PRIMARY KEY (id),
    CONSTRAINT ck_profile_change_log_actor CHECK (actor_kind IN ('USER', 'ADMIN', 'CLIENT', 'SYSTEM', 'IDENTITY_PROVIDER')),
    CONSTRAINT ck_profile_change_log_source CHECK (source_kind IN ('SELF_SERVICE', 'ADMIN_CONSOLE', 'API', 'DIRECTORY_SYNC', 'SYSTEM_COMPUTED', 'MIGRATION'))
);
COMMENT ON TABLE profile.profile_change_log IS 'CAP-PROFILE-007 字段级变更历史；只保留掩码值，完整前后值进 obs.audit_event（INV-G-007）';

CREATE OR REPLACE TRIGGER trg_profile_change_log_append_only
    BEFORE UPDATE OR DELETE ON profile.profile_change_log
    FOR EACH STATEMENT EXECUTE FUNCTION core.fn_append_only();

CREATE INDEX IF NOT EXISTS ix_profile_change_log_user ON profile.profile_change_log (user_id, changed_at DESC);

-- -----------------------------------------------------------------------------
-- 5. 实名核验断言（CAP-PROFILE-011、能力地图 §3.5：断言由平台唯一存储与解释）
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS profile.identity_assurance_assertion (
    id                 uuid        NOT NULL DEFAULT core.uuid_generate_v7(),
    user_id            uuid        NOT NULL,
    ial_level          text        NOT NULL,
    assertion_state    text        NOT NULL DEFAULT 'ACTIVE',
    verified_at        timestamptz NOT NULL,
    expires_at         timestamptz NULL,
    evidence_type      text        NOT NULL,
    verifier_kind      text        NOT NULL,
    verifier_ref       text        NOT NULL,
    evidence_ref       text        NULL,
    region_code        text        NULL,
    superseded_by_id   uuid        NULL,
    revoked_at         timestamptz NULL,
    created_at         timestamptz NOT NULL DEFAULT now(),
    updated_at         timestamptz NOT NULL DEFAULT now(),
    row_version        bigint      NOT NULL DEFAULT 1,
    CONSTRAINT pk_identity_assurance_assertion PRIMARY KEY (id),
    CONSTRAINT fk_identity_assurance_assertion_user FOREIGN KEY (user_id) REFERENCES id.global_user (id) ON DELETE CASCADE,
    CONSTRAINT fk_identity_assurance_assertion_superseded FOREIGN KEY (superseded_by_id) REFERENCES profile.identity_assurance_assertion (id),
    CONSTRAINT ck_identity_assurance_ial CHECK (ial_level IN ('IAL1', 'IAL2', 'IAL3')),
    CONSTRAINT ck_identity_assurance_state CHECK (assertion_state IN ('ACTIVE', 'EXPIRED', 'SUPERSEDED', 'REVOKED')),
    CONSTRAINT ck_identity_assurance_evidence CHECK (evidence_type IN (
        'PHONE_VERIFIED', 'EMAIL_VERIFIED', 'ID_DOCUMENT', 'LIVENESS', 'BANK_CARD_MATCH',
        'CARRIER_MATCH', 'IN_PERSON', 'FEDERATED_ASSERTION'
    )),
    CONSTRAINT ck_identity_assurance_verifier CHECK (verifier_kind IN ('PLATFORM', 'BUSINESS_LINE', 'EXTERNAL_SERVICE', 'IDENTITY_PROVIDER')),
    -- 能力地图 §3.5：手机号已验证不得推断为自然人已实名
    CONSTRAINT ck_identity_assurance_ial1_only CHECK (
        evidence_type NOT IN ('PHONE_VERIFIED', 'EMAIL_VERIFIED') OR ial_level = 'IAL1'
    ),
    CONSTRAINT ck_identity_assurance_revoked CHECK ((assertion_state = 'REVOKED') = (revoked_at IS NOT NULL))
);
COMMENT ON TABLE profile.identity_assurance_assertion IS 'CAP-PROFILE-011：IAL 断言的存储与解释权在平台，核验实施（CAP-PROFILE-012）可外部化；业务不得自行解释 IAL';

CREATE OR REPLACE TRIGGER trg_identity_assurance_assertion_touch
    BEFORE UPDATE ON profile.identity_assurance_assertion
    FOR EACH ROW EXECUTE FUNCTION core.fn_touch_updated_at();

CREATE UNIQUE INDEX IF NOT EXISTS ux_identity_assurance_active
    ON profile.identity_assurance_assertion (user_id)
    WHERE assertion_state = 'ACTIVE';

-- -----------------------------------------------------------------------------
-- 6. 通知偏好（CAP-PROFILE-010、CAP-SSC-011：安全类通知不可完全关闭）
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS profile.notification_preference (
    user_id       uuid        NOT NULL,
    category      text        NOT NULL,
    channel       text        NOT NULL,
    is_enabled    boolean     NOT NULL DEFAULT true,
    updated_at    timestamptz NOT NULL DEFAULT now(),
    updated_via   text        NOT NULL DEFAULT 'SELF_SERVICE',
    CONSTRAINT pk_notification_preference PRIMARY KEY (user_id, category, channel),
    CONSTRAINT fk_notification_preference_user FOREIGN KEY (user_id) REFERENCES id.global_user (id) ON DELETE CASCADE,
    CONSTRAINT ck_notification_preference_category CHECK (category IN ('SECURITY', 'TRANSACTIONAL', 'MARKETING', 'PRODUCT_UPDATE')),
    CONSTRAINT ck_notification_preference_channel CHECK (channel IN ('SMS', 'EMAIL', 'PUSH', 'IN_APP')),
    -- CAP-SSC-011：安全类通知不允许用户完全关闭
    CONSTRAINT ck_notification_preference_security_always_on CHECK (category <> 'SECURITY' OR is_enabled)
);
COMMENT ON TABLE profile.notification_preference IS 'CAP-PROFILE-010 / CAP-SSC-011：营销订阅与安全通知分开建模，安全类不可关闭（数据库层强制）';

SELECT core.fn_apply_standard_grants('profile');
SELECT core.fn_apply_append_only_grants('profile', 'profile_change_log');

SELECT core.fn_migration_apply('090', 'profile：字段元数据、公共资料、敏感属性、业务扩展资料、变更历史、IAL 断言、通知偏好');
