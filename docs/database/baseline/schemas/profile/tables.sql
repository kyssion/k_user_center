-- =============================================================================
-- baseline/schemas/profile/tables.sql
-- profile Schema 的最终基表、同 Schema 约束、索引及内联 COMMENT
-- PostgreSQL 16+；应用技术栈：.NET 10 + SqlSugar
-- =============================================================================

CREATE TABLE profile.field_definition (
    field_code text        NOT NULL,
    namespace_code text        NOT NULL,
    schema_version integer     NOT NULL,
    value_type text        NOT NULL,
    authority_domain text        NOT NULL,
    classification_code text        NOT NULL,
    purpose_codes text[]      NOT NULL,
    visibility_rule jsonb       NOT NULL,
    mutability_rule jsonb       NOT NULL,
    retention_policy_code text        NOT NULL,
    validation_schema jsonb       NOT NULL,
    is_active boolean     NOT NULL DEFAULT true,
    CONSTRAINT pk_field_definition PRIMARY KEY (namespace_code, field_code, schema_version),
    CONSTRAINT ck_field_definition_type CHECK (value_type IN ('STRING', 'NUMBER', 'BOOLEAN', 'DATE', 'DATETIME', 'OBJECT', 'ARRAY', 'ENCRYPTED'))
);

COMMENT ON TABLE profile.field_definition IS 'REQ-PRIV-002：Profile 字段的命名空间、类型、权威方、分类、用途、可见/可改与保留元数据。';

CREATE TABLE profile.user_profile (
    user_id uuid        NOT NULL,
    display_name text        NULL,
    avatar_uri text        NULL,
    locale text        NOT NULL DEFAULT 'zh-CN',
    time_zone text        NOT NULL DEFAULT 'Asia/Shanghai',
    profile_version bigint      NOT NULL DEFAULT 1,
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    row_version bigint      NOT NULL DEFAULT 1,
    CONSTRAINT pk_user_profile PRIMARY KEY (user_id),
    CONSTRAINT ck_user_profile_version CHECK (profile_version >= 1)
);

COMMENT ON TABLE profile.user_profile IS 'CAP-PROFILE-001/003：Global User 的最小公共资料；业务事实与业务扩展字段不进入本表。';

CREATE TABLE profile.sensitive_attribute (
    id uuid        NOT NULL DEFAULT gen_random_uuid(),
    user_id uuid        NOT NULL,
    namespace_code text        NOT NULL,
    field_code text        NOT NULL,
    field_schema_version integer     NOT NULL,
    encrypted_value bytea       NOT NULL,
    encryption_key_ref text        NOT NULL,
    value_hash bytea       NULL,
    source_kind text        NOT NULL,
    valid_from timestamptz NOT NULL DEFAULT clock_timestamp(),
    valid_until timestamptz NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    row_version bigint      NOT NULL DEFAULT 1,
    CONSTRAINT pk_sensitive_attribute PRIMARY KEY (id),
    CONSTRAINT uq_sensitive_attribute UNIQUE (user_id, namespace_code, field_code),
    CONSTRAINT fk_sensitive_attribute_definition FOREIGN KEY (namespace_code, field_code, field_schema_version) REFERENCES profile.field_definition(namespace_code, field_code, schema_version),
    CONSTRAINT ck_sensitive_attribute_source CHECK (source_kind IN ('USER', 'VERIFIED_SOURCE', 'TENANT', 'MIGRATION')),
    CONSTRAINT ck_sensitive_attribute_window CHECK (valid_until IS NULL OR valid_until > valid_from)
);

COMMENT ON TABLE profile.sensitive_attribute IS 'CAP-PROFILE-004/005：随机化加密保存的敏感扩展属性；不支持模糊或前缀检索。';

CREATE TABLE profile.business_profile (
    id uuid        NOT NULL DEFAULT gen_random_uuid(),
    membership_id uuid        NOT NULL,
    namespace_code text        NOT NULL,
    field_code text        NOT NULL,
    field_schema_version integer     NOT NULL,
    value_json jsonb       NULL,
    encrypted_value bytea       NULL,
    encryption_key_ref text        NULL,
    authority_domain text        NOT NULL,
    value_version bigint      NOT NULL DEFAULT 1,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    row_version bigint      NOT NULL DEFAULT 1,
    CONSTRAINT pk_business_profile PRIMARY KEY (id),
    CONSTRAINT uq_business_profile UNIQUE (membership_id, namespace_code, field_code),
    CONSTRAINT fk_business_profile_definition FOREIGN KEY (namespace_code, field_code, field_schema_version) REFERENCES profile.field_definition(namespace_code, field_code, schema_version),
    CONSTRAINT ck_business_profile_value CHECK (num_nonnulls(value_json, encrypted_value) = 1),
    CONSTRAINT ck_business_profile_key CHECK ((encrypted_value IS NULL) = (encryption_key_ref IS NULL)),
    CONSTRAINT ck_business_profile_version CHECK (value_version >= 1)
);

COMMENT ON TABLE profile.business_profile IS 'REQ-PRIV-001：按 Membership 隔离的业务扩展资料，受字段定义的权威域与可改规则约束。';

CREATE TABLE profile.profile_change (
    id uuid        NOT NULL DEFAULT gen_random_uuid(),
    user_id uuid        NULL,
    membership_id uuid        NULL,
    namespace_code text        NOT NULL,
    field_code text        NOT NULL,
    old_value_hash bytea       NULL,
    new_value_hash bytea       NULL,
    actor_kind text        NOT NULL,
    actor_ref text        NOT NULL,
    source_version bigint      NOT NULL,
    trace_id text        NULL,
    changed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT pk_profile_change PRIMARY KEY (id),
    CONSTRAINT ck_profile_change_subject CHECK (num_nonnulls(user_id, membership_id) = 1),
    CONSTRAINT ck_profile_change_actor CHECK (actor_kind IN ('USER', 'ADMIN', 'TENANT_ADMIN', 'SYSTEM', 'DIRECTORY')),
    CONSTRAINT ck_profile_change_version CHECK (source_version >= 1)
);

COMMENT ON TABLE profile.profile_change IS 'CAP-PROFILE-007 / CAP-EVENT-007：Profile 变更的版本、摘要、操作者和事件重放依据。';

CREATE TABLE profile.user_preference (
    id uuid        NOT NULL DEFAULT gen_random_uuid(),
    user_id uuid        NOT NULL,
    preference_namespace text        NOT NULL,
    preference_key text        NOT NULL,
    preference_value jsonb       NOT NULL,
    value_schema_version integer     NOT NULL,
    source_kind text        NOT NULL DEFAULT 'USER',
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    row_version bigint      NOT NULL DEFAULT 1,
    CONSTRAINT pk_user_preference PRIMARY KEY (id),
    CONSTRAINT uq_user_preference UNIQUE (user_id, preference_namespace, preference_key),
    CONSTRAINT ck_user_preference_namespace CHECK (preference_namespace ~ '^[a-z][a-z0-9_.-]{1,63}$'),
    CONSTRAINT ck_user_preference_key CHECK (preference_key ~ '^[a-z][a-z0-9_.-]{1,63}$'),
    CONSTRAINT ck_user_preference_source CHECK (source_kind IN ('USER', 'SYSTEM_DEFAULT', 'TENANT_POLICY')),
    CONSTRAINT ck_user_preference_version CHECK (value_schema_version >= 1)
);

COMMENT ON TABLE profile.user_preference IS 'CAP-PROFILE-009：主题、语言、时区和其他非安全偏好的命名空间键值；安全约束不得被偏好覆盖。';

CREATE TABLE profile.notification_preference (
    id uuid        NOT NULL DEFAULT gen_random_uuid(),
    user_id uuid        NOT NULL,
    notification_category text        NOT NULL,
    channel_code text        NOT NULL,
    preference_state text        NOT NULL DEFAULT 'ENABLED',
    mandatory boolean     NOT NULL DEFAULT false,
    quiet_hours jsonb       NULL,
    consent_id uuid        NULL,
    consent_epoch bigint      NULL,
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    row_version bigint      NOT NULL DEFAULT 1,
    CONSTRAINT pk_notification_preference PRIMARY KEY (id),
    CONSTRAINT uq_notification_preference UNIQUE (user_id, notification_category, channel_code),
    CONSTRAINT ck_notification_preference_category CHECK (notification_category IN ('SECURITY', 'TRANSACTIONAL', 'SERVICE', 'MARKETING')),
    CONSTRAINT ck_notification_preference_channel CHECK (channel_code IN ('SMS', 'EMAIL', 'PUSH', 'IN_APP', 'VOICE')),
    CONSTRAINT ck_notification_preference_state CHECK (preference_state IN ('ENABLED', 'DISABLED', 'SUPPRESSED')),
    CONSTRAINT ck_notification_preference_mandatory CHECK (NOT mandatory OR preference_state = 'ENABLED'),
    CONSTRAINT ck_notification_preference_consent CHECK (
    (consent_id IS NULL AND consent_epoch IS NULL) OR (consent_id IS NOT NULL AND consent_epoch IS NOT NULL)
    )
);

COMMENT ON TABLE profile.notification_preference IS 'CAP-PROFILE-010 / CAP-SSC-011：事务、安全、服务与营销通知分离；强制安全通知不可完全关闭。';

CREATE INDEX ix_fk_sensitive_attribute_namespace_code_field_code_fi_5f1f5dcf ON profile.sensitive_attribute (namespace_code, field_code, field_schema_version);

CREATE INDEX ix_fk_business_profile_namespace_code_field_code_field_5b36bf75 ON profile.business_profile (namespace_code, field_code, field_schema_version);

COMMENT ON COLUMN profile.field_definition.field_code IS '稳定机器可读代码；展示文本由资源或目录解析。';
COMMENT ON COLUMN profile.field_definition.namespace_code IS '稳定机器可读代码；展示文本由资源或目录解析。';
COMMENT ON COLUMN profile.field_definition.schema_version IS '对象、策略或源数据的显式版本；不得以不可信客户端时间戳替代。';
COMMENT ON COLUMN profile.field_definition.value_type IS '对象类别判别字段；允许值由 CHECK 或对应注册表限定。';
COMMENT ON COLUMN profile.field_definition.authority_domain IS 'profile.field_definition.authority_domain 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN profile.field_definition.classification_code IS '稳定机器可读代码；展示文本由资源或目录解析。';
COMMENT ON COLUMN profile.field_definition.purpose_codes IS '代码或引用集合；写入前去重、校验 allowlist，并满足表约束。';
COMMENT ON COLUMN profile.field_definition.visibility_rule IS '版本化结构化扩展数据；必须由 .NET 按对应 JSON Schema 校验，不得替代核心状态或外键。';
COMMENT ON COLUMN profile.field_definition.mutability_rule IS '版本化结构化扩展数据；必须由 .NET 按对应 JSON Schema 校验，不得替代核心状态或外键。';
COMMENT ON COLUMN profile.field_definition.retention_policy_code IS '稳定机器可读代码；展示文本由资源或目录解析。';
COMMENT ON COLUMN profile.field_definition.validation_schema IS '版本化结构化扩展数据；必须由 .NET 按对应 JSON Schema 校验，不得替代核心状态或外键。';
COMMENT ON COLUMN profile.field_definition.is_active IS '显式布尔开关；启用前置条件与失效行为由约束和版本化策略控制。';
COMMENT ON COLUMN profile.user_profile.user_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN profile.user_profile.display_name IS 'profile.user_profile.display_name 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN profile.user_profile.avatar_uri IS '受控 URI；写入前必须执行协议、主机、重定向与 SSRF 安全校验。';
COMMENT ON COLUMN profile.user_profile.locale IS 'profile.user_profile.locale 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN profile.user_profile.time_zone IS 'profile.user_profile.time_zone 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN profile.user_profile.profile_version IS '对象、策略或源数据的显式版本；不得以不可信客户端时间戳替代。';
COMMENT ON COLUMN profile.user_profile.updated_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN profile.user_profile.row_version IS '乐观并发版本；更新必须使用原值 compare-and-set，成功后由数据库单调递增。';
COMMENT ON COLUMN profile.sensitive_attribute.id IS '内部 UUID 主键；仅用于数据库关系，不作为跨域公开标识。';
COMMENT ON COLUMN profile.sensitive_attribute.user_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN profile.sensitive_attribute.namespace_code IS '稳定机器可读代码；展示文本由资源或目录解析。';
COMMENT ON COLUMN profile.sensitive_attribute.field_code IS '稳定机器可读代码；展示文本由资源或目录解析。';
COMMENT ON COLUMN profile.sensitive_attribute.field_schema_version IS '对象、策略或源数据的显式版本；不得以不可信客户端时间戳替代。';
COMMENT ON COLUMN profile.sensitive_attribute.encrypted_value IS '随机化加密密文；解密密钥由独立 KMS/HSM 引用管理。';
COMMENT ON COLUMN profile.sensitive_attribute.encryption_key_ref IS '外部 KMS/HSM 或受控密钥资产引用；不得保存私钥或 Secret 明文。';
COMMENT ON COLUMN profile.sensitive_attribute.value_hash IS '不可逆摘要；用于等值匹配、幂等、完整性或最小化证据，不保存原始敏感值。';
COMMENT ON COLUMN profile.sensitive_attribute.source_kind IS '对象类别判别字段；允许值由 CHECK 或对应注册表限定。';
COMMENT ON COLUMN profile.sensitive_attribute.valid_from IS 'profile.sensitive_attribute.valid_from 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN profile.sensitive_attribute.valid_until IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN profile.sensitive_attribute.created_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN profile.sensitive_attribute.updated_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN profile.sensitive_attribute.row_version IS '乐观并发版本；更新必须使用原值 compare-and-set，成功后由数据库单调递增。';
COMMENT ON COLUMN profile.business_profile.id IS '内部 UUID 主键；仅用于数据库关系，不作为跨域公开标识。';
COMMENT ON COLUMN profile.business_profile.membership_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN profile.business_profile.namespace_code IS '稳定机器可读代码；展示文本由资源或目录解析。';
COMMENT ON COLUMN profile.business_profile.field_code IS '稳定机器可读代码；展示文本由资源或目录解析。';
COMMENT ON COLUMN profile.business_profile.field_schema_version IS '对象、策略或源数据的显式版本；不得以不可信客户端时间戳替代。';
COMMENT ON COLUMN profile.business_profile.value_json IS '版本化结构化扩展数据；必须由 .NET 按对应 JSON Schema 校验，不得替代核心状态或外键。';
COMMENT ON COLUMN profile.business_profile.encrypted_value IS '随机化加密密文；解密密钥由独立 KMS/HSM 引用管理。';
COMMENT ON COLUMN profile.business_profile.encryption_key_ref IS '外部 KMS/HSM 或受控密钥资产引用；不得保存私钥或 Secret 明文。';
COMMENT ON COLUMN profile.business_profile.authority_domain IS 'profile.business_profile.authority_domain 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN profile.business_profile.value_version IS '对象、策略或源数据的显式版本；不得以不可信客户端时间戳替代。';
COMMENT ON COLUMN profile.business_profile.created_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN profile.business_profile.updated_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN profile.business_profile.row_version IS '乐观并发版本；更新必须使用原值 compare-and-set，成功后由数据库单调递增。';
COMMENT ON COLUMN profile.profile_change.id IS '内部 UUID 主键；仅用于数据库关系，不作为跨域公开标识。';
COMMENT ON COLUMN profile.profile_change.user_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN profile.profile_change.membership_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN profile.profile_change.namespace_code IS '稳定机器可读代码；展示文本由资源或目录解析。';
COMMENT ON COLUMN profile.profile_change.field_code IS '稳定机器可读代码；展示文本由资源或目录解析。';
COMMENT ON COLUMN profile.profile_change.old_value_hash IS '不可逆摘要；用于等值匹配、幂等、完整性或最小化证据，不保存原始敏感值。';
COMMENT ON COLUMN profile.profile_change.new_value_hash IS '不可逆摘要；用于等值匹配、幂等、完整性或最小化证据，不保存原始敏感值。';
COMMENT ON COLUMN profile.profile_change.actor_kind IS '对象类别判别字段；允许值由 CHECK 或对应注册表限定。';
COMMENT ON COLUMN profile.profile_change.actor_ref IS '不透明对象引用；不得从格式推断手机号、邮箱或其他业务事实。';
COMMENT ON COLUMN profile.profile_change.source_version IS '对象、策略或源数据的显式版本；不得以不可信客户端时间戳替代。';
COMMENT ON COLUMN profile.profile_change.trace_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN profile.profile_change.changed_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN profile.user_preference.id IS '内部 UUID 主键；仅用于数据库关系，不作为跨域公开标识。';
COMMENT ON COLUMN profile.user_preference.user_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN profile.user_preference.preference_namespace IS 'profile.user_preference.preference_namespace 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN profile.user_preference.preference_key IS 'profile.user_preference.preference_key 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN profile.user_preference.preference_value IS '版本化结构化扩展数据；必须由 .NET 按对应 JSON Schema 校验，不得替代核心状态或外键。';
COMMENT ON COLUMN profile.user_preference.value_schema_version IS '对象、策略或源数据的显式版本；不得以不可信客户端时间戳替代。';
COMMENT ON COLUMN profile.user_preference.source_kind IS '对象类别判别字段；允许值由 CHECK 或对应注册表限定。';
COMMENT ON COLUMN profile.user_preference.updated_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN profile.user_preference.row_version IS '乐观并发版本；更新必须使用原值 compare-and-set，成功后由数据库单调递增。';
COMMENT ON COLUMN profile.notification_preference.id IS '内部 UUID 主键；仅用于数据库关系，不作为跨域公开标识。';
COMMENT ON COLUMN profile.notification_preference.user_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN profile.notification_preference.notification_category IS 'profile.notification_preference.notification_category 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN profile.notification_preference.channel_code IS '稳定机器可读代码；展示文本由资源或目录解析。';
COMMENT ON COLUMN profile.notification_preference.preference_state IS '显式状态当前值；合法取值见 CHECK，完整状态转换由 .NET 领域策略执行。';
COMMENT ON COLUMN profile.notification_preference.mandatory IS 'profile.notification_preference.mandatory 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN profile.notification_preference.quiet_hours IS '版本化结构化扩展数据；必须由 .NET 按对应 JSON Schema 校验，不得替代核心状态或外键。';
COMMENT ON COLUMN profile.notification_preference.consent_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN profile.notification_preference.consent_epoch IS '安全或同意水位版本；只能单调递增，用于令牌、缓存与撤销新鲜度校验。';
COMMENT ON COLUMN profile.notification_preference.updated_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN profile.notification_preference.row_version IS '乐观并发版本；更新必须使用原值 compare-and-set，成功后由数据库单调递增。';

COMMENT ON CONSTRAINT pk_field_definition ON profile.field_definition IS '主键约束：唯一标识 profile.field_definition 记录。';
COMMENT ON CONSTRAINT ck_field_definition_type ON profile.field_definition IS '检查约束：限制 profile.field_definition 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT pk_user_profile ON profile.user_profile IS '主键约束：唯一标识 profile.user_profile 记录。';
COMMENT ON CONSTRAINT ck_user_profile_version ON profile.user_profile IS '检查约束：限制 profile.user_profile 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT pk_sensitive_attribute ON profile.sensitive_attribute IS '主键约束：唯一标识 profile.sensitive_attribute 记录。';
COMMENT ON CONSTRAINT uq_sensitive_attribute ON profile.sensitive_attribute IS '唯一约束：保证 user_id、namespace_code、field_code 在 profile.sensitive_attribute 范围内不重复。';
COMMENT ON CONSTRAINT fk_sensitive_attribute_definition ON profile.sensitive_attribute IS '外键约束：profile.sensitive_attribute 的 namespace_code、field_code、field_schema_version 必须引用 profile.field_definition；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT ck_sensitive_attribute_source ON profile.sensitive_attribute IS '检查约束：限制 profile.sensitive_attribute 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_sensitive_attribute_window ON profile.sensitive_attribute IS '检查约束：限制 profile.sensitive_attribute 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT pk_business_profile ON profile.business_profile IS '主键约束：唯一标识 profile.business_profile 记录。';
COMMENT ON CONSTRAINT uq_business_profile ON profile.business_profile IS '唯一约束：保证 membership_id、namespace_code、field_code 在 profile.business_profile 范围内不重复。';
COMMENT ON CONSTRAINT fk_business_profile_definition ON profile.business_profile IS '外键约束：profile.business_profile 的 namespace_code、field_code、field_schema_version 必须引用 profile.field_definition；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT ck_business_profile_value ON profile.business_profile IS '检查约束：限制 profile.business_profile 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_business_profile_key ON profile.business_profile IS '检查约束：限制 profile.business_profile 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_business_profile_version ON profile.business_profile IS '检查约束：限制 profile.business_profile 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT pk_profile_change ON profile.profile_change IS '主键约束：唯一标识 profile.profile_change 记录。';
COMMENT ON CONSTRAINT ck_profile_change_subject ON profile.profile_change IS '检查约束：限制 profile.profile_change 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_profile_change_actor ON profile.profile_change IS '检查约束：限制 profile.profile_change 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_profile_change_version ON profile.profile_change IS '检查约束：限制 profile.profile_change 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT pk_user_preference ON profile.user_preference IS '主键约束：唯一标识 profile.user_preference 记录。';
COMMENT ON CONSTRAINT uq_user_preference ON profile.user_preference IS '唯一约束：保证 user_id、preference_namespace、preference_key 在 profile.user_preference 范围内不重复。';
COMMENT ON CONSTRAINT ck_user_preference_namespace ON profile.user_preference IS '检查约束：限制 profile.user_preference 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_user_preference_key ON profile.user_preference IS '检查约束：限制 profile.user_preference 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_user_preference_source ON profile.user_preference IS '检查约束：限制 profile.user_preference 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_user_preference_version ON profile.user_preference IS '检查约束：限制 profile.user_preference 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT pk_notification_preference ON profile.notification_preference IS '主键约束：唯一标识 profile.notification_preference 记录。';
COMMENT ON CONSTRAINT uq_notification_preference ON profile.notification_preference IS '唯一约束：保证 user_id、notification_category、channel_code 在 profile.notification_preference 范围内不重复。';
COMMENT ON CONSTRAINT ck_notification_preference_category ON profile.notification_preference IS '检查约束：限制 profile.notification_preference 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_notification_preference_channel ON profile.notification_preference IS '检查约束：限制 profile.notification_preference 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_notification_preference_state ON profile.notification_preference IS '检查约束：限制 profile.notification_preference 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_notification_preference_mandatory ON profile.notification_preference IS '检查约束：限制 profile.notification_preference 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_notification_preference_consent ON profile.notification_preference IS '检查约束：限制 profile.notification_preference 的字段取值或组合满足结构与安全底线。';

COMMENT ON INDEX profile.pk_field_definition IS '约束 pk_field_definition 的支撑唯一索引。';
COMMENT ON INDEX profile.pk_user_profile IS '约束 pk_user_profile 的支撑唯一索引。';
COMMENT ON INDEX profile.pk_sensitive_attribute IS '约束 pk_sensitive_attribute 的支撑唯一索引。';
COMMENT ON INDEX profile.uq_sensitive_attribute IS '约束 uq_sensitive_attribute 的支撑唯一索引。';
COMMENT ON INDEX profile.pk_business_profile IS '约束 pk_business_profile 的支撑唯一索引。';
COMMENT ON INDEX profile.uq_business_profile IS '约束 uq_business_profile 的支撑唯一索引。';
COMMENT ON INDEX profile.pk_profile_change IS '约束 pk_profile_change 的支撑唯一索引。';
COMMENT ON INDEX profile.pk_user_preference IS '约束 pk_user_preference 的支撑唯一索引。';
COMMENT ON INDEX profile.uq_user_preference IS '约束 uq_user_preference 的支撑唯一索引。';
COMMENT ON INDEX profile.pk_notification_preference IS '约束 pk_notification_preference 的支撑唯一索引。';
COMMENT ON INDEX profile.uq_notification_preference IS '约束 uq_notification_preference 的支撑唯一索引。';
COMMENT ON INDEX profile.ix_fk_sensitive_attribute_namespace_code_field_code_fi_5f1f5dcf IS '查询索引：优化 profile.sensitive_attribute 按 namespace_code、field_code、field_schema_version 的访问。';
COMMENT ON INDEX profile.ix_fk_business_profile_namespace_code_field_code_field_5b36bf75 IS '查询索引：优化 profile.business_profile 按 namespace_code、field_code、field_schema_version 的访问。';

