\set ON_ERROR_STOP on

SET ROLE iam_owner;

-- Profile、身份保证、协议、同意和隐私权请求。

CREATE TABLE iam.user_profiles (
    id uuid PRIMARY KEY,
    user_id uuid NOT NULL,
    display_name varchar(200),
    avatar_uri text,
    locale varchar(35),
    timezone varchar(64),
    primary_contact_identifier_id uuid,
    profile_version bigint NOT NULL DEFAULT 0,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    row_version bigint NOT NULL DEFAULT 0,
    CONSTRAINT uq_user_profiles_user UNIQUE (user_id),
    CONSTRAINT ck_user_profiles_versions CHECK (profile_version >= 0 AND row_version >= 0)
);
COMMENT ON TABLE iam.user_profiles IS '用户稳定公共资料；字段可见性、输入净化和对外 Claim 映射由 PROFILE 代码处理。';
COMMENT ON COLUMN iam.user_profiles.id IS '应用生成的 Profile UUIDv7。';
COMMENT ON COLUMN iam.user_profiles.user_id IS '逻辑引用 iam.global_users.id，每个用户最多一条稳定 Profile。';
COMMENT ON COLUMN iam.user_profiles.display_name IS '可空；展示名称，属于个人数据。';
COMMENT ON COLUMN iam.user_profiles.avatar_uri IS '可空；受控头像对象引用，不接受任意主动内容。';
COMMENT ON COLUMN iam.user_profiles.locale IS '可空；BCP 47 语言区域偏好。';
COMMENT ON COLUMN iam.user_profiles.timezone IS '可空；IANA 时区名称。';
COMMENT ON COLUMN iam.user_profiles.primary_contact_identifier_id IS '可空；逻辑引用 iam.identifiers.id；代码校验其属于当前用户、已验证且当前有效绑定。';
COMMENT ON COLUMN iam.user_profiles.profile_version IS '资料语义版本，用于事件和缓存。';
COMMENT ON COLUMN iam.user_profiles.created_at IS '数据库插入时间。';
COMMENT ON COLUMN iam.user_profiles.updated_at IS '数据库更新时间；应用显式刷新。';
COMMENT ON COLUMN iam.user_profiles.row_version IS '乐观锁版本。';

CREATE TABLE iam.profile_documents (
    id uuid PRIMARY KEY,
    user_id uuid NOT NULL,
    namespace varchar(100) NOT NULL,
    scope_type varchar(40) NOT NULL,
    scope_id uuid,
    schema_version integer NOT NULL,
    document_version bigint NOT NULL,
    payload jsonb NOT NULL,
    payload_digest char(64) NOT NULL,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    row_version bigint NOT NULL DEFAULT 0,
    CONSTRAINT uq_profile_document UNIQUE NULLS NOT DISTINCT (user_id, namespace, scope_type, scope_id),
    CONSTRAINT ck_profile_document_versions CHECK (schema_version > 0 AND document_version > 0 AND row_version >= 0)
);
COMMENT ON TABLE iam.profile_documents IS '业务扩展资料、偏好和通知设置的版本化 JSON 文档；Schema、权限和字段级隐私由 PROFILE 代码执行。';
COMMENT ON COLUMN iam.profile_documents.id IS '应用生成的文档 UUIDv7。';
COMMENT ON COLUMN iam.profile_documents.user_id IS '逻辑引用 iam.global_users.id。';
COMMENT ON COLUMN iam.profile_documents.namespace IS '文档命名空间，例如 PREFERENCES、NOTIFICATION_SETTINGS。';
COMMENT ON COLUMN iam.profile_documents.scope_type IS '文档作用域类型。';
COMMENT ON COLUMN iam.profile_documents.scope_id IS '可空；按 scope_type 逻辑引用作用域对象。';
COMMENT ON COLUMN iam.profile_documents.schema_version IS 'JSON Schema 正整数版本。';
COMMENT ON COLUMN iam.profile_documents.document_version IS '文档语义版本。';
COMMENT ON COLUMN iam.profile_documents.payload IS '扩展资料载荷；代码校验 Schema、敏感级别和大小。';
COMMENT ON COLUMN iam.profile_documents.payload_digest IS '规范化载荷 SHA-256 摘要。';
COMMENT ON COLUMN iam.profile_documents.created_at IS '数据库插入时间。';
COMMENT ON COLUMN iam.profile_documents.updated_at IS '数据库更新时间；应用显式刷新。';
COMMENT ON COLUMN iam.profile_documents.row_version IS '乐观锁版本。';

CREATE TABLE iam.identity_assurance_assertions (
    id uuid PRIMARY KEY,
    user_id uuid NOT NULL,
    ial varchar(40) NOT NULL,
    provider_type varchar(40) NOT NULL,
    provider_id uuid,
    evidence_type varchar(80) NOT NULL,
    evidence_digest char(64) NOT NULL,
    state varchar(40) NOT NULL,
    verified_at timestamptz NOT NULL,
    expires_at timestamptz,
    revoked_at timestamptz,
    attributes jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    row_version bigint NOT NULL DEFAULT 0,
    CONSTRAINT ck_assurance_expiry CHECK (expires_at IS NULL OR expires_at > verified_at),
    CONSTRAINT ck_assurance_version CHECK (row_version >= 0)
);
COMMENT ON TABLE iam.identity_assurance_assertions IS '身份核验断言及证据摘要；等级映射、复核和撤销由 ID/PROFILE 代码处理。';
COMMENT ON COLUMN iam.identity_assurance_assertions.id IS '应用生成的断言 UUIDv7。';
COMMENT ON COLUMN iam.identity_assurance_assertions.user_id IS '逻辑引用 iam.global_users.id。';
COMMENT ON COLUMN iam.identity_assurance_assertions.ial IS '身份保证等级快照。';
COMMENT ON COLUMN iam.identity_assurance_assertions.provider_type IS '核验提供者类型。';
COMMENT ON COLUMN iam.identity_assurance_assertions.provider_id IS '可空；逻辑引用身份提供者、应用或外部服务登记。';
COMMENT ON COLUMN iam.identity_assurance_assertions.evidence_type IS '证据类型代码。';
COMMENT ON COLUMN iam.identity_assurance_assertions.evidence_digest IS '受控证据包规范化摘要，不保存证件原文。';
COMMENT ON COLUMN iam.identity_assurance_assertions.state IS '断言状态。';
COMMENT ON COLUMN iam.identity_assurance_assertions.verified_at IS '核验完成时间。';
COMMENT ON COLUMN iam.identity_assurance_assertions.expires_at IS '可空；断言过期时间。';
COMMENT ON COLUMN iam.identity_assurance_assertions.revoked_at IS '可空；断言撤销时间。';
COMMENT ON COLUMN iam.identity_assurance_assertions.attributes IS '脱敏核验属性；代码白名单控制。';
COMMENT ON COLUMN iam.identity_assurance_assertions.created_at IS '数据库插入时间。';
COMMENT ON COLUMN iam.identity_assurance_assertions.row_version IS '乐观锁版本。';

CREATE TABLE iam.agreement_versions (
    id uuid PRIMARY KEY,
    agreement_type varchar(80) NOT NULL,
    region_code varchar(20) NOT NULL,
    version integer NOT NULL,
    content_uri text NOT NULL,
    content_digest char(64) NOT NULL,
    state varchar(40) NOT NULL,
    published_at timestamptz,
    effective_at timestamptz,
    retired_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT uq_agreement_version UNIQUE (agreement_type, region_code, version),
    CONSTRAINT ck_agreement_version CHECK (version > 0)
);
COMMENT ON TABLE iam.agreement_versions IS '服务协议和隐私政策的不可变版本元数据；适用性和重新接受判断由 PRIV 代码处理。';
COMMENT ON COLUMN iam.agreement_versions.id IS '应用生成的协议版本 UUIDv7。';
COMMENT ON COLUMN iam.agreement_versions.agreement_type IS '协议类型代码。';
COMMENT ON COLUMN iam.agreement_versions.region_code IS '适用地区代码。';
COMMENT ON COLUMN iam.agreement_versions.version IS '同类型和地区内正整数版本。';
COMMENT ON COLUMN iam.agreement_versions.content_uri IS '不可变协议内容对象引用。';
COMMENT ON COLUMN iam.agreement_versions.content_digest IS '协议内容 SHA-256 摘要。';
COMMENT ON COLUMN iam.agreement_versions.state IS '发布状态。';
COMMENT ON COLUMN iam.agreement_versions.published_at IS '可空；发布时间。';
COMMENT ON COLUMN iam.agreement_versions.effective_at IS '可空；生效时间。';
COMMENT ON COLUMN iam.agreement_versions.retired_at IS '可空；停止用于新接受的时间。';
COMMENT ON COLUMN iam.agreement_versions.created_at IS '数据库插入时间。';

CREATE TABLE iam.agreement_acceptances (
    id uuid PRIMARY KEY,
    user_id uuid NOT NULL,
    agreement_version_id uuid NOT NULL,
    source varchar(80) NOT NULL,
    evidence_digest char(64) NOT NULL,
    source_ip inet,
    user_agent_digest varchar(128),
    accepted_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT uq_agreement_acceptance UNIQUE (user_id, agreement_version_id)
);
COMMENT ON TABLE iam.agreement_acceptances IS '用户接受特定协议版本的不可变证据。';
COMMENT ON COLUMN iam.agreement_acceptances.id IS '应用生成的接受记录 UUIDv7。';
COMMENT ON COLUMN iam.agreement_acceptances.user_id IS '逻辑引用 iam.global_users.id。';
COMMENT ON COLUMN iam.agreement_acceptances.agreement_version_id IS '逻辑引用 iam.agreement_versions.id。';
COMMENT ON COLUMN iam.agreement_acceptances.source IS '接受入口或渠道代码。';
COMMENT ON COLUMN iam.agreement_acceptances.evidence_digest IS '接受证据包规范化摘要。';
COMMENT ON COLUMN iam.agreement_acceptances.source_ip IS '可空；接受来源 IP，属于受限个人数据。';
COMMENT ON COLUMN iam.agreement_acceptances.user_agent_digest IS '可空；User-Agent 摘要。';
COMMENT ON COLUMN iam.agreement_acceptances.accepted_at IS '用户明确接受业务时间。';
COMMENT ON COLUMN iam.agreement_acceptances.created_at IS '数据库插入时间。';

CREATE TABLE iam.consent_aggregates (
    id uuid PRIMARY KEY,
    subject_type varchar(40) NOT NULL,
    subject_id uuid NOT NULL,
    purpose_code varchar(100) NOT NULL,
    category_set_digest char(64) NOT NULL,
    recipient_type varchar(40) NOT NULL,
    recipient_id uuid NOT NULL,
    consent_epoch bigint NOT NULL DEFAULT 0,
    current_consent_id uuid,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    row_version bigint NOT NULL DEFAULT 0,
    CONSTRAINT uq_consent_aggregate UNIQUE (subject_type, subject_id, purpose_code, category_set_digest, recipient_type, recipient_id),
    CONSTRAINT ck_consent_aggregate_versions CHECK (consent_epoch >= 0 AND row_version >= 0)
);
COMMENT ON TABLE iam.consent_aggregates IS '同一主体、目的、数据类别集合和接收方的 Consent 聚合及撤销水位。';
COMMENT ON COLUMN iam.consent_aggregates.id IS '应用生成的 Consent 聚合 UUIDv7。';
COMMENT ON COLUMN iam.consent_aggregates.subject_type IS '同意主体类型。';
COMMENT ON COLUMN iam.consent_aggregates.subject_id IS '主体逻辑 ID。';
COMMENT ON COLUMN iam.consent_aggregates.purpose_code IS '处理目的稳定代码。';
COMMENT ON COLUMN iam.consent_aggregates.category_set_digest IS '规范化数据类别集合摘要。';
COMMENT ON COLUMN iam.consent_aggregates.recipient_type IS '数据接收方类型。';
COMMENT ON COLUMN iam.consent_aggregates.recipient_id IS '接收方逻辑 ID。';
COMMENT ON COLUMN iam.consent_aggregates.consent_epoch IS 'Consent 安全水位；撤回或范围收缩时由代码递增。';
COMMENT ON COLUMN iam.consent_aggregates.current_consent_id IS '可空；逻辑引用当前 iam.consents.id。';
COMMENT ON COLUMN iam.consent_aggregates.created_at IS '数据库插入时间。';
COMMENT ON COLUMN iam.consent_aggregates.updated_at IS '数据库更新时间；应用显式刷新。';
COMMENT ON COLUMN iam.consent_aggregates.row_version IS '乐观锁版本。';

CREATE TABLE iam.consents (
    id uuid PRIMARY KEY,
    aggregate_id uuid NOT NULL,
    version bigint NOT NULL,
    state varchar(40) NOT NULL,
    scope_snapshot text[] NOT NULL DEFAULT ARRAY[]::text[],
    category_snapshot jsonb NOT NULL,
    evidence_digest char(64) NOT NULL,
    policy_version_id uuid,
    granted_at timestamptz,
    withdrawn_at timestamptz,
    expires_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT uq_consents_version UNIQUE (aggregate_id, version),
    CONSTRAINT ck_consents_version CHECK (version > 0)
);
COMMENT ON TABLE iam.consents IS 'Consent 不可变版本事实；有效性、范围包含和撤回传播由 PRIV/OAP 代码判断。';
COMMENT ON COLUMN iam.consents.id IS '应用生成的 Consent UUIDv7。';
COMMENT ON COLUMN iam.consents.aggregate_id IS '逻辑引用 iam.consent_aggregates.id。';
COMMENT ON COLUMN iam.consents.version IS '聚合内单调正整数版本。';
COMMENT ON COLUMN iam.consents.state IS 'Consent 版本状态。';
COMMENT ON COLUMN iam.consents.scope_snapshot IS '授权 Scope 快照。';
COMMENT ON COLUMN iam.consents.category_snapshot IS '数据类别和用途快照。';
COMMENT ON COLUMN iam.consents.evidence_digest IS '同意证据包摘要。';
COMMENT ON COLUMN iam.consents.policy_version_id IS '可空；逻辑引用 iam.policy_versions.id。';
COMMENT ON COLUMN iam.consents.granted_at IS '可空；明确同意时间。';
COMMENT ON COLUMN iam.consents.withdrawn_at IS '可空；撤回时间。';
COMMENT ON COLUMN iam.consents.expires_at IS '可空；同意过期时间。';
COMMENT ON COLUMN iam.consents.created_at IS '数据库插入时间。';

CREATE TABLE iam.privacy_requests (
    id uuid PRIMARY KEY,
    user_id uuid NOT NULL,
    agent_type varchar(40),
    agent_id uuid,
    request_type varchar(40) NOT NULL,
    operation_id uuid NOT NULL,
    state varchar(40) NOT NULL,
    identity_verification_id uuid,
    deadline_at timestamptz NOT NULL,
    result_summary jsonb,
    rejection_reason varchar(100),
    submitted_at timestamptz NOT NULL,
    completed_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    row_version bigint NOT NULL DEFAULT 0,
    CONSTRAINT uq_privacy_request_operation UNIQUE (operation_id),
    CONSTRAINT ck_privacy_request_deadline CHECK (deadline_at > submitted_at),
    CONSTRAINT ck_privacy_request_version CHECK (row_version >= 0)
);
COMMENT ON TABLE iam.privacy_requests IS '访问、更正、导出、删除等数据主体权利请求；身份核验、期限、编排和例外由 PRIV 代码处理。';
COMMENT ON COLUMN iam.privacy_requests.id IS '应用生成的隐私请求 UUIDv7。';
COMMENT ON COLUMN iam.privacy_requests.user_id IS '逻辑引用 iam.global_users.id。';
COMMENT ON COLUMN iam.privacy_requests.agent_type IS '可空；代理请求人类型。';
COMMENT ON COLUMN iam.privacy_requests.agent_id IS '可空；代理请求人逻辑 ID。';
COMMENT ON COLUMN iam.privacy_requests.request_type IS '权利请求类型。';
COMMENT ON COLUMN iam.privacy_requests.operation_id IS '逻辑引用 iam.operations.id，用于跨系统编排。';
COMMENT ON COLUMN iam.privacy_requests.state IS '请求状态；由 PRIV 状态机维护。';
COMMENT ON COLUMN iam.privacy_requests.identity_verification_id IS '可空；逻辑引用 iam.identity_assurance_assertions.id。';
COMMENT ON COLUMN iam.privacy_requests.deadline_at IS '法定或策略处理截止时间。';
COMMENT ON COLUMN iam.privacy_requests.result_summary IS '可空；脱敏处理结果摘要。';
COMMENT ON COLUMN iam.privacy_requests.rejection_reason IS '可空；稳定拒绝原因码。';
COMMENT ON COLUMN iam.privacy_requests.submitted_at IS '请求提交业务时间。';
COMMENT ON COLUMN iam.privacy_requests.completed_at IS '可空；处理完成时间。';
COMMENT ON COLUMN iam.privacy_requests.created_at IS '数据库插入时间。';
COMMENT ON COLUMN iam.privacy_requests.updated_at IS '数据库更新时间；应用显式刷新。';
COMMENT ON COLUMN iam.privacy_requests.row_version IS '乐观锁版本。';

CREATE TABLE iam.legal_holds (
    id uuid PRIMARY KEY,
    target_type varchar(40) NOT NULL,
    target_id uuid NOT NULL,
    basis_code varchar(100) NOT NULL,
    scope_snapshot jsonb NOT NULL,
    approver_type varchar(40) NOT NULL,
    approver_id uuid NOT NULL,
    state varchar(40) NOT NULL,
    effective_at timestamptz NOT NULL,
    expires_at timestamptz,
    released_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    row_version bigint NOT NULL DEFAULT 0,
    CONSTRAINT ck_legal_hold_expiry CHECK (expires_at IS NULL OR expires_at > effective_at),
    CONSTRAINT ck_legal_hold_version CHECK (row_version >= 0)
);
COMMENT ON TABLE iam.legal_holds IS '法律保留事实；适用范围、授权和解除由 PRIV/CTRL 代码决定。';
COMMENT ON COLUMN iam.legal_holds.id IS '应用生成的 Legal Hold UUIDv7。';
COMMENT ON COLUMN iam.legal_holds.target_type IS '保留目标类型。';
COMMENT ON COLUMN iam.legal_holds.target_id IS '保留目标逻辑 ID。';
COMMENT ON COLUMN iam.legal_holds.basis_code IS '法律或合规依据代码。';
COMMENT ON COLUMN iam.legal_holds.scope_snapshot IS '受保留数据范围快照。';
COMMENT ON COLUMN iam.legal_holds.approver_type IS '批准者类型。';
COMMENT ON COLUMN iam.legal_holds.approver_id IS '批准者逻辑 ID。';
COMMENT ON COLUMN iam.legal_holds.state IS '保留状态。';
COMMENT ON COLUMN iam.legal_holds.effective_at IS '保留生效时间。';
COMMENT ON COLUMN iam.legal_holds.expires_at IS '可空；计划失效时间。';
COMMENT ON COLUMN iam.legal_holds.released_at IS '可空；实际解除时间。';
COMMENT ON COLUMN iam.legal_holds.created_at IS '数据库插入时间。';
COMMENT ON COLUMN iam.legal_holds.updated_at IS '数据库更新时间；应用显式刷新。';
COMMENT ON COLUMN iam.legal_holds.row_version IS '乐观锁版本。';

CREATE TABLE iam.data_export_artifacts (
    id uuid PRIMARY KEY,
    privacy_request_id uuid NOT NULL,
    object_storage_ref text NOT NULL,
    key_id uuid NOT NULL,
    content_digest char(64) NOT NULL,
    format varchar(40) NOT NULL,
    size_bytes bigint NOT NULL,
    state varchar(40) NOT NULL,
    expires_at timestamptz NOT NULL,
    downloaded_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT ck_export_artifact_size CHECK (size_bytes >= 0),
    CONSTRAINT ck_export_artifact_expiry CHECK (expires_at > created_at)
);
COMMENT ON TABLE iam.data_export_artifacts IS '隐私数据导出文件元数据；文件位于加密对象存储，下载鉴权和销毁由 PRIV 代码处理。';
COMMENT ON COLUMN iam.data_export_artifacts.id IS '应用生成的导出物 UUIDv7。';
COMMENT ON COLUMN iam.data_export_artifacts.privacy_request_id IS '逻辑引用 iam.privacy_requests.id。';
COMMENT ON COLUMN iam.data_export_artifacts.object_storage_ref IS '受控对象存储引用，不是公开 URL。';
COMMENT ON COLUMN iam.data_export_artifacts.key_id IS '逻辑引用 iam.cryptographic_keys.id 或 KMS Key 元数据。';
COMMENT ON COLUMN iam.data_export_artifacts.content_digest IS '导出文件 SHA-256 摘要。';
COMMENT ON COLUMN iam.data_export_artifacts.format IS '导出格式代码。';
COMMENT ON COLUMN iam.data_export_artifacts.size_bytes IS '文件非负字节数。';
COMMENT ON COLUMN iam.data_export_artifacts.state IS '导出物状态。';
COMMENT ON COLUMN iam.data_export_artifacts.expires_at IS '下载和保留过期时间。';
COMMENT ON COLUMN iam.data_export_artifacts.downloaded_at IS '可空；首次成功下载时间。';
COMMENT ON COLUMN iam.data_export_artifacts.created_at IS '数据库插入时间。';

CREATE TABLE iam.deletion_proofs (
    id uuid PRIMARY KEY,
    privacy_request_id uuid NOT NULL,
    system_code varchar(100) NOT NULL,
    result varchar(40) NOT NULL,
    deleted_item_count bigint NOT NULL DEFAULT 0,
    retained_items jsonb NOT NULL DEFAULT '[]'::jsonb,
    evidence_digest char(64) NOT NULL,
    completed_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT uq_deletion_proof_system UNIQUE (privacy_request_id, system_code),
    CONSTRAINT ck_deletion_proof_count CHECK (deleted_item_count >= 0)
);
COMMENT ON TABLE iam.deletion_proofs IS '各系统删除、匿名化或依法保留的不可变证明。';
COMMENT ON COLUMN iam.deletion_proofs.id IS '应用生成的证明 UUIDv7。';
COMMENT ON COLUMN iam.deletion_proofs.privacy_request_id IS '逻辑引用 iam.privacy_requests.id。';
COMMENT ON COLUMN iam.deletion_proofs.system_code IS '处理系统稳定代码。';
COMMENT ON COLUMN iam.deletion_proofs.result IS '处理结果代码。';
COMMENT ON COLUMN iam.deletion_proofs.deleted_item_count IS '删除或匿名化对象数量。';
COMMENT ON COLUMN iam.deletion_proofs.retained_items IS '依法保留的数据类别和依据，不保存原始内容。';
COMMENT ON COLUMN iam.deletion_proofs.evidence_digest IS '处理证据包 SHA-256 摘要。';
COMMENT ON COLUMN iam.deletion_proofs.completed_at IS '该系统处理完成时间。';
COMMENT ON COLUMN iam.deletion_proofs.created_at IS '数据库插入时间。';

CREATE INDEX ix_profile_documents_user ON iam.profile_documents (user_id, namespace);
CREATE INDEX ix_user_profiles_primary_contact ON iam.user_profiles (primary_contact_identifier_id) WHERE primary_contact_identifier_id IS NOT NULL;
CREATE INDEX ix_assurance_user ON iam.identity_assurance_assertions (user_id, state, expires_at);
CREATE INDEX ix_consents_aggregate ON iam.consents (aggregate_id, version DESC);
CREATE INDEX ix_privacy_requests_user ON iam.privacy_requests (user_id, state, submitted_at DESC);
CREATE INDEX ix_privacy_requests_deadline ON iam.privacy_requests (state, deadline_at);
CREATE INDEX ix_legal_holds_target ON iam.legal_holds (target_type, target_id, state);
COMMENT ON INDEX iam.ix_privacy_requests_deadline IS '隐私处理器按状态和法定截止时间查询待办。';
COMMENT ON INDEX iam.ix_user_profiles_primary_contact IS '从 Identifier 反查将其设为主联系方式的 Profile。';
