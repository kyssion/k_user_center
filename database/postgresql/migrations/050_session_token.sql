\set ON_ERROR_STOP on

SET ROLE iam_owner;

-- 设备、会话、授权 Grant 与 Token 元数据。Token 原文永不落库。

CREATE TABLE iam.devices (
    id uuid PRIMARY KEY,
    user_id uuid NOT NULL,
    device_public_id varchar(96) NOT NULL,
    fingerprint varchar(256),
    lifecycle_state varchar(40) NOT NULL,
    trust_state varchar(40) NOT NULL,
    loss_state varchar(40) NOT NULL,
    display_name varchar(160),
    platform varchar(80),
    first_seen_at timestamptz NOT NULL,
    last_seen_at timestamptz,
    metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    row_version bigint NOT NULL DEFAULT 0,
    CONSTRAINT uq_devices_public UNIQUE (device_public_id),
    CONSTRAINT ck_devices_version CHECK (row_version >= 0)
);
COMMENT ON TABLE iam.devices IS '跨会话设备实体；指纹只作风险信号，信任、挂失和生命周期由 SESSION/RISK 代码维护。';
COMMENT ON COLUMN iam.devices.id IS '应用生成的设备 UUIDv7。';
COMMENT ON COLUMN iam.devices.user_id IS '逻辑引用 iam.global_users.id。';
COMMENT ON COLUMN iam.devices.device_public_id IS '不可推断设备公开标识。';
COMMENT ON COLUMN iam.devices.fingerprint IS '可空；设备不可逆指纹，属于受限安全数据。';
COMMENT ON COLUMN iam.devices.lifecycle_state IS '设备生命周期状态。';
COMMENT ON COLUMN iam.devices.trust_state IS '设备信任状态；由风险和用户操作共同决定。';
COMMENT ON COLUMN iam.devices.loss_state IS '设备挂失状态。';
COMMENT ON COLUMN iam.devices.display_name IS '可空；用户可识别设备名称。';
COMMENT ON COLUMN iam.devices.platform IS '可空；平台或设备类别。';
COMMENT ON COLUMN iam.devices.first_seen_at IS '首次观察业务时间。';
COMMENT ON COLUMN iam.devices.last_seen_at IS '可空；最近观察业务时间。';
COMMENT ON COLUMN iam.devices.metadata IS '受控设备元数据；禁止保存高熵原始指纹材料。';
COMMENT ON COLUMN iam.devices.created_at IS '数据库插入时间。';
COMMENT ON COLUMN iam.devices.updated_at IS '数据库更新时间；由技术 Trigger 自动刷新。';
COMMENT ON COLUMN iam.devices.row_version IS '乐观锁版本。';

CREATE TABLE iam.sessions (
    id uuid PRIMARY KEY,
    session_id varchar(128) NOT NULL,
    user_id uuid NOT NULL,
    client_id uuid NOT NULL,
    tenant_id uuid,
    device_id uuid,
    authentication_context_id uuid NOT NULL,
    state varchar(40) NOT NULL,
    security_profile_code varchar(40) NOT NULL,
    security_profile_version integer NOT NULL,
    consent_id uuid,
    consent_epoch bigint,
    revocation_watermark bigint,
    user_security_epoch bigint NOT NULL,
    client_security_epoch bigint NOT NULL,
    tenant_security_epoch bigint,
    idle_expires_at timestamptz NOT NULL,
    absolute_expires_at timestamptz NOT NULL,
    last_seen_at timestamptz NOT NULL,
    revoked_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    row_version bigint NOT NULL DEFAULT 0,
    CONSTRAINT uq_sessions_public UNIQUE (session_id),
    CONSTRAINT ck_sessions_profile_version CHECK (security_profile_version > 0),
    CONSTRAINT ck_sessions_epochs CHECK (user_security_epoch >= 0 AND client_security_epoch >= 0 AND (tenant_security_epoch IS NULL OR tenant_security_epoch >= 0) AND (consent_epoch IS NULL OR consent_epoch >= 0) AND (revocation_watermark IS NULL OR revocation_watermark >= 0)),
    CONSTRAINT ck_sessions_expiry CHECK (absolute_expires_at > created_at AND idle_expires_at > created_at AND idle_expires_at <= absolute_expires_at),
    CONSTRAINT ck_sessions_version CHECK (row_version >= 0),
    CONSTRAINT ck_sessions_consent_reference CHECK ((consent_id IS NULL) = (consent_epoch IS NULL)),
    CONSTRAINT ck_sessions_tenant_epoch CHECK ((tenant_id IS NULL) = (tenant_security_epoch IS NULL))
);
COMMENT ON TABLE iam.sessions IS 'OP/设备会话；有效性、滑动过期、并发会话和撤销由 SESSION 代码判定。';
COMMENT ON COLUMN iam.sessions.id IS '应用生成的会话内部 UUIDv7。';
COMMENT ON COLUMN iam.sessions.session_id IS '协议或客户端可见的高熵会话标识。';
COMMENT ON COLUMN iam.sessions.user_id IS '逻辑引用 iam.global_users.id。';
COMMENT ON COLUMN iam.sessions.client_id IS '逻辑引用 iam.oauth_clients.id。';
COMMENT ON COLUMN iam.sessions.tenant_id IS '可空；逻辑引用 iam.tenants.id。';
COMMENT ON COLUMN iam.sessions.device_id IS '可空；逻辑引用 iam.devices.id。';
COMMENT ON COLUMN iam.sessions.authentication_context_id IS '逻辑引用 iam.authentication_contexts.id。';
COMMENT ON COLUMN iam.sessions.state IS '会话状态；由 SESSION 状态机维护。';
COMMENT ON COLUMN iam.sessions.security_profile_code IS '创建会话时适用的 Security Profile 稳定代码。';
COMMENT ON COLUMN iam.sessions.security_profile_version IS '创建会话时适用的 Security Profile 正整数版本。';
COMMENT ON COLUMN iam.sessions.consent_id IS '可空；以 Consent 为处理依据时逻辑引用 iam.consents.id。';
COMMENT ON COLUMN iam.sessions.consent_epoch IS '可空；以 Consent 为依据时的聚合安全水位快照。';
COMMENT ON COLUMN iam.sessions.revocation_watermark IS '可空；创建会话时适用的撤销水位快照。';
COMMENT ON COLUMN iam.sessions.user_security_epoch IS '签发时用户安全水位快照。';
COMMENT ON COLUMN iam.sessions.client_security_epoch IS '签发时 Client 安全水位快照。';
COMMENT ON COLUMN iam.sessions.tenant_security_epoch IS '可空；签发时租户安全水位快照。';
COMMENT ON COLUMN iam.sessions.idle_expires_at IS '代码计算的空闲过期时间。';
COMMENT ON COLUMN iam.sessions.absolute_expires_at IS '代码计算的绝对过期时间。';
COMMENT ON COLUMN iam.sessions.last_seen_at IS '最近会话活动时间；更新节流由代码控制。';
COMMENT ON COLUMN iam.sessions.revoked_at IS '可空；会话撤销时间。';
COMMENT ON COLUMN iam.sessions.created_at IS '数据库插入时间。';
COMMENT ON COLUMN iam.sessions.updated_at IS '数据库更新时间；由技术 Trigger 自动刷新。';
COMMENT ON COLUMN iam.sessions.row_version IS '数据库自动递增的乐观锁版本；代码只在 WHERE 条件中传入 expected version。';

CREATE TABLE iam.session_policy_versions (
    session_id uuid NOT NULL,
    policy_version_id uuid NOT NULL,
    apply_order integer NOT NULL,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT pk_session_policy_versions PRIMARY KEY (session_id, policy_version_id),
    CONSTRAINT uq_session_policy_order UNIQUE (session_id, apply_order),
    CONSTRAINT ck_session_policy_order CHECK (apply_order >= 0)
);
COMMENT ON TABLE iam.session_policy_versions IS '会话创建时采用的策略版本快照关系；数据库保护版本存在性和顺序唯一，策略适用性仍由代码判定。';
COMMENT ON COLUMN iam.session_policy_versions.session_id IS '逻辑引用 iam.sessions.id。';
COMMENT ON COLUMN iam.session_policy_versions.policy_version_id IS '逻辑引用 iam.policy_versions.id。';
COMMENT ON COLUMN iam.session_policy_versions.apply_order IS '创建快照中的稳定非负顺序。';
COMMENT ON COLUMN iam.session_policy_versions.created_at IS '数据库记录时间。';

CREATE TABLE iam.session_participants (
    id uuid PRIMARY KEY,
    session_id uuid NOT NULL,
    rp_client_id uuid NOT NULL,
    rp_sid varchar(128) NOT NULL,
    logout_state varchar(40) NOT NULL,
    last_logout_result varchar(40),
    last_notified_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    row_version bigint NOT NULL DEFAULT 0,
    CONSTRAINT uq_session_participant UNIQUE (session_id, rp_client_id),
    CONSTRAINT uq_session_participant_sid UNIQUE (rp_client_id, rp_sid),
    CONSTRAINT ck_session_participant_version CHECK (row_version >= 0)
);
COMMENT ON TABLE iam.session_participants IS '参与统一会话的 RP 及其 sid，用于前后通道退出确认。';
COMMENT ON COLUMN iam.session_participants.id IS '应用生成的参与记录 UUIDv7。';
COMMENT ON COLUMN iam.session_participants.session_id IS '逻辑引用 iam.sessions.id。';
COMMENT ON COLUMN iam.session_participants.rp_client_id IS '逻辑引用 iam.oauth_clients.id。';
COMMENT ON COLUMN iam.session_participants.rp_sid IS 'RP 作用域内会话 sid。';
COMMENT ON COLUMN iam.session_participants.logout_state IS '退出通知状态；重试和完成条件由 SESSION 代码维护。';
COMMENT ON COLUMN iam.session_participants.last_logout_result IS '可空；最近退出通知结果码。';
COMMENT ON COLUMN iam.session_participants.last_notified_at IS '可空；最近通知时间。';
COMMENT ON COLUMN iam.session_participants.created_at IS '数据库插入时间。';
COMMENT ON COLUMN iam.session_participants.updated_at IS '数据库更新时间；由技术 Trigger 自动刷新。';
COMMENT ON COLUMN iam.session_participants.row_version IS '乐观锁版本。';

CREATE TABLE iam.authorization_codes (
    id uuid PRIMARY KEY,
    code_hash varchar(256) NOT NULL,
    client_id uuid NOT NULL,
    user_id uuid NOT NULL,
    login_transaction_id uuid NOT NULL,
    redirect_uri_digest char(64) NOT NULL,
    pkce_challenge varchar(256),
    pkce_method varchar(20),
    scope_snapshot text[] NOT NULL,
    state varchar(40) NOT NULL,
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    row_version bigint NOT NULL DEFAULT 0,
    CONSTRAINT uq_authorization_codes_hash UNIQUE (code_hash),
    CONSTRAINT ck_authorization_codes_version CHECK (row_version >= 0),
    CONSTRAINT ck_authorization_codes_expiry CHECK (expires_at > created_at)
);
COMMENT ON TABLE iam.authorization_codes IS '一次性 OAuth 授权码摘要；重定向、PKCE、Client 和消费校验由 OAP 代码执行。';
COMMENT ON COLUMN iam.authorization_codes.id IS '应用生成的授权码记录 UUIDv7。';
COMMENT ON COLUMN iam.authorization_codes.code_hash IS '授权码不可逆摘要，全局唯一。';
COMMENT ON COLUMN iam.authorization_codes.client_id IS '逻辑引用 iam.oauth_clients.id。';
COMMENT ON COLUMN iam.authorization_codes.user_id IS '逻辑引用 iam.global_users.id。';
COMMENT ON COLUMN iam.authorization_codes.login_transaction_id IS '逻辑引用 iam.login_transactions.id。';
COMMENT ON COLUMN iam.authorization_codes.redirect_uri_digest IS '精确回调地址摘要。';
COMMENT ON COLUMN iam.authorization_codes.pkce_challenge IS '可空；PKCE Challenge。';
COMMENT ON COLUMN iam.authorization_codes.pkce_method IS '可空；PKCE 方法，算法 Allowlist 由代码校验。';
COMMENT ON COLUMN iam.authorization_codes.scope_snapshot IS '授权码签发时 Scope 快照。';
COMMENT ON COLUMN iam.authorization_codes.state IS '授权码状态；原子消费由 OAP 代码使用条件更新。';
COMMENT ON COLUMN iam.authorization_codes.expires_at IS '授权码过期时间。';
COMMENT ON COLUMN iam.authorization_codes.consumed_at IS '可空；消费时间。';
COMMENT ON COLUMN iam.authorization_codes.created_at IS '数据库插入时间。';
COMMENT ON COLUMN iam.authorization_codes.row_version IS '乐观锁版本。';

CREATE TABLE iam.authorization_grants (
    id uuid PRIMARY KEY,
    user_id uuid NOT NULL,
    client_id uuid NOT NULL,
    resource_id uuid,
    tenant_id uuid,
    scope_snapshot text[] NOT NULL,
    consent_id uuid,
    state varchar(40) NOT NULL,
    requested_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    granted_at timestamptz,
    expires_at timestamptz,
    revoked_at timestamptz,
    grant_version bigint NOT NULL DEFAULT 0,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    row_version bigint NOT NULL DEFAULT 0,
    CONSTRAINT ck_authorization_grants_versions CHECK (grant_version >= 0 AND row_version >= 0),
    CONSTRAINT ck_authorization_grants_granted_at CHECK (granted_at IS NULL OR granted_at >= requested_at),
    CONSTRAINT ck_authorization_grants_expiry CHECK (expires_at IS NULL OR expires_at > coalesce(granted_at, requested_at)),
    CONSTRAINT ck_authorization_grants_revoked_at CHECK (revoked_at IS NULL OR revoked_at >= coalesce(granted_at, requested_at))
);
COMMENT ON TABLE iam.authorization_grants IS '用户对 Client 和资源的授权请求与生效关系；保存 PENDING、ACTIVE、DENIED、REVOKED、EXPIRED 所需时间事实，状态转换、Scope 收敛、Consent 和撤销判断不在数据库中实现。';
COMMENT ON COLUMN iam.authorization_grants.id IS '应用生成的 Grant UUIDv7。';
COMMENT ON COLUMN iam.authorization_grants.user_id IS '逻辑引用 iam.global_users.id。';
COMMENT ON COLUMN iam.authorization_grants.client_id IS '逻辑引用 iam.oauth_clients.id。';
COMMENT ON COLUMN iam.authorization_grants.resource_id IS '可空；逻辑引用 iam.api_resources.id。';
COMMENT ON COLUMN iam.authorization_grants.tenant_id IS '可空；逻辑引用 iam.tenants.id。';
COMMENT ON COLUMN iam.authorization_grants.scope_snapshot IS '当前授权 Scope 快照；代码确保不超出 Client 和 Consent 上界。';
COMMENT ON COLUMN iam.authorization_grants.consent_id IS '可空；逻辑引用 iam.consents.id。';
COMMENT ON COLUMN iam.authorization_grants.state IS 'Grant 状态值；数据库只保存事实，不定义状态全集与合法转换。';
COMMENT ON COLUMN iam.authorization_grants.requested_at IS '授权请求创建时间；PENDING、DENIED 或请求过期状态也必须保留该事实。';
COMMENT ON COLUMN iam.authorization_grants.granted_at IS '可空；进入 ACTIVE 时的授权生效时间，未生效 Grant 保持为空。';
COMMENT ON COLUMN iam.authorization_grants.expires_at IS '可空；授权请求或已生效 Grant 的过期时间。';
COMMENT ON COLUMN iam.authorization_grants.revoked_at IS '可空；撤销时间。';
COMMENT ON COLUMN iam.authorization_grants.grant_version IS 'Grant 安全版本，用于 Token 失效判断。';
COMMENT ON COLUMN iam.authorization_grants.created_at IS '数据库插入时间。';
COMMENT ON COLUMN iam.authorization_grants.updated_at IS '数据库更新时间；由技术 Trigger 自动刷新。';
COMMENT ON COLUMN iam.authorization_grants.row_version IS '乐观锁版本。';

CREATE TABLE iam.token_families (
    id uuid PRIMARY KEY,
    grant_id uuid NOT NULL,
    client_id uuid NOT NULL,
    user_id uuid NOT NULL,
    device_id uuid,
    current_instance_id uuid,
    state varchar(40) NOT NULL,
    family_version bigint NOT NULL DEFAULT 0,
    reuse_detected_at timestamptz,
    expires_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    row_version bigint NOT NULL DEFAULT 0,
    CONSTRAINT ck_token_families_versions CHECK (family_version >= 0 AND row_version >= 0),
    CONSTRAINT ck_token_families_expiry CHECK (expires_at > created_at)
);
COMMENT ON TABLE iam.token_families IS 'Refresh Token Family 根记录；轮换、重放检测和家族撤销由 OAP 代码执行。';
COMMENT ON COLUMN iam.token_families.id IS '应用生成的 Token Family UUIDv7。';
COMMENT ON COLUMN iam.token_families.grant_id IS '逻辑引用 iam.authorization_grants.id。';
COMMENT ON COLUMN iam.token_families.client_id IS '逻辑引用 iam.oauth_clients.id。';
COMMENT ON COLUMN iam.token_families.user_id IS '逻辑引用 iam.global_users.id。';
COMMENT ON COLUMN iam.token_families.device_id IS '可空；逻辑引用 iam.devices.id。';
COMMENT ON COLUMN iam.token_families.current_instance_id IS '可空；逻辑引用 iam.refresh_token_instances.id。';
COMMENT ON COLUMN iam.token_families.state IS 'Token Family 状态。';
COMMENT ON COLUMN iam.token_families.family_version IS '家族安全版本。';
COMMENT ON COLUMN iam.token_families.reuse_detected_at IS '可空；首次检测到旧 Token 重放时间。';
COMMENT ON COLUMN iam.token_families.expires_at IS '家族绝对过期时间。';
COMMENT ON COLUMN iam.token_families.created_at IS '数据库插入时间。';
COMMENT ON COLUMN iam.token_families.updated_at IS '数据库更新时间；由技术 Trigger 自动刷新。';
COMMENT ON COLUMN iam.token_families.row_version IS '乐观锁版本。';

CREATE TABLE iam.refresh_token_instances (
    id uuid PRIMARY KEY,
    family_id uuid NOT NULL,
    token_hash varchar(256) NOT NULL,
    sequence_no bigint NOT NULL,
    state varchar(40) NOT NULL,
    issued_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    used_at timestamptz,
    replaced_by_id uuid,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    row_version bigint NOT NULL DEFAULT 0,
    CONSTRAINT uq_refresh_token_hash UNIQUE (token_hash),
    CONSTRAINT uq_refresh_token_sequence UNIQUE (family_id, sequence_no),
    CONSTRAINT ck_refresh_token_sequence CHECK (sequence_no > 0),
    CONSTRAINT ck_refresh_token_version CHECK (row_version >= 0),
    CONSTRAINT ck_refresh_token_expiry CHECK (expires_at > issued_at),
    CONSTRAINT ck_refresh_token_used_time CHECK (used_at IS NULL OR used_at >= issued_at)
);
COMMENT ON TABLE iam.refresh_token_instances IS 'Refresh Token 单次实例；仅保存摘要，原子轮换和重放响应由 OAP 代码处理。';
COMMENT ON COLUMN iam.refresh_token_instances.id IS '应用生成的实例 UUIDv7。';
COMMENT ON COLUMN iam.refresh_token_instances.family_id IS '逻辑引用 iam.token_families.id。';
COMMENT ON COLUMN iam.refresh_token_instances.token_hash IS 'Refresh Token 不可逆摘要，全局唯一。';
COMMENT ON COLUMN iam.refresh_token_instances.sequence_no IS 'Family 内单调正整数序号。';
COMMENT ON COLUMN iam.refresh_token_instances.state IS '实例状态；由 OAP 状态机维护。';
COMMENT ON COLUMN iam.refresh_token_instances.issued_at IS '签发业务时间。';
COMMENT ON COLUMN iam.refresh_token_instances.expires_at IS '过期时间。';
COMMENT ON COLUMN iam.refresh_token_instances.used_at IS '可空；首次成功消费时间。';
COMMENT ON COLUMN iam.refresh_token_instances.replaced_by_id IS '可空；逻辑引用下一 iam.refresh_token_instances.id。';
COMMENT ON COLUMN iam.refresh_token_instances.created_at IS '数据库插入时间。';
COMMENT ON COLUMN iam.refresh_token_instances.row_version IS '乐观锁版本。';

CREATE TABLE iam.access_token_records (
    id uuid NOT NULL,
    jti varchar(160) NOT NULL,
    token_hash varchar(256),
    user_id uuid,
    subject_type varchar(40) NOT NULL,
    subject_id varchar(128) NOT NULL,
    actor_type varchar(40),
    actor_id uuid,
    delegation_id uuid,
    delegation_chain_snapshot jsonb NOT NULL DEFAULT '[]'::jsonb,
    client_id uuid NOT NULL,
    tenant_id uuid,
    audience text[] NOT NULL,
    scope_snapshot text[] NOT NULL,
    security_profile_code varchar(40) NOT NULL,
    security_profile_version integer NOT NULL,
    consent_id uuid,
    consent_epoch bigint,
    revocation_watermark bigint,
    sender_constraint_type varchar(40),
    sender_constraint_thumbprint varchar(256),
    authorization_decision_id uuid,
    grant_id uuid,
    session_id uuid,
    user_security_epoch bigint,
    client_security_epoch bigint NOT NULL,
    tenant_security_epoch bigint,
    issued_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    revoked_at timestamptz,
    CONSTRAINT pk_access_token_records PRIMARY KEY (id, jti),
    CONSTRAINT uq_access_token_jti UNIQUE (jti),
    CONSTRAINT ck_access_token_profile_version CHECK (security_profile_version > 0),
    CONSTRAINT ck_access_token_epochs CHECK ((user_security_epoch IS NULL OR user_security_epoch >= 0) AND client_security_epoch >= 0 AND (tenant_security_epoch IS NULL OR tenant_security_epoch >= 0) AND (consent_epoch IS NULL OR consent_epoch >= 0) AND (revocation_watermark IS NULL OR revocation_watermark >= 0)),
    CONSTRAINT ck_access_token_expiry CHECK (expires_at > issued_at),
    CONSTRAINT ck_access_token_actor_pair CHECK ((actor_type IS NULL) = (actor_id IS NULL)),
    CONSTRAINT ck_access_token_tenant_epoch CHECK ((tenant_id IS NULL) = (tenant_security_epoch IS NULL)),
    CONSTRAINT ck_access_token_consent_reference CHECK ((consent_id IS NULL) = (consent_epoch IS NULL)),
    CONSTRAINT ck_access_token_sender_constraint CHECK (
        (sender_constraint_type IS NULL) = (sender_constraint_thumbprint IS NULL)
    ),
    CONSTRAINT ck_access_token_revocation_time CHECK (revoked_at IS NULL OR revoked_at >= issued_at)
) PARTITION BY HASH (jti);
COMMENT ON TABLE iam.access_token_records IS 'Access Token 元数据和撤销定位信息；按 JTI Hash 分区以维持数据库全局唯一，不保存完整 Token。';
COMMENT ON COLUMN iam.access_token_records.id IS '应用生成的记录 UUIDv7，与 JTI 组成分区主键。';
COMMENT ON COLUMN iam.access_token_records.jti IS 'Token JTI；数据库全局唯一且为 Hash 分区键。';
COMMENT ON COLUMN iam.access_token_records.token_hash IS '可空；Opaque Token 或审计用途的不可逆摘要。';
COMMENT ON COLUMN iam.access_token_records.user_id IS '可空；自然人 Token 逻辑引用 iam.global_users.id。';
COMMENT ON COLUMN iam.access_token_records.subject_type IS 'Token Subject 类型，例如 USER、MACHINE 或 EXTERNAL_SUBJECT。';
COMMENT ON COLUMN iam.access_token_records.subject_id IS 'Token 中 Subject 快照。';
COMMENT ON COLUMN iam.access_token_records.actor_type IS '可空；代理或 Token Exchange 场景中的 Actor 类型。';
COMMENT ON COLUMN iam.access_token_records.actor_id IS '可空；按 actor_type 逻辑引用自然人、机器主体或 Client。';
COMMENT ON COLUMN iam.access_token_records.delegation_id IS '可空；逻辑引用 iam.delegations.id。';
COMMENT ON COLUMN iam.access_token_records.delegation_chain_snapshot IS '委托链稳定引用和深度快照；代码校验链路范围且禁止扩权。';
COMMENT ON COLUMN iam.access_token_records.client_id IS '逻辑引用 iam.oauth_clients.id。';
COMMENT ON COLUMN iam.access_token_records.tenant_id IS '可空；逻辑引用 iam.tenants.id；存在租户安全水位时必须同时保存租户标识。';
COMMENT ON COLUMN iam.access_token_records.audience IS 'Token Audience 快照。';
COMMENT ON COLUMN iam.access_token_records.scope_snapshot IS 'Token Scope 快照。';
COMMENT ON COLUMN iam.access_token_records.security_profile_code IS 'Token 签发时适用的 Security Profile 稳定代码。';
COMMENT ON COLUMN iam.access_token_records.security_profile_version IS 'Token 签发时适用的 Security Profile 正整数版本。';
COMMENT ON COLUMN iam.access_token_records.consent_id IS '可空；以 Consent 为处理依据时逻辑引用 iam.consents.id。';
COMMENT ON COLUMN iam.access_token_records.consent_epoch IS '可空；签发时适用的 Consent 安全水位。';
COMMENT ON COLUMN iam.access_token_records.revocation_watermark IS '可空；签发时适用的撤销水位。';
COMMENT ON COLUMN iam.access_token_records.sender_constraint_type IS '可空；发送方约束类型，例如 DPOP_JKT 或 MTLS_X5T_S256。';
COMMENT ON COLUMN iam.access_token_records.sender_constraint_thumbprint IS '可空；DPoP 公钥或 mTLS 证书确认值的摘要，不保存私钥或证书秘密。';
COMMENT ON COLUMN iam.access_token_records.authorization_decision_id IS '可空；逻辑引用 iam.authorization_decisions.decision_id，记录签发依据的 PDP 全局决策。';
COMMENT ON COLUMN iam.access_token_records.grant_id IS '可空；逻辑引用 iam.authorization_grants.id。';
COMMENT ON COLUMN iam.access_token_records.session_id IS '可空；逻辑引用 iam.sessions.id。';
COMMENT ON COLUMN iam.access_token_records.user_security_epoch IS '可空；签发时用户安全水位。';
COMMENT ON COLUMN iam.access_token_records.client_security_epoch IS '签发时 Client 安全水位。';
COMMENT ON COLUMN iam.access_token_records.tenant_security_epoch IS '可空；签发时租户安全水位。';
COMMENT ON COLUMN iam.access_token_records.issued_at IS 'Token 签发时间；用于查询、保留和归档。';
COMMENT ON COLUMN iam.access_token_records.expires_at IS 'Token 过期时间。';
COMMENT ON COLUMN iam.access_token_records.revoked_at IS '可空；单 Token 撤销时间。';
COMMENT ON CONSTRAINT uq_access_token_jti ON iam.access_token_records IS '保证 Access Token JTI 在数据库内全局唯一；因此采用 Hash 而非月度 Range 分区。';

CREATE TABLE iam.access_token_policy_versions (
    token_jti varchar(160) NOT NULL,
    policy_version_id uuid NOT NULL,
    apply_order integer NOT NULL,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT pk_access_token_policy_versions PRIMARY KEY (token_jti, policy_version_id),
    CONSTRAINT uq_access_token_policy_order UNIQUE (token_jti, apply_order),
    CONSTRAINT ck_access_token_policy_order CHECK (apply_order >= 0)
);
COMMENT ON TABLE iam.access_token_policy_versions IS 'Access Token 签发时采用的策略版本快照关系；数据库保护版本存在性和顺序唯一，Token 声明及策略适用性仍由代码判定。';
COMMENT ON COLUMN iam.access_token_policy_versions.token_jti IS '逻辑引用 iam.access_token_records.jti。';
COMMENT ON COLUMN iam.access_token_policy_versions.policy_version_id IS '逻辑引用 iam.policy_versions.id。';
COMMENT ON COLUMN iam.access_token_policy_versions.apply_order IS '签发快照中的稳定非负顺序。';
COMMENT ON COLUMN iam.access_token_policy_versions.created_at IS '数据库记录时间。';

CREATE TABLE iam.revocation_entries (
    id uuid PRIMARY KEY,
    target_type varchar(40) NOT NULL,
    target_id varchar(256) NOT NULL,
    target_hash varchar(256),
    scope_type varchar(40),
    scope_id uuid,
    reason_code varchar(100) NOT NULL,
    security_watermark bigint,
    effective_at timestamptz NOT NULL,
    expires_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT uq_revocation_target UNIQUE (target_type, target_id, effective_at),
    CONSTRAINT ck_revocation_watermark CHECK (security_watermark IS NULL OR security_watermark >= 0),
    CONSTRAINT ck_revocation_expiry CHECK (expires_at IS NULL OR expires_at > effective_at)
);
COMMENT ON TABLE iam.revocation_entries IS '会话、Token、Grant、主体或 Key 的统一撤销事实和 Denylist；SESSION 持有模型，其他领域提交撤销原因并消费水位。';
COMMENT ON COLUMN iam.revocation_entries.id IS '应用生成的撤销记录 UUIDv7。';
COMMENT ON COLUMN iam.revocation_entries.target_type IS '撤销目标类型。';
COMMENT ON COLUMN iam.revocation_entries.target_id IS '目标稳定 ID 或安全编码值；代码按类型解释。';
COMMENT ON COLUMN iam.revocation_entries.target_hash IS '可空；敏感目标的不可逆摘要。';
COMMENT ON COLUMN iam.revocation_entries.scope_type IS '可空；撤销作用域类型。';
COMMENT ON COLUMN iam.revocation_entries.scope_id IS '可空；撤销作用域逻辑 ID。';
COMMENT ON COLUMN iam.revocation_entries.reason_code IS '稳定撤销原因码。';
COMMENT ON COLUMN iam.revocation_entries.security_watermark IS '可空；撤销后安全水位。';
COMMENT ON COLUMN iam.revocation_entries.effective_at IS '撤销生效时间。';
COMMENT ON COLUMN iam.revocation_entries.expires_at IS '可空；短期 Denylist 失效时间。';
COMMENT ON COLUMN iam.revocation_entries.created_at IS '数据库插入时间。';

CREATE INDEX ix_devices_user ON iam.devices (user_id, lifecycle_state, last_seen_at DESC);
CREATE INDEX ix_sessions_user_state ON iam.sessions (user_id, state, absolute_expires_at);
CREATE INDEX ix_sessions_client_state ON iam.sessions (client_id, state, absolute_expires_at);
CREATE INDEX ix_session_policy_versions_policy ON iam.session_policy_versions (policy_version_id, session_id);
CREATE INDEX ix_authorization_codes_expiry ON iam.authorization_codes (state, expires_at);
CREATE INDEX ix_authorization_grants_user_client ON iam.authorization_grants (user_id, client_id, state);
CREATE INDEX ix_token_families_grant ON iam.token_families (grant_id, state);
CREATE INDEX ix_access_token_subject ON iam.access_token_records (subject_id, issued_at DESC);
CREATE INDEX ix_access_token_tenant ON iam.access_token_records (tenant_id, issued_at DESC) WHERE tenant_id IS NOT NULL;
CREATE INDEX ix_access_token_policy_versions_policy ON iam.access_token_policy_versions (policy_version_id, token_jti);
