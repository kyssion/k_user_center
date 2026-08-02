-- =============================================================================
-- baseline/schemas/authn/tables.sql
-- authn Schema 的最终基表、同 Schema 约束、索引及内联 COMMENT
-- PostgreSQL 16+；应用技术栈：.NET 10 + SqlSugar
-- =============================================================================

CREATE TABLE authn.authenticator (
    id uuid        NOT NULL DEFAULT gen_random_uuid(),
    user_id uuid        NOT NULL,
    authenticator_type text        NOT NULL,
    authenticator_state text        NOT NULL DEFAULT 'PENDING',
    display_name text        NULL,
    credential_public_id bytea       NULL,
    public_key_cose bytea       NULL,
    secret_cipher bytea       NULL,
    secret_key_version integer     NULL,
    aaguid uuid        NULL,
    sign_count bigint      NULL,
    user_verification boolean     NOT NULL DEFAULT false,
    phishing_resistant boolean     NOT NULL DEFAULT false,
    backup_eligible boolean     NULL,
    backup_state boolean     NULL,
    syncable boolean     NOT NULL DEFAULT false,
    hardware_protected boolean     NOT NULL DEFAULT false,
    attestation_trust_level text        NULL,
    aal_ceiling text        NOT NULL DEFAULT 'AAL1',
    registered_at timestamptz NULL,
    suspended_at timestamptz NULL,
    locked_at timestamptz NULL,
    compromised_at timestamptz NULL,
    revoked_at timestamptz NULL,
    replaced_by_id uuid        NULL,
    expires_at timestamptz NULL,
    last_used_at timestamptz NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    row_version bigint      NOT NULL DEFAULT 1,
    state_expired_at timestamptz NULL,
    state_reason_code text NULL,
    CONSTRAINT pk_authenticator PRIMARY KEY (id),
    CONSTRAINT fk_authenticator_replaced_by FOREIGN KEY (replaced_by_id) REFERENCES authn.authenticator(id),
    CONSTRAINT ck_authenticator_type CHECK (authenticator_type IN ('PASSWORD', 'PASSKEY', 'SECURITY_KEY', 'TOTP', 'SMS_OTP', 'EMAIL_OTP', 'RECOVERY_CODE', 'FEDERATED')),
    CONSTRAINT ck_authenticator_state CHECK (authenticator_state IN ('PENDING', 'ACTIVE', 'SUSPENDED', 'LOCKED', 'EXPIRED', 'COMPROMISED', 'REVOKED', 'REPLACED')),
    CONSTRAINT ck_authenticator_aal CHECK (aal_ceiling IN ('AAL1', 'AAL2', 'AAL3')),
    CONSTRAINT ck_authenticator_passkey_material CHECK (authenticator_type NOT IN ('PASSKEY', 'SECURITY_KEY') OR (credential_public_id IS NOT NULL AND public_key_cose IS NOT NULL)),
    CONSTRAINT ck_authenticator_totp_material CHECK (authenticator_type <> 'TOTP' OR (secret_cipher IS NOT NULL AND secret_key_version IS NOT NULL)),
    CONSTRAINT ck_authenticator_syncable_aal CHECK (NOT syncable OR aal_ceiling <> 'AAL3'),
    CONSTRAINT ck_authenticator_active CHECK (authenticator_state <> 'ACTIVE' OR registered_at IS NOT NULL),
    CONSTRAINT ck_authenticator_replaced CHECK ((authenticator_state = 'REPLACED') = (replaced_by_id IS NOT NULL)),
    CONSTRAINT ck_authenticator_expired_state CHECK ((authenticator_state = 'EXPIRED') = (state_expired_at IS NOT NULL)),
    CONSTRAINT ck_authenticator_compromised_state CHECK (
    authenticator_state <> 'COMPROMISED' OR compromised_at IS NOT NULL
    ),
    CONSTRAINT ck_authenticator_revoked_state CHECK (authenticator_state <> 'REVOKED' OR revoked_at IS NOT NULL)
);

COMMENT ON TABLE authn.authenticator IS 'CAP-AUTH-011 至 018 / REQ-AUTH-017/018：认证器生命周期、WebAuthn 证据、同步/备份属性和 AAL 上限。';

CREATE TABLE authn.password_credential (
    user_id uuid        NOT NULL,
    authenticator_id uuid        NOT NULL,
    password_hash text        NOT NULL,
    password_hash_algorithm text        NOT NULL,
    password_hash_parameters jsonb       NOT NULL,
    password_changed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    must_change boolean     NOT NULL DEFAULT false,
    compromised_at timestamptz NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    row_version bigint      NOT NULL DEFAULT 1,
    CONSTRAINT pk_password_credential PRIMARY KEY (user_id),
    CONSTRAINT uq_password_credential_authenticator UNIQUE (authenticator_id),
    CONSTRAINT fk_password_credential_authenticator FOREIGN KEY (authenticator_id) REFERENCES authn.authenticator(id),
    CONSTRAINT ck_password_credential_phc CHECK (password_hash LIKE '$%'),
    CONSTRAINT ck_password_credential_algorithm CHECK (password_hash_algorithm IN ('ARGON2ID', 'SCRYPT', 'PBKDF2', 'BCRYPT'))
);

COMMENT ON TABLE authn.password_credential IS 'CAP-AUTH-004/005：密码只保存经批准的加盐自适应或内存困难哈希及参数版本，禁止快速摘要直接存储。';

CREATE TABLE authn.password_history (
    id uuid        NOT NULL DEFAULT gen_random_uuid(),
    user_id uuid        NOT NULL,
    password_hash text        NOT NULL,
    password_hash_algorithm text        NOT NULL,
    password_hash_parameters jsonb       NOT NULL,
    replaced_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    retain_until timestamptz NOT NULL,
    CONSTRAINT pk_password_history PRIMARY KEY (id),
    CONSTRAINT ck_password_history_window CHECK (retain_until > replaced_at)
);

COMMENT ON TABLE authn.password_history IS 'CAP-AUTH-005：受保留策略约束的历史口令哈希，用于阻断短期复用；不保存明文。';

CREATE TABLE authn.recovery_code_batch (
    id uuid        NOT NULL DEFAULT gen_random_uuid(),
    user_id uuid        NOT NULL,
    batch_state text        NOT NULL DEFAULT 'ACTIVE',
    generated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    expires_at timestamptz NULL,
    revoked_at timestamptz NULL,
    CONSTRAINT pk_recovery_code_batch PRIMARY KEY (id),
    CONSTRAINT ck_recovery_code_batch_state CHECK (batch_state IN ('ACTIVE', 'EXHAUSTED', 'REVOKED', 'EXPIRED'))
);

COMMENT ON TABLE authn.recovery_code_batch IS 'CAP-AUTH-017：恢复码批次状态、轮换、失效与耗尽证据。';

CREATE TABLE authn.recovery_code (
    id uuid        NOT NULL DEFAULT gen_random_uuid(),
    batch_id uuid        NOT NULL,
    code_hash bytea       NOT NULL,
    used_at timestamptz NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    hash_algorithm text NOT NULL DEFAULT 'HMAC-SHA-256',
    hash_key_version integer NOT NULL DEFAULT 1,
    CONSTRAINT pk_recovery_code PRIMARY KEY (id),
    CONSTRAINT uq_recovery_code_hash UNIQUE (code_hash),
    CONSTRAINT fk_recovery_code_batch FOREIGN KEY (batch_id) REFERENCES authn.recovery_code_batch(id) ON DELETE CASCADE,
    CONSTRAINT ck_recovery_code_hash CHECK (octet_length(code_hash) = 32),
    CONSTRAINT ck_recovery_code_hash_profile CHECK (hash_algorithm IN ('HMAC-SHA-256', 'HMAC-SM3') AND hash_key_version > 0)
);

COMMENT ON TABLE authn.recovery_code IS 'CAP-AUTH-017：单次使用恢复码的不可逆哈希和消费时间。';

CREATE TABLE authn.login_transaction (
    id uuid        NOT NULL DEFAULT gen_random_uuid(),
    public_id text        NOT NULL,
    client_id uuid        NOT NULL,
    business_line_id uuid        NOT NULL,
    tenant_id uuid        NOT NULL DEFAULT '00000000-0000-0000-0000-000000000000',
    user_id uuid        NULL,
    login_transaction_state text        NOT NULL DEFAULT 'CREATED',
    profile_code text        NOT NULL,
    response_type text        NOT NULL DEFAULT 'code',
    requested_scopes text[]      NOT NULL DEFAULT '{}',
    requested_resources text[]      NOT NULL DEFAULT '{}',
    authorization_details jsonb       NULL,
    redirect_uri text        NOT NULL,
    state_hash bytea       NULL,
    nonce_hash bytea       NULL,
    code_challenge text        NOT NULL,
    code_challenge_method text        NOT NULL DEFAULT 'S256',
    prompt_values text[]      NOT NULL DEFAULT '{}',
    requested_acr_values text[]      NOT NULL DEFAULT '{}',
    required_aal text        NOT NULL DEFAULT 'AAL1',
    achieved_aal text        NULL,
    achieved_ial text        NULL,
    achieved_acr text        NULL,
    achieved_amr text[]      NOT NULL DEFAULT '{}',
    risk_level text        NULL,
    risk_assessment_id uuid        NULL,
    remaining_steps jsonb       NOT NULL DEFAULT '[]'::jsonb,
    pending_consent_scopes text[]      NOT NULL DEFAULT '{}',
    ip_hash bytea       NULL,
    user_agent_hash bytea       NULL,
    device_fingerprint_hash bytea       NULL,
    authenticated_at timestamptz NULL,
    completed_at timestamptz NULL,
    consumed_at timestamptz NULL,
    abandoned_at timestamptz NULL,
    block_reason_code text        NULL,
    expires_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    row_version bigint      NOT NULL DEFAULT 1,
    identified_at timestamptz NULL,
    partially_authenticated_at timestamptz NULL,
    pending_consent_at timestamptz NULL,
    expired_at timestamptz NULL,
    blocked_at timestamptz NULL,
    abandon_reason_code text NULL,
    CONSTRAINT pk_login_transaction PRIMARY KEY (id),
    CONSTRAINT uq_login_transaction_public_id UNIQUE (public_id),
    CONSTRAINT ck_login_transaction_state CHECK (login_transaction_state IN ('CREATED', 'IDENTIFIED', 'PARTIALLY_AUTHENTICATED', 'AUTHENTICATED', 'PENDING_CONSENT', 'COMPLETED', 'EXPIRED', 'ABANDONED', 'BLOCKED')),
    CONSTRAINT ck_login_transaction_pkce CHECK (code_challenge_method = 'S256' AND length(code_challenge) BETWEEN 43 AND 128),
    CONSTRAINT ck_login_transaction_response CHECK (response_type = 'code'),
    CONSTRAINT ck_login_transaction_aal CHECK (required_aal IN ('AAL1', 'AAL2', 'AAL3') AND (achieved_aal IS NULL OR achieved_aal IN ('AAL1', 'AAL2', 'AAL3'))),
    CONSTRAINT ck_login_transaction_identified CHECK (login_transaction_state IN ('CREATED', 'EXPIRED', 'ABANDONED', 'BLOCKED') OR user_id IS NOT NULL),
    CONSTRAINT ck_login_transaction_authenticated CHECK (login_transaction_state NOT IN ('AUTHENTICATED', 'PENDING_CONSENT', 'COMPLETED') OR (authenticated_at IS NOT NULL AND achieved_aal IS NOT NULL)),
    CONSTRAINT ck_login_transaction_completed CHECK ((login_transaction_state = 'COMPLETED') = (completed_at IS NOT NULL)),
    CONSTRAINT ck_login_transaction_blocked CHECK (login_transaction_state <> 'BLOCKED' OR block_reason_code IS NOT NULL),
    CONSTRAINT ck_login_transaction_ttl CHECK (expires_at > created_at AND expires_at - created_at <= interval '15 minutes'),
    CONSTRAINT ck_login_transaction_expired CHECK ((login_transaction_state = 'EXPIRED') = (expired_at IS NOT NULL)),
    CONSTRAINT ck_login_transaction_abandoned CHECK (
    (login_transaction_state = 'ABANDONED') = (abandoned_at IS NOT NULL)
    AND (login_transaction_state <> 'ABANDONED' OR abandon_reason_code IS NOT NULL)
    ),
    CONSTRAINT ck_login_transaction_blocked_time CHECK ((login_transaction_state = 'BLOCKED') = (blocked_at IS NOT NULL))
);

COMMENT ON TABLE authn.login_transaction IS 'CAP-AUTH-021 / INV-G-016：服务端权威登录事务；AUTHENTICATED 后按是否需要 Consent 进入 PENDING_CONSENT 或 COMPLETED。';

CREATE TABLE authn.login_factor (
    id uuid        NOT NULL DEFAULT gen_random_uuid(),
    login_transaction_id uuid        NOT NULL,
    authenticator_id uuid        NULL,
    challenge_id uuid        NULL,
    amr_value text        NOT NULL,
    factor_category text        NOT NULL,
    achieved_aal text        NOT NULL,
    phishing_resistant boolean     NOT NULL,
    user_verified boolean     NOT NULL,
    backup_eligible boolean     NULL,
    backup_state boolean     NULL,
    hardware_protected boolean     NULL,
    attestation_level text        NULL,
    assurance_rule_version integer    NOT NULL,
    evidence jsonb       NOT NULL,
    verified_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT pk_login_factor PRIMARY KEY (id),
    CONSTRAINT fk_login_factor_transaction FOREIGN KEY (login_transaction_id) REFERENCES authn.login_transaction(id) ON DELETE CASCADE,
    CONSTRAINT fk_login_factor_authenticator FOREIGN KEY (authenticator_id) REFERENCES authn.authenticator(id),
    CONSTRAINT ck_login_factor_aal CHECK (achieved_aal IN ('AAL1', 'AAL2', 'AAL3')),
    CONSTRAINT uq_login_factor UNIQUE NULLS NOT DISTINCT (login_transaction_id, amr_value, authenticator_id)
);

COMMENT ON TABLE authn.login_factor IS 'REQ-AUTH-017/018：本次认证证据、amr、认证器特征与版本化 AAL 计算结果。';

CREATE TABLE authn.verification_challenge (
    id uuid        NOT NULL DEFAULT gen_random_uuid(),
    public_id text        NOT NULL,
    challenge_purpose text        NOT NULL,
    challenge_state text        NOT NULL DEFAULT 'ISSUED',
    client_id uuid        NOT NULL,
    login_transaction_id uuid        NULL,
    user_id uuid        NULL,
    target_identifier_id uuid        NULL,
    target_blind_index bytea       NULL,
    delivery_channel text        NOT NULL,
    challenge_hash bytea       NOT NULL,
    attempt_count integer     NOT NULL DEFAULT 0,
    max_attempts integer     NOT NULL DEFAULT 5,
    verified_at timestamptz NULL,
    consumed_at timestamptz NULL,
    locked_at timestamptz NULL,
    superseded_by_id uuid        NULL,
    expires_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    row_version bigint      NOT NULL DEFAULT 1,
    hash_algorithm text NOT NULL DEFAULT 'HMAC-SHA-256',
    hash_key_version integer NOT NULL DEFAULT 1,
    risk_assessment_id uuid NOT NULL,
    risk_context_hash bytea NOT NULL,
    expired_at timestamptz NULL,
    cancelled_at timestamptz NULL,
    state_reason_code text NULL,
    CONSTRAINT pk_verification_challenge PRIMARY KEY (id),
    CONSTRAINT uq_verification_challenge_public_id UNIQUE (public_id),
    CONSTRAINT uq_verification_challenge_hash UNIQUE (challenge_hash),
    CONSTRAINT fk_verification_challenge_tx FOREIGN KEY (login_transaction_id) REFERENCES authn.login_transaction(id),
    CONSTRAINT fk_verification_challenge_superseded FOREIGN KEY (superseded_by_id) REFERENCES authn.verification_challenge(id),
    CONSTRAINT ck_verification_challenge_purpose CHECK (challenge_purpose IN ('REGISTER', 'LOGIN', 'STEP_UP', 'BIND_IDENTIFIER', 'REBIND_OLD', 'REBIND_NEW', 'PASSWORD_RESET', 'ACCOUNT_RECOVERY', 'DELETE_ACCOUNT', 'DELETE_WITHDRAW', 'WEBAUTHN_REGISTRATION', 'WEBAUTHN_ASSERTION', 'CONSENT_CONFIRM', 'DOMAIN_VERIFY')),
    CONSTRAINT ck_verification_challenge_state CHECK (challenge_state IN ('ISSUED', 'VERIFIED', 'CONSUMED', 'EXPIRED', 'LOCKED', 'CANCELLED')),
    CONSTRAINT ck_verification_challenge_channel CHECK (delivery_channel IN ('SMS', 'EMAIL', 'VOICE', 'PUSH', 'IN_APP', 'NONE')),
    CONSTRAINT ck_verification_challenge_hash CHECK (octet_length(challenge_hash) = 32),
    CONSTRAINT ck_verification_challenge_attempt CHECK (attempt_count >= 0 AND max_attempts BETWEEN 1 AND 5 AND attempt_count <= max_attempts),
    CONSTRAINT ck_verification_challenge_consumed CHECK ((challenge_state = 'CONSUMED') = (consumed_at IS NOT NULL)),
    CONSTRAINT ck_verification_challenge_ttl CHECK (expires_at > created_at AND expires_at - created_at <= interval '5 minutes'),
    CONSTRAINT ck_challenge_hash_profile CHECK (hash_algorithm IN ('HMAC-SHA-256', 'HMAC-SM3') AND hash_key_version > 0),
    CONSTRAINT ck_verification_challenge_risk_hash CHECK (octet_length(risk_context_hash) = 32),
    CONSTRAINT ck_verification_challenge_target CHECK (num_nonnulls(user_id, target_identifier_id, target_blind_index) >= 1),
    CONSTRAINT ck_verification_challenge_verified CHECK ((challenge_state IN ('VERIFIED', 'CONSUMED')) = (verified_at IS NOT NULL)),
    CONSTRAINT ck_verification_challenge_expired CHECK ((challenge_state = 'EXPIRED') = (expired_at IS NOT NULL)),
    CONSTRAINT ck_verification_challenge_locked CHECK ((challenge_state = 'LOCKED') = (locked_at IS NOT NULL)),
    CONSTRAINT ck_verification_challenge_cancelled CHECK ((challenge_state = 'CANCELLED') = (cancelled_at IS NOT NULL)),
    CONSTRAINT ck_verification_challenge_superseded CHECK (superseded_by_id IS NULL OR challenge_state = 'CANCELLED')
);

COMMENT ON TABLE authn.verification_challenge IS 'REQ-AUTH-013 至 015：短信、邮件、WebAuthn 等短期 Challenge 的用途/Client/事务绑定、限次与单次消费。';

CREATE TABLE authn.device_authorization (
    id uuid        NOT NULL DEFAULT gen_random_uuid(),
    client_id uuid        NOT NULL,
    tenant_id uuid        NOT NULL DEFAULT '00000000-0000-0000-0000-000000000000',
    device_code_hash bytea       NOT NULL,
    user_code_hash bytea       NOT NULL,
    requested_scopes text[]      NOT NULL DEFAULT '{}',
    requested_resources text[]      NOT NULL DEFAULT '{}',
    authorization_details jsonb       NULL,
    polling_interval_seconds integer     NOT NULL DEFAULT 5,
    poll_count integer     NOT NULL DEFAULT 0,
    slow_down_count integer     NOT NULL DEFAULT 0,
    last_polled_at timestamptz NULL,
    authorized_user_id uuid        NULL,
    login_transaction_id uuid        NULL,
    grant_id uuid        NULL,
    approved_at timestamptz NULL,
    denied_at timestamptz NULL,
    consumed_at timestamptz NULL,
    expires_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    row_version bigint      NOT NULL DEFAULT 1,
    device_code_hash_algorithm text NOT NULL DEFAULT 'SHA-256',
    user_code_hash_algorithm text NOT NULL DEFAULT 'HMAC-SHA-256',
    user_code_hash_key_version integer NOT NULL DEFAULT 1,
    CONSTRAINT pk_device_authorization PRIMARY KEY (id),
    CONSTRAINT uq_device_authorization_device_code UNIQUE (device_code_hash),
    CONSTRAINT uq_device_authorization_user_code UNIQUE (user_code_hash),
    CONSTRAINT fk_device_authorization_tx FOREIGN KEY (login_transaction_id) REFERENCES authn.login_transaction(id),
    CONSTRAINT ck_device_authorization_hash CHECK (octet_length(device_code_hash) = 32 AND octet_length(user_code_hash) = 32),
    CONSTRAINT ck_device_authorization_interval CHECK (polling_interval_seconds BETWEEN 5 AND 60),
    CONSTRAINT ck_device_authorization_poll CHECK (poll_count >= 0 AND slow_down_count >= 0),
    CONSTRAINT ck_device_authorization_outcome CHECK (num_nonnulls(approved_at, denied_at) <= 1),
    CONSTRAINT ck_device_authorization_approval CHECK (approved_at IS NULL OR (authorized_user_id IS NOT NULL AND login_transaction_id IS NOT NULL)),
    CONSTRAINT ck_device_authorization_consume CHECK (consumed_at IS NULL OR approved_at IS NOT NULL),
    CONSTRAINT ck_device_authorization_ttl CHECK (expires_at > created_at AND expires_at - created_at <= interval '15 minutes'),
    CONSTRAINT ck_device_code_hash_profile CHECK (device_code_hash_algorithm IN ('SHA-256', 'SM3')),
    CONSTRAINT ck_user_code_hash_profile CHECK (user_code_hash_algorithm IN ('HMAC-SHA-256', 'HMAC-SM3') AND user_code_hash_key_version > 0)
);

COMMENT ON TABLE authn.device_authorization IS 'CAP-OAP-017 / REQ-OAP-005/006：RFC 8628 device_code/user_code、轮询间隔、slow_down、批准、拒绝、过期与单次消费。';

ALTER TABLE authn.login_factor
    ADD CONSTRAINT fk_login_factor_challenge FOREIGN KEY (challenge_id) REFERENCES authn.verification_challenge(id);

CREATE UNIQUE INDEX ux_authenticator_credential_id ON authn.authenticator(credential_public_id) WHERE credential_public_id IS NOT NULL;

CREATE UNIQUE INDEX ux_recovery_code_batch_active ON authn.recovery_code_batch(user_id) WHERE batch_state = 'ACTIVE';

CREATE UNIQUE INDEX ux_challenge_active_target ON authn.verification_challenge(challenge_purpose, client_id, target_blind_index) WHERE challenge_state = 'ISSUED' AND target_blind_index IS NOT NULL;

CREATE INDEX ix_login_transaction_expiry ON authn.login_transaction(expires_at) WHERE login_transaction_state NOT IN ('COMPLETED', 'EXPIRED', 'ABANDONED');

CREATE INDEX ix_device_authorization_expiry ON authn.device_authorization(expires_at) WHERE consumed_at IS NULL AND denied_at IS NULL;

CREATE INDEX ix_fk_authenticator_replaced_by_id ON authn.authenticator (replaced_by_id);

CREATE INDEX ix_fk_recovery_code_batch_id ON authn.recovery_code (batch_id);

CREATE INDEX ix_fk_login_factor_authenticator_id ON authn.login_factor (authenticator_id);

CREATE INDEX ix_fk_login_factor_challenge_id ON authn.login_factor (challenge_id);

CREATE INDEX ix_fk_verification_challenge_login_transaction_id ON authn.verification_challenge (login_transaction_id);

CREATE INDEX ix_fk_verification_challenge_superseded_by_id ON authn.verification_challenge (superseded_by_id);

CREATE INDEX ix_fk_device_authorization_login_transaction_id ON authn.device_authorization (login_transaction_id);

COMMENT ON COLUMN authn.authenticator.id IS '内部 UUID 主键；仅用于数据库关系，不作为跨域公开标识。';
COMMENT ON COLUMN authn.authenticator.user_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN authn.authenticator.authenticator_type IS '对象类别判别字段；允许值由 CHECK 或对应注册表限定。';
COMMENT ON COLUMN authn.authenticator.authenticator_state IS '显式状态当前值；合法取值见 CHECK，完整状态转换由 .NET 领域策略执行。';
COMMENT ON COLUMN authn.authenticator.display_name IS 'authn.authenticator.display_name 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN authn.authenticator.credential_public_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN authn.authenticator.public_key_cose IS 'authn.authenticator.public_key_cose 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN authn.authenticator.secret_cipher IS '随机化加密密文；解密密钥由独立 KMS/HSM 引用管理。';
COMMENT ON COLUMN authn.authenticator.secret_key_version IS '生成密文、HMAC 或盲索引所用密钥版本；轮换时保留可验证窗口。';
COMMENT ON COLUMN authn.authenticator.aaguid IS 'authn.authenticator.aaguid 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN authn.authenticator.sign_count IS '非负计数器；并发更新使用原子 SQL 或乐观并发控制。';
COMMENT ON COLUMN authn.authenticator.user_verification IS 'authn.authenticator.user_verification 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN authn.authenticator.phishing_resistant IS 'authn.authenticator.phishing_resistant 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN authn.authenticator.backup_eligible IS 'authn.authenticator.backup_eligible 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN authn.authenticator.backup_state IS '显式状态当前值；合法取值见 CHECK，完整状态转换由 .NET 领域策略执行。';
COMMENT ON COLUMN authn.authenticator.syncable IS 'authn.authenticator.syncable 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN authn.authenticator.hardware_protected IS 'authn.authenticator.hardware_protected 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN authn.authenticator.attestation_trust_level IS 'authn.authenticator.attestation_trust_level 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN authn.authenticator.aal_ceiling IS 'authn.authenticator.aal_ceiling 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN authn.authenticator.registered_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN authn.authenticator.suspended_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN authn.authenticator.locked_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN authn.authenticator.compromised_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN authn.authenticator.revoked_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN authn.authenticator.replaced_by_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN authn.authenticator.expires_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN authn.authenticator.last_used_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN authn.authenticator.created_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN authn.authenticator.updated_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN authn.authenticator.row_version IS '乐观并发版本；更新必须使用原值 compare-and-set，成功后由数据库单调递增。';
COMMENT ON COLUMN authn.authenticator.state_expired_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN authn.authenticator.state_reason_code IS '稳定机器可读代码；展示文本由资源或目录解析。';
COMMENT ON COLUMN authn.password_credential.user_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN authn.password_credential.authenticator_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN authn.password_credential.password_hash IS '不可逆摘要；用于等值匹配、幂等、完整性或最小化证据，不保存原始敏感值。';
COMMENT ON COLUMN authn.password_credential.password_hash_algorithm IS '显式算法标识；必须来自环境算法 allowlist，禁止弱算法与静默降级。';
COMMENT ON COLUMN authn.password_credential.password_hash_parameters IS '版本化结构化扩展数据；必须由 .NET 按对应 JSON Schema 校验，不得替代核心状态或外键。';
COMMENT ON COLUMN authn.password_credential.password_changed_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN authn.password_credential.must_change IS 'authn.password_credential.must_change 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN authn.password_credential.compromised_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN authn.password_credential.created_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN authn.password_credential.updated_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN authn.password_credential.row_version IS '乐观并发版本；更新必须使用原值 compare-and-set，成功后由数据库单调递增。';
COMMENT ON COLUMN authn.password_history.id IS '内部 UUID 主键；仅用于数据库关系，不作为跨域公开标识。';
COMMENT ON COLUMN authn.password_history.user_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN authn.password_history.password_hash IS '不可逆摘要；用于等值匹配、幂等、完整性或最小化证据，不保存原始敏感值。';
COMMENT ON COLUMN authn.password_history.password_hash_algorithm IS '显式算法标识；必须来自环境算法 allowlist，禁止弱算法与静默降级。';
COMMENT ON COLUMN authn.password_history.password_hash_parameters IS '版本化结构化扩展数据；必须由 .NET 按对应 JSON Schema 校验，不得替代核心状态或外键。';
COMMENT ON COLUMN authn.password_history.replaced_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN authn.password_history.retain_until IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN authn.recovery_code_batch.id IS '内部 UUID 主键；仅用于数据库关系，不作为跨域公开标识。';
COMMENT ON COLUMN authn.recovery_code_batch.user_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN authn.recovery_code_batch.batch_state IS '显式状态当前值；合法取值见 CHECK，完整状态转换由 .NET 领域策略执行。';
COMMENT ON COLUMN authn.recovery_code_batch.generated_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN authn.recovery_code_batch.expires_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN authn.recovery_code_batch.revoked_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN authn.recovery_code.id IS '内部 UUID 主键；仅用于数据库关系，不作为跨域公开标识。';
COMMENT ON COLUMN authn.recovery_code.batch_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN authn.recovery_code.code_hash IS '不可逆摘要；用于等值匹配、幂等、完整性或最小化证据，不保存原始敏感值。';
COMMENT ON COLUMN authn.recovery_code.used_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN authn.recovery_code.created_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN authn.recovery_code.hash_algorithm IS '显式算法标识；必须来自环境算法 allowlist，禁止弱算法与静默降级。';
COMMENT ON COLUMN authn.recovery_code.hash_key_version IS '生成密文、HMAC 或盲索引所用密钥版本；轮换时保留可验证窗口。';
COMMENT ON COLUMN authn.login_transaction.id IS '内部 UUID 主键；仅用于数据库关系，不作为跨域公开标识。';
COMMENT ON COLUMN authn.login_transaction.public_id IS '不可复用的公开稳定标识；插入时登记到 core.public_id_ledger。';
COMMENT ON COLUMN authn.login_transaction.client_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN authn.login_transaction.business_line_id IS '业务线隔离键；关联 org.business_line，用于业务线范围隔离。';
COMMENT ON COLUMN authn.login_transaction.tenant_id IS '租户隔离键；全零 UUID 表示平台范围，应用查询必须显式携带可信租户上下文。';
COMMENT ON COLUMN authn.login_transaction.user_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN authn.login_transaction.login_transaction_state IS '显式状态当前值；合法取值见 CHECK，完整状态转换由 .NET 领域策略执行。';
COMMENT ON COLUMN authn.login_transaction.profile_code IS '稳定机器可读代码；展示文本由资源或目录解析。';
COMMENT ON COLUMN authn.login_transaction.response_type IS '对象类别判别字段；允许值由 CHECK 或对应注册表限定。';
COMMENT ON COLUMN authn.login_transaction.requested_scopes IS '代码或引用集合；写入前去重、校验 allowlist，并满足表约束。';
COMMENT ON COLUMN authn.login_transaction.requested_resources IS '代码或引用集合；写入前去重、校验 allowlist，并满足表约束。';
COMMENT ON COLUMN authn.login_transaction.authorization_details IS '版本化结构化扩展数据；必须由 .NET 按对应 JSON Schema 校验，不得替代核心状态或外键。';
COMMENT ON COLUMN authn.login_transaction.redirect_uri IS '受控 URI；写入前必须执行协议、主机、重定向与 SSRF 安全校验。';
COMMENT ON COLUMN authn.login_transaction.state_hash IS '不可逆摘要；用于等值匹配、幂等、完整性或最小化证据，不保存原始敏感值。';
COMMENT ON COLUMN authn.login_transaction.nonce_hash IS '不可逆摘要；用于等值匹配、幂等、完整性或最小化证据，不保存原始敏感值。';
COMMENT ON COLUMN authn.login_transaction.code_challenge IS 'authn.login_transaction.code_challenge 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN authn.login_transaction.code_challenge_method IS 'authn.login_transaction.code_challenge_method 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN authn.login_transaction.prompt_values IS '代码或引用集合；写入前去重、校验 allowlist，并满足表约束。';
COMMENT ON COLUMN authn.login_transaction.requested_acr_values IS '代码或引用集合；写入前去重、校验 allowlist，并满足表约束。';
COMMENT ON COLUMN authn.login_transaction.required_aal IS 'authn.login_transaction.required_aal 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN authn.login_transaction.achieved_aal IS 'authn.login_transaction.achieved_aal 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN authn.login_transaction.achieved_ial IS 'authn.login_transaction.achieved_ial 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN authn.login_transaction.achieved_acr IS 'authn.login_transaction.achieved_acr 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN authn.login_transaction.achieved_amr IS '代码或引用集合；写入前去重、校验 allowlist，并满足表约束。';
COMMENT ON COLUMN authn.login_transaction.risk_level IS 'authn.login_transaction.risk_level 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN authn.login_transaction.risk_assessment_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN authn.login_transaction.remaining_steps IS '代码或引用集合；写入前去重、校验 allowlist，并满足表约束。';
COMMENT ON COLUMN authn.login_transaction.pending_consent_scopes IS '代码或引用集合；写入前去重、校验 allowlist，并满足表约束。';
COMMENT ON COLUMN authn.login_transaction.ip_hash IS '不可逆摘要；用于等值匹配、幂等、完整性或最小化证据，不保存原始敏感值。';
COMMENT ON COLUMN authn.login_transaction.user_agent_hash IS '不可逆摘要；用于等值匹配、幂等、完整性或最小化证据，不保存原始敏感值。';
COMMENT ON COLUMN authn.login_transaction.device_fingerprint_hash IS '不可逆摘要；用于等值匹配、幂等、完整性或最小化证据，不保存原始敏感值。';
COMMENT ON COLUMN authn.login_transaction.authenticated_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN authn.login_transaction.completed_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN authn.login_transaction.consumed_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN authn.login_transaction.abandoned_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN authn.login_transaction.block_reason_code IS '稳定机器可读代码；展示文本由资源或目录解析。';
COMMENT ON COLUMN authn.login_transaction.expires_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN authn.login_transaction.created_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN authn.login_transaction.updated_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN authn.login_transaction.row_version IS '乐观并发版本；更新必须使用原值 compare-and-set，成功后由数据库单调递增。';
COMMENT ON COLUMN authn.login_transaction.identified_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN authn.login_transaction.partially_authenticated_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN authn.login_transaction.pending_consent_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN authn.login_transaction.expired_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN authn.login_transaction.blocked_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN authn.login_transaction.abandon_reason_code IS '稳定机器可读代码；展示文本由资源或目录解析。';
COMMENT ON COLUMN authn.login_factor.id IS '内部 UUID 主键；仅用于数据库关系，不作为跨域公开标识。';
COMMENT ON COLUMN authn.login_factor.login_transaction_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN authn.login_factor.authenticator_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN authn.login_factor.challenge_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN authn.login_factor.amr_value IS 'authn.login_factor.amr_value 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN authn.login_factor.factor_category IS 'authn.login_factor.factor_category 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN authn.login_factor.achieved_aal IS 'authn.login_factor.achieved_aal 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN authn.login_factor.phishing_resistant IS 'authn.login_factor.phishing_resistant 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN authn.login_factor.user_verified IS 'authn.login_factor.user_verified 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN authn.login_factor.backup_eligible IS 'authn.login_factor.backup_eligible 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN authn.login_factor.backup_state IS '显式状态当前值；合法取值见 CHECK，完整状态转换由 .NET 领域策略执行。';
COMMENT ON COLUMN authn.login_factor.hardware_protected IS 'authn.login_factor.hardware_protected 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN authn.login_factor.attestation_level IS 'authn.login_factor.attestation_level 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN authn.login_factor.assurance_rule_version IS '对象、策略或源数据的显式版本；不得以不可信客户端时间戳替代。';
COMMENT ON COLUMN authn.login_factor.evidence IS '版本化结构化扩展数据；必须由 .NET 按对应 JSON Schema 校验，不得替代核心状态或外键。';
COMMENT ON COLUMN authn.login_factor.verified_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN authn.verification_challenge.id IS '内部 UUID 主键；仅用于数据库关系，不作为跨域公开标识。';
COMMENT ON COLUMN authn.verification_challenge.public_id IS '不可复用的公开稳定标识；插入时登记到 core.public_id_ledger。';
COMMENT ON COLUMN authn.verification_challenge.challenge_purpose IS 'authn.verification_challenge.challenge_purpose 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN authn.verification_challenge.challenge_state IS '显式状态当前值；合法取值见 CHECK，完整状态转换由 .NET 领域策略执行。';
COMMENT ON COLUMN authn.verification_challenge.client_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN authn.verification_challenge.login_transaction_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN authn.verification_challenge.user_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN authn.verification_challenge.target_identifier_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN authn.verification_challenge.target_blind_index IS '带版本的密钥化盲索引；只用于受控等值检索。';
COMMENT ON COLUMN authn.verification_challenge.delivery_channel IS 'authn.verification_challenge.delivery_channel 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN authn.verification_challenge.challenge_hash IS '不可逆摘要；用于等值匹配、幂等、完整性或最小化证据，不保存原始敏感值。';
COMMENT ON COLUMN authn.verification_challenge.attempt_count IS '非负计数器；并发更新使用原子 SQL 或乐观并发控制。';
COMMENT ON COLUMN authn.verification_challenge.max_attempts IS '非负计数器；并发更新使用原子 SQL 或乐观并发控制。';
COMMENT ON COLUMN authn.verification_challenge.verified_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN authn.verification_challenge.consumed_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN authn.verification_challenge.locked_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN authn.verification_challenge.superseded_by_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN authn.verification_challenge.expires_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN authn.verification_challenge.created_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN authn.verification_challenge.updated_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN authn.verification_challenge.row_version IS '乐观并发版本；更新必须使用原值 compare-and-set，成功后由数据库单调递增。';
COMMENT ON COLUMN authn.verification_challenge.hash_algorithm IS '显式算法标识；必须来自环境算法 allowlist，禁止弱算法与静默降级。';
COMMENT ON COLUMN authn.verification_challenge.hash_key_version IS '生成密文、HMAC 或盲索引所用密钥版本；轮换时保留可验证窗口。';
COMMENT ON COLUMN authn.verification_challenge.risk_assessment_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN authn.verification_challenge.risk_context_hash IS '不可逆摘要；用于等值匹配、幂等、完整性或最小化证据，不保存原始敏感值。';
COMMENT ON COLUMN authn.verification_challenge.expired_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN authn.verification_challenge.cancelled_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN authn.verification_challenge.state_reason_code IS '稳定机器可读代码；展示文本由资源或目录解析。';
COMMENT ON COLUMN authn.device_authorization.id IS '内部 UUID 主键；仅用于数据库关系，不作为跨域公开标识。';
COMMENT ON COLUMN authn.device_authorization.client_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN authn.device_authorization.tenant_id IS '租户隔离键；全零 UUID 表示平台范围，应用查询必须显式携带可信租户上下文。';
COMMENT ON COLUMN authn.device_authorization.device_code_hash IS '不可逆摘要；用于等值匹配、幂等、完整性或最小化证据，不保存原始敏感值。';
COMMENT ON COLUMN authn.device_authorization.user_code_hash IS '不可逆摘要；用于等值匹配、幂等、完整性或最小化证据，不保存原始敏感值。';
COMMENT ON COLUMN authn.device_authorization.requested_scopes IS '代码或引用集合；写入前去重、校验 allowlist，并满足表约束。';
COMMENT ON COLUMN authn.device_authorization.requested_resources IS '代码或引用集合；写入前去重、校验 allowlist，并满足表约束。';
COMMENT ON COLUMN authn.device_authorization.authorization_details IS '版本化结构化扩展数据；必须由 .NET 按对应 JSON Schema 校验，不得替代核心状态或外键。';
COMMENT ON COLUMN authn.device_authorization.polling_interval_seconds IS '以秒为单位的显式时长；有效范围由安全策略及表约束限制。';
COMMENT ON COLUMN authn.device_authorization.poll_count IS '非负计数器；并发更新使用原子 SQL 或乐观并发控制。';
COMMENT ON COLUMN authn.device_authorization.slow_down_count IS '非负计数器；并发更新使用原子 SQL 或乐观并发控制。';
COMMENT ON COLUMN authn.device_authorization.last_polled_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN authn.device_authorization.authorized_user_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN authn.device_authorization.login_transaction_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN authn.device_authorization.grant_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN authn.device_authorization.approved_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN authn.device_authorization.denied_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN authn.device_authorization.consumed_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN authn.device_authorization.expires_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN authn.device_authorization.created_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN authn.device_authorization.updated_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN authn.device_authorization.row_version IS '乐观并发版本；更新必须使用原值 compare-and-set，成功后由数据库单调递增。';
COMMENT ON COLUMN authn.device_authorization.device_code_hash_algorithm IS '显式算法标识；必须来自环境算法 allowlist，禁止弱算法与静默降级。';
COMMENT ON COLUMN authn.device_authorization.user_code_hash_algorithm IS '显式算法标识；必须来自环境算法 allowlist，禁止弱算法与静默降级。';
COMMENT ON COLUMN authn.device_authorization.user_code_hash_key_version IS '生成密文、HMAC 或盲索引所用密钥版本；轮换时保留可验证窗口。';

COMMENT ON CONSTRAINT pk_authenticator ON authn.authenticator IS '主键约束：唯一标识 authn.authenticator 记录。';
COMMENT ON CONSTRAINT fk_authenticator_replaced_by ON authn.authenticator IS '外键约束：authn.authenticator 的 replaced_by_id 必须引用 authn.authenticator；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT ck_authenticator_type ON authn.authenticator IS '检查约束：限制 authn.authenticator 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_authenticator_state ON authn.authenticator IS '检查约束：限制 authn.authenticator 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_authenticator_aal ON authn.authenticator IS '检查约束：限制 authn.authenticator 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_authenticator_passkey_material ON authn.authenticator IS '检查约束：限制 authn.authenticator 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_authenticator_totp_material ON authn.authenticator IS '检查约束：限制 authn.authenticator 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_authenticator_syncable_aal ON authn.authenticator IS '检查约束：限制 authn.authenticator 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_authenticator_active ON authn.authenticator IS '检查约束：限制 authn.authenticator 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_authenticator_replaced ON authn.authenticator IS '检查约束：限制 authn.authenticator 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_authenticator_expired_state ON authn.authenticator IS '检查约束：限制 authn.authenticator 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_authenticator_compromised_state ON authn.authenticator IS '检查约束：限制 authn.authenticator 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_authenticator_revoked_state ON authn.authenticator IS '检查约束：限制 authn.authenticator 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT pk_password_credential ON authn.password_credential IS '主键约束：唯一标识 authn.password_credential 记录。';
COMMENT ON CONSTRAINT uq_password_credential_authenticator ON authn.password_credential IS '唯一约束：保证 authenticator_id 在 authn.password_credential 范围内不重复。';
COMMENT ON CONSTRAINT fk_password_credential_authenticator ON authn.password_credential IS '外键约束：authn.password_credential 的 authenticator_id 必须引用 authn.authenticator；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT ck_password_credential_phc ON authn.password_credential IS '检查约束：限制 authn.password_credential 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_password_credential_algorithm ON authn.password_credential IS '检查约束：限制 authn.password_credential 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT pk_password_history ON authn.password_history IS '主键约束：唯一标识 authn.password_history 记录。';
COMMENT ON CONSTRAINT ck_password_history_window ON authn.password_history IS '检查约束：限制 authn.password_history 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT pk_recovery_code_batch ON authn.recovery_code_batch IS '主键约束：唯一标识 authn.recovery_code_batch 记录。';
COMMENT ON CONSTRAINT ck_recovery_code_batch_state ON authn.recovery_code_batch IS '检查约束：限制 authn.recovery_code_batch 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT pk_recovery_code ON authn.recovery_code IS '主键约束：唯一标识 authn.recovery_code 记录。';
COMMENT ON CONSTRAINT uq_recovery_code_hash ON authn.recovery_code IS '唯一约束：保证 code_hash 在 authn.recovery_code 范围内不重复。';
COMMENT ON CONSTRAINT fk_recovery_code_batch ON authn.recovery_code IS '外键约束：authn.recovery_code 的 batch_id 必须引用 authn.recovery_code_batch；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT ck_recovery_code_hash ON authn.recovery_code IS '检查约束：限制 authn.recovery_code 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_recovery_code_hash_profile ON authn.recovery_code IS '检查约束：限制 authn.recovery_code 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT pk_login_transaction ON authn.login_transaction IS '主键约束：唯一标识 authn.login_transaction 记录。';
COMMENT ON CONSTRAINT uq_login_transaction_public_id ON authn.login_transaction IS '唯一约束：保证 public_id 在 authn.login_transaction 范围内不重复。';
COMMENT ON CONSTRAINT ck_login_transaction_state ON authn.login_transaction IS '检查约束：限制 authn.login_transaction 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_login_transaction_pkce ON authn.login_transaction IS '检查约束：限制 authn.login_transaction 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_login_transaction_response ON authn.login_transaction IS '检查约束：限制 authn.login_transaction 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_login_transaction_aal ON authn.login_transaction IS '检查约束：限制 authn.login_transaction 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_login_transaction_identified ON authn.login_transaction IS '检查约束：限制 authn.login_transaction 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_login_transaction_authenticated ON authn.login_transaction IS '检查约束：限制 authn.login_transaction 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_login_transaction_completed ON authn.login_transaction IS '检查约束：限制 authn.login_transaction 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_login_transaction_blocked ON authn.login_transaction IS '检查约束：限制 authn.login_transaction 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_login_transaction_ttl ON authn.login_transaction IS '检查约束：限制 authn.login_transaction 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_login_transaction_expired ON authn.login_transaction IS '检查约束：限制 authn.login_transaction 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_login_transaction_abandoned ON authn.login_transaction IS '检查约束：限制 authn.login_transaction 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_login_transaction_blocked_time ON authn.login_transaction IS '检查约束：限制 authn.login_transaction 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT pk_login_factor ON authn.login_factor IS '主键约束：唯一标识 authn.login_factor 记录。';
COMMENT ON CONSTRAINT fk_login_factor_transaction ON authn.login_factor IS '外键约束：authn.login_factor 的 login_transaction_id 必须引用 authn.login_transaction；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT fk_login_factor_authenticator ON authn.login_factor IS '外键约束：authn.login_factor 的 authenticator_id 必须引用 authn.authenticator；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT ck_login_factor_aal ON authn.login_factor IS '检查约束：限制 authn.login_factor 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT fk_login_factor_challenge ON authn.login_factor IS '外键约束：authn.login_factor 的 challenge_id 必须引用 authn.verification_challenge；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT uq_login_factor ON authn.login_factor IS '唯一约束：保证 login_transaction_id、amr_value、authenticator_id 在 authn.login_factor 范围内不重复。';
COMMENT ON CONSTRAINT pk_verification_challenge ON authn.verification_challenge IS '主键约束：唯一标识 authn.verification_challenge 记录。';
COMMENT ON CONSTRAINT uq_verification_challenge_public_id ON authn.verification_challenge IS '唯一约束：保证 public_id 在 authn.verification_challenge 范围内不重复。';
COMMENT ON CONSTRAINT uq_verification_challenge_hash ON authn.verification_challenge IS '唯一约束：保证 challenge_hash 在 authn.verification_challenge 范围内不重复。';
COMMENT ON CONSTRAINT fk_verification_challenge_tx ON authn.verification_challenge IS '外键约束：authn.verification_challenge 的 login_transaction_id 必须引用 authn.login_transaction；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT fk_verification_challenge_superseded ON authn.verification_challenge IS '外键约束：authn.verification_challenge 的 superseded_by_id 必须引用 authn.verification_challenge；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT ck_verification_challenge_purpose ON authn.verification_challenge IS '检查约束：限制 authn.verification_challenge 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_verification_challenge_state ON authn.verification_challenge IS '检查约束：限制 authn.verification_challenge 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_verification_challenge_channel ON authn.verification_challenge IS '检查约束：限制 authn.verification_challenge 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_verification_challenge_hash ON authn.verification_challenge IS '检查约束：限制 authn.verification_challenge 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_verification_challenge_attempt ON authn.verification_challenge IS '检查约束：限制 authn.verification_challenge 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_verification_challenge_consumed ON authn.verification_challenge IS '检查约束：限制 authn.verification_challenge 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_verification_challenge_ttl ON authn.verification_challenge IS '检查约束：限制 authn.verification_challenge 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_challenge_hash_profile ON authn.verification_challenge IS '检查约束：限制 authn.verification_challenge 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_verification_challenge_risk_hash ON authn.verification_challenge IS '检查约束：限制 authn.verification_challenge 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_verification_challenge_target ON authn.verification_challenge IS '检查约束：限制 authn.verification_challenge 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_verification_challenge_verified ON authn.verification_challenge IS '检查约束：限制 authn.verification_challenge 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_verification_challenge_expired ON authn.verification_challenge IS '检查约束：限制 authn.verification_challenge 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_verification_challenge_locked ON authn.verification_challenge IS '检查约束：限制 authn.verification_challenge 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_verification_challenge_cancelled ON authn.verification_challenge IS '检查约束：限制 authn.verification_challenge 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_verification_challenge_superseded ON authn.verification_challenge IS '检查约束：限制 authn.verification_challenge 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT pk_device_authorization ON authn.device_authorization IS '主键约束：唯一标识 authn.device_authorization 记录。';
COMMENT ON CONSTRAINT uq_device_authorization_device_code ON authn.device_authorization IS '唯一约束：保证 device_code_hash 在 authn.device_authorization 范围内不重复。';
COMMENT ON CONSTRAINT uq_device_authorization_user_code ON authn.device_authorization IS '唯一约束：保证 user_code_hash 在 authn.device_authorization 范围内不重复。';
COMMENT ON CONSTRAINT fk_device_authorization_tx ON authn.device_authorization IS '外键约束：authn.device_authorization 的 login_transaction_id 必须引用 authn.login_transaction；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT ck_device_authorization_hash ON authn.device_authorization IS '检查约束：限制 authn.device_authorization 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_device_authorization_interval ON authn.device_authorization IS '检查约束：限制 authn.device_authorization 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_device_authorization_poll ON authn.device_authorization IS '检查约束：限制 authn.device_authorization 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_device_authorization_outcome ON authn.device_authorization IS '检查约束：限制 authn.device_authorization 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_device_authorization_approval ON authn.device_authorization IS '检查约束：限制 authn.device_authorization 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_device_authorization_consume ON authn.device_authorization IS '检查约束：限制 authn.device_authorization 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_device_authorization_ttl ON authn.device_authorization IS '检查约束：限制 authn.device_authorization 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_device_code_hash_profile ON authn.device_authorization IS '检查约束：限制 authn.device_authorization 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_user_code_hash_profile ON authn.device_authorization IS '检查约束：限制 authn.device_authorization 的字段取值或组合满足结构与安全底线。';

COMMENT ON INDEX authn.ux_authenticator_credential_id IS '查询索引：优化 authn.authenticator 按 credential_public_id 的访问，仅覆盖 WHERE 条件命中的记录。';
COMMENT ON INDEX authn.ux_recovery_code_batch_active IS '查询索引：优化 authn.recovery_code_batch 按 user_id 的访问，仅覆盖 WHERE 条件命中的记录。';
COMMENT ON INDEX authn.ux_challenge_active_target IS '查询索引：优化 authn.verification_challenge 按 challenge_purpose、client_id、target_blind_index 的访问，仅覆盖 WHERE 条件命中的记录。';
COMMENT ON INDEX authn.ix_login_transaction_expiry IS '查询索引：优化 authn.login_transaction 按 expires_at 的访问，仅覆盖 WHERE 条件命中的记录。';
COMMENT ON INDEX authn.ix_device_authorization_expiry IS '查询索引：优化 authn.device_authorization 按 expires_at 的访问，仅覆盖 WHERE 条件命中的记录。';
COMMENT ON INDEX authn.pk_authenticator IS '约束 pk_authenticator 的支撑唯一索引。';
COMMENT ON INDEX authn.pk_password_credential IS '约束 pk_password_credential 的支撑唯一索引。';
COMMENT ON INDEX authn.uq_password_credential_authenticator IS '约束 uq_password_credential_authenticator 的支撑唯一索引。';
COMMENT ON INDEX authn.pk_password_history IS '约束 pk_password_history 的支撑唯一索引。';
COMMENT ON INDEX authn.pk_recovery_code_batch IS '约束 pk_recovery_code_batch 的支撑唯一索引。';
COMMENT ON INDEX authn.pk_recovery_code IS '约束 pk_recovery_code 的支撑唯一索引。';
COMMENT ON INDEX authn.uq_recovery_code_hash IS '约束 uq_recovery_code_hash 的支撑唯一索引。';
COMMENT ON INDEX authn.pk_login_transaction IS '约束 pk_login_transaction 的支撑唯一索引。';
COMMENT ON INDEX authn.uq_login_transaction_public_id IS '约束 uq_login_transaction_public_id 的支撑唯一索引。';
COMMENT ON INDEX authn.pk_login_factor IS '约束 pk_login_factor 的支撑唯一索引。';
COMMENT ON INDEX authn.uq_login_factor IS '约束 uq_login_factor 的支撑唯一索引。';
COMMENT ON INDEX authn.pk_verification_challenge IS '约束 pk_verification_challenge 的支撑唯一索引。';
COMMENT ON INDEX authn.uq_verification_challenge_public_id IS '约束 uq_verification_challenge_public_id 的支撑唯一索引。';
COMMENT ON INDEX authn.uq_verification_challenge_hash IS '约束 uq_verification_challenge_hash 的支撑唯一索引。';
COMMENT ON INDEX authn.pk_device_authorization IS '约束 pk_device_authorization 的支撑唯一索引。';
COMMENT ON INDEX authn.uq_device_authorization_device_code IS '约束 uq_device_authorization_device_code 的支撑唯一索引。';
COMMENT ON INDEX authn.uq_device_authorization_user_code IS '约束 uq_device_authorization_user_code 的支撑唯一索引。';
COMMENT ON INDEX authn.ix_fk_authenticator_replaced_by_id IS '查询索引：优化 authn.authenticator 按 replaced_by_id 的访问。';
COMMENT ON INDEX authn.ix_fk_recovery_code_batch_id IS '查询索引：优化 authn.recovery_code 按 batch_id 的访问。';
COMMENT ON INDEX authn.ix_fk_login_factor_authenticator_id IS '查询索引：优化 authn.login_factor 按 authenticator_id 的访问。';
COMMENT ON INDEX authn.ix_fk_login_factor_challenge_id IS '查询索引：优化 authn.login_factor 按 challenge_id 的访问。';
COMMENT ON INDEX authn.ix_fk_verification_challenge_login_transaction_id IS '查询索引：优化 authn.verification_challenge 按 login_transaction_id 的访问。';
COMMENT ON INDEX authn.ix_fk_verification_challenge_superseded_by_id IS '查询索引：优化 authn.verification_challenge 按 superseded_by_id 的访问。';
COMMENT ON INDEX authn.ix_fk_device_authorization_login_transaction_id IS '查询索引：优化 authn.device_authorization 按 login_transaction_id 的访问。';

