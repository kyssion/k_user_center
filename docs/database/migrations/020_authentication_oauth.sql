-- =============================================================================
-- 020_authentication_oauth.sql
-- 认证器、Login Transaction、Device Grant、Client、Session、Grant、Token 与撤销
-- =============================================================================

BEGIN;
SET LOCAL lock_timeout = '10s';
SET LOCAL statement_timeout = '5min';

CREATE TABLE authn.authenticator (
    id                       uuid        NOT NULL DEFAULT gen_random_uuid(),
    user_id                  uuid        NOT NULL,
    authenticator_type       text        NOT NULL,
    authenticator_state      text        NOT NULL DEFAULT 'PENDING',
    display_name             text        NULL,
    credential_public_id     bytea       NULL,
    public_key_cose          bytea       NULL,
    secret_cipher            bytea       NULL,
    secret_key_version       integer     NULL,
    aaguid                   uuid        NULL,
    sign_count               bigint      NULL,
    user_verification        boolean     NOT NULL DEFAULT false,
    phishing_resistant       boolean     NOT NULL DEFAULT false,
    backup_eligible          boolean     NULL,
    backup_state             boolean     NULL,
    syncable                 boolean     NOT NULL DEFAULT false,
    hardware_protected       boolean     NOT NULL DEFAULT false,
    attestation_trust_level  text        NULL,
    aal_ceiling              text        NOT NULL DEFAULT 'AAL1',
    registered_at            timestamptz NULL,
    suspended_at             timestamptz NULL,
    locked_at                timestamptz NULL,
    compromised_at           timestamptz NULL,
    revoked_at               timestamptz NULL,
    replaced_by_id           uuid        NULL,
    expires_at               timestamptz NULL,
    last_used_at             timestamptz NULL,
    created_at               timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at               timestamptz NOT NULL DEFAULT clock_timestamp(),
    row_version              bigint      NOT NULL DEFAULT 1,
    CONSTRAINT pk_authenticator PRIMARY KEY (id),
    CONSTRAINT fk_authenticator_user FOREIGN KEY (user_id) REFERENCES iam.user_account(id),
    CONSTRAINT fk_authenticator_replaced_by FOREIGN KEY (replaced_by_id) REFERENCES authn.authenticator(id),
    CONSTRAINT ck_authenticator_type CHECK (authenticator_type IN ('PASSWORD', 'PASSKEY', 'SECURITY_KEY', 'TOTP', 'SMS_OTP', 'EMAIL_OTP', 'RECOVERY_CODE', 'FEDERATED')),
    CONSTRAINT ck_authenticator_state CHECK (authenticator_state IN ('PENDING', 'ACTIVE', 'SUSPENDED', 'LOCKED', 'EXPIRED', 'COMPROMISED', 'REVOKED', 'REPLACED')),
    CONSTRAINT ck_authenticator_aal CHECK (aal_ceiling IN ('AAL1', 'AAL2', 'AAL3')),
    CONSTRAINT ck_authenticator_passkey_material CHECK (authenticator_type NOT IN ('PASSKEY', 'SECURITY_KEY') OR (credential_public_id IS NOT NULL AND public_key_cose IS NOT NULL)),
    CONSTRAINT ck_authenticator_totp_material CHECK (authenticator_type <> 'TOTP' OR (secret_cipher IS NOT NULL AND secret_key_version IS NOT NULL)),
    CONSTRAINT ck_authenticator_syncable_aal CHECK (NOT syncable OR aal_ceiling <> 'AAL3'),
    CONSTRAINT ck_authenticator_active CHECK (authenticator_state <> 'ACTIVE' OR registered_at IS NOT NULL),
    CONSTRAINT ck_authenticator_replaced CHECK ((authenticator_state = 'REPLACED') = (replaced_by_id IS NOT NULL))
);
COMMENT ON TABLE authn.authenticator IS 'CAP-AUTH-011 至 018 / REQ-AUTH-017/018：认证器生命周期、WebAuthn 证据、同步/备份属性和 AAL 上限。';

CREATE TABLE authn.password_credential (
    user_id                  uuid        NOT NULL,
    authenticator_id         uuid        NOT NULL,
    password_hash            text        NOT NULL,
    password_hash_algorithm  text        NOT NULL,
    password_hash_parameters jsonb       NOT NULL,
    password_changed_at      timestamptz NOT NULL DEFAULT clock_timestamp(),
    must_change              boolean     NOT NULL DEFAULT false,
    compromised_at           timestamptz NULL,
    created_at               timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at               timestamptz NOT NULL DEFAULT clock_timestamp(),
    row_version              bigint      NOT NULL DEFAULT 1,
    CONSTRAINT pk_password_credential PRIMARY KEY (user_id),
    CONSTRAINT uq_password_credential_authenticator UNIQUE (authenticator_id),
    CONSTRAINT fk_password_credential_user FOREIGN KEY (user_id) REFERENCES iam.user_account(id),
    CONSTRAINT fk_password_credential_authenticator FOREIGN KEY (authenticator_id) REFERENCES authn.authenticator(id),
    CONSTRAINT ck_password_credential_phc CHECK (password_hash LIKE '$%'),
    CONSTRAINT ck_password_credential_algorithm CHECK (password_hash_algorithm IN ('ARGON2ID', 'SCRYPT', 'PBKDF2', 'BCRYPT'))
);
COMMENT ON TABLE authn.password_credential IS 'CAP-AUTH-004/005：密码只保存经批准的加盐自适应或内存困难哈希及参数版本，禁止快速摘要直接存储。';

CREATE TABLE authn.password_history (
    id                       uuid        NOT NULL DEFAULT gen_random_uuid(),
    user_id                  uuid        NOT NULL,
    password_hash            text        NOT NULL,
    password_hash_algorithm  text        NOT NULL,
    password_hash_parameters jsonb       NOT NULL,
    replaced_at              timestamptz NOT NULL DEFAULT clock_timestamp(),
    retain_until             timestamptz NOT NULL,
    CONSTRAINT pk_password_history PRIMARY KEY (id),
    CONSTRAINT fk_password_history_user FOREIGN KEY (user_id) REFERENCES iam.user_account(id),
    CONSTRAINT ck_password_history_window CHECK (retain_until > replaced_at)
);
COMMENT ON TABLE authn.password_history IS 'CAP-AUTH-005：受保留策略约束的历史口令哈希，用于阻断短期复用；不保存明文。';

CREATE TABLE authn.recovery_code_batch (
    id                uuid        NOT NULL DEFAULT gen_random_uuid(),
    user_id           uuid        NOT NULL,
    batch_state       text        NOT NULL DEFAULT 'ACTIVE',
    generated_at      timestamptz NOT NULL DEFAULT clock_timestamp(),
    expires_at        timestamptz NULL,
    revoked_at        timestamptz NULL,
    CONSTRAINT pk_recovery_code_batch PRIMARY KEY (id),
    CONSTRAINT fk_recovery_code_batch_user FOREIGN KEY (user_id) REFERENCES iam.user_account(id),
    CONSTRAINT ck_recovery_code_batch_state CHECK (batch_state IN ('ACTIVE', 'EXHAUSTED', 'REVOKED', 'EXPIRED'))
);
COMMENT ON TABLE authn.recovery_code_batch IS 'CAP-AUTH-017：恢复码批次状态、轮换、失效与耗尽证据。';

CREATE TABLE authn.recovery_code (
    id             uuid        NOT NULL DEFAULT gen_random_uuid(),
    batch_id       uuid        NOT NULL,
    code_hash      bytea       NOT NULL,
    used_at        timestamptz NULL,
    created_at     timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT pk_recovery_code PRIMARY KEY (id),
    CONSTRAINT uq_recovery_code_hash UNIQUE (code_hash),
    CONSTRAINT fk_recovery_code_batch FOREIGN KEY (batch_id) REFERENCES authn.recovery_code_batch(id) ON DELETE CASCADE,
    CONSTRAINT ck_recovery_code_hash CHECK (octet_length(code_hash) = 32)
);
COMMENT ON TABLE authn.recovery_code IS 'CAP-AUTH-017：单次使用恢复码的不可逆哈希和消费时间。';

CREATE TABLE oauth.application (
    id                   uuid        NOT NULL DEFAULT gen_random_uuid(),
    public_id            text        NOT NULL,
    business_line_id     uuid        NOT NULL,
    display_name         text        NOT NULL,
    application_type     text        NOT NULL,
    application_state    text        NOT NULL DEFAULT 'DRAFT',
    owner_ref            text        NOT NULL,
    contact_ref          text        NULL,
    created_at           timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at           timestamptz NOT NULL DEFAULT clock_timestamp(),
    row_version          bigint      NOT NULL DEFAULT 1,
    CONSTRAINT pk_application PRIMARY KEY (id),
    CONSTRAINT uq_application_public_id UNIQUE (public_id),
    CONSTRAINT ck_application_type CHECK (application_type IN ('WEB_SERVER', 'SPA_BFF', 'NATIVE_APP', 'MINI_PROGRAM', 'SERVER_TO_SERVER', 'INPUT_CONSTRAINED_DEVICE', 'ADMIN_CONSOLE')),
    CONSTRAINT ck_application_state CHECK (application_state IN ('DRAFT', 'ACTIVE', 'SUSPENDED', 'RETIRED'))
);
COMMENT ON TABLE oauth.application IS 'CAP-TENANT-002：应用登记及负责人；一个应用可对应多个环境和安全 Profile 的 Client。';

CREATE TABLE oauth.client (
    id                           uuid        NOT NULL DEFAULT gen_random_uuid(),
    public_id                    text        NOT NULL,
    application_id               uuid        NOT NULL,
    business_line_id             uuid        NOT NULL,
    tenant_id                    uuid        NOT NULL DEFAULT '00000000-0000-0000-0000-000000000000',
    environment                  text        NOT NULL,
    client_state                 text        NOT NULL DEFAULT 'DRAFT',
    client_kind                  text        NOT NULL,
    display_name                 text        NOT NULL,
    profile_code                 text        NOT NULL,
    profile_version              integer     NOT NULL,
    token_endpoint_auth_method   text        NOT NULL DEFAULT 'none',
    allowed_grant_types          text[]      NOT NULL,
    allowed_scopes               text[]      NOT NULL DEFAULT '{}',
    allowed_resources            text[]      NOT NULL DEFAULT '{}',
    subject_mode                 text        NOT NULL DEFAULT 'PAIRWISE_PER_CLIENT',
    access_token_format          text        NOT NULL DEFAULT 'JWT',
    id_token_signed_alg          text        NOT NULL DEFAULT 'ES256',
    require_par                  boolean     NOT NULL DEFAULT false,
    require_sender_constrained   boolean     NOT NULL DEFAULT false,
    sender_constraint_method     text        NULL,
    consent_required             boolean     NOT NULL DEFAULT false,
    sso_domain_boundary          text        NOT NULL,
    owner_ref                    text        NOT NULL,
    permission_baseline          jsonb       NOT NULL DEFAULT '{}'::jsonb,
    credential_rotation_policy   jsonb       NOT NULL DEFAULT '{}'::jsonb,
    client_security_epoch        bigint      NOT NULL DEFAULT 1,
    onboarding_report_ref        text        NULL,
    approval_case_id             uuid        NULL,
    reactivation_review_ref      text        NULL,
    approved_at                  timestamptz NULL,
    suspended_at                 timestamptz NULL,
    compromised_at               timestamptz NULL,
    retired_at                   timestamptz NULL,
    expires_at                   timestamptz NULL,
    last_used_at                 timestamptz NULL,
    created_at                   timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at                   timestamptz NOT NULL DEFAULT clock_timestamp(),
    row_version                  bigint      NOT NULL DEFAULT 1,
    CONSTRAINT pk_client PRIMARY KEY (id),
    CONSTRAINT uq_client_public_id UNIQUE (public_id),
    CONSTRAINT fk_client_application FOREIGN KEY (application_id) REFERENCES oauth.application(id),
    CONSTRAINT fk_client_profile FOREIGN KEY (profile_code, profile_version) REFERENCES core.security_profile(profile_code, profile_version),
    CONSTRAINT ck_client_environment CHECK (environment IN ('DEV', 'TEST', 'STAGING', 'PROD')),
    CONSTRAINT ck_client_state CHECK (client_state IN ('DRAFT', 'VALIDATED', 'APPROVED', 'ACTIVE', 'SUSPENDED', 'COMPROMISED', 'RETIRED')),
    CONSTRAINT ck_client_kind CHECK (client_kind IN ('PUBLIC', 'CONFIDENTIAL')),
    CONSTRAINT ck_client_auth_method CHECK (token_endpoint_auth_method IN ('none', 'private_key_jwt', 'tls_client_auth', 'self_signed_tls_client_auth', 'client_secret_basic')),
    CONSTRAINT ck_client_grants CHECK (allowed_grant_types <@ ARRAY['authorization_code', 'refresh_token', 'client_credentials', 'urn:ietf:params:oauth:grant-type:token-exchange', 'urn:ietf:params:oauth:grant-type:device_code']::text[] AND cardinality(allowed_grant_types) > 0),
    CONSTRAINT ck_client_no_weak_grants CHECK (NOT allowed_grant_types && ARRAY['implicit', 'password']::text[]),
    CONSTRAINT ck_client_public_auth CHECK (client_kind <> 'PUBLIC' OR token_endpoint_auth_method = 'none'),
    CONSTRAINT ck_client_device_profile CHECK (NOT ('urn:ietf:params:oauth:grant-type:device_code' = ANY(allowed_grant_types)) OR profile_code = 'SP1-D'),
    CONSTRAINT ck_client_sender CHECK ((sender_constraint_method IS NULL) = (NOT require_sender_constrained) AND (sender_constraint_method IS NULL OR sender_constraint_method IN ('DPOP', 'MTLS'))),
    CONSTRAINT ck_client_subject_mode CHECK (subject_mode IN ('PAIRWISE_PER_CLIENT', 'PAIRWISE_PER_BUSINESS_LINE', 'SHARED_GLOBAL')),
    CONSTRAINT ck_client_token_format CHECK (access_token_format IN ('JWT', 'REFERENCE')),
    CONSTRAINT ck_client_alg CHECK (id_token_signed_alg IN ('ES256', 'ES384', 'PS256', 'RS256', 'EdDSA', 'SM2')),
    CONSTRAINT ck_client_epoch CHECK (client_security_epoch >= 1),
    CONSTRAINT ck_client_active CHECK (client_state <> 'ACTIVE' OR (approved_at IS NOT NULL AND onboarding_report_ref IS NOT NULL AND owner_ref <> '')),
    CONSTRAINT ck_client_reactivation CHECK (reactivation_review_ref IS NULL OR client_state = 'ACTIVE')
);
COMMENT ON TABLE oauth.client IS 'CAP-OAP-001 至 017 / REQ-MACHINE-018：Client Profile、Grant、认证方式、最小权限、轮换、审批、暂停恢复与失陷终态。';

CREATE TABLE oauth.client_uri (
    id             uuid        NOT NULL DEFAULT gen_random_uuid(),
    client_id      uuid        NOT NULL,
    uri_kind       text        NOT NULL,
    uri_value      text        NOT NULL,
    is_loopback    boolean     NOT NULL DEFAULT false,
    created_by_ref text        NOT NULL,
    created_at     timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT pk_client_uri PRIMARY KEY (id),
    CONSTRAINT uq_client_uri UNIQUE (client_id, uri_kind, uri_value),
    CONSTRAINT fk_client_uri_client FOREIGN KEY (client_id) REFERENCES oauth.client(id) ON DELETE CASCADE,
    CONSTRAINT ck_client_uri_kind CHECK (uri_kind IN ('REDIRECT', 'POST_LOGOUT_REDIRECT', 'FRONT_CHANNEL_LOGOUT', 'BACK_CHANNEL_LOGOUT', 'INITIATE_LOGIN')),
    CONSTRAINT ck_client_uri_no_wildcard CHECK (position('*' in uri_value) = 0 AND position('#' in uri_value) = 0),
    CONSTRAINT ck_client_uri_scheme CHECK (uri_value ~ '^https://' OR (is_loopback AND uri_value ~ '^http://(127\.0\.0\.1|\[::1\])(:[0-9]{1,5})?(/.*)?$') OR uri_value ~ '^[a-z][a-z0-9+.-]*:/')
);
COMMENT ON TABLE oauth.client_uri IS 'CAP-OAP-004 / REQ-AUTH-002：精确回调和退出 URI；仅原生应用 loopback 允许 HTTP 动态端口。';

CREATE TABLE oauth.client_credential (
    id                    uuid        NOT NULL DEFAULT gen_random_uuid(),
    client_id             uuid        NOT NULL,
    credential_kind       text        NOT NULL,
    credential_state      text        NOT NULL DEFAULT 'ACTIVE',
    key_id                text        NULL,
    secret_hash           text        NULL,
    public_jwk            jsonb       NULL,
    jwks_uri              text        NULL,
    certificate_thumbprint bytea      NULL,
    algorithm             text        NULL,
    not_before            timestamptz NOT NULL DEFAULT clock_timestamp(),
    not_after             timestamptz NOT NULL,
    rotated_from_id       uuid        NULL,
    revoked_at            timestamptz NULL,
    revoke_reason_code    text        NULL,
    created_at            timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at            timestamptz NOT NULL DEFAULT clock_timestamp(),
    row_version           bigint      NOT NULL DEFAULT 1,
    CONSTRAINT pk_client_credential PRIMARY KEY (id),
    CONSTRAINT uq_client_credential_key UNIQUE (client_id, key_id),
    CONSTRAINT fk_client_credential_client FOREIGN KEY (client_id) REFERENCES oauth.client(id) ON DELETE CASCADE,
    CONSTRAINT fk_client_credential_rotated FOREIGN KEY (rotated_from_id) REFERENCES oauth.client_credential(id),
    CONSTRAINT ck_client_credential_kind CHECK (credential_kind IN ('SECRET_HASH', 'PUBLIC_JWK', 'JWKS_URI', 'MTLS_CERT')),
    CONSTRAINT ck_client_credential_state CHECK (credential_state IN ('ACTIVE', 'GRACE', 'EXPIRED', 'REVOKED')),
    CONSTRAINT ck_client_credential_material CHECK ((credential_kind = 'SECRET_HASH' AND secret_hash LIKE '$%') OR (credential_kind = 'PUBLIC_JWK' AND public_jwk IS NOT NULL AND key_id IS NOT NULL) OR (credential_kind = 'JWKS_URI' AND jwks_uri ~ '^https://') OR (credential_kind = 'MTLS_CERT' AND certificate_thumbprint IS NOT NULL)),
    CONSTRAINT ck_client_credential_window CHECK (not_after > not_before),
    CONSTRAINT ck_client_credential_revoked CHECK ((credential_state = 'REVOKED') = (revoked_at IS NOT NULL))
);
COMMENT ON TABLE oauth.client_credential IS 'REQ-MACHINE-003/015/016：Client secret 哈希、公钥、JWKS URI 或 mTLS 证书指纹及安全轮换窗口。';

CREATE TABLE oauth.api_resource (
    id                     uuid        NOT NULL DEFAULT gen_random_uuid(),
    public_id              text        NOT NULL,
    audience_value         text        NOT NULL,
    display_name           text        NOT NULL,
    business_line_id       uuid        NOT NULL,
    owner_ref              text        NOT NULL,
    resource_state         text        NOT NULL DEFAULT 'DRAFT',
    minimum_profile_code   text        NOT NULL DEFAULT 'SP1',
    revocation_check_mode  text        NOT NULL DEFAULT 'SIGNAL_STREAM',
    supported_obligations  text[]      NOT NULL DEFAULT '{}',
    onboarding_report_ref  text        NULL,
    created_at             timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at             timestamptz NOT NULL DEFAULT clock_timestamp(),
    row_version            bigint      NOT NULL DEFAULT 1,
    CONSTRAINT pk_api_resource PRIMARY KEY (id),
    CONSTRAINT uq_api_resource_public_id UNIQUE (public_id),
    CONSTRAINT uq_api_resource_audience UNIQUE (audience_value),
    CONSTRAINT ck_api_resource_state CHECK (resource_state IN ('DRAFT', 'ACTIVE', 'DEPRECATED', 'RETIRED')),
    CONSTRAINT ck_api_resource_profile CHECK (minimum_profile_code IN ('SP1', 'SP1-D', 'SP2', 'SP3', 'SP4', 'SP5')),
    CONSTRAINT ck_api_resource_revocation CHECK (revocation_check_mode IN ('SIGNAL_STREAM', 'INTROSPECTION', 'SHORT_TTL_ONLY')),
    CONSTRAINT ck_api_resource_active CHECK (resource_state <> 'ACTIVE' OR onboarding_report_ref IS NOT NULL)
);
COMMENT ON TABLE oauth.api_resource IS 'CAP-OAP-013 / REQ-MACHINE-005：Resource、audience、Owner、最小 Profile、撤销校验与 obligation 能力。';

CREATE TABLE oauth.scope_definition (
    scope_code           text        NOT NULL,
    api_resource_id      uuid        NOT NULL,
    display_name         text        NOT NULL,
    description          text        NOT NULL,
    data_classification  text        NOT NULL,
    requires_consent     boolean     NOT NULL DEFAULT true,
    is_sensitive         boolean     NOT NULL DEFAULT false,
    minimum_profile_code text        NOT NULL DEFAULT 'SP1',
    claim_mapping        jsonb       NULL,
    deprecated_at        timestamptz NULL,
    created_at           timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT pk_scope_definition PRIMARY KEY (scope_code),
    CONSTRAINT fk_scope_definition_resource FOREIGN KEY (api_resource_id) REFERENCES oauth.api_resource(id),
    CONSTRAINT fk_scope_definition_classification FOREIGN KEY (data_classification) REFERENCES core.data_classification(classification_code),
    CONSTRAINT ck_scope_definition_code CHECK (scope_code ~ '^[a-z][a-z0-9:._-]{1,127}$'),
    CONSTRAINT ck_scope_definition_profile CHECK (minimum_profile_code IN ('SP1', 'SP1-D', 'SP2', 'SP3', 'SP4', 'SP5')),
    CONSTRAINT ck_scope_definition_sensitive CHECK (NOT is_sensitive OR requires_consent)
);
COMMENT ON TABLE oauth.scope_definition IS 'CAP-AUTHZ-001 / CAP-PRIV-003：Scope 目录、Resource、数据分级、同意要求与 Claim 映射。';

CREATE TABLE authn.login_transaction (
    id                       uuid        NOT NULL DEFAULT gen_random_uuid(),
    public_id                text        NOT NULL,
    client_id                uuid        NOT NULL,
    business_line_id         uuid        NOT NULL,
    tenant_id                uuid        NOT NULL DEFAULT '00000000-0000-0000-0000-000000000000',
    user_id                  uuid        NULL,
    login_transaction_state  text        NOT NULL DEFAULT 'CREATED',
    profile_code             text        NOT NULL,
    response_type            text        NOT NULL DEFAULT 'code',
    requested_scopes         text[]      NOT NULL DEFAULT '{}',
    requested_resources      text[]      NOT NULL DEFAULT '{}',
    authorization_details    jsonb       NULL,
    redirect_uri             text        NOT NULL,
    state_hash               bytea       NULL,
    nonce_hash               bytea       NULL,
    code_challenge           text        NOT NULL,
    code_challenge_method    text        NOT NULL DEFAULT 'S256',
    prompt_values            text[]      NOT NULL DEFAULT '{}',
    requested_acr_values     text[]      NOT NULL DEFAULT '{}',
    required_aal             text        NOT NULL DEFAULT 'AAL1',
    achieved_aal             text        NULL,
    achieved_ial             text        NULL,
    achieved_acr             text        NULL,
    achieved_amr             text[]      NOT NULL DEFAULT '{}',
    risk_level               text        NULL,
    risk_assessment_id       uuid        NULL,
    remaining_steps          jsonb       NOT NULL DEFAULT '[]'::jsonb,
    pending_consent_scopes   text[]      NOT NULL DEFAULT '{}',
    ip_hash                  bytea       NULL,
    user_agent_hash          bytea       NULL,
    device_fingerprint_hash  bytea       NULL,
    authenticated_at         timestamptz NULL,
    completed_at             timestamptz NULL,
    consumed_at              timestamptz NULL,
    abandoned_at             timestamptz NULL,
    block_reason_code        text        NULL,
    expires_at               timestamptz NOT NULL,
    created_at               timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at               timestamptz NOT NULL DEFAULT clock_timestamp(),
    row_version              bigint      NOT NULL DEFAULT 1,
    CONSTRAINT pk_login_transaction PRIMARY KEY (id),
    CONSTRAINT uq_login_transaction_public_id UNIQUE (public_id),
    CONSTRAINT fk_login_transaction_client FOREIGN KEY (client_id) REFERENCES oauth.client(id),
    CONSTRAINT fk_login_transaction_user FOREIGN KEY (user_id) REFERENCES iam.user_account(id),
    CONSTRAINT ck_login_transaction_state CHECK (login_transaction_state IN ('CREATED', 'IDENTIFIED', 'PARTIALLY_AUTHENTICATED', 'AUTHENTICATED', 'PENDING_CONSENT', 'COMPLETED', 'EXPIRED', 'ABANDONED', 'BLOCKED')),
    CONSTRAINT ck_login_transaction_pkce CHECK (code_challenge_method = 'S256' AND length(code_challenge) BETWEEN 43 AND 128),
    CONSTRAINT ck_login_transaction_response CHECK (response_type = 'code'),
    CONSTRAINT ck_login_transaction_aal CHECK (required_aal IN ('AAL1', 'AAL2', 'AAL3') AND (achieved_aal IS NULL OR achieved_aal IN ('AAL1', 'AAL2', 'AAL3'))),
    CONSTRAINT ck_login_transaction_identified CHECK (login_transaction_state IN ('CREATED', 'EXPIRED', 'ABANDONED', 'BLOCKED') OR user_id IS NOT NULL),
    CONSTRAINT ck_login_transaction_authenticated CHECK (login_transaction_state NOT IN ('AUTHENTICATED', 'PENDING_CONSENT', 'COMPLETED') OR (authenticated_at IS NOT NULL AND achieved_aal IS NOT NULL)),
    CONSTRAINT ck_login_transaction_completed CHECK ((login_transaction_state = 'COMPLETED') = (completed_at IS NOT NULL)),
    CONSTRAINT ck_login_transaction_blocked CHECK (login_transaction_state <> 'BLOCKED' OR block_reason_code IS NOT NULL),
    CONSTRAINT ck_login_transaction_ttl CHECK (expires_at > created_at AND expires_at - created_at <= interval '15 minutes')
);
COMMENT ON TABLE authn.login_transaction IS 'CAP-AUTH-021 / INV-G-016：服务端权威登录事务；AUTHENTICATED 后按是否需要 Consent 进入 PENDING_CONSENT 或 COMPLETED。';

CREATE TABLE authn.login_factor (
    id                    uuid        NOT NULL DEFAULT gen_random_uuid(),
    login_transaction_id  uuid        NOT NULL,
    authenticator_id      uuid        NULL,
    challenge_id          uuid        NULL,
    amr_value             text        NOT NULL,
    factor_category       text        NOT NULL,
    achieved_aal          text        NOT NULL,
    phishing_resistant    boolean     NOT NULL,
    user_verified         boolean     NOT NULL,
    backup_eligible       boolean     NULL,
    backup_state          boolean     NULL,
    hardware_protected    boolean     NULL,
    attestation_level     text        NULL,
    assurance_rule_version integer    NOT NULL,
    evidence              jsonb       NOT NULL,
    verified_at           timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT pk_login_factor PRIMARY KEY (id),
    CONSTRAINT uq_login_factor UNIQUE (login_transaction_id, amr_value, authenticator_id),
    CONSTRAINT fk_login_factor_transaction FOREIGN KEY (login_transaction_id) REFERENCES authn.login_transaction(id) ON DELETE CASCADE,
    CONSTRAINT fk_login_factor_authenticator FOREIGN KEY (authenticator_id) REFERENCES authn.authenticator(id),
    CONSTRAINT ck_login_factor_aal CHECK (achieved_aal IN ('AAL1', 'AAL2', 'AAL3'))
);
COMMENT ON TABLE authn.login_factor IS 'REQ-AUTH-017/018：本次认证证据、amr、认证器特征与版本化 AAL 计算结果。';

CREATE TABLE authn.verification_challenge (
    id                    uuid        NOT NULL DEFAULT gen_random_uuid(),
    public_id             text        NOT NULL,
    challenge_purpose     text        NOT NULL,
    challenge_state       text        NOT NULL DEFAULT 'ISSUED',
    client_id             uuid        NOT NULL,
    login_transaction_id  uuid        NULL,
    user_id               uuid        NULL,
    target_identifier_id  uuid        NULL,
    target_blind_index    bytea       NULL,
    delivery_channel      text        NOT NULL,
    challenge_hash        bytea       NOT NULL,
    attempt_count         integer     NOT NULL DEFAULT 0,
    max_attempts          integer     NOT NULL DEFAULT 5,
    verified_at           timestamptz NULL,
    consumed_at           timestamptz NULL,
    locked_at             timestamptz NULL,
    superseded_by_id      uuid        NULL,
    expires_at            timestamptz NOT NULL,
    created_at            timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at            timestamptz NOT NULL DEFAULT clock_timestamp(),
    row_version            bigint      NOT NULL DEFAULT 1,
    CONSTRAINT pk_verification_challenge PRIMARY KEY (id),
    CONSTRAINT uq_verification_challenge_public_id UNIQUE (public_id),
    CONSTRAINT uq_verification_challenge_hash UNIQUE (challenge_hash),
    CONSTRAINT fk_verification_challenge_client FOREIGN KEY (client_id) REFERENCES oauth.client(id),
    CONSTRAINT fk_verification_challenge_tx FOREIGN KEY (login_transaction_id) REFERENCES authn.login_transaction(id),
    CONSTRAINT fk_verification_challenge_user FOREIGN KEY (user_id) REFERENCES iam.user_account(id),
    CONSTRAINT fk_verification_challenge_identifier FOREIGN KEY (target_identifier_id) REFERENCES iam.identifier(id),
    CONSTRAINT fk_verification_challenge_superseded FOREIGN KEY (superseded_by_id) REFERENCES authn.verification_challenge(id),
    CONSTRAINT ck_verification_challenge_purpose CHECK (challenge_purpose IN ('REGISTER', 'LOGIN', 'STEP_UP', 'BIND_IDENTIFIER', 'REBIND_OLD', 'REBIND_NEW', 'PASSWORD_RESET', 'ACCOUNT_RECOVERY', 'DELETE_ACCOUNT', 'DELETE_WITHDRAW', 'WEBAUTHN_REGISTRATION', 'WEBAUTHN_ASSERTION', 'CONSENT_CONFIRM', 'DOMAIN_VERIFY')),
    CONSTRAINT ck_verification_challenge_state CHECK (challenge_state IN ('ISSUED', 'VERIFIED', 'CONSUMED', 'EXPIRED', 'LOCKED', 'CANCELLED')),
    CONSTRAINT ck_verification_challenge_channel CHECK (delivery_channel IN ('SMS', 'EMAIL', 'VOICE', 'PUSH', 'IN_APP', 'NONE')),
    CONSTRAINT ck_verification_challenge_hash CHECK (octet_length(challenge_hash) = 32),
    CONSTRAINT ck_verification_challenge_attempt CHECK (attempt_count >= 0 AND max_attempts BETWEEN 1 AND 5 AND attempt_count <= max_attempts),
    CONSTRAINT ck_verification_challenge_consumed CHECK ((challenge_state = 'CONSUMED') = (consumed_at IS NOT NULL)),
    CONSTRAINT ck_verification_challenge_ttl CHECK (expires_at > created_at AND expires_at - created_at <= interval '5 minutes')
);
COMMENT ON TABLE authn.verification_challenge IS 'REQ-AUTH-013 至 015：短信、邮件、WebAuthn 等短期 Challenge 的用途/Client/事务绑定、限次与单次消费。';

CREATE TABLE authn.device_authorization (
    id                       uuid        NOT NULL DEFAULT gen_random_uuid(),
    client_id                uuid        NOT NULL,
    tenant_id                uuid        NOT NULL DEFAULT '00000000-0000-0000-0000-000000000000',
    device_code_hash         bytea       NOT NULL,
    user_code_hash           bytea       NOT NULL,
    requested_scopes         text[]      NOT NULL DEFAULT '{}',
    requested_resources      text[]      NOT NULL DEFAULT '{}',
    authorization_details    jsonb       NULL,
    polling_interval_seconds integer     NOT NULL DEFAULT 5,
    poll_count               integer     NOT NULL DEFAULT 0,
    slow_down_count          integer     NOT NULL DEFAULT 0,
    last_polled_at           timestamptz NULL,
    authorized_user_id       uuid        NULL,
    login_transaction_id     uuid        NULL,
    grant_id                 uuid        NULL,
    approved_at              timestamptz NULL,
    denied_at                timestamptz NULL,
    consumed_at              timestamptz NULL,
    expires_at               timestamptz NOT NULL,
    created_at               timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at               timestamptz NOT NULL DEFAULT clock_timestamp(),
    row_version              bigint      NOT NULL DEFAULT 1,
    CONSTRAINT pk_device_authorization PRIMARY KEY (id),
    CONSTRAINT uq_device_authorization_device_code UNIQUE (device_code_hash),
    CONSTRAINT uq_device_authorization_user_code UNIQUE (user_code_hash),
    CONSTRAINT fk_device_authorization_client FOREIGN KEY (client_id) REFERENCES oauth.client(id),
    CONSTRAINT fk_device_authorization_user FOREIGN KEY (authorized_user_id) REFERENCES iam.user_account(id),
    CONSTRAINT fk_device_authorization_tx FOREIGN KEY (login_transaction_id) REFERENCES authn.login_transaction(id),
    CONSTRAINT ck_device_authorization_hash CHECK (octet_length(device_code_hash) = 32 AND octet_length(user_code_hash) = 32),
    CONSTRAINT ck_device_authorization_interval CHECK (polling_interval_seconds BETWEEN 5 AND 60),
    CONSTRAINT ck_device_authorization_poll CHECK (poll_count >= 0 AND slow_down_count >= 0),
    CONSTRAINT ck_device_authorization_outcome CHECK (num_nonnulls(approved_at, denied_at) <= 1),
    CONSTRAINT ck_device_authorization_approval CHECK (approved_at IS NULL OR (authorized_user_id IS NOT NULL AND login_transaction_id IS NOT NULL)),
    CONSTRAINT ck_device_authorization_consume CHECK (consumed_at IS NULL OR approved_at IS NOT NULL),
    CONSTRAINT ck_device_authorization_ttl CHECK (expires_at > created_at AND expires_at - created_at <= interval '15 minutes')
);
COMMENT ON TABLE authn.device_authorization IS 'CAP-OAP-017 / REQ-OAP-005/006：RFC 8628 device_code/user_code、轮询间隔、slow_down、批准、拒绝、过期与单次消费。';

CREATE VIEW authn.device_authorization_status AS
SELECT d.*,
       CASE
           WHEN d.consumed_at IS NOT NULL THEN 'CONSUMED'
           WHEN d.denied_at IS NOT NULL THEN 'ACCESS_DENIED'
           WHEN d.expires_at <= clock_timestamp() THEN 'EXPIRED_TOKEN'
           WHEN d.approved_at IS NOT NULL THEN 'AUTHORIZED'
           ELSE 'AUTHORIZATION_PENDING'
       END AS derived_status
  FROM authn.device_authorization d;
COMMENT ON VIEW authn.device_authorization_status IS 'RFC 8628 派生状态视图；源表用不可互斥时间证据避免额外未登记状态机。';

CREATE TABLE oauth.device (
    id                     uuid        NOT NULL DEFAULT gen_random_uuid(),
    public_id              text        NOT NULL,
    user_id                uuid        NOT NULL,
    device_lifecycle_state text        NOT NULL DEFAULT 'REGISTERED',
    device_trust_state     text        NOT NULL DEFAULT 'UNTRUSTED',
    device_loss_state      text        NOT NULL DEFAULT 'CLEAR',
    fingerprint_hash       bytea       NOT NULL,
    display_name           text        NULL,
    platform_code          text        NULL,
    push_token_cipher      bytea       NULL,
    cipher_key_version     integer     NULL,
    first_seen_at          timestamptz NOT NULL DEFAULT clock_timestamp(),
    last_seen_at           timestamptz NOT NULL DEFAULT clock_timestamp(),
    trusted_at             timestamptz NULL,
    trust_expires_at       timestamptz NULL,
    lost_at                timestamptz NULL,
    loss_cleared_at        timestamptz NULL,
    retired_at             timestamptz NULL,
    revoked_at             timestamptz NULL,
    revoke_reason_code     text        NULL,
    created_at             timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at             timestamptz NOT NULL DEFAULT clock_timestamp(),
    row_version            bigint      NOT NULL DEFAULT 1,
    CONSTRAINT pk_device PRIMARY KEY (id),
    CONSTRAINT uq_device_public_id UNIQUE (public_id),
    CONSTRAINT uq_device_fingerprint UNIQUE (user_id, fingerprint_hash),
    CONSTRAINT fk_device_user FOREIGN KEY (user_id) REFERENCES iam.user_account(id),
    CONSTRAINT ck_device_lifecycle CHECK (device_lifecycle_state IN ('REGISTERED', 'RETIRED', 'REVOKED')),
    CONSTRAINT ck_device_trust CHECK (device_trust_state IN ('UNTRUSTED', 'TRUSTED')),
    CONSTRAINT ck_device_loss CHECK (device_loss_state IN ('CLEAR', 'LOST')),
    CONSTRAINT ck_device_fingerprint CHECK (octet_length(fingerprint_hash) = 32),
    CONSTRAINT ck_device_trusted CHECK (device_trust_state <> 'TRUSTED' OR trusted_at IS NOT NULL),
    CONSTRAINT ck_device_lost CHECK (device_loss_state <> 'LOST' OR (lost_at IS NOT NULL AND device_trust_state = 'UNTRUSTED'))
);
COMMENT ON TABLE oauth.device IS 'CAP-SESSION-004/006 / REQ-SESSION-017：设备生命周期、可信与挂失三个正交维度；挂失撤销会话和 Token Family。';

CREATE TABLE oauth.authorization_grant (
    id                       uuid        NOT NULL DEFAULT gen_random_uuid(),
    public_id                text        NOT NULL,
    subject_kind             text        NOT NULL,
    subject_id               uuid        NOT NULL,
    client_id                uuid        NOT NULL,
    tenant_id                uuid        NOT NULL DEFAULT '00000000-0000-0000-0000-000000000000',
    grant_state              text        NOT NULL DEFAULT 'PENDING',
    login_transaction_id     uuid        NULL,
    requested_scopes         text[]      NOT NULL DEFAULT '{}',
    granted_scopes           text[]      NOT NULL DEFAULT '{}',
    granted_resources        text[]      NOT NULL DEFAULT '{}',
    authorization_details    jsonb       NULL,
    consent_required         boolean     NOT NULL DEFAULT false,
    consent_id               uuid        NULL,
    consent_context_hash     bytea       NULL,
    consent_epoch_at_grant   bigint      NULL,
    policy_version           bigint      NULL,
    user_epoch_at_grant      bigint      NULL,
    client_epoch_at_grant    bigint      NOT NULL,
    tenant_epoch_at_grant    bigint      NULL,
    granted_at               timestamptz NULL,
    denied_at                timestamptz NULL,
    expires_at               timestamptz NULL,
    revoked_at               timestamptz NULL,
    revoke_reason_code       text        NULL,
    revoked_by_ref           text        NULL,
    created_at               timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at               timestamptz NOT NULL DEFAULT clock_timestamp(),
    row_version              bigint      NOT NULL DEFAULT 1,
    CONSTRAINT pk_authorization_grant PRIMARY KEY (id),
    CONSTRAINT uq_authorization_grant_public_id UNIQUE (public_id),
    CONSTRAINT fk_authorization_grant_client FOREIGN KEY (client_id) REFERENCES oauth.client(id),
    CONSTRAINT fk_authorization_grant_tx FOREIGN KEY (login_transaction_id) REFERENCES authn.login_transaction(id),
    CONSTRAINT ck_authorization_grant_subject CHECK (subject_kind IN ('USER', 'MACHINE')),
    CONSTRAINT ck_authorization_grant_state CHECK (grant_state IN ('PENDING', 'ACTIVE', 'DENIED', 'REVOKED', 'EXPIRED')),
    CONSTRAINT ck_authorization_grant_scope CHECK (granted_scopes <@ requested_scopes),
    CONSTRAINT ck_authorization_grant_active CHECK (
        grant_state <> 'ACTIVE'
        OR (granted_at IS NOT NULL AND (subject_kind = 'MACHINE' OR login_transaction_id IS NOT NULL))
    ),
    CONSTRAINT ck_authorization_grant_denied CHECK ((grant_state = 'DENIED') = (denied_at IS NOT NULL)),
    CONSTRAINT ck_authorization_grant_revoked CHECK ((grant_state = 'REVOKED') = (revoked_at IS NOT NULL)),
    CONSTRAINT ck_authorization_grant_consent CHECK (NOT consent_required OR (consent_id IS NOT NULL AND consent_context_hash IS NOT NULL AND consent_epoch_at_grant IS NOT NULL)),
    CONSTRAINT ck_authorization_grant_epoch CHECK (client_epoch_at_grant >= 1 AND (consent_epoch_at_grant IS NULL OR consent_epoch_at_grant >= 1))
);
COMMENT ON TABLE oauth.authorization_grant IS 'CAP-SESSION-009 / REQ-SESSION-018：PENDING Grant 不能签发 Token；完成 Login Transaction 和所需 Consent 后才可 ACTIVE。';

CREATE TABLE oauth.user_session (
    id                    uuid        NOT NULL DEFAULT gen_random_uuid(),
    public_id             text        NOT NULL,
    session_kind          text        NOT NULL DEFAULT 'OP',
    parent_session_id     uuid        NULL,
    user_id               uuid        NOT NULL,
    device_id             uuid        NULL,
    login_transaction_id  uuid        NOT NULL,
    origin_client_id      uuid        NOT NULL,
    tenant_id             uuid        NOT NULL DEFAULT '00000000-0000-0000-0000-000000000000',
    session_state         text        NOT NULL DEFAULT 'ACTIVE',
    profile_code          text        NOT NULL,
    achieved_aal          text        NOT NULL,
    achieved_ial          text        NULL,
    achieved_acr          text        NULL,
    amr_values            text[]      NOT NULL DEFAULT '{}',
    auth_time             timestamptz NOT NULL,
    last_reauth_at        timestamptz NULL,
    user_epoch_at_issue   bigint      NOT NULL,
    client_epoch_at_issue bigint      NOT NULL,
    tenant_epoch_at_issue bigint      NULL,
    idle_expires_at       timestamptz NOT NULL,
    absolute_expires_at   timestamptz NOT NULL,
    risk_level            text        NULL,
    compromised_at        timestamptz NULL,
    revoked_at            timestamptz NULL,
    revoke_reason_code    text        NULL,
    created_at            timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at            timestamptz NOT NULL DEFAULT clock_timestamp(),
    row_version           bigint      NOT NULL DEFAULT 1,
    CONSTRAINT pk_user_session PRIMARY KEY (id),
    CONSTRAINT uq_user_session_public_id UNIQUE (public_id),
    CONSTRAINT fk_user_session_parent FOREIGN KEY (parent_session_id) REFERENCES oauth.user_session(id),
    CONSTRAINT fk_user_session_user FOREIGN KEY (user_id) REFERENCES iam.user_account(id),
    CONSTRAINT fk_user_session_device FOREIGN KEY (device_id) REFERENCES oauth.device(id),
    CONSTRAINT fk_user_session_tx FOREIGN KEY (login_transaction_id) REFERENCES authn.login_transaction(id),
    CONSTRAINT fk_user_session_client FOREIGN KEY (origin_client_id) REFERENCES oauth.client(id),
    CONSTRAINT ck_user_session_kind CHECK (session_kind IN ('OP', 'DEVICE')),
    CONSTRAINT ck_user_session_state CHECK (session_state IN ('ACTIVE', 'EXPIRED', 'COMPROMISED', 'REVOKED')),
    CONSTRAINT ck_user_session_aal CHECK (achieved_aal IN ('AAL1', 'AAL2', 'AAL3')),
    CONSTRAINT ck_user_session_epoch CHECK (user_epoch_at_issue >= 1 AND client_epoch_at_issue >= 1),
    CONSTRAINT ck_user_session_expiry CHECK (idle_expires_at <= absolute_expires_at),
    CONSTRAINT ck_user_session_revoked CHECK ((session_state = 'REVOKED') = (revoked_at IS NOT NULL)),
    CONSTRAINT ck_user_session_compromised CHECK (session_state <> 'COMPROMISED' OR compromised_at IS NOT NULL)
);
COMMENT ON TABLE oauth.user_session IS 'CAP-SESSION-001 至 006 / INV-G-016：仅由 COMPLETED Login Transaction 派生的 OP/Device Session 及安全 epoch 快照。';

CREATE TABLE oauth.token_family (
    id                      uuid        NOT NULL DEFAULT gen_random_uuid(),
    subject_kind            text        NOT NULL,
    subject_id              uuid        NOT NULL,
    client_id               uuid        NOT NULL,
    grant_id                uuid        NOT NULL,
    session_id              uuid        NULL,
    device_id               uuid        NULL,
    tenant_id               uuid        NOT NULL DEFAULT '00000000-0000-0000-0000-000000000000',
    token_family_state      text        NOT NULL DEFAULT 'ACTIVE',
    profile_code            text        NOT NULL,
    sender_constraint_method text       NULL,
    sender_constraint_thumbprint bytea  NULL,
    generation_count        integer     NOT NULL DEFAULT 0,
    idle_expires_at         timestamptz NOT NULL,
    absolute_expires_at     timestamptz NOT NULL,
    compromised_at          timestamptz NULL,
    compromise_reason_code  text        NULL,
    revoked_at              timestamptz NULL,
    revoke_reason_code      text        NULL,
    created_at              timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at              timestamptz NOT NULL DEFAULT clock_timestamp(),
    row_version             bigint      NOT NULL DEFAULT 1,
    CONSTRAINT pk_token_family PRIMARY KEY (id),
    CONSTRAINT fk_token_family_client FOREIGN KEY (client_id) REFERENCES oauth.client(id),
    CONSTRAINT fk_token_family_grant FOREIGN KEY (grant_id) REFERENCES oauth.authorization_grant(id),
    CONSTRAINT fk_token_family_session FOREIGN KEY (session_id) REFERENCES oauth.user_session(id),
    CONSTRAINT fk_token_family_device FOREIGN KEY (device_id) REFERENCES oauth.device(id),
    CONSTRAINT ck_token_family_subject CHECK (subject_kind IN ('USER', 'MACHINE')),
    CONSTRAINT ck_token_family_state CHECK (token_family_state IN ('ACTIVE', 'COMPROMISED', 'REVOKED', 'EXPIRED')),
    CONSTRAINT ck_token_family_sender CHECK ((sender_constraint_method IS NULL AND sender_constraint_thumbprint IS NULL) OR (sender_constraint_method IN ('DPOP', 'MTLS') AND sender_constraint_thumbprint IS NOT NULL)),
    CONSTRAINT ck_token_family_expiry CHECK (idle_expires_at <= absolute_expires_at),
    CONSTRAINT ck_token_family_compromised CHECK (token_family_state <> 'COMPROMISED' OR (compromised_at IS NOT NULL AND compromise_reason_code IS NOT NULL))
);
COMMENT ON TABLE oauth.token_family IS 'CAP-SESSION-008 / CAP-OAP-008：Refresh Token 家族、设备/会话/Grant 绑定、发送方约束与家族级失陷撤销。';

CREATE TABLE oauth.refresh_token (
    id                           uuid        NOT NULL DEFAULT gen_random_uuid(),
    family_id                    uuid        NOT NULL,
    generation                   integer     NOT NULL,
    token_hash                   bytea       NOT NULL,
    refresh_token_instance_state text        NOT NULL DEFAULT 'CURRENT',
    issued_at                    timestamptz NOT NULL DEFAULT clock_timestamp(),
    expires_at                   timestamptz NOT NULL,
    used_at                      timestamptz NULL,
    successor_id                 uuid        NULL,
    retry_window_until           timestamptz NULL,
    binding_context_hash         bytea       NULL,
    revoked_at                   timestamptz NULL,
    revoke_reason_code           text        NULL,
    CONSTRAINT pk_refresh_token PRIMARY KEY (id),
    CONSTRAINT uq_refresh_token_hash UNIQUE (token_hash),
    CONSTRAINT uq_refresh_token_generation UNIQUE (family_id, generation),
    CONSTRAINT fk_refresh_token_family FOREIGN KEY (family_id) REFERENCES oauth.token_family(id) ON DELETE CASCADE,
    CONSTRAINT fk_refresh_token_successor FOREIGN KEY (successor_id) REFERENCES oauth.refresh_token(id),
    CONSTRAINT ck_refresh_token_state CHECK (refresh_token_instance_state IN ('CURRENT', 'USED', 'REVOKED', 'EXPIRED')),
    CONSTRAINT ck_refresh_token_hash CHECK (octet_length(token_hash) = 32),
    CONSTRAINT ck_refresh_token_used CHECK ((refresh_token_instance_state = 'USED') = (used_at IS NOT NULL)),
    CONSTRAINT ck_refresh_token_generation CHECK (generation > 0)
);
COMMENT ON TABLE oauth.refresh_token IS 'REQ-SESSION-002/014：Refresh Token 单次实例、原子轮换、丢包重试窗口和重放检测；只保存哈希。';

CREATE TABLE oauth.authorization_code (
    id                       uuid        NOT NULL DEFAULT gen_random_uuid(),
    code_hash                bytea       NOT NULL,
    authorization_code_state text        NOT NULL DEFAULT 'ISSUED',
    client_id                uuid        NOT NULL,
    user_id                  uuid        NOT NULL,
    login_transaction_id     uuid        NOT NULL,
    session_id               uuid        NULL,
    grant_id                 uuid        NOT NULL,
    redirect_uri             text        NOT NULL,
    code_challenge           text        NOT NULL,
    code_challenge_method    text        NOT NULL DEFAULT 'S256',
    nonce_hash               bytea       NULL,
    scopes                   text[]      NOT NULL DEFAULT '{}',
    resources                text[]      NOT NULL DEFAULT '{}',
    issued_at                timestamptz NOT NULL DEFAULT clock_timestamp(),
    expires_at               timestamptz NOT NULL,
    consumed_at              timestamptz NULL,
    replay_detected_at       timestamptz NULL,
    revoked_at               timestamptz NULL,
    CONSTRAINT pk_authorization_code PRIMARY KEY (id),
    CONSTRAINT uq_authorization_code_hash UNIQUE (code_hash),
    CONSTRAINT fk_authorization_code_client FOREIGN KEY (client_id) REFERENCES oauth.client(id),
    CONSTRAINT fk_authorization_code_user FOREIGN KEY (user_id) REFERENCES iam.user_account(id),
    CONSTRAINT fk_authorization_code_tx FOREIGN KEY (login_transaction_id) REFERENCES authn.login_transaction(id),
    CONSTRAINT fk_authorization_code_session FOREIGN KEY (session_id) REFERENCES oauth.user_session(id),
    CONSTRAINT fk_authorization_code_grant FOREIGN KEY (grant_id) REFERENCES oauth.authorization_grant(id),
    CONSTRAINT ck_authorization_code_state CHECK (authorization_code_state IN ('ISSUED', 'CONSUMED', 'EXPIRED', 'REVOKED')),
    CONSTRAINT ck_authorization_code_hash CHECK (octet_length(code_hash) = 32),
    CONSTRAINT ck_authorization_code_pkce CHECK (code_challenge_method = 'S256'),
    CONSTRAINT ck_authorization_code_consumed CHECK ((authorization_code_state = 'CONSUMED') = (consumed_at IS NOT NULL)),
    CONSTRAINT ck_authorization_code_ttl CHECK (expires_at > issued_at AND expires_at - issued_at <= interval '60 seconds')
);
COMMENT ON TABLE oauth.authorization_code IS 'REQ-AUTH-004：绑定 Client、redirect URI、PKCE、Login Transaction 与 Grant 的单次授权码；重放触发关联撤销。';

CREATE TABLE oauth.reference_access_token (
    jti                       text        NOT NULL,
    token_hash                bytea       NOT NULL,
    subject_kind              text        NOT NULL,
    subject_id                uuid        NOT NULL,
    actor_kind                text        NULL,
    actor_ref                 text        NULL,
    client_id                 uuid        NOT NULL,
    grant_id                  uuid        NOT NULL,
    session_id                uuid        NULL,
    token_family_id           uuid        NULL,
    tenant_id                 uuid        NOT NULL DEFAULT '00000000-0000-0000-0000-000000000000',
    audiences                 text[]      NOT NULL,
    scopes                    text[]      NOT NULL DEFAULT '{}',
    profile_code              text        NOT NULL,
    policy_version            bigint      NULL,
    user_epoch_at_issue       bigint      NULL,
    client_epoch_at_issue     bigint      NOT NULL,
    tenant_epoch_at_issue     bigint      NULL,
    consent_id                uuid        NULL,
    consent_context_hash      bytea       NULL,
    consent_epoch_at_issue    bigint      NULL,
    sender_constraint_thumbprint bytea    NULL,
    issued_at                 timestamptz NOT NULL DEFAULT clock_timestamp(),
    expires_at                timestamptz NOT NULL,
    revoked_at                timestamptz NULL,
    CONSTRAINT pk_reference_access_token PRIMARY KEY (jti),
    CONSTRAINT uq_reference_access_token_hash UNIQUE (token_hash),
    CONSTRAINT fk_reference_access_token_client FOREIGN KEY (client_id) REFERENCES oauth.client(id),
    CONSTRAINT fk_reference_access_token_grant FOREIGN KEY (grant_id) REFERENCES oauth.authorization_grant(id),
    CONSTRAINT fk_reference_access_token_session FOREIGN KEY (session_id) REFERENCES oauth.user_session(id),
    CONSTRAINT fk_reference_access_token_family FOREIGN KEY (token_family_id) REFERENCES oauth.token_family(id),
    CONSTRAINT ck_reference_access_token_subject CHECK (subject_kind IN ('USER', 'MACHINE')),
    CONSTRAINT ck_reference_access_token_actor CHECK ((actor_kind IS NULL) = (actor_ref IS NULL)),
    CONSTRAINT ck_reference_access_token_audience CHECK (cardinality(audiences) > 0),
    CONSTRAINT ck_reference_access_token_epoch CHECK (client_epoch_at_issue >= 1 AND (consent_epoch_at_issue IS NULL OR consent_epoch_at_issue >= 1)),
    CONSTRAINT ck_reference_access_token_consent CHECK (
        (consent_id IS NULL AND consent_context_hash IS NULL AND consent_epoch_at_issue IS NULL)
        OR (consent_id IS NOT NULL AND consent_context_hash IS NOT NULL AND consent_epoch_at_issue IS NOT NULL)
    ),
    CONSTRAINT ck_reference_access_token_ttl CHECK (expires_at > issued_at)
);
COMMENT ON TABLE oauth.reference_access_token IS 'CAP-SESSION-007/011：需内省的 Access Token 引用、Subject/Actor、audience/scope 和全部适用安全版本快照。';

CREATE TABLE oauth.revocation_record (
    id                uuid        NOT NULL DEFAULT gen_random_uuid(),
    revocation_kind   text        NOT NULL,
    target_ref        text        NOT NULL,
    user_id           uuid        NULL,
    client_id         uuid        NULL,
    tenant_id         uuid        NOT NULL DEFAULT '00000000-0000-0000-0000-000000000000',
    effective_epoch   bigint      NULL,
    reason_code       text        NOT NULL,
    source_kind       text        NOT NULL,
    source_ref        text        NULL,
    revoked_at        timestamptz NOT NULL DEFAULT clock_timestamp(),
    prunable_after    timestamptz NOT NULL,
    CONSTRAINT pk_revocation_record PRIMARY KEY (id),
    CONSTRAINT ck_revocation_record_kind CHECK (revocation_kind IN ('SESSION', 'TOKEN_FAMILY', 'GRANT', 'CLIENT', 'USER_EPOCH', 'TENANT_EPOCH', 'CONSENT_EPOCH', 'JTI', 'DEVICE', 'AUTHENTICATOR', 'DELEGATION')),
    CONSTRAINT ck_revocation_record_source CHECK (source_kind IN ('USER', 'ADMIN', 'RISK', 'SYSTEM', 'IDENTITY_PROVIDER', 'PRIVACY', 'CLIENT')),
    CONSTRAINT ck_revocation_record_retention CHECK (prunable_after > revoked_at)
);
COMMENT ON TABLE oauth.revocation_record IS 'CAP-SESSION-010 / REQ-SESSION-012：Grant、Client、Session、Token、Consent、设备与委托撤销水位的追加记录。';

CREATE TABLE oauth.logout_request (
    id               uuid        NOT NULL DEFAULT gen_random_uuid(),
    operation_id     uuid        NOT NULL,
    user_id          uuid        NOT NULL,
    scope_kind       text        NOT NULL,
    scope_ref        text        NULL,
    initiator_kind   text        NOT NULL,
    initiator_ref    text        NULL,
    logout_state     text        NOT NULL DEFAULT 'IN_PROGRESS',
    requested_at     timestamptz NOT NULL DEFAULT clock_timestamp(),
    completed_at     timestamptz NULL,
    updated_at       timestamptz NOT NULL DEFAULT clock_timestamp(),
    row_version      bigint      NOT NULL DEFAULT 1,
    CONSTRAINT pk_logout_request PRIMARY KEY (id),
    CONSTRAINT uq_logout_request_operation UNIQUE (operation_id),
    CONSTRAINT fk_logout_request_operation FOREIGN KEY (operation_id) REFERENCES core.async_operation(id),
    CONSTRAINT fk_logout_request_user FOREIGN KEY (user_id) REFERENCES iam.user_account(id),
    CONSTRAINT ck_logout_request_scope CHECK (scope_kind IN ('CLIENT', 'SESSION', 'DEVICE', 'TENANT', 'ALL_DEVICES', 'GLOBAL')),
    CONSTRAINT ck_logout_request_initiator CHECK (initiator_kind IN ('USER', 'ADMIN', 'RISK', 'IDENTITY_PROVIDER', 'SYSTEM')),
    CONSTRAINT ck_logout_request_state CHECK (logout_state IN ('IN_PROGRESS', 'PARTIAL', 'COMPLETED')),
    CONSTRAINT ck_logout_request_completed CHECK ((logout_state = 'COMPLETED') = (completed_at IS NOT NULL))
);
COMMENT ON TABLE oauth.logout_request IS 'CAP-SESSION-002 / CAP-OAP-012：OP、RP、Device Session 与 Token Family 的完整退出 Operation。';

CREATE TABLE oauth.logout_target_result (
    id                       uuid        NOT NULL DEFAULT gen_random_uuid(),
    logout_request_id        uuid        NOT NULL,
    client_id                uuid        NOT NULL,
    channel                  text        NOT NULL,
    delivery_state           text        NOT NULL DEFAULT 'PENDING',
    unconfirmed_reason_class text        NULL,
    attempt_count            integer     NOT NULL DEFAULT 0,
    next_attempt_at          timestamptz NULL,
    confirmed_at             timestamptz NULL,
    last_error_code          text        NULL,
    dead_lettered_at         timestamptz NULL,
    updated_at               timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT pk_logout_target_result PRIMARY KEY (id),
    CONSTRAINT uq_logout_target_result UNIQUE (logout_request_id, client_id, channel),
    CONSTRAINT fk_logout_target_result_request FOREIGN KEY (logout_request_id) REFERENCES oauth.logout_request(id) ON DELETE CASCADE,
    CONSTRAINT fk_logout_target_result_client FOREIGN KEY (client_id) REFERENCES oauth.client(id),
    CONSTRAINT ck_logout_target_result_channel CHECK (channel IN ('BACK_CHANNEL', 'FRONT_CHANNEL')),
    CONSTRAINT ck_logout_target_result_state CHECK (delivery_state IN ('PENDING', 'CONFIRMED', 'FAILED', 'DEAD_LETTER', 'NOT_APPLICABLE')),
    CONSTRAINT ck_logout_target_result_reason CHECK (unconfirmed_reason_class IS NULL OR unconfirmed_reason_class IN ('BACK_CHANNEL_UNCONFIRMED', 'FRONT_CHANNEL_INEFFECTIVE')),
    CONSTRAINT ck_logout_target_result_confirmed CHECK ((delivery_state = 'CONFIRMED') = (confirmed_at IS NOT NULL))
);
COMMENT ON TABLE oauth.logout_target_result IS 'AT-SESSION-006/011：逐 RP 的 Back/Front Channel Logout 送达、确认、失败分类与对账。';

ALTER TABLE iam.user_account
    ADD CONSTRAINT fk_user_account_creation_client
    FOREIGN KEY (creation_client_id) REFERENCES oauth.client(id);
ALTER TABLE authn.login_factor
    ADD CONSTRAINT fk_login_factor_challenge
    FOREIGN KEY (challenge_id) REFERENCES authn.verification_challenge(id);
ALTER TABLE authn.device_authorization
    ADD CONSTRAINT fk_device_authorization_grant
    FOREIGN KEY (grant_id) REFERENCES oauth.authorization_grant(id);

CREATE UNIQUE INDEX ux_authenticator_credential_id ON authn.authenticator(credential_public_id) WHERE credential_public_id IS NOT NULL;
CREATE UNIQUE INDEX ux_recovery_code_batch_active ON authn.recovery_code_batch(user_id) WHERE batch_state = 'ACTIVE';
CREATE UNIQUE INDEX ux_challenge_active_target ON authn.verification_challenge(challenge_purpose, client_id, target_blind_index) WHERE challenge_state = 'ISSUED' AND target_blind_index IS NOT NULL;
CREATE INDEX ix_login_transaction_expiry ON authn.login_transaction(expires_at) WHERE login_transaction_state NOT IN ('COMPLETED', 'EXPIRED', 'ABANDONED');
CREATE INDEX ix_device_authorization_expiry ON authn.device_authorization(expires_at) WHERE consumed_at IS NULL AND denied_at IS NULL;
CREATE INDEX ix_client_owner_review ON oauth.client(owner_ref, expires_at) WHERE client_state = 'ACTIVE';
CREATE INDEX ix_device_user ON oauth.device(user_id, device_lifecycle_state, device_loss_state);
CREATE UNIQUE INDEX ux_authorization_grant_active ON oauth.authorization_grant(subject_kind, subject_id, client_id) WHERE grant_state IN ('PENDING', 'ACTIVE');
CREATE INDEX ix_authorization_grant_client ON oauth.authorization_grant(client_id, grant_state);
CREATE INDEX ix_user_session_user ON oauth.user_session(user_id, session_state, created_at DESC);
CREATE INDEX ix_user_session_device ON oauth.user_session(device_id, session_state) WHERE device_id IS NOT NULL;
CREATE INDEX ix_user_session_expiry ON oauth.user_session(idle_expires_at) WHERE session_state = 'ACTIVE';
CREATE UNIQUE INDEX ux_refresh_token_current ON oauth.refresh_token(family_id) WHERE refresh_token_instance_state = 'CURRENT';
CREATE INDEX ix_token_family_grant ON oauth.token_family(grant_id, token_family_state);
CREATE INDEX ix_authorization_code_expiry ON oauth.authorization_code(expires_at) WHERE authorization_code_state = 'ISSUED';
CREATE INDEX ix_reference_access_token_expiry ON oauth.reference_access_token(expires_at) WHERE revoked_at IS NULL;
CREATE INDEX ix_revocation_target ON oauth.revocation_record(revocation_kind, target_ref, revoked_at DESC);
CREATE INDEX ix_logout_target_retry ON oauth.logout_target_result(next_attempt_at) WHERE delivery_state IN ('PENDING', 'FAILED');

CREATE OR REPLACE FUNCTION authn.fn_assert_user_can_authenticate(p_user_id uuid)
RETURNS void
LANGUAGE plpgsql
AS $$
DECLARE v_user iam.user_account%ROWTYPE;
BEGIN
    SELECT * INTO v_user FROM iam.user_account WHERE id = p_user_id;
    IF NOT FOUND THEN RAISE EXCEPTION 'SUBJECT_NOT_FOUND' USING ERRCODE = '23503'; END IF;
    IF v_user.security_freeze_state = 'FROZEN' THEN RAISE EXCEPTION 'SUBJECT_FROZEN' USING ERRCODE = '23514'; END IF;
    IF v_user.authentication_lock_state = 'LOCKED' AND (v_user.lock_until IS NULL OR v_user.lock_until > clock_timestamp()) THEN
        RAISE EXCEPTION 'SUBJECT_LOCKED' USING ERRCODE = '23514';
    END IF;
    IF v_user.lifecycle_state NOT IN ('PROVISIONAL', 'ACTIVE', 'DORMANT') THEN
        RAISE EXCEPTION 'INVALID_STATE_TRANSITION: lifecycle=%', v_user.lifecycle_state USING ERRCODE = '23514';
    END IF;
END;
$$;
COMMENT ON FUNCTION authn.fn_assert_user_can_authenticate(uuid) IS 'INV-G-013：认证、会话和认证器登记前校验主体生命周期、锁定和冻结。';

CREATE OR REPLACE FUNCTION oauth.fn_session_insert_guard()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE v_state text; v_user uuid;
BEGIN
    PERFORM authn.fn_assert_user_can_authenticate(NEW.user_id);
    IF NOT EXISTS (SELECT 1 FROM iam.user_account WHERE id = NEW.user_id AND lifecycle_state = 'ACTIVE') THEN
        RAISE EXCEPTION 'INV-G-013: 仅 ACTIVE 主体可创建会话' USING ERRCODE = '23514';
    END IF;
    SELECT login_transaction_state, user_id INTO v_state, v_user FROM authn.login_transaction WHERE id = NEW.login_transaction_id;
    IF v_state IS DISTINCT FROM 'COMPLETED' OR v_user IS DISTINCT FROM NEW.user_id THEN
        RAISE EXCEPTION 'INV-G-016: Login Transaction 未完成或主体不一致' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;
COMMENT ON FUNCTION oauth.fn_session_insert_guard() IS 'INV-G-013/016：冻结主体或未完成 Login Transaction 不得创建 Session。';

CREATE OR REPLACE FUNCTION oauth.fn_grant_activation_guard()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE v_state text;
BEGIN
    IF NEW.grant_state = 'ACTIVE' THEN
        IF TG_OP = 'UPDATE' AND OLD.grant_state = 'ACTIVE' THEN
            RETURN NEW;
        END IF;
        IF NEW.subject_kind = 'USER' THEN
            SELECT login_transaction_state INTO v_state FROM authn.login_transaction WHERE id = NEW.login_transaction_id;
            IF v_state IS DISTINCT FROM 'COMPLETED' THEN
                RAISE EXCEPTION 'REQ-SESSION-018: 用户 Grant 只能由 COMPLETED Login Transaction 激活' USING ERRCODE = '23514';
            END IF;
        END IF;
        IF NEW.consent_required AND NEW.consent_id IS NULL THEN
            RAISE EXCEPTION 'REQ-SESSION-018: 缺少所需 Consent' USING ERRCODE = '23514';
        END IF;
    END IF;
    RETURN NEW;
END;
$$;
COMMENT ON FUNCTION oauth.fn_grant_activation_guard() IS 'REQ-SESSION-018：Grant 激活前校验登录事务和 Consent 引用。';

CREATE OR REPLACE FUNCTION oauth.fn_client_state_guard()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF OLD.client_state = 'RETIRED' AND NEW.client_state <> 'RETIRED' THEN
        RAISE EXCEPTION 'INVALID_STATE_TRANSITION: RETIRED Client 不得恢复' USING ERRCODE = '23514';
    END IF;
    IF OLD.client_state = 'COMPROMISED' AND NEW.client_state NOT IN ('COMPROMISED', 'RETIRED') THEN
        RAISE EXCEPTION 'INVALID_STATE_TRANSITION: COMPROMISED Client 只能转为 RETIRED' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;
COMMENT ON FUNCTION oauth.fn_client_state_guard() IS 'Client 状态守卫：受损后只能维持受损或退役，退役不可恢复。';

CREATE OR REPLACE FUNCTION authn.fn_authenticator_activation_guard()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.authenticator_state = 'ACTIVE' THEN
        PERFORM authn.fn_assert_user_can_authenticate(NEW.user_id);
    END IF;
    RETURN NEW;
END;
$$;
COMMENT ON FUNCTION authn.fn_authenticator_activation_guard() IS '认证器登记或恢复为 ACTIVE 前校验主体可认证状态。';

CREATE OR REPLACE FUNCTION authn.fn_device_authorization_guard()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
          FROM oauth.client c
         WHERE c.id = NEW.client_id
           AND c.client_state = 'ACTIVE'
           AND c.profile_code = 'SP1-D'
           AND 'urn:ietf:params:oauth:grant-type:device_code' = ANY(c.allowed_grant_types)
    ) THEN
        RAISE EXCEPTION 'INVALID_CLIENT: Device Authorization 仅允许启用 Device Grant 的 ACTIVE SP1-D Client' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;
COMMENT ON FUNCTION authn.fn_device_authorization_guard() IS 'REQ-OAP-003：Device Authorization 只能由启用 Device Grant 的 ACTIVE SP1-D Client 创建。';

CREATE OR REPLACE FUNCTION oauth.fn_device_loss_guard()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.device_loss_state = 'LOST' AND OLD.device_loss_state <> 'LOST' THEN
        NEW.device_trust_state := 'UNTRUSTED';
        NEW.lost_at := clock_timestamp();
        NEW.loss_cleared_at := NULL;
        UPDATE oauth.user_session
           SET session_state = 'REVOKED', revoked_at = clock_timestamp(), revoke_reason_code = 'DEVICE_LOST'
         WHERE device_id = NEW.id AND session_state = 'ACTIVE';
        UPDATE oauth.token_family
           SET token_family_state = 'REVOKED', revoked_at = clock_timestamp(), revoke_reason_code = 'DEVICE_LOST'
         WHERE device_id = NEW.id AND token_family_state = 'ACTIVE';
        INSERT INTO oauth.revocation_record(
            revocation_kind, target_ref, user_id, reason_code, source_kind, source_ref, prunable_after
        ) VALUES (
            'DEVICE', NEW.public_id, NEW.user_id, 'DEVICE_LOST', 'SYSTEM', NEW.public_id,
            clock_timestamp() + interval '400 days'
        );
    END IF;
    IF OLD.device_loss_state = 'LOST' AND NEW.device_loss_state = 'CLEAR' THEN
        NEW.device_trust_state := 'UNTRUSTED';
        NEW.loss_cleared_at := clock_timestamp();
    ELSIF OLD.device_loss_state = NEW.device_loss_state
       AND (NEW.lost_at IS DISTINCT FROM OLD.lost_at
            OR NEW.loss_cleared_at IS DISTINCT FROM OLD.loss_cleared_at) THEN
        RAISE EXCEPTION 'DEVICE_LOSS_EVIDENCE_IMMUTABLE' USING ERRCODE = '55000';
    END IF;
    RETURN NEW;
END;
$$;
COMMENT ON FUNCTION oauth.fn_device_loss_guard() IS 'REQ-SESSION-017：挂失原子撤销关联会话和 Token Family；解除挂失不恢复可信关系。';

CREATE TRIGGER trg_authenticator_touch BEFORE UPDATE ON authn.authenticator FOR EACH ROW EXECUTE FUNCTION core.fn_touch_updated_at();
CREATE TRIGGER trg_authenticator_version BEFORE UPDATE ON authn.authenticator FOR EACH ROW EXECUTE FUNCTION core.fn_increment_row_version();
CREATE TRIGGER trg_authenticator_activation BEFORE INSERT OR UPDATE ON authn.authenticator FOR EACH ROW EXECUTE FUNCTION authn.fn_authenticator_activation_guard();
CREATE TRIGGER trg_authenticator_terminal BEFORE UPDATE ON authn.authenticator FOR EACH ROW EXECUTE FUNCTION core.fn_terminal_state_guard('authenticator_state', 'REVOKED', 'REPLACED');
CREATE TRIGGER trg_password_touch BEFORE UPDATE ON authn.password_credential FOR EACH ROW EXECUTE FUNCTION core.fn_touch_updated_at();
CREATE TRIGGER trg_password_version BEFORE UPDATE ON authn.password_credential FOR EACH ROW EXECUTE FUNCTION core.fn_increment_row_version();
CREATE TRIGGER trg_application_touch BEFORE UPDATE ON oauth.application FOR EACH ROW EXECUTE FUNCTION core.fn_touch_updated_at();
CREATE TRIGGER trg_application_version BEFORE UPDATE ON oauth.application FOR EACH ROW EXECUTE FUNCTION core.fn_increment_row_version();
CREATE TRIGGER trg_application_public_id BEFORE INSERT ON oauth.application FOR EACH ROW EXECUTE FUNCTION core.fn_register_public_id('APPLICATION');
CREATE TRIGGER trg_client_touch BEFORE UPDATE ON oauth.client FOR EACH ROW EXECUTE FUNCTION core.fn_touch_updated_at();
CREATE TRIGGER trg_client_version BEFORE UPDATE ON oauth.client FOR EACH ROW EXECUTE FUNCTION core.fn_increment_row_version();
CREATE TRIGGER trg_client_epoch BEFORE UPDATE ON oauth.client FOR EACH ROW EXECUTE FUNCTION core.fn_forbid_epoch_decrease('client_security_epoch');
CREATE TRIGGER trg_client_public_id BEFORE INSERT ON oauth.client FOR EACH ROW EXECUTE FUNCTION core.fn_register_public_id('CLIENT');
CREATE TRIGGER trg_client_terminal BEFORE UPDATE ON oauth.client FOR EACH ROW EXECUTE FUNCTION oauth.fn_client_state_guard();
CREATE TRIGGER trg_client_credential_touch BEFORE UPDATE ON oauth.client_credential FOR EACH ROW EXECUTE FUNCTION core.fn_touch_updated_at();
CREATE TRIGGER trg_client_credential_version BEFORE UPDATE ON oauth.client_credential FOR EACH ROW EXECUTE FUNCTION core.fn_increment_row_version();
CREATE TRIGGER trg_api_resource_touch BEFORE UPDATE ON oauth.api_resource FOR EACH ROW EXECUTE FUNCTION core.fn_touch_updated_at();
CREATE TRIGGER trg_api_resource_version BEFORE UPDATE ON oauth.api_resource FOR EACH ROW EXECUTE FUNCTION core.fn_increment_row_version();
CREATE TRIGGER trg_api_resource_public_id BEFORE INSERT ON oauth.api_resource FOR EACH ROW EXECUTE FUNCTION core.fn_register_public_id('API_RESOURCE');
CREATE TRIGGER trg_login_transaction_touch BEFORE UPDATE ON authn.login_transaction FOR EACH ROW EXECUTE FUNCTION core.fn_touch_updated_at();
CREATE TRIGGER trg_login_transaction_version BEFORE UPDATE ON authn.login_transaction FOR EACH ROW EXECUTE FUNCTION core.fn_increment_row_version();
CREATE TRIGGER trg_login_transaction_public_id BEFORE INSERT ON authn.login_transaction FOR EACH ROW EXECUTE FUNCTION core.fn_register_public_id('LOGIN_TRANSACTION');
CREATE TRIGGER trg_login_transaction_terminal BEFORE UPDATE ON authn.login_transaction FOR EACH ROW EXECUTE FUNCTION core.fn_terminal_state_guard('login_transaction_state', 'COMPLETED', 'EXPIRED', 'ABANDONED');
CREATE TRIGGER trg_challenge_touch BEFORE UPDATE ON authn.verification_challenge FOR EACH ROW EXECUTE FUNCTION core.fn_touch_updated_at();
CREATE TRIGGER trg_challenge_version BEFORE UPDATE ON authn.verification_challenge FOR EACH ROW EXECUTE FUNCTION core.fn_increment_row_version();
CREATE TRIGGER trg_challenge_public_id BEFORE INSERT ON authn.verification_challenge FOR EACH ROW EXECUTE FUNCTION core.fn_register_public_id('CHALLENGE');
CREATE TRIGGER trg_device_authorization_touch BEFORE UPDATE ON authn.device_authorization FOR EACH ROW EXECUTE FUNCTION core.fn_touch_updated_at();
CREATE TRIGGER trg_device_authorization_version BEFORE UPDATE ON authn.device_authorization FOR EACH ROW EXECUTE FUNCTION core.fn_increment_row_version();
CREATE TRIGGER trg_device_authorization_client BEFORE INSERT ON authn.device_authorization FOR EACH ROW EXECUTE FUNCTION authn.fn_device_authorization_guard();
CREATE TRIGGER trg_device_touch BEFORE UPDATE ON oauth.device FOR EACH ROW EXECUTE FUNCTION core.fn_touch_updated_at();
CREATE TRIGGER trg_device_version BEFORE UPDATE ON oauth.device FOR EACH ROW EXECUTE FUNCTION core.fn_increment_row_version();
CREATE TRIGGER trg_device_loss BEFORE UPDATE ON oauth.device FOR EACH ROW EXECUTE FUNCTION oauth.fn_device_loss_guard();
CREATE TRIGGER trg_device_public_id BEFORE INSERT ON oauth.device FOR EACH ROW EXECUTE FUNCTION core.fn_register_public_id('DEVICE');
CREATE TRIGGER trg_grant_touch BEFORE UPDATE ON oauth.authorization_grant FOR EACH ROW EXECUTE FUNCTION core.fn_touch_updated_at();
CREATE TRIGGER trg_grant_version BEFORE UPDATE ON oauth.authorization_grant FOR EACH ROW EXECUTE FUNCTION core.fn_increment_row_version();
CREATE TRIGGER trg_grant_activation BEFORE INSERT OR UPDATE ON oauth.authorization_grant FOR EACH ROW EXECUTE FUNCTION oauth.fn_grant_activation_guard();
CREATE TRIGGER trg_grant_terminal BEFORE UPDATE ON oauth.authorization_grant FOR EACH ROW EXECUTE FUNCTION core.fn_terminal_state_guard('grant_state', 'DENIED', 'REVOKED', 'EXPIRED');
CREATE TRIGGER trg_grant_public_id BEFORE INSERT ON oauth.authorization_grant FOR EACH ROW EXECUTE FUNCTION core.fn_register_public_id('GRANT');
CREATE TRIGGER trg_session_insert BEFORE INSERT ON oauth.user_session FOR EACH ROW EXECUTE FUNCTION oauth.fn_session_insert_guard();
CREATE TRIGGER trg_session_touch BEFORE UPDATE ON oauth.user_session FOR EACH ROW EXECUTE FUNCTION core.fn_touch_updated_at();
CREATE TRIGGER trg_session_version BEFORE UPDATE ON oauth.user_session FOR EACH ROW EXECUTE FUNCTION core.fn_increment_row_version();
CREATE TRIGGER trg_session_public_id BEFORE INSERT ON oauth.user_session FOR EACH ROW EXECUTE FUNCTION core.fn_register_public_id('SESSION');
CREATE TRIGGER trg_token_family_touch BEFORE UPDATE ON oauth.token_family FOR EACH ROW EXECUTE FUNCTION core.fn_touch_updated_at();
CREATE TRIGGER trg_token_family_version BEFORE UPDATE ON oauth.token_family FOR EACH ROW EXECUTE FUNCTION core.fn_increment_row_version();
CREATE TRIGGER trg_revocation_append_only BEFORE UPDATE OR DELETE ON oauth.revocation_record FOR EACH STATEMENT EXECUTE FUNCTION core.fn_append_only();
CREATE TRIGGER trg_logout_touch BEFORE UPDATE ON oauth.logout_request FOR EACH ROW EXECUTE FUNCTION core.fn_touch_updated_at();
CREATE TRIGGER trg_logout_version BEFORE UPDATE ON oauth.logout_request FOR EACH ROW EXECUTE FUNCTION core.fn_increment_row_version();
CREATE TRIGGER trg_logout_target_touch BEFORE UPDATE ON oauth.logout_target_result FOR EACH ROW EXECUTE FUNCTION core.fn_touch_updated_at();

SELECT core.fn_register_migration('020', '认证器、Login Transaction、Device Grant、Client、Session、Grant、Token 与撤销', NULLIF(current_setting('kuc.migration_sha256', true), ''));
COMMIT;
