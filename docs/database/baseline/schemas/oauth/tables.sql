-- =============================================================================
-- baseline/schemas/oauth/tables.sql
-- oauth Schema 的最终基表、同 Schema 约束、索引及内联 COMMENT
-- PostgreSQL 16+；应用技术栈：.NET 10 + SqlSugar
-- =============================================================================

CREATE TABLE oauth.application (
    id uuid        NOT NULL DEFAULT gen_random_uuid(),
    public_id text        NOT NULL,
    business_line_id uuid        NOT NULL,
    display_name text        NOT NULL,
    application_type text        NOT NULL,
    application_state text        NOT NULL DEFAULT 'DRAFT',
    owner_ref text        NOT NULL,
    contact_ref text        NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    row_version bigint      NOT NULL DEFAULT 1,
    CONSTRAINT pk_application PRIMARY KEY (id),
    CONSTRAINT uq_application_public_id UNIQUE (public_id),
    CONSTRAINT ck_application_type CHECK (application_type IN ('WEB_SERVER', 'SPA_BFF', 'NATIVE_APP', 'MINI_PROGRAM', 'SERVER_TO_SERVER', 'INPUT_CONSTRAINED_DEVICE', 'ADMIN_CONSOLE')),
    CONSTRAINT ck_application_state CHECK (application_state IN ('DRAFT', 'ACTIVE', 'SUSPENDED', 'RETIRED'))
);

COMMENT ON TABLE oauth.application IS 'CAP-TENANT-002：应用登记及负责人；一个应用可对应多个环境和安全 Profile 的 Client。';

CREATE TABLE oauth.client (
    id uuid        NOT NULL DEFAULT gen_random_uuid(),
    public_id text        NOT NULL,
    application_id uuid        NOT NULL,
    business_line_id uuid        NOT NULL,
    tenant_id uuid        NOT NULL DEFAULT '00000000-0000-0000-0000-000000000000',
    environment text        NOT NULL,
    client_state text        NOT NULL DEFAULT 'DRAFT',
    client_kind text        NOT NULL,
    display_name text        NOT NULL,
    profile_code text        NOT NULL,
    profile_version integer     NOT NULL,
    token_endpoint_auth_method text        NOT NULL DEFAULT 'none',
    allowed_grant_types text[]      NOT NULL,
    allowed_scopes text[]      NOT NULL DEFAULT '{}',
    allowed_resources text[]      NOT NULL DEFAULT '{}',
    subject_mode text        NOT NULL DEFAULT 'PAIRWISE_PER_CLIENT',
    access_token_format text        NOT NULL DEFAULT 'JWT',
    id_token_signed_alg text        NOT NULL DEFAULT 'ES256',
    require_par boolean     NOT NULL DEFAULT false,
    require_sender_constrained boolean     NOT NULL DEFAULT false,
    sender_constraint_method text        NULL,
    consent_required boolean     NOT NULL DEFAULT false,
    sso_domain_boundary text        NOT NULL,
    owner_ref text        NOT NULL,
    permission_baseline jsonb       NOT NULL DEFAULT '{}'::jsonb,
    credential_rotation_policy jsonb       NOT NULL DEFAULT '{}'::jsonb,
    client_security_epoch bigint      NOT NULL DEFAULT 1,
    onboarding_report_ref text        NULL,
    approval_case_id uuid        NULL,
    reactivation_review_ref text        NULL,
    approved_at timestamptz NULL,
    suspended_at timestamptz NULL,
    compromised_at timestamptz NULL,
    retired_at timestamptz NULL,
    expires_at timestamptz NULL,
    last_used_at timestamptz NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    row_version bigint      NOT NULL DEFAULT 1,
    configuration_hash bytea NOT NULL,
    approval_execution_id uuid NULL,
    last_activation_execution_id uuid NULL,
    CONSTRAINT pk_client PRIMARY KEY (id),
    CONSTRAINT uq_client_public_id UNIQUE (public_id),
    CONSTRAINT fk_client_application FOREIGN KEY (application_id) REFERENCES oauth.application(id),
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
    CONSTRAINT ck_client_reactivation CHECK (reactivation_review_ref IS NULL OR client_state = 'ACTIVE'),
    CONSTRAINT ck_client_configuration_hash CHECK (octet_length(configuration_hash) = 32),
    CONSTRAINT uq_client_id_tenant UNIQUE (id, tenant_id),
    CONSTRAINT uq_client_id_tenant_business UNIQUE (id, tenant_id, business_line_id)
);

COMMENT ON TABLE oauth.client IS 'CAP-OAP-001 至 017 / REQ-MACHINE-018：Client Profile、Grant、认证方式、最小权限、轮换、审批、暂停恢复与失陷终态。';

CREATE TABLE oauth.client_uri (
    id uuid        NOT NULL DEFAULT gen_random_uuid(),
    client_id uuid        NOT NULL,
    uri_kind text        NOT NULL,
    uri_value text        NOT NULL,
    is_loopback boolean     NOT NULL DEFAULT false,
    created_by_ref text        NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT pk_client_uri PRIMARY KEY (id),
    CONSTRAINT uq_client_uri UNIQUE (client_id, uri_kind, uri_value),
    CONSTRAINT fk_client_uri_client FOREIGN KEY (client_id) REFERENCES oauth.client(id) ON DELETE CASCADE,
    CONSTRAINT ck_client_uri_kind CHECK (uri_kind IN ('REDIRECT', 'POST_LOGOUT_REDIRECT', 'FRONT_CHANNEL_LOGOUT', 'BACK_CHANNEL_LOGOUT', 'INITIATE_LOGIN')),
    CONSTRAINT ck_client_uri_no_wildcard CHECK (position('*' in uri_value) = 0 AND position('#' in uri_value) = 0),
    CONSTRAINT ck_client_uri_scheme CHECK (uri_value ~ '^https://' OR (is_loopback AND uri_value ~ '^http://(127\.0\.0\.1|\[::1\])(:[0-9]{1,5})?(/.*)?$') OR uri_value ~ '^[a-z][a-z0-9+.-]*:/')
);

COMMENT ON TABLE oauth.client_uri IS 'CAP-OAP-004 / REQ-AUTH-002：精确回调和退出 URI；仅原生应用 loopback 允许 HTTP 动态端口。';

CREATE TABLE oauth.client_credential (
    id uuid        NOT NULL DEFAULT gen_random_uuid(),
    client_id uuid        NOT NULL,
    credential_kind text        NOT NULL,
    credential_state text        NOT NULL DEFAULT 'ACTIVE',
    key_id text        NULL,
    secret_hash text        NULL,
    public_jwk jsonb       NULL,
    jwks_uri text        NULL,
    certificate_thumbprint bytea      NULL,
    algorithm text        NULL,
    not_before timestamptz NOT NULL DEFAULT clock_timestamp(),
    not_after timestamptz NOT NULL,
    rotated_from_id uuid        NULL,
    revoked_at timestamptz NULL,
    revoke_reason_code text        NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    row_version bigint      NOT NULL DEFAULT 1,
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
    id uuid        NOT NULL DEFAULT gen_random_uuid(),
    public_id text        NOT NULL,
    audience_value text        NOT NULL,
    display_name text        NOT NULL,
    business_line_id uuid        NOT NULL,
    owner_ref text        NOT NULL,
    resource_state text        NOT NULL DEFAULT 'DRAFT',
    minimum_profile_code text        NOT NULL DEFAULT 'SP1',
    revocation_check_mode text        NOT NULL DEFAULT 'SIGNAL_STREAM',
    supported_obligations text[]      NOT NULL DEFAULT '{}',
    onboarding_report_ref text        NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    row_version bigint      NOT NULL DEFAULT 1,
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
    scope_code text        NOT NULL,
    api_resource_id uuid        NOT NULL,
    display_name text        NOT NULL,
    description text        NOT NULL,
    data_classification text        NOT NULL,
    requires_consent boolean     NOT NULL DEFAULT true,
    is_sensitive boolean     NOT NULL DEFAULT false,
    minimum_profile_code text        NOT NULL DEFAULT 'SP1',
    claim_mapping jsonb       NULL,
    deprecated_at timestamptz NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT pk_scope_definition PRIMARY KEY (scope_code),
    CONSTRAINT fk_scope_definition_resource FOREIGN KEY (api_resource_id) REFERENCES oauth.api_resource(id),
    CONSTRAINT ck_scope_definition_code CHECK (scope_code ~ '^[a-z][a-z0-9:._-]{1,127}$'),
    CONSTRAINT ck_scope_definition_profile CHECK (minimum_profile_code IN ('SP1', 'SP1-D', 'SP2', 'SP3', 'SP4', 'SP5')),
    CONSTRAINT ck_scope_definition_sensitive CHECK (NOT is_sensitive OR requires_consent)
);

COMMENT ON TABLE oauth.scope_definition IS 'CAP-AUTHZ-001 / CAP-PRIV-003：Scope 目录、Resource、数据分级、同意要求与 Claim 映射。';

CREATE TABLE oauth.device (
    id uuid        NOT NULL DEFAULT gen_random_uuid(),
    public_id text        NOT NULL,
    user_id uuid        NOT NULL,
    device_lifecycle_state text        NOT NULL DEFAULT 'REGISTERED',
    device_trust_state text        NOT NULL DEFAULT 'UNTRUSTED',
    device_loss_state text        NOT NULL DEFAULT 'CLEAR',
    fingerprint_hash bytea       NOT NULL,
    display_name text        NULL,
    platform_code text        NULL,
    push_token_cipher bytea       NULL,
    cipher_key_version integer     NULL,
    first_seen_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    last_seen_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    trusted_at timestamptz NULL,
    trust_expires_at timestamptz NULL,
    lost_at timestamptz NULL,
    loss_cleared_at timestamptz NULL,
    retired_at timestamptz NULL,
    revoked_at timestamptz NULL,
    revoke_reason_code text        NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    row_version bigint      NOT NULL DEFAULT 1,
    state_reason_code text NULL,
    trust_evidence_hash bytea NULL,
    loss_reason_code text NULL,
    loss_clear_evidence_hash bytea NULL,
    CONSTRAINT pk_device PRIMARY KEY (id),
    CONSTRAINT uq_device_public_id UNIQUE (public_id),
    CONSTRAINT uq_device_fingerprint UNIQUE (user_id, fingerprint_hash),
    CONSTRAINT ck_device_lifecycle CHECK (device_lifecycle_state IN ('REGISTERED', 'RETIRED', 'REVOKED')),
    CONSTRAINT ck_device_trust CHECK (device_trust_state IN ('UNTRUSTED', 'TRUSTED')),
    CONSTRAINT ck_device_loss CHECK (device_loss_state IN ('CLEAR', 'LOST')),
    CONSTRAINT ck_device_fingerprint CHECK (octet_length(fingerprint_hash) = 32),
    CONSTRAINT ck_device_trusted CHECK (device_trust_state <> 'TRUSTED' OR trusted_at IS NOT NULL),
    CONSTRAINT ck_device_lost CHECK (device_loss_state <> 'LOST' OR (lost_at IS NOT NULL AND device_trust_state = 'UNTRUSTED')),
    CONSTRAINT ck_device_trust_evidence CHECK (trust_evidence_hash IS NULL OR octet_length(trust_evidence_hash) = 32),
    CONSTRAINT ck_device_loss_clear_evidence CHECK (loss_clear_evidence_hash IS NULL OR octet_length(loss_clear_evidence_hash) = 32),
    CONSTRAINT ck_device_retired CHECK (device_lifecycle_state <> 'RETIRED' OR retired_at IS NOT NULL),
    CONSTRAINT ck_device_revoked CHECK (
    (device_lifecycle_state = 'REVOKED') = (revoked_at IS NOT NULL)
    AND (device_lifecycle_state <> 'REVOKED' OR revoke_reason_code IS NOT NULL)
    )
);

COMMENT ON TABLE oauth.device IS 'CAP-SESSION-004/006 / REQ-SESSION-017：设备生命周期、可信与挂失三个正交维度；挂失撤销会话和 Token Family。';

CREATE TABLE oauth.authorization_grant (
    id uuid        NOT NULL DEFAULT gen_random_uuid(),
    public_id text        NOT NULL,
    subject_kind text        NOT NULL,
    subject_id uuid        NOT NULL,
    client_id uuid        NOT NULL,
    tenant_id uuid        NOT NULL DEFAULT '00000000-0000-0000-0000-000000000000',
    grant_state text        NOT NULL DEFAULT 'PENDING',
    login_transaction_id uuid        NULL,
    requested_scopes text[]      NOT NULL DEFAULT '{}',
    granted_scopes text[]      NOT NULL DEFAULT '{}',
    granted_resources text[]      NOT NULL DEFAULT '{}',
    authorization_details jsonb       NULL,
    consent_required boolean     NOT NULL DEFAULT false,
    consent_id uuid        NULL,
    consent_context_hash bytea       NULL,
    consent_epoch_at_grant bigint      NULL,
    policy_version bigint      NULL,
    user_epoch_at_grant bigint      NULL,
    client_epoch_at_grant bigint      NOT NULL,
    tenant_epoch_at_grant bigint      NULL,
    granted_at timestamptz NULL,
    denied_at timestamptz NULL,
    expires_at timestamptz NULL,
    revoked_at timestamptz NULL,
    revoke_reason_code text        NULL,
    revoked_by_ref text        NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    row_version bigint      NOT NULL DEFAULT 1,
    machine_epoch_at_grant bigint NULL,
    CONSTRAINT pk_authorization_grant PRIMARY KEY (id),
    CONSTRAINT uq_authorization_grant_public_id UNIQUE (public_id),
    CONSTRAINT fk_authorization_grant_client FOREIGN KEY (client_id) REFERENCES oauth.client(id),
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
    CONSTRAINT ck_authorization_grant_epoch CHECK (client_epoch_at_grant >= 1 AND (consent_epoch_at_grant IS NULL OR consent_epoch_at_grant >= 1)),
    CONSTRAINT fk_grant_client_scope FOREIGN KEY (client_id, tenant_id)
    REFERENCES oauth.client(id, tenant_id),
    CONSTRAINT ck_grant_subject_epoch CHECK (
    (subject_kind = 'USER' AND user_epoch_at_grant IS NOT NULL AND machine_epoch_at_grant IS NULL)
    OR (subject_kind = 'MACHINE' AND user_epoch_at_grant IS NULL AND machine_epoch_at_grant IS NOT NULL)
    ),
    CONSTRAINT ck_grant_subject_context CHECK (
    (subject_kind = 'USER' AND login_transaction_id IS NOT NULL)
    OR (subject_kind = 'MACHINE' AND login_transaction_id IS NULL AND NOT consent_required)
    ),
    CONSTRAINT ck_grant_state_evidence CHECK (
    (granted_at IS NULL OR grant_state IN ('ACTIVE', 'REVOKED', 'EXPIRED'))
    AND ((grant_state = 'DENIED') = (denied_at IS NOT NULL))
    AND (grant_state <> 'ACTIVE' OR (granted_at IS NOT NULL AND expires_at IS NOT NULL))
    AND (grant_state <> 'REVOKED' OR (revoked_at IS NOT NULL AND NULLIF(btrim(revoke_reason_code), '') IS NOT NULL AND NULLIF(btrim(revoked_by_ref), '') IS NOT NULL))
    )
);

COMMENT ON TABLE oauth.authorization_grant IS 'CAP-SESSION-009 / REQ-SESSION-018：PENDING Grant 不能签发 Token；完成 Login Transaction 和所需 Consent 后才可 ACTIVE。';

CREATE TABLE oauth.user_session (
    id uuid        NOT NULL DEFAULT gen_random_uuid(),
    public_id text        NOT NULL,
    session_kind text        NOT NULL DEFAULT 'OP',
    parent_session_id uuid        NULL,
    user_id uuid        NOT NULL,
    device_id uuid        NULL,
    login_transaction_id uuid        NOT NULL,
    origin_client_id uuid        NOT NULL,
    tenant_id uuid        NOT NULL DEFAULT '00000000-0000-0000-0000-000000000000',
    session_state text        NOT NULL DEFAULT 'ACTIVE',
    profile_code text        NOT NULL,
    achieved_aal text        NOT NULL,
    achieved_ial text        NULL,
    achieved_acr text        NULL,
    amr_values text[]      NOT NULL DEFAULT '{}',
    auth_time timestamptz NOT NULL,
    last_reauth_at timestamptz NULL,
    user_epoch_at_issue bigint      NOT NULL,
    client_epoch_at_issue bigint      NOT NULL,
    tenant_epoch_at_issue bigint      NULL,
    idle_expires_at timestamptz NOT NULL,
    absolute_expires_at timestamptz NOT NULL,
    risk_level text        NULL,
    compromised_at timestamptz NULL,
    revoked_at timestamptz NULL,
    revoke_reason_code text        NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    row_version bigint      NOT NULL DEFAULT 1,
    expired_at timestamptz NULL,
    compromise_reason_code text NULL,
    CONSTRAINT pk_user_session PRIMARY KEY (id),
    CONSTRAINT uq_user_session_public_id UNIQUE (public_id),
    CONSTRAINT fk_user_session_parent FOREIGN KEY (parent_session_id) REFERENCES oauth.user_session(id),
    CONSTRAINT fk_user_session_device FOREIGN KEY (device_id) REFERENCES oauth.device(id),
    CONSTRAINT fk_user_session_client FOREIGN KEY (origin_client_id) REFERENCES oauth.client(id),
    CONSTRAINT ck_user_session_kind CHECK (session_kind IN ('OP', 'DEVICE')),
    CONSTRAINT ck_user_session_state CHECK (session_state IN ('ACTIVE', 'EXPIRED', 'COMPROMISED', 'REVOKED')),
    CONSTRAINT ck_user_session_aal CHECK (achieved_aal IN ('AAL1', 'AAL2', 'AAL3')),
    CONSTRAINT ck_user_session_epoch CHECK (user_epoch_at_issue >= 1 AND client_epoch_at_issue >= 1),
    CONSTRAINT ck_user_session_expiry CHECK (idle_expires_at <= absolute_expires_at),
    CONSTRAINT fk_session_client_scope FOREIGN KEY (origin_client_id, tenant_id)
    REFERENCES oauth.client(id, tenant_id),
    CONSTRAINT ck_user_session_expired CHECK ((session_state = 'EXPIRED') = (expired_at IS NOT NULL)),
    CONSTRAINT ck_user_session_compromised CHECK (
    (compromised_at IS NULL) = (compromise_reason_code IS NULL)
    AND (compromised_at IS NULL OR session_state IN ('COMPROMISED', 'REVOKED'))
    AND (session_state <> 'COMPROMISED' OR compromised_at IS NOT NULL)
    ),
    CONSTRAINT ck_user_session_revoked CHECK (
    (revoked_at IS NULL) = (revoke_reason_code IS NULL)
    AND (session_state = 'REVOKED') = (revoked_at IS NOT NULL)
    )
);

COMMENT ON TABLE oauth.user_session IS 'CAP-SESSION-001 至 006 / INV-G-016：仅由 COMPLETED Login Transaction 派生的 OP/Device Session 及安全 epoch 快照。';

CREATE TABLE oauth.token_family (
    id uuid        NOT NULL DEFAULT gen_random_uuid(),
    subject_kind text        NOT NULL,
    subject_id uuid        NOT NULL,
    client_id uuid        NOT NULL,
    grant_id uuid        NOT NULL,
    session_id uuid        NULL,
    device_id uuid        NULL,
    tenant_id uuid        NOT NULL DEFAULT '00000000-0000-0000-0000-000000000000',
    token_family_state text        NOT NULL DEFAULT 'ACTIVE',
    profile_code text        NOT NULL,
    sender_constraint_method text       NULL,
    sender_constraint_thumbprint bytea  NULL,
    generation_count integer     NOT NULL DEFAULT 0,
    idle_expires_at timestamptz NOT NULL,
    absolute_expires_at timestamptz NOT NULL,
    compromised_at timestamptz NULL,
    compromise_reason_code text        NULL,
    revoked_at timestamptz NULL,
    revoke_reason_code text        NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    row_version bigint      NOT NULL DEFAULT 1,
    CONSTRAINT pk_token_family PRIMARY KEY (id),
    CONSTRAINT fk_token_family_client FOREIGN KEY (client_id) REFERENCES oauth.client(id),
    CONSTRAINT fk_token_family_grant FOREIGN KEY (grant_id) REFERENCES oauth.authorization_grant(id),
    CONSTRAINT fk_token_family_session FOREIGN KEY (session_id) REFERENCES oauth.user_session(id),
    CONSTRAINT fk_token_family_device FOREIGN KEY (device_id) REFERENCES oauth.device(id),
    CONSTRAINT ck_token_family_subject CHECK (subject_kind IN ('USER', 'MACHINE')),
    CONSTRAINT ck_token_family_state CHECK (token_family_state IN ('ACTIVE', 'COMPROMISED', 'REVOKED', 'EXPIRED')),
    CONSTRAINT ck_token_family_sender CHECK ((sender_constraint_method IS NULL AND sender_constraint_thumbprint IS NULL) OR (sender_constraint_method IN ('DPOP', 'MTLS') AND sender_constraint_thumbprint IS NOT NULL)),
    CONSTRAINT ck_token_family_expiry CHECK (idle_expires_at <= absolute_expires_at),
    CONSTRAINT ck_token_family_compromised CHECK (
    (compromised_at IS NULL) = (compromise_reason_code IS NULL)
    AND (compromised_at IS NULL OR token_family_state IN ('COMPROMISED', 'REVOKED'))
    AND (token_family_state <> 'COMPROMISED' OR compromised_at IS NOT NULL)
    ),
    CONSTRAINT ck_token_family_revoked CHECK (
    (revoked_at IS NULL) = (revoke_reason_code IS NULL)
    AND (token_family_state = 'REVOKED') = (revoked_at IS NOT NULL)
    )
);

COMMENT ON TABLE oauth.token_family IS 'CAP-SESSION-008 / CAP-OAP-008：Refresh Token 家族、设备/会话/Grant 绑定、发送方约束与家族级失陷撤销。';

CREATE TABLE oauth.refresh_token (
    id uuid        NOT NULL DEFAULT gen_random_uuid(),
    family_id uuid        NOT NULL,
    generation integer     NOT NULL,
    token_hash bytea       NOT NULL,
    refresh_token_instance_state text        NOT NULL DEFAULT 'CURRENT',
    issued_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    expires_at timestamptz NOT NULL,
    used_at timestamptz NULL,
    successor_id uuid        NULL,
    retry_window_until timestamptz NULL,
    binding_context_hash bytea       NULL,
    revoked_at timestamptz NULL,
    revoke_reason_code text        NULL,
    CONSTRAINT pk_refresh_token PRIMARY KEY (id),
    CONSTRAINT uq_refresh_token_hash UNIQUE (token_hash),
    CONSTRAINT uq_refresh_token_generation UNIQUE (family_id, generation),
    CONSTRAINT fk_refresh_token_family FOREIGN KEY (family_id) REFERENCES oauth.token_family(id) ON DELETE CASCADE,
    CONSTRAINT ck_refresh_token_state CHECK (refresh_token_instance_state IN ('CURRENT', 'USED', 'REVOKED', 'EXPIRED')),
    CONSTRAINT ck_refresh_token_hash CHECK (octet_length(token_hash) = 32),
    CONSTRAINT ck_refresh_token_generation CHECK (generation > 0),
    CONSTRAINT fk_refresh_token_successor FOREIGN KEY (successor_id) REFERENCES oauth.refresh_token(id)
    DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT ck_refresh_token_used CHECK (
    (refresh_token_instance_state = 'USED' AND used_at IS NOT NULL AND successor_id IS NOT NULL AND retry_window_until IS NOT NULL)
    OR (refresh_token_instance_state <> 'USED' AND used_at IS NULL AND successor_id IS NULL AND retry_window_until IS NULL)
    ),
    CONSTRAINT ck_refresh_token_revoked CHECK (
    (refresh_token_instance_state = 'REVOKED' AND revoked_at IS NOT NULL AND NULLIF(btrim(revoke_reason_code), '') IS NOT NULL)
    OR (refresh_token_instance_state <> 'REVOKED' AND revoked_at IS NULL AND revoke_reason_code IS NULL)
    ),
    CONSTRAINT ck_refresh_token_retry_window CHECK (
    retry_window_until IS NULL OR (used_at IS NOT NULL AND retry_window_until >= used_at AND retry_window_until <= used_at + interval '60 seconds')
    )
);

COMMENT ON TABLE oauth.refresh_token IS 'REQ-SESSION-002/014：Refresh Token 单次实例、原子轮换、丢包重试窗口和重放检测；只保存哈希。';

CREATE TABLE oauth.authorization_code (
    id uuid        NOT NULL DEFAULT gen_random_uuid(),
    code_hash bytea       NOT NULL,
    authorization_code_state text        NOT NULL DEFAULT 'ISSUED',
    client_id uuid        NOT NULL,
    user_id uuid        NOT NULL,
    login_transaction_id uuid        NOT NULL,
    session_id uuid        NULL,
    grant_id uuid        NOT NULL,
    redirect_uri text        NOT NULL,
    code_challenge text        NOT NULL,
    code_challenge_method text        NOT NULL DEFAULT 'S256',
    nonce_hash bytea       NULL,
    scopes text[]      NOT NULL DEFAULT '{}',
    resources text[]      NOT NULL DEFAULT '{}',
    issued_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz NULL,
    replay_detected_at timestamptz NULL,
    revoked_at timestamptz NULL,
    CONSTRAINT pk_authorization_code PRIMARY KEY (id),
    CONSTRAINT uq_authorization_code_hash UNIQUE (code_hash),
    CONSTRAINT fk_authorization_code_client FOREIGN KEY (client_id) REFERENCES oauth.client(id),
    CONSTRAINT fk_authorization_code_session FOREIGN KEY (session_id) REFERENCES oauth.user_session(id),
    CONSTRAINT fk_authorization_code_grant FOREIGN KEY (grant_id) REFERENCES oauth.authorization_grant(id),
    CONSTRAINT ck_authorization_code_state CHECK (authorization_code_state IN ('ISSUED', 'CONSUMED', 'EXPIRED', 'REVOKED')),
    CONSTRAINT ck_authorization_code_hash CHECK (octet_length(code_hash) = 32),
    CONSTRAINT ck_authorization_code_pkce CHECK (code_challenge_method = 'S256'),
    CONSTRAINT ck_authorization_code_consumed CHECK ((authorization_code_state = 'CONSUMED') = (consumed_at IS NOT NULL)),
    CONSTRAINT ck_authorization_code_ttl CHECK (expires_at > issued_at AND expires_at - issued_at <= interval '60 seconds'),
    CONSTRAINT ck_authorization_code_revoked CHECK ((authorization_code_state = 'REVOKED') = (revoked_at IS NOT NULL)),
    CONSTRAINT ck_authorization_code_replay CHECK (replay_detected_at IS NULL OR authorization_code_state = 'CONSUMED')
);

COMMENT ON TABLE oauth.authorization_code IS 'REQ-AUTH-004：绑定 Client、redirect URI、PKCE、Login Transaction 与 Grant 的单次授权码；重放触发关联撤销。';

CREATE TABLE oauth.reference_access_token (
    jti text        NOT NULL,
    token_hash bytea       NOT NULL,
    subject_kind text        NOT NULL,
    subject_id uuid        NOT NULL,
    actor_kind text        NULL,
    actor_ref text        NULL,
    client_id uuid        NOT NULL,
    grant_id uuid        NOT NULL,
    session_id uuid        NULL,
    token_family_id uuid        NULL,
    tenant_id uuid        NOT NULL DEFAULT '00000000-0000-0000-0000-000000000000',
    audiences text[]      NOT NULL,
    scopes text[]      NOT NULL DEFAULT '{}',
    profile_code text        NOT NULL,
    policy_version bigint      NULL,
    user_epoch_at_issue bigint      NULL,
    client_epoch_at_issue bigint      NOT NULL,
    tenant_epoch_at_issue bigint      NULL,
    consent_id uuid        NULL,
    consent_context_hash bytea       NULL,
    consent_epoch_at_issue bigint      NULL,
    sender_constraint_thumbprint bytea    NULL,
    issued_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    expires_at timestamptz NOT NULL,
    revoked_at timestamptz NULL,
    machine_epoch_at_issue bigint NULL,
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
    CONSTRAINT ck_reference_access_token_ttl CHECK (expires_at > issued_at),
    CONSTRAINT ck_reference_token_subject_epoch CHECK (
    (subject_kind = 'USER' AND user_epoch_at_issue IS NOT NULL AND machine_epoch_at_issue IS NULL)
    OR (subject_kind = 'MACHINE' AND user_epoch_at_issue IS NULL AND machine_epoch_at_issue IS NOT NULL)
    )
);

COMMENT ON TABLE oauth.reference_access_token IS 'CAP-SESSION-007/011：需内省的 Access Token 引用、Subject/Actor、audience/scope 和全部适用安全版本快照。';

CREATE TABLE oauth.revocation_record (
    id uuid        NOT NULL DEFAULT gen_random_uuid(),
    revocation_kind text        NOT NULL,
    target_ref text        NOT NULL,
    user_id uuid        NULL,
    client_id uuid        NULL,
    tenant_id uuid        NOT NULL DEFAULT '00000000-0000-0000-0000-000000000000',
    effective_epoch bigint      NULL,
    reason_code text        NOT NULL,
    source_kind text        NOT NULL,
    source_ref text        NULL,
    revoked_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    prunable_after timestamptz NOT NULL,
    CONSTRAINT pk_revocation_record PRIMARY KEY (id),
    CONSTRAINT ck_revocation_record_kind CHECK (revocation_kind IN ('SESSION', 'TOKEN_FAMILY', 'GRANT', 'CLIENT', 'USER_EPOCH', 'TENANT_EPOCH', 'CONSENT_EPOCH', 'JTI', 'DEVICE', 'AUTHENTICATOR', 'DELEGATION')),
    CONSTRAINT ck_revocation_record_source CHECK (source_kind IN ('USER', 'ADMIN', 'RISK', 'SYSTEM', 'IDENTITY_PROVIDER', 'PRIVACY', 'CLIENT')),
    CONSTRAINT ck_revocation_record_retention CHECK (prunable_after > revoked_at)
);

COMMENT ON TABLE oauth.revocation_record IS 'CAP-SESSION-010 / REQ-SESSION-012：Grant、Client、Session、Token、Consent、设备与委托撤销水位的追加记录。';

CREATE TABLE oauth.logout_request (
    id uuid        NOT NULL DEFAULT gen_random_uuid(),
    operation_id uuid        NOT NULL,
    user_id uuid        NOT NULL,
    scope_kind text        NOT NULL,
    scope_ref text        NULL,
    initiator_kind text        NOT NULL,
    initiator_ref text        NULL,
    logout_state text        NOT NULL DEFAULT 'IN_PROGRESS',
    requested_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    completed_at timestamptz NULL,
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    row_version bigint      NOT NULL DEFAULT 1,
    CONSTRAINT pk_logout_request PRIMARY KEY (id),
    CONSTRAINT uq_logout_request_operation UNIQUE (operation_id),
    CONSTRAINT ck_logout_request_scope CHECK (scope_kind IN ('CLIENT', 'SESSION', 'DEVICE', 'TENANT', 'ALL_DEVICES', 'GLOBAL')),
    CONSTRAINT ck_logout_request_initiator CHECK (initiator_kind IN ('USER', 'ADMIN', 'RISK', 'IDENTITY_PROVIDER', 'SYSTEM')),
    CONSTRAINT ck_logout_request_state CHECK (logout_state IN ('IN_PROGRESS', 'PARTIAL', 'COMPLETED')),
    CONSTRAINT ck_logout_request_completed CHECK ((logout_state = 'COMPLETED') = (completed_at IS NOT NULL))
);

COMMENT ON TABLE oauth.logout_request IS 'CAP-SESSION-002 / CAP-OAP-012：OP、RP、Device Session 与 Token Family 的完整退出 Operation。';

CREATE TABLE oauth.logout_target_result (
    id uuid        NOT NULL DEFAULT gen_random_uuid(),
    logout_request_id uuid        NOT NULL,
    client_id uuid        NOT NULL,
    channel text        NOT NULL,
    delivery_state text        NOT NULL DEFAULT 'PENDING',
    unconfirmed_reason_class text        NULL,
    attempt_count integer     NOT NULL DEFAULT 0,
    next_attempt_at timestamptz NULL,
    confirmed_at timestamptz NULL,
    last_error_code text        NULL,
    dead_lettered_at timestamptz NULL,
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
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

CREATE INDEX ix_client_owner_review ON oauth.client(owner_ref, expires_at) WHERE client_state = 'ACTIVE';

CREATE INDEX ix_device_user ON oauth.device(user_id, device_lifecycle_state, device_loss_state);

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

CREATE UNIQUE INDEX ux_authorization_grant_active
    ON oauth.authorization_grant(subject_kind, subject_id, client_id, tenant_id)
    WHERE grant_state IN ('PENDING', 'ACTIVE');

CREATE UNIQUE INDEX ux_user_session_login_transaction ON oauth.user_session(login_transaction_id);

CREATE UNIQUE INDEX ux_authorization_code_login_transaction ON oauth.authorization_code(login_transaction_id);

CREATE UNIQUE INDEX ux_token_family_active_grant ON oauth.token_family(grant_id)
    WHERE token_family_state = 'ACTIVE';

CREATE INDEX ix_fk_client_application_id ON oauth.client (application_id);

CREATE INDEX ix_fk_client_credential_rotated_from_id ON oauth.client_credential (rotated_from_id);

CREATE INDEX ix_fk_scope_definition_api_resource_id ON oauth.scope_definition (api_resource_id);

CREATE INDEX ix_fk_authorization_grant_client_id_tenant_id ON oauth.authorization_grant (client_id, tenant_id);

CREATE INDEX ix_fk_user_session_parent_session_id ON oauth.user_session (parent_session_id);

CREATE INDEX ix_fk_user_session_device_id ON oauth.user_session (device_id);

CREATE INDEX ix_fk_user_session_origin_client_id ON oauth.user_session (origin_client_id);

CREATE INDEX ix_fk_user_session_origin_client_id_tenant_id ON oauth.user_session (origin_client_id, tenant_id);

CREATE INDEX ix_fk_token_family_client_id ON oauth.token_family (client_id);

CREATE INDEX ix_fk_token_family_session_id ON oauth.token_family (session_id);

CREATE INDEX ix_fk_token_family_device_id ON oauth.token_family (device_id);

CREATE INDEX ix_fk_refresh_token_successor_id ON oauth.refresh_token (successor_id);

CREATE INDEX ix_fk_authorization_code_client_id ON oauth.authorization_code (client_id);

CREATE INDEX ix_fk_authorization_code_session_id ON oauth.authorization_code (session_id);

CREATE INDEX ix_fk_authorization_code_grant_id ON oauth.authorization_code (grant_id);

CREATE INDEX ix_fk_reference_access_token_client_id ON oauth.reference_access_token (client_id);

CREATE INDEX ix_fk_reference_access_token_grant_id ON oauth.reference_access_token (grant_id);

CREATE INDEX ix_fk_reference_access_token_session_id ON oauth.reference_access_token (session_id);

CREATE INDEX ix_fk_reference_access_token_token_family_id ON oauth.reference_access_token (token_family_id);

CREATE INDEX ix_fk_logout_target_result_client_id ON oauth.logout_target_result (client_id);

COMMENT ON COLUMN oauth.application.id IS '内部 UUID 主键；仅用于数据库关系，不作为跨域公开标识。';
COMMENT ON COLUMN oauth.application.public_id IS '不可复用的公开稳定标识；插入时登记到 core.public_id_ledger。';
COMMENT ON COLUMN oauth.application.business_line_id IS '业务线隔离键；关联 org.business_line，用于业务线范围隔离。';
COMMENT ON COLUMN oauth.application.display_name IS 'oauth.application.display_name 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN oauth.application.application_type IS '对象类别判别字段；允许值由 CHECK 或对应注册表限定。';
COMMENT ON COLUMN oauth.application.application_state IS '显式状态当前值；合法取值见 CHECK，完整状态转换由 .NET 领域策略执行。';
COMMENT ON COLUMN oauth.application.owner_ref IS '不透明对象引用；不得从格式推断手机号、邮箱或其他业务事实。';
COMMENT ON COLUMN oauth.application.contact_ref IS '不透明对象引用；不得从格式推断手机号、邮箱或其他业务事实。';
COMMENT ON COLUMN oauth.application.created_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN oauth.application.updated_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN oauth.application.row_version IS '乐观并发版本；更新必须使用原值 compare-and-set，成功后由数据库单调递增。';
COMMENT ON COLUMN oauth.client.id IS '内部 UUID 主键；仅用于数据库关系，不作为跨域公开标识。';
COMMENT ON COLUMN oauth.client.public_id IS '不可复用的公开稳定标识；插入时登记到 core.public_id_ledger。';
COMMENT ON COLUMN oauth.client.application_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN oauth.client.business_line_id IS '业务线隔离键；关联 org.business_line，用于业务线范围隔离。';
COMMENT ON COLUMN oauth.client.tenant_id IS '租户隔离键；全零 UUID 表示平台范围，应用查询必须显式携带可信租户上下文。';
COMMENT ON COLUMN oauth.client.environment IS 'oauth.client.environment 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN oauth.client.client_state IS '显式状态当前值；合法取值见 CHECK，完整状态转换由 .NET 领域策略执行。';
COMMENT ON COLUMN oauth.client.client_kind IS '对象类别判别字段；允许值由 CHECK 或对应注册表限定。';
COMMENT ON COLUMN oauth.client.display_name IS 'oauth.client.display_name 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN oauth.client.profile_code IS '稳定机器可读代码；展示文本由资源或目录解析。';
COMMENT ON COLUMN oauth.client.profile_version IS '对象、策略或源数据的显式版本；不得以不可信客户端时间戳替代。';
COMMENT ON COLUMN oauth.client.token_endpoint_auth_method IS 'oauth.client.token_endpoint_auth_method 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN oauth.client.allowed_grant_types IS '代码或引用集合；写入前去重、校验 allowlist，并满足表约束。';
COMMENT ON COLUMN oauth.client.allowed_scopes IS '代码或引用集合；写入前去重、校验 allowlist，并满足表约束。';
COMMENT ON COLUMN oauth.client.allowed_resources IS '代码或引用集合；写入前去重、校验 allowlist，并满足表约束。';
COMMENT ON COLUMN oauth.client.subject_mode IS 'oauth.client.subject_mode 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN oauth.client.access_token_format IS 'oauth.client.access_token_format 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN oauth.client.id_token_signed_alg IS 'oauth.client.id_token_signed_alg 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN oauth.client.require_par IS 'oauth.client.require_par 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN oauth.client.require_sender_constrained IS 'oauth.client.require_sender_constrained 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN oauth.client.sender_constraint_method IS 'oauth.client.sender_constraint_method 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN oauth.client.consent_required IS 'oauth.client.consent_required 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN oauth.client.sso_domain_boundary IS 'oauth.client.sso_domain_boundary 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN oauth.client.owner_ref IS '不透明对象引用；不得从格式推断手机号、邮箱或其他业务事实。';
COMMENT ON COLUMN oauth.client.permission_baseline IS '版本化结构化扩展数据；必须由 .NET 按对应 JSON Schema 校验，不得替代核心状态或外键。';
COMMENT ON COLUMN oauth.client.credential_rotation_policy IS '版本化结构化扩展数据；必须由 .NET 按对应 JSON Schema 校验，不得替代核心状态或外键。';
COMMENT ON COLUMN oauth.client.client_security_epoch IS '安全或同意水位版本；只能单调递增，用于令牌、缓存与撤销新鲜度校验。';
COMMENT ON COLUMN oauth.client.onboarding_report_ref IS '不透明对象引用；不得从格式推断手机号、邮箱或其他业务事实。';
COMMENT ON COLUMN oauth.client.approval_case_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN oauth.client.reactivation_review_ref IS '不透明对象引用；不得从格式推断手机号、邮箱或其他业务事实。';
COMMENT ON COLUMN oauth.client.approved_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN oauth.client.suspended_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN oauth.client.compromised_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN oauth.client.retired_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN oauth.client.expires_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN oauth.client.last_used_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN oauth.client.created_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN oauth.client.updated_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN oauth.client.row_version IS '乐观并发版本；更新必须使用原值 compare-and-set，成功后由数据库单调递增。';
COMMENT ON COLUMN oauth.client.configuration_hash IS '不可逆摘要；用于等值匹配、幂等、完整性或最小化证据，不保存原始敏感值。';
COMMENT ON COLUMN oauth.client.approval_execution_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN oauth.client.last_activation_execution_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN oauth.client_uri.id IS '内部 UUID 主键；仅用于数据库关系，不作为跨域公开标识。';
COMMENT ON COLUMN oauth.client_uri.client_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN oauth.client_uri.uri_kind IS '对象类别判别字段；允许值由 CHECK 或对应注册表限定。';
COMMENT ON COLUMN oauth.client_uri.uri_value IS 'oauth.client_uri.uri_value 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN oauth.client_uri.is_loopback IS '显式布尔开关；启用前置条件与失效行为由约束和版本化策略控制。';
COMMENT ON COLUMN oauth.client_uri.created_by_ref IS '不透明对象引用；不得从格式推断手机号、邮箱或其他业务事实。';
COMMENT ON COLUMN oauth.client_uri.created_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN oauth.client_credential.id IS '内部 UUID 主键；仅用于数据库关系，不作为跨域公开标识。';
COMMENT ON COLUMN oauth.client_credential.client_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN oauth.client_credential.credential_kind IS '对象类别判别字段；允许值由 CHECK 或对应注册表限定。';
COMMENT ON COLUMN oauth.client_credential.credential_state IS '显式状态当前值；合法取值见 CHECK，完整状态转换由 .NET 领域策略执行。';
COMMENT ON COLUMN oauth.client_credential.key_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN oauth.client_credential.secret_hash IS '不可逆摘要；用于等值匹配、幂等、完整性或最小化证据，不保存原始敏感值。';
COMMENT ON COLUMN oauth.client_credential.public_jwk IS '版本化结构化扩展数据；必须由 .NET 按对应 JSON Schema 校验，不得替代核心状态或外键。';
COMMENT ON COLUMN oauth.client_credential.jwks_uri IS '受控 URI；写入前必须执行协议、主机、重定向与 SSRF 安全校验。';
COMMENT ON COLUMN oauth.client_credential.certificate_thumbprint IS 'oauth.client_credential.certificate_thumbprint 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN oauth.client_credential.algorithm IS 'oauth.client_credential.algorithm 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN oauth.client_credential.not_before IS 'oauth.client_credential.not_before 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN oauth.client_credential.not_after IS 'oauth.client_credential.not_after 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN oauth.client_credential.rotated_from_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN oauth.client_credential.revoked_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN oauth.client_credential.revoke_reason_code IS '稳定机器可读代码；展示文本由资源或目录解析。';
COMMENT ON COLUMN oauth.client_credential.created_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN oauth.client_credential.updated_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN oauth.client_credential.row_version IS '乐观并发版本；更新必须使用原值 compare-and-set，成功后由数据库单调递增。';
COMMENT ON COLUMN oauth.api_resource.id IS '内部 UUID 主键；仅用于数据库关系，不作为跨域公开标识。';
COMMENT ON COLUMN oauth.api_resource.public_id IS '不可复用的公开稳定标识；插入时登记到 core.public_id_ledger。';
COMMENT ON COLUMN oauth.api_resource.audience_value IS 'oauth.api_resource.audience_value 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN oauth.api_resource.display_name IS 'oauth.api_resource.display_name 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN oauth.api_resource.business_line_id IS '业务线隔离键；关联 org.business_line，用于业务线范围隔离。';
COMMENT ON COLUMN oauth.api_resource.owner_ref IS '不透明对象引用；不得从格式推断手机号、邮箱或其他业务事实。';
COMMENT ON COLUMN oauth.api_resource.resource_state IS '显式状态当前值；合法取值见 CHECK，完整状态转换由 .NET 领域策略执行。';
COMMENT ON COLUMN oauth.api_resource.minimum_profile_code IS '稳定机器可读代码；展示文本由资源或目录解析。';
COMMENT ON COLUMN oauth.api_resource.revocation_check_mode IS 'oauth.api_resource.revocation_check_mode 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN oauth.api_resource.supported_obligations IS '代码或引用集合；写入前去重、校验 allowlist，并满足表约束。';
COMMENT ON COLUMN oauth.api_resource.onboarding_report_ref IS '不透明对象引用；不得从格式推断手机号、邮箱或其他业务事实。';
COMMENT ON COLUMN oauth.api_resource.created_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN oauth.api_resource.updated_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN oauth.api_resource.row_version IS '乐观并发版本；更新必须使用原值 compare-and-set，成功后由数据库单调递增。';
COMMENT ON COLUMN oauth.scope_definition.scope_code IS '稳定机器可读代码；展示文本由资源或目录解析。';
COMMENT ON COLUMN oauth.scope_definition.api_resource_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN oauth.scope_definition.display_name IS 'oauth.scope_definition.display_name 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN oauth.scope_definition.description IS 'oauth.scope_definition.description 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN oauth.scope_definition.data_classification IS 'oauth.scope_definition.data_classification 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN oauth.scope_definition.requires_consent IS 'oauth.scope_definition.requires_consent 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN oauth.scope_definition.is_sensitive IS '显式布尔开关；启用前置条件与失效行为由约束和版本化策略控制。';
COMMENT ON COLUMN oauth.scope_definition.minimum_profile_code IS '稳定机器可读代码；展示文本由资源或目录解析。';
COMMENT ON COLUMN oauth.scope_definition.claim_mapping IS '版本化结构化扩展数据；必须由 .NET 按对应 JSON Schema 校验，不得替代核心状态或外键。';
COMMENT ON COLUMN oauth.scope_definition.deprecated_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN oauth.scope_definition.created_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN oauth.device.id IS '内部 UUID 主键；仅用于数据库关系，不作为跨域公开标识。';
COMMENT ON COLUMN oauth.device.public_id IS '不可复用的公开稳定标识；插入时登记到 core.public_id_ledger。';
COMMENT ON COLUMN oauth.device.user_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN oauth.device.device_lifecycle_state IS '显式状态当前值；合法取值见 CHECK，完整状态转换由 .NET 领域策略执行。';
COMMENT ON COLUMN oauth.device.device_trust_state IS '显式状态当前值；合法取值见 CHECK，完整状态转换由 .NET 领域策略执行。';
COMMENT ON COLUMN oauth.device.device_loss_state IS '显式状态当前值；合法取值见 CHECK，完整状态转换由 .NET 领域策略执行。';
COMMENT ON COLUMN oauth.device.fingerprint_hash IS '不可逆摘要；用于等值匹配、幂等、完整性或最小化证据，不保存原始敏感值。';
COMMENT ON COLUMN oauth.device.display_name IS 'oauth.device.display_name 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN oauth.device.platform_code IS '稳定机器可读代码；展示文本由资源或目录解析。';
COMMENT ON COLUMN oauth.device.push_token_cipher IS '随机化加密密文；解密密钥由独立 KMS/HSM 引用管理。';
COMMENT ON COLUMN oauth.device.cipher_key_version IS '生成密文、HMAC 或盲索引所用密钥版本；轮换时保留可验证窗口。';
COMMENT ON COLUMN oauth.device.first_seen_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN oauth.device.last_seen_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN oauth.device.trusted_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN oauth.device.trust_expires_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN oauth.device.lost_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN oauth.device.loss_cleared_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN oauth.device.retired_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN oauth.device.revoked_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN oauth.device.revoke_reason_code IS '稳定机器可读代码；展示文本由资源或目录解析。';
COMMENT ON COLUMN oauth.device.created_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN oauth.device.updated_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN oauth.device.row_version IS '乐观并发版本；更新必须使用原值 compare-and-set，成功后由数据库单调递增。';
COMMENT ON COLUMN oauth.device.state_reason_code IS '稳定机器可读代码；展示文本由资源或目录解析。';
COMMENT ON COLUMN oauth.device.trust_evidence_hash IS '不可逆摘要；用于等值匹配、幂等、完整性或最小化证据，不保存原始敏感值。';
COMMENT ON COLUMN oauth.device.loss_reason_code IS '稳定机器可读代码；展示文本由资源或目录解析。';
COMMENT ON COLUMN oauth.device.loss_clear_evidence_hash IS '不可逆摘要；用于等值匹配、幂等、完整性或最小化证据，不保存原始敏感值。';
COMMENT ON COLUMN oauth.authorization_grant.id IS '内部 UUID 主键；仅用于数据库关系，不作为跨域公开标识。';
COMMENT ON COLUMN oauth.authorization_grant.public_id IS '不可复用的公开稳定标识；插入时登记到 core.public_id_ledger。';
COMMENT ON COLUMN oauth.authorization_grant.subject_kind IS '对象类别判别字段；允许值由 CHECK 或对应注册表限定。';
COMMENT ON COLUMN oauth.authorization_grant.subject_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN oauth.authorization_grant.client_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN oauth.authorization_grant.tenant_id IS '租户隔离键；全零 UUID 表示平台范围，应用查询必须显式携带可信租户上下文。';
COMMENT ON COLUMN oauth.authorization_grant.grant_state IS '显式状态当前值；合法取值见 CHECK，完整状态转换由 .NET 领域策略执行。';
COMMENT ON COLUMN oauth.authorization_grant.login_transaction_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN oauth.authorization_grant.requested_scopes IS '代码或引用集合；写入前去重、校验 allowlist，并满足表约束。';
COMMENT ON COLUMN oauth.authorization_grant.granted_scopes IS '代码或引用集合；写入前去重、校验 allowlist，并满足表约束。';
COMMENT ON COLUMN oauth.authorization_grant.granted_resources IS '代码或引用集合；写入前去重、校验 allowlist，并满足表约束。';
COMMENT ON COLUMN oauth.authorization_grant.authorization_details IS '版本化结构化扩展数据；必须由 .NET 按对应 JSON Schema 校验，不得替代核心状态或外键。';
COMMENT ON COLUMN oauth.authorization_grant.consent_required IS 'oauth.authorization_grant.consent_required 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN oauth.authorization_grant.consent_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN oauth.authorization_grant.consent_context_hash IS '不可逆摘要；用于等值匹配、幂等、完整性或最小化证据，不保存原始敏感值。';
COMMENT ON COLUMN oauth.authorization_grant.consent_epoch_at_grant IS '安全或同意水位版本；只能单调递增，用于令牌、缓存与撤销新鲜度校验。';
COMMENT ON COLUMN oauth.authorization_grant.policy_version IS '对象、策略或源数据的显式版本；不得以不可信客户端时间戳替代。';
COMMENT ON COLUMN oauth.authorization_grant.user_epoch_at_grant IS '安全或同意水位版本；只能单调递增，用于令牌、缓存与撤销新鲜度校验。';
COMMENT ON COLUMN oauth.authorization_grant.client_epoch_at_grant IS '安全或同意水位版本；只能单调递增，用于令牌、缓存与撤销新鲜度校验。';
COMMENT ON COLUMN oauth.authorization_grant.tenant_epoch_at_grant IS '安全或同意水位版本；只能单调递增，用于令牌、缓存与撤销新鲜度校验。';
COMMENT ON COLUMN oauth.authorization_grant.granted_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN oauth.authorization_grant.denied_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN oauth.authorization_grant.expires_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN oauth.authorization_grant.revoked_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN oauth.authorization_grant.revoke_reason_code IS '稳定机器可读代码；展示文本由资源或目录解析。';
COMMENT ON COLUMN oauth.authorization_grant.revoked_by_ref IS '不透明对象引用；不得从格式推断手机号、邮箱或其他业务事实。';
COMMENT ON COLUMN oauth.authorization_grant.created_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN oauth.authorization_grant.updated_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN oauth.authorization_grant.row_version IS '乐观并发版本；更新必须使用原值 compare-and-set，成功后由数据库单调递增。';
COMMENT ON COLUMN oauth.authorization_grant.machine_epoch_at_grant IS '安全或同意水位版本；只能单调递增，用于令牌、缓存与撤销新鲜度校验。';
COMMENT ON COLUMN oauth.user_session.id IS '内部 UUID 主键；仅用于数据库关系，不作为跨域公开标识。';
COMMENT ON COLUMN oauth.user_session.public_id IS '不可复用的公开稳定标识；插入时登记到 core.public_id_ledger。';
COMMENT ON COLUMN oauth.user_session.session_kind IS '对象类别判别字段；允许值由 CHECK 或对应注册表限定。';
COMMENT ON COLUMN oauth.user_session.parent_session_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN oauth.user_session.user_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN oauth.user_session.device_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN oauth.user_session.login_transaction_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN oauth.user_session.origin_client_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN oauth.user_session.tenant_id IS '租户隔离键；全零 UUID 表示平台范围，应用查询必须显式携带可信租户上下文。';
COMMENT ON COLUMN oauth.user_session.session_state IS '显式状态当前值；合法取值见 CHECK，完整状态转换由 .NET 领域策略执行。';
COMMENT ON COLUMN oauth.user_session.profile_code IS '稳定机器可读代码；展示文本由资源或目录解析。';
COMMENT ON COLUMN oauth.user_session.achieved_aal IS 'oauth.user_session.achieved_aal 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN oauth.user_session.achieved_ial IS 'oauth.user_session.achieved_ial 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN oauth.user_session.achieved_acr IS 'oauth.user_session.achieved_acr 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN oauth.user_session.amr_values IS '代码或引用集合；写入前去重、校验 allowlist，并满足表约束。';
COMMENT ON COLUMN oauth.user_session.auth_time IS 'oauth.user_session.auth_time 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN oauth.user_session.last_reauth_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN oauth.user_session.user_epoch_at_issue IS '安全或同意水位版本；只能单调递增，用于令牌、缓存与撤销新鲜度校验。';
COMMENT ON COLUMN oauth.user_session.client_epoch_at_issue IS '安全或同意水位版本；只能单调递增，用于令牌、缓存与撤销新鲜度校验。';
COMMENT ON COLUMN oauth.user_session.tenant_epoch_at_issue IS '安全或同意水位版本；只能单调递增，用于令牌、缓存与撤销新鲜度校验。';
COMMENT ON COLUMN oauth.user_session.idle_expires_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN oauth.user_session.absolute_expires_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN oauth.user_session.risk_level IS 'oauth.user_session.risk_level 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN oauth.user_session.compromised_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN oauth.user_session.revoked_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN oauth.user_session.revoke_reason_code IS '稳定机器可读代码；展示文本由资源或目录解析。';
COMMENT ON COLUMN oauth.user_session.created_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN oauth.user_session.updated_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN oauth.user_session.row_version IS '乐观并发版本；更新必须使用原值 compare-and-set，成功后由数据库单调递增。';
COMMENT ON COLUMN oauth.user_session.expired_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN oauth.user_session.compromise_reason_code IS '稳定机器可读代码；展示文本由资源或目录解析。';
COMMENT ON COLUMN oauth.token_family.id IS '内部 UUID 主键；仅用于数据库关系，不作为跨域公开标识。';
COMMENT ON COLUMN oauth.token_family.subject_kind IS '对象类别判别字段；允许值由 CHECK 或对应注册表限定。';
COMMENT ON COLUMN oauth.token_family.subject_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN oauth.token_family.client_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN oauth.token_family.grant_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN oauth.token_family.session_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN oauth.token_family.device_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN oauth.token_family.tenant_id IS '租户隔离键；全零 UUID 表示平台范围，应用查询必须显式携带可信租户上下文。';
COMMENT ON COLUMN oauth.token_family.token_family_state IS '显式状态当前值；合法取值见 CHECK，完整状态转换由 .NET 领域策略执行。';
COMMENT ON COLUMN oauth.token_family.profile_code IS '稳定机器可读代码；展示文本由资源或目录解析。';
COMMENT ON COLUMN oauth.token_family.sender_constraint_method IS 'oauth.token_family.sender_constraint_method 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN oauth.token_family.sender_constraint_thumbprint IS 'oauth.token_family.sender_constraint_thumbprint 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN oauth.token_family.generation_count IS '非负计数器；并发更新使用原子 SQL 或乐观并发控制。';
COMMENT ON COLUMN oauth.token_family.idle_expires_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN oauth.token_family.absolute_expires_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN oauth.token_family.compromised_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN oauth.token_family.compromise_reason_code IS '稳定机器可读代码；展示文本由资源或目录解析。';
COMMENT ON COLUMN oauth.token_family.revoked_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN oauth.token_family.revoke_reason_code IS '稳定机器可读代码；展示文本由资源或目录解析。';
COMMENT ON COLUMN oauth.token_family.created_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN oauth.token_family.updated_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN oauth.token_family.row_version IS '乐观并发版本；更新必须使用原值 compare-and-set，成功后由数据库单调递增。';
COMMENT ON COLUMN oauth.refresh_token.id IS '内部 UUID 主键；仅用于数据库关系，不作为跨域公开标识。';
COMMENT ON COLUMN oauth.refresh_token.family_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN oauth.refresh_token.generation IS 'oauth.refresh_token.generation 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN oauth.refresh_token.token_hash IS '不可逆摘要；用于等值匹配、幂等、完整性或最小化证据，不保存原始敏感值。';
COMMENT ON COLUMN oauth.refresh_token.refresh_token_instance_state IS '显式状态当前值；合法取值见 CHECK，完整状态转换由 .NET 领域策略执行。';
COMMENT ON COLUMN oauth.refresh_token.issued_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN oauth.refresh_token.expires_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN oauth.refresh_token.used_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN oauth.refresh_token.successor_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN oauth.refresh_token.retry_window_until IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN oauth.refresh_token.binding_context_hash IS '不可逆摘要；用于等值匹配、幂等、完整性或最小化证据，不保存原始敏感值。';
COMMENT ON COLUMN oauth.refresh_token.revoked_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN oauth.refresh_token.revoke_reason_code IS '稳定机器可读代码；展示文本由资源或目录解析。';
COMMENT ON COLUMN oauth.authorization_code.id IS '内部 UUID 主键；仅用于数据库关系，不作为跨域公开标识。';
COMMENT ON COLUMN oauth.authorization_code.code_hash IS '不可逆摘要；用于等值匹配、幂等、完整性或最小化证据，不保存原始敏感值。';
COMMENT ON COLUMN oauth.authorization_code.authorization_code_state IS '显式状态当前值；合法取值见 CHECK，完整状态转换由 .NET 领域策略执行。';
COMMENT ON COLUMN oauth.authorization_code.client_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN oauth.authorization_code.user_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN oauth.authorization_code.login_transaction_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN oauth.authorization_code.session_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN oauth.authorization_code.grant_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN oauth.authorization_code.redirect_uri IS '受控 URI；写入前必须执行协议、主机、重定向与 SSRF 安全校验。';
COMMENT ON COLUMN oauth.authorization_code.code_challenge IS 'oauth.authorization_code.code_challenge 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN oauth.authorization_code.code_challenge_method IS 'oauth.authorization_code.code_challenge_method 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN oauth.authorization_code.nonce_hash IS '不可逆摘要；用于等值匹配、幂等、完整性或最小化证据，不保存原始敏感值。';
COMMENT ON COLUMN oauth.authorization_code.scopes IS '代码或引用集合；写入前去重、校验 allowlist，并满足表约束。';
COMMENT ON COLUMN oauth.authorization_code.resources IS '代码或引用集合；写入前去重、校验 allowlist，并满足表约束。';
COMMENT ON COLUMN oauth.authorization_code.issued_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN oauth.authorization_code.expires_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN oauth.authorization_code.consumed_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN oauth.authorization_code.replay_detected_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN oauth.authorization_code.revoked_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN oauth.reference_access_token.jti IS 'oauth.reference_access_token.jti 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN oauth.reference_access_token.token_hash IS '不可逆摘要；用于等值匹配、幂等、完整性或最小化证据，不保存原始敏感值。';
COMMENT ON COLUMN oauth.reference_access_token.subject_kind IS '对象类别判别字段；允许值由 CHECK 或对应注册表限定。';
COMMENT ON COLUMN oauth.reference_access_token.subject_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN oauth.reference_access_token.actor_kind IS '对象类别判别字段；允许值由 CHECK 或对应注册表限定。';
COMMENT ON COLUMN oauth.reference_access_token.actor_ref IS '不透明对象引用；不得从格式推断手机号、邮箱或其他业务事实。';
COMMENT ON COLUMN oauth.reference_access_token.client_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN oauth.reference_access_token.grant_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN oauth.reference_access_token.session_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN oauth.reference_access_token.token_family_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN oauth.reference_access_token.tenant_id IS '租户隔离键；全零 UUID 表示平台范围，应用查询必须显式携带可信租户上下文。';
COMMENT ON COLUMN oauth.reference_access_token.audiences IS '代码或引用集合；写入前去重、校验 allowlist，并满足表约束。';
COMMENT ON COLUMN oauth.reference_access_token.scopes IS '代码或引用集合；写入前去重、校验 allowlist，并满足表约束。';
COMMENT ON COLUMN oauth.reference_access_token.profile_code IS '稳定机器可读代码；展示文本由资源或目录解析。';
COMMENT ON COLUMN oauth.reference_access_token.policy_version IS '对象、策略或源数据的显式版本；不得以不可信客户端时间戳替代。';
COMMENT ON COLUMN oauth.reference_access_token.user_epoch_at_issue IS '安全或同意水位版本；只能单调递增，用于令牌、缓存与撤销新鲜度校验。';
COMMENT ON COLUMN oauth.reference_access_token.client_epoch_at_issue IS '安全或同意水位版本；只能单调递增，用于令牌、缓存与撤销新鲜度校验。';
COMMENT ON COLUMN oauth.reference_access_token.tenant_epoch_at_issue IS '安全或同意水位版本；只能单调递增，用于令牌、缓存与撤销新鲜度校验。';
COMMENT ON COLUMN oauth.reference_access_token.consent_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN oauth.reference_access_token.consent_context_hash IS '不可逆摘要；用于等值匹配、幂等、完整性或最小化证据，不保存原始敏感值。';
COMMENT ON COLUMN oauth.reference_access_token.consent_epoch_at_issue IS '安全或同意水位版本；只能单调递增，用于令牌、缓存与撤销新鲜度校验。';
COMMENT ON COLUMN oauth.reference_access_token.sender_constraint_thumbprint IS 'oauth.reference_access_token.sender_constraint_thumbprint 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN oauth.reference_access_token.issued_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN oauth.reference_access_token.expires_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN oauth.reference_access_token.revoked_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN oauth.reference_access_token.machine_epoch_at_issue IS '安全或同意水位版本；只能单调递增，用于令牌、缓存与撤销新鲜度校验。';
COMMENT ON COLUMN oauth.revocation_record.id IS '内部 UUID 主键；仅用于数据库关系，不作为跨域公开标识。';
COMMENT ON COLUMN oauth.revocation_record.revocation_kind IS '对象类别判别字段；允许值由 CHECK 或对应注册表限定。';
COMMENT ON COLUMN oauth.revocation_record.target_ref IS '不透明对象引用；不得从格式推断手机号、邮箱或其他业务事实。';
COMMENT ON COLUMN oauth.revocation_record.user_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN oauth.revocation_record.client_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN oauth.revocation_record.tenant_id IS '租户隔离键；全零 UUID 表示平台范围，应用查询必须显式携带可信租户上下文。';
COMMENT ON COLUMN oauth.revocation_record.effective_epoch IS '安全或同意水位版本；只能单调递增，用于令牌、缓存与撤销新鲜度校验。';
COMMENT ON COLUMN oauth.revocation_record.reason_code IS '稳定机器可读代码；展示文本由资源或目录解析。';
COMMENT ON COLUMN oauth.revocation_record.source_kind IS '对象类别判别字段；允许值由 CHECK 或对应注册表限定。';
COMMENT ON COLUMN oauth.revocation_record.source_ref IS '不透明对象引用；不得从格式推断手机号、邮箱或其他业务事实。';
COMMENT ON COLUMN oauth.revocation_record.revoked_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN oauth.revocation_record.prunable_after IS 'oauth.revocation_record.prunable_after 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN oauth.logout_request.id IS '内部 UUID 主键；仅用于数据库关系，不作为跨域公开标识。';
COMMENT ON COLUMN oauth.logout_request.operation_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN oauth.logout_request.user_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN oauth.logout_request.scope_kind IS '对象类别判别字段；允许值由 CHECK 或对应注册表限定。';
COMMENT ON COLUMN oauth.logout_request.scope_ref IS '不透明对象引用；不得从格式推断手机号、邮箱或其他业务事实。';
COMMENT ON COLUMN oauth.logout_request.initiator_kind IS '对象类别判别字段；允许值由 CHECK 或对应注册表限定。';
COMMENT ON COLUMN oauth.logout_request.initiator_ref IS '不透明对象引用；不得从格式推断手机号、邮箱或其他业务事实。';
COMMENT ON COLUMN oauth.logout_request.logout_state IS '显式状态当前值；合法取值见 CHECK，完整状态转换由 .NET 领域策略执行。';
COMMENT ON COLUMN oauth.logout_request.requested_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN oauth.logout_request.completed_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN oauth.logout_request.updated_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN oauth.logout_request.row_version IS '乐观并发版本；更新必须使用原值 compare-and-set，成功后由数据库单调递增。';
COMMENT ON COLUMN oauth.logout_target_result.id IS '内部 UUID 主键；仅用于数据库关系，不作为跨域公开标识。';
COMMENT ON COLUMN oauth.logout_target_result.logout_request_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN oauth.logout_target_result.client_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN oauth.logout_target_result.channel IS 'oauth.logout_target_result.channel 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN oauth.logout_target_result.delivery_state IS '显式状态当前值；合法取值见 CHECK，完整状态转换由 .NET 领域策略执行。';
COMMENT ON COLUMN oauth.logout_target_result.unconfirmed_reason_class IS 'oauth.logout_target_result.unconfirmed_reason_class 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN oauth.logout_target_result.attempt_count IS '非负计数器；并发更新使用原子 SQL 或乐观并发控制。';
COMMENT ON COLUMN oauth.logout_target_result.next_attempt_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN oauth.logout_target_result.confirmed_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN oauth.logout_target_result.last_error_code IS '稳定机器可读代码；展示文本由资源或目录解析。';
COMMENT ON COLUMN oauth.logout_target_result.dead_lettered_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN oauth.logout_target_result.updated_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';

COMMENT ON CONSTRAINT pk_application ON oauth.application IS '主键约束：唯一标识 oauth.application 记录。';
COMMENT ON CONSTRAINT uq_application_public_id ON oauth.application IS '唯一约束：保证 public_id 在 oauth.application 范围内不重复。';
COMMENT ON CONSTRAINT ck_application_type ON oauth.application IS '检查约束：限制 oauth.application 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_application_state ON oauth.application IS '检查约束：限制 oauth.application 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT pk_client ON oauth.client IS '主键约束：唯一标识 oauth.client 记录。';
COMMENT ON CONSTRAINT uq_client_public_id ON oauth.client IS '唯一约束：保证 public_id 在 oauth.client 范围内不重复。';
COMMENT ON CONSTRAINT fk_client_application ON oauth.client IS '外键约束：oauth.client 的 application_id 必须引用 oauth.application；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT ck_client_environment ON oauth.client IS '检查约束：限制 oauth.client 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_client_state ON oauth.client IS '检查约束：限制 oauth.client 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_client_kind ON oauth.client IS '检查约束：限制 oauth.client 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_client_auth_method ON oauth.client IS '检查约束：限制 oauth.client 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_client_grants ON oauth.client IS '检查约束：限制 oauth.client 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_client_no_weak_grants ON oauth.client IS '检查约束：限制 oauth.client 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_client_public_auth ON oauth.client IS '检查约束：限制 oauth.client 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_client_device_profile ON oauth.client IS '检查约束：限制 oauth.client 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_client_sender ON oauth.client IS '检查约束：限制 oauth.client 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_client_subject_mode ON oauth.client IS '检查约束：限制 oauth.client 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_client_token_format ON oauth.client IS '检查约束：限制 oauth.client 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_client_alg ON oauth.client IS '检查约束：限制 oauth.client 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_client_epoch ON oauth.client IS '检查约束：限制 oauth.client 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_client_active ON oauth.client IS '检查约束：限制 oauth.client 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_client_reactivation ON oauth.client IS '检查约束：限制 oauth.client 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_client_configuration_hash ON oauth.client IS '检查约束：限制 oauth.client 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT uq_client_id_tenant ON oauth.client IS '唯一约束：保证 id、tenant_id 在 oauth.client 范围内不重复。';
COMMENT ON CONSTRAINT uq_client_id_tenant_business ON oauth.client IS '唯一约束：保证 id、tenant_id、business_line_id 在 oauth.client 范围内不重复。';
COMMENT ON CONSTRAINT pk_client_uri ON oauth.client_uri IS '主键约束：唯一标识 oauth.client_uri 记录。';
COMMENT ON CONSTRAINT uq_client_uri ON oauth.client_uri IS '唯一约束：保证 client_id、uri_kind、uri_value 在 oauth.client_uri 范围内不重复。';
COMMENT ON CONSTRAINT fk_client_uri_client ON oauth.client_uri IS '外键约束：oauth.client_uri 的 client_id 必须引用 oauth.client；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT ck_client_uri_kind ON oauth.client_uri IS '检查约束：限制 oauth.client_uri 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_client_uri_no_wildcard ON oauth.client_uri IS '检查约束：限制 oauth.client_uri 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_client_uri_scheme ON oauth.client_uri IS '检查约束：限制 oauth.client_uri 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT pk_client_credential ON oauth.client_credential IS '主键约束：唯一标识 oauth.client_credential 记录。';
COMMENT ON CONSTRAINT uq_client_credential_key ON oauth.client_credential IS '唯一约束：保证 client_id、key_id 在 oauth.client_credential 范围内不重复。';
COMMENT ON CONSTRAINT fk_client_credential_client ON oauth.client_credential IS '外键约束：oauth.client_credential 的 client_id 必须引用 oauth.client；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT fk_client_credential_rotated ON oauth.client_credential IS '外键约束：oauth.client_credential 的 rotated_from_id 必须引用 oauth.client_credential；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT ck_client_credential_kind ON oauth.client_credential IS '检查约束：限制 oauth.client_credential 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_client_credential_state ON oauth.client_credential IS '检查约束：限制 oauth.client_credential 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_client_credential_material ON oauth.client_credential IS '检查约束：限制 oauth.client_credential 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_client_credential_window ON oauth.client_credential IS '检查约束：限制 oauth.client_credential 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_client_credential_revoked ON oauth.client_credential IS '检查约束：限制 oauth.client_credential 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT pk_api_resource ON oauth.api_resource IS '主键约束：唯一标识 oauth.api_resource 记录。';
COMMENT ON CONSTRAINT uq_api_resource_public_id ON oauth.api_resource IS '唯一约束：保证 public_id 在 oauth.api_resource 范围内不重复。';
COMMENT ON CONSTRAINT uq_api_resource_audience ON oauth.api_resource IS '唯一约束：保证 audience_value 在 oauth.api_resource 范围内不重复。';
COMMENT ON CONSTRAINT ck_api_resource_state ON oauth.api_resource IS '检查约束：限制 oauth.api_resource 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_api_resource_profile ON oauth.api_resource IS '检查约束：限制 oauth.api_resource 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_api_resource_revocation ON oauth.api_resource IS '检查约束：限制 oauth.api_resource 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_api_resource_active ON oauth.api_resource IS '检查约束：限制 oauth.api_resource 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT pk_scope_definition ON oauth.scope_definition IS '主键约束：唯一标识 oauth.scope_definition 记录。';
COMMENT ON CONSTRAINT fk_scope_definition_resource ON oauth.scope_definition IS '外键约束：oauth.scope_definition 的 api_resource_id 必须引用 oauth.api_resource；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT ck_scope_definition_code ON oauth.scope_definition IS '检查约束：限制 oauth.scope_definition 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_scope_definition_profile ON oauth.scope_definition IS '检查约束：限制 oauth.scope_definition 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_scope_definition_sensitive ON oauth.scope_definition IS '检查约束：限制 oauth.scope_definition 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT pk_device ON oauth.device IS '主键约束：唯一标识 oauth.device 记录。';
COMMENT ON CONSTRAINT uq_device_public_id ON oauth.device IS '唯一约束：保证 public_id 在 oauth.device 范围内不重复。';
COMMENT ON CONSTRAINT uq_device_fingerprint ON oauth.device IS '唯一约束：保证 user_id、fingerprint_hash 在 oauth.device 范围内不重复。';
COMMENT ON CONSTRAINT ck_device_lifecycle ON oauth.device IS '检查约束：限制 oauth.device 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_device_trust ON oauth.device IS '检查约束：限制 oauth.device 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_device_loss ON oauth.device IS '检查约束：限制 oauth.device 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_device_fingerprint ON oauth.device IS '检查约束：限制 oauth.device 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_device_trusted ON oauth.device IS '检查约束：限制 oauth.device 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_device_lost ON oauth.device IS '检查约束：限制 oauth.device 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_device_trust_evidence ON oauth.device IS '检查约束：限制 oauth.device 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_device_loss_clear_evidence ON oauth.device IS '检查约束：限制 oauth.device 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_device_retired ON oauth.device IS '检查约束：限制 oauth.device 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_device_revoked ON oauth.device IS '检查约束：限制 oauth.device 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT pk_authorization_grant ON oauth.authorization_grant IS '主键约束：唯一标识 oauth.authorization_grant 记录。';
COMMENT ON CONSTRAINT uq_authorization_grant_public_id ON oauth.authorization_grant IS '唯一约束：保证 public_id 在 oauth.authorization_grant 范围内不重复。';
COMMENT ON CONSTRAINT fk_authorization_grant_client ON oauth.authorization_grant IS '外键约束：oauth.authorization_grant 的 client_id 必须引用 oauth.client；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT ck_authorization_grant_subject ON oauth.authorization_grant IS '检查约束：限制 oauth.authorization_grant 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_authorization_grant_state ON oauth.authorization_grant IS '检查约束：限制 oauth.authorization_grant 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_authorization_grant_scope ON oauth.authorization_grant IS '检查约束：限制 oauth.authorization_grant 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_authorization_grant_active ON oauth.authorization_grant IS '检查约束：限制 oauth.authorization_grant 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_authorization_grant_denied ON oauth.authorization_grant IS '检查约束：限制 oauth.authorization_grant 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_authorization_grant_revoked ON oauth.authorization_grant IS '检查约束：限制 oauth.authorization_grant 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_authorization_grant_consent ON oauth.authorization_grant IS '检查约束：限制 oauth.authorization_grant 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_authorization_grant_epoch ON oauth.authorization_grant IS '检查约束：限制 oauth.authorization_grant 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT fk_grant_client_scope ON oauth.authorization_grant IS '外键约束：oauth.authorization_grant 的 client_id、tenant_id 必须引用 oauth.client；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT ck_grant_subject_epoch ON oauth.authorization_grant IS '检查约束：限制 oauth.authorization_grant 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_grant_subject_context ON oauth.authorization_grant IS '检查约束：限制 oauth.authorization_grant 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_grant_state_evidence ON oauth.authorization_grant IS '检查约束：限制 oauth.authorization_grant 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT pk_user_session ON oauth.user_session IS '主键约束：唯一标识 oauth.user_session 记录。';
COMMENT ON CONSTRAINT uq_user_session_public_id ON oauth.user_session IS '唯一约束：保证 public_id 在 oauth.user_session 范围内不重复。';
COMMENT ON CONSTRAINT fk_user_session_parent ON oauth.user_session IS '外键约束：oauth.user_session 的 parent_session_id 必须引用 oauth.user_session；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT fk_user_session_device ON oauth.user_session IS '外键约束：oauth.user_session 的 device_id 必须引用 oauth.device；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT fk_user_session_client ON oauth.user_session IS '外键约束：oauth.user_session 的 origin_client_id 必须引用 oauth.client；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT ck_user_session_kind ON oauth.user_session IS '检查约束：限制 oauth.user_session 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_user_session_state ON oauth.user_session IS '检查约束：限制 oauth.user_session 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_user_session_aal ON oauth.user_session IS '检查约束：限制 oauth.user_session 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_user_session_epoch ON oauth.user_session IS '检查约束：限制 oauth.user_session 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_user_session_expiry ON oauth.user_session IS '检查约束：限制 oauth.user_session 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT fk_session_client_scope ON oauth.user_session IS '外键约束：oauth.user_session 的 origin_client_id、tenant_id 必须引用 oauth.client；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT ck_user_session_expired ON oauth.user_session IS '检查约束：限制 oauth.user_session 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_user_session_compromised ON oauth.user_session IS '检查约束：限制 oauth.user_session 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_user_session_revoked ON oauth.user_session IS '检查约束：限制 oauth.user_session 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT pk_token_family ON oauth.token_family IS '主键约束：唯一标识 oauth.token_family 记录。';
COMMENT ON CONSTRAINT fk_token_family_client ON oauth.token_family IS '外键约束：oauth.token_family 的 client_id 必须引用 oauth.client；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT fk_token_family_grant ON oauth.token_family IS '外键约束：oauth.token_family 的 grant_id 必须引用 oauth.authorization_grant；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT fk_token_family_session ON oauth.token_family IS '外键约束：oauth.token_family 的 session_id 必须引用 oauth.user_session；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT fk_token_family_device ON oauth.token_family IS '外键约束：oauth.token_family 的 device_id 必须引用 oauth.device；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT ck_token_family_subject ON oauth.token_family IS '检查约束：限制 oauth.token_family 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_token_family_state ON oauth.token_family IS '检查约束：限制 oauth.token_family 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_token_family_sender ON oauth.token_family IS '检查约束：限制 oauth.token_family 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_token_family_expiry ON oauth.token_family IS '检查约束：限制 oauth.token_family 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_token_family_compromised ON oauth.token_family IS '检查约束：限制 oauth.token_family 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_token_family_revoked ON oauth.token_family IS '检查约束：限制 oauth.token_family 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT pk_refresh_token ON oauth.refresh_token IS '主键约束：唯一标识 oauth.refresh_token 记录。';
COMMENT ON CONSTRAINT uq_refresh_token_hash ON oauth.refresh_token IS '唯一约束：保证 token_hash 在 oauth.refresh_token 范围内不重复。';
COMMENT ON CONSTRAINT uq_refresh_token_generation ON oauth.refresh_token IS '唯一约束：保证 family_id、generation 在 oauth.refresh_token 范围内不重复。';
COMMENT ON CONSTRAINT fk_refresh_token_family ON oauth.refresh_token IS '外键约束：oauth.refresh_token 的 family_id 必须引用 oauth.token_family；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT ck_refresh_token_state ON oauth.refresh_token IS '检查约束：限制 oauth.refresh_token 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_refresh_token_hash ON oauth.refresh_token IS '检查约束：限制 oauth.refresh_token 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_refresh_token_generation ON oauth.refresh_token IS '检查约束：限制 oauth.refresh_token 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT fk_refresh_token_successor ON oauth.refresh_token IS '外键约束：oauth.refresh_token 的 successor_id 必须引用 oauth.refresh_token；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT ck_refresh_token_used ON oauth.refresh_token IS '检查约束：限制 oauth.refresh_token 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_refresh_token_revoked ON oauth.refresh_token IS '检查约束：限制 oauth.refresh_token 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_refresh_token_retry_window ON oauth.refresh_token IS '检查约束：限制 oauth.refresh_token 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT pk_authorization_code ON oauth.authorization_code IS '主键约束：唯一标识 oauth.authorization_code 记录。';
COMMENT ON CONSTRAINT uq_authorization_code_hash ON oauth.authorization_code IS '唯一约束：保证 code_hash 在 oauth.authorization_code 范围内不重复。';
COMMENT ON CONSTRAINT fk_authorization_code_client ON oauth.authorization_code IS '外键约束：oauth.authorization_code 的 client_id 必须引用 oauth.client；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT fk_authorization_code_session ON oauth.authorization_code IS '外键约束：oauth.authorization_code 的 session_id 必须引用 oauth.user_session；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT fk_authorization_code_grant ON oauth.authorization_code IS '外键约束：oauth.authorization_code 的 grant_id 必须引用 oauth.authorization_grant；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT ck_authorization_code_state ON oauth.authorization_code IS '检查约束：限制 oauth.authorization_code 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_authorization_code_hash ON oauth.authorization_code IS '检查约束：限制 oauth.authorization_code 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_authorization_code_pkce ON oauth.authorization_code IS '检查约束：限制 oauth.authorization_code 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_authorization_code_consumed ON oauth.authorization_code IS '检查约束：限制 oauth.authorization_code 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_authorization_code_ttl ON oauth.authorization_code IS '检查约束：限制 oauth.authorization_code 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_authorization_code_revoked ON oauth.authorization_code IS '检查约束：限制 oauth.authorization_code 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_authorization_code_replay ON oauth.authorization_code IS '检查约束：限制 oauth.authorization_code 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT pk_reference_access_token ON oauth.reference_access_token IS '主键约束：唯一标识 oauth.reference_access_token 记录。';
COMMENT ON CONSTRAINT uq_reference_access_token_hash ON oauth.reference_access_token IS '唯一约束：保证 token_hash 在 oauth.reference_access_token 范围内不重复。';
COMMENT ON CONSTRAINT fk_reference_access_token_client ON oauth.reference_access_token IS '外键约束：oauth.reference_access_token 的 client_id 必须引用 oauth.client；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT fk_reference_access_token_grant ON oauth.reference_access_token IS '外键约束：oauth.reference_access_token 的 grant_id 必须引用 oauth.authorization_grant；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT fk_reference_access_token_session ON oauth.reference_access_token IS '外键约束：oauth.reference_access_token 的 session_id 必须引用 oauth.user_session；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT fk_reference_access_token_family ON oauth.reference_access_token IS '外键约束：oauth.reference_access_token 的 token_family_id 必须引用 oauth.token_family；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT ck_reference_access_token_subject ON oauth.reference_access_token IS '检查约束：限制 oauth.reference_access_token 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_reference_access_token_actor ON oauth.reference_access_token IS '检查约束：限制 oauth.reference_access_token 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_reference_access_token_audience ON oauth.reference_access_token IS '检查约束：限制 oauth.reference_access_token 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_reference_access_token_epoch ON oauth.reference_access_token IS '检查约束：限制 oauth.reference_access_token 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_reference_access_token_consent ON oauth.reference_access_token IS '检查约束：限制 oauth.reference_access_token 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_reference_access_token_ttl ON oauth.reference_access_token IS '检查约束：限制 oauth.reference_access_token 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_reference_token_subject_epoch ON oauth.reference_access_token IS '检查约束：限制 oauth.reference_access_token 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT pk_revocation_record ON oauth.revocation_record IS '主键约束：唯一标识 oauth.revocation_record 记录。';
COMMENT ON CONSTRAINT ck_revocation_record_kind ON oauth.revocation_record IS '检查约束：限制 oauth.revocation_record 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_revocation_record_source ON oauth.revocation_record IS '检查约束：限制 oauth.revocation_record 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_revocation_record_retention ON oauth.revocation_record IS '检查约束：限制 oauth.revocation_record 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT pk_logout_request ON oauth.logout_request IS '主键约束：唯一标识 oauth.logout_request 记录。';
COMMENT ON CONSTRAINT uq_logout_request_operation ON oauth.logout_request IS '唯一约束：保证 operation_id 在 oauth.logout_request 范围内不重复。';
COMMENT ON CONSTRAINT ck_logout_request_scope ON oauth.logout_request IS '检查约束：限制 oauth.logout_request 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_logout_request_initiator ON oauth.logout_request IS '检查约束：限制 oauth.logout_request 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_logout_request_state ON oauth.logout_request IS '检查约束：限制 oauth.logout_request 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_logout_request_completed ON oauth.logout_request IS '检查约束：限制 oauth.logout_request 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT pk_logout_target_result ON oauth.logout_target_result IS '主键约束：唯一标识 oauth.logout_target_result 记录。';
COMMENT ON CONSTRAINT uq_logout_target_result ON oauth.logout_target_result IS '唯一约束：保证 logout_request_id、client_id、channel 在 oauth.logout_target_result 范围内不重复。';
COMMENT ON CONSTRAINT fk_logout_target_result_request ON oauth.logout_target_result IS '外键约束：oauth.logout_target_result 的 logout_request_id 必须引用 oauth.logout_request；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT fk_logout_target_result_client ON oauth.logout_target_result IS '外键约束：oauth.logout_target_result 的 client_id 必须引用 oauth.client；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT ck_logout_target_result_channel ON oauth.logout_target_result IS '检查约束：限制 oauth.logout_target_result 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_logout_target_result_state ON oauth.logout_target_result IS '检查约束：限制 oauth.logout_target_result 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_logout_target_result_reason ON oauth.logout_target_result IS '检查约束：限制 oauth.logout_target_result 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_logout_target_result_confirmed ON oauth.logout_target_result IS '检查约束：限制 oauth.logout_target_result 的字段取值或组合满足结构与安全底线。';

COMMENT ON INDEX oauth.ix_client_owner_review IS '查询索引：优化 oauth.client 按 owner_ref、expires_at 的访问，仅覆盖 WHERE 条件命中的记录。';
COMMENT ON INDEX oauth.ix_device_user IS '查询索引：优化 oauth.device 按 user_id、device_lifecycle_state、device_loss_state 的访问。';
COMMENT ON INDEX oauth.ix_authorization_grant_client IS '查询索引：优化 oauth.authorization_grant 按 client_id、grant_state 的访问。';
COMMENT ON INDEX oauth.ix_user_session_user IS '查询索引：优化 oauth.user_session 按 user_id、session_state、created_at 的访问。';
COMMENT ON INDEX oauth.ix_user_session_device IS '查询索引：优化 oauth.user_session 按 device_id、session_state 的访问，仅覆盖 WHERE 条件命中的记录。';
COMMENT ON INDEX oauth.ix_user_session_expiry IS '查询索引：优化 oauth.user_session 按 idle_expires_at 的访问，仅覆盖 WHERE 条件命中的记录。';
COMMENT ON INDEX oauth.ux_refresh_token_current IS '查询索引：优化 oauth.refresh_token 按 family_id 的访问，仅覆盖 WHERE 条件命中的记录。';
COMMENT ON INDEX oauth.ix_token_family_grant IS '查询索引：优化 oauth.token_family 按 grant_id、token_family_state 的访问。';
COMMENT ON INDEX oauth.ix_authorization_code_expiry IS '查询索引：优化 oauth.authorization_code 按 expires_at 的访问，仅覆盖 WHERE 条件命中的记录。';
COMMENT ON INDEX oauth.ix_reference_access_token_expiry IS '查询索引：优化 oauth.reference_access_token 按 expires_at 的访问，仅覆盖 WHERE 条件命中的记录。';
COMMENT ON INDEX oauth.ix_revocation_target IS '查询索引：优化 oauth.revocation_record 按 revocation_kind、target_ref、revoked_at 的访问。';
COMMENT ON INDEX oauth.ix_logout_target_retry IS '查询索引：优化 oauth.logout_target_result 按 next_attempt_at 的访问，仅覆盖 WHERE 条件命中的记录。';
COMMENT ON INDEX oauth.ux_authorization_grant_active IS '查询索引：优化 oauth.authorization_grant 按 subject_kind、subject_id、client_id、tenant_id 的访问，仅覆盖 WHERE 条件命中的记录。';
COMMENT ON INDEX oauth.ux_user_session_login_transaction IS '查询索引：优化 oauth.user_session 按 login_transaction_id 的访问。';
COMMENT ON INDEX oauth.ux_authorization_code_login_transaction IS '查询索引：优化 oauth.authorization_code 按 login_transaction_id 的访问。';
COMMENT ON INDEX oauth.ux_token_family_active_grant IS '查询索引：优化 oauth.token_family 按 grant_id 的访问，仅覆盖 WHERE 条件命中的记录。';
COMMENT ON INDEX oauth.pk_application IS '约束 pk_application 的支撑唯一索引。';
COMMENT ON INDEX oauth.uq_application_public_id IS '约束 uq_application_public_id 的支撑唯一索引。';
COMMENT ON INDEX oauth.pk_client IS '约束 pk_client 的支撑唯一索引。';
COMMENT ON INDEX oauth.uq_client_public_id IS '约束 uq_client_public_id 的支撑唯一索引。';
COMMENT ON INDEX oauth.uq_client_id_tenant IS '约束 uq_client_id_tenant 的支撑唯一索引。';
COMMENT ON INDEX oauth.uq_client_id_tenant_business IS '约束 uq_client_id_tenant_business 的支撑唯一索引。';
COMMENT ON INDEX oauth.pk_client_uri IS '约束 pk_client_uri 的支撑唯一索引。';
COMMENT ON INDEX oauth.uq_client_uri IS '约束 uq_client_uri 的支撑唯一索引。';
COMMENT ON INDEX oauth.pk_client_credential IS '约束 pk_client_credential 的支撑唯一索引。';
COMMENT ON INDEX oauth.uq_client_credential_key IS '约束 uq_client_credential_key 的支撑唯一索引。';
COMMENT ON INDEX oauth.pk_api_resource IS '约束 pk_api_resource 的支撑唯一索引。';
COMMENT ON INDEX oauth.uq_api_resource_public_id IS '约束 uq_api_resource_public_id 的支撑唯一索引。';
COMMENT ON INDEX oauth.uq_api_resource_audience IS '约束 uq_api_resource_audience 的支撑唯一索引。';
COMMENT ON INDEX oauth.pk_scope_definition IS '约束 pk_scope_definition 的支撑唯一索引。';
COMMENT ON INDEX oauth.pk_device IS '约束 pk_device 的支撑唯一索引。';
COMMENT ON INDEX oauth.uq_device_public_id IS '约束 uq_device_public_id 的支撑唯一索引。';
COMMENT ON INDEX oauth.uq_device_fingerprint IS '约束 uq_device_fingerprint 的支撑唯一索引。';
COMMENT ON INDEX oauth.pk_authorization_grant IS '约束 pk_authorization_grant 的支撑唯一索引。';
COMMENT ON INDEX oauth.uq_authorization_grant_public_id IS '约束 uq_authorization_grant_public_id 的支撑唯一索引。';
COMMENT ON INDEX oauth.pk_user_session IS '约束 pk_user_session 的支撑唯一索引。';
COMMENT ON INDEX oauth.uq_user_session_public_id IS '约束 uq_user_session_public_id 的支撑唯一索引。';
COMMENT ON INDEX oauth.pk_token_family IS '约束 pk_token_family 的支撑唯一索引。';
COMMENT ON INDEX oauth.pk_refresh_token IS '约束 pk_refresh_token 的支撑唯一索引。';
COMMENT ON INDEX oauth.uq_refresh_token_hash IS '约束 uq_refresh_token_hash 的支撑唯一索引。';
COMMENT ON INDEX oauth.uq_refresh_token_generation IS '约束 uq_refresh_token_generation 的支撑唯一索引。';
COMMENT ON INDEX oauth.pk_authorization_code IS '约束 pk_authorization_code 的支撑唯一索引。';
COMMENT ON INDEX oauth.uq_authorization_code_hash IS '约束 uq_authorization_code_hash 的支撑唯一索引。';
COMMENT ON INDEX oauth.pk_reference_access_token IS '约束 pk_reference_access_token 的支撑唯一索引。';
COMMENT ON INDEX oauth.uq_reference_access_token_hash IS '约束 uq_reference_access_token_hash 的支撑唯一索引。';
COMMENT ON INDEX oauth.pk_revocation_record IS '约束 pk_revocation_record 的支撑唯一索引。';
COMMENT ON INDEX oauth.pk_logout_request IS '约束 pk_logout_request 的支撑唯一索引。';
COMMENT ON INDEX oauth.uq_logout_request_operation IS '约束 uq_logout_request_operation 的支撑唯一索引。';
COMMENT ON INDEX oauth.pk_logout_target_result IS '约束 pk_logout_target_result 的支撑唯一索引。';
COMMENT ON INDEX oauth.uq_logout_target_result IS '约束 uq_logout_target_result 的支撑唯一索引。';
COMMENT ON INDEX oauth.ix_fk_client_application_id IS '查询索引：优化 oauth.client 按 application_id 的访问。';
COMMENT ON INDEX oauth.ix_fk_client_credential_rotated_from_id IS '查询索引：优化 oauth.client_credential 按 rotated_from_id 的访问。';
COMMENT ON INDEX oauth.ix_fk_scope_definition_api_resource_id IS '查询索引：优化 oauth.scope_definition 按 api_resource_id 的访问。';
COMMENT ON INDEX oauth.ix_fk_authorization_grant_client_id_tenant_id IS '查询索引：优化 oauth.authorization_grant 按 client_id、tenant_id 的访问。';
COMMENT ON INDEX oauth.ix_fk_user_session_parent_session_id IS '查询索引：优化 oauth.user_session 按 parent_session_id 的访问。';
COMMENT ON INDEX oauth.ix_fk_user_session_device_id IS '查询索引：优化 oauth.user_session 按 device_id 的访问。';
COMMENT ON INDEX oauth.ix_fk_user_session_origin_client_id IS '查询索引：优化 oauth.user_session 按 origin_client_id 的访问。';
COMMENT ON INDEX oauth.ix_fk_user_session_origin_client_id_tenant_id IS '查询索引：优化 oauth.user_session 按 origin_client_id、tenant_id 的访问。';
COMMENT ON INDEX oauth.ix_fk_token_family_client_id IS '查询索引：优化 oauth.token_family 按 client_id 的访问。';
COMMENT ON INDEX oauth.ix_fk_token_family_session_id IS '查询索引：优化 oauth.token_family 按 session_id 的访问。';
COMMENT ON INDEX oauth.ix_fk_token_family_device_id IS '查询索引：优化 oauth.token_family 按 device_id 的访问。';
COMMENT ON INDEX oauth.ix_fk_refresh_token_successor_id IS '查询索引：优化 oauth.refresh_token 按 successor_id 的访问。';
COMMENT ON INDEX oauth.ix_fk_authorization_code_client_id IS '查询索引：优化 oauth.authorization_code 按 client_id 的访问。';
COMMENT ON INDEX oauth.ix_fk_authorization_code_session_id IS '查询索引：优化 oauth.authorization_code 按 session_id 的访问。';
COMMENT ON INDEX oauth.ix_fk_authorization_code_grant_id IS '查询索引：优化 oauth.authorization_code 按 grant_id 的访问。';
COMMENT ON INDEX oauth.ix_fk_reference_access_token_client_id IS '查询索引：优化 oauth.reference_access_token 按 client_id 的访问。';
COMMENT ON INDEX oauth.ix_fk_reference_access_token_grant_id IS '查询索引：优化 oauth.reference_access_token 按 grant_id 的访问。';
COMMENT ON INDEX oauth.ix_fk_reference_access_token_session_id IS '查询索引：优化 oauth.reference_access_token 按 session_id 的访问。';
COMMENT ON INDEX oauth.ix_fk_reference_access_token_token_family_id IS '查询索引：优化 oauth.reference_access_token 按 token_family_id 的访问。';
COMMENT ON INDEX oauth.ix_fk_logout_target_result_client_id IS '查询索引：优化 oauth.logout_target_result 按 client_id 的访问。';

