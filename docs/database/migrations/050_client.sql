-- =============================================================================
-- 050_client.sql
-- OAP 域：Application、Client、回调地址、Client 凭证、API Resource、Scope
-- 依据：能力地图 §4.14；蓝图 §6 安全 Profile、§8.2（REQ-AUTH-001/002）、§13（REQ-MACHINE-002/003/005）
-- 关键：数据库层直接拒绝 Implicit 与 ROPC，拒绝公开客户端持有 secret
-- =============================================================================

SET client_min_messages = warning;

-- -----------------------------------------------------------------------------
-- 1. 应用（CAP-TENANT-002）
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS oap.application (
    id                uuid        NOT NULL DEFAULT core.uuid_generate_v7(),
    public_id         text        NOT NULL,
    business_line_id  uuid        NOT NULL,
    display_name      text        NOT NULL,
    application_type  text        NOT NULL,
    application_state text        NOT NULL DEFAULT 'DRAFT',
    owner_ref         text        NOT NULL,
    contact_ref       text        NULL,
    created_at        timestamptz NOT NULL DEFAULT now(),
    updated_at        timestamptz NOT NULL DEFAULT now(),
    row_version       bigint      NOT NULL DEFAULT 1,
    CONSTRAINT pk_application PRIMARY KEY (id),
    CONSTRAINT uq_application_public_id UNIQUE (public_id),
    CONSTRAINT fk_application_business_line FOREIGN KEY (business_line_id) REFERENCES tenant.business_line (id),
    CONSTRAINT ck_application_type CHECK (application_type IN (
        'WEB_SERVER', 'SPA_BFF', 'NATIVE_APP', 'MINI_PROGRAM', 'SERVER_TO_SERVER', 'DEVICE', 'ADMIN_CONSOLE'
    )),
    CONSTRAINT ck_application_state CHECK (application_state IN ('DRAFT', 'ACTIVE', 'SUSPENDED', 'RETIRED'))
);
COMMENT ON TABLE oap.application IS 'CAP-TENANT-002 应用登记；一个应用可包含多个环境的 Client';

CREATE OR REPLACE TRIGGER trg_application_touch
    BEFORE UPDATE ON oap.application
    FOR EACH ROW EXECUTE FUNCTION core.fn_touch_updated_at();
CREATE OR REPLACE TRIGGER trg_application_public_id
    BEFORE INSERT ON oap.application
    FOR EACH ROW EXECUTE FUNCTION core.fn_register_public_id('APPLICATION');

-- -----------------------------------------------------------------------------
-- 2. Client（CAP-TENANT-003、CAP-OAP-001、REQ-OAP-001）
-- public_id 即对外 OAuth client_id
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS oap.client (
    id                          uuid        NOT NULL DEFAULT core.uuid_generate_v7(),
    public_id                   text        NOT NULL,
    application_id              uuid        NOT NULL,
    business_line_id            uuid        NOT NULL,
    tenant_id                   uuid        NOT NULL DEFAULT '00000000-0000-0000-0000-000000000000',
    environment                 text        NOT NULL,
    client_state                text        NOT NULL DEFAULT 'DRAFT',
    client_kind                 text        NOT NULL,
    display_name                text        NOT NULL,
    profile_code                text        NOT NULL,
    profile_version             text        NOT NULL,
    token_endpoint_auth_method  text        NOT NULL DEFAULT 'none',
    allowed_grant_types         text[]      NOT NULL DEFAULT '{authorization_code,refresh_token}',
    allowed_scopes              text[]      NOT NULL DEFAULT '{}',
    allowed_resources           text[]      NOT NULL DEFAULT '{}',
    subject_mode                text        NOT NULL DEFAULT 'PAIRWISE_PER_CLIENT',
    access_token_format         text        NOT NULL DEFAULT 'JWT',
    id_token_signed_alg         text        NOT NULL DEFAULT 'ES256',
    require_pushed_authorization boolean    NOT NULL DEFAULT false,
    require_sender_constrained  boolean     NOT NULL DEFAULT false,
    sender_constraint_method    text        NULL,
    sso_domain_boundary         text        NOT NULL,
    is_first_party              boolean     NOT NULL DEFAULT true,
    consent_required            boolean     NOT NULL DEFAULT false,
    security_epoch              bigint      NOT NULL DEFAULT 1,
    onboarding_report_ref       text        NULL,
    approved_at                 timestamptz NULL,
    approved_by_ref             text        NULL,
    suspended_at                timestamptz NULL,
    compromised_at              timestamptz NULL,
    retired_at                  timestamptz NULL,
    owner_ref                   text        NOT NULL,
    expires_at                  timestamptz NULL,
    last_used_at                timestamptz NULL,
    created_at                  timestamptz NOT NULL DEFAULT now(),
    updated_at                  timestamptz NOT NULL DEFAULT now(),
    row_version                 bigint      NOT NULL DEFAULT 1,
    CONSTRAINT pk_client PRIMARY KEY (id),
    CONSTRAINT uq_client_public_id UNIQUE (public_id),
    CONSTRAINT fk_client_application FOREIGN KEY (application_id) REFERENCES oap.application (id),
    CONSTRAINT fk_client_business_line FOREIGN KEY (business_line_id) REFERENCES tenant.business_line (id),
    CONSTRAINT fk_client_profile FOREIGN KEY (profile_code, profile_version) REFERENCES core.security_profile (profile_code, profile_version),
    CONSTRAINT ck_client_environment CHECK (environment IN ('DEV', 'TEST', 'STAGING', 'PROD')),
    CONSTRAINT ck_client_state CHECK (client_state IN ('DRAFT', 'VALIDATED', 'APPROVED', 'ACTIVE', 'SUSPENDED', 'COMPROMISED', 'RETIRED')),
    CONSTRAINT ck_client_kind CHECK (client_kind IN ('CONFIDENTIAL', 'PUBLIC')),
    CONSTRAINT ck_client_auth_method CHECK (token_endpoint_auth_method IN (
        'none', 'private_key_jwt', 'tls_client_auth', 'self_signed_tls_client_auth', 'client_secret_basic'
    )),
    -- REQ-AUTH-001 / CAP-OAP-003：任何环境禁止 Implicit 与 ROPC
    CONSTRAINT ck_client_grant_types CHECK (
        allowed_grant_types <@ ARRAY[
            'authorization_code', 'refresh_token', 'client_credentials',
            'urn:ietf:params:oauth:grant-type:token-exchange',
            'urn:ietf:params:oauth:grant-type:device_code'
        ]::text[]
        AND array_length(allowed_grant_types, 1) >= 1
    ),
    -- REQ-MACHINE-002：公开客户端不得持有 Client Secret
    CONSTRAINT ck_client_public_no_secret CHECK (
        client_kind <> 'PUBLIC' OR token_endpoint_auth_method = 'none'
    ),
    -- REQ-MACHINE-003：机密客户端优先 private_key_jwt / mTLS；client_secret_basic 属于需登记例外的弱方式
    CONSTRAINT ck_client_confidential_auth CHECK (
        client_kind <> 'CONFIDENTIAL' OR token_endpoint_auth_method <> 'none'
    ),
    -- 蓝图 §6：SP5 必须使用发送方约束 Token
    CONSTRAINT ck_client_sp5_sender_constrained CHECK (
        profile_code <> 'SP5' OR (require_sender_constrained AND sender_constraint_method IS NOT NULL)
    ),
    CONSTRAINT ck_client_sender_constraint CHECK (
        sender_constraint_method IS NULL OR sender_constraint_method IN ('DPOP', 'MTLS')
    ),
    CONSTRAINT ck_client_sender_constraint_pair CHECK (
        require_sender_constrained = (sender_constraint_method IS NOT NULL)
    ),
    CONSTRAINT ck_client_subject_mode CHECK (subject_mode IN ('PAIRWISE_PER_CLIENT', 'PAIRWISE_PER_BUSINESS_LINE', 'SHARED_GLOBAL')),
    CONSTRAINT ck_client_token_format CHECK (access_token_format IN ('JWT', 'REFERENCE')),
    -- CAP-OAP-006：禁止 none 与算法降级
    CONSTRAINT ck_client_id_token_alg CHECK (id_token_signed_alg IN ('ES256', 'ES384', 'PS256', 'RS256', 'EdDSA', 'SM2')),
    -- CAP-PLT-019：进入 ACTIVE 必须已通过接入认证并有审批记录
    CONSTRAINT ck_client_active_requires_approval CHECK (
        client_state <> 'ACTIVE' OR (approved_at IS NOT NULL AND approved_by_ref IS NOT NULL AND onboarding_report_ref IS NOT NULL)
    ),
    CONSTRAINT ck_client_retired CHECK ((client_state = 'RETIRED') = (retired_at IS NOT NULL)),
    CONSTRAINT ck_client_epoch CHECK (security_epoch >= 1)
);
COMMENT ON TABLE oap.client IS 'CAP-TENANT-003 / CAP-OAP-001：每个 Client 绑定唯一 Profile 编号与版本（REQ-OAP-001/003）；数据库层拒绝 Implicit、ROPC 与公开客户端持有 secret';
COMMENT ON COLUMN oap.client.sso_domain_boundary IS 'CAP-SESSION-001：SSO 域边界必须在接入时登记，跨域应用不得假定共享浏览器会话（能力地图 §5.7 第 9 步）';
COMMENT ON COLUMN oap.client.security_epoch IS 'client_security_epoch：凭证轮换、禁用或失陷时递增（蓝图 §4.3）';
COMMENT ON COLUMN oap.client.onboarding_report_ref IS 'CAP-PLT-019 接入认证报告位置；未通过 Profile 检查的 Client 不得获得生产凭证';

CREATE OR REPLACE TRIGGER trg_client_touch
    BEFORE UPDATE ON oap.client
    FOR EACH ROW EXECUTE FUNCTION core.fn_touch_updated_at();
CREATE OR REPLACE TRIGGER trg_client_epoch
    BEFORE UPDATE ON oap.client
    FOR EACH ROW EXECUTE FUNCTION core.fn_forbid_epoch_decrease('security_epoch');
CREATE OR REPLACE TRIGGER trg_client_public_id
    BEFORE INSERT ON oap.client
    FOR EACH ROW EXECUTE FUNCTION core.fn_register_public_id('CLIENT');

CREATE INDEX IF NOT EXISTS ix_client_application ON oap.client (application_id, environment);
CREATE INDEX IF NOT EXISTS ix_client_state ON oap.client (client_state, environment);
CREATE INDEX IF NOT EXISTS ix_client_owner_review ON oap.client (expires_at) WHERE client_state = 'ACTIVE' AND expires_at IS NOT NULL;

-- -----------------------------------------------------------------------------
-- 3. 回调与退出地址（REQ-AUTH-002、CAP-OAP-004、REQ-SESSION-006、REQ-SESSION-015）
-- 精确匹配：一行一个完整 URI，生产禁止通配符
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS oap.client_uri (
    id           uuid        NOT NULL DEFAULT core.uuid_generate_v7(),
    client_id    uuid        NOT NULL,
    uri_kind     text        NOT NULL,
    uri_value    text        NOT NULL,
    is_loopback  boolean     NOT NULL DEFAULT false,
    created_at   timestamptz NOT NULL DEFAULT now(),
    created_by_ref text      NOT NULL,
    CONSTRAINT pk_client_uri PRIMARY KEY (id),
    CONSTRAINT uq_client_uri UNIQUE (client_id, uri_kind, uri_value),
    CONSTRAINT fk_client_uri_client FOREIGN KEY (client_id) REFERENCES oap.client (id) ON DELETE CASCADE,
    CONSTRAINT ck_client_uri_kind CHECK (uri_kind IN (
        'REDIRECT', 'POST_LOGOUT_REDIRECT', 'FRONT_CHANNEL_LOGOUT', 'BACK_CHANNEL_LOGOUT', 'INITIATE_LOGIN'
    )),
    -- CAP-OAP-004：禁止通配符与开放重定向
    CONSTRAINT ck_client_uri_no_wildcard CHECK (uri_value NOT LIKE '%*%'),
    -- 仅原生端 loopback 允许 http，其余必须 https 或自定义 scheme
    CONSTRAINT ck_client_uri_scheme CHECK (
        uri_value ~ '^https://'
        OR (is_loopback AND uri_value ~ '^http://(127\.0\.0\.1|\[::1\])(:[0-9]{1,5})?(/.*)?$')
        OR uri_value ~ '^[a-z][a-z0-9+.-]*:/'
    ),
    CONSTRAINT ck_client_uri_no_fragment CHECK (position('#' in uri_value) = 0)
);
COMMENT ON TABLE oap.client_uri IS 'REQ-AUTH-002 精确匹配回调；loopback 动态端口按 RFC 8252 例外（AT-AUTH-008），生产禁止通配符';

CREATE INDEX IF NOT EXISTS ix_client_uri_lookup ON oap.client_uri (client_id, uri_kind);

-- -----------------------------------------------------------------------------
-- 4. Client 凭证（REQ-MACHINE-003、REQ-MACHINE-015、REQ-KEY-002 双钥窗口）
-- 不存私钥；secret 只存哈希；JWK 只存公钥
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS oap.client_credential (
    id                 uuid        NOT NULL DEFAULT core.uuid_generate_v7(),
    client_id          uuid        NOT NULL,
    credential_kind    text        NOT NULL,
    credential_state   text        NOT NULL DEFAULT 'ACTIVE',
    key_id             text        NULL,
    secret_hash        text        NULL,
    public_jwk         jsonb       NULL,
    jwks_uri           text        NULL,
    cert_thumbprint_s256 bytea     NULL,
    signing_algorithm  text        NULL,
    not_before         timestamptz NOT NULL DEFAULT now(),
    not_after          timestamptz NULL,
    rotated_from_id    uuid        NULL,
    revoked_at         timestamptz NULL,
    revoke_reason_code text        NULL,
    created_at         timestamptz NOT NULL DEFAULT now(),
    updated_at         timestamptz NOT NULL DEFAULT now(),
    row_version        bigint      NOT NULL DEFAULT 1,
    CONSTRAINT pk_client_credential PRIMARY KEY (id),
    CONSTRAINT uq_client_credential_kid UNIQUE (client_id, key_id),
    CONSTRAINT fk_client_credential_client FOREIGN KEY (client_id) REFERENCES oap.client (id) ON DELETE CASCADE,
    CONSTRAINT fk_client_credential_rotated_from FOREIGN KEY (rotated_from_id) REFERENCES oap.client_credential (id),
    CONSTRAINT ck_client_credential_kind CHECK (credential_kind IN ('SECRET', 'PUBLIC_JWK', 'JWKS_URI', 'MTLS_CERT')),
    CONSTRAINT ck_client_credential_state CHECK (credential_state IN ('ACTIVE', 'GRACE', 'EXPIRED', 'REVOKED')),
    -- secret 必须是哈希（PHC 串），禁止明文
    CONSTRAINT ck_client_credential_secret CHECK (
        credential_kind <> 'SECRET' OR (secret_hash IS NOT NULL AND secret_hash LIKE '$%')
    ),
    CONSTRAINT ck_client_credential_jwk CHECK (credential_kind <> 'PUBLIC_JWK' OR (public_jwk IS NOT NULL AND key_id IS NOT NULL)),
    CONSTRAINT ck_client_credential_jwks_uri CHECK (credential_kind <> 'JWKS_URI' OR jwks_uri ~ '^https://'),
    CONSTRAINT ck_client_credential_mtls CHECK (credential_kind <> 'MTLS_CERT' OR cert_thumbprint_s256 IS NOT NULL),
    CONSTRAINT ck_client_credential_revoked CHECK ((credential_state = 'REVOKED') = (revoked_at IS NOT NULL)),
    CONSTRAINT ck_client_credential_window CHECK (not_after IS NULL OR not_after > not_before)
);
COMMENT ON TABLE oap.client_credential IS 'REQ-MACHINE-003/015：Client 认证材料；支持 GRACE 双钥窗口以实现无中断轮换（REQ-KEY-002）';
COMMENT ON COLUMN oap.client_credential.secret_hash IS '仅在按 CAP-CTRL-006 登记例外时允许存在；默认应使用 private_key_jwt 或 mTLS';

CREATE OR REPLACE TRIGGER trg_client_credential_touch
    BEFORE UPDATE ON oap.client_credential
    FOR EACH ROW EXECUTE FUNCTION core.fn_touch_updated_at();

CREATE INDEX IF NOT EXISTS ix_client_credential_active ON oap.client_credential (client_id, credential_state);
CREATE INDEX IF NOT EXISTS ix_client_credential_expiry ON oap.client_credential (not_after) WHERE credential_state IN ('ACTIVE', 'GRACE');

-- -----------------------------------------------------------------------------
-- 5. API Resource 与 Scope（REQ-MACHINE-005、CAP-OAP-013、CAP-AUTHZ-001）
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS oap.api_resource (
    id                 uuid        NOT NULL DEFAULT core.uuid_generate_v7(),
    public_id          text        NOT NULL,
    audience_value     text        NOT NULL,
    display_name       text        NOT NULL,
    business_line_id   uuid        NOT NULL,
    owner_ref          text        NOT NULL,
    resource_state     text        NOT NULL DEFAULT 'DRAFT',
    token_profile_code text        NOT NULL,
    requires_epoch_check boolean   NOT NULL DEFAULT true,
    revocation_check_mode text     NOT NULL DEFAULT 'SIGNAL_STREAM',
    created_at         timestamptz NOT NULL DEFAULT now(),
    updated_at         timestamptz NOT NULL DEFAULT now(),
    row_version        bigint      NOT NULL DEFAULT 1,
    CONSTRAINT pk_api_resource PRIMARY KEY (id),
    CONSTRAINT uq_api_resource_public_id UNIQUE (public_id),
    CONSTRAINT uq_api_resource_audience UNIQUE (audience_value),
    CONSTRAINT fk_api_resource_business_line FOREIGN KEY (business_line_id) REFERENCES tenant.business_line (id),
    CONSTRAINT ck_api_resource_state CHECK (resource_state IN ('DRAFT', 'ACTIVE', 'DEPRECATED', 'RETIRED')),
    CONSTRAINT ck_api_resource_profile CHECK (token_profile_code IN ('SP1', 'SP2', 'SP3', 'SP4', 'SP5')),
    CONSTRAINT ck_api_resource_revocation CHECK (revocation_check_mode IN ('SIGNAL_STREAM', 'INTROSPECTION', 'SHORT_TTL_ONLY')),
    -- REQ-SESSION-013：高风险资源必须校验 epoch/watermark，不得只验签名与有效期
    CONSTRAINT ck_api_resource_epoch_required CHECK (
        token_profile_code = 'SP1' OR requires_epoch_check
    )
);
COMMENT ON TABLE oap.api_resource IS 'REQ-MACHINE-005：资源注册明确 audience、Owner、Token Profile；REQ-SESSION-012/013 的水位校验方式在此登记';

CREATE OR REPLACE TRIGGER trg_api_resource_touch
    BEFORE UPDATE ON oap.api_resource
    FOR EACH ROW EXECUTE FUNCTION core.fn_touch_updated_at();
CREATE OR REPLACE TRIGGER trg_api_resource_public_id
    BEFORE INSERT ON oap.api_resource
    FOR EACH ROW EXECUTE FUNCTION core.fn_register_public_id('API_RESOURCE');

CREATE TABLE IF NOT EXISTS oap.scope_definition (
    scope_code           text        NOT NULL,
    api_resource_id      uuid        NOT NULL,
    display_name         text        NOT NULL,
    description          text        NOT NULL,
    requires_consent     boolean     NOT NULL DEFAULT true,
    is_sensitive         boolean     NOT NULL DEFAULT false,
    data_classification  text        NOT NULL DEFAULT 'INTERNAL',
    min_profile_code     text        NOT NULL DEFAULT 'SP1',
    claim_mapping        jsonb       NULL,
    deprecated_at        timestamptz NULL,
    created_at           timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT pk_scope_definition PRIMARY KEY (scope_code),
    CONSTRAINT fk_scope_definition_resource FOREIGN KEY (api_resource_id) REFERENCES oap.api_resource (id),
    CONSTRAINT fk_scope_definition_classification FOREIGN KEY (data_classification) REFERENCES core.data_classification (classification_code),
    CONSTRAINT ck_scope_definition_code CHECK (scope_code ~ '^[a-z][a-z0-9:._-]{1,63}$'),
    CONSTRAINT ck_scope_definition_profile CHECK (min_profile_code IN ('SP1', 'SP2', 'SP3', 'SP4', 'SP5')),
    -- 敏感 scope 必须要求同意且不得由 SP1 客户端申请（CAP-PRIV-006 最小化）
    CONSTRAINT ck_scope_definition_sensitive CHECK (
        NOT is_sensitive OR (requires_consent AND min_profile_code <> 'SP1')
    )
);
COMMENT ON TABLE oap.scope_definition IS 'CAP-AUTHZ-001 / CAP-PRIV-003：scope 目录与同意要求；claim_mapping 落实 REQ-PRIV-005 的 purpose→claim 可审计映射';

CREATE INDEX IF NOT EXISTS ix_scope_definition_resource ON oap.scope_definition (api_resource_id);

SELECT core.fn_apply_standard_grants('oap');

SELECT core.fn_migration_apply('050', 'client：Application、Client、回调地址、Client 凭证、API Resource、Scope');
