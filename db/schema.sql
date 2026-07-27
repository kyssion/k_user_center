-- =============================================================================
-- 用户中心（Passport / SSO / OAuth2 / OIDC）数据库 Schema
-- 目标数据库：PostgreSQL >= 14
-- 规范：snake_case；业务主表 bigint IDENTITY 主键；timestamptz；令牌只存哈希；
--       软删除 + 部分唯一索引；login_logs / audit_logs 按 created_at 月度分区。
-- 本脚本要求在空库上从头到尾一次性执行无错误。
-- =============================================================================

CREATE EXTENSION IF NOT EXISTS pgcrypto; -- 提供 gen_random_uuid()

-- =============================================================================
-- 一、账号域（Passport）
-- =============================================================================

-- 1. users 全局唯一账号主表
CREATE TABLE users (
    id                  bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    public_id           uuid        NOT NULL UNIQUE DEFAULT gen_random_uuid(),
    username            varchar(64),
    email               varchar(255),
    phone               varchar(32),
    password_hash       varchar(255),
    password_algo       varchar(32),
    password_params     jsonb,
    password_updated_at timestamptz,
    nickname            varchar(64),
    avatar_url          varchar(512),
    gender              smallint    NOT NULL DEFAULT 0,
    birth_date          date,
    status              smallint    NOT NULL DEFAULT 1,
    email_verified      boolean     NOT NULL DEFAULT false,
    phone_verified      boolean     NOT NULL DEFAULT false,
    mfa_enabled         boolean     NOT NULL DEFAULT false,
    extra               jsonb       NOT NULL DEFAULT '{}'::jsonb,
    last_login_at       timestamptz,
    created_at          timestamptz NOT NULL DEFAULT now(),
    updated_at          timestamptz NOT NULL DEFAULT now(),
    deleted_at          timestamptz,
    CONSTRAINT chk_users_status CHECK (status IN (1, 2, 3)),
    CONSTRAINT chk_users_gender CHECK (gender IN (0, 1, 2)),
    CONSTRAINT chk_users_password_algo CHECK (password_algo IS NULL OR password_algo IN ('argon2id', 'bcrypt'))
);

-- 软删除场景下的部分唯一索引：注销（deleted_at 非空）后原值可复用
CREATE UNIQUE INDEX ux_users_username ON users (username) WHERE deleted_at IS NULL;
CREATE UNIQUE INDEX ux_users_email    ON users (email)    WHERE deleted_at IS NULL;
CREATE UNIQUE INDEX ux_users_phone    ON users (phone)    WHERE deleted_at IS NULL;

COMMENT ON TABLE  users IS '全局唯一账号主表（Passport），用户在用户中心只注册一次';
COMMENT ON COLUMN users.id IS '内部自增主键，不对外暴露';
COMMENT ON COLUMN users.public_id IS '对外的全局 Passport ID（uuid），避免暴露自增 ID';
COMMENT ON COLUMN users.username IS '用户名，可空；部分唯一索引（deleted_at IS NULL）';
COMMENT ON COLUMN users.email IS '邮箱，可空；部分唯一索引（deleted_at IS NULL）';
COMMENT ON COLUMN users.phone IS '手机号，可空；部分唯一索引（deleted_at IS NULL）';
COMMENT ON COLUMN users.password_hash IS '密码哈希，可空（允许纯第三方登录账号）';
COMMENT ON COLUMN users.password_algo IS '密码哈希算法：argon2id / bcrypt，支持惰性升级';
COMMENT ON COLUMN users.password_params IS '哈希算法参数（cost、memory 等），jsonb';
COMMENT ON COLUMN users.password_updated_at IS '密码最后修改时间';
COMMENT ON COLUMN users.gender IS '性别：0未知/1男/2女';
COMMENT ON COLUMN users.status IS '账号状态：1正常/2锁定/3注销';
COMMENT ON COLUMN users.email_verified IS '邮箱是否已验证';
COMMENT ON COLUMN users.phone_verified IS '手机号是否已验证';
COMMENT ON COLUMN users.mfa_enabled IS '是否启用多因素认证';
COMMENT ON COLUMN users.extra IS '扩展字段（jsonb）';
COMMENT ON COLUMN users.deleted_at IS '软删除时间，非空表示已注销';

-- 2. user_identities 第三方联合登录绑定
CREATE TABLE user_identities (
    id               bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_id          bigint       NOT NULL REFERENCES users (id),
    provider         varchar(32)  NOT NULL,
    provider_user_id varchar(255) NOT NULL,
    union_id         varchar(255),
    provider_data    jsonb        NOT NULL DEFAULT '{}'::jsonb,
    created_at       timestamptz  NOT NULL DEFAULT now(),
    CONSTRAINT ux_user_identities_provider_uid UNIQUE (provider, provider_user_id)
);

CREATE INDEX ix_user_identities_user_id  ON user_identities (user_id);
CREATE INDEX ix_user_identities_union_id ON user_identities (union_id);

COMMENT ON TABLE  user_identities IS '第三方联合登录绑定（wechat/google/github 等）';
COMMENT ON COLUMN user_identities.provider IS '第三方平台标识：wechat/google/github 等';
COMMENT ON COLUMN user_identities.provider_user_id IS '第三方平台的用户唯一 ID（如 openid）';
COMMENT ON COLUMN user_identities.union_id IS '第三方平台的跨应用统一 ID（如微信 unionid）';
COMMENT ON COLUMN user_identities.provider_data IS '第三方返回的原始资料快照（jsonb）';

-- 3. password_histories 密码历史（防重用，应用层保留最近 5 条）
CREATE TABLE password_histories (
    id            bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_id       bigint       NOT NULL REFERENCES users (id),
    password_hash varchar(255) NOT NULL,
    password_algo varchar(32)  NOT NULL,
    created_at    timestamptz  NOT NULL DEFAULT now()
);

CREATE INDEX ix_password_histories_user_created ON password_histories (user_id, created_at DESC);

COMMENT ON TABLE  password_histories IS '密码历史，防止用户重复使用近期密码（应用层保留最近 5 条）';
COMMENT ON COLUMN password_histories.password_hash IS '历史密码哈希';
COMMENT ON COLUMN password_histories.password_algo IS '历史密码使用的哈希算法';

-- 4. verification_codes 短信/邮件验证码
--    备用持久化方案：生产环境建议使用 Redis 存储验证码，本表用于无 Redis 场景与审计留痕
CREATE TABLE verification_codes (
    id              bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    identifier      varchar(255) NOT NULL,
    scene           varchar(32)  NOT NULL,
    code_hash       varchar(255) NOT NULL,
    send_ip         inet,
    attempt_count   integer      NOT NULL DEFAULT 0,
    last_attempt_at timestamptz,
    locked_until    timestamptz,
    expires_at      timestamptz  NOT NULL,
    consumed_at     timestamptz,
    created_at      timestamptz  NOT NULL DEFAULT now(),
    CONSTRAINT chk_verification_codes_scene CHECK (scene IN ('register', 'login', 'reset_password', 'bind'))
);

CREATE INDEX ix_verification_codes_identifier ON verification_codes (identifier, scene, created_at DESC);
CREATE INDEX ix_verification_codes_expires    ON verification_codes (expires_at); -- TTL 清理扫描

COMMENT ON TABLE  verification_codes IS '短信/邮件验证码（备用持久化，生产建议放 Redis）';
COMMENT ON COLUMN verification_codes.identifier IS '接收方标识：手机号或邮箱';
COMMENT ON COLUMN verification_codes.scene IS '使用场景：register/login/reset_password/bind';
COMMENT ON COLUMN verification_codes.code_hash IS '验证码哈希（不存明文）';
COMMENT ON COLUMN verification_codes.send_ip IS '发送请求来源 IP';
COMMENT ON COLUMN verification_codes.attempt_count IS '当前验证码已尝试校验次数（防暴力猜测）';
COMMENT ON COLUMN verification_codes.last_attempt_at IS '最近一次校验时间';
COMMENT ON COLUMN verification_codes.locked_until IS '锁定到期时间，超过尝试上限后锁定至该时刻';
COMMENT ON COLUMN verification_codes.expires_at IS '过期时间';
COMMENT ON COLUMN verification_codes.consumed_at IS '消费时间，非空表示已使用（一次性）';

-- 5. mfa_credentials 多因素认证凭证（预留）
CREATE TABLE mfa_credentials (
    id                     bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_id                bigint      NOT NULL REFERENCES users (id),
    mfa_type               varchar(16) NOT NULL,
    secret_encrypted       text,
    webauthn_credential_id varchar(512),
    webauthn_public_key    jsonb,
    backup_codes_hash      text[],
    verified_at            timestamptz,
    is_active              boolean     NOT NULL DEFAULT true,
    created_at             timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT chk_mfa_credentials_type CHECK (mfa_type IN ('totp', 'webauthn', 'sms'))
);

CREATE INDEX ix_mfa_credentials_user_id ON mfa_credentials (user_id);

COMMENT ON TABLE  mfa_credentials IS '多因素认证凭证（totp/webauthn/sms，预留）';
COMMENT ON COLUMN mfa_credentials.mfa_type IS 'MFA 类型：totp/webauthn/sms';
COMMENT ON COLUMN mfa_credentials.secret_encrypted IS 'TOTP 密钥（应用层加密存储）';
COMMENT ON COLUMN mfa_credentials.webauthn_credential_id IS 'WebAuthn 凭证 ID';
COMMENT ON COLUMN mfa_credentials.webauthn_public_key IS 'WebAuthn 公钥（jsonb）';
COMMENT ON COLUMN mfa_credentials.backup_codes_hash IS '备用恢复码哈希数组';
COMMENT ON COLUMN mfa_credentials.verified_at IS '凭证完成验证绑定的时间';

-- =============================================================================
-- 二、业务线域（多业务线接入）
-- =============================================================================

-- 6. business_lines 业务线定义
CREATE TABLE business_lines (
    id          bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    code        varchar(64)  NOT NULL UNIQUE,
    name        varchar(128) NOT NULL,
    description text,
    status      smallint     NOT NULL DEFAULT 1,
    settings    jsonb        NOT NULL DEFAULT '{}'::jsonb,
    created_at  timestamptz  NOT NULL DEFAULT now(),
    updated_at  timestamptz  NOT NULL DEFAULT now(),
    CONSTRAINT chk_business_lines_status CHECK (status IN (1, 2))
);

COMMENT ON TABLE  business_lines IS '业务线定义（租户维度），一个业务线可挂多个 oauth_clients';
COMMENT ON COLUMN business_lines.code IS '业务线唯一编码，如 mall/community';
COMMENT ON COLUMN business_lines.status IS '状态：1启用/2停用';
COMMENT ON COLUMN business_lines.settings IS '业务线策略配置：会话超时、是否强制 MFA 等（jsonb）';

-- 7. user_business_lines 用户与业务线开通关系
CREATE TABLE user_business_lines (
    id               bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_id          bigint      NOT NULL REFERENCES users (id),
    business_line_id bigint      NOT NULL REFERENCES business_lines (id),
    status           smallint    NOT NULL DEFAULT 1,
    registered_at    timestamptz NOT NULL DEFAULT now(),
    extra            jsonb       NOT NULL DEFAULT '{}'::jsonb,
    CONSTRAINT ux_user_business_lines UNIQUE (user_id, business_line_id),
    CONSTRAINT chk_user_business_lines_status CHECK (status IN (1, 2))
);

CREATE INDEX ix_user_business_lines_bl ON user_business_lines (business_line_id);

COMMENT ON TABLE  user_business_lines IS '用户与业务线的开通关系：用户全局注册一次，按业务线开通';
COMMENT ON COLUMN user_business_lines.status IS '开通状态：1正常/2禁用';
COMMENT ON COLUMN user_business_lines.registered_at IS '在该业务线的开通时间';
COMMENT ON COLUMN user_business_lines.extra IS '业务线侧扩展资料（jsonb），预留 RBAC 等扩展';

-- 8. oauth_clients 接入应用（OAuth2 客户端）
CREATE TABLE oauth_clients (
    id                        bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    client_id                 varchar(64)  NOT NULL UNIQUE,
    client_secret_hash        varchar(255),
    business_line_id          bigint       NOT NULL REFERENCES business_lines (id),
    client_name               varchar(128) NOT NULL,
    client_type               varchar(16)  NOT NULL DEFAULT 'confidential',
    redirect_uris             text[]       NOT NULL DEFAULT '{}',
    post_logout_redirect_uris text[]       NOT NULL DEFAULT '{}',
    allowed_grant_types       text[]       NOT NULL DEFAULT '{authorization_code,refresh_token}',
    allowed_scopes            text[]       NOT NULL DEFAULT '{}',
    require_pkce              boolean      NOT NULL DEFAULT true,
    require_consent           boolean      NOT NULL DEFAULT false,
    access_token_ttl          integer      NOT NULL DEFAULT 3600,
    refresh_token_ttl         integer      NOT NULL DEFAULT 2592000,
    status                    smallint     NOT NULL DEFAULT 1,
    created_at                timestamptz  NOT NULL DEFAULT now(),
    updated_at                timestamptz  NOT NULL DEFAULT now(),
    CONSTRAINT chk_oauth_clients_type   CHECK (client_type IN ('confidential', 'public')),
    CONSTRAINT chk_oauth_clients_status CHECK (status IN (1, 2)),
    CONSTRAINT chk_oauth_clients_ttl    CHECK (access_token_ttl > 0 AND refresh_token_ttl > 0)
);

CREATE INDEX ix_oauth_clients_business_line ON oauth_clients (business_line_id);

COMMENT ON TABLE  oauth_clients IS 'OAuth2/OIDC 接入客户端（应用实例），一个业务线可有 Web/App 多个客户端';
COMMENT ON COLUMN oauth_clients.client_id IS '对外的客户端标识（client_id）';
COMMENT ON COLUMN oauth_clients.client_secret_hash IS '客户端密钥 bcrypt 哈希，不存明文；public 客户端可为空';
COMMENT ON COLUMN oauth_clients.client_type IS '客户端类型：confidential（服务端）/public（SPA、移动端）';
COMMENT ON COLUMN oauth_clients.redirect_uris IS '允许的授权回调地址白名单';
COMMENT ON COLUMN oauth_clients.post_logout_redirect_uris IS '登出后允许跳转的地址白名单';
COMMENT ON COLUMN oauth_clients.allowed_grant_types IS '允许的授权类型：authorization_code/refresh_token/client_credentials 等';
COMMENT ON COLUMN oauth_clients.allowed_scopes IS '允许申请的 scope 列表';
COMMENT ON COLUMN oauth_clients.require_pkce IS '是否强制 PKCE（默认强制）';
COMMENT ON COLUMN oauth_clients.require_consent IS '是否需要用户授权同意页（自有业务线可免 consent）';
COMMENT ON COLUMN oauth_clients.access_token_ttl IS 'access token 有效期（秒），默认 3600';
COMMENT ON COLUMN oauth_clients.refresh_token_ttl IS 'refresh token 有效期（秒），默认 2592000（30 天）';
COMMENT ON COLUMN oauth_clients.status IS '状态：1启用/2禁用';

-- 9. scopes Scope 字典
CREATE TABLE scopes (
    id                bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    name              varchar(64)  NOT NULL UNIQUE,
    display_name      varchar(128) NOT NULL,
    description       text,
    type              varchar(16)  NOT NULL DEFAULT 'resource',
    show_in_discovery boolean      NOT NULL DEFAULT true,
    CONSTRAINT chk_scopes_type CHECK (type IN ('identity', 'resource'))
);

COMMENT ON TABLE  scopes IS 'Scope 字典，供管理后台与 OIDC Discovery 使用';
COMMENT ON COLUMN scopes.name IS 'scope 名称，如 openid/profile/user.read';
COMMENT ON COLUMN scopes.type IS '类型：identity（身份声明）/resource（资源权限）';
COMMENT ON COLUMN scopes.show_in_discovery IS '是否在 OIDC Discovery 文档中公开';

-- =============================================================================
-- 三、SSO / OAuth2 / OIDC 域
-- =============================================================================

-- 10. sso_sessions 认证中心全局登录会话（SSO 核心）
CREATE TABLE sso_sessions (
    id                 uuid         NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
    user_id            bigint       NOT NULL REFERENCES users (id),
    session_token_hash varchar(255) NOT NULL UNIQUE,
    login_method       varchar(32)  NOT NULL,
    ip                 inet,
    user_agent         text,
    device_info        jsonb        NOT NULL DEFAULT '{}'::jsonb,
    status             smallint     NOT NULL DEFAULT 1,
    last_activity_at   timestamptz  NOT NULL DEFAULT now(),
    expires_at         timestamptz  NOT NULL,
    revoked_at         timestamptz,
    created_at         timestamptz  NOT NULL DEFAULT now(),
    CONSTRAINT chk_sso_sessions_status CHECK (status IN (1, 2, 3))
);

CREATE INDEX ix_sso_sessions_user_active    ON sso_sessions (user_id)    WHERE status = 1;
CREATE INDEX ix_sso_sessions_expires_active ON sso_sessions (expires_at) WHERE status = 1;

COMMENT ON TABLE  sso_sessions IS '认证中心全局登录会话（浏览器 SSO cookie 对应），单点登出的级联撤销根节点';
COMMENT ON COLUMN sso_sessions.id IS '会话 uuid 主键，供下游令牌表通过 session_id 关联';
COMMENT ON COLUMN sso_sessions.session_token_hash IS '会话令牌 SHA-256 哈希，不存明文';
COMMENT ON COLUMN sso_sessions.login_method IS '登录方式：password/sms/wechat 等';
COMMENT ON COLUMN sso_sessions.status IS '会话状态：1活跃/2登出/3被踢';
COMMENT ON COLUMN sso_sessions.last_activity_at IS '最近活跃时间（滑动续期依据）';
COMMENT ON COLUMN sso_sessions.expires_at IS '会话过期时间';
COMMENT ON COLUMN sso_sessions.revoked_at IS '撤销时间（登出/被踢）';

-- 11. oauth_authorization_codes 授权码（10 分钟有效、一次性）
CREATE TABLE oauth_authorization_codes (
    id                    bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    code_hash             varchar(255) NOT NULL UNIQUE,
    client_ref_id         bigint       NOT NULL REFERENCES oauth_clients (id),
    user_id               bigint       NOT NULL REFERENCES users (id),
    session_id            uuid REFERENCES sso_sessions (id),
    redirect_uri          varchar(512) NOT NULL,
    scope                 text         NOT NULL,
    code_challenge        varchar(255),
    code_challenge_method varchar(8),
    nonce                 varchar(255),
    expires_at            timestamptz  NOT NULL,
    consumed_at           timestamptz,
    created_at            timestamptz  NOT NULL DEFAULT now(),
    CONSTRAINT chk_oauth_codes_challenge_method CHECK (code_challenge_method IS NULL OR code_challenge_method IN ('S256', 'plain'))
);

CREATE INDEX ix_oauth_codes_expires_pending ON oauth_authorization_codes (expires_at) WHERE consumed_at IS NULL;

COMMENT ON TABLE  oauth_authorization_codes IS 'OAuth2 授权码（10 分钟有效、一次性消费）';
COMMENT ON COLUMN oauth_authorization_codes.code_hash IS '授权码 SHA-256 哈希，不存明文';
COMMENT ON COLUMN oauth_authorization_codes.client_ref_id IS '关联 oauth_clients.id（内部自增 ID）';
COMMENT ON COLUMN oauth_authorization_codes.session_id IS '签发该授权码的 SSO 会话，用于单点登出级联撤销';
COMMENT ON COLUMN oauth_authorization_codes.code_challenge IS 'PKCE 质询值';
COMMENT ON COLUMN oauth_authorization_codes.code_challenge_method IS 'PKCE 方法：S256/plain（RFC 7636）';
COMMENT ON COLUMN oauth_authorization_codes.nonce IS 'OIDC nonce，回填 id_token 防重放';
COMMENT ON COLUMN oauth_authorization_codes.consumed_at IS '消费时间，非空表示已兑换（一次性）';

-- 12. oauth_refresh_tokens 刷新令牌（一次性轮转）
CREATE TABLE oauth_refresh_tokens (
    id             bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    token_hash     varchar(255) NOT NULL UNIQUE,
    user_id        bigint       NOT NULL REFERENCES users (id),
    client_ref_id  bigint       NOT NULL REFERENCES oauth_clients (id),
    session_id     uuid REFERENCES sso_sessions (id),
    scope          text         NOT NULL,
    expires_at     timestamptz  NOT NULL,
    revoked_at     timestamptz,
    revoke_reason  varchar(64),
    replaced_by_id bigint,
    ip             inet,
    created_at     timestamptz  NOT NULL DEFAULT now()
);

CREATE INDEX ix_oauth_refresh_tokens_user_client ON oauth_refresh_tokens (user_id, client_ref_id);
CREATE INDEX ix_oauth_refresh_tokens_session     ON oauth_refresh_tokens (session_id);
CREATE INDEX ix_oauth_refresh_tokens_expires     ON oauth_refresh_tokens (expires_at); -- TTL 清理扫描

COMMENT ON TABLE  oauth_refresh_tokens IS 'OAuth2 刷新令牌，一次性轮转（rotation），旧令牌重放即视为攻击';
COMMENT ON COLUMN oauth_refresh_tokens.token_hash IS 'refresh token SHA-256 哈希，不存明文';
COMMENT ON COLUMN oauth_refresh_tokens.session_id IS '签发时所属 SSO 会话，撤销会话即可级联撤销（单点登出）';
COMMENT ON COLUMN oauth_refresh_tokens.revoke_reason IS '撤销原因：rotated/logout/reuse_detected/admin 等';
COMMENT ON COLUMN oauth_refresh_tokens.replaced_by_id IS '轮转链：指向替换本令牌的新令牌 id（自引用逻辑关联，不加物理 FK，避免轮转写入时的约束开销与删除顺序耦合）';
COMMENT ON COLUMN oauth_refresh_tokens.ip IS '签发时客户端 IP';

-- 13. user_consents 用户授权记录
CREATE TABLE user_consents (
    id             bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_id        bigint      NOT NULL REFERENCES users (id),
    client_ref_id  bigint      NOT NULL REFERENCES oauth_clients (id),
    granted_scopes text        NOT NULL,
    granted_at     timestamptz NOT NULL DEFAULT now(),
    expires_at     timestamptz,
    revoked_at     timestamptz,
    CONSTRAINT ux_user_consents UNIQUE (user_id, client_ref_id)
);

COMMENT ON TABLE  user_consents IS '用户对客户端的授权同意记录（consent）';
COMMENT ON COLUMN user_consents.granted_scopes IS '用户已同意的 scope（空格分隔）';
COMMENT ON COLUMN user_consents.revoked_at IS '用户撤销授权的时间';

-- 14. token_denylist JWT access token 撤销名单
CREATE TABLE token_denylist (
    id         bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    jti        varchar(64) NOT NULL UNIQUE,
    user_id    bigint,
    reason     varchar(64),
    expires_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX ix_token_denylist_expires ON token_denylist (expires_at);

COMMENT ON TABLE  token_denylist IS 'JWT access token 撤销名单（jti 维度），配合 Redis 缓存查询；到达 expires_at 后可清理';
COMMENT ON COLUMN token_denylist.jti IS '被撤销的 JWT 的 jti 声明';
COMMENT ON COLUMN token_denylist.user_id IS '所属用户（逻辑关联，便于按用户批量撤销统计）';
COMMENT ON COLUMN token_denylist.expires_at IS '原 token 的过期时间，之后本条记录可安全清理';

-- 15. signing_keys JWK 签名密钥轮换
CREATE TABLE signing_keys (
    id                    bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    kid                   varchar(64) NOT NULL UNIQUE,
    algorithm             varchar(16) NOT NULL,
    use                   varchar(8)  NOT NULL DEFAULT 'sig',
    public_jwk            jsonb       NOT NULL,
    private_key_encrypted text        NOT NULL,
    status                varchar(16) NOT NULL DEFAULT 'active',
    created_at            timestamptz NOT NULL DEFAULT now(),
    expires_at            timestamptz,
    retired_at            timestamptz,
    CONSTRAINT chk_signing_keys_algorithm CHECK (algorithm IN ('RS256', 'ES256')),
    CONSTRAINT chk_signing_keys_status    CHECK (status IN ('active', 'retired', 'revoked'))
);

COMMENT ON TABLE  signing_keys IS 'JWT 签名密钥（JWK）轮换管理，公钥经 jwks_uri 对外发布';
COMMENT ON COLUMN signing_keys.kid IS 'JWK key id，写入 JWT header';
COMMENT ON COLUMN signing_keys.algorithm IS '签名算法：RS256/ES256';
COMMENT ON COLUMN signing_keys.public_jwk IS '公钥 JWK（jsonb），可直接拼入 jwks 响应';
COMMENT ON COLUMN signing_keys.private_key_encrypted IS '私钥密文（应用层 KMS/信封加密）';
COMMENT ON COLUMN signing_keys.status IS '密钥状态：active（签发中）/retired（仅验签）/revoked（吊销）';

-- =============================================================================
-- 四、安全审计域（月度 RANGE 分区，逻辑外键——不加 REFERENCES）
-- =============================================================================

-- 16. login_logs 登录/认证日志（分区表）
CREATE TABLE login_logs (
    id                 bigint GENERATED ALWAYS AS IDENTITY,
    user_id            bigint,
    login_identifier   varchar(255),
    business_line_id   bigint,
    client_ref_id      bigint,
    login_method       varchar(32),
    ip                 inet,
    user_agent         text,
    device_fingerprint varchar(128),
    success            boolean     NOT NULL,
    failure_reason     varchar(128),
    created_at         timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (id, created_at)
) PARTITION BY RANGE (created_at);

CREATE INDEX ix_login_logs_user_created       ON login_logs (user_id, created_at DESC);
CREATE INDEX ix_login_logs_identifier_created ON login_logs (login_identifier, created_at DESC);
CREATE INDEX ix_login_logs_ip_created         ON login_logs (ip, created_at DESC);

COMMENT ON TABLE  login_logs IS '登录/认证日志，按 created_at 月度分区；user_id 等为逻辑外键（无约束）';
COMMENT ON COLUMN login_logs.user_id IS '用户 ID（逻辑外键，可空——记录登录失败尝试）';
COMMENT ON COLUMN login_logs.login_identifier IS '登录时输入的标识（用户名/邮箱/手机号），用于防撞库统计';
COMMENT ON COLUMN login_logs.business_line_id IS '业务线 ID（逻辑外键）';
COMMENT ON COLUMN login_logs.client_ref_id IS '客户端内部 ID（逻辑外键，关联 oauth_clients.id）';
COMMENT ON COLUMN login_logs.success IS '是否登录成功';
COMMENT ON COLUMN login_logs.failure_reason IS '失败原因：wrong_password/user_locked/code_invalid 等';

-- 17. audit_logs 关键操作审计（分区表）
CREATE TABLE audit_logs (
    id               bigint GENERATED ALWAYS AS IDENTITY,
    operator_user_id bigint,
    action           varchar(64) NOT NULL,
    resource_type    varchar(64) NOT NULL,
    resource_id      varchar(128),
    changes          jsonb,
    ip               inet,
    request_id       uuid,
    created_at       timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (id, created_at)
) PARTITION BY RANGE (created_at);

CREATE INDEX ix_audit_logs_operator_created ON audit_logs (operator_user_id, created_at DESC);
CREATE INDEX ix_audit_logs_resource         ON audit_logs (resource_type, resource_id);

COMMENT ON TABLE  audit_logs IS '关键操作审计（密码修改、绑定变更、授权撤销、客户端管理等），按 created_at 月度分区';
COMMENT ON COLUMN audit_logs.operator_user_id IS '操作者用户 ID（逻辑外键，可空=系统操作）';
COMMENT ON COLUMN audit_logs.action IS '动作标识，如 password.change/identity.bind/client.update';
COMMENT ON COLUMN audit_logs.resource_type IS '资源类型，如 user/oauth_client/consent';
COMMENT ON COLUMN audit_logs.resource_id IS '资源 ID（字符串，兼容 uuid/bigint）';
COMMENT ON COLUMN audit_logs.changes IS '变更前后值（jsonb）';
COMMENT ON COLUMN audit_logs.request_id IS '链路追踪请求 ID';

-- =============================================================================
-- 五、分区管理函数与预建分区
-- =============================================================================

-- 动态创建指定表的指定月份分区，已存在则跳过。
-- 用法：SELECT ensure_monthly_partition('login_logs', date '2026-08-01');
-- 建议由定时任务（如 pg_cron 或应用调度）每月提前调用创建下月分区。
CREATE OR REPLACE FUNCTION ensure_monthly_partition(p_table text, p_month date)
RETURNS void
LANGUAGE plpgsql
AS $$
DECLARE
    v_start          date := date_trunc('month', p_month)::date;
    v_end            date := (date_trunc('month', p_month) + interval '1 month')::date;
    v_partition_name text := format('%s_%s', p_table, to_char(v_start, 'YYYYMM'));
BEGIN
    IF to_regclass(v_partition_name) IS NULL THEN
        EXECUTE format(
            'CREATE TABLE %I PARTITION OF %I FOR VALUES FROM (%L) TO (%L)',
            v_partition_name, p_table, v_start, v_end
        );
    END IF;
END;
$$;

COMMENT ON FUNCTION ensure_monthly_partition(text, date) IS '为指定分区表创建指定月份的 RANGE 分区（存在则跳过），命名规则 <table>_YYYYMM';

-- 预建 login_logs、audit_logs 自当前月起共 3 个月的分区
DO $$
DECLARE
    v_month date;
    i       int;
BEGIN
    FOR i IN 0..2 LOOP
        v_month := (date_trunc('month', now()) + make_interval(months => i))::date;
        PERFORM ensure_monthly_partition('login_logs', v_month);
        PERFORM ensure_monthly_partition('audit_logs', v_month);
    END LOOP;
END;
$$;

-- DEFAULT 兜底分区：若定时任务中断、未及时创建下月分区，写入将落入 DEFAULT 分区而不报错，
-- 避免日志写入失败影响业务；恢复后应将 DEFAULT 分区中的数据离线迁移回对应月分区。
CREATE TABLE login_logs_default PARTITION OF login_logs DEFAULT;
CREATE TABLE audit_logs_default PARTITION OF audit_logs DEFAULT;

COMMENT ON TABLE login_logs_default IS 'login_logs 的 DEFAULT 兜底分区，防止月分区缺失导致写入报错';
COMMENT ON TABLE audit_logs_default IS 'audit_logs 的 DEFAULT 兜底分区，防止月分区缺失导致写入报错';
