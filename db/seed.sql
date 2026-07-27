-- =============================================================================
-- 用户中心初始化数据（seed）
-- 前置：先执行 db/schema.sql
-- 幂等：所有插入均使用 ON CONFLICT DO NOTHING，可重复执行。
-- =============================================================================

-- -----------------------------------------------------------------------------
-- 1. Scope 字典
--    identity 类型：OIDC 标准身份 scope；resource 类型：资源 API 权限示例
-- -----------------------------------------------------------------------------
INSERT INTO scopes (name, display_name, description, type, show_in_discovery)
VALUES
    ('openid',         'OpenID',   'OIDC 必需 scope，请求签发 id_token',        'identity', true),
    ('profile',        '基本资料', '昵称、头像、性别、生日等基本资料',           'identity', true),
    ('email',          '邮箱',     '邮箱地址及验证状态',                         'identity', true),
    ('phone',          '手机号',   '手机号及验证状态',                           'identity', true),
    ('offline_access', '离线访问', '签发 refresh token，允许离线刷新访问令牌',   'identity', true),
    ('user.read',      '读取用户信息', '资源 scope 示例：调用用户中心 API 读取用户信息', 'resource', true)
ON CONFLICT (name) DO NOTHING;

-- -----------------------------------------------------------------------------
-- 2. 示例业务线
-- -----------------------------------------------------------------------------
INSERT INTO business_lines (code, name, description, status, settings)
VALUES
    ('mall',      '商城', '电商商城业务线', 1, '{"session_timeout_minutes": 43200, "force_mfa": false}'::jsonb),
    ('community', '社区', '内容社区业务线', 1, '{"session_timeout_minutes": 43200, "force_mfa": false}'::jsonb)
ON CONFLICT (code) DO NOTHING;

-- -----------------------------------------------------------------------------
-- 3. 示例 OAuth 客户端（每个业务线各 1 个）
--    注意：
--    - business_line_id 通过子查询按 code 关联，不硬编码自增 id；
--    - client_secret_hash 应由应用层用 bcrypt 对随机生成的明文密钥哈希后写入，
--      下方为明显的占位值，切勿用于任何真实环境。
-- -----------------------------------------------------------------------------
INSERT INTO oauth_clients (
    client_id, client_secret_hash, business_line_id, client_name, client_type,
    redirect_uris, post_logout_redirect_uris,
    allowed_grant_types, allowed_scopes,
    require_pkce, require_consent, access_token_ttl, refresh_token_ttl, status
)
VALUES
    (
        'mall-web',
        '$2b$12$PLACEHOLDER.REPLACE.WITH.REAL.BCRYPT.HASH.000000000000000', -- 占位：应用层 bcrypt 生成
        (SELECT id FROM business_lines WHERE code = 'mall'),
        '商城 Web 端',
        'confidential',
        ARRAY['https://mall.example.com/auth/callback'],
        ARRAY['https://mall.example.com/'],
        ARRAY['authorization_code', 'refresh_token'],
        ARRAY['openid', 'profile', 'email', 'phone', 'offline_access', 'user.read'],
        true,  -- require_pkce
        false, -- 自有业务线免 consent
        3600,
        2592000,
        1
    ),
    (
        'community-web',
        '$2b$12$PLACEHOLDER.REPLACE.WITH.REAL.BCRYPT.HASH.111111111111111', -- 占位：应用层 bcrypt 生成
        (SELECT id FROM business_lines WHERE code = 'community'),
        '社区 Web 端',
        'confidential',
        ARRAY['https://community.example.com/auth/callback'],
        ARRAY['https://community.example.com/'],
        ARRAY['authorization_code', 'refresh_token'],
        ARRAY['openid', 'profile', 'email', 'offline_access', 'user.read'],
        true,  -- require_pkce
        false, -- 自有业务线免 consent
        3600,
        2592000,
        1
    )
ON CONFLICT (client_id) DO NOTHING;
