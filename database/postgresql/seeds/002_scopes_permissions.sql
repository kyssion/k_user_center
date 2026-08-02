\set ON_ERROR_STOP on

SET ROLE iam_owner;

INSERT INTO iam.oauth_scopes (
    id, resource_id, scope_code, display_name, description, sensitivity, consent_required, state
)
VALUES
    ('20000000-0000-0000-0000-000000000001', NULL, 'openid', 'OpenID', '请求 OIDC 身份 Subject。', 'NORMAL', false, 'ACTIVE'),
    ('20000000-0000-0000-0000-000000000002', NULL, 'profile', '基础资料', '请求受控基础资料 Claim。', 'PERSONAL', true, 'ACTIVE'),
    ('20000000-0000-0000-0000-000000000003', NULL, 'email', '邮箱', '请求受控邮箱 Claim。', 'SENSITIVE_PERSONAL', true, 'ACTIVE'),
    ('20000000-0000-0000-0000-000000000004', NULL, 'phone', '手机号', '请求受控手机号 Claim。', 'SENSITIVE_PERSONAL', true, 'ACTIVE'),
    ('20000000-0000-0000-0000-000000000005', NULL, 'offline_access', '离线访问', '请求 Refresh Token；是否允许由 Client、Consent 和风险策略判断。', 'HIGH', true, 'ACTIVE')
ON CONFLICT ON CONSTRAINT uq_oauth_scopes_code DO NOTHING;

INSERT INTO iam.permissions (
    id, permission_code, resource_type, action, sensitivity, description, state
)
VALUES
    ('21000000-0000-0000-0000-000000000001', 'iam.user.read', 'USER', 'READ', 'PERSONAL', '读取受控用户基本信息。', 'ACTIVE'),
    ('21000000-0000-0000-0000-000000000002', 'iam.user.manage', 'USER', 'MANAGE', 'HIGH', '管理用户生命周期；需代码执行保证等级和审批。', 'ACTIVE'),
    ('21000000-0000-0000-0000-000000000003', 'iam.credential.manage', 'AUTHENTICATOR', 'MANAGE', 'CRITICAL', '管理认证器和凭证元数据。', 'ACTIVE'),
    ('21000000-0000-0000-0000-000000000004', 'iam.tenant.manage', 'TENANT', 'MANAGE', 'HIGH', '管理租户、组织和成员关系。', 'ACTIVE'),
    ('21000000-0000-0000-0000-000000000005', 'iam.authorization.manage', 'AUTHORIZATION', 'MANAGE', 'CRITICAL', '管理角色、权限和策略绑定。', 'ACTIVE'),
    ('21000000-0000-0000-0000-000000000006', 'iam.audit.read', 'AUDIT', 'READ', 'HIGH', '读取审计证据。', 'ACTIVE'),
    ('21000000-0000-0000-0000-000000000007', 'iam.key.manage', 'KEY', 'MANAGE', 'CRITICAL', '管理密钥元数据和轮换。', 'ACTIVE'),
    ('21000000-0000-0000-0000-000000000008', 'iam.config.release', 'CONFIGURATION', 'RELEASE', 'CRITICAL', '发布或回滚安全配置。', 'ACTIVE'),
    ('21000000-0000-0000-0000-000000000009', 'iam.event.replay', 'EVENT', 'REPLAY', 'CRITICAL', '发起受控事件回放。', 'ACTIVE'),
    ('21000000-0000-0000-0000-000000000010', 'iam.privacy.process', 'PRIVACY_REQUEST', 'PROCESS', 'CRITICAL', '处理数据主体权利请求。', 'ACTIVE')
ON CONFLICT ON CONSTRAINT uq_permissions_code DO NOTHING;

