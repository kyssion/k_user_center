\set ON_ERROR_STOP on

SET ROLE iam_owner;

WITH seed(id, resource_id, scope_code, display_name, description, sensitivity, consent_required, state) AS (
VALUES
    ('20000000-0000-0000-0000-000000000001', NULL, 'openid', 'OpenID', '请求 OIDC 身份 Subject。', 'NORMAL', false, 'ACTIVE'),
    ('20000000-0000-0000-0000-000000000002', NULL, 'profile', '基础资料', '请求受控基础资料 Claim。', 'PERSONAL', true, 'ACTIVE'),
    ('20000000-0000-0000-0000-000000000003', NULL, 'email', '邮箱', '请求受控邮箱 Claim。', 'SENSITIVE_PERSONAL', true, 'ACTIVE'),
    ('20000000-0000-0000-0000-000000000004', NULL, 'phone', '手机号', '请求受控手机号 Claim。', 'SENSITIVE_PERSONAL', true, 'ACTIVE'),
    ('20000000-0000-0000-0000-000000000005', NULL, 'offline_access', '离线访问', '请求 Refresh Token；是否允许由 Client、Consent 和风险策略判断。', 'HIGH', true, 'ACTIVE')
), applied AS (
INSERT INTO iam.oauth_scopes AS current_scope (
    id, resource_id, scope_code, display_name, description, sensitivity, consent_required, state
)
SELECT id::uuid, resource_id::uuid, scope_code, display_name, description, sensitivity, consent_required, state
FROM seed
ON CONFLICT ON CONSTRAINT uq_oauth_scopes_code DO UPDATE
SET id = current_scope.id
WHERE current_scope.id = EXCLUDED.id
  AND current_scope.resource_id IS NOT DISTINCT FROM EXCLUDED.resource_id
  AND current_scope.display_name = EXCLUDED.display_name
  AND current_scope.description = EXCLUDED.description
  AND current_scope.sensitivity = EXCLUDED.sensitivity
  AND current_scope.consent_required = EXCLUDED.consent_required
RETURNING 1
)
SELECT 1 / CASE WHEN (SELECT count(*) FROM applied) = (SELECT count(*) FROM seed) THEN 1 ELSE 0 END AS seed_content_match;

WITH seed(id, permission_code, resource_type, action, sensitivity, description, state) AS (
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
    ('21000000-0000-0000-0000-000000000010', 'iam.privacy.process', 'PRIVACY_REQUEST', 'PROCESS', 'CRITICAL', '处理数据主体权利请求。', 'ACTIVE'),
    ('21000000-0000-0000-0000-000000000011', 'iam.identifier.read', 'IDENTIFIER', 'READ', 'SENSITIVE_PERSONAL', '读取受控标识元数据，不直接暴露标识明文。', 'ACTIVE'),
    ('21000000-0000-0000-0000-000000000012', 'iam.identifier.manage', 'IDENTIFIER', 'MANAGE', 'CRITICAL', '验证、绑定、解绑和换绑用户标识。', 'ACTIVE'),
    ('21000000-0000-0000-0000-000000000013', 'iam.authenticator.read', 'AUTHENTICATOR', 'READ', 'HIGH', '读取认证器状态和非秘密元数据。', 'ACTIVE'),
    ('21000000-0000-0000-0000-000000000014', 'iam.session.read', 'SESSION', 'READ', 'HIGH', '读取受控会话和设备会话状态。', 'ACTIVE'),
    ('21000000-0000-0000-0000-000000000015', 'iam.session.revoke', 'SESSION', 'REVOKE', 'CRITICAL', '撤销会话、Grant 或 Token Family。', 'ACTIVE'),
    ('21000000-0000-0000-0000-000000000016', 'iam.client.read', 'OAUTH_CLIENT', 'READ', 'INTERNAL', '读取 OAuth/OIDC Client 配置元数据。', 'ACTIVE'),
    ('21000000-0000-0000-0000-000000000017', 'iam.client.manage', 'OAUTH_CLIENT', 'MANAGE', 'CRITICAL', '管理 Client、回调、Profile 和认证方式。', 'ACTIVE'),
    ('21000000-0000-0000-0000-000000000018', 'iam.tenant.read', 'TENANT', 'READ', 'INTERNAL', '读取租户、组织和成员关系。', 'ACTIVE'),
    ('21000000-0000-0000-0000-000000000019', 'iam.membership.read', 'MEMBERSHIP', 'READ', 'PERSONAL', '读取租户成员关系和有效范围。', 'ACTIVE'),
    ('21000000-0000-0000-0000-000000000020', 'iam.membership.manage', 'MEMBERSHIP', 'MANAGE', 'HIGH', '邀请、加入、移除和变更租户成员。', 'ACTIVE'),
    ('21000000-0000-0000-0000-000000000021', 'iam.authorization.read', 'AUTHORIZATION', 'READ', 'HIGH', '读取角色、权限、策略绑定和决策证据。', 'ACTIVE'),
    ('21000000-0000-0000-0000-000000000022', 'iam.policy.read', 'POLICY', 'READ', 'HIGH', '读取授权策略版本和绑定。', 'ACTIVE'),
    ('21000000-0000-0000-0000-000000000023', 'iam.policy.publish', 'POLICY', 'PUBLISH', 'CRITICAL', '发布或回滚授权策略版本。', 'ACTIVE'),
    ('21000000-0000-0000-0000-000000000024', 'iam.consent.read', 'CONSENT', 'READ', 'SENSITIVE_PERSONAL', '读取同意记录和适用安全水位。', 'ACTIVE'),
    ('21000000-0000-0000-0000-000000000025', 'iam.consent.manage', 'CONSENT', 'MANAGE', 'HIGH', '授予、取代或撤回 Consent。', 'ACTIVE'),
    ('21000000-0000-0000-0000-000000000026', 'iam.privacy.read', 'PRIVACY_REQUEST', 'READ', 'SENSITIVE_PERSONAL', '读取个人权利请求和处理进度。', 'ACTIVE'),
    ('21000000-0000-0000-0000-000000000027', 'iam.risk.read', 'RISK', 'READ', 'HIGH', '读取风险评估、信号和限制结果。', 'ACTIVE'),
    ('21000000-0000-0000-0000-000000000028', 'iam.risk.investigate', 'RISK_CASE', 'INVESTIGATE', 'CRITICAL', '调查风险案件并执行受控处置。', 'ACTIVE'),
    ('21000000-0000-0000-0000-000000000029', 'iam.approval.read', 'APPROVAL_CASE', 'READ', 'HIGH', '读取审批单、请求摘要和审批进度。', 'ACTIVE'),
    ('21000000-0000-0000-0000-000000000030', 'iam.approval.review', 'APPROVAL_CASE', 'REVIEW', 'CRITICAL', '对高风险审批单执行批准或拒绝。', 'ACTIVE'),
    ('21000000-0000-0000-0000-000000000031', 'iam.delegation.read', 'DELEGATION', 'READ', 'HIGH', '读取委托关系和有效范围。', 'ACTIVE'),
    ('21000000-0000-0000-0000-000000000032', 'iam.delegation.manage', 'DELEGATION', 'MANAGE', 'CRITICAL', '创建、激活或撤销委托关系。', 'ACTIVE'),
    ('21000000-0000-0000-0000-000000000033', 'iam.key.read', 'KEY', 'READ', 'HIGH', '读取密钥、证书和 JWKS 非秘密元数据。', 'ACTIVE'),
    ('21000000-0000-0000-0000-000000000034', 'iam.config.read', 'CONFIGURATION', 'READ', 'HIGH', '读取不可变配置版本和发布状态。', 'ACTIVE'),
    ('21000000-0000-0000-0000-000000000035', 'iam.event.read', 'EVENT', 'READ', 'INTERNAL', '读取事件 Schema、投递和消费者水位。', 'ACTIVE'),
    ('21000000-0000-0000-0000-000000000036', 'iam.event.publish', 'EVENT', 'PUBLISH', 'HIGH', '以获授权 Producer 身份发布登记事件类型。', 'ACTIVE'),
    ('21000000-0000-0000-0000-000000000037', 'iam.webhook.manage', 'WEBHOOK', 'MANAGE', 'CRITICAL', '管理 Webhook 订阅、目标和签名密钥。', 'ACTIVE'),
    ('21000000-0000-0000-0000-000000000038', 'iam.message.read', 'MESSAGE', 'READ', 'HIGH', '读取消息请求和投递状态，不暴露敏感内容。', 'ACTIVE'),
    ('21000000-0000-0000-0000-000000000039', 'iam.message.send', 'MESSAGE', 'SEND', 'HIGH', '发送登记模板消息。', 'ACTIVE'),
    ('21000000-0000-0000-0000-000000000040', 'iam.message.template.manage', 'MESSAGE_TEMPLATE', 'MANAGE', 'CRITICAL', '创建、审批和发布消息模板版本。', 'ACTIVE'),
    ('21000000-0000-0000-0000-000000000041', 'iam.migration.read', 'MIGRATION', 'READ', 'HIGH', '读取迁移批次、映射和对账结果。', 'ACTIVE'),
    ('21000000-0000-0000-0000-000000000042', 'iam.migration.manage', 'MIGRATION', 'MANAGE', 'CRITICAL', '创建迁移批次并执行受控切换或回退。', 'ACTIVE'),
    ('21000000-0000-0000-0000-000000000043', 'iam.profile.read', 'PROFILE', 'READ', 'PERSONAL', '读取受控用户 Profile 和字段文档。', 'ACTIVE'),
    ('21000000-0000-0000-0000-000000000044', 'iam.profile.manage', 'PROFILE', 'MANAGE', 'HIGH', '修改用户资料和主联系方式引用。', 'ACTIVE'),
    ('21000000-0000-0000-0000-000000000045', 'iam.federation.read', 'IDENTITY_PROVIDER', 'READ', 'HIGH', '读取外部身份源和目录同步状态。', 'ACTIVE'),
    ('21000000-0000-0000-0000-000000000046', 'iam.federation.manage', 'IDENTITY_PROVIDER', 'MANAGE', 'CRITICAL', '管理身份源、目录连接器和同步映射。', 'ACTIVE'),
    ('21000000-0000-0000-0000-000000000047', 'iam.machine.read', 'MACHINE_PRINCIPAL', 'READ', 'HIGH', '读取机器主体和工作负载信任元数据。', 'ACTIVE'),
    ('21000000-0000-0000-0000-000000000048', 'iam.machine.manage', 'MACHINE_PRINCIPAL', 'MANAGE', 'CRITICAL', '管理机器主体、凭证和工作负载信任。', 'ACTIVE')
), applied AS (
INSERT INTO iam.permissions AS current_permission (
    id, permission_code, resource_type, action, sensitivity, description, state
)
SELECT id::uuid, permission_code, resource_type, action, sensitivity, description, state
FROM seed
ON CONFLICT ON CONSTRAINT uq_permissions_code DO UPDATE
SET id = current_permission.id
WHERE current_permission.id = EXCLUDED.id
  AND current_permission.resource_type = EXCLUDED.resource_type
  AND current_permission.action = EXCLUDED.action
  AND current_permission.sensitivity = EXCLUDED.sensitivity
  AND current_permission.description = EXCLUDED.description
RETURNING 1
)
SELECT 1 / CASE WHEN (SELECT count(*) FROM applied) = (SELECT count(*) FROM seed) THEN 1 ELSE 0 END AS seed_content_match;
