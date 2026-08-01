-- =============================================================================
-- 900_seed.sql
-- 仅含跨环境稳定的安全 Profile、时长、分类、错误、义务和基础权限种子
-- =============================================================================

BEGIN;

-- 全零 UUID 是显式的平台范围，不是“无租户”；所有直接 tenant_id 外键均可校验。
INSERT INTO org.business_line(
    id, public_id, business_line_code, display_name, business_line_state,
    owner_ref, data_residency_region
)
SELECT
    '00000000-0000-0000-0000-000000000000', 'biz_0000000000000000',
    'platform', '平台控制面', 'PROVISIONING', 'platform-security', 'CN'
WHERE NOT EXISTS (
    SELECT 1 FROM org.business_line WHERE id = '00000000-0000-0000-0000-000000000000'
);

UPDATE org.business_line
   SET business_line_state = 'ACTIVE', activated_at = COALESCE(activated_at, clock_timestamp())
 WHERE id = '00000000-0000-0000-0000-000000000000'
   AND business_line_state = 'PROVISIONING';

INSERT INTO org.tenant(
    id, public_id, business_line_id, tenant_code, display_name, tenant_state,
    tenant_type, data_residency_region, tenant_security_epoch
)
SELECT
    '00000000-0000-0000-0000-000000000000', 'ten_0000000000000000',
    '00000000-0000-0000-0000-000000000000', 'platform', '平台范围', 'PROVISIONING',
    'PLATFORM', 'CN', 1
WHERE NOT EXISTS (
    SELECT 1 FROM org.tenant WHERE id = '00000000-0000-0000-0000-000000000000'
);

UPDATE org.tenant
   SET tenant_state = 'ACTIVE'
 WHERE id = '00000000-0000-0000-0000-000000000000'
   AND tenant_state = 'PROVISIONING';

INSERT INTO core.data_classification(classification_code, display_name, sensitivity_rank, handling_rules) VALUES
('C0', '公开', 0, '{"encryption":"transport","logging":"allowed","export":"allowed"}'),
('C1', '内部', 2, '{"encryption":"at_rest","logging":"minimized","export":"controlled"}'),
('C2', '敏感', 5, '{"encryption":"field_level","logging":"masked","export":"strong_auth"}'),
('C3', '高度敏感/凭证', 8, '{"encryption":"kms_hsm","logging":"forbidden","export":"forbidden_by_default"}')
ON CONFLICT (classification_code) DO NOTHING;

INSERT INTO core.security_profile(profile_code, profile_version, display_name, applicability, minimum_controls, effective_at) VALUES
('SP1', 1, '普通 Web/移动应用', '低至普通风险人类用户应用', '{"pkce":"S256","redirect_uri":"exact","access_token_max_seconds":900,"refresh_rotation":true}', '2026-01-01T00:00:00Z'),
('SP1-D', 1, '输入受限设备', '仅 RFC 8628 Device Authorization Grant', '{"device_grant":true,"poll_min_seconds":5,"user_confirmation":true,"client_secret":false}', '2026-01-01T00:00:00Z'),
('SP2', 1, '敏感业务', '支付、隐私、资料安全变更等', '{"aal":"AAL2","step_up_max_age_seconds":300,"access_token_max_seconds":300,"fail_closed":true}', '2026-01-01T00:00:00Z'),
('SP3', 1, '特权管理', '管理员、策略、密钥和批量敏感操作', '{"aal":"AAL3","phishing_resistant":true,"approval":true,"session_idle_seconds":1800,"fail_closed":true}', '2026-01-01T00:00:00Z'),
('SP4', 1, '机器主体', 'Client Credentials、工作负载联合与 Token Exchange', '{"access_token_max_seconds":300,"refresh_token":false,"sender_constrained_preferred":true}', '2026-01-01T00:00:00Z'),
('SP5', 1, '高价值受监管', '最高风险、受监管或高价值业务', '{"aal":"AAL3","sender_constrained":true,"access_token_max_seconds":120,"fail_closed":true,"approval":true}', '2026-01-01T00:00:00Z')
ON CONFLICT (profile_code, profile_version) DO NOTHING;

INSERT INTO core.duration_policy(policy_code, profile_code, duration_seconds, max_attempts, description, effective_at) VALUES
('TTL-TOKEN-001', 'SP1', 900, NULL, '人类用户 Access Token 最大 15 分钟', '2026-01-01T00:00:00Z'),
('TTL-TOKEN-001', 'SP2', 300, NULL, '敏感业务 Access Token 最大 5 分钟', '2026-01-01T00:00:00Z'),
('TTL-TOKEN-001', 'SP3', 300, NULL, '特权管理 Access Token 最大 5 分钟', '2026-01-01T00:00:00Z'),
('TTL-TOKEN-001', 'SP5', 120, NULL, '高价值业务 Access Token 最大 2 分钟', '2026-01-01T00:00:00Z'),
('TTL-TOKEN-002', 'SP4', 300, NULL, '机器主体 Access Token 最大 5 分钟', '2026-01-01T00:00:00Z'),
('TTL-CODE-001', 'SP1', 60, 1, '授权码最大 60 秒且单次使用', '2026-01-01T00:00:00Z'),
('TTL-LOGINTX-001', 'SP1', 900, 1, 'Login Transaction 最大 15 分钟且单次消费', '2026-01-01T00:00:00Z'),
('TTL-CHALLENGE-001', 'SP1', 300, 5, '短信/邮件 Challenge 最大 5 分钟、最多 5 次', '2026-01-01T00:00:00Z'),
('TTL-STEPUP-001', 'SP2', 300, NULL, '敏感操作最大认证年龄 5 分钟', '2026-01-01T00:00:00Z'),
('TERM-DELETE-001', 'SP1', 1296000, NULL, '注销冷静期默认 15 日', '2026-01-01T00:00:00Z'),
('TERM-REBIND-001', 'SP2', 86400, NULL, '换绑与认证器替换保护期至少 24 小时', '2026-01-01T00:00:00Z'),
('TERM-RECOVERY-001', 'SP2', 86400, NULL, '高保证恢复最短等待 24 小时', '2026-01-01T00:00:00Z'),
('TERM-RECOVERY-002', 'SP2', 604800, NULL, '恢复观察期至少 7 日', '2026-01-01T00:00:00Z'),
('TERM-EXPORT-001', 'SP2', 86400, 1, '数据导出链接最大 24 小时且默认单次下载', '2026-01-01T00:00:00Z')
ON CONFLICT (policy_code, profile_code, effective_at) DO NOTHING;

INSERT INTO core.error_registry(error_code, contract_kind, http_status, protocol_error, retryable, user_visible, description) VALUES
('ACCESS_DENIED', 'DOMAIN_API', 403, NULL, false, true, '无权访问；跨租户时不泄漏资源是否存在'),
('SUBJECT_FROZEN', 'DOMAIN_API', 403, NULL, false, true, '主体被冻结'),
('SUBJECT_LOCKED', 'DOMAIN_API', 423, NULL, true, true, '主体认证被锁定'),
('INVALID_STATE_TRANSITION', 'DOMAIN_API', 409, NULL, false, true, '非法状态转换'),
('IDEMPOTENCY_CONFLICT', 'DOMAIN_API', 409, NULL, false, true, '同一幂等键对应不同请求摘要'),
('OPTIMISTIC_LOCK_CONFLICT', 'DOMAIN_API', 409, NULL, true, true, '资源版本已变化'),
('CONSENT_REQUIRED', 'OAUTH', 400, 'consent_required', false, true, '授权需要完成明确 Consent'),
('CONSENT_EPOCH_STALE', 'DOMAIN_API', 403, NULL, true, false, 'Consent 水位过期'),
('AUTHORIZATION_PENDING', 'OAUTH', 400, 'authorization_pending', true, true, 'Device Authorization 尚未完成'),
('SLOW_DOWN', 'OAUTH', 400, 'slow_down', true, true, 'Device Authorization 轮询过快'),
('ACCESS_DENIED_OAUTH', 'OAUTH', 400, 'access_denied', false, true, '资源所有者拒绝授权'),
('EXPIRED_TOKEN', 'OAUTH', 400, 'expired_token', false, true, 'Device Code 已过期'),
('INVALID_GRANT', 'OAUTH', 400, 'invalid_grant', false, true, '授权码、Refresh Token 或 Grant 无效'),
('INVALID_CLIENT', 'OAUTH', 401, 'invalid_client', false, true, 'Client 身份或状态无效'),
('TEMPORARILY_UNAVAILABLE', 'OAUTH', 503, 'temporarily_unavailable', true, true, '依赖暂时不可用')
ON CONFLICT (error_code) DO UPDATE SET contract_kind = EXCLUDED.contract_kind, http_status = EXCLUDED.http_status, protocol_error = EXCLUDED.protocol_error, retryable = EXCLUDED.retryable, user_visible = EXCLUDED.user_visible, description = EXCLUDED.description;

INSERT INTO authz.obligation_type(obligation_code, schema_version, display_name, parameter_schema, execution_point, is_mandatory) VALUES
('STEP_UP', 1, '提升认证保证等级', '{"type":"object","required":["required_aal","max_auth_age_seconds"]}', 'BEFORE_COMMIT', true),
('MASK_FIELDS', 1, '字段脱敏', '{"type":"object","required":["field_codes","masking_profile"]}', 'RESPONSE_TRANSFORM', true),
('ROW_FILTER', 1, '行级过滤', '{"type":"object","required":["filter_expression"]}', 'QUERY_FILTER', true),
('WATERMARK', 1, '导出水印', '{"type":"object","required":["watermark_text"]}', 'RESPONSE_TRANSFORM', true),
('ADDITIONAL_AUDIT', 1, '附加审计', '{"type":"object","required":["audit_type"]}', 'AFTER_COMMIT', true)
ON CONFLICT (obligation_code, schema_version) DO UPDATE SET display_name = EXCLUDED.display_name, parameter_schema = EXCLUDED.parameter_schema, execution_point = EXCLUDED.execution_point, is_mandatory = EXCLUDED.is_mandatory;

INSERT INTO authz.permission(permission_code, resource_type, action_code, risk_tier, required_profile_code, description) VALUES
('identity.user.read', 'USER', 'READ', 'NORMAL', 'SP1', '读取最小用户主档'),
('identity.user.freeze', 'USER', 'FREEZE', 'CRITICAL', 'SP3', '全局冻结用户'),
('identity.user.merge', 'USER', 'MERGE', 'CRITICAL', 'SP3', '执行账号合并'),
('identity.user.delete', 'USER', 'DELETE', 'CRITICAL', 'SP2', '发起或执行账号删除'),
('tenant.membership.manage', 'MEMBERSHIP', 'MANAGE', 'HIGH', 'SP2', '管理租户 Membership'),
('tenant.invitation.create', 'INVITATION', 'CREATE', 'HIGH', 'SP2', '创建租户邀请'),
('tenant.invitation.accept', 'INVITATION', 'ACCEPT', 'HIGH', 'SP2', '接受租户邀请并创建或激活成员关系'),
('authz.policy.publish', 'POLICY', 'PUBLISH', 'CRITICAL', 'SP3', '发布授权策略'),
('control.approval.decide', 'APPROVAL_CASE', 'DECIDE', 'CRITICAL', 'SP3', '审批高风险变更'),
('crypto.key.rotate', 'KEY', 'ROTATE', 'CRITICAL', 'SP3', '轮换密钥'),
('audit.event.query', 'AUDIT', 'QUERY', 'HIGH', 'SP3', '查询审计事件'),
('privacy.request.process', 'PRIVACY_REQUEST', 'PROCESS', 'HIGH', 'SP2', '处理个人权利请求'),
('integration.event.replay', 'EVENT', 'REPLAY', 'CRITICAL', 'SP3', '审批并执行事件回放')
ON CONFLICT (permission_code) DO UPDATE SET resource_type = EXCLUDED.resource_type, action_code = EXCLUDED.action_code, risk_tier = EXCLUDED.risk_tier, required_profile_code = EXCLUDED.required_profile_code, description = EXCLUDED.description;

-- 能力地图/蓝图中的 218 个 REQ/API/EVT/INV 标识全部进入机器可解析追踪矩阵。
WITH domain_series(prefix, max_no, capability_id, owner_code, phase_code) AS (
    VALUES
        ('API-G', 19, 'CAP-API-001', 'platform-api', 'PHASE-0'),
        ('EVT-G', 13, 'CAP-EVENT-001', 'event-platform', 'PHASE-0'),
        ('INV-G', 18, 'CAP-CTRL-001', 'platform-governance', 'PHASE-0'),
        ('REQ-ASR', 5, 'CAP-ASR-001', 'assurance', 'PHASE-2'),
        ('REQ-AUTH', 18, 'CAP-AUTH-001', 'authentication', 'PHASE-1A'),
        ('REQ-AUTHZ', 16, 'CAP-AUTHZ-001', 'authorization', 'PHASE-1B'),
        ('REQ-CTRL', 7, 'CAP-CTRL-001', 'platform-governance', 'PHASE-0'),
        ('REQ-FED', 8, 'CAP-FED-001', 'federation', 'PHASE-2'),
        ('REQ-ID', 16, 'CAP-ID-001', 'identity', 'PHASE-1A'),
        ('REQ-KEY', 9, 'CAP-KEY-001', 'key-management', 'PHASE-0'),
        ('REQ-MACHINE', 18, 'CAP-MACHINE-001', 'workload-identity', 'PHASE-2'),
        ('REQ-MIG', 10, 'CAP-PLT-007', 'migration', 'PHASE-0'),
        ('REQ-OAP', 6, 'CAP-OAP-001', 'oauth-platform', 'PHASE-1A'),
        ('REQ-PRIV', 14, 'CAP-PRIV-001', 'privacy', 'PHASE-1B'),
        ('REQ-RISK', 9, 'CAP-RISK-001', 'risk', 'PHASE-2'),
        ('REQ-SESSION', 18, 'CAP-SESSION-001', 'session-token', 'PHASE-1A'),
        ('REQ-TENANT', 11, 'CAP-TENANT-001', 'tenant-platform', 'PHASE-1B')
), generated AS (
    SELECT prefix || '-' || lpad(n::text, 3, '0') AS requirement_id,
           capability_id, owner_code, phase_code
      FROM domain_series
      CROSS JOIN LATERAL generate_series(1, max_no) AS n
), exceptional(requirement_id, capability_id, owner_code, phase_code) AS (
    VALUES
        ('API-AUTH-001', 'CAP-API-001', 'authentication', 'PHASE-1A'),
        ('EVT-USER-001', 'CAP-EVENT-001', 'identity', 'PHASE-1A'),
        ('INV-SESSION-001', 'CAP-SESSION-001', 'session-token', 'PHASE-1A')
), trace_source AS (
    SELECT * FROM generated
    UNION ALL
    SELECT * FROM exceptional
)
INSERT INTO core.requirement_trace(
    requirement_id, capability_id, owner_code, profile_codes, phase_code,
    invariant_ids, api_event_ids, test_ids, slo_ids
)
SELECT requirement_id,
       capability_id,
       owner_code,
       '{}'::text[],
       phase_code,
       CASE WHEN requirement_id LIKE 'INV-%' THEN ARRAY[requirement_id] ELSE '{}'::text[] END,
       CASE WHEN requirement_id LIKE 'API-%' OR requirement_id LIKE 'EVT-%' THEN ARRAY[requirement_id] ELSE '{}'::text[] END,
       ARRAY['TEST-' || requirement_id],
       '{}'::text[]
  FROM trace_source
ON CONFLICT (requirement_id, capability_id, phase_code) DO NOTHING;

SELECT core.fn_register_migration('900', '平台范围租户、安全目录、权限与 218 条需求追踪种子', NULLIF(current_setting('kuc.migration_sha256', true), ''));
COMMIT;
