-- =============================================================================
-- baseline/schemas/core/seed.sql
-- core Schema 的幂等基线种子
-- PostgreSQL 16+；应用技术栈：.NET 10 + SqlSugar
-- =============================================================================

\set ON_ERROR_STOP on

SELECT (NOT EXISTS (SELECT 1 FROM core.schema_migration WHERE version = 'baseline:core:seed'))::text AS kuc_run_seed \gset
\if :kuc_run_seed
BEGIN;
SET LOCAL lock_timeout = '10s';
SET LOCAL statement_timeout = '10min';

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
('CONTEXT_SCOPE_MISMATCH', 'DOMAIN_API', 403, NULL, false, true, 'Tenant、Organization、Client 或资源范围不一致；不泄漏目标是否存在'),
('DECISION_STALE', 'DOMAIN_API', 409, NULL, false, true, '授权、风险或审批依据已过期，必须重新评估，不能原样重试旧决定'),
('IDENTIFIER_ALREADY_BOUND', 'DOMAIN_API', 409, NULL, false, true, '标识已在目标唯一范围内绑定'),
('ACTIVE_GRANT_EXISTS', 'DOMAIN_API', 409, NULL, false, true, '相同主体、Client 和 Tenant 已存在有效 Grant'),
('SESSION_CONTEXT_MISMATCH', 'DOMAIN_API', 409, NULL, false, true, 'Session 与登录事务、主体、Client、Tenant、设备或 epoch 上下文不一致'),
('GRANT_CONTEXT_MISMATCH', 'DOMAIN_API', 409, NULL, false, true, 'Grant 与主体、Client、Tenant、范围、Consent 或登录事务上下文不一致'),
('AUTHORIZATION_CODE_CONTEXT_MISMATCH', 'DOMAIN_API', 409, NULL, false, true, 'Authorization Code 与 Grant、登录事务或 Session 上下文不一致'),
('TOKEN_FAMILY_CONTEXT_MISMATCH', 'DOMAIN_API', 409, NULL, false, true, 'Token Family 与 Grant、主体、Client、Tenant、Session 或 epoch 上下文不一致'),
('REFERENCE_TOKEN_CONTEXT_MISMATCH', 'DOMAIN_API', 409, NULL, false, true, 'Reference Token 的范围、依据对象、期限或 epoch 上下文不一致'),
('CHALLENGE_CONTEXT_MISMATCH', 'DOMAIN_API', 409, NULL, false, true, 'Challenge 与用途、目标、Client、事务或风险上下文不一致'),
('CHALLENGE_ALREADY_CONSUMED', 'DOMAIN_API', 409, NULL, false, true, 'Challenge 已被消费或不再可用'),
('DEVICE_AUTHORIZATION_CONTEXT_MISMATCH', 'DOMAIN_API', 409, NULL, false, true, 'Device Authorization 与 Client、Tenant、Profile 或授权能力不一致'),
('INVITATION_CONTEXT_MISMATCH', 'DOMAIN_API', 409, NULL, false, true, 'Invitation 与目标主体、Tenant、Organization、Role 或授权依据不一致'),
('INVITATION_ALREADY_ACCEPTED', 'DOMAIN_API', 409, NULL, false, true, 'Invitation 已被接受或不再可消费'),
('ROLE_ASSIGNMENT_CONTEXT_MISMATCH', 'DOMAIN_API', 409, NULL, false, true, 'Role Assignment 与主体、Tenant、Organization、角色范围或职责分离规则不一致'),
('CONSENT_CONTEXT_MISMATCH', 'DOMAIN_API', 409, NULL, false, true, 'Consent 与主体、用途、类别、接收方、来源或聚合版本不一致'),
('CONSENT_NOT_EFFECTIVE', 'DOMAIN_API', 403, NULL, false, true, 'Consent 未授权、已过期或已被更新版本取代'),
('APPROVAL_CONTEXT_MISMATCH', 'DOMAIN_API', 409, NULL, false, true, '审批与 Tenant、资源、版本、摘要或风险快照不一致'),
('APPROVAL_BINDING_INVALID', 'DOMAIN_API', 409, NULL, false, true, '资源激活绑定的审批未执行、已失效、已使用或上下文不一致'),
('APPROVAL_NOT_EXECUTABLE', 'DOMAIN_API', 409, NULL, false, true, '审批未满足人数、职责分离、有效期或当前状态要求'),
('RESOURCE_ACTIVATION_CONTEXT_MISMATCH', 'DOMAIN_API', 409, NULL, false, true, 'Client、Identity Provider 或受控资源的配置、凭证、环境或审批上下文不一致'),
('DELEGATION_SCOPE_EXPANSION', 'DOMAIN_API', 409, NULL, false, true, '委托相对父委托或当前主体权限发生范围扩张'),
('MACHINE_CREDENTIAL_CONTEXT_MISMATCH', 'DOMAIN_API', 409, NULL, false, true, '机器凭证与 Machine、环境、材料类型、Key/Certificate 或轮换链不一致'),
('ATTESTATION_CONTEXT_MISMATCH', 'DOMAIN_API', 409, NULL, false, true, '工作负载证明与 Machine、Trust Bundle、环境、受众、选择器或时效不一致'),
('KEY_RELEASE_CONTEXT_MISMATCH', 'DOMAIN_API', 409, NULL, false, true, 'Key、Certificate 或 JWKS 的用途、算法、环境、有效期或传播窗口不一致'),
('EMERGENCY_ACCESS_CONTEXT_MISMATCH', 'DOMAIN_API', 409, NULL, false, true, '安全例外或 Break-glass 与审批、主体、权限、风险或期限上下文不一致'),
('MESSAGE_TEMPLATE_OR_ROUTE_INVALID', 'DOMAIN_API', 409, NULL, false, true, '消息模板或路由未激活，或其通道、用途与发送命令不一致'),
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

SELECT core.fn_register_migration('baseline:core:seed', 'core Schema 基线种子');
COMMIT;
\endif

