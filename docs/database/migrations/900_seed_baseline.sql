-- =============================================================================
-- 900_seed_baseline.sql
-- 参考数据播种：安全 Profile、时长基线、数据分级、一致性等级、错误契约、
--              义务类型、敏感操作等级要求、基础权限目录
-- 依据：蓝图 §6、§15.3.1、§5.2、§16；能力地图 §4.6、§4.20
-- 幂等：全部使用 ON CONFLICT，可重复执行
-- 重要：本文件的数值来源于蓝图，实现方不得就地修改；调整必须先改蓝图并走 REQ-CTRL-002 审批
-- =============================================================================

SET client_min_messages = warning;

-- -----------------------------------------------------------------------------
-- 1. 数据分级（CAP-PRIV-005）与一致性等级（蓝图 §16）
-- -----------------------------------------------------------------------------
INSERT INTO core.data_classification (classification_code, display_name, handling_rule, may_appear_in_event, requires_encryption) VALUES
    ('PUBLIC',           '公开',     '可对外公开，无额外限制', true,  false),
    ('INTERNAL',         '内部',     '仅平台与授权业务可见，事件可携带最小必要字段', true,  false),
    ('SENSITIVE',        '敏感',     '需授权与审计，事件默认不携带，携带需字段白名单', false, true),
    ('STRICT_SENSITIVE', '严格敏感', '单独同意、加密存储、禁止进入事件与日志，访问逐次审计', false, true)
ON CONFLICT (classification_code) DO UPDATE
    SET display_name = EXCLUDED.display_name,
        handling_rule = EXCLUDED.handling_rule,
        may_appear_in_event = EXCLUDED.may_appear_in_event,
        requires_encryption = EXCLUDED.requires_encryption;

INSERT INTO core.consistency_level (level_code, display_name, semantics) VALUES
    ('C0', '强一致',     'Identifier、Authenticator、Grant、关键授权写入'),
    ('C1', '有界陈旧',   '冻结、撤销、高风险权限、安全 epoch，陈旧上界即适用的撤销 SLO'),
    ('C2', '最终一致',   'Profile、偏好、普通 Membership 副本'),
    ('C3', '可靠追加',   '审计、安全证据与事件 Outbox')
ON CONFLICT (level_code) DO UPDATE
    SET display_name = EXCLUDED.display_name, semantics = EXCLUDED.semantics;

-- -----------------------------------------------------------------------------
-- 2. 安全 Profile（蓝图 §6）
-- -----------------------------------------------------------------------------
INSERT INTO core.security_profile (profile_code, profile_version, display_name, applicability, min_requirement, revocation_slo_code) VALUES
    ('SP1', 'v1', '普通用户',   '普通登录和低风险读取',
     'Authorization Code + PKCE S256、Refresh Rotation、基础风控', 'SLO-REVOKE-002'),
    ('SP2', 'v1', '敏感操作',   '改密、换绑、导出、注销、授权',
     'AAL2、5 分钟内重新认证、实时风险和实时授权', 'SLO-REVOKE-001'),
    ('SP3', 'v1', '特权管理',   '管理员、密钥、策略、批量敏感操作',
     '抗钓鱼 MFA、短会话、审批或 JIT、强审计、可信管理端', 'SLO-REVOKE-001'),
    ('SP4', 'v1', '机器身份',   '服务间和工作负载',
     '私钥或 mTLS、明确 audience、Token 不超过 5 分钟、自动轮换', 'SLO-REVOKE-001'),
    ('SP5', 'v1', '高价值 API', '资金、核心资产、强监管',
     'FAPI 2.0、PAR、sender-constrained Token、严格 Client 认证', 'SLO-REVOKE-001')
ON CONFLICT (profile_code, profile_version) DO UPDATE
    SET display_name = EXCLUDED.display_name,
        applicability = EXCLUDED.applicability,
        min_requirement = EXCLUDED.min_requirement,
        revocation_slo_code = EXCLUDED.revocation_slo_code;

-- -----------------------------------------------------------------------------
-- 3. 时长基线（蓝图 §15.3.1）
-- max_duration / min_duration 为机器可判定值，供 CI 与配置扫描比对
-- -----------------------------------------------------------------------------
INSERT INTO core.duration_baseline (baseline_code, target_object, profile_code, baseline_text, max_duration, min_duration, max_attempts, source_reference) VALUES
    ('TTL-TOKEN-001',      '人类用户 Access Token 最大有效期', 'SP1', '≤ 15 分钟',                   interval '15 minutes', NULL, NULL, '蓝图 §15.3.1'),
    ('TTL-TOKEN-001',      '人类用户 Access Token 最大有效期', 'SP2', '≤ 5 分钟',                    interval '5 minutes',  NULL, NULL, '蓝图 §15.3.1'),
    ('TTL-TOKEN-001',      '人类用户 Access Token 最大有效期', 'SP3', '≤ 5 分钟',                    interval '5 minutes',  NULL, NULL, '蓝图 §15.3.1'),
    ('TTL-TOKEN-001',      '人类用户 Access Token 最大有效期', 'SP5', '≤ 2 分钟',                    interval '2 minutes',  NULL, NULL, '蓝图 §15.3.1'),
    ('TTL-TOKEN-002',      '机器主体 Access Token',            'SP4', '≤ 5 分钟',                    interval '5 minutes',  NULL, NULL, 'REQ-MACHINE-006'),
    ('TTL-TOKEN-003',      'Refresh Token 绝对期',             'SP1', '≤ 90 天，空闲期 ≤ 30 天',      interval '90 days',    NULL, NULL, '蓝图 §15.3.1'),
    ('TTL-TOKEN-003',      'Refresh Token 绝对期',             'SP2', '≤ 30 天',                     interval '30 days',    NULL, NULL, '蓝图 §15.3.1'),
    ('TTL-TOKEN-003',      'Refresh Token 绝对期',             'SP3', '≤ 1 天',                      interval '1 day',      NULL, NULL, '蓝图 §15.3.1'),
    ('TTL-TOKEN-003',      'Refresh Token 绝对期',             'SP5', '不得宽于 SP3 且必须发送方约束', interval '1 day',      NULL, NULL, '蓝图 §15.3.1'),
    ('TTL-TOKEN-003',      'Refresh Token 绝对期',             'SP4', '机器主体不签发 Refresh Token',  interval '0',          NULL, NULL, '蓝图 §15.3.1'),
    ('TTL-TOKEN-004',      'ID Token',                         '*',   '≤ 5 分钟，仅用于认证结果确认',  interval '5 minutes',  NULL, NULL, 'REQ-SESSION-003'),
    ('TTL-CODE-001',       '授权码',                           '*',   '≤ 60 秒且单次使用',            interval '60 seconds', NULL, NULL, 'REQ-AUTH-004'),
    ('TTL-SESSION-001',    'OP Session 绝对期',                '*',   '≤ 30 天，空闲期 ≤ 7 天',       interval '30 days',    NULL, NULL, '蓝图 §15.3.1'),
    ('TTL-SESSION-001',    'OP Session 绝对期',                'SP3', '≤ 12 小时，空闲期 ≤ 30 分钟',  interval '12 hours',   NULL, NULL, '蓝图 §15.3.1'),
    ('TTL-SESSION-001',    'OP Session 绝对期',                'SP5', '不得宽于 SP3',                interval '12 hours',   NULL, NULL, '蓝图 §15.3.1'),
    ('TTL-LOGINTX-001',    'Login Transaction',                '*',   '≤ 15 分钟，单次消费',          interval '15 minutes', NULL, NULL, 'INV-G-016'),
    ('TTL-CHALLENGE-001',  '短信/邮件验证码 Challenge',        '*',   '≤ 5 分钟，尝试 ≤ 5 次，间隔 ≥ 60 秒', interval '5 minutes', interval '60 seconds', 5, 'REQ-AUTH-013'),
    ('TTL-STEPUP-001',     '敏感操作最大认证年龄',              '*',   '≤ 5 分钟',                    interval '5 minutes',  NULL, NULL, '蓝图 §6 SP2'),
    ('TTL-JWKS-001',       'JWKS 缓存与双钥重叠窗口',           '*',   'max-age 登记；发布到签名 ≥ 2×max-age', NULL,        NULL, NULL, 'REQ-KEY-002'),
    ('TERM-DELETE-001',    '注销冷静期',                        '*',   '默认 15 自然日，不得短于 7 日', interval '15 days',    interval '7 days', NULL, 'CAP-ID-020'),
    ('TERM-REBIND-001',    '换绑与认证器替换后的保护期',        '*',   '≥ 24 小时',                   NULL, interval '24 hours', NULL, 'CAP-AUTH-016'),
    ('TERM-IDENTIFIER-001','手机号解绑隔离期',                  '*',   '≥ 90 天',                     NULL, interval '90 days', NULL, 'REQ-ID-006'),
    ('TERM-RECOVERY-001',  '高保证账号恢复等待期',              '*',   '24 至 72 小时，按风险取值',     interval '72 hours', interval '24 hours', NULL, 'CAP-ASR-005'),
    ('TERM-RECOVERY-002',  '恢复后观察期',                      '*',   '≥ 7 天',                      NULL, interval '7 days', NULL, 'CAP-ASR-007'),
    ('TERM-TENANT-001',    '租户所有权转移等待期',              '*',   '≥ 72 小时并通知原所有人',       NULL, interval '72 hours', NULL, 'REQ-TENANT-005'),
    ('TERM-DORMANT-001',   '转入 DORMANT 的未登录阈值',         '*',   '默认 18 个月',                 interval '18 months', NULL, NULL, 'CAP-ID-024'),
    ('TERM-EXCEPTION-001', '安全例外最长有效期',                '*',   '≤ 6 个月，到期默认收紧',       interval '6 months',  NULL, NULL, 'CAP-CTRL-006'),
    ('TERM-KEY-001',       '签名密钥常规轮换周期',              '*',   '≤ 90 天',                     interval '90 days',   NULL, NULL, 'REQ-KEY-002'),
    ('TERM-EXPORT-001',    '数据导出下载链接有效期',            '*',   '≤ 24 小时，过期销毁',          interval '24 hours',  NULL, NULL, 'REQ-PRIV-006')
ON CONFLICT (baseline_code, profile_code) DO UPDATE
    SET target_object = EXCLUDED.target_object,
        baseline_text = EXCLUDED.baseline_text,
        max_duration = EXCLUDED.max_duration,
        min_duration = EXCLUDED.min_duration,
        max_attempts = EXCLUDED.max_attempts,
        source_reference = EXCLUDED.source_reference;

-- -----------------------------------------------------------------------------
-- 4. 统一错误契约（蓝图 §5.2、CAP-API-004）
-- 错误码一经发布不得改变语义，只能标记 deprecated_at
-- -----------------------------------------------------------------------------
INSERT INTO core.error_code (domain_code, http_status, meaning, client_action, retryable) VALUES
    ('INVALID_REQUEST',           400, '格式或参数错误',            '修正后新请求',          false),
    ('AUTHENTICATION_REQUIRED',   401, '无有效认证',                '重新认证',              false),
    ('ACCESS_DENIED',             403, '已认证但无权',              '不自动重试',            false),
    ('STEP_UP_REQUIRED',          403, '需要升级认证',              '按目标 acr 重新认证',   false),
    ('IDENTITY_ALREADY_BOUND',    409, '唯一身份已被占用',          '进入冲突流程',          false),
    ('IDEMPOTENCY_KEY_REUSED',    409, '同键请求体不同',            '使用新键',              false),
    ('VERSION_MISMATCH',          412, '乐观锁冲突',                '重新读取后决策',        false),
    ('INVALID_STATE_TRANSITION',  422, '当前状态不允许操作',        '修正业务流程',          false),
    ('MERGE_CONFLICT',            422, '账号合并冲突',              '人工处置',              false),
    ('SUBJECT_FROZEN',            423, '主体被冻结',                '不重试，进入处置',      false),
    ('RATE_LIMITED',              429, '超出频率或配额',            '按 Retry-After 重试',   true),
    ('DEPENDENCY_UNAVAILABLE',    503, '依赖暂不可用',              '仅幂等重试',            true),
    ('AUTHZ_UNAVAILABLE',         503, '授权结论不可确定',          '高风险操作失败关闭',    true)
ON CONFLICT (domain_code) DO UPDATE
    SET http_status = EXCLUDED.http_status,
        meaning = EXCLUDED.meaning,
        client_action = EXCLUDED.client_action,
        retryable = EXCLUDED.retryable;

-- -----------------------------------------------------------------------------
-- 5. 义务类型（REQ-AUTHZ-014）
-- -----------------------------------------------------------------------------
INSERT INTO authz.obligation_type (obligation_code, schema_version, display_name, params_schema, enforcement_point, is_mandatory) VALUES
    ('STEP_UP',        1, '要求升级认证', '{"type":"object","required":["target_acr","max_auth_age_seconds"]}'::jsonb, 'PRE_HANDLER',  true),
    ('MASK_FIELDS',    1, '字段脱敏',     '{"type":"object","required":["fields","mask_style"]}'::jsonb,               'RESPONSE',     true),
    ('ROW_FILTER',     1, '行级过滤',     '{"type":"object","required":["predicate"]}'::jsonb,                         'DATA_ACCESS',  true),
    ('WATERMARK',      1, '水印',         '{"type":"object","required":["watermark_text"]}'::jsonb,                     'RESPONSE',     true),
    ('EXTRA_AUDIT',    1, '附加审计',     '{"type":"object","required":["audit_category","fields"]}'::jsonb,            'POST_COMMIT',  true)
ON CONFLICT (obligation_code, schema_version) DO UPDATE
    SET display_name = EXCLUDED.display_name,
        params_schema = EXCLUDED.params_schema,
        enforcement_point = EXCLUDED.enforcement_point,
        is_mandatory = EXCLUDED.is_mandatory;

-- -----------------------------------------------------------------------------
-- 6. 敏感操作等级要求（CAP-ASR-003、蓝图 §6）
-- -----------------------------------------------------------------------------
INSERT INTO asr.sensitive_operation_requirement
    (operation_code, display_name, profile_code, min_ial, min_aal, max_auth_age_seconds, forbidden_amr, max_risk_level,
     requires_step_up, requires_approval, requires_waiting_period, requires_phishing_resistant) VALUES
    ('PASSWORD_CHANGE',        '修改密码',            'SP2', 'IAL1', 'AAL2', 300, '{}',              'MEDIUM', true,  false, false, false),
    ('IDENTIFIER_REBIND',      '换绑手机或邮箱',      'SP2', 'IAL1', 'AAL2', 300, '{sms}',           'MEDIUM', true,  false, false, false),
    ('AUTHENTICATOR_REMOVE',   '移除认证器',          'SP2', 'IAL1', 'AAL2', 300, '{sms}',           'LOW',    true,  false, false, false),
    ('RECOVERY_CHANNEL_CHANGE','修改恢复渠道',        'SP2', 'IAL1', 'AAL2', 300, '{sms}',           'LOW',    true,  false, true,  false),
    ('DATA_EXPORT',            '数据导出',            'SP2', 'IAL1', 'AAL2', 300, '{}',              'MEDIUM', true,  false, false, false),
    ('ACCOUNT_DELETE',         '账号注销',            'SP2', 'IAL1', 'AAL2', 300, '{}',              'LOW',    true,  false, true,  false),
    ('ACCOUNT_MERGE',          '账号合并',            'SP2', 'IAL2', 'AAL2', 300, '{sms}',           'LOW',    true,  true,  false, false),
    ('CONSENT_GRANT',          '授权同意',            'SP2', 'IAL1', 'AAL2', 300, '{}',              'MEDIUM', true,  false, false, false),
    ('ADMIN_LOGIN',            '管理后台登录',        'SP3', 'IAL1', 'AAL3', 300, '{sms,otp}',       'LOW',    true,  false, false, true),
    ('ADMIN_MFA_RESET',        '重置管理员 MFA',      'SP3', 'IAL2', 'AAL3', 300, '{sms,otp}',       'LOW',    true,  true,  true,  true),
    ('KEY_ROTATION',           '密钥轮换',            'SP3', 'IAL1', 'AAL3', 300, '{sms,otp}',       'LOW',    true,  true,  false, true),
    ('HIGH_RISK_CONFIG',       '高风险配置变更',      'SP3', 'IAL1', 'AAL3', 300, '{sms,otp}',       'LOW',    true,  true,  false, true),
    ('BULK_SENSITIVE_READ',    '批量敏感数据读取',    'SP3', 'IAL1', 'AAL3', 300, '{sms,otp}',       'LOW',    true,  true,  false, true),
    ('TENANT_OWNERSHIP_TRANSFER','租户所有权转移',    'SP3', 'IAL2', 'AAL3', 300, '{sms,otp}',       'LOW',    true,  true,  true,  true),
    ('FUND_OPERATION',         '资金类操作',          'SP5', 'IAL2', 'AAL3', 120, '{sms,otp}',       'LOW',    true,  false, false, true)
ON CONFLICT (operation_code) DO UPDATE
    SET display_name = EXCLUDED.display_name,
        profile_code = EXCLUDED.profile_code,
        min_ial = EXCLUDED.min_ial,
        min_aal = EXCLUDED.min_aal,
        max_auth_age_seconds = EXCLUDED.max_auth_age_seconds,
        forbidden_amr = EXCLUDED.forbidden_amr,
        max_risk_level = EXCLUDED.max_risk_level,
        requires_step_up = EXCLUDED.requires_step_up,
        requires_approval = EXCLUDED.requires_approval,
        requires_waiting_period = EXCLUDED.requires_waiting_period,
        requires_phishing_resistant = EXCLUDED.requires_phishing_resistant;

-- -----------------------------------------------------------------------------
-- 7. 基础权限目录（CAP-AUTHZ-001，阶段 1a 最小集）
-- -----------------------------------------------------------------------------
INSERT INTO authz.permission (permission_code, resource_type, action_code, display_name, is_high_risk, requires_realtime_decision, min_profile_code, data_classification) VALUES
    ('user.read',              'USER',            'READ',       '查询用户基本信息',   false, false, 'SP1', 'INTERNAL'),
    ('user.read_sensitive',     'USER',            'READ_SENSITIVE', '查看用户敏感字段', true,  true,  'SP3', 'SENSITIVE'),
    ('user.lifecycle_manage',   'USER',            'MANAGE',     '用户状态处置',       true,  true,  'SP3', 'SENSITIVE'),
    ('user.session_revoke',     'SESSION',         'REVOKE',     '撤销会话与 Token',   true,  true,  'SP3', 'INTERNAL'),
    ('user.credential_reset',   'CREDENTIAL',      'RESET',      '重置凭证与 MFA',     true,  true,  'SP3', 'STRICT_SENSITIVE'),
    ('membership.manage',       'MEMBERSHIP',      'MANAGE',     '成员关系管理',       false, false, 'SP2', 'INTERNAL'),
    ('tenant.manage',           'TENANT',          'MANAGE',     '租户配置管理',       false, false, 'SP2', 'INTERNAL'),
    ('client.manage',           'CLIENT',          'MANAGE',     'Client 接入配置',    true,  true,  'SP3', 'INTERNAL'),
    ('policy.manage',           'AUTHZ_POLICY',    'MANAGE',     '授权策略管理',       true,  true,  'SP3', 'INTERNAL'),
    ('key.manage',              'KEY_ASSET',       'MANAGE',     '密钥台账管理',       true,  true,  'SP3', 'STRICT_SENSITIVE'),
    ('privacy.request_handle',  'PRIVACY_REQUEST', 'HANDLE',     '隐私请求处理',       true,  true,  'SP3', 'SENSITIVE'),
    ('audit.read',              'AUDIT_EVENT',     'READ',       '审计查询',           false, false, 'SP3', 'SENSITIVE'),
    ('risk.case_handle',        'RISK_CASE',       'HANDLE',     '风险案件处置',       true,  true,  'SP3', 'SENSITIVE'),
    ('machine.manage',          'MACHINE_PRINCIPAL','MANAGE',    '机器身份管理',       true,  true,  'SP3', 'INTERNAL')
ON CONFLICT (permission_code) DO UPDATE
    SET resource_type = EXCLUDED.resource_type,
        action_code = EXCLUDED.action_code,
        display_name = EXCLUDED.display_name,
        is_high_risk = EXCLUDED.is_high_risk,
        requires_realtime_decision = EXCLUDED.requires_realtime_decision,
        min_profile_code = EXCLUDED.min_profile_code,
        data_classification = EXCLUDED.data_classification;

SELECT core.fn_migration_apply('900', 'seed_baseline：安全 Profile、时长基线、数据分级、错误契约、义务类型、敏感操作要求、基础权限目录');
