\set ON_ERROR_STOP on

SET ROLE iam_owner;

WITH seed(id, template_code, channel, locale, subject_template, content_template, variable_schema) AS (
    VALUES
        ('40000000-0000-0000-0000-000000000001'::uuid, 'LOGIN_OTP', 'SMS', 'zh-CN', NULL::text, '验证码：{{code}}，{{expires_minutes}} 分钟内有效。请勿向他人透露。', '{"type":"object","properties":{"code":{"type":"string","minLength":4,"maxLength":12},"expires_minutes":{"type":"integer","minimum":1,"maximum":5}},"required":["code","expires_minutes"],"additionalProperties":false}'::jsonb),
        ('40000000-0000-0000-0000-000000000002'::uuid, 'SECURITY_ALERT', 'EMAIL', 'zh-CN', '账号安全提醒', '检测到账号安全事件：{{event_name}}。如非本人操作，请立即进入安全中心。', '{"type":"object","properties":{"event_name":{"type":"string","minLength":1,"maxLength":120}},"required":["event_name"],"additionalProperties":false}'::jsonb),
        ('40000000-0000-0000-0000-000000000003'::uuid, 'AUTHENTICATOR_CHANGED', 'EMAIL', 'zh-CN', '认证方式已变更', '你的认证方式已于 {{changed_at}} 发生变更。如非本人操作，请立即冻结账号。', '{"type":"object","properties":{"changed_at":{"type":"string","format":"date-time"}},"required":["changed_at"],"additionalProperties":false}'::jsonb),
        ('40000000-0000-0000-0000-000000000004'::uuid, 'PASSWORD_CHANGED', 'SMS', 'zh-CN', NULL::text, '你的账号密码已变更。如非本人操作，请立即冻结账号。', '{"type":"object","properties":{},"additionalProperties":false}'::jsonb),
        ('40000000-0000-0000-0000-000000000005'::uuid, 'NEW_DEVICE_LOGIN', 'EMAIL', 'zh-CN', '新设备登录提醒', '检测到新设备 {{device_name}} 于 {{occurred_at}} 登录。如非本人操作，请立即冻结账号。', '{"type":"object","properties":{"device_name":{"type":"string","minLength":1,"maxLength":160},"occurred_at":{"type":"string","format":"date-time"}},"required":["device_name","occurred_at"],"additionalProperties":false}'::jsonb),
        ('40000000-0000-0000-0000-000000000006'::uuid, 'IDENTIFIER_CHANGED', 'EMAIL', 'zh-CN', '联系方式已变更', '你的{{identifier_type}}已于 {{changed_at}} 发生变更。如非本人操作，请立即冻结账号。', '{"type":"object","properties":{"identifier_type":{"type":"string","enum":["手机号","邮箱"]},"changed_at":{"type":"string","format":"date-time"}},"required":["identifier_type","changed_at"],"additionalProperties":false}'::jsonb),
        ('40000000-0000-0000-0000-000000000007'::uuid, 'ACCOUNT_RECOVERY_STARTED', 'EMAIL', 'zh-CN', '账号恢复已开始', '账号恢复请求已于 {{requested_at}} 提交，预计等待 {{wait_hours}} 小时。', '{"type":"object","properties":{"requested_at":{"type":"string","format":"date-time"},"wait_hours":{"type":"integer","minimum":24,"maximum":72}},"required":["requested_at","wait_hours"],"additionalProperties":false}'::jsonb),
        ('40000000-0000-0000-0000-000000000008'::uuid, 'ACCOUNT_RECOVERY_COMPLETED', 'EMAIL', 'zh-CN', '账号恢复已完成', '账号恢复已于 {{completed_at}} 完成，请检查认证方式和登录设备。', '{"type":"object","properties":{"completed_at":{"type":"string","format":"date-time"}},"required":["completed_at"],"additionalProperties":false}'::jsonb),
        ('40000000-0000-0000-0000-000000000009'::uuid, 'HIGH_RISK_LOGIN', 'SMS', 'zh-CN', NULL::text, '检测到高风险登录（{{occurred_at}}）。{{action_required}}', '{"type":"object","properties":{"occurred_at":{"type":"string","format":"date-time"},"action_required":{"type":"string","minLength":1,"maxLength":160}},"required":["occurred_at","action_required"],"additionalProperties":false}'::jsonb),
        ('40000000-0000-0000-0000-000000000010'::uuid, 'ACCOUNT_FROZEN', 'EMAIL', 'zh-CN', '账号已冻结', '账号已于 {{frozen_at}} 冻结，原因码：{{reason_code}}。', '{"type":"object","properties":{"frozen_at":{"type":"string","format":"date-time"},"reason_code":{"type":"string","minLength":1,"maxLength":100}},"required":["frozen_at","reason_code"],"additionalProperties":false}'::jsonb),
        ('40000000-0000-0000-0000-000000000011'::uuid, 'ACCOUNT_DELETION_REQUESTED', 'EMAIL', 'zh-CN', '账号注销申请已受理', '注销申请已受理，计划于 {{effective_date}} 执行。冷静期内可按产品流程撤销申请。', '{"type":"object","properties":{"effective_date":{"type":"string","format":"date-time"}},"required":["effective_date"],"additionalProperties":false}'::jsonb),
        ('40000000-0000-0000-0000-000000000012'::uuid, 'DATA_EXPORT_READY', 'EMAIL', 'zh-CN', '个人数据导出已就绪', '个人数据导出已就绪，下载入口将在 {{expires_at}} 失效。访问前需要重新完成强认证。', '{"type":"object","properties":{"expires_at":{"type":"string","format":"date-time"}},"required":["expires_at"],"additionalProperties":false}'::jsonb),
        ('40000000-0000-0000-0000-000000000013'::uuid, 'TENANT_OWNERSHIP_TRANSFER', 'EMAIL', 'zh-CN', '租户所有权转移提醒', '租户所有权转移请求已创建，最早生效时间为 {{effective_at}}。如有异议请立即处理。', '{"type":"object","properties":{"effective_at":{"type":"string","format":"date-time"}},"required":["effective_at"],"additionalProperties":false}'::jsonb)
), applied AS (
INSERT INTO iam.message_template_versions AS current_template (
    id, template_code, channel, locale, version, subject_template, content_template,
    variable_schema, content_digest, state, published_at
)
SELECT
    id, template_code, channel, locale, 1, subject_template, content_template,
    variable_schema,
    encode(sha256(convert_to(coalesce(subject_template, '') || E'\n' || content_template || E'\n' || variable_schema::text, 'UTF8')), 'hex'),
    'DRAFT', NULL
FROM seed
ON CONFLICT ON CONSTRAINT uq_message_template_version DO NOTHING
RETURNING template_code, channel, locale, version
), matched AS (
SELECT seed.template_code, seed.channel, seed.locale
FROM seed
WHERE EXISTS (
          SELECT 1
          FROM applied
          WHERE applied.template_code = seed.template_code
            AND applied.channel = seed.channel
            AND applied.locale = seed.locale
            AND applied.version = 1
      )
   OR EXISTS (
       SELECT 1
       FROM iam.message_template_versions current_template
       WHERE current_template.template_code = seed.template_code
         AND current_template.channel = seed.channel
         AND current_template.locale = seed.locale
         AND current_template.version = 1
         AND current_template.id = seed.id
         AND current_template.content_digest = encode(sha256(convert_to(coalesce(seed.subject_template, '') || E'\n' || seed.content_template || E'\n' || seed.variable_schema::text, 'UTF8')), 'hex')
   )
)
SELECT 1 / CASE WHEN (SELECT count(*) FROM matched) = (SELECT count(*) FROM seed) THEN 1 ELSE 0 END AS seed_content_match;
