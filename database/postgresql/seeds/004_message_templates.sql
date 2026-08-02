\set ON_ERROR_STOP on

SET ROLE iam_owner;

WITH seed(id, template_code, channel, locale, subject_template, content_template, variable_schema) AS (
    VALUES
        ('40000000-0000-0000-0000-000000000001'::uuid, 'LOGIN_OTP', 'SMS', 'zh-CN', NULL::text, '验证码：{{code}}，{{expires_minutes}} 分钟内有效。请勿向他人透露。', '{"type":"object","required":["code","expires_minutes"],"additionalProperties":false}'::jsonb),
        ('40000000-0000-0000-0000-000000000002'::uuid, 'SECURITY_ALERT', 'EMAIL', 'zh-CN', '账号安全提醒', '检测到账号安全事件：{{event_name}}。如非本人操作，请立即进入安全中心。', '{"type":"object","required":["event_name"],"additionalProperties":false}'::jsonb),
        ('40000000-0000-0000-0000-000000000003'::uuid, 'AUTHENTICATOR_CHANGED', 'EMAIL', 'zh-CN', '认证方式已变更', '你的认证方式已于 {{changed_at}} 发生变更。如非本人操作，请立即冻结账号。', '{"type":"object","required":["changed_at"],"additionalProperties":false}'::jsonb),
        ('40000000-0000-0000-0000-000000000004'::uuid, 'PASSWORD_CHANGED', 'SMS', 'zh-CN', NULL::text, '你的账号密码已变更。如非本人操作，请立即冻结账号。', '{"type":"object","additionalProperties":false}'::jsonb)
)
INSERT INTO iam.message_template_versions (
    id, template_code, channel, locale, version, subject_template, content_template,
    variable_schema, content_digest, state, published_at
)
SELECT
    id, template_code, channel, locale, 1, subject_template, content_template,
    variable_schema,
    encode(sha256(convert_to(coalesce(subject_template, '') || E'\n' || content_template || E'\n' || variable_schema::text, 'UTF8')), 'hex'),
    'PUBLISHED', CURRENT_TIMESTAMP
FROM seed
ON CONFLICT ON CONSTRAINT uq_message_template_version DO NOTHING;

