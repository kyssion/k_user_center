\set ON_ERROR_STOP on

SET ROLE iam_owner;

-- 未发布的旧 OTP 模板不能再被激活；已经发布的版本由控制面审批流程退役，Verification 会继续阻断发布。
UPDATE iam.message_template_versions
   SET state = 'RETIRED'
 WHERE id = '40000000-0000-0000-0000-000000000001'::uuid
   AND template_code = 'LOGIN_OTP'
   AND channel = 'SMS'
   AND locale = 'zh-CN'
   AND version = 1
   AND state = 'DRAFT'
   AND approval_case_id IS NULL
   AND published_at IS NULL;

WITH seed(id, template_code, channel, locale, version, subject_template, content_template, variable_schema) AS (
    VALUES (
        '40000000-0000-0000-0000-000000000014'::uuid,
        'LOGIN_OTP',
        'SMS',
        'zh-CN',
        2,
        NULL::text,
        '验证码：{{code}}，{{expires_minutes}} 分钟内有效。请勿向他人透露。',
        '{"type":"object","properties":{"code":{"type":"string","minLength":4,"maxLength":12,"x-storage":"EPHEMERAL_SECRET"},"expires_minutes":{"type":"integer","minimum":1,"maximum":5,"x-storage":"PERSISTED_PARAMETER"}},"required":["code","expires_minutes"],"additionalProperties":false}'::jsonb
    )
), applied AS (
    INSERT INTO iam.message_template_versions AS current_template (
        id, template_code, channel, locale, version, subject_template, content_template,
        variable_schema, content_digest, state, published_at
    )
    SELECT
        id, template_code, channel, locale, version, subject_template, content_template,
        variable_schema,
        encode(sha256(convert_to(coalesce(subject_template, '') || E'\n' || content_template || E'\n' || variable_schema::text, 'UTF8')), 'hex'),
        'DRAFT', NULL
    FROM seed
    ON CONFLICT ON CONSTRAINT uq_message_template_version DO UPDATE
    SET id = current_template.id
    WHERE current_template.id = EXCLUDED.id
      AND current_template.content_digest = EXCLUDED.content_digest
    RETURNING 1
)
SELECT 1 / CASE WHEN (SELECT count(*) FROM applied) = 1 THEN 1 ELSE 0 END AS seed_content_match;
