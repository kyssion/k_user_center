\set ON_ERROR_STOP on

SET ROLE iam_owner;

-- 角色权限关系保留撤销历史；同一角色和权限只能存在一个当前关系，撤销后可追加新关系。
ALTER TABLE iam.role_permissions
    DROP CONSTRAINT uq_role_permissions;

CREATE UNIQUE INDEX uq_role_permissions_current ON iam.role_permissions (role_id, permission_id) WHERE removed_at IS NULL;

CREATE INDEX ix_role_permissions_role_history ON iam.role_permissions (role_id, created_at DESC);

COMMENT ON INDEX iam.uq_role_permissions_current IS '同一角色和权限最多一个未撤销关系；撤销后通过新行重新授予。';
COMMENT ON INDEX iam.ix_role_permissions_role_history IS '按角色查询权限关系追加历史。';

-- 验证码等投递秘密不进入 IAM 数据库；这里只保存外部短期秘密存储的非承载型句柄和失效时间。
ALTER TABLE iam.message_requests
    ADD COLUMN delivery_secret_handle varchar(512),
    ADD COLUMN delivery_secret_expires_at timestamptz,
    ADD CONSTRAINT ck_message_request_no_secret_parameters CHECK (
        parameters::text !~* '"(code|verification_code|otp|magic_link_token|access_token|refresh_token|authorization_code)"[[:space:]]*:'
    ),
    ADD CONSTRAINT ck_message_request_delivery_secret CHECK (
        (delivery_secret_handle IS NULL AND delivery_secret_expires_at IS NULL)
        OR (
            delivery_secret_handle IS NOT NULL
            AND delivery_secret_expires_at IS NOT NULL
            AND char_length(delivery_secret_handle) >= 16
            AND delivery_secret_expires_at > created_at
            AND delivery_secret_expires_at <= expires_at
        )
    );

COMMENT ON COLUMN iam.message_requests.delivery_secret_handle IS '可空；外部短期秘密存储的非承载型不透明句柄，仅凭该值不能读取验证码等秘密；原值不得进入 IAM 数据库、事件、日志或审计。';
COMMENT ON COLUMN iam.message_requests.delivery_secret_expires_at IS '可空；短期秘密句柄失效时间，不晚于消息请求失效时间。';
COMMENT ON COLUMN iam.message_requests.parameters IS '持久化的非秘密模板变量；验证码、Magic Link Token 和完整 Token 必须通过 delivery_secret_handle 在 Worker 内存中注入。';
