\set ON_ERROR_STOP on

SET ROLE iam_owner;

-- Subject 轮换需要保留历史映射；状态判断仍由 ID 代码完成，数据库只保存历史、CAS 和“最多一个当前值”的结构事实。
ALTER TABLE iam.user_subjects
    ADD COLUMN retired_at timestamptz,
    ADD COLUMN current_subject_slot smallint DEFAULT 1,
    ADD COLUMN updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    ADD COLUMN row_version bigint NOT NULL DEFAULT 0;

ALTER TABLE iam.user_subjects
    DROP CONSTRAINT uq_user_subject_user_client,
    ADD CONSTRAINT uq_user_subject_current UNIQUE (user_id, client_id, current_subject_slot),
    ADD CONSTRAINT ck_user_subject_rotation_shape CHECK (
        (current_subject_slot = 1 AND retired_at IS NULL)
        OR (current_subject_slot IS NULL AND retired_at IS NOT NULL)
    ),
    ADD CONSTRAINT ck_user_subject_row_version CHECK (row_version >= 0);

COMMENT ON TABLE iam.user_subjects IS '用户面向 Client 的追加式公开 Subject 分配；历史 Subject 永久保留，Pairwise 生成和轮换条件由 ID 代码实现。';
COMMENT ON COLUMN iam.user_subjects.retired_at IS '可空；旧 Subject 退出当前映射的业务时间，历史值不得删除或复用。';
COMMENT ON COLUMN iam.user_subjects.current_subject_slot IS '当前占位固定为 1，历史记录为 NULL；只用于维持同一 User 与 Client 最多一个当前 Subject。';
COMMENT ON COLUMN iam.user_subjects.updated_at IS '数据库更新时间；应用更新 SQL 显式刷新。';
COMMENT ON COLUMN iam.user_subjects.row_version IS 'Subject 当前占位切换的乐观锁版本。';
COMMENT ON CONSTRAINT uq_user_subject_current ON iam.user_subjects IS '同一 User 与 Client 最多一个当前 Subject；是否允许轮换由代码判断。';
COMMENT ON CONSTRAINT ck_user_subject_rotation_shape ON iam.user_subjects IS '只约束当前占位与退役时间的行内结构，不定义轮换状态机。';

-- Membership 终态后重新加入必须创建新事实；数据库只维持“最多一个当前占位”，不解释业务状态。
ALTER TABLE iam.memberships
    ADD COLUMN current_occupancy_slot smallint DEFAULT 1;

ALTER TABLE iam.memberships
    DROP CONSTRAINT uq_memberships_scope_user,
    ADD CONSTRAINT uq_memberships_current UNIQUE (scope_type, scope_id, user_id, current_occupancy_slot),
    ADD CONSTRAINT ck_memberships_current_slot CHECK (current_occupancy_slot IS NULL OR current_occupancy_slot = 1);

COMMENT ON COLUMN iam.memberships.current_occupancy_slot IS '可空；当前占位为 1，终态历史记录由代码写 NULL；数据库不根据 state 自动释放占位。';
COMMENT ON CONSTRAINT uq_memberships_current ON iam.memberships IS '同一作用域和用户最多一个当前 Membership；重新加入创建新记录。';
COMMENT ON CONSTRAINT ck_memberships_current_slot ON iam.memberships IS '只限制技术占位值，不定义 Membership 状态机。';

-- 已登记的高频查询和反向影响分析索引；索引不替代权限、租户、状态和引用有效性校验。
CREATE INDEX ix_identifier_bindings_identifier ON iam.identifier_bindings (identifier_id, bound_at DESC);
CREATE INDEX ix_authorization_decisions_decision_id ON iam.authorization_decisions (decision_id, decided_at);
CREATE INDEX ix_risk_signals_signal_id ON iam.risk_signals (signal_id, occurred_at);
CREATE INDEX ix_webhook_deliveries_delivery_id ON iam.webhook_deliveries (delivery_id, created_at);
CREATE INDEX ix_webhook_deliveries_event_subscription ON iam.webhook_deliveries (event_id, subscription_id, created_at DESC);
CREATE INDEX ix_message_requests_request_id ON iam.message_requests (request_id, created_at);
CREATE INDEX ix_risk_assessment_signals_signal ON iam.risk_assessment_signals (signal_id, assessment_id);

CREATE INDEX ix_operations_policy_versions_gin ON iam.operations USING gin (policy_version_ids);
CREATE INDEX ix_sessions_policy_versions_gin ON iam.sessions USING gin (policy_version_ids);
CREATE INDEX ix_access_tokens_policy_versions_gin ON iam.access_token_records USING gin (policy_version_ids);
CREATE INDEX ix_authorization_decisions_policy_versions_gin ON iam.authorization_decisions USING gin (policy_version_ids);

CREATE INDEX ix_user_role_assignments_role ON iam.user_role_assignments (role_id, state, valid_until);
CREATE INDEX ix_group_role_assignments_role ON iam.group_role_assignments (role_id, state, valid_until);
CREATE INDEX ix_machine_role_assignments_role ON iam.machine_role_assignments (role_id, state, valid_until);
CREATE INDEX ix_configuration_release_items_version ON iam.configuration_release_items (configuration_version_id, release_id);

CREATE INDEX ix_identifiers_key ON iam.identifiers (key_id) WHERE key_id IS NOT NULL;
CREATE INDEX ix_credential_materials_key ON iam.credential_materials (key_id) WHERE key_id IS NOT NULL;
CREATE INDEX ix_data_export_artifacts_key ON iam.data_export_artifacts (key_id);
CREATE INDEX ix_jwks_release_keys_key ON iam.jwks_release_keys (key_id);
CREATE INDEX ix_certificates_key ON iam.certificates (key_id) WHERE key_id IS NOT NULL;
CREATE INDEX ix_machine_credentials_key ON iam.machine_credentials (key_id) WHERE key_id IS NOT NULL;
CREATE INDEX ix_machine_credentials_certificate ON iam.machine_credentials (certificate_id) WHERE certificate_id IS NOT NULL;
CREATE INDEX ix_webhook_signing_keys_key ON iam.webhook_signing_keys (key_id);

COMMENT ON INDEX iam.ix_identifier_bindings_identifier IS '按 Identifier 读取历史绑定和解绑墓碑；归属与隔离期由代码判断。';
COMMENT ON INDEX iam.ix_authorization_decisions_decision_id IS '按公开决策 ID 定位分区内授权决策；全局唯一性由 PDP 生成与幂等代码保证。';
COMMENT ON INDEX iam.ix_risk_signals_signal_id IS '按公开信号 ID 定位分区内风险信号；全局唯一性由生产代码保证。';
COMMENT ON INDEX iam.ix_webhook_deliveries_delivery_id IS '按公开投递 ID 定位分区内任务；跨分区唯一性由创建命令保证。';
COMMENT ON INDEX iam.ix_webhook_deliveries_event_subscription IS '按事件和订阅诊断投递历史。';
COMMENT ON INDEX iam.ix_message_requests_request_id IS '按公开消息请求 ID 定位分区内请求；跨分区唯一性由幂等命令保证。';
COMMENT ON INDEX iam.ix_risk_assessment_signals_signal IS '从风险信号反向定位受影响评估。';
COMMENT ON INDEX iam.ix_operations_policy_versions_gin IS '按策略版本反向定位 Operation 快照。';
COMMENT ON INDEX iam.ix_sessions_policy_versions_gin IS '按策略版本反向定位会话快照。';
COMMENT ON INDEX iam.ix_access_tokens_policy_versions_gin IS '按策略版本反向定位 Token 元数据快照。';
COMMENT ON INDEX iam.ix_authorization_decisions_policy_versions_gin IS '按策略版本反向定位授权决策证据。';
COMMENT ON INDEX iam.ix_user_role_assignments_role IS '角色变更时定位用户授予影响面。';
COMMENT ON INDEX iam.ix_group_role_assignments_role IS '角色变更时定位用户组授予影响面。';
COMMENT ON INDEX iam.ix_machine_role_assignments_role IS '角色变更时定位机器主体授予影响面。';
COMMENT ON INDEX iam.ix_configuration_release_items_version IS '从配置版本反向定位发布记录。';
COMMENT ON INDEX iam.ix_identifiers_key IS 'Key 轮换时定位 Identifier 密文。';
COMMENT ON INDEX iam.ix_credential_materials_key IS 'Key 轮换或退役时定位认证材料。';
COMMENT ON INDEX iam.ix_data_export_artifacts_key IS 'Key 轮换或销毁前定位隐私导出物。';
COMMENT ON INDEX iam.ix_jwks_release_keys_key IS 'Key 轮换时定位 JWKS 发布。';
COMMENT ON INDEX iam.ix_certificates_key IS 'Key 轮换时定位证书。';
COMMENT ON INDEX iam.ix_machine_credentials_key IS 'Key 轮换时定位机器凭证。';
COMMENT ON INDEX iam.ix_machine_credentials_certificate IS '证书轮换时定位机器凭证。';
COMMENT ON INDEX iam.ix_webhook_signing_keys_key IS 'Key 轮换时定位 Webhook 签名配置。';
