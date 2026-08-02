\set ON_ERROR_STOP on

SET ROLE iam_owner;

-- 跨领域逻辑引用和高容量时间查询的补充索引；不创建 Foreign Key。
CREATE INDEX ix_user_subjects_user ON iam.user_subjects (user_id, client_id);
CREATE INDEX ix_identifier_claims_owner ON iam.identifier_claims (owner_user_id, claim_state);
CREATE INDEX ix_credential_materials_authenticator ON iam.credential_materials (authenticator_id, material_type, material_version DESC);
CREATE INDEX ix_recovery_codes_batch ON iam.recovery_codes (batch_id, state);
CREATE INDEX ix_login_steps_transaction ON iam.login_transaction_steps (login_transaction_id, state);
CREATE INDEX ix_tenant_domains_tenant ON iam.tenant_domains (tenant_id, state);
CREATE INDEX ix_group_members_group ON iam.group_members (group_id, removed_at);
CREATE INDEX ix_session_participants_session ON iam.session_participants (session_id, logout_state);
CREATE INDEX ix_refresh_tokens_family ON iam.refresh_token_instances (family_id, sequence_no DESC);
CREATE INDEX ix_agreement_acceptances_user ON iam.agreement_acceptances (user_id, accepted_at DESC);
CREATE INDEX ix_consent_aggregates_subject ON iam.consent_aggregates (subject_type, subject_id, purpose_code);
CREATE INDEX ix_legal_holds_active ON iam.legal_holds (state, expires_at, effective_at);
CREATE INDEX ix_data_export_privacy_request ON iam.data_export_artifacts (privacy_request_id, state);
CREATE INDEX ix_deletion_proofs_privacy_request ON iam.deletion_proofs (privacy_request_id, system_code);
CREATE INDEX ix_risk_assessment_signals_assessment ON iam.risk_assessment_signals (assessment_id, signal_id);
CREATE INDEX ix_approval_actions_reviewer ON iam.approval_actions (reviewer_type, reviewer_id, created_at DESC);
CREATE INDEX ix_jwks_release_keys_release ON iam.jwks_release_keys (jwks_release_id, display_order);
CREATE INDEX ix_configuration_release_items_release ON iam.configuration_release_items (release_id, apply_order);
CREATE INDEX ix_webhook_signing_keys_subscription ON iam.webhook_signing_keys (subscription_id, state, valid_until);
CREATE INDEX ix_consumer_checkpoints_watermark ON iam.consumer_checkpoints (consumer_id, security_watermark);
CREATE INDEX ix_contact_reachability_state ON iam.contact_reachability (channel, reachability_state, updated_at);
CREATE INDEX ix_migration_items_platform ON iam.migration_items (platform_object_type, platform_object_id, state);

COMMENT ON INDEX iam.ix_user_subjects_user IS '从用户和 Client 定位 Subject 映射。';
COMMENT ON INDEX iam.ix_identifier_claims_owner IS '从用户定位当前标识占用。';
COMMENT ON INDEX iam.ix_credential_materials_authenticator IS '认证时按认证器、材料类型和版本读取安全材料。';
COMMENT ON INDEX iam.ix_recovery_codes_batch IS '恢复流程按批次和状态定位恢复码。';
COMMENT ON INDEX iam.ix_login_steps_transaction IS '登录编排器按事务读取步骤。';
COMMENT ON INDEX iam.ix_tenant_domains_tenant IS '租户管理按状态读取域名。';
COMMENT ON INDEX iam.ix_group_members_group IS '用户组管理读取当前和历史成员。';
COMMENT ON INDEX iam.ix_session_participants_session IS '统一退出按会话读取 RP 参与者。';
COMMENT ON INDEX iam.ix_refresh_tokens_family IS 'Refresh Token 轮换按 Family 和序号定位实例。';
COMMENT ON INDEX iam.ix_agreement_acceptances_user IS '按用户查询协议接受证据。';
COMMENT ON INDEX iam.ix_consent_aggregates_subject IS '按主体和目的定位 Consent 聚合。';
COMMENT ON INDEX iam.ix_legal_holds_active IS '隐私处理前定位生效的 Legal Hold。';
COMMENT ON INDEX iam.ix_data_export_privacy_request IS '按隐私请求定位导出物。';
COMMENT ON INDEX iam.ix_deletion_proofs_privacy_request IS '按隐私请求汇总下游删除证明。';
COMMENT ON INDEX iam.ix_risk_assessment_signals_assessment IS '按评估读取参与信号。';
COMMENT ON INDEX iam.ix_approval_actions_reviewer IS '审计审批人历史动作。';
COMMENT ON INDEX iam.ix_jwks_release_keys_release IS '生成 JWKS 时按发布和顺序读取 Key。';
COMMENT ON INDEX iam.ix_configuration_release_items_release IS '激活发布时按顺序读取配置项。';
COMMENT ON INDEX iam.ix_webhook_signing_keys_subscription IS '投递时定位订阅当前签名 Key。';
COMMENT ON INDEX iam.ix_consumer_checkpoints_watermark IS '查询消费者安全水位传播进度。';
COMMENT ON INDEX iam.ix_contact_reachability_state IS '按渠道和可达性状态运营联系方式。';
COMMENT ON INDEX iam.ix_migration_items_platform IS '从平台对象追溯迁移项。';

-- BRIN 适合追加型时间分区内扫描；B-Tree 业务路径索引已在各领域 Migration 定义。
CREATE INDEX ix_audit_events_recorded_brin ON iam.audit_events USING brin (recorded_at);
CREATE INDEX ix_authentication_attempts_occurred_brin ON iam.authentication_attempts USING brin (occurred_at);
CREATE INDEX ix_access_token_records_issued_brin ON iam.access_token_records USING brin (issued_at);
CREATE INDEX ix_authorization_decisions_decided_brin ON iam.authorization_decisions USING brin (decided_at);
CREATE INDEX ix_risk_signals_occurred_brin ON iam.risk_signals USING brin (occurred_at);
CREATE INDEX ix_workload_attestations_received_brin ON iam.workload_attestations USING brin (received_at);
CREATE INDEX ix_webhook_deliveries_created_brin ON iam.webhook_deliveries USING brin (created_at);
CREATE INDEX ix_webhook_attempts_created_brin ON iam.webhook_delivery_attempts USING brin (created_at);
CREATE INDEX ix_message_requests_created_brin ON iam.message_requests USING brin (created_at);
CREATE INDEX ix_message_attempts_created_brin ON iam.message_delivery_attempts USING brin (created_at);
CREATE INDEX ix_migration_change_recorded_brin ON iam.migration_change_logs USING brin (recorded_at);

COMMENT ON INDEX iam.ix_audit_events_recorded_brin IS '审计事件按记录时间执行大范围顺序扫描。';
COMMENT ON INDEX iam.ix_authentication_attempts_occurred_brin IS '认证尝试按发生时间执行大范围顺序扫描。';
COMMENT ON INDEX iam.ix_access_token_records_issued_brin IS 'Token 元数据按签发时间执行保留和调查扫描。';
COMMENT ON INDEX iam.ix_authorization_decisions_decided_brin IS '授权决策按决策时间执行证据扫描。';
COMMENT ON INDEX iam.ix_risk_signals_occurred_brin IS '风险信号按发生时间执行模型回溯扫描。';
COMMENT ON INDEX iam.ix_workload_attestations_received_brin IS '工作负载证明按接收时间执行调查扫描。';
COMMENT ON INDEX iam.ix_webhook_deliveries_created_brin IS 'Webhook 投递按创建时间执行归档扫描。';
COMMENT ON INDEX iam.ix_webhook_attempts_created_brin IS 'Webhook 尝试按创建时间执行归档扫描。';
COMMENT ON INDEX iam.ix_message_requests_created_brin IS '消息请求按创建时间执行归档扫描。';
COMMENT ON INDEX iam.ix_message_attempts_created_brin IS '消息尝试按创建时间执行归档扫描。';
COMMENT ON INDEX iam.ix_migration_change_recorded_brin IS '迁移变更按记录时间执行回放扫描。';

