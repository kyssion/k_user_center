-- =============================================================================
-- baseline/schemas/authn/links.sql
-- authn 源表拥有的最终跨 Schema 外键、绑定触发器、支撑索引及 COMMENT
-- PostgreSQL 16+；应用技术栈：.NET 10 + SqlSugar
-- =============================================================================

\set ON_ERROR_STOP on

SELECT (NOT EXISTS (SELECT 1 FROM core.schema_migration WHERE version = 'baseline:authn:links'))::text AS kuc_run_links \gset
\if :kuc_run_links
BEGIN;
SET LOCAL lock_timeout = '10s';
SET LOCAL statement_timeout = '5min';

ALTER TABLE authn.login_transaction
    ADD CONSTRAINT fk_login_tx_client_scope FOREIGN KEY (client_id, tenant_id, business_line_id)
        REFERENCES oauth.client(id, tenant_id, business_line_id),
    ADD CONSTRAINT fk_login_transaction_risk FOREIGN KEY (risk_assessment_id) REFERENCES risk.risk_assessment(id),
    ADD CONSTRAINT fk_login_transaction_client FOREIGN KEY (client_id) REFERENCES oauth.client(id),
    ADD CONSTRAINT fk_login_transaction_user FOREIGN KEY (user_id) REFERENCES iam.user_account(id);

ALTER TABLE authn.device_authorization
    ADD CONSTRAINT fk_device_authorization_tenant FOREIGN KEY (tenant_id) REFERENCES org.tenant(id),
    ADD CONSTRAINT fk_device_authorization_client FOREIGN KEY (client_id) REFERENCES oauth.client(id),
    ADD CONSTRAINT fk_device_authorization_user FOREIGN KEY (authorized_user_id) REFERENCES iam.user_account(id),
    ADD CONSTRAINT fk_device_authorization_grant FOREIGN KEY (grant_id) REFERENCES oauth.authorization_grant(id);

ALTER TABLE authn.verification_challenge
    ADD CONSTRAINT fk_verification_challenge_risk FOREIGN KEY (risk_assessment_id) REFERENCES risk.risk_assessment(id),
    ADD CONSTRAINT fk_verification_challenge_client FOREIGN KEY (client_id) REFERENCES oauth.client(id),
    ADD CONSTRAINT fk_verification_challenge_user FOREIGN KEY (user_id) REFERENCES iam.user_account(id),
    ADD CONSTRAINT fk_verification_challenge_identifier FOREIGN KEY (target_identifier_id) REFERENCES iam.identifier(id);

ALTER TABLE authn.authenticator
    ADD CONSTRAINT fk_authenticator_user FOREIGN KEY (user_id) REFERENCES iam.user_account(id);

ALTER TABLE authn.password_credential
    ADD CONSTRAINT fk_password_credential_user FOREIGN KEY (user_id) REFERENCES iam.user_account(id);

ALTER TABLE authn.password_history
    ADD CONSTRAINT fk_password_history_user FOREIGN KEY (user_id) REFERENCES iam.user_account(id);

ALTER TABLE authn.recovery_code_batch
    ADD CONSTRAINT fk_recovery_code_batch_user FOREIGN KEY (user_id) REFERENCES iam.user_account(id);

CREATE INDEX ix_fk_login_transaction_client_id_tenant_id_business_line_id ON authn.login_transaction (client_id, tenant_id, business_line_id);

CREATE INDEX ix_fk_device_authorization_tenant_id ON authn.device_authorization (tenant_id);

CREATE INDEX ix_fk_login_transaction_risk_assessment_id ON authn.login_transaction (risk_assessment_id);

CREATE INDEX ix_fk_verification_challenge_risk_assessment_id ON authn.verification_challenge (risk_assessment_id);

CREATE INDEX ix_fk_authenticator_user_id ON authn.authenticator (user_id);

CREATE INDEX ix_fk_password_history_user_id ON authn.password_history (user_id);

CREATE INDEX ix_fk_recovery_code_batch_user_id ON authn.recovery_code_batch (user_id);

CREATE INDEX ix_fk_login_transaction_user_id ON authn.login_transaction (user_id);

CREATE INDEX ix_fk_verification_challenge_client_id ON authn.verification_challenge (client_id);

CREATE INDEX ix_fk_verification_challenge_user_id ON authn.verification_challenge (user_id);

CREATE INDEX ix_fk_verification_challenge_target_identifier_id ON authn.verification_challenge (target_identifier_id);

CREATE INDEX ix_fk_device_authorization_client_id ON authn.device_authorization (client_id);

CREATE INDEX ix_fk_device_authorization_authorized_user_id ON authn.device_authorization (authorized_user_id);

CREATE INDEX ix_fk_device_authorization_grant_id ON authn.device_authorization (grant_id);

COMMENT ON CONSTRAINT fk_login_tx_client_scope ON authn.login_transaction IS '外键约束：authn.login_transaction 的 client_id、tenant_id、business_line_id 必须引用 oauth.client；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT fk_device_authorization_tenant ON authn.device_authorization IS '外键约束：authn.device_authorization 的 tenant_id 必须引用 org.tenant；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT fk_login_transaction_risk ON authn.login_transaction IS '外键约束：authn.login_transaction 的 risk_assessment_id 必须引用 risk.risk_assessment；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT fk_verification_challenge_risk ON authn.verification_challenge IS '外键约束：authn.verification_challenge 的 risk_assessment_id 必须引用 risk.risk_assessment；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT fk_authenticator_user ON authn.authenticator IS '外键约束：authn.authenticator 的 user_id 必须引用 iam.user_account；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT fk_password_credential_user ON authn.password_credential IS '外键约束：authn.password_credential 的 user_id 必须引用 iam.user_account；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT fk_password_history_user ON authn.password_history IS '外键约束：authn.password_history 的 user_id 必须引用 iam.user_account；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT fk_recovery_code_batch_user ON authn.recovery_code_batch IS '外键约束：authn.recovery_code_batch 的 user_id 必须引用 iam.user_account；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT fk_login_transaction_client ON authn.login_transaction IS '外键约束：authn.login_transaction 的 client_id 必须引用 oauth.client；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT fk_login_transaction_user ON authn.login_transaction IS '外键约束：authn.login_transaction 的 user_id 必须引用 iam.user_account；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT fk_verification_challenge_client ON authn.verification_challenge IS '外键约束：authn.verification_challenge 的 client_id 必须引用 oauth.client；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT fk_verification_challenge_user ON authn.verification_challenge IS '外键约束：authn.verification_challenge 的 user_id 必须引用 iam.user_account；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT fk_verification_challenge_identifier ON authn.verification_challenge IS '外键约束：authn.verification_challenge 的 target_identifier_id 必须引用 iam.identifier；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT fk_device_authorization_client ON authn.device_authorization IS '外键约束：authn.device_authorization 的 client_id 必须引用 oauth.client；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT fk_device_authorization_user ON authn.device_authorization IS '外键约束：authn.device_authorization 的 authorized_user_id 必须引用 iam.user_account；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT fk_device_authorization_grant ON authn.device_authorization IS '外键约束：authn.device_authorization 的 grant_id 必须引用 oauth.authorization_grant；级联行为以约束定义为准。';

COMMENT ON INDEX authn.ix_fk_login_transaction_client_id_tenant_id_business_line_id IS '跨 Schema 外键前导索引：优化 authn.login_transaction 按 client_id、tenant_id、business_line_id 的关联与删除校验。';
COMMENT ON INDEX authn.ix_fk_device_authorization_tenant_id IS '跨 Schema 外键前导索引：优化 authn.device_authorization 按 tenant_id 的关联与删除校验。';
COMMENT ON INDEX authn.ix_fk_login_transaction_risk_assessment_id IS '跨 Schema 外键前导索引：优化 authn.login_transaction 按 risk_assessment_id 的关联与删除校验。';
COMMENT ON INDEX authn.ix_fk_verification_challenge_risk_assessment_id IS '跨 Schema 外键前导索引：优化 authn.verification_challenge 按 risk_assessment_id 的关联与删除校验。';
COMMENT ON INDEX authn.ix_fk_authenticator_user_id IS '跨 Schema 外键前导索引：优化 authn.authenticator 按 user_id 的关联与删除校验。';
COMMENT ON INDEX authn.ix_fk_password_history_user_id IS '跨 Schema 外键前导索引：优化 authn.password_history 按 user_id 的关联与删除校验。';
COMMENT ON INDEX authn.ix_fk_recovery_code_batch_user_id IS '跨 Schema 外键前导索引：优化 authn.recovery_code_batch 按 user_id 的关联与删除校验。';
COMMENT ON INDEX authn.ix_fk_login_transaction_user_id IS '跨 Schema 外键前导索引：优化 authn.login_transaction 按 user_id 的关联与删除校验。';
COMMENT ON INDEX authn.ix_fk_verification_challenge_client_id IS '跨 Schema 外键前导索引：优化 authn.verification_challenge 按 client_id 的关联与删除校验。';
COMMENT ON INDEX authn.ix_fk_verification_challenge_user_id IS '跨 Schema 外键前导索引：优化 authn.verification_challenge 按 user_id 的关联与删除校验。';
COMMENT ON INDEX authn.ix_fk_verification_challenge_target_identifier_id IS '跨 Schema 外键前导索引：优化 authn.verification_challenge 按 target_identifier_id 的关联与删除校验。';
COMMENT ON INDEX authn.ix_fk_device_authorization_client_id IS '跨 Schema 外键前导索引：优化 authn.device_authorization 按 client_id 的关联与删除校验。';
COMMENT ON INDEX authn.ix_fk_device_authorization_authorized_user_id IS '跨 Schema 外键前导索引：优化 authn.device_authorization 按 authorized_user_id 的关联与删除校验。';
COMMENT ON INDEX authn.ix_fk_device_authorization_grant_id IS '跨 Schema 外键前导索引：优化 authn.device_authorization 按 grant_id 的关联与删除校验。';

SELECT core.fn_register_migration('baseline:authn:links', 'authn Schema 跨域约束与绑定');
COMMIT;
\endif

