-- =============================================================================
-- baseline/schemas/oauth/links.sql
-- oauth 源表拥有的最终跨 Schema 外键、绑定触发器、支撑索引及 COMMENT
-- PostgreSQL 16+；应用技术栈：.NET 10 + SqlSugar
-- =============================================================================

\set ON_ERROR_STOP on

SELECT (NOT EXISTS (SELECT 1 FROM core.schema_migration WHERE version = 'baseline:oauth:links'))::text AS kuc_run_links \gset
\if :kuc_run_links
BEGIN;
SET LOCAL lock_timeout = '10s';
SET LOCAL statement_timeout = '5min';

ALTER TABLE oauth.client
    ADD CONSTRAINT fk_client_tenant FOREIGN KEY (tenant_id) REFERENCES org.tenant(id),
    ADD CONSTRAINT fk_client_tenant_business FOREIGN KEY (tenant_id, business_line_id) REFERENCES org.tenant(id, business_line_id),
    ADD CONSTRAINT fk_client_profile FOREIGN KEY (profile_code, profile_version) REFERENCES core.security_profile(profile_code, profile_version),
    ADD CONSTRAINT fk_client_business_line FOREIGN KEY (business_line_id) REFERENCES org.business_line(id),
    ADD CONSTRAINT fk_client_approval FOREIGN KEY (approval_case_id) REFERENCES control.approval_case(id);

ALTER TABLE oauth.authorization_grant
    ADD CONSTRAINT fk_authorization_grant_tenant FOREIGN KEY (tenant_id) REFERENCES org.tenant(id),
    ADD CONSTRAINT fk_authorization_grant_tx FOREIGN KEY (login_transaction_id) REFERENCES authn.login_transaction(id),
    ADD CONSTRAINT fk_authorization_grant_consent FOREIGN KEY (consent_id) REFERENCES privacy.consent(id);

ALTER TABLE oauth.user_session
    ADD CONSTRAINT fk_user_session_tenant FOREIGN KEY (tenant_id) REFERENCES org.tenant(id),
    ADD CONSTRAINT fk_user_session_user FOREIGN KEY (user_id) REFERENCES iam.user_account(id),
    ADD CONSTRAINT fk_user_session_tx FOREIGN KEY (login_transaction_id) REFERENCES authn.login_transaction(id);

ALTER TABLE oauth.token_family
    ADD CONSTRAINT fk_token_family_tenant FOREIGN KEY (tenant_id) REFERENCES org.tenant(id);

ALTER TABLE oauth.reference_access_token
    ADD CONSTRAINT fk_reference_token_tenant FOREIGN KEY (tenant_id) REFERENCES org.tenant(id),
    ADD CONSTRAINT fk_reference_access_token_consent FOREIGN KEY (consent_id) REFERENCES privacy.consent(id);

ALTER TABLE oauth.revocation_record
    ADD CONSTRAINT fk_revocation_tenant FOREIGN KEY (tenant_id) REFERENCES org.tenant(id);

ALTER TABLE oauth.scope_definition
    ADD CONSTRAINT fk_scope_definition_classification FOREIGN KEY (data_classification) REFERENCES core.data_classification(classification_code);

ALTER TABLE oauth.device
    ADD CONSTRAINT fk_device_user FOREIGN KEY (user_id) REFERENCES iam.user_account(id);

ALTER TABLE oauth.authorization_code
    ADD CONSTRAINT fk_authorization_code_user FOREIGN KEY (user_id) REFERENCES iam.user_account(id),
    ADD CONSTRAINT fk_authorization_code_tx FOREIGN KEY (login_transaction_id) REFERENCES authn.login_transaction(id);

ALTER TABLE oauth.logout_request
    ADD CONSTRAINT fk_logout_request_operation FOREIGN KEY (operation_id) REFERENCES core.async_operation(id),
    ADD CONSTRAINT fk_logout_request_user FOREIGN KEY (user_id) REFERENCES iam.user_account(id);

ALTER TABLE oauth.application
    ADD CONSTRAINT fk_application_business_line FOREIGN KEY (business_line_id) REFERENCES org.business_line(id);

ALTER TABLE oauth.api_resource
    ADD CONSTRAINT fk_api_resource_business_line FOREIGN KEY (business_line_id) REFERENCES org.business_line(id);

CREATE TRIGGER trg_client_binding_immutable BEFORE UPDATE ON oauth.client FOR EACH ROW
    EXECUTE FUNCTION control.fn_active_approval_binding_guard('client_state', 'ACTIVE', 'approval_case_id', 'approval_execution_id');

CREATE INDEX ix_fk_client_tenant_id ON oauth.client (tenant_id);

CREATE INDEX ix_fk_client_tenant_id_business_line_id ON oauth.client (tenant_id, business_line_id);

CREATE INDEX ix_fk_authorization_grant_tenant_id ON oauth.authorization_grant (tenant_id);

CREATE INDEX ix_fk_user_session_tenant_id ON oauth.user_session (tenant_id);

CREATE INDEX ix_fk_token_family_tenant_id ON oauth.token_family (tenant_id);

CREATE INDEX ix_fk_reference_access_token_tenant_id ON oauth.reference_access_token (tenant_id);

CREATE INDEX ix_fk_revocation_record_tenant_id ON oauth.revocation_record (tenant_id);

CREATE INDEX ix_fk_client_profile_code_profile_version ON oauth.client (profile_code, profile_version);

CREATE INDEX ix_fk_scope_definition_data_classification ON oauth.scope_definition (data_classification);

CREATE INDEX ix_fk_authorization_grant_login_transaction_id ON oauth.authorization_grant (login_transaction_id);

CREATE INDEX ix_fk_authorization_code_user_id ON oauth.authorization_code (user_id);

CREATE INDEX ix_fk_logout_request_user_id ON oauth.logout_request (user_id);

CREATE INDEX ix_fk_application_business_line_id ON oauth.application (business_line_id);

CREATE INDEX ix_fk_client_business_line_id ON oauth.client (business_line_id);

CREATE INDEX ix_fk_api_resource_business_line_id ON oauth.api_resource (business_line_id);

CREATE INDEX ix_fk_authorization_grant_consent_id ON oauth.authorization_grant (consent_id);

CREATE INDEX ix_fk_reference_access_token_consent_id ON oauth.reference_access_token (consent_id);

CREATE INDEX ix_fk_client_approval_case_id ON oauth.client (approval_case_id);

COMMENT ON CONSTRAINT fk_client_tenant ON oauth.client IS '外键约束：oauth.client 的 tenant_id 必须引用 org.tenant；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT fk_client_tenant_business ON oauth.client IS '外键约束：oauth.client 的 tenant_id、business_line_id 必须引用 org.tenant；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT fk_authorization_grant_tenant ON oauth.authorization_grant IS '外键约束：oauth.authorization_grant 的 tenant_id 必须引用 org.tenant；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT fk_user_session_tenant ON oauth.user_session IS '外键约束：oauth.user_session 的 tenant_id 必须引用 org.tenant；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT fk_token_family_tenant ON oauth.token_family IS '外键约束：oauth.token_family 的 tenant_id 必须引用 org.tenant；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT fk_reference_token_tenant ON oauth.reference_access_token IS '外键约束：oauth.reference_access_token 的 tenant_id 必须引用 org.tenant；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT fk_revocation_tenant ON oauth.revocation_record IS '外键约束：oauth.revocation_record 的 tenant_id 必须引用 org.tenant；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT fk_client_profile ON oauth.client IS '外键约束：oauth.client 的 profile_code、profile_version 必须引用 core.security_profile；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT fk_scope_definition_classification ON oauth.scope_definition IS '外键约束：oauth.scope_definition 的 data_classification 必须引用 core.data_classification；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT fk_device_user ON oauth.device IS '外键约束：oauth.device 的 user_id 必须引用 iam.user_account；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT fk_authorization_grant_tx ON oauth.authorization_grant IS '外键约束：oauth.authorization_grant 的 login_transaction_id 必须引用 authn.login_transaction；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT fk_user_session_user ON oauth.user_session IS '外键约束：oauth.user_session 的 user_id 必须引用 iam.user_account；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT fk_user_session_tx ON oauth.user_session IS '外键约束：oauth.user_session 的 login_transaction_id 必须引用 authn.login_transaction；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT fk_authorization_code_user ON oauth.authorization_code IS '外键约束：oauth.authorization_code 的 user_id 必须引用 iam.user_account；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT fk_authorization_code_tx ON oauth.authorization_code IS '外键约束：oauth.authorization_code 的 login_transaction_id 必须引用 authn.login_transaction；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT fk_logout_request_operation ON oauth.logout_request IS '外键约束：oauth.logout_request 的 operation_id 必须引用 core.async_operation；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT fk_logout_request_user ON oauth.logout_request IS '外键约束：oauth.logout_request 的 user_id 必须引用 iam.user_account；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT fk_application_business_line ON oauth.application IS '外键约束：oauth.application 的 business_line_id 必须引用 org.business_line；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT fk_client_business_line ON oauth.client IS '外键约束：oauth.client 的 business_line_id 必须引用 org.business_line；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT fk_api_resource_business_line ON oauth.api_resource IS '外键约束：oauth.api_resource 的 business_line_id 必须引用 org.business_line；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT fk_authorization_grant_consent ON oauth.authorization_grant IS '外键约束：oauth.authorization_grant 的 consent_id 必须引用 privacy.consent；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT fk_reference_access_token_consent ON oauth.reference_access_token IS '外键约束：oauth.reference_access_token 的 consent_id 必须引用 privacy.consent；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT fk_client_approval ON oauth.client IS '外键约束：oauth.client 的 approval_case_id 必须引用 control.approval_case；级联行为以约束定义为准。';

COMMENT ON INDEX oauth.ix_fk_client_tenant_id IS '跨 Schema 外键前导索引：优化 oauth.client 按 tenant_id 的关联与删除校验。';
COMMENT ON INDEX oauth.ix_fk_client_tenant_id_business_line_id IS '跨 Schema 外键前导索引：优化 oauth.client 按 tenant_id、business_line_id 的关联与删除校验。';
COMMENT ON INDEX oauth.ix_fk_authorization_grant_tenant_id IS '跨 Schema 外键前导索引：优化 oauth.authorization_grant 按 tenant_id 的关联与删除校验。';
COMMENT ON INDEX oauth.ix_fk_user_session_tenant_id IS '跨 Schema 外键前导索引：优化 oauth.user_session 按 tenant_id 的关联与删除校验。';
COMMENT ON INDEX oauth.ix_fk_token_family_tenant_id IS '跨 Schema 外键前导索引：优化 oauth.token_family 按 tenant_id 的关联与删除校验。';
COMMENT ON INDEX oauth.ix_fk_reference_access_token_tenant_id IS '跨 Schema 外键前导索引：优化 oauth.reference_access_token 按 tenant_id 的关联与删除校验。';
COMMENT ON INDEX oauth.ix_fk_revocation_record_tenant_id IS '跨 Schema 外键前导索引：优化 oauth.revocation_record 按 tenant_id 的关联与删除校验。';
COMMENT ON INDEX oauth.ix_fk_client_profile_code_profile_version IS '跨 Schema 外键前导索引：优化 oauth.client 按 profile_code、profile_version 的关联与删除校验。';
COMMENT ON INDEX oauth.ix_fk_scope_definition_data_classification IS '跨 Schema 外键前导索引：优化 oauth.scope_definition 按 data_classification 的关联与删除校验。';
COMMENT ON INDEX oauth.ix_fk_authorization_grant_login_transaction_id IS '跨 Schema 外键前导索引：优化 oauth.authorization_grant 按 login_transaction_id 的关联与删除校验。';
COMMENT ON INDEX oauth.ix_fk_authorization_code_user_id IS '跨 Schema 外键前导索引：优化 oauth.authorization_code 按 user_id 的关联与删除校验。';
COMMENT ON INDEX oauth.ix_fk_logout_request_user_id IS '跨 Schema 外键前导索引：优化 oauth.logout_request 按 user_id 的关联与删除校验。';
COMMENT ON INDEX oauth.ix_fk_application_business_line_id IS '跨 Schema 外键前导索引：优化 oauth.application 按 business_line_id 的关联与删除校验。';
COMMENT ON INDEX oauth.ix_fk_client_business_line_id IS '跨 Schema 外键前导索引：优化 oauth.client 按 business_line_id 的关联与删除校验。';
COMMENT ON INDEX oauth.ix_fk_api_resource_business_line_id IS '跨 Schema 外键前导索引：优化 oauth.api_resource 按 business_line_id 的关联与删除校验。';
COMMENT ON INDEX oauth.ix_fk_authorization_grant_consent_id IS '跨 Schema 外键前导索引：优化 oauth.authorization_grant 按 consent_id 的关联与删除校验。';
COMMENT ON INDEX oauth.ix_fk_reference_access_token_consent_id IS '跨 Schema 外键前导索引：优化 oauth.reference_access_token 按 consent_id 的关联与删除校验。';
COMMENT ON INDEX oauth.ix_fk_client_approval_case_id IS '跨 Schema 外键前导索引：优化 oauth.client 按 approval_case_id 的关联与删除校验。';

COMMENT ON TRIGGER trg_client_binding_immutable ON oauth.client IS '跨 Schema 触发器：调用 control.fn_active_approval_binding_guard 保护发布、审批或安全绑定底线。';

SELECT core.fn_register_migration('baseline:oauth:links', 'oauth Schema 跨域约束与绑定');
COMMIT;
\endif

