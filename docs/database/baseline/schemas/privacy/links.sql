-- =============================================================================
-- baseline/schemas/privacy/links.sql
-- privacy 源表拥有的最终跨 Schema 外键、绑定触发器、支撑索引及 COMMENT
-- PostgreSQL 16+；应用技术栈：.NET 10 + SqlSugar
-- =============================================================================

\set ON_ERROR_STOP on

SELECT (NOT EXISTS (SELECT 1 FROM core.schema_migration WHERE version = 'baseline:privacy:links'))::text AS kuc_run_links \gset
\if :kuc_run_links
BEGIN;
SET LOCAL lock_timeout = '10s';
SET LOCAL statement_timeout = '5min';

ALTER TABLE privacy.agreement_acceptance
    ADD CONSTRAINT fk_agreement_acceptance_tenant FOREIGN KEY (tenant_id) REFERENCES org.tenant(id),
    ADD CONSTRAINT fk_agreement_acceptance_user FOREIGN KEY (user_id) REFERENCES iam.user_account(id),
    ADD CONSTRAINT fk_agreement_acceptance_client FOREIGN KEY (client_id) REFERENCES oauth.client(id);

ALTER TABLE privacy.consent_aggregate
    ADD CONSTRAINT fk_consent_aggregate_tenant FOREIGN KEY (tenant_id) REFERENCES org.tenant(id),
    ADD CONSTRAINT fk_consent_aggregate_user FOREIGN KEY (user_id) REFERENCES iam.user_account(id);

ALTER TABLE privacy.data_category
    ADD CONSTRAINT fk_data_category_class FOREIGN KEY (classification_code) REFERENCES core.data_classification(classification_code);

ALTER TABLE privacy.consent
    ADD CONSTRAINT fk_consent_client FOREIGN KEY (source_client_id) REFERENCES oauth.client(id),
    ADD CONSTRAINT fk_consent_login_tx FOREIGN KEY (source_login_transaction_id) REFERENCES authn.login_transaction(id);

ALTER TABLE privacy.marketing_subscription
    ADD CONSTRAINT fk_marketing_subscription_user FOREIGN KEY (user_id) REFERENCES iam.user_account(id);

ALTER TABLE privacy.privacy_request
    ADD CONSTRAINT fk_privacy_request_user FOREIGN KEY (user_id) REFERENCES iam.user_account(id),
    ADD CONSTRAINT fk_privacy_request_operation FOREIGN KEY (operation_id) REFERENCES core.async_operation(id),
    ADD CONSTRAINT fk_privacy_request_tx FOREIGN KEY (identity_verification_tx_id) REFERENCES authn.login_transaction(id);

ALTER TABLE privacy.export_job
    ADD CONSTRAINT fk_export_job_class FOREIGN KEY (classification_code) REFERENCES core.data_classification(classification_code);

ALTER TABLE privacy.minor_protection
    ADD CONSTRAINT fk_minor_protection_user FOREIGN KEY (minor_user_id) REFERENCES iam.user_account(id),
    ADD CONSTRAINT fk_minor_protection_guardian FOREIGN KEY (guardian_user_id) REFERENCES iam.user_account(id),
    ADD CONSTRAINT fk_minor_protection_delegation FOREIGN KEY (guardian_delegation_id) REFERENCES assurance.delegation(id);

ALTER TABLE privacy.retention_rule
    ADD CONSTRAINT fk_retention_rule_approval FOREIGN KEY (approval_case_id) REFERENCES control.approval_case(id);

ALTER TABLE privacy.cross_border_authorization
    ADD CONSTRAINT fk_cross_border_approval FOREIGN KEY (approval_case_id) REFERENCES control.approval_case(id);

ALTER TABLE privacy.privacy_impact_assessment
    ADD CONSTRAINT fk_pia_approval FOREIGN KEY (approval_case_id) REFERENCES control.approval_case(id);

CREATE INDEX ix_fk_agreement_acceptance_tenant_id ON privacy.agreement_acceptance (tenant_id);

CREATE INDEX ix_fk_consent_aggregate_tenant_id ON privacy.consent_aggregate (tenant_id);

CREATE INDEX ix_fk_data_category_classification_code ON privacy.data_category (classification_code);

CREATE INDEX ix_fk_agreement_acceptance_user_id ON privacy.agreement_acceptance (user_id);

CREATE INDEX ix_fk_agreement_acceptance_client_id ON privacy.agreement_acceptance (client_id);

CREATE INDEX ix_fk_consent_source_client_id ON privacy.consent (source_client_id);

CREATE INDEX ix_fk_consent_source_login_transaction_id ON privacy.consent (source_login_transaction_id);

CREATE INDEX ix_fk_privacy_request_identity_verification_tx_id ON privacy.privacy_request (identity_verification_tx_id);

CREATE INDEX ix_fk_export_job_classification_code ON privacy.export_job (classification_code);

CREATE INDEX ix_fk_minor_protection_guardian_user_id ON privacy.minor_protection (guardian_user_id);

CREATE INDEX ix_fk_retention_rule_approval_case_id ON privacy.retention_rule (approval_case_id);

CREATE INDEX ix_fk_cross_border_authorization_approval_case_id ON privacy.cross_border_authorization (approval_case_id);

CREATE INDEX ix_fk_privacy_impact_assessment_approval_case_id ON privacy.privacy_impact_assessment (approval_case_id);

CREATE INDEX ix_fk_minor_protection_guardian_delegation_id ON privacy.minor_protection (guardian_delegation_id);

COMMENT ON CONSTRAINT fk_agreement_acceptance_tenant ON privacy.agreement_acceptance IS '外键约束：privacy.agreement_acceptance 的 tenant_id 必须引用 org.tenant；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT fk_consent_aggregate_tenant ON privacy.consent_aggregate IS '外键约束：privacy.consent_aggregate 的 tenant_id 必须引用 org.tenant；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT fk_data_category_class ON privacy.data_category IS '外键约束：privacy.data_category 的 classification_code 必须引用 core.data_classification；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT fk_agreement_acceptance_user ON privacy.agreement_acceptance IS '外键约束：privacy.agreement_acceptance 的 user_id 必须引用 iam.user_account；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT fk_agreement_acceptance_client ON privacy.agreement_acceptance IS '外键约束：privacy.agreement_acceptance 的 client_id 必须引用 oauth.client；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT fk_consent_aggregate_user ON privacy.consent_aggregate IS '外键约束：privacy.consent_aggregate 的 user_id 必须引用 iam.user_account；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT fk_consent_client ON privacy.consent IS '外键约束：privacy.consent 的 source_client_id 必须引用 oauth.client；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT fk_consent_login_tx ON privacy.consent IS '外键约束：privacy.consent 的 source_login_transaction_id 必须引用 authn.login_transaction；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT fk_marketing_subscription_user ON privacy.marketing_subscription IS '外键约束：privacy.marketing_subscription 的 user_id 必须引用 iam.user_account；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT fk_privacy_request_user ON privacy.privacy_request IS '外键约束：privacy.privacy_request 的 user_id 必须引用 iam.user_account；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT fk_privacy_request_operation ON privacy.privacy_request IS '外键约束：privacy.privacy_request 的 operation_id 必须引用 core.async_operation；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT fk_privacy_request_tx ON privacy.privacy_request IS '外键约束：privacy.privacy_request 的 identity_verification_tx_id 必须引用 authn.login_transaction；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT fk_export_job_class ON privacy.export_job IS '外键约束：privacy.export_job 的 classification_code 必须引用 core.data_classification；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT fk_minor_protection_user ON privacy.minor_protection IS '外键约束：privacy.minor_protection 的 minor_user_id 必须引用 iam.user_account；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT fk_minor_protection_guardian ON privacy.minor_protection IS '外键约束：privacy.minor_protection 的 guardian_user_id 必须引用 iam.user_account；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT fk_retention_rule_approval ON privacy.retention_rule IS '外键约束：privacy.retention_rule 的 approval_case_id 必须引用 control.approval_case；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT fk_cross_border_approval ON privacy.cross_border_authorization IS '外键约束：privacy.cross_border_authorization 的 approval_case_id 必须引用 control.approval_case；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT fk_pia_approval ON privacy.privacy_impact_assessment IS '外键约束：privacy.privacy_impact_assessment 的 approval_case_id 必须引用 control.approval_case；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT fk_minor_protection_delegation ON privacy.minor_protection IS '外键约束：privacy.minor_protection 的 guardian_delegation_id 必须引用 assurance.delegation；级联行为以约束定义为准。';

COMMENT ON INDEX privacy.ix_fk_agreement_acceptance_tenant_id IS '跨 Schema 外键前导索引：优化 privacy.agreement_acceptance 按 tenant_id 的关联与删除校验。';
COMMENT ON INDEX privacy.ix_fk_consent_aggregate_tenant_id IS '跨 Schema 外键前导索引：优化 privacy.consent_aggregate 按 tenant_id 的关联与删除校验。';
COMMENT ON INDEX privacy.ix_fk_data_category_classification_code IS '跨 Schema 外键前导索引：优化 privacy.data_category 按 classification_code 的关联与删除校验。';
COMMENT ON INDEX privacy.ix_fk_agreement_acceptance_user_id IS '跨 Schema 外键前导索引：优化 privacy.agreement_acceptance 按 user_id 的关联与删除校验。';
COMMENT ON INDEX privacy.ix_fk_agreement_acceptance_client_id IS '跨 Schema 外键前导索引：优化 privacy.agreement_acceptance 按 client_id 的关联与删除校验。';
COMMENT ON INDEX privacy.ix_fk_consent_source_client_id IS '跨 Schema 外键前导索引：优化 privacy.consent 按 source_client_id 的关联与删除校验。';
COMMENT ON INDEX privacy.ix_fk_consent_source_login_transaction_id IS '跨 Schema 外键前导索引：优化 privacy.consent 按 source_login_transaction_id 的关联与删除校验。';
COMMENT ON INDEX privacy.ix_fk_privacy_request_identity_verification_tx_id IS '跨 Schema 外键前导索引：优化 privacy.privacy_request 按 identity_verification_tx_id 的关联与删除校验。';
COMMENT ON INDEX privacy.ix_fk_export_job_classification_code IS '跨 Schema 外键前导索引：优化 privacy.export_job 按 classification_code 的关联与删除校验。';
COMMENT ON INDEX privacy.ix_fk_minor_protection_guardian_user_id IS '跨 Schema 外键前导索引：优化 privacy.minor_protection 按 guardian_user_id 的关联与删除校验。';
COMMENT ON INDEX privacy.ix_fk_retention_rule_approval_case_id IS '跨 Schema 外键前导索引：优化 privacy.retention_rule 按 approval_case_id 的关联与删除校验。';
COMMENT ON INDEX privacy.ix_fk_cross_border_authorization_approval_case_id IS '跨 Schema 外键前导索引：优化 privacy.cross_border_authorization 按 approval_case_id 的关联与删除校验。';
COMMENT ON INDEX privacy.ix_fk_privacy_impact_assessment_approval_case_id IS '跨 Schema 外键前导索引：优化 privacy.privacy_impact_assessment 按 approval_case_id 的关联与删除校验。';
COMMENT ON INDEX privacy.ix_fk_minor_protection_guardian_delegation_id IS '跨 Schema 外键前导索引：优化 privacy.minor_protection 按 guardian_delegation_id 的关联与删除校验。';

SELECT core.fn_register_migration('baseline:privacy:links', 'privacy Schema 跨域约束与绑定');
COMMIT;
\endif

