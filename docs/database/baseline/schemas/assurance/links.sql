-- =============================================================================
-- baseline/schemas/assurance/links.sql
-- assurance 源表拥有的最终跨 Schema 外键、绑定触发器、支撑索引及 COMMENT
-- PostgreSQL 16+；应用技术栈：.NET 10 + SqlSugar
-- =============================================================================

\set ON_ERROR_STOP on

SELECT (NOT EXISTS (SELECT 1 FROM core.schema_migration WHERE version = 'baseline:assurance:links'))::text AS kuc_run_links \gset
\if :kuc_run_links
BEGIN;
SET LOCAL lock_timeout = '10s';
SET LOCAL statement_timeout = '5min';

ALTER TABLE assurance.identity_assurance_assertion
    ADD CONSTRAINT fk_identity_assurance_user FOREIGN KEY (user_id) REFERENCES iam.user_account(id);

ALTER TABLE assurance.recovery_request
    ADD CONSTRAINT fk_recovery_request_user FOREIGN KEY (user_id) REFERENCES iam.user_account(id),
    ADD CONSTRAINT fk_recovery_request_operation FOREIGN KEY (operation_id) REFERENCES core.async_operation(id),
    ADD CONSTRAINT fk_recovery_request_risk FOREIGN KEY (risk_assessment_id) REFERENCES risk.risk_assessment(id),
    ADD CONSTRAINT fk_recovery_request_approval FOREIGN KEY (approval_case_id) REFERENCES control.approval_case(id);

ALTER TABLE assurance.delegation
    ADD CONSTRAINT fk_delegation_subject FOREIGN KEY (subject_user_id) REFERENCES iam.user_account(id),
    ADD CONSTRAINT fk_delegation_actor FOREIGN KEY (actor_user_id) REFERENCES iam.user_account(id),
    ADD CONSTRAINT fk_delegation_tenant FOREIGN KEY (tenant_id) REFERENCES org.tenant(id),
    ADD CONSTRAINT fk_delegation_approval FOREIGN KEY (approval_case_id) REFERENCES control.approval_case(id),
    ADD CONSTRAINT fk_delegation_risk FOREIGN KEY (risk_assessment_id) REFERENCES risk.risk_assessment(id);

CREATE INDEX ix_fk_identity_assurance_assertion_user_id ON assurance.identity_assurance_assertion (user_id);

CREATE INDEX ix_fk_recovery_request_user_id ON assurance.recovery_request (user_id);

CREATE INDEX ix_fk_recovery_request_risk_assessment_id ON assurance.recovery_request (risk_assessment_id);

CREATE INDEX ix_fk_recovery_request_approval_case_id ON assurance.recovery_request (approval_case_id);

CREATE INDEX ix_fk_delegation_tenant_id ON assurance.delegation (tenant_id);

CREATE INDEX ix_fk_delegation_approval_case_id ON assurance.delegation (approval_case_id);

CREATE INDEX ix_fk_delegation_risk_assessment_id ON assurance.delegation (risk_assessment_id);

COMMENT ON CONSTRAINT fk_identity_assurance_user ON assurance.identity_assurance_assertion IS '外键约束：assurance.identity_assurance_assertion 的 user_id 必须引用 iam.user_account；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT fk_recovery_request_user ON assurance.recovery_request IS '外键约束：assurance.recovery_request 的 user_id 必须引用 iam.user_account；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT fk_recovery_request_operation ON assurance.recovery_request IS '外键约束：assurance.recovery_request 的 operation_id 必须引用 core.async_operation；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT fk_recovery_request_risk ON assurance.recovery_request IS '外键约束：assurance.recovery_request 的 risk_assessment_id 必须引用 risk.risk_assessment；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT fk_recovery_request_approval ON assurance.recovery_request IS '外键约束：assurance.recovery_request 的 approval_case_id 必须引用 control.approval_case；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT fk_delegation_subject ON assurance.delegation IS '外键约束：assurance.delegation 的 subject_user_id 必须引用 iam.user_account；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT fk_delegation_actor ON assurance.delegation IS '外键约束：assurance.delegation 的 actor_user_id 必须引用 iam.user_account；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT fk_delegation_tenant ON assurance.delegation IS '外键约束：assurance.delegation 的 tenant_id 必须引用 org.tenant；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT fk_delegation_approval ON assurance.delegation IS '外键约束：assurance.delegation 的 approval_case_id 必须引用 control.approval_case；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT fk_delegation_risk ON assurance.delegation IS '外键约束：assurance.delegation 的 risk_assessment_id 必须引用 risk.risk_assessment；级联行为以约束定义为准。';

COMMENT ON INDEX assurance.ix_fk_identity_assurance_assertion_user_id IS '跨 Schema 外键前导索引：优化 assurance.identity_assurance_assertion 按 user_id 的关联与删除校验。';
COMMENT ON INDEX assurance.ix_fk_recovery_request_user_id IS '跨 Schema 外键前导索引：优化 assurance.recovery_request 按 user_id 的关联与删除校验。';
COMMENT ON INDEX assurance.ix_fk_recovery_request_risk_assessment_id IS '跨 Schema 外键前导索引：优化 assurance.recovery_request 按 risk_assessment_id 的关联与删除校验。';
COMMENT ON INDEX assurance.ix_fk_recovery_request_approval_case_id IS '跨 Schema 外键前导索引：优化 assurance.recovery_request 按 approval_case_id 的关联与删除校验。';
COMMENT ON INDEX assurance.ix_fk_delegation_tenant_id IS '跨 Schema 外键前导索引：优化 assurance.delegation 按 tenant_id 的关联与删除校验。';
COMMENT ON INDEX assurance.ix_fk_delegation_approval_case_id IS '跨 Schema 外键前导索引：优化 assurance.delegation 按 approval_case_id 的关联与删除校验。';
COMMENT ON INDEX assurance.ix_fk_delegation_risk_assessment_id IS '跨 Schema 外键前导索引：优化 assurance.delegation 按 risk_assessment_id 的关联与删除校验。';

SELECT core.fn_register_migration('baseline:assurance:links', 'assurance Schema 跨域约束与绑定');
COMMIT;
\endif

