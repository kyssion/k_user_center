-- =============================================================================
-- baseline/schemas/audit/links.sql
-- audit 源表拥有的最终跨 Schema 外键、绑定触发器、支撑索引及 COMMENT
-- PostgreSQL 16+；应用技术栈：.NET 10 + SqlSugar
-- =============================================================================

\set ON_ERROR_STOP on

SELECT (NOT EXISTS (SELECT 1 FROM core.schema_migration WHERE version = 'baseline:audit:links'))::text AS kuc_run_links \gset
\if :kuc_run_links
BEGIN;
SET LOCAL lock_timeout = '10s';
SET LOCAL statement_timeout = '5min';

ALTER TABLE audit.audit_event
    ADD CONSTRAINT fk_audit_event_tenant FOREIGN KEY (tenant_id) REFERENCES org.tenant(id),
    ADD CONSTRAINT fk_audit_event_approval FOREIGN KEY (approval_case_id) REFERENCES control.approval_case(id),
    ADD CONSTRAINT fk_audit_event_decision FOREIGN KEY (decision_id) REFERENCES authz.authorization_decision(id),
    ADD CONSTRAINT fk_audit_event_class FOREIGN KEY (classification_code) REFERENCES core.data_classification(classification_code);

ALTER TABLE audit.data_access_event
    ADD CONSTRAINT fk_data_access_tenant FOREIGN KEY (tenant_id) REFERENCES org.tenant(id),
    ADD CONSTRAINT fk_data_access_decision FOREIGN KEY (decision_id) REFERENCES authz.authorization_decision(id);

CREATE INDEX ix_fk_audit_event_tenant_id ON audit.audit_event (tenant_id);

CREATE INDEX ix_fk_data_access_event_tenant_id ON audit.data_access_event (tenant_id);

CREATE INDEX ix_fk_audit_event_approval_case_id ON audit.audit_event (approval_case_id);

CREATE INDEX ix_fk_audit_event_decision_id ON audit.audit_event (decision_id);

CREATE INDEX ix_fk_audit_event_classification_code ON audit.audit_event (classification_code);

CREATE INDEX ix_fk_data_access_event_decision_id ON audit.data_access_event (decision_id);

COMMENT ON CONSTRAINT fk_audit_event_tenant ON audit.audit_event IS '外键约束：audit.audit_event 的 tenant_id 必须引用 org.tenant；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT fk_data_access_tenant ON audit.data_access_event IS '外键约束：audit.data_access_event 的 tenant_id 必须引用 org.tenant；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT fk_audit_event_approval ON audit.audit_event IS '外键约束：audit.audit_event 的 approval_case_id 必须引用 control.approval_case；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT fk_audit_event_decision ON audit.audit_event IS '外键约束：audit.audit_event 的 decision_id 必须引用 authz.authorization_decision；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT fk_audit_event_class ON audit.audit_event IS '外键约束：audit.audit_event 的 classification_code 必须引用 core.data_classification；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT fk_data_access_decision ON audit.data_access_event IS '外键约束：audit.data_access_event 的 decision_id 必须引用 authz.authorization_decision；级联行为以约束定义为准。';

COMMENT ON INDEX audit.ix_fk_audit_event_tenant_id IS '跨 Schema 外键前导索引：优化 audit.audit_event 按 tenant_id 的关联与删除校验。';
COMMENT ON INDEX audit.ix_fk_data_access_event_tenant_id IS '跨 Schema 外键前导索引：优化 audit.data_access_event 按 tenant_id 的关联与删除校验。';
COMMENT ON INDEX audit.ix_fk_audit_event_approval_case_id IS '跨 Schema 外键前导索引：优化 audit.audit_event 按 approval_case_id 的关联与删除校验。';
COMMENT ON INDEX audit.ix_fk_audit_event_decision_id IS '跨 Schema 外键前导索引：优化 audit.audit_event 按 decision_id 的关联与删除校验。';
COMMENT ON INDEX audit.ix_fk_audit_event_classification_code IS '跨 Schema 外键前导索引：优化 audit.audit_event 按 classification_code 的关联与删除校验。';
COMMENT ON INDEX audit.ix_fk_data_access_event_decision_id IS '跨 Schema 外键前导索引：优化 audit.data_access_event 按 decision_id 的关联与删除校验。';

SELECT core.fn_register_migration('baseline:audit:links', 'audit Schema 跨域约束与绑定');
COMMIT;
\endif

