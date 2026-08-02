-- =============================================================================
-- baseline/schemas/authz/links.sql
-- authz 源表拥有的最终跨 Schema 外键、绑定触发器、支撑索引及 COMMENT
-- PostgreSQL 16+；应用技术栈：.NET 10 + SqlSugar
-- =============================================================================

\set ON_ERROR_STOP on

SELECT (NOT EXISTS (SELECT 1 FROM core.schema_migration WHERE version = 'baseline:authz:links'))::text AS kuc_run_links \gset
\if :kuc_run_links
BEGIN;
SET LOCAL lock_timeout = '10s';
SET LOCAL statement_timeout = '5min';

ALTER TABLE authz.role
    ADD CONSTRAINT fk_role_organization FOREIGN KEY (organization_id, tenant_id) REFERENCES org.organization(id, tenant_id),
    ADD CONSTRAINT fk_role_tenant_business FOREIGN KEY (tenant_id, business_line_id) REFERENCES org.tenant(id, business_line_id),
    ADD CONSTRAINT fk_role_business_line FOREIGN KEY (business_line_id) REFERENCES org.business_line(id),
    ADD CONSTRAINT fk_role_tenant FOREIGN KEY (tenant_id) REFERENCES org.tenant(id);

ALTER TABLE authz.authorization_decision
    ADD CONSTRAINT fk_authz_decision_tenant FOREIGN KEY (tenant_id) REFERENCES org.tenant(id);

ALTER TABLE authz.relationship_tuple
    ADD CONSTRAINT fk_relationship_tenant FOREIGN KEY (tenant_id) REFERENCES org.tenant(id);

ALTER TABLE authz.role_assignment
    ADD CONSTRAINT fk_role_assignment_business_line FOREIGN KEY (business_line_id) REFERENCES org.business_line(id),
    ADD CONSTRAINT fk_role_assignment_tenant FOREIGN KEY (tenant_id) REFERENCES org.tenant(id),
    ADD CONSTRAINT fk_role_assignment_org FOREIGN KEY (organization_id) REFERENCES org.organization(id),
    ADD CONSTRAINT fk_role_assignment_approval FOREIGN KEY (approval_case_id) REFERENCES control.approval_case(id);

ALTER TABLE authz.access_review
    ADD CONSTRAINT fk_access_review_operation FOREIGN KEY (operation_id) REFERENCES core.async_operation(id);

ALTER TABLE authz.policy_release
    ADD CONSTRAINT fk_policy_release_approval FOREIGN KEY (approval_case_id) REFERENCES control.approval_case(id);

CREATE TRIGGER trg_policy_release_guard BEFORE UPDATE ON authz.policy_release FOR EACH ROW
    EXECUTE FUNCTION control.fn_release_guard('policy_state', 'activated_at', 'retired_at', 'revoked_at',
        'approval_case_id', 'approval_execution_id');

CREATE TRIGGER trg_policy_release_binding_immutable BEFORE UPDATE ON authz.policy_release FOR EACH ROW
    EXECUTE FUNCTION control.fn_active_approval_binding_guard('policy_state', 'ACTIVE', 'approval_case_id', 'approval_execution_id');

CREATE INDEX ix_fk_role_organization_id_tenant_id ON authz.role (organization_id, tenant_id);

CREATE INDEX ix_fk_role_tenant_id_business_line_id ON authz.role (tenant_id, business_line_id);

CREATE INDEX ix_fk_authorization_decision_tenant_id ON authz.authorization_decision (tenant_id);

CREATE INDEX ix_fk_relationship_tuple_tenant_id ON authz.relationship_tuple (tenant_id);

CREATE INDEX ix_fk_role_business_line_id ON authz.role (business_line_id);

CREATE INDEX ix_fk_role_assignment_business_line_id ON authz.role_assignment (business_line_id);

CREATE INDEX ix_fk_role_assignment_tenant_id ON authz.role_assignment (tenant_id);

CREATE INDEX ix_fk_role_assignment_organization_id ON authz.role_assignment (organization_id);

CREATE INDEX ix_fk_role_assignment_approval_case_id ON authz.role_assignment (approval_case_id);

CREATE INDEX ix_fk_policy_release_approval_case_id ON authz.policy_release (approval_case_id);

COMMENT ON CONSTRAINT fk_role_organization ON authz.role IS '外键约束：authz.role 的 organization_id、tenant_id 必须引用 org.organization；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT fk_role_tenant_business ON authz.role IS '外键约束：authz.role 的 tenant_id、business_line_id 必须引用 org.tenant；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT fk_authz_decision_tenant ON authz.authorization_decision IS '外键约束：authz.authorization_decision 的 tenant_id 必须引用 org.tenant；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT fk_relationship_tenant ON authz.relationship_tuple IS '外键约束：authz.relationship_tuple 的 tenant_id 必须引用 org.tenant；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT fk_role_business_line ON authz.role IS '外键约束：authz.role 的 business_line_id 必须引用 org.business_line；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT fk_role_tenant ON authz.role IS '外键约束：authz.role 的 tenant_id 必须引用 org.tenant；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT fk_role_assignment_business_line ON authz.role_assignment IS '外键约束：authz.role_assignment 的 business_line_id 必须引用 org.business_line；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT fk_role_assignment_tenant ON authz.role_assignment IS '外键约束：authz.role_assignment 的 tenant_id 必须引用 org.tenant；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT fk_role_assignment_org ON authz.role_assignment IS '外键约束：authz.role_assignment 的 organization_id 必须引用 org.organization；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT fk_access_review_operation ON authz.access_review IS '外键约束：authz.access_review 的 operation_id 必须引用 core.async_operation；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT fk_role_assignment_approval ON authz.role_assignment IS '外键约束：authz.role_assignment 的 approval_case_id 必须引用 control.approval_case；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT fk_policy_release_approval ON authz.policy_release IS '外键约束：authz.policy_release 的 approval_case_id 必须引用 control.approval_case；级联行为以约束定义为准。';

COMMENT ON INDEX authz.ix_fk_role_organization_id_tenant_id IS '跨 Schema 外键前导索引：优化 authz.role 按 organization_id、tenant_id 的关联与删除校验。';
COMMENT ON INDEX authz.ix_fk_role_tenant_id_business_line_id IS '跨 Schema 外键前导索引：优化 authz.role 按 tenant_id、business_line_id 的关联与删除校验。';
COMMENT ON INDEX authz.ix_fk_authorization_decision_tenant_id IS '跨 Schema 外键前导索引：优化 authz.authorization_decision 按 tenant_id 的关联与删除校验。';
COMMENT ON INDEX authz.ix_fk_relationship_tuple_tenant_id IS '跨 Schema 外键前导索引：优化 authz.relationship_tuple 按 tenant_id 的关联与删除校验。';
COMMENT ON INDEX authz.ix_fk_role_business_line_id IS '跨 Schema 外键前导索引：优化 authz.role 按 business_line_id 的关联与删除校验。';
COMMENT ON INDEX authz.ix_fk_role_assignment_business_line_id IS '跨 Schema 外键前导索引：优化 authz.role_assignment 按 business_line_id 的关联与删除校验。';
COMMENT ON INDEX authz.ix_fk_role_assignment_tenant_id IS '跨 Schema 外键前导索引：优化 authz.role_assignment 按 tenant_id 的关联与删除校验。';
COMMENT ON INDEX authz.ix_fk_role_assignment_organization_id IS '跨 Schema 外键前导索引：优化 authz.role_assignment 按 organization_id 的关联与删除校验。';
COMMENT ON INDEX authz.ix_fk_role_assignment_approval_case_id IS '跨 Schema 外键前导索引：优化 authz.role_assignment 按 approval_case_id 的关联与删除校验。';
COMMENT ON INDEX authz.ix_fk_policy_release_approval_case_id IS '跨 Schema 外键前导索引：优化 authz.policy_release 按 approval_case_id 的关联与删除校验。';

COMMENT ON TRIGGER trg_policy_release_guard ON authz.policy_release IS '跨 Schema 触发器：调用 control.fn_release_guard 保护发布、审批或安全绑定底线。';

COMMENT ON TRIGGER trg_policy_release_binding_immutable ON authz.policy_release IS '跨 Schema 触发器：调用 control.fn_active_approval_binding_guard 保护发布、审批或安全绑定底线。';

SELECT core.fn_register_migration('baseline:authz:links', 'authz Schema 跨域约束与绑定');
COMMIT;
\endif

