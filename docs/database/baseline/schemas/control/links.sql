-- =============================================================================
-- baseline/schemas/control/links.sql
-- control 源表拥有的最终跨 Schema 外键、绑定触发器、支撑索引及 COMMENT
-- PostgreSQL 16+；应用技术栈：.NET 10 + SqlSugar
-- =============================================================================

\set ON_ERROR_STOP on

SELECT (NOT EXISTS (SELECT 1 FROM core.schema_migration WHERE version = 'baseline:control:links'))::text AS kuc_run_links \gset
\if :kuc_run_links
BEGIN;
SET LOCAL lock_timeout = '10s';
SET LOCAL statement_timeout = '5min';

ALTER TABLE control.approval_case
    ADD CONSTRAINT fk_approval_case_tenant FOREIGN KEY (tenant_id) REFERENCES org.tenant(id);

ALTER TABLE control.break_glass_grant
    ADD CONSTRAINT fk_break_glass_tenant FOREIGN KEY (tenant_id) REFERENCES org.tenant(id),
    ADD CONSTRAINT fk_break_glass_user FOREIGN KEY (user_id) REFERENCES iam.user_account(id);

ALTER TABLE control.security_exception
    ADD CONSTRAINT fk_security_exception_tenant FOREIGN KEY (tenant_id) REFERENCES org.tenant(id);

ALTER TABLE control.client_certification_run
    ADD CONSTRAINT fk_client_certification_client FOREIGN KEY (client_id) REFERENCES oauth.client(id),
    ADD CONSTRAINT fk_client_certification_operation FOREIGN KEY (operation_id) REFERENCES core.async_operation(id),
    ADD CONSTRAINT fk_client_certification_profile FOREIGN KEY (profile_code, profile_version) REFERENCES core.security_profile(profile_code, profile_version);

CREATE INDEX ix_fk_approval_case_tenant_id ON control.approval_case (tenant_id);

CREATE INDEX ix_fk_break_glass_grant_tenant_id ON control.break_glass_grant (tenant_id);

CREATE INDEX ix_fk_security_exception_tenant_id ON control.security_exception (tenant_id);

CREATE INDEX ix_fk_break_glass_grant_user_id ON control.break_glass_grant (user_id);

CREATE INDEX ix_fk_client_certification_run_client_id ON control.client_certification_run (client_id);

CREATE INDEX ix_fk_client_certification_run_profile_code_profile_version ON control.client_certification_run (profile_code, profile_version);

COMMENT ON CONSTRAINT fk_approval_case_tenant ON control.approval_case IS '外键约束：control.approval_case 的 tenant_id 必须引用 org.tenant；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT fk_break_glass_tenant ON control.break_glass_grant IS '外键约束：control.break_glass_grant 的 tenant_id 必须引用 org.tenant；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT fk_security_exception_tenant ON control.security_exception IS '外键约束：control.security_exception 的 tenant_id 必须引用 org.tenant；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT fk_break_glass_user ON control.break_glass_grant IS '外键约束：control.break_glass_grant 的 user_id 必须引用 iam.user_account；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT fk_client_certification_client ON control.client_certification_run IS '外键约束：control.client_certification_run 的 client_id 必须引用 oauth.client；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT fk_client_certification_operation ON control.client_certification_run IS '外键约束：control.client_certification_run 的 operation_id 必须引用 core.async_operation；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT fk_client_certification_profile ON control.client_certification_run IS '外键约束：control.client_certification_run 的 profile_code、profile_version 必须引用 core.security_profile；级联行为以约束定义为准。';

COMMENT ON INDEX control.ix_fk_approval_case_tenant_id IS '跨 Schema 外键前导索引：优化 control.approval_case 按 tenant_id 的关联与删除校验。';
COMMENT ON INDEX control.ix_fk_break_glass_grant_tenant_id IS '跨 Schema 外键前导索引：优化 control.break_glass_grant 按 tenant_id 的关联与删除校验。';
COMMENT ON INDEX control.ix_fk_security_exception_tenant_id IS '跨 Schema 外键前导索引：优化 control.security_exception 按 tenant_id 的关联与删除校验。';
COMMENT ON INDEX control.ix_fk_break_glass_grant_user_id IS '跨 Schema 外键前导索引：优化 control.break_glass_grant 按 user_id 的关联与删除校验。';
COMMENT ON INDEX control.ix_fk_client_certification_run_client_id IS '跨 Schema 外键前导索引：优化 control.client_certification_run 按 client_id 的关联与删除校验。';
COMMENT ON INDEX control.ix_fk_client_certification_run_profile_code_profile_version IS '跨 Schema 外键前导索引：优化 control.client_certification_run 按 profile_code、profile_version 的关联与删除校验。';

SELECT core.fn_register_migration('baseline:control:links', 'control Schema 跨域约束与绑定');
COMMIT;
\endif

