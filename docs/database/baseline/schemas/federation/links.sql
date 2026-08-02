-- =============================================================================
-- baseline/schemas/federation/links.sql
-- federation 源表拥有的最终跨 Schema 外键、绑定触发器、支撑索引及 COMMENT
-- PostgreSQL 16+；应用技术栈：.NET 10 + SqlSugar
-- =============================================================================

\set ON_ERROR_STOP on

SELECT (NOT EXISTS (SELECT 1 FROM core.schema_migration WHERE version = 'baseline:federation:links'))::text AS kuc_run_links \gset
\if :kuc_run_links
BEGIN;
SET LOCAL lock_timeout = '10s';
SET LOCAL statement_timeout = '5min';

ALTER TABLE federation.identity_provider
    ADD CONSTRAINT fk_identity_provider_tenant FOREIGN KEY (tenant_id) REFERENCES org.tenant(id),
    ADD CONSTRAINT fk_identity_provider_approval FOREIGN KEY (approval_case_id) REFERENCES control.approval_case(id);

ALTER TABLE federation.external_identity
    ADD CONSTRAINT fk_external_identity_user FOREIGN KEY (user_id) REFERENCES iam.user_account(id);

ALTER TABLE federation.directory_connection
    ADD CONSTRAINT fk_directory_connection_tenant FOREIGN KEY (tenant_id) REFERENCES org.tenant(id);

ALTER TABLE federation.directory_sync_run
    ADD CONSTRAINT fk_directory_sync_run_operation FOREIGN KEY (operation_id) REFERENCES core.async_operation(id);

ALTER TABLE federation.federation_migration
    ADD CONSTRAINT fk_federation_migration_tenant FOREIGN KEY (tenant_id) REFERENCES org.tenant(id),
    ADD CONSTRAINT fk_federation_migration_operation FOREIGN KEY (operation_id) REFERENCES core.async_operation(id);

CREATE TRIGGER trg_identity_provider_binding_immutable BEFORE UPDATE ON federation.identity_provider FOR EACH ROW
    EXECUTE FUNCTION control.fn_active_approval_binding_guard('provider_state', 'ACTIVE', 'approval_case_id', 'approval_execution_id');

CREATE INDEX ix_fk_directory_connection_tenant_id ON federation.directory_connection (tenant_id);

CREATE INDEX ix_fk_federation_migration_tenant_id ON federation.federation_migration (tenant_id);

CREATE INDEX ix_fk_identity_provider_approval_case_id ON federation.identity_provider (approval_case_id);

COMMENT ON CONSTRAINT fk_identity_provider_tenant ON federation.identity_provider IS '外键约束：federation.identity_provider 的 tenant_id 必须引用 org.tenant；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT fk_external_identity_user ON federation.external_identity IS '外键约束：federation.external_identity 的 user_id 必须引用 iam.user_account；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT fk_directory_connection_tenant ON federation.directory_connection IS '外键约束：federation.directory_connection 的 tenant_id 必须引用 org.tenant；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT fk_directory_sync_run_operation ON federation.directory_sync_run IS '外键约束：federation.directory_sync_run 的 operation_id 必须引用 core.async_operation；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT fk_federation_migration_tenant ON federation.federation_migration IS '外键约束：federation.federation_migration 的 tenant_id 必须引用 org.tenant；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT fk_federation_migration_operation ON federation.federation_migration IS '外键约束：federation.federation_migration 的 operation_id 必须引用 core.async_operation；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT fk_identity_provider_approval ON federation.identity_provider IS '外键约束：federation.identity_provider 的 approval_case_id 必须引用 control.approval_case；级联行为以约束定义为准。';

COMMENT ON INDEX federation.ix_fk_directory_connection_tenant_id IS '跨 Schema 外键前导索引：优化 federation.directory_connection 按 tenant_id 的关联与删除校验。';
COMMENT ON INDEX federation.ix_fk_federation_migration_tenant_id IS '跨 Schema 外键前导索引：优化 federation.federation_migration 按 tenant_id 的关联与删除校验。';
COMMENT ON INDEX federation.ix_fk_identity_provider_approval_case_id IS '跨 Schema 外键前导索引：优化 federation.identity_provider 按 approval_case_id 的关联与删除校验。';

COMMENT ON TRIGGER trg_identity_provider_binding_immutable ON federation.identity_provider IS '跨 Schema 触发器：调用 control.fn_active_approval_binding_guard 保护发布、审批或安全绑定底线。';

SELECT core.fn_register_migration('baseline:federation:links', 'federation Schema 跨域约束与绑定');
COMMIT;
\endif

