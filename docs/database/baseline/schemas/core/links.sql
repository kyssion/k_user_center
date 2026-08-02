-- =============================================================================
-- baseline/schemas/core/links.sql
-- core 源表拥有的最终跨 Schema 外键、绑定触发器、支撑索引及 COMMENT
-- PostgreSQL 16+；应用技术栈：.NET 10 + SqlSugar
-- =============================================================================

\set ON_ERROR_STOP on

SELECT (NOT EXISTS (SELECT 1 FROM core.schema_migration WHERE version = 'baseline:core:links'))::text AS kuc_run_links \gset
\if :kuc_run_links
BEGIN;
SET LOCAL lock_timeout = '10s';
SET LOCAL statement_timeout = '5min';

ALTER TABLE core.async_operation
    ADD CONSTRAINT fk_async_operation_tenant FOREIGN KEY (tenant_id) REFERENCES org.tenant(id);

ALTER TABLE core.idempotency_request
    ADD CONSTRAINT fk_idempotency_tenant FOREIGN KEY (tenant_id) REFERENCES org.tenant(id);

ALTER TABLE core.requirement_trace
    ADD CONSTRAINT fk_requirement_trace_exception FOREIGN KEY (exception_id) REFERENCES control.security_exception(id);

CREATE INDEX ix_fk_idempotency_request_tenant_id ON core.idempotency_request (tenant_id);

CREATE INDEX ix_fk_requirement_trace_exception_id ON core.requirement_trace (exception_id);

COMMENT ON CONSTRAINT fk_async_operation_tenant ON core.async_operation IS '外键约束：core.async_operation 的 tenant_id 必须引用 org.tenant；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT fk_idempotency_tenant ON core.idempotency_request IS '外键约束：core.idempotency_request 的 tenant_id 必须引用 org.tenant；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT fk_requirement_trace_exception ON core.requirement_trace IS '外键约束：core.requirement_trace 的 exception_id 必须引用 control.security_exception；级联行为以约束定义为准。';

COMMENT ON INDEX core.ix_fk_idempotency_request_tenant_id IS '跨 Schema 外键前导索引：优化 core.idempotency_request 按 tenant_id 的关联与删除校验。';
COMMENT ON INDEX core.ix_fk_requirement_trace_exception_id IS '跨 Schema 外键前导索引：优化 core.requirement_trace 按 exception_id 的关联与删除校验。';

SELECT core.fn_register_migration('baseline:core:links', 'core Schema 跨域约束与绑定');
COMMIT;
\endif

