-- =============================================================================
-- baseline/schemas/migration/links.sql
-- migration 源表拥有的最终跨 Schema 外键、绑定触发器、支撑索引及 COMMENT
-- PostgreSQL 16+；应用技术栈：.NET 10 + SqlSugar
-- =============================================================================

\set ON_ERROR_STOP on

SELECT (NOT EXISTS (SELECT 1 FROM core.schema_migration WHERE version = 'baseline:migration:links'))::text AS kuc_run_links \gset
\if :kuc_run_links
BEGIN;
SET LOCAL lock_timeout = '10s';
SET LOCAL statement_timeout = '5min';

ALTER TABLE migration.migration_batch
    ADD CONSTRAINT fk_migration_batch_operation FOREIGN KEY (operation_id) REFERENCES core.async_operation(id);

ALTER TABLE migration.duplicate_candidate
    ADD CONSTRAINT fk_duplicate_candidate_approval FOREIGN KEY (approval_case_id) REFERENCES control.approval_case(id);

ALTER TABLE migration.reconciliation_run
    ADD CONSTRAINT fk_reconciliation_run_operation FOREIGN KEY (operation_id) REFERENCES core.async_operation(id);

ALTER TABLE migration.rollback_execution
    ADD CONSTRAINT fk_rollback_execution_operation FOREIGN KEY (operation_id) REFERENCES core.async_operation(id),
    ADD CONSTRAINT fk_rollback_execution_approval FOREIGN KEY (approval_case_id) REFERENCES control.approval_case(id);

CREATE INDEX ix_fk_duplicate_candidate_approval_case_id ON migration.duplicate_candidate (approval_case_id);

CREATE INDEX ix_fk_rollback_execution_approval_case_id ON migration.rollback_execution (approval_case_id);

COMMENT ON CONSTRAINT fk_migration_batch_operation ON migration.migration_batch IS '外键约束：migration.migration_batch 的 operation_id 必须引用 core.async_operation；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT fk_duplicate_candidate_approval ON migration.duplicate_candidate IS '外键约束：migration.duplicate_candidate 的 approval_case_id 必须引用 control.approval_case；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT fk_reconciliation_run_operation ON migration.reconciliation_run IS '外键约束：migration.reconciliation_run 的 operation_id 必须引用 core.async_operation；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT fk_rollback_execution_operation ON migration.rollback_execution IS '外键约束：migration.rollback_execution 的 operation_id 必须引用 core.async_operation；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT fk_rollback_execution_approval ON migration.rollback_execution IS '外键约束：migration.rollback_execution 的 approval_case_id 必须引用 control.approval_case；级联行为以约束定义为准。';

COMMENT ON INDEX migration.ix_fk_duplicate_candidate_approval_case_id IS '跨 Schema 外键前导索引：优化 migration.duplicate_candidate 按 approval_case_id 的关联与删除校验。';
COMMENT ON INDEX migration.ix_fk_rollback_execution_approval_case_id IS '跨 Schema 外键前导索引：优化 migration.rollback_execution 按 approval_case_id 的关联与删除校验。';

SELECT core.fn_register_migration('baseline:migration:links', 'migration Schema 跨域约束与绑定');
COMMIT;
\endif

