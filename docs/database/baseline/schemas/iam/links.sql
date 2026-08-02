-- =============================================================================
-- baseline/schemas/iam/links.sql
-- iam 源表拥有的最终跨 Schema 外键、绑定触发器、支撑索引及 COMMENT
-- PostgreSQL 16+；应用技术栈：.NET 10 + SqlSugar
-- =============================================================================

\set ON_ERROR_STOP on

SELECT (NOT EXISTS (SELECT 1 FROM core.schema_migration WHERE version = 'baseline:iam:links'))::text AS kuc_run_links \gset
\if :kuc_run_links
BEGIN;
SET LOCAL lock_timeout = '10s';
SET LOCAL statement_timeout = '5min';

ALTER TABLE iam.account_merge
    ADD CONSTRAINT fk_account_merge_operation FOREIGN KEY (operation_id) REFERENCES core.async_operation(id),
    ADD CONSTRAINT fk_account_merge_approval FOREIGN KEY (approval_case_id) REFERENCES control.approval_case(id);

ALTER TABLE iam.account_deletion
    ADD CONSTRAINT fk_account_deletion_operation FOREIGN KEY (operation_id) REFERENCES core.async_operation(id);

ALTER TABLE iam.user_account
    ADD CONSTRAINT fk_user_account_creation_client FOREIGN KEY (creation_client_id) REFERENCES oauth.client(id);

CREATE INDEX ix_fk_account_merge_operation_id ON iam.account_merge (operation_id);

CREATE INDEX ix_fk_user_account_creation_client_id ON iam.user_account (creation_client_id);

CREATE INDEX ix_fk_account_merge_approval_case_id ON iam.account_merge (approval_case_id);

COMMENT ON CONSTRAINT fk_account_merge_operation ON iam.account_merge IS '外键约束：iam.account_merge 的 operation_id 必须引用 core.async_operation；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT fk_account_deletion_operation ON iam.account_deletion IS '外键约束：iam.account_deletion 的 operation_id 必须引用 core.async_operation；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT fk_user_account_creation_client ON iam.user_account IS '外键约束：iam.user_account 的 creation_client_id 必须引用 oauth.client；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT fk_account_merge_approval ON iam.account_merge IS '外键约束：iam.account_merge 的 approval_case_id 必须引用 control.approval_case；级联行为以约束定义为准。';

COMMENT ON INDEX iam.ix_fk_account_merge_operation_id IS '跨 Schema 外键前导索引：优化 iam.account_merge 按 operation_id 的关联与删除校验。';
COMMENT ON INDEX iam.ix_fk_user_account_creation_client_id IS '跨 Schema 外键前导索引：优化 iam.user_account 按 creation_client_id 的关联与删除校验。';
COMMENT ON INDEX iam.ix_fk_account_merge_approval_case_id IS '跨 Schema 外键前导索引：优化 iam.account_merge 按 approval_case_id 的关联与删除校验。';

SELECT core.fn_register_migration('baseline:iam:links', 'iam Schema 跨域约束与绑定');
COMMIT;
\endif

