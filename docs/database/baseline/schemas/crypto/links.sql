-- =============================================================================
-- baseline/schemas/crypto/links.sql
-- crypto 源表拥有的最终跨 Schema 外键、绑定触发器、支撑索引及 COMMENT
-- PostgreSQL 16+；应用技术栈：.NET 10 + SqlSugar
-- =============================================================================

\set ON_ERROR_STOP on

SELECT (NOT EXISTS (SELECT 1 FROM core.schema_migration WHERE version = 'baseline:crypto:links'))::text AS kuc_run_links \gset
\if :kuc_run_links
BEGIN;
SET LOCAL lock_timeout = '10s';
SET LOCAL statement_timeout = '5min';

ALTER TABLE crypto.key_asset
    ADD CONSTRAINT fk_key_asset_approval FOREIGN KEY (approval_case_id) REFERENCES control.approval_case(id);

CREATE TRIGGER trg_jwks_release_guard BEFORE UPDATE ON crypto.jwks_release FOR EACH ROW
    EXECUTE FUNCTION control.fn_release_guard('release_state', 'published_at', 'activated_at',
        'superseded_at', 'revoked_at', 'revoke_reason_code');

CREATE INDEX ix_fk_key_asset_approval_case_id ON crypto.key_asset (approval_case_id);

COMMENT ON CONSTRAINT fk_key_asset_approval ON crypto.key_asset IS '外键约束：crypto.key_asset 的 approval_case_id 必须引用 control.approval_case；级联行为以约束定义为准。';

COMMENT ON INDEX crypto.ix_fk_key_asset_approval_case_id IS '跨 Schema 外键前导索引：优化 crypto.key_asset 按 approval_case_id 的关联与删除校验。';

COMMENT ON TRIGGER trg_jwks_release_guard ON crypto.jwks_release IS '跨 Schema 触发器：调用 control.fn_release_guard 保护发布、审批或安全绑定底线。';

SELECT core.fn_register_migration('baseline:crypto:links', 'crypto Schema 跨域约束与绑定');
COMMIT;
\endif

