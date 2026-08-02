-- =============================================================================
-- baseline/finalize.sql
-- 基线收尾：验证显式 COMMENT 已覆盖；补注释函数仅作为兼容安全网
-- =============================================================================

\set ON_ERROR_STOP on

SELECT (NOT EXISTS (SELECT 1 FROM core.schema_migration WHERE version = 'baseline:finalize'))::text AS kuc_run_finalize \gset
\if :kuc_run_finalize
BEGIN;
SET LOCAL lock_timeout = '10s';
SET LOCAL statement_timeout = '5min';

DO $$
DECLARE
    v_missing_columns integer;
    v_missing_objects integer;
BEGIN
    v_missing_columns := core.fn_apply_complete_column_comments();
    v_missing_objects := core.fn_apply_complete_object_comments();

    IF v_missing_columns <> 0 OR v_missing_objects <> 0 THEN
        RAISE EXCEPTION
            'BASELINE_EXPLICIT_COMMENT_MISSING: columns=%, objects=%',
            v_missing_columns,
            v_missing_objects
            USING ERRCODE = '55000';
    END IF;
END;
$$;

SELECT core.fn_register_migration('baseline:finalize', '基线对象注释完整性收尾');
COMMIT;
\endif
