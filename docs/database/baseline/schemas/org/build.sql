-- =============================================================================
-- baseline/schemas/org/build.sql
-- org Schema 局部对象构建入口；不执行跨 Schema links 和 seed
-- PostgreSQL 16+；应用技术栈：.NET 10 + SqlSugar
-- =============================================================================

\set ON_ERROR_STOP on

SELECT (NOT EXISTS (SELECT 1 FROM core.schema_migration WHERE version = 'baseline:org'))::text AS kuc_run_schema \gset
\if :kuc_run_schema
BEGIN;
SET LOCAL lock_timeout = '10s';
SET LOCAL statement_timeout = '10min';

\ir tables.sql
\ir routines.sql

SELECT core.fn_register_migration('baseline:org', 'org Schema 局部对象');
COMMIT;
\endif

