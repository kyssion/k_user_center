-- =============================================================================
-- baseline/schemas/org/seed.sql
-- org Schema 的幂等基线种子
-- PostgreSQL 16+；应用技术栈：.NET 10 + SqlSugar
-- =============================================================================

\set ON_ERROR_STOP on

SELECT (NOT EXISTS (SELECT 1 FROM core.schema_migration WHERE version = 'baseline:org:seed'))::text AS kuc_run_seed \gset
\if :kuc_run_seed
BEGIN;
SET LOCAL lock_timeout = '10s';
SET LOCAL statement_timeout = '10min';

INSERT INTO org.business_line(
    id, public_id, business_line_code, display_name, business_line_state,
    owner_ref, data_residency_region
)
SELECT
    '00000000-0000-0000-0000-000000000000', 'biz_0000000000000000',
    'platform', '平台控制面', 'PROVISIONING', 'platform-security', 'CN'
WHERE NOT EXISTS (
    SELECT 1 FROM org.business_line WHERE id = '00000000-0000-0000-0000-000000000000'
);

UPDATE org.business_line
   SET business_line_state = 'ACTIVE', activated_at = COALESCE(activated_at, clock_timestamp())
 WHERE id = '00000000-0000-0000-0000-000000000000'
   AND business_line_state = 'PROVISIONING';

INSERT INTO org.tenant(
    id, public_id, business_line_id, tenant_code, display_name, tenant_state,
    tenant_type, data_residency_region, tenant_security_epoch
)
SELECT
    '00000000-0000-0000-0000-000000000000', 'ten_0000000000000000',
    '00000000-0000-0000-0000-000000000000', 'platform', '平台范围', 'PROVISIONING',
    'PLATFORM', 'CN', 1
WHERE NOT EXISTS (
    SELECT 1 FROM org.tenant WHERE id = '00000000-0000-0000-0000-000000000000'
);

UPDATE org.tenant
   SET tenant_state = 'ACTIVE'
 WHERE id = '00000000-0000-0000-0000-000000000000'
   AND tenant_state = 'PROVISIONING';

SELECT core.fn_register_migration('baseline:org:seed', 'org Schema 基线种子');
COMMIT;
\endif

