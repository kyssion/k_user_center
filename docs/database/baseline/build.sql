-- =============================================================================
-- baseline/build.sql
-- 空库一键构建入口；也支持各 Schema 分步执行
-- 执行：psql --dbname "$KUC_DATABASE_URL" --file docs/database/baseline/build.sql
-- =============================================================================

\set ON_ERROR_STOP on

SELECT pg_advisory_lock(hashtextextended('k_user_center:database-baseline', 0));

SELECT (to_regclass('core.schema_migration') IS NULL)::text AS kuc_run_bootstrap \gset
\if :kuc_run_bootstrap
  \ir bootstrap.sql
\endif

-- 第一阶段：core 提供公共表和共享例程，必须先于其余 17 个 Schema。
\ir schemas/core/build.sql

-- 第二阶段：其余 Schema 的局部表、同域约束、例程和视图。
\ir schemas/iam/build.sql
\ir schemas/authn/build.sql
\ir schemas/oauth/build.sql
\ir schemas/org/build.sql
\ir schemas/authz/build.sql
\ir schemas/profile/build.sql
\ir schemas/privacy/build.sql
\ir schemas/federation/build.sql
\ir schemas/risk/build.sql
\ir schemas/workload/build.sql
\ir schemas/assurance/build.sql
\ir schemas/crypto/build.sql
\ir schemas/control/build.sql
\ir schemas/integration/build.sql
\ir schemas/audit/build.sql
\ir schemas/messaging/build.sql
\ir schemas/migration/build.sql

-- 第三阶段：全部表就绪后，按源表所属 Schema 建立跨域外键和绑定。
\ir schemas/core/links.sql
\ir schemas/iam/links.sql
\ir schemas/authn/links.sql
\ir schemas/oauth/links.sql
\ir schemas/org/links.sql
\ir schemas/authz/links.sql
\ir schemas/profile/links.sql
\ir schemas/privacy/links.sql
\ir schemas/federation/links.sql
\ir schemas/risk/links.sql
\ir schemas/workload/links.sql
\ir schemas/assurance/links.sql
\ir schemas/crypto/links.sql
\ir schemas/control/links.sql
\ir schemas/integration/links.sql
\ir schemas/audit/links.sql
\ir schemas/messaging/links.sql
\ir schemas/migration/links.sql

-- 第四阶段：注释安全网与基线种子。
\ir finalize.sql
\ir schemas/core/seed.sql
\ir schemas/org/seed.sql
\ir schemas/authz/seed.sql

-- 第五阶段：先创建角色并统一所有权，再按对象所属 Schema 应用最小权限。
\ir roles.sql
\ir schemas/core/security.sql
\ir schemas/iam/security.sql
\ir schemas/authn/security.sql
\ir schemas/oauth/security.sql
\ir schemas/org/security.sql
\ir schemas/authz/security.sql
\ir schemas/profile/security.sql
\ir schemas/privacy/security.sql
\ir schemas/federation/security.sql
\ir schemas/risk/security.sql
\ir schemas/workload/security.sql
\ir schemas/assurance/security.sql
\ir schemas/crypto/security.sql
\ir schemas/control/security.sql
\ir schemas/integration/security.sql
\ir schemas/audit/security.sql
\ir schemas/messaging/security.sql
\ir schemas/migration/security.sql

-- 第六阶段：以对象所有者执行最终结构和安全验收；RLS 不在默认构建中。
SET ROLE kuc_owner;
\ir verify.sql
RESET ROLE;

SELECT pg_advisory_unlock(hashtextextended('k_user_center:database-baseline', 0));
