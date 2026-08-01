-- psql 一键构建入口；路径相对本文件解析。
-- 执行：psql --dbname "$KUC_DATABASE_URL" --file docs/database/build.sql
\set ON_ERROR_STOP on

SELECT pg_advisory_lock(hashtextextended('k_user_center:database-migration', 0));

SELECT (to_regclass('core.schema_migration') IS NULL)::text AS run_000 \gset
\if :run_000
  \if :{?kuc_sha_000}
    SELECT set_config('kuc.migration_sha256', :'kuc_sha_000', false);
  \else
    SELECT set_config('kuc.migration_sha256', '', false);
  \endif
  \ir migrations/000_bootstrap.sql
\else
  \if :{?kuc_sha_000}
    SELECT core.fn_register_migration('000', 'PostgreSQL 基线、Schema、安全函数与迁移台账', :'kuc_sha_000');
  \endif
\endif

SELECT (NOT EXISTS (SELECT 1 FROM core.schema_migration WHERE version = '010'))::text AS run_010 \gset
\if :run_010
  \if :{?kuc_sha_010}
    SELECT set_config('kuc.migration_sha256', :'kuc_sha_010', false);
  \else
    SELECT set_config('kuc.migration_sha256', '', false);
  \endif
  \ir migrations/010_core_identity.sql
\else
  \if :{?kuc_sha_010}
    SELECT core.fn_register_migration('010', '公共契约、Operation、Global User、Subject、Identifier、合并与注销', :'kuc_sha_010');
  \endif
\endif
SELECT (NOT EXISTS (SELECT 1 FROM core.schema_migration WHERE version = '020'))::text AS run_020 \gset
\if :run_020
  \if :{?kuc_sha_020}
    SELECT set_config('kuc.migration_sha256', :'kuc_sha_020', false);
  \else
    SELECT set_config('kuc.migration_sha256', '', false);
  \endif
  \ir migrations/020_authentication_oauth.sql
\else
  \if :{?kuc_sha_020}
    SELECT core.fn_register_migration('020', '认证器、Login Transaction、Device Grant、Client、Session、Grant、Token 与撤销', :'kuc_sha_020');
  \endif
\endif
SELECT (NOT EXISTS (SELECT 1 FROM core.schema_migration WHERE version = '030'))::text AS run_030 \gset
\if :run_030
  \if :{?kuc_sha_030}
    SELECT set_config('kuc.migration_sha256', :'kuc_sha_030', false);
  \else
    SELECT set_config('kuc.migration_sha256', '', false);
  \endif
  \ir migrations/030_organization_authorization_profile.sql
\else
  \if :{?kuc_sha_030}
    SELECT core.fn_register_migration('030', '业务线、租户、组织、Membership、授权策略与 Profile', :'kuc_sha_030');
  \endif
\endif
SELECT (NOT EXISTS (SELECT 1 FROM core.schema_migration WHERE version = '040'))::text AS run_040 \gset
\if :run_040
  \if :{?kuc_sha_040}
    SELECT set_config('kuc.migration_sha256', :'kuc_sha_040', false);
  \else
    SELECT set_config('kuc.migration_sha256', '', false);
  \endif
  \ir migrations/040_privacy_federation.sql
\else
  \if :{?kuc_sha_040}
    SELECT core.fn_register_migration('040', 'Consent、隐私请求、保留导出、OIDC/SAML/SCIM 联合与目录同步', :'kuc_sha_040');
  \endif
\endif
SELECT (NOT EXISTS (SELECT 1 FROM core.schema_migration WHERE version = '050'))::text AS run_050 \gset
\if :run_050
  \if :{?kuc_sha_050}
    SELECT set_config('kuc.migration_sha256', :'kuc_sha_050', false);
  \else
    SELECT set_config('kuc.migration_sha256', '', false);
  \endif
  \ir migrations/050_control_risk_workload_assurance_crypto.sql
\else
  \if :{?kuc_sha_050}
    SELECT core.fn_register_migration('050', '控制面审批、风险、保证等级、委托、机器身份、密钥与证书', :'kuc_sha_050');
  \endif
\endif
SELECT (NOT EXISTS (SELECT 1 FROM core.schema_migration WHERE version = '060'))::text AS run_060 \gset
\if :run_060
  \if :{?kuc_sha_060}
    SELECT set_config('kuc.migration_sha256', :'kuc_sha_060', false);
  \else
    SELECT set_config('kuc.migration_sha256', '', false);
  \endif
  \ir migrations/060_integration_audit_messaging.sql
\else
  \if :{?kuc_sha_060}
    SELECT core.fn_register_migration('060', '事件、Outbox、Webhook、审计、消息投递与可达性', :'kuc_sha_060');
  \endif
\endif
SELECT (NOT EXISTS (SELECT 1 FROM core.schema_migration WHERE version = '070'))::text AS run_070 \gset
\if :run_070
  \if :{?kuc_sha_070}
    SELECT set_config('kuc.migration_sha256', :'kuc_sha_070', false);
  \else
    SELECT set_config('kuc.migration_sha256', '', false);
  \endif
  \ir migrations/070_migration_catalog_comments.sql
\else
  \if :{?kuc_sha_070}
    SELECT core.fn_register_migration('070', '迁移双轨、映射、反向 CDC、对账、回滚与全库数据字典', :'kuc_sha_070');
  \endif
\endif
SELECT (NOT EXISTS (SELECT 1 FROM core.schema_migration WHERE version = '075'))::text AS run_075 \gset
\if :run_075
  \if :{?kuc_sha_075}
    SELECT set_config('kuc.migration_sha256', :'kuc_sha_075', false);
  \else
    SELECT set_config('kuc.migration_sha256', '', false);
  \endif
  \ir migrations/075_integrity_hardening.sql
\else
  \if :{?kuc_sha_075}
    SELECT core.fn_register_migration('075', '跨领域审批、租户、上下文、不可变证据与外键索引加固', :'kuc_sha_075');
  \endif
\endif
SELECT (NOT EXISTS (SELECT 1 FROM core.schema_migration WHERE version = '080'))::text AS run_080 \gset
\if :run_080
  \if :{?kuc_sha_080}
    SELECT set_config('kuc.migration_sha256', :'kuc_sha_080', false);
  \else
    SELECT set_config('kuc.migration_sha256', '', false);
  \endif
  \ir migrations/080_roles_permissions.sql
\else
  \if :{?kuc_sha_080}
    SELECT core.fn_register_migration('080', '统一对象所有者、显式最小权限与职责分离角色', :'kuc_sha_080');
  \endif
\endif
-- 080 已把对象所有权转交 kuc_owner；后续种子和验收必须显式切换到 owner。
SET ROLE kuc_owner;
SELECT (NOT EXISTS (SELECT 1 FROM core.schema_migration WHERE version = '900'))::text AS run_900 \gset
\if :run_900
  \if :{?kuc_sha_900}
    SELECT set_config('kuc.migration_sha256', :'kuc_sha_900', false);
  \else
    SELECT set_config('kuc.migration_sha256', '', false);
  \endif
  \ir migrations/900_seed.sql
\else
  \if :{?kuc_sha_900}
    SELECT core.fn_register_migration('900', '平台范围租户、安全目录、权限与 218 条需求追踪种子', :'kuc_sha_900');
  \endif
\endif
SELECT set_config('kuc.migration_sha256', '', false);
\ir verify.sql

SELECT pg_advisory_unlock(hashtextextended('k_user_center:database-migration', 0));
