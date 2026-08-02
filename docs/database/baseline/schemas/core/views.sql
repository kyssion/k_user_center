-- =============================================================================
-- baseline/schemas/core/views.sql
-- core Schema 的视图及内联 COMMENT
-- PostgreSQL 16+；应用技术栈：.NET 10 + SqlSugar
-- =============================================================================

CREATE VIEW core.data_dictionary AS
SELECT n.nspname AS schema_name,
       c.relname AS table_name,
       obj_description(c.oid, 'pg_class') AS table_description,
       a.attnum AS ordinal_position,
       a.attname AS column_name,
       format_type(a.atttypid, a.atttypmod) AS data_type,
       a.attnotnull AS is_not_null,
       pg_get_expr(ad.adbin, ad.adrelid) AS default_expression,
       col_description(c.oid, a.attnum) AS column_description
  FROM pg_class c
  JOIN pg_namespace n ON n.oid = c.relnamespace
  JOIN pg_attribute a ON a.attrelid = c.oid
  LEFT JOIN pg_attrdef ad ON ad.adrelid = c.oid AND ad.adnum = a.attnum
 WHERE n.nspname = ANY(ARRAY['core','iam','authn','oauth','org','authz','profile','privacy','federation','risk','workload','assurance','crypto','control','integration','audit','messaging','migration'])
   AND c.relkind IN ('r','p') AND a.attnum > 0 AND NOT a.attisdropped;

COMMENT ON VIEW core.data_dictionary IS '全库 Schema、表、表描述、列序、类型、空值、默认值和列描述的可查询数据字典。';

CREATE VIEW core.object_dictionary AS
SELECT 'DATABASE'::text AS object_dimension, NULL::text AS schema_name, NULL::text AS parent_object,
       d.datname AS object_name, shobj_description(d.oid, 'pg_database') AS description
  FROM pg_database d WHERE d.datname = current_database()
UNION ALL
SELECT 'EXTENSION', NULL, NULL, e.extname, obj_description(e.oid, 'pg_extension')
  FROM pg_extension e WHERE e.extname = 'pgcrypto'
UNION ALL
SELECT 'SCHEMA', n.nspname, NULL, n.nspname, obj_description(n.oid, 'pg_namespace')
  FROM pg_namespace n
 WHERE n.nspname = ANY(ARRAY['core','iam','authn','oauth','org','authz','profile','privacy','federation','risk','workload','assurance','crypto','control','integration','audit','messaging','migration'])
UNION ALL
SELECT CASE c.relkind WHEN 'r' THEN 'TABLE' WHEN 'p' THEN 'TABLE' WHEN 'v' THEN 'VIEW'
                      WHEN 'm' THEN 'MATERIALIZED_VIEW' WHEN 'S' THEN 'SEQUENCE' END,
       n.nspname, NULL, c.relname, obj_description(c.oid, 'pg_class')
  FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
 WHERE n.nspname = ANY(ARRAY['core','iam','authn','oauth','org','authz','profile','privacy','federation','risk','workload','assurance','crypto','control','integration','audit','messaging','migration'])
   AND c.relkind IN ('r','p','v','m','S')
UNION ALL
SELECT 'COLUMN', n.nspname, c.relname, a.attname, col_description(c.oid, a.attnum)
  FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
  JOIN pg_attribute a ON a.attrelid = c.oid
 WHERE n.nspname = ANY(ARRAY['core','iam','authn','oauth','org','authz','profile','privacy','federation','risk','workload','assurance','crypto','control','integration','audit','messaging','migration'])
   AND c.relkind IN ('r','p','v','m') AND a.attnum > 0 AND NOT a.attisdropped
UNION ALL
SELECT 'INDEX', n.nspname, tbl.relname, idx.relname, obj_description(idx.oid, 'pg_class')
  FROM pg_index i JOIN pg_class idx ON idx.oid = i.indexrelid JOIN pg_class tbl ON tbl.oid = i.indrelid
  JOIN pg_namespace n ON n.oid = idx.relnamespace
 WHERE n.nspname = ANY(ARRAY['core','iam','authn','oauth','org','authz','profile','privacy','federation','risk','workload','assurance','crypto','control','integration','audit','messaging','migration'])
UNION ALL
SELECT 'CONSTRAINT', n.nspname, c.relname, con.conname, obj_description(con.oid, 'pg_constraint')
  FROM pg_constraint con JOIN pg_class c ON c.oid = con.conrelid JOIN pg_namespace n ON n.oid = c.relnamespace
 WHERE n.nspname = ANY(ARRAY['core','iam','authn','oauth','org','authz','profile','privacy','federation','risk','workload','assurance','crypto','control','integration','audit','messaging','migration'])
UNION ALL
SELECT 'TRIGGER', n.nspname, c.relname, t.tgname, obj_description(t.oid, 'pg_trigger')
  FROM pg_trigger t JOIN pg_class c ON c.oid = t.tgrelid JOIN pg_namespace n ON n.oid = c.relnamespace
 WHERE NOT t.tgisinternal
   AND n.nspname = ANY(ARRAY['core','iam','authn','oauth','org','authz','profile','privacy','federation','risk','workload','assurance','crypto','control','integration','audit','messaging','migration'])
UNION ALL
SELECT CASE WHEN t.typtype = 'd' THEN 'DOMAIN' ELSE 'TYPE' END,
       n.nspname, NULL, t.typname, obj_description(t.oid, 'pg_type')
  FROM pg_type t
  JOIN pg_namespace n ON n.oid = t.typnamespace
  LEFT JOIN pg_class c ON c.oid = t.typrelid
 WHERE n.nspname = ANY(ARRAY['core','iam','authn','oauth','org','authz','profile','privacy','federation','risk','workload','assurance','crypto','control','integration','audit','messaging','migration'])
   AND (t.typtype IN ('d','e','r','m') OR (t.typtype = 'c' AND c.relkind = 'c'))
UNION ALL
SELECT CASE WHEN p.prokind = 'p' THEN 'PROCEDURE' ELSE 'FUNCTION' END,
       n.nspname, NULL, p.proname || '(' || pg_get_function_identity_arguments(p.oid) || ')', obj_description(p.oid, 'pg_proc')
  FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
 WHERE p.prokind IN ('f','p')
   AND n.nspname = ANY(ARRAY['core','iam','authn','oauth','org','authz','profile','privacy','federation','risk','workload','assurance','crypto','control','integration','audit','messaging','migration'])
UNION ALL
SELECT 'ROLE', NULL, NULL, r.rolname, shobj_description(r.oid, 'pg_authid')
  FROM pg_roles r
 WHERE r.rolname = ANY(ARRAY['kuc_owner','kuc_migrator','kuc_app','kuc_authn_writer','kuc_control_writer',
                            'kuc_outbox_dispatcher','kuc_message_dispatcher','kuc_audit_writer','kuc_auditor','kuc_readonly'])
UNION ALL
SELECT 'POLICY', n.nspname, c.relname, pol.polname, obj_description(pol.oid, 'pg_policy')
  FROM pg_policy pol JOIN pg_class c ON c.oid = pol.polrelid JOIN pg_namespace n ON n.oid = c.relnamespace
 WHERE n.nspname = ANY(ARRAY['core','iam','authn','oauth','org','authz','profile','privacy','federation','risk','workload','assurance','crypto','control','integration','audit','messaging','migration']);

COMMENT ON VIEW core.object_dictionary IS '数据库、扩展、Schema、表/视图/序列、列、Type/Domain、索引、约束、触发器、函数/过程、角色和 RLS Policy 的统一可查询对象说明目录。';

COMMENT ON COLUMN core.data_dictionary.schema_name IS 'core.data_dictionary.schema_name 的只读投影列；语义继承来源对象及本视图定义。';

COMMENT ON COLUMN core.data_dictionary.table_name IS 'core.data_dictionary.table_name 的只读投影列；语义继承来源对象及本视图定义。';

COMMENT ON COLUMN core.data_dictionary.table_description IS 'core.data_dictionary.table_description 的只读投影列；语义继承来源对象及本视图定义。';

COMMENT ON COLUMN core.data_dictionary.ordinal_position IS 'core.data_dictionary.ordinal_position 的只读投影列；语义继承来源对象及本视图定义。';

COMMENT ON COLUMN core.data_dictionary.column_name IS 'core.data_dictionary.column_name 的只读投影列；语义继承来源对象及本视图定义。';

COMMENT ON COLUMN core.data_dictionary.data_type IS 'core.data_dictionary.data_type 的只读投影列；语义继承来源对象及本视图定义。';

COMMENT ON COLUMN core.data_dictionary.is_not_null IS 'core.data_dictionary.is_not_null 的只读投影列；语义继承来源对象及本视图定义。';

COMMENT ON COLUMN core.data_dictionary.default_expression IS 'core.data_dictionary.default_expression 的只读投影列；语义继承来源对象及本视图定义。';

COMMENT ON COLUMN core.data_dictionary.column_description IS 'core.data_dictionary.column_description 的只读投影列；语义继承来源对象及本视图定义。';

COMMENT ON COLUMN core.object_dictionary.object_dimension IS 'core.object_dictionary.object_dimension 的只读投影列；语义继承来源对象及本视图定义。';

COMMENT ON COLUMN core.object_dictionary.schema_name IS 'core.object_dictionary.schema_name 的只读投影列；语义继承来源对象及本视图定义。';

COMMENT ON COLUMN core.object_dictionary.parent_object IS 'core.object_dictionary.parent_object 的只读投影列；语义继承来源对象及本视图定义。';

COMMENT ON COLUMN core.object_dictionary.object_name IS 'core.object_dictionary.object_name 的只读投影列；语义继承来源对象及本视图定义。';

COMMENT ON COLUMN core.object_dictionary.description IS 'core.object_dictionary.description 的只读投影列；语义继承来源对象及本视图定义。';

