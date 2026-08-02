-- =============================================================================
-- baseline/schemas/core/routines.sql
-- core Schema 的最终函数、过程、局部触发器及内联 COMMENT
-- PostgreSQL 16+；应用技术栈：.NET 10 + SqlSugar
-- =============================================================================

CREATE OR REPLACE FUNCTION core.fn_touch_updated_at()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    NEW.updated_at := clock_timestamp();
    RETURN NEW;
END;
$$;
COMMENT ON FUNCTION core.fn_touch_updated_at() IS '统一维护 updated_at；安全判断使用数据库可信时钟。';

CREATE OR REPLACE FUNCTION core.fn_increment_row_version()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    NEW.row_version := OLD.row_version + 1;
    RETURN NEW;
END;
$$;
COMMENT ON FUNCTION core.fn_increment_row_version() IS '数据库强制将 row_version 精确递增 1；应用仍必须使用原版本做 compare-and-set。';

CREATE OR REPLACE FUNCTION core.fn_forbid_epoch_decrease()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    v_column text := TG_ARGV[0];
    v_old bigint;
    v_new bigint;
BEGIN
    EXECUTE format('SELECT ($1).%I, ($2).%I', v_column, v_column)
       INTO v_old, v_new USING OLD, NEW;
    IF v_new < v_old THEN
        RAISE EXCEPTION '% 不得回退：% -> %', v_column, v_old, v_new USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;
COMMENT ON FUNCTION core.fn_forbid_epoch_decrease() IS '保证 user/client/tenant/consent security epoch 单调递增。';

CREATE OR REPLACE FUNCTION core.fn_append_only()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION '% 是追加型对象，禁止 %', TG_TABLE_SCHEMA || '.' || TG_TABLE_NAME, TG_OP
        USING ERRCODE = '55000';
END;
$$;
COMMENT ON FUNCTION core.fn_append_only() IS '阻断追加型审计、撤销、投递证据的 UPDATE/DELETE。';

CREATE OR REPLACE FUNCTION core.fn_terminal_state_guard()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    v_column text := TG_ARGV[0];
    v_old text;
    v_new text;
    v_terminal text[];
BEGIN
    v_terminal := TG_ARGV[1:TG_NARGS - 1];
    EXECUTE format('SELECT ($1).%I, ($2).%I', v_column, v_column)
       INTO v_old, v_new USING OLD, NEW;
    IF v_old = ANY(v_terminal) AND v_new IS DISTINCT FROM v_old THEN
        RAISE EXCEPTION 'INVALID_STATE_TRANSITION: %.% 的终态 % 不得离开', TG_TABLE_NAME, v_column, v_old
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;
COMMENT ON FUNCTION core.fn_terminal_state_guard() IS '通用终态保护触发器；参数为状态列名和终态列表。';

CREATE OR REPLACE FUNCTION core.fn_register_public_id()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, core
AS $$
BEGIN
    INSERT INTO core.public_id_ledger(public_id, entity_kind, entity_id)
    VALUES (NEW.public_id, TG_ARGV[0], NEW.id);
    RETURN NEW;
END;
$$;
COMMENT ON FUNCTION core.fn_register_public_id() IS '在实体插入时以受限 SECURITY DEFINER 权限原子登记不可复用 public_id。';

CREATE OR REPLACE FUNCTION core.fn_hash_jsonb(p_value jsonb)
RETURNS bytea
LANGUAGE sql
IMMUTABLE
STRICT
AS $$
    SELECT digest(convert_to(p_value::text, 'UTF8'), 'sha256');
$$;
COMMENT ON FUNCTION core.fn_hash_jsonb(jsonb) IS '对 PostgreSQL JSONB 规范文本计算 SHA-256；用于数据库自有审计链、迁移和诊断，不作为 .NET 业务上下文摘要或密码哈希。';

CREATE OR REPLACE FUNCTION core.fn_apply_complete_column_comments()
RETURNS integer
LANGUAGE plpgsql
AS $$
DECLARE r record; v_description text; v_count integer := 0;
BEGIN
    FOR r IN
        SELECT n.nspname AS schema_name, c.relname AS table_name, a.attname AS column_name,
               format_type(a.atttypid, a.atttypmod) AS data_type,
               obj_description(c.oid, 'pg_class') AS table_description
          FROM pg_class c
          JOIN pg_namespace n ON n.oid = c.relnamespace
          JOIN pg_attribute a ON a.attrelid = c.oid
         WHERE n.nspname = ANY(ARRAY['core','iam','authn','oauth','org','authz','profile','privacy','federation','risk','workload','assurance','crypto','control','integration','audit','messaging','migration'])
           AND c.relkind IN ('r','p','v','m') AND a.attnum > 0 AND NOT a.attisdropped
           AND col_description(c.oid, a.attnum) IS NULL
         ORDER BY n.nspname, c.relname, a.attnum
    LOOP
        v_description := CASE
            WHEN r.column_name = 'id' THEN '内部主键 UUID；仅用于数据库关系，不作为跨域公开标识。'
            WHEN r.column_name = 'public_id' THEN '不可复用的公开稳定标识；插入时登记到 core.public_id_ledger。'
            WHEN r.column_name = 'tenant_id' THEN '租户隔离键；全零 UUID 表示平台范围，应用查询必须显式携带可信租户上下文。'
            WHEN r.column_name = 'business_line_id' THEN '业务线隔离键；引用 org.business_line。'
            WHEN r.column_name = 'row_version' THEN '乐观并发版本；更新必须使用原值 compare-and-set，成功后单调递增。'
            WHEN r.column_name LIKE '%\_epoch' ESCAPE '\' OR r.column_name LIKE '%\_epoch\_at\_%' ESCAPE '\' THEN '安全或同意水位版本；只能单调递增，用于 Token、缓存和撤销新鲜度校验。'
            WHEN r.column_name LIKE '%\_state' ESCAPE '\' THEN '显式状态机当前值；合法取值见本表 CHECK，完整转换由 .NET 领域策略按蓝图执行，数据库仅保护终态和原子安全底线。'
            WHEN r.column_name LIKE '%\_hash' ESCAPE '\' OR r.column_name LIKE '%\_hashes' ESCAPE '\'
              OR r.column_name LIKE '%\_digest' ESCAPE '\' THEN '不可逆摘要；用于等值匹配、幂等、完整性或最小化证据，不保存原始敏感值。'
            WHEN r.column_name LIKE '%\_ciphertext' ESCAPE '\' OR r.column_name LIKE '%\_cipher' ESCAPE '\'
              OR r.column_name LIKE 'encrypted\_%' ESCAPE '\' THEN '随机化加密密文；解密密钥由独立 KMS/HSM 引用管理。'
            WHEN r.column_name LIKE '%\_blind\_index' ESCAPE '\' THEN '带版本的密钥化盲索引；只用于受控等值检索，不可作为所有权唯一性摘要。'
            WHEN r.column_name LIKE '%\_key\_ref' ESCAPE '\' OR r.column_name LIKE '%\_key\_id' ESCAPE '\' THEN '外部 KMS/HSM 或受控密钥资产引用；不是私钥或 Secret 明文。'
            WHEN r.column_name LIKE '%\_key\_version' ESCAPE '\' THEN '生成密文、HMAC 或盲索引所用密钥版本；轮换时必须保留可验证窗口。'
            WHEN r.column_name LIKE '%\_algorithm' ESCAPE '\' THEN '显式算法标识；必须来自环境算法 allowlist，禁止 none、弱算法和静默降级。'
            WHEN r.column_name LIKE '%\_id' ESCAPE '\' THEN '关联对象内部 UUID；具体目标由外键或字段语义限定。'
            WHEN r.column_name LIKE '%\_at' ESCAPE '\' OR r.column_name LIKE '%\_until' ESCAPE '\' THEN '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。'
            WHEN r.column_name LIKE '%\_count' ESCAPE '\' OR r.column_name LIKE '%\_attempt' ESCAPE '\' THEN '非负计数器；并发更新需使用原子 SQL 或乐观锁。'
            WHEN r.column_name LIKE '%\_seconds' ESCAPE '\' THEN '以秒为单位的显式时长；上限由 Security Profile、时长策略和表约束共同限制。'
            WHEN r.column_name LIKE '%\_version' ESCAPE '\' THEN '对象、Schema、策略或源数据的显式版本；不得以不可信客户端时间戳替代。'
            WHEN r.column_name LIKE '%\_code' ESCAPE '\' THEN '稳定机器可读代码；展示文本应通过资源或目录解析。'
            WHEN r.column_name LIKE '%\_kind' ESCAPE '\' OR r.column_name LIKE '%\_type' ESCAPE '\' THEN '对象类别判别字段；允许值由 CHECK 或对应注册表约束。'
            WHEN r.column_name LIKE '%\_ref' ESCAPE '\' THEN '不透明对象引用；不得假定其可解析为手机号、邮箱或其他业务事实。'
            WHEN r.column_name LIKE '%\_uri' ESCAPE '\' THEN '受控 URI；写入前必须执行协议、主机、重定向和 SSRF 安全校验。'
            WHEN r.column_name LIKE 'is\_%' ESCAPE '\' OR r.column_name LIKE 'has\_%' ESCAPE '\'
              OR r.column_name LIKE '%\_enabled' ESCAPE '\' THEN '显式布尔开关；默认值、启用前置条件和失效行为由本表约束及版本化策略控制。'
            WHEN r.data_type LIKE '%[]' THEN '有序或集合型代码列表；写入前必须去重、校验 allowlist，并遵守表约束定义的包含关系。'
            WHEN r.data_type = 'jsonb' THEN '版本化结构化扩展数据；必须通过对应 JSON Schema 校验，不得替代核心状态、租户键、外键或安全 epoch。'
            ELSE format('%s；列 %s（%s）承载该记录的领域属性，写入方必须满足本表约束、数据分类、保留与审计规则。',
                        COALESCE(r.table_description, r.schema_name || '.' || r.table_name), r.column_name, r.data_type)
        END;
        EXECUTE format('COMMENT ON COLUMN %I.%I.%I IS %L', r.schema_name, r.table_name, r.column_name, v_description);
        v_count := v_count + 1;
    END LOOP;
    RETURN v_count;
END;
$$;

CREATE OR REPLACE FUNCTION core.fn_apply_complete_object_comments()
RETURNS integer
LANGUAGE plpgsql
AS $$
DECLARE r record; v_description text; v_count integer := 0;
BEGIN
    FOR r IN
        SELECT n.oid, n.nspname
          FROM pg_namespace n
         WHERE n.nspname = ANY(ARRAY['core','iam','authn','oauth','org','authz','profile','privacy','federation','risk','workload','assurance','crypto','control','integration','audit','messaging','migration'])
           AND NULLIF(btrim(obj_description(n.oid, 'pg_namespace')), '') IS NULL
    LOOP
        EXECUTE format('COMMENT ON SCHEMA %I IS %L', r.nspname,
            format('统一身份与访问平台 %s 领域 Schema；对象必须通过版本化迁移、最小权限和审计治理。', r.nspname));
        v_count := v_count + 1;
    END LOOP;

    FOR r IN
        SELECT c.oid, n.nspname, c.relname, c.relkind
          FROM pg_class c
          JOIN pg_namespace n ON n.oid = c.relnamespace
         WHERE n.nspname = ANY(ARRAY['core','iam','authn','oauth','org','authz','profile','privacy','federation','risk','workload','assurance','crypto','control','integration','audit','messaging','migration'])
           AND c.relkind IN ('r','p','v','m','S')
           AND NULLIF(btrim(obj_description(c.oid, 'pg_class')), '') IS NULL
    LOOP
        v_description := format('%s.%s：统一身份与访问平台受迁移、权限、保留和审计规则治理的%s。',
            r.nspname, r.relname,
            CASE r.relkind WHEN 'v' THEN '查询视图' WHEN 'm' THEN '物化视图' WHEN 'S' THEN '受控序列' ELSE '领域基表' END);
        EXECUTE format('%s %I.%I IS %L',
            CASE r.relkind WHEN 'v' THEN 'COMMENT ON VIEW' WHEN 'm' THEN 'COMMENT ON MATERIALIZED VIEW'
                           WHEN 'S' THEN 'COMMENT ON SEQUENCE' ELSE 'COMMENT ON TABLE' END,
            r.nspname, r.relname, v_description);
        v_count := v_count + 1;
    END LOOP;

    FOR r IN

        SELECT idx.oid, n.nspname, idx.relname AS index_name, tbl.relname AS table_name,
               i.indisprimary, i.indisunique, i.indpred IS NOT NULL AS is_partial
          FROM pg_index i
          JOIN pg_class idx ON idx.oid = i.indexrelid
          JOIN pg_class tbl ON tbl.oid = i.indrelid
          JOIN pg_namespace n ON n.oid = idx.relnamespace
         WHERE n.nspname = ANY(ARRAY['core','iam','authn','oauth','org','authz','profile','privacy','federation','risk','workload','assurance','crypto','control','integration','audit','messaging','migration'])
           AND NULLIF(btrim(obj_description(idx.oid, 'pg_class')), '') IS NULL
    LOOP
        v_description := format('%s.%s 上的%s%s索引 %s；用于数据库级唯一性、完整性或受控查询路径。',
            r.nspname, r.table_name,
            CASE WHEN r.indisprimary THEN '主键' WHEN r.indisunique THEN '唯一' ELSE '查询' END,
            CASE WHEN r.is_partial THEN '部分' ELSE '' END,
            r.index_name);
        EXECUTE format('COMMENT ON INDEX %I.%I IS %L', r.nspname, r.index_name, v_description);
        v_count := v_count + 1;
    END LOOP;

    FOR r IN
        SELECT con.oid, con.conname, con.contype, n.nspname, c.relname
          FROM pg_constraint con
          JOIN pg_class c ON c.oid = con.conrelid
          JOIN pg_namespace n ON n.oid = c.relnamespace
         WHERE n.nspname = ANY(ARRAY['core','iam','authn','oauth','org','authz','profile','privacy','federation','risk','workload','assurance','crypto','control','integration','audit','messaging','migration'])
           AND NULLIF(btrim(obj_description(con.oid, 'pg_constraint')), '') IS NULL
    LOOP
        v_description := format('%s.%s 的%s约束 %s；由数据库拒绝违反领域完整性的数据。',
            r.nspname, r.relname,
            CASE r.contype WHEN 'p' THEN '主键' WHEN 'u' THEN '唯一' WHEN 'f' THEN '外键'
                           WHEN 'c' THEN '检查' WHEN 'x' THEN '排斥' ELSE '完整性' END,
            r.conname);
        EXECUTE format('COMMENT ON CONSTRAINT %I ON %I.%I IS %L', r.conname, r.nspname, r.relname, v_description);
        v_count := v_count + 1;
    END LOOP;

    FOR r IN
        SELECT t.oid, t.tgname, n.nspname, c.relname, pn.nspname AS function_schema, p.proname AS function_name
          FROM pg_trigger t
          JOIN pg_class c ON c.oid = t.tgrelid
          JOIN pg_namespace n ON n.oid = c.relnamespace
          JOIN pg_proc p ON p.oid = t.tgfoid
          JOIN pg_namespace pn ON pn.oid = p.pronamespace
         WHERE NOT t.tgisinternal
           AND n.nspname = ANY(ARRAY['core','iam','authn','oauth','org','authz','profile','privacy','federation','risk','workload','assurance','crypto','control','integration','audit','messaging','migration'])
           AND NULLIF(btrim(obj_description(t.oid, 'pg_trigger')), '') IS NULL
    LOOP
        v_description := format('%s.%s 的触发器 %s；调用 %s.%s 维护终态/原子安全底线、不可变证据、版本、审计或结构完整性。',
            r.nspname, r.relname, r.tgname, r.function_schema, r.function_name);
        EXECUTE format('COMMENT ON TRIGGER %I ON %I.%I IS %L', r.tgname, r.nspname, r.relname, v_description);
        v_count := v_count + 1;
    END LOOP;

    FOR r IN
        SELECT t.oid, n.nspname, t.typname, t.typtype
          FROM pg_type t
          JOIN pg_namespace n ON n.oid = t.typnamespace
          LEFT JOIN pg_class c ON c.oid = t.typrelid
         WHERE n.nspname = ANY(ARRAY['core','iam','authn','oauth','org','authz','profile','privacy','federation','risk','workload','assurance','crypto','control','integration','audit','messaging','migration'])
           AND (t.typtype IN ('d','e','r','m') OR (t.typtype = 'c' AND c.relkind = 'c'))
           AND NULLIF(btrim(obj_description(t.oid, 'pg_type')), '') IS NULL
    LOOP
        v_description := format('%s.%s：平台显式声明的%s；取值、兼容和迁移必须版本化治理。',
            r.nspname, r.typname, CASE WHEN r.typtype = 'd' THEN 'Domain' ELSE '数据类型' END);
        IF r.typtype = 'd' THEN
            EXECUTE format('COMMENT ON DOMAIN %I.%I IS %L', r.nspname, r.typname, v_description);
        ELSE
            EXECUTE format('COMMENT ON TYPE %I.%I IS %L', r.nspname, r.typname, v_description);
        END IF;
        v_count := v_count + 1;
    END LOOP;

    FOR r IN
        SELECT p.oid, n.nspname, p.proname, p.prokind,
               pg_get_function_identity_arguments(p.oid) AS identity_arguments
          FROM pg_proc p
          JOIN pg_namespace n ON n.oid = p.pronamespace
         WHERE n.nspname = ANY(ARRAY['core','iam','authn','oauth','org','authz','profile','privacy','federation','risk','workload','assurance','crypto','control','integration','audit','messaging','migration'])
           AND p.prokind IN ('f','p')
           AND NULLIF(btrim(obj_description(p.oid, 'pg_proc')), '') IS NULL
    LOOP
        v_description := format('%s.%s：平台数据库领域规则、触发器或受控查询辅助%s；调用权限遵循最小授权。',
            r.nspname, r.proname, CASE WHEN r.prokind = 'p' THEN '过程' ELSE '函数' END);
        IF r.prokind = 'p' THEN
            EXECUTE format('COMMENT ON PROCEDURE %I.%I(%s) IS %L', r.nspname, r.proname, r.identity_arguments, v_description);
        ELSE
            EXECUTE format('COMMENT ON FUNCTION %I.%I(%s) IS %L', r.nspname, r.proname, r.identity_arguments, v_description);
        END IF;
        v_count := v_count + 1;
    END LOOP;

    FOR r IN
        SELECT pol.oid, pol.polname, n.nspname, c.relname
          FROM pg_policy pol
          JOIN pg_class c ON c.oid = pol.polrelid
          JOIN pg_namespace n ON n.oid = c.relnamespace
         WHERE n.nspname = ANY(ARRAY['core','iam','authn','oauth','org','authz','profile','privacy','federation','risk','workload','assurance','crypto','control','integration','audit','messaging','migration'])
           AND NULLIF(btrim(obj_description(pol.oid, 'pg_policy')), '') IS NULL
    LOOP
        v_description := format('%s.%s 的 RLS Policy %s；限制业务角色的租户可见性并为受控平台角色保留显式路径。',
            r.nspname, r.relname, r.polname);

        EXECUTE format('COMMENT ON POLICY %I ON %I.%I IS %L', r.polname, r.nspname, r.relname, v_description);
        v_count := v_count + 1;
    END LOOP;

    RETURN v_count;
END;
$$;

CREATE OR REPLACE FUNCTION core.fn_immutable_except()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    v_old jsonb := to_jsonb(OLD);
    v_new jsonb := to_jsonb(NEW);
    i integer;
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION '% 是不可变对象，禁止 DELETE', TG_TABLE_SCHEMA || '.' || TG_TABLE_NAME USING ERRCODE = '55000';
    END IF;
    IF TG_NARGS > 0 THEN
        FOR i IN 0..TG_NARGS - 1 LOOP
            v_old := v_old - TG_ARGV[i];
            v_new := v_new - TG_ARGV[i];
        END LOOP;
    END IF;
    IF v_old IS DISTINCT FROM v_new THEN
        RAISE EXCEPTION '% 的版本内容不可原地修改', TG_TABLE_SCHEMA || '.' || TG_TABLE_NAME USING ERRCODE = '55000';
    END IF;
    RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION core.fn_immutable_after_draft()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    v_old jsonb := to_jsonb(OLD);
    v_new jsonb := to_jsonb(NEW);
    v_old_state text;
    i integer;
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION '% 禁止 DELETE', TG_TABLE_SCHEMA || '.' || TG_TABLE_NAME USING ERRCODE = '55000';
    END IF;
    v_old_state := v_old ->> TG_ARGV[0];
    IF v_old_state = 'DRAFT' THEN RETURN NEW; END IF;
    IF TG_NARGS > 0 THEN
        FOR i IN 0..TG_NARGS - 1 LOOP
            v_old := v_old - TG_ARGV[i];
            v_new := v_new - TG_ARGV[i];
        END LOOP;
    END IF;
    IF v_old IS DISTINCT FROM v_new THEN
        RAISE EXCEPTION 'CONFIGURATION_CONTENT_IMMUTABLE: % 离开 DRAFT 后配置内容不可修改', TG_TABLE_SCHEMA || '.' || TG_TABLE_NAME USING ERRCODE = '55000';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_operation_touch BEFORE UPDATE ON core.async_operation FOR EACH ROW EXECUTE FUNCTION core.fn_touch_updated_at();

CREATE TRIGGER trg_operation_version BEFORE UPDATE ON core.async_operation FOR EACH ROW EXECUTE FUNCTION core.fn_increment_row_version();

CREATE TRIGGER trg_operation_public_id BEFORE INSERT ON core.async_operation FOR EACH ROW EXECUTE FUNCTION core.fn_register_public_id('OPERATION');

CREATE TRIGGER trg_operation_terminal BEFORE UPDATE ON core.async_operation FOR EACH ROW EXECUTE FUNCTION core.fn_terminal_state_guard('operation_state', 'COMPLETED', 'FAILED', 'CANCELLED');

CREATE TRIGGER trg_operation_step_touch BEFORE UPDATE ON core.async_operation_step FOR EACH ROW EXECUTE FUNCTION core.fn_touch_updated_at();

CREATE TRIGGER trg_operation_step_version BEFORE UPDATE ON core.async_operation_step FOR EACH ROW EXECUTE FUNCTION core.fn_increment_row_version();

CREATE TRIGGER trg_requirement_trace_touch BEFORE UPDATE ON core.requirement_trace FOR EACH ROW EXECUTE FUNCTION core.fn_touch_updated_at();

CREATE TRIGGER trg_requirement_trace_version BEFORE UPDATE ON core.requirement_trace FOR EACH ROW EXECUTE FUNCTION core.fn_increment_row_version();

CREATE TRIGGER trg_security_profile_immutable BEFORE UPDATE OR DELETE ON core.security_profile FOR EACH ROW
    EXECUTE FUNCTION core.fn_immutable_except('is_active', 'retired_at');

CREATE TRIGGER trg_duration_policy_immutable BEFORE UPDATE OR DELETE ON core.duration_policy FOR EACH ROW
    EXECUTE FUNCTION core.fn_immutable_except('retired_at');

CREATE TRIGGER trg_data_classification_immutable BEFORE UPDATE OR DELETE ON core.data_classification FOR EACH ROW
    EXECUTE FUNCTION core.fn_immutable_except();

COMMENT ON FUNCTION core.fn_apply_complete_column_comments() IS '为平台所有基表、视图和物化视图中尚未显式注释的列补充非空数据字典注释；迁移末尾和 CI 均可重复执行。';

COMMENT ON FUNCTION core.fn_apply_complete_object_comments() IS '为平台 Schema、表/视图/序列、Type/Domain、索引、约束、触发器、函数/过程及 RLS Policy 补充缺失的非空对象描述；可重复执行。';

COMMENT ON FUNCTION core.fn_immutable_except() IS '除触发器参数列外，阻止版本化目录、发布内容和安全证据被原地修改或删除。';

COMMENT ON FUNCTION core.fn_immutable_after_draft() IS '配置资源离开 DRAFT 后，只允许修改触发器参数列；其余配置内容及摘要不可原地改写。';

COMMENT ON TRIGGER trg_operation_touch ON core.async_operation IS '触发器：调用 core.fn_touch_updated_at 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_operation_version ON core.async_operation IS '触发器：调用 core.fn_increment_row_version 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_operation_public_id ON core.async_operation IS '触发器：调用 core.fn_register_public_id 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_operation_terminal ON core.async_operation IS '触发器：调用 core.fn_terminal_state_guard 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_operation_step_touch ON core.async_operation_step IS '触发器：调用 core.fn_touch_updated_at 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_operation_step_version ON core.async_operation_step IS '触发器：调用 core.fn_increment_row_version 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_requirement_trace_touch ON core.requirement_trace IS '触发器：调用 core.fn_touch_updated_at 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_requirement_trace_version ON core.requirement_trace IS '触发器：调用 core.fn_increment_row_version 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_security_profile_immutable ON core.security_profile IS '触发器：调用 core.fn_immutable_except 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_duration_policy_immutable ON core.duration_policy IS '触发器：调用 core.fn_immutable_except 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_data_classification_immutable ON core.data_classification IS '触发器：调用 core.fn_immutable_except 维护数据库结构完整性、不可变证据或关键原子安全底线。';
