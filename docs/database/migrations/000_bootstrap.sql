-- =============================================================================
-- 000_bootstrap.sql
-- 迁移台账、公共 schema、通用函数与触发器、数据库角色
-- 依据：蓝图 §11.0 技术基线、§4.3 安全版本、§18.1 数据库契约测试
-- 目标：PostgreSQL 16+
-- 幂等：全部 DDL 为 IF NOT EXISTS / OR REPLACE，可重复执行
-- 回滚：见 rollback/999_rollback_all.sql
-- =============================================================================

SET client_min_messages = warning;

-- -----------------------------------------------------------------------------
-- 0. 扩展
-- -----------------------------------------------------------------------------
-- gen_random_uuid() 为 PG13+ 内置，不需要 pgcrypto。
-- 本库不安装任何依赖密钥的加密扩展：加解密与 HMAC 一律在应用侧用 KMS 密钥完成（REQ-KEY-001）。
CREATE EXTENSION IF NOT EXISTS btree_gin;

-- -----------------------------------------------------------------------------
-- 1. 公共 schema
-- -----------------------------------------------------------------------------
CREATE SCHEMA IF NOT EXISTS core;
COMMENT ON SCHEMA core IS '公共基础设施：迁移台账、通用函数、标识台账、幂等记录、参考数据';

-- -----------------------------------------------------------------------------
-- 2. 迁移台账
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS core.schema_migration (
    version           text        NOT NULL,
    description       text        NOT NULL,
    first_applied_at  timestamptz NOT NULL DEFAULT now(),
    last_applied_at   timestamptz NOT NULL DEFAULT now(),
    apply_count       integer     NOT NULL DEFAULT 1,
    applied_by        text        NOT NULL DEFAULT current_user,
    CONSTRAINT pk_schema_migration PRIMARY KEY (version)
);
COMMENT ON TABLE core.schema_migration IS '迁移版本台账，支撑蓝图 §18.2 第 4 条“数据库迁移不可回滚且未经过演练”的可追溯性（REQ-MIG-001）';

CREATE OR REPLACE FUNCTION core.fn_migration_apply(p_version text, p_description text)
RETURNS void
LANGUAGE plpgsql
AS $$
BEGIN
    INSERT INTO core.schema_migration (version, description)
    VALUES (p_version, p_description)
    ON CONFLICT (version) DO UPDATE
        SET last_applied_at = now(),
            apply_count     = core.schema_migration.apply_count + 1,
            applied_by      = current_user;
END;
$$;
COMMENT ON FUNCTION core.fn_migration_apply(text, text) IS '登记迁移版本；因所有 DDL 幂等，重复执行只累加 apply_count 而不报错';

-- -----------------------------------------------------------------------------
-- 3. 内部主键生成：UUIDv7
-- 能力地图 §3.2：内部主键允许有序 ID 以保证索引局部性，但禁止对外暴露
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION core.uuid_generate_v7()
RETURNS uuid
LANGUAGE plpgsql
PARALLEL SAFE
AS $$
DECLARE
    v_time_ms bytea;
    v_bytes   bytea;
BEGIN
    -- 48 bit 毫秒时间戳（大端），取 int8send 的后 6 字节
    v_time_ms := substring(int8send((extract(epoch FROM clock_timestamp()) * 1000)::bigint) FROM 3 FOR 6);
    -- 10 字节随机：直接复用内置 CSPRNG，避免引入 pgcrypto
    v_bytes   := v_time_ms || substring(uuid_send(gen_random_uuid()) FROM 7 FOR 10);
    -- version = 7
    v_bytes   := set_byte(v_bytes, 6, ((get_byte(v_bytes, 6) & 15) | 112));
    -- variant = RFC 4122
    v_bytes   := set_byte(v_bytes, 8, ((get_byte(v_bytes, 8) & 63) | 128));
    RETURN encode(v_bytes, 'hex')::uuid;
END;
$$;
COMMENT ON FUNCTION core.uuid_generate_v7() IS 'UUIDv7 内部主键；应用侧亦可自行生成，两者必须同算法（能力地图 §3.2）';

-- -----------------------------------------------------------------------------
-- 4. 通用触发器函数
-- -----------------------------------------------------------------------------

-- 4.1 updated_at 自动维护（不触碰 row_version，避免与 ORM 乐观锁冲突）
CREATE OR REPLACE FUNCTION core.fn_touch_updated_at()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    NEW.updated_at := now();
    RETURN NEW;
END;
$$;

-- 4.2 安全水位单调递增（蓝图 §4.3、SLO-DR-002：无法证明单调时失败关闭）
CREATE OR REPLACE FUNCTION core.fn_forbid_epoch_decrease()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    v_col text := COALESCE(TG_ARGV[0], 'security_epoch');
    v_old bigint;
    v_new bigint;
BEGIN
    EXECUTE format('SELECT ($1).%I, ($2).%I', v_col, v_col) INTO v_old, v_new USING OLD, NEW;
    IF v_new < v_old THEN
        RAISE EXCEPTION 'EPOCH_MONOTONICITY_VIOLATION: %.%.% % -> %',
            TG_TABLE_SCHEMA, TG_TABLE_NAME, v_col, v_old, v_new
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;
COMMENT ON FUNCTION core.fn_forbid_epoch_decrease() IS 'security_epoch / policy_version 等安全水位只增不减（蓝图 §4.3）';

-- 4.3 追加型表保护（权限是主控制，触发器为纵深防御）
CREATE OR REPLACE FUNCTION core.fn_append_only()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'APPEND_ONLY_VIOLATION: % 禁止在 %.% 上执行（INV-G-008）',
        TG_OP, TG_TABLE_SCHEMA, TG_TABLE_NAME
        USING ERRCODE = '42501';
END;
$$;

-- 4.4 对外标识永不复用（INV-G-001）
CREATE OR REPLACE FUNCTION core.fn_register_public_id()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    v_entity text := TG_ARGV[0];
    v_column text := COALESCE(TG_ARGV[1], 'public_id');
    v_value  text;
BEGIN
    EXECUTE format('SELECT ($1).%I', v_column) INTO v_value USING NEW;
    IF v_value IS NULL THEN
        RETURN NEW;
    END IF;
    -- 不使用 ON CONFLICT：冲突必须冒泡为错误，这正是"永不复用"的执行点
    INSERT INTO core.public_id_ledger (public_id, entity_type) VALUES (v_value, v_entity);
    RETURN NEW;
END;
$$;
COMMENT ON FUNCTION core.fn_register_public_id() IS '将对外标识登记进插入型台账；实体行删除不释放占用（INV-G-001）';

-- -----------------------------------------------------------------------------
-- 5. 月分区维护
-- 依据：本文档 §8。默认分区兜底，落入默认分区应告警而不是让写入失败
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION core.fn_ensure_monthly_partitions(
    p_schema        text,
    p_table         text,
    p_months_ahead  integer DEFAULT 3,
    p_append_only   boolean DEFAULT false
)
RETURNS integer
LANGUAGE plpgsql
AS $$
DECLARE
    v_base    date := date_trunc('month', now())::date;
    v_i       integer;
    v_part    text;
    v_from    date;
    v_to      date;
    v_created integer := 0;
BEGIN
    FOR v_i IN 0..p_months_ahead LOOP
        v_from := (v_base + (v_i || ' month')::interval)::date;
        v_to   := (v_base + ((v_i + 1) || ' month')::interval)::date;
        v_part := format('%s_p%s', p_table, to_char(v_from, 'YYYYMM'));

        IF NOT EXISTS (
            SELECT 1 FROM pg_class c
            JOIN pg_namespace n ON n.oid = c.relnamespace
            WHERE n.nspname = p_schema AND c.relname = v_part
        ) THEN
            EXECUTE format(
                'CREATE TABLE %I.%I PARTITION OF %I.%I FOR VALUES FROM (%L) TO (%L)',
                p_schema, v_part, p_schema, p_table, v_from, v_to
            );
            -- 分区不继承父表权限，且会命中 ALTER DEFAULT PRIVILEGES，
            -- 因此追加型父表的新分区必须单独收回 UPDATE/DELETE（INV-G-008）
            IF p_append_only THEN
                PERFORM core.fn_apply_append_only_grants(p_schema, v_part);
            END IF;
            v_created := v_created + 1;
        END IF;
    END LOOP;
    RETURN v_created;
END;
$$;

CREATE OR REPLACE FUNCTION core.fn_ensure_default_partition(
    p_schema      text,
    p_table       text,
    p_append_only boolean DEFAULT false
)
RETURNS void
LANGUAGE plpgsql
AS $$
DECLARE
    v_part text := format('%s_pdefault', p_table);
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_class c
        JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = p_schema AND c.relname = v_part
    ) THEN
        EXECUTE format('CREATE TABLE %I.%I PARTITION OF %I.%I DEFAULT', p_schema, v_part, p_schema, p_table);
        IF p_append_only THEN
            PERFORM core.fn_apply_append_only_grants(p_schema, v_part);
        END IF;
    END IF;
END;
$$;
COMMENT ON FUNCTION core.fn_ensure_default_partition(text, text, boolean) IS '默认分区兜底：宁可落入默认分区并告警，也不允许审计与风险写入失败';

-- -----------------------------------------------------------------------------
-- 6. 数据库角色
-- 依据：蓝图 §9.1 凭证与资料分安全域、§11.0 凭证域与审计域独立
-- 口令由部署流水线注入，迁移脚本不设置口令（CAP-KEY-002）
-- -----------------------------------------------------------------------------
DO $$
DECLARE
    v_role text;
BEGIN
    FOREACH v_role IN ARRAY ARRAY['uc_migrator', 'uc_app', 'uc_cred_app', 'uc_audit_writer', 'uc_auditor', 'uc_readonly']
    LOOP
        IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = v_role) THEN
            EXECUTE format('CREATE ROLE %I NOLOGIN', v_role);
        END IF;
    END LOOP;
END;
$$;

-- 标准授权：业务域与控制面 schema 统一调用
CREATE OR REPLACE FUNCTION core.fn_apply_standard_grants(p_schema text)
RETURNS void
LANGUAGE plpgsql
AS $$
BEGIN
    EXECUTE format('GRANT USAGE ON SCHEMA %I TO uc_app, uc_readonly, uc_auditor', p_schema);
    EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA %I TO uc_app', p_schema);
    EXECUTE format('GRANT SELECT ON ALL TABLES IN SCHEMA %I TO uc_readonly, uc_auditor', p_schema);
    EXECUTE format('GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA %I TO uc_app', p_schema);
    EXECUTE format('ALTER DEFAULT PRIVILEGES IN SCHEMA %I GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO uc_app', p_schema);
    EXECUTE format('ALTER DEFAULT PRIVILEGES IN SCHEMA %I GRANT SELECT ON TABLES TO uc_readonly, uc_auditor', p_schema);
END;
$$;

-- 追加型表授权：只给 INSERT + SELECT，收回 UPDATE/DELETE/TRUNCATE（INV-G-008）
CREATE OR REPLACE FUNCTION core.fn_apply_append_only_grants(p_schema text, p_table text, p_role text DEFAULT 'uc_app')
RETURNS void
LANGUAGE plpgsql
AS $$
BEGIN
    EXECUTE format('REVOKE ALL ON %I.%I FROM %I', p_schema, p_table, p_role);
    EXECUTE format('GRANT SELECT, INSERT ON %I.%I TO %I', p_schema, p_table, p_role);
END;
$$;
COMMENT ON FUNCTION core.fn_apply_append_only_grants(text, text, text) IS '追加型表只授 INSERT/SELECT；这是审计不可篡改的主控制手段，触发器仅为纵深防御';

-- 凭证域收紧：仅认证服务角色可访问
CREATE OR REPLACE FUNCTION core.fn_apply_credential_grants(p_schema text)
RETURNS void
LANGUAGE plpgsql
AS $$
BEGIN
    EXECUTE format('REVOKE ALL ON SCHEMA %I FROM uc_app, uc_readonly, uc_auditor', p_schema);
    EXECUTE format('GRANT USAGE ON SCHEMA %I TO uc_cred_app', p_schema);
    EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA %I TO uc_cred_app', p_schema);
    EXECUTE format('ALTER DEFAULT PRIVILEGES IN SCHEMA %I GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO uc_cred_app', p_schema);
END;
$$;

SELECT core.fn_migration_apply('000', 'bootstrap：迁移台账、UUIDv7、通用触发器函数、分区维护、角色与授权助手');
