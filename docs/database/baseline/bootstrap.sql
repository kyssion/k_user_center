
-- =============================================================================
-- baseline/bootstrap.sql
-- PostgreSQL 基线、Schema 与迁移台账
-- 目标：PostgreSQL 16+；应用：.NET 10 + SqlSugar
-- =============================================================================

BEGIN;

SET LOCAL lock_timeout = '10s';
SET LOCAL statement_timeout = '5min';
SET LOCAL client_min_messages = warning;

CREATE EXTENSION IF NOT EXISTS pgcrypto;

DO $$
BEGIN
    EXECUTE format(
        'COMMENT ON DATABASE %I IS %L',
        current_database(),
        '统一身份与访问平台 PostgreSQL 权威数据库；承载身份、认证、授权、租户、隐私、风险、机器身份、审计、集成与迁移控制数据。'
    );
END;
$$;
COMMENT ON EXTENSION pgcrypto IS '平台使用的 PostgreSQL 密码学扩展；提供 gen_random_uuid、digest 等数据库侧基础能力，不替代 KMS/HSM。';

CREATE SCHEMA IF NOT EXISTS core;
CREATE SCHEMA IF NOT EXISTS iam;
CREATE SCHEMA IF NOT EXISTS authn;
CREATE SCHEMA IF NOT EXISTS oauth;
CREATE SCHEMA IF NOT EXISTS org;
CREATE SCHEMA IF NOT EXISTS authz;
CREATE SCHEMA IF NOT EXISTS profile;
CREATE SCHEMA IF NOT EXISTS privacy;
CREATE SCHEMA IF NOT EXISTS federation;
CREATE SCHEMA IF NOT EXISTS risk;
CREATE SCHEMA IF NOT EXISTS workload;
CREATE SCHEMA IF NOT EXISTS assurance;
CREATE SCHEMA IF NOT EXISTS crypto;
CREATE SCHEMA IF NOT EXISTS control;
CREATE SCHEMA IF NOT EXISTS integration;
CREATE SCHEMA IF NOT EXISTS audit;
CREATE SCHEMA IF NOT EXISTS messaging;
CREATE SCHEMA IF NOT EXISTS migration;

COMMENT ON SCHEMA core IS '平台公共契约：迁移、幂等、Operation、参考数据与数据库辅助函数。';
COMMENT ON SCHEMA iam IS '身份主体与标识域：Global User、pairwise Subject、Identifier、账号合并与注销。';
COMMENT ON SCHEMA authn IS '认证域：认证器、密码、Challenge、Login Transaction、设备授权与保证等级证据。';
COMMENT ON SCHEMA oauth IS 'OAuth/OIDC 会话与授权域：Client、Resource、Grant、Session、Token、撤销与退出。';
COMMENT ON SCHEMA org IS '业务线、租户、组织、Membership、Invitation、用户组与计量。';
COMMENT ON SCHEMA authz IS '授权域：权限、角色、策略、义务、PEP 能力与决策证据。';
COMMENT ON SCHEMA profile IS '用户资料与身份核验断言域。';
COMMENT ON SCHEMA privacy IS '用途、Consent、协议、个人权利请求、保留与导出。';
COMMENT ON SCHEMA federation IS 'OIDC/SAML 联合、外部身份、属性映射与目录同步。';
COMMENT ON SCHEMA risk IS '风险信号、评估、处置、案件、拒绝名单与策略版本。';
COMMENT ON SCHEMA workload IS 'Client 之外的机器主体、工作负载证明、机器凭证与 Token Exchange。';
COMMENT ON SCHEMA assurance IS 'IAL/AAL/FAL、敏感操作要求、高保证恢复与自然人委托。';
COMMENT ON SCHEMA crypto IS '密钥、证书与 JWKS 发布台账；不保存私钥明文。';
COMMENT ON SCHEMA control IS '配置发布、高风险审批、安全例外、Break-glass 与复核。';
COMMENT ON SCHEMA integration IS '事件 Schema、Outbox、Webhook、投递、回放与消费方水位。';
COMMENT ON SCHEMA audit IS '不可篡改审计、数据访问审计与封存证明。';
COMMENT ON SCHEMA messaging IS '短信、邮件、Push 等消息供应商、模板、发送、回执与可达性。';
COMMENT ON SCHEMA migration IS '旧系统迁移批次、ID 映射、重复候选、变更日志与对账。';

CREATE TABLE core.schema_migration (
    version             text        NOT NULL,
    description         text        NOT NULL,
    script_sha256       text        NULL,
    applied_at          timestamptz NOT NULL DEFAULT clock_timestamp(),
    applied_by          text        NOT NULL DEFAULT current_user,
    application_name    text        NULL DEFAULT current_setting('application_name', true),
    CONSTRAINT pk_schema_migration PRIMARY KEY (version),
    CONSTRAINT ck_schema_migration_sha256 CHECK (script_sha256 IS NULL OR script_sha256 ~ '^[0-9a-f]{64}$')
);
COMMENT ON TABLE core.schema_migration IS 'CAP-PLT-007 / REQ-MIG-009：数据库迁移版本、内容摘要、执行时间与执行主体台账。';
COMMENT ON COLUMN core.schema_migration.version IS '不可重复的迁移或基线模块版本标识。';
COMMENT ON COLUMN core.schema_migration.description IS '迁移目的与范围的稳定说明；同版本说明漂移会被拒绝。';
COMMENT ON COLUMN core.schema_migration.script_sha256 IS '可选的迁移内容 SHA-256 十六进制摘要，用于发现内容漂移。';
COMMENT ON COLUMN core.schema_migration.applied_at IS '数据库可信时钟记录的迁移完成时间。';
COMMENT ON COLUMN core.schema_migration.applied_by IS '实际执行迁移的数据库角色。';
COMMENT ON COLUMN core.schema_migration.application_name IS '执行连接声明的 PostgreSQL application_name，便于审计定位。';
COMMENT ON CONSTRAINT pk_schema_migration ON core.schema_migration IS '主键约束：保证迁移版本仅登记一次。';
COMMENT ON CONSTRAINT ck_schema_migration_sha256 ON core.schema_migration IS '检查约束：非空脚本摘要必须是 64 位小写 SHA-256 十六进制文本。';
COMMENT ON INDEX core.pk_schema_migration IS '约束 pk_schema_migration 的支撑唯一索引。';

CREATE OR REPLACE FUNCTION core.fn_register_migration(
    p_version text,
    p_description text,
    p_script_sha256 text DEFAULT NULL
) RETURNS void
LANGUAGE plpgsql
AS $$
DECLARE
    v_existing core.schema_migration%ROWTYPE;
BEGIN
    IF p_script_sha256 IS NOT NULL AND p_script_sha256 !~ '^[0-9a-f]{64}$' THEN
        RAISE EXCEPTION 'MIGRATION_HASH_INVALID: %', p_version USING ERRCODE = '22023';
    END IF;

    SELECT * INTO v_existing
      FROM core.schema_migration
     WHERE version = p_version
     FOR UPDATE;

    IF FOUND THEN
        IF v_existing.description IS DISTINCT FROM p_description THEN
            RAISE EXCEPTION 'MIGRATION_DESCRIPTION_DRIFT: %', p_version USING ERRCODE = '55000';
        END IF;
        IF v_existing.script_sha256 IS NOT NULL
           AND p_script_sha256 IS NOT NULL

           AND v_existing.script_sha256 <> p_script_sha256 THEN
            RAISE EXCEPTION 'MIGRATION_CONTENT_DRIFT: %', p_version USING ERRCODE = '55000';
        END IF;
        IF v_existing.script_sha256 IS NULL AND p_script_sha256 IS NOT NULL THEN
            UPDATE core.schema_migration
               SET script_sha256 = p_script_sha256,
                   application_name = current_setting('application_name', true)
             WHERE version = p_version;
        END IF;
        RETURN;
    END IF;

    INSERT INTO core.schema_migration(version, description, script_sha256)
    VALUES (p_version, p_description, p_script_sha256);
END;
$$;
COMMENT ON FUNCTION core.fn_register_migration(text, text, text) IS '登记迁移并锁定版本、描述和可选 SHA-256；同版本描述或非空摘要漂移时失败。';

SELECT core.fn_register_migration(
    '000',
    'PostgreSQL 基线、Schema 与迁移台账',
    NULLIF(current_setting('kuc.migration_sha256', true), '')
);

COMMIT;
