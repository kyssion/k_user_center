-- =============================================================================
-- 160_audit.sql
-- OBS 域审计子域（独立安全域）：审计事件、数据访问审计、审计封存
-- 依据：能力地图 §4.12；蓝图 §15.2（INV-G-007/008、CAP-OBS-001 至 005）
-- 关键：uc_app 只有 INSERT；哈希链 + 周期封存使删改可离线检测
-- =============================================================================

SET client_min_messages = warning;

-- -----------------------------------------------------------------------------
-- 1. 审计事件（CAP-OBS-001/002、蓝图 §15.2 字段清单）
-- 不设任何指向业务表的外键：审计必须在主体被删除后依然完整可读
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS obs.audit_event (
    id                  uuid        NOT NULL DEFAULT core.uuid_generate_v7(),
    occurred_at         timestamptz NOT NULL DEFAULT now(),
    recorded_at         timestamptz NOT NULL DEFAULT now(),
    event_category      text        NOT NULL,
    action_code         text        NOT NULL,
    outcome             text        NOT NULL,
    -- 操作者与代理链（CAP-ASR-012：Actor 与 Subject 必须可区分）
    actor_kind          text        NOT NULL,
    actor_ref           text        NOT NULL,
    on_behalf_of_ref    text        NULL,
    delegation_ref      text        NULL,
    -- 对象
    subject_public_id   text        NULL,
    tenant_id           uuid        NOT NULL DEFAULT '00000000-0000-0000-0000-000000000000',
    business_line_id    uuid        NULL,
    client_ref          text        NULL,
    resource_kind       text        NULL,
    resource_ref        text        NULL,
    -- 变更证据
    before_value        jsonb       NULL,
    after_value         jsonb       NULL,
    reason              text        NULL,
    approval_case_ref   text        NULL,
    policy_version      bigint      NULL,
    profile_code        text        NULL,
    -- 环境与追踪
    source_ip_hash      bytea       NULL,
    source_region       text        NULL,
    user_agent_hash     bytea       NULL,
    trace_id            text        NULL,
    correlation_id      text        NULL,
    data_classification text        NOT NULL DEFAULT 'SENSITIVE',
    -- 防篡改哈希链（应用侧按 chain_shard 计算，写入前取 advisory lock 串行化）
    chain_shard         smallint    NOT NULL DEFAULT 0,
    chain_seq           bigint      NOT NULL,
    prev_entry_hash     bytea       NULL,
    entry_hash          bytea       NOT NULL,
    CONSTRAINT pk_audit_event PRIMARY KEY (id, occurred_at),
    CONSTRAINT ck_audit_event_category CHECK (event_category IN (
        'AUTHENTICATION', 'AUTHORIZATION', 'IDENTITY_LIFECYCLE', 'IDENTIFIER_BINDING', 'CREDENTIAL',
        'SESSION', 'GRANT_CONSENT', 'TENANT_MEMBERSHIP', 'PROFILE', 'PRIVACY', 'ADMIN_OPERATION',
        'CONFIG_CHANGE', 'KEY_OPERATION', 'MACHINE_IDENTITY', 'RISK_DISPOSITION', 'MIGRATION'
    )),
    CONSTRAINT ck_audit_event_outcome CHECK (outcome IN ('SUCCESS', 'FAILURE', 'DENIED', 'PARTIAL', 'PENDING')),
    CONSTRAINT ck_audit_event_actor CHECK (actor_kind IN ('USER', 'ADMIN', 'AGENT', 'CLIENT', 'MACHINE', 'SYSTEM', 'IDENTITY_PROVIDER')),
    CONSTRAINT ck_audit_event_hash CHECK (octet_length(entry_hash) = 32),
    CONSTRAINT ck_audit_event_prev_hash CHECK (prev_entry_hash IS NULL OR octet_length(prev_entry_hash) = 32),
    CONSTRAINT ck_audit_event_chain CHECK (chain_shard BETWEEN 0 AND 255 AND chain_seq >= 1),
    -- 代理操作必须能区分"本人操作"与"代人操作"（能力地图 §6 集成约束）
    CONSTRAINT ck_audit_event_delegation CHECK (
        actor_kind <> 'AGENT' OR (on_behalf_of_ref IS NOT NULL AND delegation_ref IS NOT NULL)
    )
) PARTITION BY RANGE (occurred_at);
COMMENT ON TABLE obs.audit_event IS 'CAP-OBS-001/002 与 INV-G-008：不可篡改审计；uc_app 仅有 INSERT 权限，entry_hash 链 + obs.audit_seal 使删改可离线检测（AT-AUDIT-001）';
COMMENT ON COLUMN obs.audit_event.before_value IS '完整前后值只允许出现在本表，且不得包含密码、验证码、完整 Token 与私钥（INV-G-007）';
COMMENT ON COLUMN obs.audit_event.entry_hash IS 'SHA-256(规范化条目 || prev_entry_hash)；同 chain_shard 内严格串行，写入前取 pg_advisory_xact_lock';
COMMENT ON COLUMN obs.audit_event.subject_public_id IS '只存对外标识，不设外键：主体被删除后审计仍须完整可读（CAP-ID-022）';

-- 分区不使用通用追加型授权助手（它会一并授出 SELECT）；
-- obs 域的授权统一由本文件末尾的 DO 块与 ALTER DEFAULT PRIVILEGES 控制：uc_app 只有 INSERT
SELECT core.fn_ensure_monthly_partitions('obs', 'audit_event', 3, false);
SELECT core.fn_ensure_default_partition('obs', 'audit_event', false);

-- 同一分片内序号唯一，保证哈希链无分叉
CREATE UNIQUE INDEX IF NOT EXISTS ux_audit_event_chain
    ON obs.audit_event (chain_shard, chain_seq, occurred_at);

CREATE INDEX IF NOT EXISTS ix_audit_event_subject ON obs.audit_event (subject_public_id, occurred_at DESC);
CREATE INDEX IF NOT EXISTS ix_audit_event_actor ON obs.audit_event (actor_ref, occurred_at DESC);
CREATE INDEX IF NOT EXISTS ix_audit_event_trace ON obs.audit_event (trace_id) WHERE trace_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS ix_audit_event_category ON obs.audit_event (event_category, action_code, occurred_at DESC);
CREATE INDEX IF NOT EXISTS ix_audit_event_tenant ON obs.audit_event (tenant_id, occurred_at DESC);

-- -----------------------------------------------------------------------------
-- 2. 审计封存（CAP-OBS-004：周期根哈希 + KMS 签名）
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS obs.audit_seal (
    id              uuid        NOT NULL DEFAULT core.uuid_generate_v7(),
    chain_shard     smallint    NOT NULL,
    period_start    timestamptz NOT NULL,
    period_end      timestamptz NOT NULL,
    first_chain_seq bigint      NOT NULL,
    last_chain_seq  bigint      NOT NULL,
    entry_count     bigint      NOT NULL,
    root_hash       bytea       NOT NULL,
    prev_seal_hash  bytea       NULL,
    signature       bytea       NOT NULL,
    signing_key_id  text        NOT NULL,
    sealed_at       timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT pk_audit_seal PRIMARY KEY (id),
    CONSTRAINT uq_audit_seal_period UNIQUE (chain_shard, period_start),
    CONSTRAINT ck_audit_seal_window CHECK (period_end > period_start),
    CONSTRAINT ck_audit_seal_seq CHECK (last_chain_seq >= first_chain_seq),
    CONSTRAINT ck_audit_seal_count CHECK (entry_count >= 0),
    CONSTRAINT ck_audit_seal_root CHECK (octet_length(root_hash) = 32)
);
COMMENT ON TABLE obs.audit_seal IS 'CAP-OBS-004：周期封存根哈希并由 KMS 签名；任何删改都会导致重算根哈希与签名不符';

CREATE OR REPLACE TRIGGER trg_audit_seal_append_only
    BEFORE UPDATE OR DELETE ON obs.audit_seal
    FOR EACH STATEMENT EXECUTE FUNCTION core.fn_append_only();

-- -----------------------------------------------------------------------------
-- 3. 数据访问审计（CAP-OBS-003、CAP-PRIV-014、CAP-KEY-005）
-- 敏感资料查询、导出、解密与批量操作都必须留痕；本表的读取本身也要审计
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS obs.data_access_audit (
    id                  uuid        NOT NULL DEFAULT core.uuid_generate_v7(),
    occurred_at         timestamptz NOT NULL DEFAULT now(),
    actor_kind          text        NOT NULL,
    actor_ref           text        NOT NULL,
    on_behalf_of_ref    text        NULL,
    access_kind         text        NOT NULL,
    purpose_code        text        NOT NULL,
    justification       text        NULL,
    approval_case_ref   text        NULL,
    subject_public_id   text        NULL,
    tenant_id           uuid        NOT NULL DEFAULT '00000000-0000-0000-0000-000000000000',
    resource_kind       text        NOT NULL,
    accessed_fields     text[]      NOT NULL DEFAULT '{}',
    record_count        integer     NOT NULL DEFAULT 1,
    query_shape_hash    bytea       NULL,
    lookup_kind         text        NULL,
    was_masked          boolean     NOT NULL DEFAULT true,
    trace_id            text        NULL,
    CONSTRAINT pk_data_access_audit PRIMARY KEY (id, occurred_at),
    CONSTRAINT ck_data_access_audit_actor CHECK (actor_kind IN ('USER', 'ADMIN', 'AGENT', 'CLIENT', 'MACHINE', 'SYSTEM')),
    CONSTRAINT ck_data_access_audit_kind CHECK (access_kind IN (
        'VIEW', 'SEARCH', 'BLIND_INDEX_LOOKUP', 'DECRYPT', 'EXPORT', 'BULK_READ', 'TOMBSTONE_READ'
    )),
    CONSTRAINT ck_data_access_audit_count CHECK (record_count >= 0),
    -- CAP-OPS-007 / CAP-KEY-005：解密、导出与批量读取必须有目的与理由，且不得默认脱敏为假
    CONSTRAINT ck_data_access_audit_justification CHECK (
        access_kind NOT IN ('DECRYPT', 'EXPORT', 'BULK_READ', 'TOMBSTONE_READ') OR justification IS NOT NULL
    )
) PARTITION BY RANGE (occurred_at);
COMMENT ON TABLE obs.data_access_audit IS 'CAP-OBS-003 / CAP-PRIV-014：谁因何目的访问过哪些敏感信息；CAP-KEY-005 的盲索引逐次检索留痕也写入本表（AT-KEY-006）';
COMMENT ON COLUMN obs.data_access_audit.lookup_kind IS 'BLIND_INDEX_LOOKUP 时记录检索域（PHONE/EMAIL/EXTERNAL_KEY），用于批量枚举模式识别与限速';

SELECT core.fn_ensure_monthly_partitions('obs', 'data_access_audit', 3, false);
SELECT core.fn_ensure_default_partition('obs', 'data_access_audit', false);

CREATE INDEX IF NOT EXISTS ix_data_access_audit_actor ON obs.data_access_audit (actor_ref, occurred_at DESC);
CREATE INDEX IF NOT EXISTS ix_data_access_audit_subject ON obs.data_access_audit (subject_public_id, occurred_at DESC);
CREATE INDEX IF NOT EXISTS ix_data_access_audit_bulk ON obs.data_access_audit (occurred_at DESC)
    WHERE access_kind IN ('BLIND_INDEX_LOOKUP', 'BULK_READ', 'EXPORT');

-- -----------------------------------------------------------------------------
-- 4. 授权：审计域独立角色
-- 业务服务只能写入，审计员只读，任何角色都不能改删
-- -----------------------------------------------------------------------------
DO $$
BEGIN
    EXECUTE 'GRANT USAGE ON SCHEMA obs TO uc_app, uc_audit_writer, uc_auditor';
    EXECUTE 'REVOKE ALL ON ALL TABLES IN SCHEMA obs FROM uc_app, uc_readonly';
    EXECUTE 'GRANT INSERT ON obs.audit_event, obs.data_access_audit TO uc_app, uc_audit_writer';
    EXECUTE 'GRANT INSERT, SELECT ON obs.audit_seal TO uc_audit_writer';
    EXECUTE 'GRANT SELECT ON ALL TABLES IN SCHEMA obs TO uc_auditor';
    EXECUTE 'ALTER DEFAULT PRIVILEGES IN SCHEMA obs GRANT INSERT ON TABLES TO uc_app, uc_audit_writer';
    EXECUTE 'ALTER DEFAULT PRIVILEGES IN SCHEMA obs GRANT SELECT ON TABLES TO uc_auditor';
END;
$$;

-- 说明：uc_app 只有 INSERT 而没有 SELECT，因此用户可见的"安全活动历史"（CAP-SSC-004）
-- 不直接查审计表，而由应用维护脱敏可读视图或独立读模型（能力地图 §4.19 约束：同源不同视图）。

SELECT core.fn_migration_apply('160', 'audit：审计事件（分区）、审计封存、数据访问审计与审计域授权');
