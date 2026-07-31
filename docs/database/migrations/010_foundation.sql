-- =============================================================================
-- 010_foundation.sql
-- 域 schema、对外标识台账、幂等与异步 Operation、参考数据表
-- 依据：能力地图 §11.0（按域码划分模块边界）、蓝图 §5.1 API 基线、§5.2 失败语义、§16 一致性等级
-- =============================================================================

SET client_min_messages = warning;

-- -----------------------------------------------------------------------------
-- 1. 域 schema：schema 名 == 能力地图域码，即模块边界
--    禁止跨 schema 直接引用对方数据访问层，跨域一律走应用服务或事件
-- -----------------------------------------------------------------------------
CREATE SCHEMA IF NOT EXISTS id;       COMMENT ON SCHEMA id      IS 'ID 域：Global User、Subject、Identifier、墓碑与别名（能力地图 §4.1）';
CREATE SCHEMA IF NOT EXISTS cred;     COMMENT ON SCHEMA cred    IS 'AUTH 域凭证子域（独立安全域）：密码、认证器、TOTP、恢复码（蓝图 §9.1）';
CREATE SCHEMA IF NOT EXISTS auth;     COMMENT ON SCHEMA auth    IS 'AUTH 域：登录事务、验证 Challenge、已完成因子（能力地图 §4.2）';
CREATE SCHEMA IF NOT EXISTS oap;      COMMENT ON SCHEMA oap     IS 'OAP 域：Application、Client、回调、Scope、API Resource（能力地图 §4.14）';
CREATE SCHEMA IF NOT EXISTS session;  COMMENT ON SCHEMA session IS 'SESSION 域：会话、设备、Grant、Token 家族、授权码、撤销记录（能力地图 §4.3）';
CREATE SCHEMA IF NOT EXISTS tenant;   COMMENT ON SCHEMA tenant  IS 'TENANT 域：业务线、租户、组织、Membership、邀请、用户组、计量（能力地图 §4.5）';
CREATE SCHEMA IF NOT EXISTS authz;    COMMENT ON SCHEMA authz   IS 'AUTHZ 域：权限目录、角色、授权关系、策略发布、决策日志（能力地图 §4.6）';
CREATE SCHEMA IF NOT EXISTS profile;  COMMENT ON SCHEMA profile IS 'PROFILE 域：公共资料、字段元数据、业务扩展资料、IAL 断言（能力地图 §4.4）';
CREATE SCHEMA IF NOT EXISTS priv;     COMMENT ON SCHEMA priv    IS 'PRIV 域：Consent、协议、订阅、隐私请求、法律保留、数据目录（能力地图 §4.9）';
CREATE SCHEMA IF NOT EXISTS fed;      COMMENT ON SCHEMA fed     IS 'FED 域：身份源、外部身份、属性映射、SCIM 同步状态（能力地图 §4.7）';
CREATE SCHEMA IF NOT EXISTS risk;     COMMENT ON SCHEMA risk    IS 'RISK 域：风险信号、评估、案件、黑名单（能力地图 §4.8）';
CREATE SCHEMA IF NOT EXISTS machine;  COMMENT ON SCHEMA machine IS 'MACHINE 域：机器主体、机器凭证、工作负载证明（能力地图 §4.15）';
CREATE SCHEMA IF NOT EXISTS kms;      COMMENT ON SCHEMA kms     IS 'KEY 域：密钥与证书台账、JWKS 发布记录；不存私钥材料（REQ-KEY-001）';
CREATE SCHEMA IF NOT EXISTS ctrl;     COMMENT ON SCHEMA ctrl    IS 'CTRL 域：配置发布、审批单、安全例外、Break-glass（能力地图 §4.16）';
CREATE SCHEMA IF NOT EXISTS event;    COMMENT ON SCHEMA event   IS 'EVENT 域：Outbox、订阅、Webhook、投递、消费方水位、Schema 注册（能力地图 §4.17）';
CREATE SCHEMA IF NOT EXISTS obs;      COMMENT ON SCHEMA obs     IS 'OBS 域审计子域（独立安全域）：审计事件、数据访问审计、封存（CAP-OBS-004）';
CREATE SCHEMA IF NOT EXISTS msg;      COMMENT ON SCHEMA msg     IS 'MSG 域：供应商、模板、发送记录、回执、可达性（能力地图 §4.18）';
CREATE SCHEMA IF NOT EXISTS asr;      COMMENT ON SCHEMA asr     IS 'ASR 域：敏感操作等级要求、账号恢复、人对人委托（能力地图 §4.20）';
CREATE SCHEMA IF NOT EXISTS mig;      COMMENT ON SCHEMA mig     IS 'MIG 域：旧 ID 映射、迁移批次、切换后变更日志（蓝图 §17）';

-- -----------------------------------------------------------------------------
-- 2. 对外标识台账（INV-G-001：UID / Subject ID / Membership ID 永不复用）
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS core.public_id_ledger (
    public_id    text        NOT NULL,
    entity_type  text        NOT NULL,
    issued_at    timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT pk_public_id_ledger PRIMARY KEY (public_id),
    CONSTRAINT ck_public_id_ledger_entity CHECK (entity_type IN (
        'GLOBAL_USER', 'SUBJECT', 'MEMBERSHIP', 'TENANT', 'BUSINESS_LINE', 'ORGANIZATION',
        'CLIENT', 'APPLICATION', 'API_RESOURCE', 'SESSION', 'DEVICE', 'GRANT',
        'MACHINE_PRINCIPAL', 'KEY_ASSET', 'PRIVACY_REQUEST', 'RISK_CASE', 'APPROVAL_CASE',
        'CONFIG_RELEASE', 'OPERATION', 'INVITATION', 'RECOVERY_REQUEST', 'DELEGATION',
        'MIGRATION_BATCH', 'IDENTITY_PROVIDER'
    )),
    CONSTRAINT ck_public_id_ledger_format CHECK (public_id ~ '^[a-z]{2,6}_[A-Za-z0-9]{16,32}$')
);
COMMENT ON TABLE core.public_id_ledger IS 'INV-G-001 执行点：所有对外标识签发即入账，实体行删除不释放占用，保证 UID/Subject/Membership ID 永不复用';

CREATE OR REPLACE TRIGGER trg_public_id_ledger_append_only
    BEFORE UPDATE OR DELETE ON core.public_id_ledger
    FOR EACH STATEMENT EXECUTE FUNCTION core.fn_append_only();

CREATE INDEX IF NOT EXISTS ix_public_id_ledger_entity ON core.public_id_ledger (entity_type, issued_at DESC);

-- -----------------------------------------------------------------------------
-- 3. 幂等记录（API-G-001、INV-G-012）
-- 相同键 + 相同请求返回同结果；相同键 + 不同请求必须冲突
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS core.idempotency_record (
    id                uuid        NOT NULL DEFAULT core.uuid_generate_v7(),
    scope             text        NOT NULL,
    idempotency_key   text        NOT NULL,
    principal_ref     text        NOT NULL,
    endpoint          text        NOT NULL,
    request_hash      bytea       NOT NULL,
    record_state      text        NOT NULL DEFAULT 'IN_PROGRESS',
    http_status       integer     NULL,
    response_body     jsonb       NULL,
    operation_id      text        NULL,
    created_at        timestamptz NOT NULL DEFAULT now(),
    updated_at        timestamptz NOT NULL DEFAULT now(),
    expires_at        timestamptz NOT NULL,
    CONSTRAINT pk_idempotency_record PRIMARY KEY (id),
    CONSTRAINT uq_idempotency_record_key UNIQUE (scope, idempotency_key),
    CONSTRAINT ck_idempotency_record_state CHECK (record_state IN ('IN_PROGRESS', 'COMPLETED', 'FAILED')),
    CONSTRAINT ck_idempotency_record_hash CHECK (octet_length(request_hash) = 32)
);
COMMENT ON TABLE core.idempotency_record IS 'API-G-001 / INV-G-012：幂等键去重与结果重放，保留期不短于客户端最大重试窗口';

CREATE OR REPLACE TRIGGER trg_idempotency_record_touch
    BEFORE UPDATE ON core.idempotency_record
    FOR EACH ROW EXECUTE FUNCTION core.fn_touch_updated_at();

CREATE INDEX IF NOT EXISTS ix_idempotency_record_expires ON core.idempotency_record (expires_at);

-- -----------------------------------------------------------------------------
-- 4. 异步 Operation（API-G-003、API-G-004、蓝图 §16 Saga 对外语义）
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS core.async_operation (
    id                  uuid        NOT NULL DEFAULT core.uuid_generate_v7(),
    public_id           text        NOT NULL,
    operation_type      text        NOT NULL,
    operation_state     text        NOT NULL DEFAULT 'PENDING',
    subject_public_id   text        NULL,
    tenant_id           uuid        NULL,
    business_line_id    uuid        NULL,
    initiated_by_type   text        NOT NULL,
    initiated_by_ref    text        NOT NULL,
    idempotency_key     text        NULL,
    saga_coordinator    text        NULL,
    step_total          integer     NOT NULL DEFAULT 0,
    step_completed      integer     NOT NULL DEFAULT 0,
    blocked_reason_code text        NULL,
    blocked_owner       text        NULL,
    failure_code        text        NULL,
    result              jsonb       NULL,
    irreversible_passed boolean     NOT NULL DEFAULT false,
    trace_id            text        NULL,
    correlation_id      text        NULL,
    created_at          timestamptz NOT NULL DEFAULT now(),
    updated_at          timestamptz NOT NULL DEFAULT now(),
    completed_at        timestamptz NULL,
    row_version         bigint      NOT NULL DEFAULT 1,
    CONSTRAINT pk_async_operation PRIMARY KEY (id),
    CONSTRAINT uq_async_operation_public_id UNIQUE (public_id),
    CONSTRAINT ck_async_operation_state CHECK (operation_state IN ('PENDING', 'PARTIAL', 'BLOCKED', 'COMPLETED', 'FAILED')),
    CONSTRAINT ck_async_operation_initiator CHECK (initiated_by_type IN ('USER', 'ADMIN', 'CLIENT', 'SYSTEM', 'MACHINE')),
    CONSTRAINT ck_async_operation_blocked CHECK (
        operation_state <> 'BLOCKED' OR (blocked_reason_code IS NOT NULL AND blocked_owner IS NOT NULL)
    ),
    CONSTRAINT ck_async_operation_progress CHECK (step_completed >= 0 AND step_completed <= GREATEST(step_total, step_completed))
);
COMMENT ON TABLE core.async_operation IS 'API-G-003/004：跨事务边界操作返回 202 + operation_id；BLOCKED 必须带原因与责任方（REQ-ID-008、CAP-ID-023）';

CREATE OR REPLACE TRIGGER trg_async_operation_touch
    BEFORE UPDATE ON core.async_operation
    FOR EACH ROW EXECUTE FUNCTION core.fn_touch_updated_at();

CREATE OR REPLACE TRIGGER trg_async_operation_public_id
    BEFORE INSERT ON core.async_operation
    FOR EACH ROW EXECUTE FUNCTION core.fn_register_public_id('OPERATION');

CREATE INDEX IF NOT EXISTS ix_async_operation_state    ON core.async_operation (operation_state, created_at DESC);
CREATE INDEX IF NOT EXISTS ix_async_operation_subject  ON core.async_operation (subject_public_id, created_at DESC);
CREATE INDEX IF NOT EXISTS ix_async_operation_tenant   ON core.async_operation (tenant_id, created_at DESC) WHERE tenant_id IS NOT NULL;

CREATE TABLE IF NOT EXISTS core.async_operation_step (
    id                uuid        NOT NULL DEFAULT core.uuid_generate_v7(),
    operation_id      uuid        NOT NULL,
    step_no           integer     NOT NULL,
    step_name         text        NOT NULL,
    authority_domain  text        NOT NULL,
    step_state        text        NOT NULL DEFAULT 'PENDING',
    compensatable     boolean     NOT NULL DEFAULT true,
    attempt_count     integer     NOT NULL DEFAULT 0,
    next_attempt_at   timestamptz NULL,
    last_error_code   text        NULL,
    evidence          jsonb       NULL,
    created_at        timestamptz NOT NULL DEFAULT now(),
    updated_at        timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT pk_async_operation_step PRIMARY KEY (id),
    CONSTRAINT uq_async_operation_step_no UNIQUE (operation_id, step_no),
    CONSTRAINT fk_async_operation_step_op FOREIGN KEY (operation_id) REFERENCES core.async_operation (id) ON DELETE CASCADE,
    CONSTRAINT ck_async_operation_step_state CHECK (step_state IN ('PENDING', 'RUNNING', 'SUCCEEDED', 'FAILED', 'COMPENSATED', 'MANUAL'))
);
COMMENT ON TABLE core.async_operation_step IS '蓝图 §16：每个 Saga 步骤声明权威域、幂等、可补偿性与人工接管状态（API-G-004）';

CREATE OR REPLACE TRIGGER trg_async_operation_step_touch
    BEFORE UPDATE ON core.async_operation_step
    FOR EACH ROW EXECUTE FUNCTION core.fn_touch_updated_at();

-- -----------------------------------------------------------------------------
-- 5. 参考数据（内容由 900_seed_baseline.sql 填充，来源为蓝图，禁止实现方自行约定）
-- -----------------------------------------------------------------------------

-- 5.1 安全 Profile（蓝图 §6）
CREATE TABLE IF NOT EXISTS core.security_profile (
    profile_code        text        NOT NULL,
    profile_version     text        NOT NULL,
    display_name        text        NOT NULL,
    applicability       text        NOT NULL,
    min_requirement     text        NOT NULL,
    revocation_slo_code text        NOT NULL,
    is_active           boolean     NOT NULL DEFAULT true,
    deprecated_after    timestamptz NULL,
    created_at          timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT pk_security_profile PRIMARY KEY (profile_code, profile_version),
    CONSTRAINT ck_security_profile_code CHECK (profile_code IN ('SP1', 'SP2', 'SP3', 'SP4', 'SP5')),
    CONSTRAINT ck_security_profile_slo CHECK (revocation_slo_code IN ('SLO-REVOKE-001', 'SLO-REVOKE-002'))
);
COMMENT ON TABLE core.security_profile IS '蓝图 §6 安全 Profile 与版本；REQ-OAP-003 要求 Profile 版本进入 Token、审计与接入报告';

CREATE UNIQUE INDEX IF NOT EXISTS ux_security_profile_active
    ON core.security_profile (profile_code) WHERE is_active;

-- 5.2 时长基线（蓝图 §15.3.1；TTL-* / TERM-*）
CREATE TABLE IF NOT EXISTS core.duration_baseline (
    baseline_code    text        NOT NULL,
    target_object    text        NOT NULL,
    -- 不适用 Profile 维度时填 '*'，避免主键含 NULL 或表达式
    profile_code     text        NOT NULL DEFAULT '*',
    baseline_text    text        NOT NULL,
    max_duration     interval    NULL,
    min_duration     interval    NULL,
    max_attempts     integer     NULL,
    source_reference text        NOT NULL,
    created_at       timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT pk_duration_baseline PRIMARY KEY (baseline_code, profile_code),
    CONSTRAINT ck_duration_baseline_profile CHECK (profile_code IN ('*', 'SP1', 'SP2', 'SP3', 'SP4', 'SP5')),
    CONSTRAINT ck_duration_baseline_code CHECK (baseline_code ~ '^(TTL|TERM)-[A-Z]+-[0-9]{3}$')
);
COMMENT ON TABLE core.duration_baseline IS '蓝图 §15.3.1 时长基线落库；未登记的时长不得由实现方自行约定，放宽必须走 REQ-CTRL-002 审批';

-- 5.3 数据分级（CAP-PRIV-005）与一致性等级（蓝图 §16）
CREATE TABLE IF NOT EXISTS core.data_classification (
    classification_code text NOT NULL,
    display_name        text NOT NULL,
    handling_rule       text NOT NULL,
    may_appear_in_event boolean NOT NULL DEFAULT false,
    requires_encryption boolean NOT NULL DEFAULT false,
    CONSTRAINT pk_data_classification PRIMARY KEY (classification_code),
    CONSTRAINT ck_data_classification_code CHECK (classification_code IN ('PUBLIC', 'INTERNAL', 'SENSITIVE', 'STRICT_SENSITIVE'))
);
COMMENT ON TABLE core.data_classification IS 'CAP-PRIV-005 数据分类分级；EVT-G-006 依据本表判定事件载荷是否可携带该级别字段';

CREATE TABLE IF NOT EXISTS core.consistency_level (
    level_code    text NOT NULL,
    display_name  text NOT NULL,
    semantics     text NOT NULL,
    CONSTRAINT pk_consistency_level PRIMARY KEY (level_code),
    CONSTRAINT ck_consistency_level_code CHECK (level_code IN ('C0', 'C1', 'C2', 'C3'))
);
COMMENT ON TABLE core.consistency_level IS '蓝图 §16 一致性等级：C0 强一致、C1 有界陈旧、C2 最终一致、C3 可靠追加（INV-G-010）';

-- 5.4 统一错误契约（蓝图 §5.2、API-G-006、CAP-API-004）
CREATE TABLE IF NOT EXISTS core.error_code (
    domain_code    text    NOT NULL,
    http_status    integer NOT NULL,
    meaning        text    NOT NULL,
    client_action  text    NOT NULL,
    retryable      boolean NOT NULL,
    published_at   timestamptz NOT NULL DEFAULT now(),
    deprecated_at  timestamptz NULL,
    CONSTRAINT pk_error_code PRIMARY KEY (domain_code),
    CONSTRAINT ck_error_code_status CHECK (http_status BETWEEN 400 AND 599)
);
COMMENT ON TABLE core.error_code IS 'CAP-API-004：错误码一经发布不得改变语义；删除只能标记 deprecated_at';

CREATE OR REPLACE TRIGGER trg_error_code_immutable_semantics
    BEFORE DELETE ON core.error_code
    FOR EACH STATEMENT EXECUTE FUNCTION core.fn_append_only();

-- -----------------------------------------------------------------------------
-- 6. 授权
-- -----------------------------------------------------------------------------
SELECT core.fn_apply_standard_grants('core');
SELECT core.fn_apply_append_only_grants('core', 'public_id_ledger');
-- error_code 允许 UPDATE（仅为写入 deprecated_at），禁止 DELETE，由 trg_error_code_immutable_semantics 保证

SELECT core.fn_migration_apply('010', 'foundation：域 schema、对外标识台账、幂等与异步 Operation、参考数据表');
