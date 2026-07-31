-- =============================================================================
-- 120_risk.sql
-- RISK 域：风险信号、风险评估、风险案件、黑名单、风险策略版本
-- 依据：能力地图 §4.8；蓝图 §14（REQ-RISK-001 至 008）
-- 关键：信号可追溯、策略可回滚、误伤与申诉改判必须可度量（CAP-OBS-010）
-- =============================================================================

SET client_min_messages = warning;

-- -----------------------------------------------------------------------------
-- 1. 风险信号（REQ-RISK-001：来源、时间、置信度、适用主体、保留期）
-- 按月分区、追加型；保留期受 priv.data_catalog_field 约束
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS risk.risk_signal (
    id                uuid        NOT NULL DEFAULT core.uuid_generate_v7(),
    occurred_at       timestamptz NOT NULL DEFAULT now(),
    signal_code       text        NOT NULL,
    source_kind       text        NOT NULL,
    source_ref        text        NULL,
    confidence        smallint    NOT NULL,
    subject_kind      text        NOT NULL,
    subject_ref       text        NOT NULL,
    tenant_id         uuid        NOT NULL DEFAULT '00000000-0000-0000-0000-000000000000',
    client_ref        text        NULL,
    payload           jsonb       NULL,
    data_classification text      NOT NULL DEFAULT 'INTERNAL',
    retention_until   timestamptz NOT NULL,
    trace_id          text        NULL,
    CONSTRAINT pk_risk_signal PRIMARY KEY (id, occurred_at),
    CONSTRAINT ck_risk_signal_source CHECK (source_kind IN (
        'PLATFORM_RULE', 'DEVICE_SDK', 'NETWORK_INTEL', 'BEHAVIOR_MODEL', 'EXTERNAL_VENDOR', 'USER_REPORT', 'ADMIN'
    )),
    CONSTRAINT ck_risk_signal_subject CHECK (subject_kind IN ('USER', 'DEVICE', 'IP', 'IDENTIFIER', 'CLIENT', 'MACHINE_PRINCIPAL')),
    CONSTRAINT ck_risk_signal_confidence CHECK (confidence BETWEEN 0 AND 100),
    CONSTRAINT ck_risk_signal_retention CHECK (retention_until > occurred_at)
) PARTITION BY RANGE (occurred_at);
COMMENT ON TABLE risk.risk_signal IS 'REQ-RISK-001 风险信号；采集范围与保留期受 CAP-PRIV-004 数据目录约束，风险画像不得成为绕过隐私治理的旁路';

SELECT core.fn_ensure_monthly_partitions('risk', 'risk_signal', 3, true);
SELECT core.fn_ensure_default_partition('risk', 'risk_signal', true);

CREATE INDEX IF NOT EXISTS ix_risk_signal_subject ON risk.risk_signal (subject_kind, subject_ref, occurred_at DESC);
CREATE INDEX IF NOT EXISTS ix_risk_signal_code ON risk.risk_signal (signal_code, occurred_at DESC);
CREATE INDEX IF NOT EXISTS ix_risk_signal_retention ON risk.risk_signal (retention_until);

-- -----------------------------------------------------------------------------
-- 2. 风险评估（CAP-RISK-006/007、REQ-RISK-003/005）
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS risk.risk_assessment (
    id                    uuid        NOT NULL DEFAULT core.uuid_generate_v7(),
    assessment_state      text        NOT NULL DEFAULT 'PENDING',
    event_kind            text        NOT NULL,
    user_id               uuid        NULL,
    login_transaction_id  uuid        NULL,
    client_id             uuid        NULL,
    device_id             uuid        NULL,
    tenant_id             uuid        NOT NULL DEFAULT '00000000-0000-0000-0000-000000000000',
    risk_score            smallint    NULL,
    risk_level            text        NULL,
    matched_rules         text[]      NOT NULL DEFAULT '{}',
    signal_ids            uuid[]      NOT NULL DEFAULT '{}',
    policy_version        bigint      NOT NULL,
    disposition           text        NULL,
    disposition_reason    text        NULL,
    explanation           jsonb       NULL,
    decided_at            timestamptz NULL,
    expires_at            timestamptz NULL,
    created_at            timestamptz NOT NULL DEFAULT now(),
    updated_at            timestamptz NOT NULL DEFAULT now(),
    row_version           bigint      NOT NULL DEFAULT 1,
    CONSTRAINT pk_risk_assessment PRIMARY KEY (id),
    CONSTRAINT fk_risk_assessment_user FOREIGN KEY (user_id) REFERENCES id.global_user (id),
    CONSTRAINT fk_risk_assessment_login_tx FOREIGN KEY (login_transaction_id) REFERENCES auth.login_transaction (id),
    CONSTRAINT fk_risk_assessment_client FOREIGN KEY (client_id) REFERENCES oap.client (id),
    CONSTRAINT ck_risk_assessment_state CHECK (assessment_state IN ('PENDING', 'SCORED', 'DISPOSED', 'EXPIRED')),
    -- REQ-RISK-... §14.1：风险决策必须覆盖注册、登录、MFA、找回、绑定、换绑、合并、注销撤回、Consent、授权、管理员操作、Client 变更、机器凭证使用
    CONSTRAINT ck_risk_assessment_event CHECK (event_kind IN (
        'REGISTER', 'LOGIN', 'MFA_CHALLENGE', 'PASSKEY_REGISTER', 'RECOVERY', 'BIND_IDENTIFIER', 'REBIND_IDENTIFIER',
        'ACCOUNT_MERGE', 'DELETE_REQUEST', 'DELETE_WITHDRAW', 'CONSENT_CHANGE', 'AUTHORIZATION',
        'ADMIN_OPERATION', 'CLIENT_CHANGE', 'MACHINE_CREDENTIAL_USE', 'DATA_EXPORT'
    )),
    CONSTRAINT ck_risk_assessment_level CHECK (risk_level IS NULL OR risk_level IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    CONSTRAINT ck_risk_assessment_score CHECK (risk_score IS NULL OR risk_score BETWEEN 0 AND 100),
    -- REQ-RISK-003：处置取值集合
    CONSTRAINT ck_risk_assessment_disposition CHECK (disposition IS NULL OR disposition IN (
        'ALLOW', 'CHALLENGE', 'STEP_UP', 'WAIT', 'DENY', 'FREEZE', 'MANUAL_REVIEW'
    )),
    CONSTRAINT ck_risk_assessment_disposed CHECK (
        (assessment_state = 'DISPOSED') = (disposition IS NOT NULL AND decided_at IS NOT NULL)
    ),
    CONSTRAINT ck_risk_assessment_scored CHECK (
        assessment_state NOT IN ('SCORED', 'DISPOSED') OR (risk_score IS NOT NULL AND risk_level IS NOT NULL)
    )
);
COMMENT ON TABLE risk.risk_assessment IS 'CAP-RISK-006/007：聚合信号输出等级与命中原因；REQ-RISK-005 风险服务不可用时 SP2/SP3/SP5 失败关闭（AT-RISK-002）';

CREATE OR REPLACE TRIGGER trg_risk_assessment_touch
    BEFORE UPDATE ON risk.risk_assessment
    FOR EACH ROW EXECUTE FUNCTION core.fn_touch_updated_at();

CREATE INDEX IF NOT EXISTS ix_risk_assessment_user ON risk.risk_assessment (user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS ix_risk_assessment_event ON risk.risk_assessment (event_kind, risk_level, created_at DESC);

-- -----------------------------------------------------------------------------
-- 3. 风险案件（CAP-RISK-017：证据、审核、申诉、反馈标签、复盘）
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS risk.risk_case (
    id                  uuid        NOT NULL DEFAULT core.uuid_generate_v7(),
    public_id           text        NOT NULL,
    case_type           text        NOT NULL,
    case_state          text        NOT NULL DEFAULT 'OPEN',
    severity            text        NOT NULL DEFAULT 'MEDIUM',
    subject_kind        text        NOT NULL,
    subject_ref         text        NOT NULL,
    tenant_id           uuid        NOT NULL DEFAULT '00000000-0000-0000-0000-000000000000',
    assessment_id       uuid        NULL,
    opened_at           timestamptz NOT NULL DEFAULT now(),
    opened_by_ref       text        NOT NULL,
    assigned_to_ref     text        NULL,
    evidence            jsonb       NULL,
    resolution_code     text        NULL,
    is_false_positive   boolean     NULL,
    appeal_state        text        NOT NULL DEFAULT 'NONE',
    appeal_submitted_at timestamptz NULL,
    appeal_decided_at   timestamptz NULL,
    appeal_overturned   boolean     NULL,
    closed_at           timestamptz NULL,
    postmortem_ref      text        NULL,
    created_at          timestamptz NOT NULL DEFAULT now(),
    updated_at          timestamptz NOT NULL DEFAULT now(),
    row_version         bigint      NOT NULL DEFAULT 1,
    CONSTRAINT pk_risk_case PRIMARY KEY (id),
    CONSTRAINT uq_risk_case_public_id UNIQUE (public_id),
    CONSTRAINT fk_risk_case_assessment FOREIGN KEY (assessment_id) REFERENCES risk.risk_assessment (id),
    CONSTRAINT ck_risk_case_type CHECK (case_type IN (
        'ACCOUNT_TAKEOVER', 'REGISTRATION_ABUSE', 'RECOVERY_FRAUD', 'CREDENTIAL_SHARING',
        'MACHINE_CREDENTIAL_ABUSE', 'INSIDER_ABUSE', 'PROMOTION_ABUSE', 'GROUP_FRAUD', 'KEY_COMPROMISE'
    )),
    CONSTRAINT ck_risk_case_state CHECK (case_state IN ('OPEN', 'INVESTIGATING', 'ACTION_TAKEN', 'CLOSED')),
    CONSTRAINT ck_risk_case_severity CHECK (severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    CONSTRAINT ck_risk_case_appeal CHECK (appeal_state IN ('NONE', 'SUBMITTED', 'UNDER_REVIEW', 'UPHELD', 'OVERTURNED')),
    -- CAP-OBS-010：关闭必须给出误伤判定，否则无法度量误拒率与申诉改判率
    CONSTRAINT ck_risk_case_closed CHECK (
        (case_state = 'CLOSED') = (closed_at IS NOT NULL AND resolution_code IS NOT NULL AND is_false_positive IS NOT NULL)
    ),
    CONSTRAINT ck_risk_case_appeal_decided CHECK (
        appeal_state NOT IN ('UPHELD', 'OVERTURNED') OR (appeal_decided_at IS NOT NULL AND appeal_overturned IS NOT NULL)
    )
);
COMMENT ON TABLE risk.risk_case IS 'CAP-RISK-017 风险案件闭环；is_false_positive 与 appeal_overturned 是 CAP-OBS-010 误拒率与申诉改判率的唯一数据源';

CREATE OR REPLACE TRIGGER trg_risk_case_touch
    BEFORE UPDATE ON risk.risk_case
    FOR EACH ROW EXECUTE FUNCTION core.fn_touch_updated_at();
CREATE OR REPLACE TRIGGER trg_risk_case_public_id
    BEFORE INSERT ON risk.risk_case
    FOR EACH ROW EXECUTE FUNCTION core.fn_register_public_id('RISK_CASE');

CREATE INDEX IF NOT EXISTS ix_risk_case_state ON risk.risk_case (case_state, severity, opened_at DESC);
CREATE INDEX IF NOT EXISTS ix_risk_case_subject ON risk.risk_case (subject_kind, subject_ref, opened_at DESC);

-- -----------------------------------------------------------------------------
-- 4. 黑名单与限制（CAP-ID-025、CAP-RISK-002）
-- 标识类条目只存盲索引，不存明文
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS risk.deny_list (
    id               uuid        NOT NULL DEFAULT core.uuid_generate_v7(),
    entry_kind       text        NOT NULL,
    entry_value_hash bytea       NOT NULL,
    entry_display    text        NULL,
    scope_kind       text        NOT NULL DEFAULT 'PLATFORM',
    scope_ref_id     uuid        NOT NULL DEFAULT '00000000-0000-0000-0000-000000000000',
    entry_state      text        NOT NULL DEFAULT 'ACTIVE',
    reason_code      text        NOT NULL,
    case_id          uuid        NULL,
    added_by_ref     text        NOT NULL,
    added_at         timestamptz NOT NULL DEFAULT now(),
    expires_at       timestamptz NULL,
    removed_at       timestamptz NULL,
    removed_by_ref   text        NULL,
    CONSTRAINT pk_deny_list PRIMARY KEY (id),
    CONSTRAINT fk_deny_list_case FOREIGN KEY (case_id) REFERENCES risk.risk_case (id),
    CONSTRAINT ck_deny_list_kind CHECK (entry_kind IN (
        'PHONE_BLIND_INDEX', 'EMAIL_BLIND_INDEX', 'EMAIL_DOMAIN', 'DEVICE_FINGERPRINT', 'IP_HASH',
        'IP_CIDR', 'USER', 'EXTERNAL_IDENTITY', 'BANK_CARD_HASH'
    )),
    CONSTRAINT ck_deny_list_scope CHECK (scope_kind IN ('PLATFORM', 'BUSINESS_LINE', 'TENANT')),
    CONSTRAINT ck_deny_list_state CHECK (entry_state IN ('ACTIVE', 'EXPIRED', 'REMOVED')),
    CONSTRAINT ck_deny_list_hash CHECK (octet_length(entry_value_hash) = 32),
    CONSTRAINT ck_deny_list_removed CHECK ((entry_state = 'REMOVED') = (removed_at IS NOT NULL AND removed_by_ref IS NOT NULL))
);
COMMENT ON TABLE risk.deny_list IS 'CAP-ID-025 黑名单；标识类条目只存盲索引摘要（REQ-KEY-008），entry_display 仅保留掩码或域名';

CREATE UNIQUE INDEX IF NOT EXISTS ux_deny_list_active
    ON risk.deny_list (entry_kind, entry_value_hash, scope_kind, scope_ref_id)
    WHERE entry_state = 'ACTIVE';
CREATE INDEX IF NOT EXISTS ix_deny_list_expiry ON risk.deny_list (expires_at) WHERE entry_state = 'ACTIVE';

-- -----------------------------------------------------------------------------
-- 5. 风险策略版本（REQ-RISK-002/006、CAP-RISK-018）
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS risk.risk_policy_version (
    policy_version     bigint      NOT NULL,
    policy_state       text        NOT NULL DEFAULT 'DRAFT',
    content_hash       bytea       NOT NULL,
    content            jsonb       NOT NULL,
    feature_sources    text[]      NOT NULL DEFAULT '{}',
    model_ref          text        NULL,
    submitted_by_ref   text        NOT NULL,
    approved_by_ref    text        NULL,
    activated_at       timestamptz NULL,
    canary_percentage  smallint    NULL,
    deactivated_at     timestamptz NULL,
    rollback_of        bigint      NULL,
    emergency_disabled_at timestamptz NULL,
    drift_metrics      jsonb       NULL,
    created_at         timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT pk_risk_policy_version PRIMARY KEY (policy_version),
    CONSTRAINT fk_risk_policy_version_rollback FOREIGN KEY (rollback_of) REFERENCES risk.risk_policy_version (policy_version),
    CONSTRAINT ck_risk_policy_version_state CHECK (policy_state IN ('DRAFT', 'SHADOW', 'CANARY', 'ACTIVE', 'DEACTIVATED', 'EMERGENCY_DISABLED')),
    -- REQ-CTRL-002：提交人不得自审
    CONSTRAINT ck_risk_policy_version_separation CHECK (approved_by_ref IS NULL OR approved_by_ref <> submitted_by_ref),
    CONSTRAINT ck_risk_policy_version_active CHECK (policy_state <> 'ACTIVE' OR (activated_at IS NOT NULL AND approved_by_ref IS NOT NULL)),
    CONSTRAINT ck_risk_policy_version_canary CHECK (canary_percentage IS NULL OR canary_percentage BETWEEN 1 AND 100)
);
COMMENT ON TABLE risk.risk_policy_version IS 'REQ-RISK-002：策略版本化、可解释、可灰度、可回滚、可紧急关闭；回滚生成新版本不改写历史决策证据（AT-RISK-004）';

CREATE UNIQUE INDEX IF NOT EXISTS ux_risk_policy_version_active
    ON risk.risk_policy_version ((policy_state)) WHERE policy_state = 'ACTIVE';

SELECT core.fn_apply_standard_grants('risk');
SELECT core.fn_apply_append_only_grants('risk', 'risk_signal');

SELECT core.fn_migration_apply('120', 'risk：风险信号、风险评估、风险案件、黑名单、风险策略版本');
