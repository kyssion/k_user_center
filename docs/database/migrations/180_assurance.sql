-- =============================================================================
-- 180_assurance.sql
-- ASR 域：敏感操作等级要求、高保证账号恢复、人对人委托
-- 依据：能力地图 §4.20、§5.6；蓝图 §8.3、§6（SP2/SP3）、TERM-RECOVERY-001/002
-- 关键：恢复不得比正常认证更容易；委托不得扩权且被代理人必须可见
-- =============================================================================

SET client_min_messages = warning;

-- -----------------------------------------------------------------------------
-- 1. 敏感操作等级要求（CAP-ASR-003、蓝图 §8.3）
-- 每个敏感操作必须声明最低等级、最大认证年龄、允许认证器与风险上限
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS asr.sensitive_operation_requirement (
    operation_code        text        NOT NULL,
    display_name          text        NOT NULL,
    profile_code          text        NOT NULL,
    min_ial               text        NOT NULL DEFAULT 'IAL1',
    min_aal               text        NOT NULL DEFAULT 'AAL2',
    min_fal               text        NULL,
    max_auth_age_seconds  integer     NOT NULL,
    allowed_amr           text[]      NOT NULL DEFAULT '{}',
    forbidden_amr         text[]      NOT NULL DEFAULT '{}',
    max_risk_level        text        NOT NULL DEFAULT 'MEDIUM',
    requires_step_up      boolean     NOT NULL DEFAULT true,
    requires_approval     boolean     NOT NULL DEFAULT false,
    requires_waiting_period boolean   NOT NULL DEFAULT false,
    requires_phishing_resistant boolean NOT NULL DEFAULT false,
    updated_at            timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT pk_sensitive_operation_requirement PRIMARY KEY (operation_code),
    CONSTRAINT ck_sensitive_operation_profile CHECK (profile_code IN ('SP2', 'SP3', 'SP5')),
    CONSTRAINT ck_sensitive_operation_ial CHECK (min_ial IN ('IAL1', 'IAL2', 'IAL3')),
    CONSTRAINT ck_sensitive_operation_aal CHECK (min_aal IN ('AAL1', 'AAL2', 'AAL3')),
    CONSTRAINT ck_sensitive_operation_fal CHECK (min_fal IS NULL OR min_fal IN ('FAL1', 'FAL2', 'FAL3')),
    CONSTRAINT ck_sensitive_operation_risk CHECK (max_risk_level IN ('LOW', 'MEDIUM', 'HIGH')),
    -- TTL-STEPUP-001：敏感操作最大认证年龄 ≤ 5 分钟
    CONSTRAINT ck_sensitive_operation_auth_age CHECK (max_auth_age_seconds BETWEEN 30 AND 300),
    -- 蓝图 §6：SP2 起最低 AAL2；SP3 必须抗钓鱼（REQ-AUTH-010）
    CONSTRAINT ck_sensitive_operation_sp2_aal CHECK (profile_code <> 'SP2' OR min_aal <> 'AAL1'),
    CONSTRAINT ck_sensitive_operation_sp3_phishing CHECK (profile_code <> 'SP3' OR requires_phishing_resistant),
    -- amr 白名单与黑名单不得交叠
    CONSTRAINT ck_sensitive_operation_amr_disjoint CHECK (NOT (allowed_amr && forbidden_amr))
);
COMMENT ON TABLE asr.sensitive_operation_requirement IS 'CAP-ASR-003：敏感操作的最低等级、最大认证年龄、允许认证器与风险上限；恢复流程不得比正常认证更容易（能力地图 §4.20 约束）';

CREATE OR REPLACE TRIGGER trg_sensitive_operation_requirement_touch
    BEFORE UPDATE ON asr.sensitive_operation_requirement
    FOR EACH ROW EXECUTE FUNCTION core.fn_touch_updated_at();

-- -----------------------------------------------------------------------------
-- 2. 高保证账号恢复（CAP-ASR-005/007/009、TERM-RECOVERY-001/002）
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS asr.recovery_request (
    id                     uuid        NOT NULL DEFAULT core.uuid_generate_v7(),
    public_id              text        NOT NULL,
    user_id                uuid        NOT NULL,
    request_state          text        NOT NULL DEFAULT 'SUBMITTED',
    recovery_kind          text        NOT NULL,
    initiated_via          text        NOT NULL,
    risk_level             text        NULL,
    evidence               jsonb       NOT NULL,
    evidence_score         smallint    NULL,
    requires_manual_review boolean     NOT NULL DEFAULT true,
    reviewer_ref           text        NULL,
    reviewed_at            timestamptz NULL,
    second_reviewer_ref    text        NULL,
    second_reviewed_at     timestamptz NULL,
    approval_case_id       uuid        NULL,
    submitted_at           timestamptz NOT NULL DEFAULT now(),
    waiting_period_ends_at timestamptz NULL,
    decided_at             timestamptz NULL,
    outcome                text        NULL,
    reject_reason_code     text        NULL,
    notified_at            timestamptz NULL,
    observation_until      timestamptz NULL,
    post_recovery_aal      text        NULL,
    created_at             timestamptz NOT NULL DEFAULT now(),
    updated_at             timestamptz NOT NULL DEFAULT now(),
    row_version            bigint      NOT NULL DEFAULT 1,
    CONSTRAINT pk_recovery_request PRIMARY KEY (id),
    CONSTRAINT uq_recovery_request_public_id UNIQUE (public_id),
    CONSTRAINT fk_recovery_request_user FOREIGN KEY (user_id) REFERENCES id.global_user (id),
    CONSTRAINT fk_recovery_request_approval FOREIGN KEY (approval_case_id) REFERENCES ctrl.approval_case (id),
    CONSTRAINT ck_recovery_request_state CHECK (request_state IN (
        'SUBMITTED', 'EVIDENCE_COLLECTED', 'WAITING_PERIOD', 'UNDER_REVIEW', 'APPROVED', 'REJECTED', 'COMPLETED', 'CANCELLED'
    )),
    CONSTRAINT ck_recovery_request_kind CHECK (recovery_kind IN (
        'LOST_ALL_AUTHENTICATORS', 'LOST_STRONG_AUTHENTICATOR', 'ADMIN_MFA_RESET', 'RECOVERY_CHANNEL_CHANGE', 'IDENTIFIER_LOST'
    )),
    CONSTRAINT ck_recovery_request_via CHECK (initiated_via IN ('SELF_SERVICE', 'AGENT', 'ADMIN', 'DEDICATED_ADMIN_CHANNEL')),
    CONSTRAINT ck_recovery_request_outcome CHECK (outcome IS NULL OR outcome IN ('GRANTED', 'DENIED')),
    -- CAP-ASR-005：双人复核，两位复核人必须不同
    CONSTRAINT ck_recovery_request_dual_review CHECK (
        second_reviewer_ref IS NULL OR second_reviewer_ref <> reviewer_ref
    ),
    CONSTRAINT ck_recovery_request_approved CHECK (
        request_state <> 'APPROVED' OR (decided_at IS NOT NULL AND reviewer_ref IS NOT NULL)
    ),
    -- TERM-RECOVERY-001：等待期 24 至 72 小时
    CONSTRAINT ck_recovery_request_waiting CHECK (
        waiting_period_ends_at IS NULL
        OR (waiting_period_ends_at - submitted_at >= interval '24 hours'
            AND waiting_period_ends_at - submitted_at <= interval '72 hours')
    ),
    -- TERM-RECOVERY-002：观察期 ≥ 7 天，期内不得自动回到恢复前最高保证等级
    CONSTRAINT ck_recovery_request_observation CHECK (
        observation_until IS NULL OR observation_until - decided_at >= interval '7 days'
    ),
    -- CAP-ASR-007：恢复后必须重新计算 AAL，禁止自动恢复到高保证状态
    CONSTRAINT ck_recovery_request_post_aal CHECK (
        request_state <> 'COMPLETED' OR (post_recovery_aal IS NOT NULL AND observation_until IS NOT NULL)
    ),
    CONSTRAINT ck_recovery_request_rejected CHECK (
        (request_state = 'REJECTED') = (reject_reason_code IS NOT NULL)
    )
);
COMMENT ON TABLE asr.recovery_request IS 'CAP-ASR-005/007/009：多证据、等待期、双人复核、通知与观察期；REQ-AUTH-006 恢复不得把高保证账号降级为单短信即可接管（AT-AUTH-005）';
COMMENT ON COLUMN asr.recovery_request.post_recovery_aal IS 'CAP-ASR-007：恢复后重新计算的 AAL，禁止直接继承恢复前的最高等级';

CREATE OR REPLACE TRIGGER trg_recovery_request_touch
    BEFORE UPDATE ON asr.recovery_request
    FOR EACH ROW EXECUTE FUNCTION core.fn_touch_updated_at();
CREATE OR REPLACE TRIGGER trg_recovery_request_public_id
    BEFORE INSERT ON asr.recovery_request
    FOR EACH ROW EXECUTE FUNCTION core.fn_register_public_id('RECOVERY_REQUEST');

CREATE UNIQUE INDEX IF NOT EXISTS ux_recovery_request_active
    ON asr.recovery_request (user_id)
    WHERE request_state IN ('SUBMITTED', 'EVIDENCE_COLLECTED', 'WAITING_PERIOD', 'UNDER_REVIEW', 'APPROVED');

CREATE INDEX IF NOT EXISTS ix_recovery_request_waiting ON asr.recovery_request (waiting_period_ends_at)
    WHERE request_state = 'WAITING_PERIOD';
CREATE INDEX IF NOT EXISTS ix_recovery_request_observation ON asr.recovery_request (observation_until)
    WHERE request_state = 'COMPLETED';

-- -----------------------------------------------------------------------------
-- 3. 人对人委托（CAP-ASR-010/011/012、INV-G-018）
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS asr.delegation (
    id                    uuid        NOT NULL DEFAULT core.uuid_generate_v7(),
    public_id             text        NOT NULL,
    principal_user_id     uuid        NOT NULL,
    agent_user_id         uuid        NOT NULL,
    delegation_kind       text        NOT NULL,
    delegation_state      text        NOT NULL DEFAULT 'PENDING',
    scope_kind            text        NOT NULL DEFAULT 'PLATFORM',
    scope_ref_id          uuid        NOT NULL DEFAULT '00000000-0000-0000-0000-000000000000',
    tenant_id             uuid        NOT NULL DEFAULT '00000000-0000-0000-0000-000000000000',
    allowed_scopes        text[]      NOT NULL DEFAULT '{}',
    allowed_operations    text[]      NOT NULL DEFAULT '{}',
    max_chain_depth       smallint    NOT NULL DEFAULT 1,
    is_visible_to_principal boolean   NOT NULL DEFAULT true,
    approval_case_id      uuid        NULL,
    granted_at            timestamptz NULL,
    starts_at             timestamptz NOT NULL DEFAULT now(),
    ends_at               timestamptz NOT NULL,
    revoked_at            timestamptz NULL,
    revoked_by_ref        text        NULL,
    revoke_reason_code    text        NULL,
    created_at            timestamptz NOT NULL DEFAULT now(),
    updated_at            timestamptz NOT NULL DEFAULT now(),
    row_version           bigint      NOT NULL DEFAULT 1,
    CONSTRAINT pk_delegation PRIMARY KEY (id),
    CONSTRAINT uq_delegation_public_id UNIQUE (public_id),
    CONSTRAINT fk_delegation_principal FOREIGN KEY (principal_user_id) REFERENCES id.global_user (id),
    CONSTRAINT fk_delegation_agent FOREIGN KEY (agent_user_id) REFERENCES id.global_user (id),
    CONSTRAINT fk_delegation_approval FOREIGN KEY (approval_case_id) REFERENCES ctrl.approval_case (id),
    CONSTRAINT ck_delegation_kind CHECK (delegation_kind IN ('GUARDIANSHIP', 'CUSTODY', 'COLLABORATION', 'AGENT_SUPPORT')),
    CONSTRAINT ck_delegation_state CHECK (delegation_state IN ('PENDING', 'ACTIVE', 'REVOKED', 'EXPIRED')),
    CONSTRAINT ck_delegation_distinct CHECK (principal_user_id <> agent_user_id),
    -- CAP-ASR-011：被代理人必须可见委托关系，结构上不允许隐藏
    CONSTRAINT ck_delegation_visible CHECK (is_visible_to_principal),
    -- CAP-ASR-012 / INV-G-018：委托必须有明确范围，空范围等于无边界 impersonation
    CONSTRAINT ck_delegation_scope_not_empty CHECK (
        array_length(allowed_scopes, 1) >= 1 OR array_length(allowed_operations, 1) >= 1
    ),
    CONSTRAINT ck_delegation_depth CHECK (max_chain_depth BETWEEN 1 AND 2),
    CONSTRAINT ck_delegation_window CHECK (ends_at > starts_at),
    CONSTRAINT ck_delegation_active CHECK (delegation_state <> 'ACTIVE' OR granted_at IS NOT NULL),
    CONSTRAINT ck_delegation_revoked CHECK ((delegation_state = 'REVOKED') = (revoked_at IS NOT NULL))
);
COMMENT ON TABLE asr.delegation IS 'CAP-ASR-010/011/012 与 INV-G-018：委托不得扩大被代理人权限边界，撤销后不得继续签发含该 Actor 的 Token；被代理人始终可见';

CREATE OR REPLACE TRIGGER trg_delegation_touch
    BEFORE UPDATE ON asr.delegation
    FOR EACH ROW EXECUTE FUNCTION core.fn_touch_updated_at();
CREATE OR REPLACE TRIGGER trg_delegation_public_id
    BEFORE INSERT ON asr.delegation
    FOR EACH ROW EXECUTE FUNCTION core.fn_register_public_id('DELEGATION');

CREATE UNIQUE INDEX IF NOT EXISTS ux_delegation_active
    ON asr.delegation (principal_user_id, agent_user_id, delegation_kind, scope_kind, scope_ref_id)
    WHERE delegation_state IN ('PENDING', 'ACTIVE');

CREATE INDEX IF NOT EXISTS ix_delegation_agent ON asr.delegation (agent_user_id, delegation_state);
CREATE INDEX IF NOT EXISTS ix_delegation_expiry ON asr.delegation (ends_at) WHERE delegation_state = 'ACTIVE';

SELECT core.fn_apply_standard_grants('asr');

SELECT core.fn_migration_apply('180', 'assurance：敏感操作等级要求、高保证账号恢复、人对人委托');
