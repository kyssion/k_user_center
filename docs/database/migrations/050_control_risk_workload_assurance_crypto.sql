-- =============================================================================
-- 050_control_risk_workload_assurance_crypto.sql
-- 审批与发布、风险、保证等级/委托、机器身份、密钥与证书
-- =============================================================================

BEGIN;
SET LOCAL lock_timeout = '10s';
SET LOCAL statement_timeout = '5min';

CREATE TABLE control.approval_case (
    id                    uuid        NOT NULL DEFAULT gen_random_uuid(),
    public_id             text        NOT NULL,
    approval_type         text        NOT NULL,
    approval_state        text        NOT NULL DEFAULT 'DRAFT',
    requested_by_ref      text        NOT NULL,
    requested_by_kind     text        NOT NULL,
    tenant_id             uuid        NOT NULL DEFAULT '00000000-0000-0000-0000-000000000000',
    resource_kind         text        NOT NULL,
    resource_ref          text        NOT NULL,
    immutable_request_hash bytea      NOT NULL,
    before_value_hash     bytea       NULL,
    after_value_hash      bytea       NOT NULL,
    justification         text        NOT NULL,
    required_approvals    smallint    NOT NULL DEFAULT 1,
    policy_version        bigint      NOT NULL,
    resource_version      text        NULL,
    risk_snapshot_hash    bytea       NOT NULL,
    valid_until           timestamptz NOT NULL,
    approved_at           timestamptz NULL,
    executed_at           timestamptz NULL,
    execution_id          uuid        NULL,
    cancelled_at          timestamptz NULL,
    expired_at            timestamptz NULL,
    created_at            timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at            timestamptz NOT NULL DEFAULT clock_timestamp(),
    row_version           bigint      NOT NULL DEFAULT 1,
    CONSTRAINT pk_approval_case PRIMARY KEY (id),
    CONSTRAINT uq_approval_case_public_id UNIQUE (public_id),
    CONSTRAINT uq_approval_case_execution UNIQUE (execution_id),
    CONSTRAINT ck_approval_case_type CHECK (approval_type IN ('CONFIG_RELEASE', 'PRIVILEGED_ACCESS', 'TENANT_TRANSFER', 'ACCOUNT_MERGE', 'SECURITY_EXCEPTION', 'BREAK_GLASS', 'DELEGATION', 'KEY_OPERATION', 'DATA_EXPORT', 'EVENT_REPLAY', 'RECOVERY')),
    CONSTRAINT ck_approval_case_state CHECK (approval_state IN ('DRAFT', 'PENDING_REVIEW', 'APPROVED', 'EXECUTED', 'REJECTED', 'CANCELLED', 'EXPIRED')),
    CONSTRAINT ck_approval_case_requester CHECK (requested_by_kind IN ('USER', 'ADMIN', 'CLIENT', 'MACHINE', 'SYSTEM')),
    CONSTRAINT ck_approval_case_hashes CHECK (octet_length(immutable_request_hash) = 32 AND octet_length(after_value_hash) = 32 AND octet_length(risk_snapshot_hash) = 32),
    CONSTRAINT ck_approval_case_required CHECK (required_approvals BETWEEN 1 AND 5),
    CONSTRAINT ck_approval_case_expiry CHECK (valid_until > created_at),
    CONSTRAINT ck_approval_case_approved CHECK (approval_state NOT IN ('APPROVED', 'EXECUTED') OR approved_at IS NOT NULL),
    CONSTRAINT ck_approval_case_executed CHECK ((approval_state = 'EXECUTED') = (executed_at IS NOT NULL AND execution_id IS NOT NULL)),
    CONSTRAINT ck_approval_case_cancelled CHECK ((approval_state = 'CANCELLED') = (cancelled_at IS NOT NULL)),
    CONSTRAINT ck_approval_case_expired CHECK ((approval_state = 'EXPIRED') = (expired_at IS NOT NULL))
);
COMMENT ON TABLE control.approval_case IS 'INV-G-017 / REQ-ASR-004/005：职责分离、不可变请求摘要、有效期、版本绑定和单次执行的高风险审批单。';

CREATE TABLE control.approval_decision (
    id                    uuid        NOT NULL DEFAULT gen_random_uuid(),
    approval_case_id      uuid        NOT NULL,
    approver_kind         text        NOT NULL,
    approver_ref          text        NOT NULL,
    decision              text        NOT NULL,
    decision_reason       text        NOT NULL,
    assurance_context_hash bytea      NOT NULL,
    risk_snapshot_hash    bytea       NOT NULL,
    decided_at            timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT pk_approval_decision PRIMARY KEY (id),
    CONSTRAINT uq_approval_decision_approver UNIQUE (approval_case_id, approver_kind, approver_ref),
    CONSTRAINT fk_approval_decision_case FOREIGN KEY (approval_case_id) REFERENCES control.approval_case(id) ON DELETE CASCADE,
    CONSTRAINT ck_approval_decision_approver CHECK (approver_kind IN ('USER', 'ADMIN')),
    CONSTRAINT ck_approval_decision_value CHECK (decision IN ('APPROVE', 'REJECT')),
    CONSTRAINT ck_approval_decision_hash CHECK (octet_length(assurance_context_hash) = 32 AND octet_length(risk_snapshot_hash) = 32)
);
COMMENT ON TABLE control.approval_decision IS '审批人的不可抵赖决定、认证保证和风险快照；同一审批人只能决定一次。';

CREATE TABLE control.config_release (
    id                    uuid        NOT NULL DEFAULT gen_random_uuid(),
    public_id             text        NOT NULL,
    config_kind           text        NOT NULL,
    config_code           text        NOT NULL,
    release_version       bigint      NOT NULL,
    release_state         text        NOT NULL DEFAULT 'DRAFT',
    environment           text        NOT NULL,
    content_hash          bytea       NOT NULL,
    content_uri           text        NOT NULL,
    dependency_versions   jsonb       NOT NULL DEFAULT '{}',
    owner_ref             text        NOT NULL,
    approval_case_id      uuid        NULL,
    rollback_of_id        uuid        NULL,
    validation_evidence   jsonb       NULL,
    staged_at             timestamptz NULL,
    activated_at          timestamptz NULL,
    deprecated_at         timestamptz NULL,
    revoked_at            timestamptz NULL,
    created_at            timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT pk_config_release PRIMARY KEY (id),
    CONSTRAINT uq_config_release_public_id UNIQUE (public_id),
    CONSTRAINT uq_config_release_version UNIQUE (config_kind, config_code, environment, release_version),
    CONSTRAINT fk_config_release_approval FOREIGN KEY (approval_case_id) REFERENCES control.approval_case(id),
    CONSTRAINT fk_config_release_rollback FOREIGN KEY (rollback_of_id) REFERENCES control.config_release(id),
    CONSTRAINT ck_config_release_kind CHECK (config_kind IN ('CLIENT', 'CALLBACK', 'IDENTITY_PROVIDER', 'AUTHZ_POLICY', 'RISK_POLICY', 'RETENTION_RULE', 'TRUST_BUNDLE', 'KEY_POLICY', 'MESSAGE_TEMPLATE', 'EVENT_SCHEMA')),
    CONSTRAINT ck_config_release_state CHECK (release_state IN ('DRAFT', 'VALIDATED', 'APPROVED', 'STAGED', 'ACTIVE', 'DEPRECATED', 'REVOKED')),
    CONSTRAINT ck_config_release_hash CHECK (octet_length(content_hash) = 32),
    CONSTRAINT ck_config_release_active CHECK (release_state <> 'ACTIVE' OR (approval_case_id IS NOT NULL AND activated_at IS NOT NULL AND validation_evidence IS NOT NULL))
);
COMMENT ON TABLE control.config_release IS 'INV-G-011 / REQ-CTRL-001 至 004：控制面不可变配置、校验、审批、灰度、激活和新 Release 回滚。';

CREATE TABLE control.security_exception (
    id                    uuid        NOT NULL DEFAULT gen_random_uuid(),
    public_id             text        NOT NULL,
    exception_code        text        NOT NULL,
    exception_state       text        NOT NULL DEFAULT 'DRAFT',
    requirement_ids       text[]      NOT NULL,
    scope_definition      jsonb       NOT NULL,
    risk_statement        text        NOT NULL,
    compensating_controls jsonb       NOT NULL,
    risk_acceptor_ref     text        NOT NULL,
    owner_ref             text        NOT NULL,
    approval_case_id      uuid        NOT NULL,
    starts_at             timestamptz NOT NULL,
    expires_at            timestamptz NOT NULL,
    tightened_at          timestamptz NULL,
    created_at            timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at            timestamptz NOT NULL DEFAULT clock_timestamp(),
    row_version           bigint      NOT NULL DEFAULT 1,
    CONSTRAINT pk_security_exception PRIMARY KEY (id),
    CONSTRAINT uq_security_exception_public_id UNIQUE (public_id),
    CONSTRAINT uq_security_exception_code UNIQUE (exception_code),
    CONSTRAINT fk_security_exception_approval FOREIGN KEY (approval_case_id) REFERENCES control.approval_case(id),
    CONSTRAINT ck_security_exception_state CHECK (exception_state IN ('DRAFT', 'APPROVED', 'ACTIVE', 'EXPIRED', 'REVOKED', 'TIGHTENED')),
    CONSTRAINT ck_security_exception_requirements CHECK (cardinality(requirement_ids) > 0),
    CONSTRAINT ck_security_exception_window CHECK (expires_at > starts_at AND expires_at <= starts_at + interval '6 months'),
    CONSTRAINT ck_security_exception_tightened CHECK ((exception_state = 'TIGHTENED') = (tightened_at IS NOT NULL))
);
COMMENT ON TABLE control.security_exception IS 'CAP-CTRL-006/007：偏离要求的范围、风险接受、补偿控制、审批和最长六个月到期收紧。';

CREATE TABLE control.break_glass_grant (
    id                    uuid        NOT NULL DEFAULT gen_random_uuid(),
    public_id             text        NOT NULL,
    user_id               uuid        NOT NULL,
    tenant_id             uuid        NOT NULL DEFAULT '00000000-0000-0000-0000-000000000000',
    permission_codes      text[]      NOT NULL,
    grant_state           text        NOT NULL DEFAULT 'PENDING',
    justification         text        NOT NULL,
    approval_case_id      uuid        NOT NULL,
    activated_at          timestamptz NULL,
    expires_at            timestamptz NOT NULL,
    revoked_at            timestamptz NULL,
    post_review_due_at    timestamptz NOT NULL,
    post_reviewed_at      timestamptz NULL,
    created_at            timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT pk_break_glass_grant PRIMARY KEY (id),
    CONSTRAINT uq_break_glass_grant_public_id UNIQUE (public_id),
    CONSTRAINT fk_break_glass_user FOREIGN KEY (user_id) REFERENCES iam.user_account(id),
    CONSTRAINT fk_break_glass_approval FOREIGN KEY (approval_case_id) REFERENCES control.approval_case(id),
    CONSTRAINT ck_break_glass_state CHECK (grant_state IN ('PENDING', 'ACTIVE', 'EXPIRED', 'REVOKED')),
    CONSTRAINT ck_break_glass_permissions CHECK (cardinality(permission_codes) > 0),
    CONSTRAINT ck_break_glass_window CHECK (expires_at > created_at AND expires_at <= created_at + interval '4 hours'),
    CONSTRAINT ck_break_glass_review CHECK (post_review_due_at > expires_at),
    CONSTRAINT ck_break_glass_active CHECK (grant_state <> 'ACTIVE' OR activated_at IS NOT NULL)
);
COMMENT ON TABLE control.break_glass_grant IS 'REQ-CTRL-006：限时、最小权限、审批、使用即告警、自动失效与事后复核的 Break-glass。';

CREATE TABLE control.owner_review (
    id                    uuid        NOT NULL DEFAULT gen_random_uuid(),
    resource_kind         text        NOT NULL,
    resource_ref          text        NOT NULL,
    owner_ref             text        NOT NULL,
    review_state          text        NOT NULL DEFAULT 'DUE',
    due_at                timestamptz NOT NULL,
    completed_at          timestamptz NULL,
    outcome               text        NULL,
    evidence_hash         bytea       NULL,
    created_at            timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT pk_owner_review PRIMARY KEY (id),
    CONSTRAINT uq_owner_review UNIQUE (resource_kind, resource_ref, due_at),
    CONSTRAINT ck_owner_review_state CHECK (review_state IN ('DUE', 'IN_PROGRESS', 'COMPLETED', 'OVERDUE', 'WAIVED')),
    CONSTRAINT ck_owner_review_outcome CHECK (outcome IS NULL OR outcome IN ('RETAIN', 'SUSPEND', 'ROTATE', 'REASSIGN', 'RETIRE')),
    CONSTRAINT ck_owner_review_complete CHECK (review_state <> 'COMPLETED' OR (completed_at IS NOT NULL AND outcome IS NOT NULL AND evidence_hash IS NOT NULL))
);
COMMENT ON TABLE control.owner_review IS 'Client、机器主体、特权授权等 Owner 有效性、用途、到期、基线和轮换的周期复核。';

CREATE TABLE control.client_certification_run (
    id                    uuid        NOT NULL DEFAULT gen_random_uuid(),
    public_id             text        NOT NULL,
    client_id             uuid        NOT NULL,
    operation_id          uuid        NOT NULL,
    certification_state   text        NOT NULL DEFAULT 'PENDING',
    profile_code          text        NOT NULL,
    profile_version       integer     NOT NULL,
    environment           text        NOT NULL,
    client_config_hash    bytea       NOT NULL,
    protocol_test_report  jsonb       NOT NULL DEFAULT '{}',
    security_test_report  jsonb       NOT NULL DEFAULT '{}',
    tenant_isolation_report jsonb     NOT NULL DEFAULT '{}',
    passed_control_codes  text[]      NOT NULL DEFAULT '{}',
    failed_control_codes  text[]      NOT NULL DEFAULT '{}',
    evidence_uri          text        NULL,
    started_at            timestamptz NULL,
    completed_at          timestamptz NULL,
    expires_at            timestamptz NOT NULL,
    created_at            timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT pk_client_certification_run PRIMARY KEY (id),
    CONSTRAINT uq_client_certification_public_id UNIQUE (public_id),
    CONSTRAINT uq_client_certification_operation UNIQUE (operation_id),
    CONSTRAINT fk_client_certification_client FOREIGN KEY (client_id) REFERENCES oauth.client(id),
    CONSTRAINT fk_client_certification_operation FOREIGN KEY (operation_id) REFERENCES core.async_operation(id),
    CONSTRAINT fk_client_certification_profile FOREIGN KEY (profile_code, profile_version) REFERENCES core.security_profile(profile_code, profile_version),
    CONSTRAINT ck_client_certification_state CHECK (certification_state IN ('PENDING', 'RUNNING', 'PASSED', 'FAILED', 'EXPIRED', 'CANCELLED')),
    CONSTRAINT ck_client_certification_hash CHECK (octet_length(client_config_hash) = 32),
    CONSTRAINT ck_client_certification_result CHECK (certification_state NOT IN ('PASSED', 'FAILED') OR completed_at IS NOT NULL),
    CONSTRAINT ck_client_certification_pass CHECK (certification_state <> 'PASSED' OR cardinality(failed_control_codes) = 0),
    CONSTRAINT ck_client_certification_expiry CHECK (expires_at > created_at)
);
COMMENT ON TABLE control.client_certification_run IS 'CAP-PLT-019：Client 上线前按适用安全 Profile 执行协议、安全、隔离和负向测试的认证报告。';

CREATE TABLE risk.risk_policy_release (
    id                    uuid        NOT NULL DEFAULT gen_random_uuid(),
    public_id             text        NOT NULL,
    policy_code           text        NOT NULL,
    policy_version        bigint      NOT NULL,
    policy_state          text        NOT NULL DEFAULT 'DRAFT',
    content_hash          bytea       NOT NULL,
    model_version         text        NULL,
    owner_ref             text        NOT NULL,
    approval_case_id      uuid        NULL,
    rollout_percentage    numeric(5,2) NOT NULL DEFAULT 0,
    emergency_disabled    boolean     NOT NULL DEFAULT false,
    activated_at          timestamptz NULL,
    created_at            timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT pk_risk_policy_release PRIMARY KEY (id),
    CONSTRAINT uq_risk_policy_release_public_id UNIQUE (public_id),
    CONSTRAINT uq_risk_policy_release_version UNIQUE (policy_code, policy_version),
    CONSTRAINT fk_risk_policy_release_approval FOREIGN KEY (approval_case_id) REFERENCES control.approval_case(id),
    CONSTRAINT ck_risk_policy_release_state CHECK (policy_state IN ('DRAFT', 'VALIDATED', 'APPROVED', 'STAGED', 'ACTIVE', 'DEPRECATED', 'REVOKED')),
    CONSTRAINT ck_risk_policy_release_hash CHECK (octet_length(content_hash) = 32),
    CONSTRAINT ck_risk_policy_release_rollout CHECK (rollout_percentage BETWEEN 0 AND 100)
);
COMMENT ON TABLE risk.risk_policy_release IS 'REQ-RISK-002：可解释、灰度、回滚和紧急关闭的不可变风险策略/模型版本。';

CREATE TABLE risk.risk_signal (
    id                    uuid        NOT NULL DEFAULT gen_random_uuid(),
    signal_type           text        NOT NULL,
    source_kind           text        NOT NULL,
    source_ref            text        NOT NULL,
    subject_kind          text        NOT NULL,
    subject_ref           text        NOT NULL,
    actor_kind            text        NULL,
    actor_ref             text        NULL,
    tenant_id             uuid        NOT NULL DEFAULT '00000000-0000-0000-0000-000000000000',
    confidence            numeric(5,4) NOT NULL,
    signal_value          jsonb       NOT NULL,
    signal_hash           bytea       NOT NULL,
    observed_at           timestamptz NOT NULL,
    received_at           timestamptz NOT NULL DEFAULT clock_timestamp(),
    retain_until          timestamptz NOT NULL,
    correlation_id        text        NULL,
    CONSTRAINT pk_risk_signal PRIMARY KEY (id),
    CONSTRAINT ck_risk_signal_actor CHECK ((actor_kind IS NULL) = (actor_ref IS NULL)),
    CONSTRAINT ck_risk_signal_confidence CHECK (confidence BETWEEN 0 AND 1),
    CONSTRAINT ck_risk_signal_hash CHECK (octet_length(signal_hash) = 32),
    CONSTRAINT ck_risk_signal_retention CHECK (retain_until > received_at)
);
COMMENT ON TABLE risk.risk_signal IS 'REQ-RISK-001/007：来源、时间、置信度、主体、最小化值和保留期明确的追加型安全信号。';

CREATE TABLE risk.risk_assessment (
    id                    uuid        NOT NULL DEFAULT gen_random_uuid(),
    public_id             text        NOT NULL,
    assessment_kind       text        NOT NULL,
    subject_kind          text        NOT NULL,
    subject_ref           text        NOT NULL,
    actor_kind            text        NULL,
    actor_ref             text        NULL,
    tenant_id             uuid        NOT NULL DEFAULT '00000000-0000-0000-0000-000000000000',
    input_hash            bytea       NOT NULL,
    risk_level            text        NOT NULL,
    disposition           text        NOT NULL,
    reason_codes          text[]      NOT NULL DEFAULT '{}',
    evidence_freshness    jsonb       NOT NULL,
    policy_id             uuid        NOT NULL,
    policy_version        bigint      NOT NULL,
    supersedes_id         uuid        NULL,
    manual_override       boolean     NOT NULL DEFAULT false,
    override_reason       text        NULL,
    assessed_at           timestamptz NOT NULL DEFAULT clock_timestamp(),
    valid_until           timestamptz NOT NULL,
    CONSTRAINT pk_risk_assessment PRIMARY KEY (id),
    CONSTRAINT uq_risk_assessment_public_id UNIQUE (public_id),
    CONSTRAINT fk_risk_assessment_policy FOREIGN KEY (policy_id) REFERENCES risk.risk_policy_release(id),
    CONSTRAINT fk_risk_assessment_supersedes FOREIGN KEY (supersedes_id) REFERENCES risk.risk_assessment(id),
    CONSTRAINT ck_risk_assessment_actor CHECK ((actor_kind IS NULL) = (actor_ref IS NULL)),
    CONSTRAINT ck_risk_assessment_level CHECK (risk_level IN ('UNKNOWN', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    CONSTRAINT ck_risk_assessment_disposition CHECK (disposition IN ('ALLOW', 'CHALLENGE', 'STEP_UP', 'WAIT', 'REVIEW', 'DENY', 'FREEZE')),
    CONSTRAINT ck_risk_assessment_hash CHECK (octet_length(input_hash) = 32),
    CONSTRAINT ck_risk_assessment_override CHECK ((manual_override AND override_reason IS NOT NULL) OR (NOT manual_override AND override_reason IS NULL)),
    CONSTRAINT ck_risk_assessment_ttl CHECK (valid_until >= assessed_at)
);
COMMENT ON TABLE risk.risk_assessment IS 'REQ-RISK-009：不可变 risk_level 与独立 disposition、策略版本、输入摘要、新鲜度及人工改判证据。';

CREATE TABLE risk.security_case (
    id                    uuid        NOT NULL DEFAULT gen_random_uuid(),
    public_id             text        NOT NULL,
    case_type             text        NOT NULL,
    case_state            text        NOT NULL DEFAULT 'OPEN',
    severity              text        NOT NULL,
    subject_refs          jsonb       NOT NULL,
    related_assessment_ids uuid[]     NOT NULL DEFAULT '{}',
    owner_ref             text        NOT NULL,
    evidence_hold_id      uuid        NULL,
    resolution_code       text        NULL,
    opened_at             timestamptz NOT NULL DEFAULT clock_timestamp(),
    resolved_at           timestamptz NULL,
    closed_at             timestamptz NULL,
    updated_at            timestamptz NOT NULL DEFAULT clock_timestamp(),
    row_version           bigint      NOT NULL DEFAULT 1,
    CONSTRAINT pk_security_case PRIMARY KEY (id),
    CONSTRAINT uq_security_case_public_id UNIQUE (public_id),
    CONSTRAINT fk_security_case_hold FOREIGN KEY (evidence_hold_id) REFERENCES privacy.legal_hold(id),
    CONSTRAINT ck_security_case_state CHECK (case_state IN ('OPEN', 'INVESTIGATING', 'CONTAINED', 'RESOLVED', 'CLOSED')),
    CONSTRAINT ck_security_case_severity CHECK (severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    CONSTRAINT ck_security_case_resolved CHECK (case_state NOT IN ('RESOLVED', 'CLOSED') OR resolved_at IS NOT NULL),
    CONSTRAINT ck_security_case_closed CHECK ((case_state = 'CLOSED') = (closed_at IS NOT NULL))
);
COMMENT ON TABLE risk.security_case IS 'REQ-RISK-008：账号接管、Client 失陷、异常管理员等安全案件的调查、证据保全、处置与复盘。';

CREATE TABLE risk.denylist_entry (
    id                    uuid        NOT NULL DEFAULT gen_random_uuid(),
    entry_kind            text        NOT NULL,
    value_hash            bytea       NOT NULL,
    scope_kind            text        NOT NULL,
    scope_ref             text        NULL,
    reason_code           text        NOT NULL,
    source_case_id        uuid        NULL,
    starts_at             timestamptz NOT NULL DEFAULT clock_timestamp(),
    expires_at            timestamptz NULL,
    created_at            timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT pk_denylist_entry PRIMARY KEY (id),
    CONSTRAINT uq_denylist_entry UNIQUE NULLS NOT DISTINCT (entry_kind, value_hash, scope_kind, scope_ref),
    CONSTRAINT fk_denylist_entry_case FOREIGN KEY (source_case_id) REFERENCES risk.security_case(id),
    CONSTRAINT ck_denylist_entry_kind CHECK (entry_kind IN ('IP', 'DEVICE', 'IDENTIFIER', 'JTI', 'CLIENT', 'KEY', 'DOMAIN')),
    CONSTRAINT ck_denylist_entry_scope CHECK (scope_kind IN ('GLOBAL', 'BUSINESS_LINE', 'TENANT', 'CLIENT')),
    CONSTRAINT ck_denylist_entry_hash CHECK (octet_length(value_hash) = 32),
    CONSTRAINT ck_denylist_entry_window CHECK (expires_at IS NULL OR expires_at > starts_at)
);
COMMENT ON TABLE risk.denylist_entry IS '风险处置使用的范围化摘要拒绝名单；不保存原始 IP、标识或 Token。';

CREATE TABLE assurance.assurance_policy (
    id                    uuid        NOT NULL DEFAULT gen_random_uuid(),
    policy_code           text        NOT NULL,
    policy_version        integer     NOT NULL,
    operation_code        text        NOT NULL,
    required_ial          text        NOT NULL,
    required_aal          text        NOT NULL,
    required_fal          text        NOT NULL,
    max_auth_age_seconds  integer     NOT NULL,
    require_phishing_resistant boolean NOT NULL DEFAULT false,
    require_hardware_protected boolean NOT NULL DEFAULT false,
    prohibited_delegation boolean     NOT NULL DEFAULT false,
    effective_at          timestamptz NOT NULL,
    CONSTRAINT pk_assurance_policy PRIMARY KEY (id),
    CONSTRAINT uq_assurance_policy_version UNIQUE (policy_code, policy_version, operation_code),
    CONSTRAINT ck_assurance_policy_ial CHECK (required_ial IN ('IAL1', 'IAL2', 'IAL3')),
    CONSTRAINT ck_assurance_policy_aal CHECK (required_aal IN ('AAL1', 'AAL2', 'AAL3')),
    CONSTRAINT ck_assurance_policy_fal CHECK (required_fal IN ('FAL1', 'FAL2', 'FAL3')),
    CONSTRAINT ck_assurance_policy_age CHECK (max_auth_age_seconds BETWEEN 0 AND 86400)
);
COMMENT ON TABLE assurance.assurance_policy IS 'CAP-ASR-001/002：敏感操作对 IAL/AAL/FAL、认证年龄、抗钓鱼/硬件与委托限制的版本化要求。';

CREATE TABLE assurance.identity_assurance_assertion (
    id                    uuid        NOT NULL DEFAULT gen_random_uuid(),
    user_id               uuid        NOT NULL,
    assertion_kind        text        NOT NULL,
    ial_level             text        NOT NULL,
    source_provider_code  text        NOT NULL,
    evidence_hash         bytea       NOT NULL,
    evidence_key_ref      text        NULL,
    assertion_state       text        NOT NULL DEFAULT 'ACTIVE',
    verified_at           timestamptz NOT NULL,
    expires_at            timestamptz NULL,
    revoked_at            timestamptz NULL,
    created_at            timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT pk_identity_assurance_assertion PRIMARY KEY (id),
    CONSTRAINT fk_identity_assurance_user FOREIGN KEY (user_id) REFERENCES iam.user_account(id),
    CONSTRAINT ck_identity_assurance_kind CHECK (assertion_kind IN ('DOCUMENT', 'DATABASE', 'IN_PERSON', 'REMOTE_VIDEO', 'GUARDIAN', 'ENTERPRISE_ATTESTATION')),
    CONSTRAINT ck_identity_assurance_ial CHECK (ial_level IN ('IAL1', 'IAL2', 'IAL3')),
    CONSTRAINT ck_identity_assurance_state CHECK (assertion_state IN ('ACTIVE', 'EXPIRED', 'REVOKED', 'SUPERSEDED')),
    CONSTRAINT ck_identity_assurance_hash CHECK (octet_length(evidence_hash) = 32),
    CONSTRAINT ck_identity_assurance_window CHECK (expires_at IS NULL OR expires_at > verified_at)
);
COMMENT ON TABLE assurance.identity_assurance_assertion IS '身份核验来源、IAL、最小化证据摘要、有效期和撤销状态；原始材料由受控证据库保存。';

CREATE TABLE assurance.recovery_request (
    id                    uuid        NOT NULL DEFAULT gen_random_uuid(),
    public_id             text        NOT NULL,
    user_id               uuid        NOT NULL,
    operation_id          uuid        NOT NULL,
    recovery_state        text        NOT NULL DEFAULT 'SUBMITTED',
    target_aal            text        NOT NULL,
    previous_max_aal      text        NULL,
    risk_assessment_id    uuid        NOT NULL,
    approval_case_id      uuid        NULL,
    waiting_until         timestamptz NOT NULL,
    observation_until     timestamptz NULL,
    completed_at          timestamptz NULL,
    rejected_at           timestamptz NULL,
    created_at            timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at            timestamptz NOT NULL DEFAULT clock_timestamp(),
    row_version           bigint      NOT NULL DEFAULT 1,
    CONSTRAINT pk_recovery_request PRIMARY KEY (id),
    CONSTRAINT uq_recovery_request_public_id UNIQUE (public_id),
    CONSTRAINT uq_recovery_request_operation UNIQUE (operation_id),
    CONSTRAINT fk_recovery_request_user FOREIGN KEY (user_id) REFERENCES iam.user_account(id),
    CONSTRAINT fk_recovery_request_operation FOREIGN KEY (operation_id) REFERENCES core.async_operation(id),
    CONSTRAINT fk_recovery_request_risk FOREIGN KEY (risk_assessment_id) REFERENCES risk.risk_assessment(id),
    CONSTRAINT fk_recovery_request_approval FOREIGN KEY (approval_case_id) REFERENCES control.approval_case(id),
    CONSTRAINT ck_recovery_request_state CHECK (recovery_state IN ('SUBMITTED', 'EVIDENCE_COLLECTED', 'WAITING', 'APPROVED', 'COMPLETED', 'REJECTED', 'CANCELLED', 'EXPIRED')),
    CONSTRAINT ck_recovery_request_aal CHECK (target_aal IN ('AAL1', 'AAL2', 'AAL3') AND (previous_max_aal IS NULL OR previous_max_aal IN ('AAL1', 'AAL2', 'AAL3'))),
    CONSTRAINT ck_recovery_request_wait CHECK (waiting_until >= created_at + interval '24 hours' AND waiting_until <= created_at + interval '72 hours'),
    CONSTRAINT ck_recovery_request_complete CHECK (recovery_state <> 'COMPLETED' OR completed_at IS NOT NULL),
    CONSTRAINT ck_recovery_request_observe CHECK (observation_until IS NULL OR (completed_at IS NOT NULL AND observation_until >= completed_at + interval '7 days'))
);
COMMENT ON TABLE assurance.recovery_request IS 'CAP-ASR-003/007：高保证恢复的证据、风险、审批、24–72 小时等待和至少七天观察期。';

CREATE TABLE assurance.delegation (
    id                    uuid        NOT NULL DEFAULT gen_random_uuid(),
    public_id             text        NOT NULL,
    subject_user_id       uuid        NOT NULL,
    actor_user_id         uuid        NOT NULL,
    tenant_id             uuid        NOT NULL,
    delegation_state      text        NOT NULL DEFAULT 'PENDING',
    allowed_actions       text[]      NOT NULL,
    resource_scope        jsonb       NOT NULL,
    prohibited_operations text[]      NOT NULL DEFAULT '{}',
    max_depth             smallint    NOT NULL DEFAULT 1,
    parent_delegation_id  uuid        NULL,
    approval_case_id      uuid        NULL,
    risk_assessment_id    uuid        NOT NULL,
    subject_assurance_hash bytea      NOT NULL,
    actor_assurance_hash  bytea       NOT NULL,
    valid_from            timestamptz NOT NULL,
    valid_until           timestamptz NOT NULL,
    activated_at          timestamptz NULL,
    revoked_at            timestamptz NULL,
    expired_at            timestamptz NULL,
    created_at            timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at            timestamptz NOT NULL DEFAULT clock_timestamp(),
    row_version           bigint      NOT NULL DEFAULT 1,
    CONSTRAINT pk_delegation PRIMARY KEY (id),
    CONSTRAINT uq_delegation_public_id UNIQUE (public_id),
    CONSTRAINT fk_delegation_subject FOREIGN KEY (subject_user_id) REFERENCES iam.user_account(id),
    CONSTRAINT fk_delegation_actor FOREIGN KEY (actor_user_id) REFERENCES iam.user_account(id),
    CONSTRAINT fk_delegation_tenant FOREIGN KEY (tenant_id) REFERENCES org.tenant(id),
    CONSTRAINT fk_delegation_parent FOREIGN KEY (parent_delegation_id) REFERENCES assurance.delegation(id),
    CONSTRAINT fk_delegation_approval FOREIGN KEY (approval_case_id) REFERENCES control.approval_case(id),
    CONSTRAINT fk_delegation_risk FOREIGN KEY (risk_assessment_id) REFERENCES risk.risk_assessment(id),
    CONSTRAINT ck_delegation_parties CHECK (subject_user_id <> actor_user_id),
    CONSTRAINT ck_delegation_state CHECK (delegation_state IN ('PENDING', 'ACTIVE', 'REJECTED', 'REVOKED', 'EXPIRED')),
    CONSTRAINT ck_delegation_actions CHECK (cardinality(allowed_actions) > 0),
    CONSTRAINT ck_delegation_depth CHECK (max_depth BETWEEN 1 AND 3),
    CONSTRAINT ck_delegation_hash CHECK (octet_length(subject_assurance_hash) = 32 AND octet_length(actor_assurance_hash) = 32),
    CONSTRAINT ck_delegation_window CHECK (valid_until > valid_from),
    CONSTRAINT ck_delegation_active CHECK (delegation_state <> 'ACTIVE' OR activated_at IS NOT NULL),
    CONSTRAINT ck_delegation_revoked CHECK ((delegation_state = 'REVOKED') = (revoked_at IS NOT NULL)),
    CONSTRAINT ck_delegation_expired CHECK ((delegation_state = 'EXPIRED') = (expired_at IS NOT NULL))
);
COMMENT ON TABLE assurance.delegation IS 'INV-G-018 / REQ-ASR-001 至 003：Subject、Actor、允许动作、租户/资源范围、链深、保证、风险和撤销的自然人委托。';

CREATE TABLE workload.machine_principal (
    id                    uuid        NOT NULL DEFAULT gen_random_uuid(),
    public_id             text        NOT NULL,
    principal_code        text        NOT NULL,
    principal_state       text        NOT NULL DEFAULT 'PROVISIONING',
    business_line_id      uuid        NOT NULL,
    tenant_id             uuid        NOT NULL DEFAULT '00000000-0000-0000-0000-000000000000',
    environment           text        NOT NULL,
    owner_ref             text        NOT NULL,
    purpose               text        NOT NULL,
    permission_baseline_hash bytea    NOT NULL,
    rotation_policy_code  text        NOT NULL,
    trust_domain          text        NULL,
    token_audiences       text[]      NOT NULL,
    max_token_ttl_seconds integer     NOT NULL DEFAULT 300,
    principal_security_epoch bigint   NOT NULL DEFAULT 1,
    expires_at            timestamptz NOT NULL,
    last_used_at          timestamptz NULL,
    suspended_at          timestamptz NULL,
    compromised_at        timestamptz NULL,
    retired_at            timestamptz NULL,
    created_at            timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at            timestamptz NOT NULL DEFAULT clock_timestamp(),
    row_version           bigint      NOT NULL DEFAULT 1,
    CONSTRAINT pk_machine_principal PRIMARY KEY (id),
    CONSTRAINT uq_machine_principal_public_id UNIQUE (public_id),
    CONSTRAINT uq_machine_principal_code UNIQUE (business_line_id, environment, principal_code),
    CONSTRAINT fk_machine_principal_business_line FOREIGN KEY (business_line_id) REFERENCES org.business_line(id),
    CONSTRAINT ck_machine_principal_state CHECK (principal_state IN ('PROVISIONING', 'ACTIVE', 'SUSPENDED', 'COMPROMISED', 'RETIRED')),
    CONSTRAINT ck_machine_principal_environment CHECK (environment IN ('DEV', 'TEST', 'STAGING', 'PRODUCTION')),
    CONSTRAINT ck_machine_principal_hash CHECK (octet_length(permission_baseline_hash) = 32),
    CONSTRAINT ck_machine_principal_audience CHECK (cardinality(token_audiences) > 0),
    CONSTRAINT ck_machine_principal_ttl CHECK (max_token_ttl_seconds BETWEEN 30 AND 300),
    CONSTRAINT ck_machine_principal_epoch CHECK (principal_security_epoch >= 1),
    CONSTRAINT ck_machine_principal_expiry CHECK (expires_at > created_at),
    CONSTRAINT ck_machine_principal_active CHECK (principal_state <> 'ACTIVE' OR (owner_ref <> '' AND purpose <> '' AND rotation_policy_code <> ''))
);
COMMENT ON TABLE workload.machine_principal IS 'REQ-MACHINE-001/006/017/018：Owner、用途、环境、最小权限基线、到期、轮换和 security epoch 完整的机器主体。';

CREATE TABLE workload.machine_credential (
    id                    uuid        NOT NULL DEFAULT gen_random_uuid(),
    machine_principal_id  uuid        NOT NULL,
    credential_kind       text        NOT NULL,
    credential_state      text        NOT NULL DEFAULT 'PENDING',
    key_id                text        NULL,
    certificate_thumbprint bytea      NULL,
    secret_hash           bytea       NULL,
    public_material       jsonb       NULL,
    key_asset_id          uuid        NULL,
    issued_at             timestamptz NOT NULL DEFAULT clock_timestamp(),
    activates_at          timestamptz NOT NULL,
    expires_at            timestamptz NOT NULL,
    rotate_before         timestamptz NOT NULL,
    revoked_at            timestamptz NULL,
    created_at            timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at            timestamptz NOT NULL DEFAULT clock_timestamp(),
    row_version           bigint      NOT NULL DEFAULT 1,
    CONSTRAINT pk_machine_credential PRIMARY KEY (id),
    CONSTRAINT fk_machine_credential_principal FOREIGN KEY (machine_principal_id) REFERENCES workload.machine_principal(id),
    CONSTRAINT ck_machine_credential_kind CHECK (credential_kind IN ('PRIVATE_KEY_JWT', 'MTLS', 'WORKLOAD_FEDERATION', 'SECRET')), 
    CONSTRAINT ck_machine_credential_state CHECK (credential_state IN ('PENDING', 'ACTIVE', 'ROTATING', 'EXPIRED', 'REVOKED', 'COMPROMISED')),
    CONSTRAINT ck_machine_credential_material CHECK (num_nonnulls(certificate_thumbprint, secret_hash, public_material, key_asset_id) >= 1),
    CONSTRAINT ck_machine_credential_window CHECK (expires_at > activates_at AND rotate_before > activates_at AND rotate_before < expires_at)
);
COMMENT ON TABLE workload.machine_credential IS '机器主体的引用式密钥、mTLS、工作负载联合或兼容 Secret 凭证；不保存私钥/Secret 明文。';

CREATE TABLE workload.trust_bundle (
    id                    uuid        NOT NULL DEFAULT gen_random_uuid(),
    public_id             text        NOT NULL,
    trust_domain          text        NOT NULL,
    bundle_version        bigint      NOT NULL,
    bundle_state          text        NOT NULL DEFAULT 'DRAFT',
    issuer                text        NOT NULL,
    allowed_audiences     text[]      NOT NULL,
    environment           text        NOT NULL,
    selector_schema       jsonb       NOT NULL,
    public_material       jsonb       NOT NULL,
    max_attestation_age_seconds integer NOT NULL,
    approval_case_id      uuid        NOT NULL,
    active_from           timestamptz NULL,
    active_until          timestamptz NULL,
    created_at            timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT pk_trust_bundle PRIMARY KEY (id),
    CONSTRAINT uq_trust_bundle_public_id UNIQUE (public_id),
    CONSTRAINT uq_trust_bundle_version UNIQUE (trust_domain, environment, bundle_version),
    CONSTRAINT fk_trust_bundle_approval FOREIGN KEY (approval_case_id) REFERENCES control.approval_case(id),
    CONSTRAINT ck_trust_bundle_state CHECK (bundle_state IN ('DRAFT', 'VALIDATED', 'APPROVED', 'ACTIVE', 'VERIFY_ONLY', 'REVOKED', 'RETIRED')),
    CONSTRAINT ck_trust_bundle_audience CHECK (cardinality(allowed_audiences) > 0),
    CONSTRAINT ck_trust_bundle_age CHECK (max_attestation_age_seconds BETWEEN 10 AND 600)
);
COMMENT ON TABLE workload.trust_bundle IS 'REQ-MACHINE-012/014：工作负载 trust domain、issuer、audience、环境、选择器和轮换公钥包。';

CREATE TABLE workload.workload_attestation (
    id                    uuid        NOT NULL DEFAULT gen_random_uuid(),
    public_id             text        NOT NULL,
    machine_principal_id  uuid        NOT NULL,
    trust_bundle_id       uuid        NOT NULL,
    attestation_state     text        NOT NULL DEFAULT 'ATTESTATION_RECEIVED',
    issuer                text        NOT NULL,
    audience              text        NOT NULL,
    nonce_hash            bytea       NOT NULL,
    jti_hash              bytea       NOT NULL,
    selector_hash         bytea       NOT NULL,
    evidence_hash         bytea       NOT NULL,
    environment           text        NOT NULL,
    received_at           timestamptz NOT NULL DEFAULT clock_timestamp(),
    verified_at           timestamptz NULL,
    credential_issued_at  timestamptz NULL,
    expires_at            timestamptz NOT NULL,
    revoked_at            timestamptz NULL,
    rejection_reason_code text        NULL,
    CONSTRAINT pk_workload_attestation PRIMARY KEY (id),
    CONSTRAINT uq_workload_attestation_public_id UNIQUE (public_id),
    CONSTRAINT uq_workload_attestation_jti UNIQUE (trust_bundle_id, jti_hash),
    CONSTRAINT fk_workload_attestation_principal FOREIGN KEY (machine_principal_id) REFERENCES workload.machine_principal(id),
    CONSTRAINT fk_workload_attestation_bundle FOREIGN KEY (trust_bundle_id) REFERENCES workload.trust_bundle(id),
    CONSTRAINT ck_workload_attestation_state CHECK (attestation_state IN ('ATTESTATION_RECEIVED', 'VERIFIED', 'CREDENTIAL_ISSUED', 'EXPIRED', 'REVOKED', 'REJECTED')),
    CONSTRAINT ck_workload_attestation_hash CHECK (octet_length(nonce_hash) = 32 AND octet_length(jti_hash) = 32 AND octet_length(selector_hash) = 32 AND octet_length(evidence_hash) = 32),
    CONSTRAINT ck_workload_attestation_expiry CHECK (expires_at > received_at),
    CONSTRAINT ck_workload_attestation_rejected CHECK (attestation_state <> 'REJECTED' OR rejection_reason_code IS NOT NULL)
);
COMMENT ON TABLE workload.workload_attestation IS 'REQ-MACHINE-013：签名、issuer、audience、时间、nonce/jti、环境和选择器验证的一次性短期工作负载证明。';

CREATE TABLE workload.token_exchange (
    id                    uuid        NOT NULL DEFAULT gen_random_uuid(),
    public_id             text        NOT NULL,
    subject_kind          text        NOT NULL,
    subject_ref           text        NOT NULL,
    actor_kind            text        NOT NULL,
    actor_ref             text        NOT NULL,
    delegation_id         uuid        NULL,
    source_token_hash     bytea       NOT NULL,
    requested_audiences   text[]      NOT NULL,
    requested_scopes      text[]      NOT NULL DEFAULT '{}',
    granted_audiences     text[]      NOT NULL,
    granted_scopes        text[]      NOT NULL DEFAULT '{}',
    tenant_id             uuid        NOT NULL DEFAULT '00000000-0000-0000-0000-000000000000',
    exchange_state        text        NOT NULL DEFAULT 'PENDING',
    policy_version        bigint      NOT NULL,
    issued_token_jti      uuid        NULL,
    created_at            timestamptz NOT NULL DEFAULT clock_timestamp(),
    completed_at          timestamptz NULL,
    CONSTRAINT pk_token_exchange PRIMARY KEY (id),
    CONSTRAINT uq_token_exchange_public_id UNIQUE (public_id),
    CONSTRAINT fk_token_exchange_delegation FOREIGN KEY (delegation_id) REFERENCES assurance.delegation(id),
    CONSTRAINT ck_token_exchange_subject CHECK (subject_kind IN ('USER', 'MACHINE')),
    CONSTRAINT ck_token_exchange_actor CHECK (actor_kind IN ('CLIENT', 'MACHINE', 'USER')),
    CONSTRAINT ck_token_exchange_hash CHECK (octet_length(source_token_hash) = 32),
    CONSTRAINT ck_token_exchange_scope CHECK (granted_scopes <@ requested_scopes AND granted_audiences <@ requested_audiences),
    CONSTRAINT ck_token_exchange_state CHECK (exchange_state IN ('PENDING', 'ISSUED', 'DENIED', 'EXPIRED')),
    CONSTRAINT ck_token_exchange_complete CHECK ((exchange_state = 'ISSUED') = (completed_at IS NOT NULL AND issued_token_jti IS NOT NULL))
);
COMMENT ON TABLE workload.token_exchange IS 'REQ-MACHINE-007/008：保留 Subject、Actor、委托链、目标 audience/scope 且不得扩权的 Token Exchange 证据。';

CREATE TABLE crypto.key_asset (
    id                    uuid        NOT NULL DEFAULT gen_random_uuid(),
    public_id             text        NOT NULL,
    key_id                text        NOT NULL,
    key_kind              text        NOT NULL,
    key_use               text        NOT NULL,
    algorithm             text        NOT NULL,
    environment           text        NOT NULL,
    owner_ref             text        NOT NULL,
    kms_provider          text        NOT NULL,
    kms_key_ref           text        NOT NULL,
    public_material       jsonb       NULL,
    key_state             text        NOT NULL DEFAULT 'GENERATED',
    key_version           bigint      NOT NULL DEFAULT 1,
    not_before            timestamptz NOT NULL,
    not_after             timestamptz NOT NULL,
    published_at          timestamptz NULL,
    signing_started_at    timestamptz NULL,
    verify_only_at        timestamptz NULL,
    compromised_at        timestamptz NULL,
    revoked_at            timestamptz NULL,
    retired_at            timestamptz NULL,
    destroyed_at          timestamptz NULL,
    approval_case_id      uuid        NULL,
    created_at            timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at            timestamptz NOT NULL DEFAULT clock_timestamp(),
    row_version           bigint      NOT NULL DEFAULT 1,
    CONSTRAINT pk_key_asset PRIMARY KEY (id),
    CONSTRAINT uq_key_asset_public_id UNIQUE (public_id),
    CONSTRAINT uq_key_asset_kid UNIQUE (environment, key_use, key_id, key_version),
    CONSTRAINT fk_key_asset_approval FOREIGN KEY (approval_case_id) REFERENCES control.approval_case(id),
    CONSTRAINT ck_key_asset_kind CHECK (key_kind IN ('ASYMMETRIC', 'SYMMETRIC', 'HMAC', 'DATA_ENCRYPTION', 'BLIND_INDEX')),
    CONSTRAINT ck_key_asset_use CHECK (key_use IN ('TOKEN_SIGNING', 'TOKEN_ENCRYPTION', 'DATA_ENCRYPTION', 'BLIND_INDEX', 'WEBHOOK_SIGNING', 'AUDIT_SEAL', 'MTLS_CA')),
    CONSTRAINT ck_key_asset_state CHECK (key_state IN ('GENERATED', 'PUBLISHED', 'SIGNING_AND_VERIFYING', 'VERIFY_ONLY', 'COMPROMISED', 'REVOKED', 'RETIRED', 'DESTROYED')),
    CONSTRAINT ck_key_asset_algorithm CHECK (algorithm <> 'none' AND algorithm <> ''),
    CONSTRAINT ck_key_asset_window CHECK (not_after > not_before),
    CONSTRAINT ck_key_asset_reference CHECK (kms_key_ref <> ''),
    CONSTRAINT ck_key_asset_destroyed CHECK ((key_state = 'DESTROYED') = (destroyed_at IS NOT NULL))
);
COMMENT ON TABLE crypto.key_asset IS 'REQ-KEY-001 至 007：KMS/HSM 引用、用途隔离、算法、kid、轮换、失陷、撤销与销毁证据；不保存私钥明文。';

CREATE TABLE crypto.certificate_asset (
    id                    uuid        NOT NULL DEFAULT gen_random_uuid(),
    public_id             text        NOT NULL,
    certificate_kind      text        NOT NULL,
    serial_number         text        NOT NULL,
    thumbprint_sha256     bytea       NOT NULL,
    subject_dn            text        NOT NULL,
    issuer_dn             text        NOT NULL,
    san_values            text[]      NOT NULL DEFAULT '{}',
    public_certificate_pem text       NOT NULL,
    private_key_asset_id  uuid        NULL,
    certificate_state     text        NOT NULL DEFAULT 'ISSUED',
    owner_ref             text        NOT NULL,
    environment           text        NOT NULL,
    issued_at             timestamptz NOT NULL,
    not_before            timestamptz NOT NULL,
    not_after             timestamptz NOT NULL,
    grace_until           timestamptz NULL,
    revoked_at            timestamptz NULL,
    revoke_reason_code    text        NULL,
    created_at            timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT pk_certificate_asset PRIMARY KEY (id),
    CONSTRAINT uq_certificate_asset_public_id UNIQUE (public_id),
    CONSTRAINT uq_certificate_asset_serial UNIQUE (issuer_dn, serial_number),
    CONSTRAINT uq_certificate_asset_thumbprint UNIQUE (thumbprint_sha256),
    CONSTRAINT fk_certificate_asset_key FOREIGN KEY (private_key_asset_id) REFERENCES crypto.key_asset(id),
    CONSTRAINT ck_certificate_asset_kind CHECK (certificate_kind IN ('TLS_SERVER', 'MTLS_CLIENT', 'SAML_SIGNING', 'WEBHOOK_SIGNING', 'CA')),
    CONSTRAINT ck_certificate_asset_state CHECK (certificate_state IN ('ISSUED', 'ACTIVE', 'GRACE', 'EXPIRED', 'REVOKED')),
    CONSTRAINT ck_certificate_asset_hash CHECK (octet_length(thumbprint_sha256) = 32),
    CONSTRAINT ck_certificate_asset_window CHECK (not_after > not_before),
    CONSTRAINT ck_certificate_asset_revoked CHECK ((certificate_state = 'REVOKED') = (revoked_at IS NOT NULL))
);
COMMENT ON TABLE crypto.certificate_asset IS '证书独立生命周期、序列号、SHA-256 指纹、公钥证书、私钥引用、有效期和吊销原因。';

CREATE TABLE crypto.jwks_release (
    id                    uuid        NOT NULL DEFAULT gen_random_uuid(),
    public_id             text        NOT NULL,
    issuer                text        NOT NULL,
    environment           text        NOT NULL,
    jwks_version          bigint      NOT NULL,
    release_state         text        NOT NULL DEFAULT 'DRAFT',
    key_asset_ids         uuid[]      NOT NULL,
    document_hash         bytea       NOT NULL,
    cache_max_age_seconds integer     NOT NULL,
    clock_skew_seconds    integer     NOT NULL,
    published_at          timestamptz NULL,
    expires_at            timestamptz NULL,
    created_at            timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT pk_jwks_release PRIMARY KEY (id),
    CONSTRAINT uq_jwks_release_public_id UNIQUE (public_id),
    CONSTRAINT uq_jwks_release_version UNIQUE (issuer, environment, jwks_version),
    CONSTRAINT ck_jwks_release_state CHECK (release_state IN ('DRAFT', 'PUBLISHED', 'ACTIVE', 'SUPERSEDED', 'REVOKED')),
    CONSTRAINT ck_jwks_release_keys CHECK (cardinality(key_asset_ids) > 0),
    CONSTRAINT ck_jwks_release_hash CHECK (octet_length(document_hash) = 32),
    CONSTRAINT ck_jwks_release_cache CHECK (cache_max_age_seconds BETWEEN 30 AND 86400 AND clock_skew_seconds BETWEEN 0 AND 300)
);
COMMENT ON TABLE crypto.jwks_release IS 'REQ-KEY-002/003：先发布后签名、双钥重叠、缓存与时钟偏差窗口明确的 JWKS 版本。';

ALTER TABLE core.requirement_trace ADD CONSTRAINT fk_requirement_trace_exception FOREIGN KEY (exception_id) REFERENCES control.security_exception(id);
ALTER TABLE iam.account_merge ADD CONSTRAINT fk_account_merge_approval FOREIGN KEY (approval_case_id) REFERENCES control.approval_case(id);
ALTER TABLE oauth.client ADD CONSTRAINT fk_client_approval FOREIGN KEY (approval_case_id) REFERENCES control.approval_case(id);
ALTER TABLE authz.role_assignment ADD CONSTRAINT fk_role_assignment_approval FOREIGN KEY (approval_case_id) REFERENCES control.approval_case(id);
ALTER TABLE authz.policy_release ADD CONSTRAINT fk_policy_release_approval FOREIGN KEY (approval_case_id) REFERENCES control.approval_case(id);
ALTER TABLE privacy.retention_rule ADD CONSTRAINT fk_retention_rule_approval FOREIGN KEY (approval_case_id) REFERENCES control.approval_case(id);
ALTER TABLE federation.identity_provider ADD CONSTRAINT fk_identity_provider_approval FOREIGN KEY (approval_case_id) REFERENCES control.approval_case(id);
ALTER TABLE privacy.cross_border_authorization ADD CONSTRAINT fk_cross_border_approval FOREIGN KEY (approval_case_id) REFERENCES control.approval_case(id);
ALTER TABLE privacy.privacy_impact_assessment ADD CONSTRAINT fk_pia_approval FOREIGN KEY (approval_case_id) REFERENCES control.approval_case(id);
ALTER TABLE privacy.minor_protection ADD CONSTRAINT fk_minor_protection_delegation FOREIGN KEY (guardian_delegation_id) REFERENCES assurance.delegation(id);
ALTER TABLE workload.machine_credential ADD CONSTRAINT fk_machine_credential_key FOREIGN KEY (key_asset_id) REFERENCES crypto.key_asset(id);

CREATE UNIQUE INDEX ux_config_release_active ON control.config_release(config_kind, config_code, environment) WHERE release_state = 'ACTIVE';
CREATE INDEX ix_approval_case_queue ON control.approval_case(approval_state, valid_until) WHERE approval_state IN ('PENDING_REVIEW', 'APPROVED');
CREATE INDEX ix_security_exception_expiry ON control.security_exception(expires_at) WHERE exception_state = 'ACTIVE';
CREATE INDEX ix_risk_signal_subject ON risk.risk_signal(subject_kind, subject_ref, observed_at DESC);
CREATE INDEX ix_risk_assessment_subject ON risk.risk_assessment(subject_kind, subject_ref, assessed_at DESC);
CREATE UNIQUE INDEX ux_risk_policy_active ON risk.risk_policy_release(policy_code) WHERE policy_state = 'ACTIVE';
CREATE INDEX ix_delegation_subject ON assurance.delegation(subject_user_id, tenant_id, delegation_state);
CREATE INDEX ix_delegation_actor ON assurance.delegation(actor_user_id, tenant_id, delegation_state);
CREATE INDEX ix_machine_owner_review ON workload.machine_principal(owner_ref, expires_at) WHERE principal_state = 'ACTIVE';
CREATE INDEX ix_machine_credential_rotation ON workload.machine_credential(rotate_before) WHERE credential_state IN ('ACTIVE', 'ROTATING');
CREATE INDEX ix_key_asset_rotation ON crypto.key_asset(not_after) WHERE key_state IN ('PUBLISHED', 'SIGNING_AND_VERIFYING', 'VERIFY_ONLY');
CREATE INDEX ix_client_certification_expiry ON control.client_certification_run(client_id, expires_at DESC) WHERE certification_state = 'PASSED';

CREATE OR REPLACE FUNCTION control.fn_approval_decision_guard()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE v_requester text; v_state text;
BEGIN
    SELECT requested_by_ref, approval_state INTO v_requester, v_state FROM control.approval_case WHERE id = NEW.approval_case_id FOR UPDATE;
    IF NEW.approver_ref = v_requester THEN RAISE EXCEPTION 'APPROVAL_FORBIDDEN: 发起人不得审批自己的请求' USING ERRCODE = '23514'; END IF;
    IF v_state <> 'PENDING_REVIEW' THEN RAISE EXCEPTION 'INVALID_STATE_TRANSITION: 审批单不在 PENDING_REVIEW' USING ERRCODE = '23514'; END IF;
    RETURN NEW;
END;
$$;
COMMENT ON FUNCTION control.fn_approval_decision_guard() IS 'INV-G-017：阻止发起人自审并只允许对待审核单据作出决定。';

CREATE OR REPLACE FUNCTION control.fn_approval_case_guard()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE v_approvals integer; v_rejections integer;
BEGIN
    IF NEW.immutable_request_hash <> OLD.immutable_request_hash OR NEW.after_value_hash <> OLD.after_value_hash THEN
        RAISE EXCEPTION 'APPROVAL_REQUEST_IMMUTABLE' USING ERRCODE = '23514';
    END IF;
    IF OLD.approval_state IN ('EXECUTED', 'REJECTED', 'CANCELLED', 'EXPIRED') AND NEW.approval_state <> OLD.approval_state THEN
        RAISE EXCEPTION 'INVALID_STATE_TRANSITION: Approval Case 终态不得离开' USING ERRCODE = '23514';
    END IF;
    IF NEW.approval_state = 'APPROVED' AND OLD.approval_state <> 'APPROVED' THEN
        SELECT count(*) FILTER (WHERE decision = 'APPROVE'), count(*) FILTER (WHERE decision = 'REJECT')
          INTO v_approvals, v_rejections FROM control.approval_decision WHERE approval_case_id = NEW.id;
        IF v_rejections > 0 OR v_approvals < NEW.required_approvals THEN
            RAISE EXCEPTION 'APPROVAL_INCOMPLETE' USING ERRCODE = '23514';
        END IF;
        IF NEW.valid_until <= clock_timestamp() THEN RAISE EXCEPTION 'APPROVAL_EXPIRED' USING ERRCODE = '23514'; END IF;
    END IF;
    RETURN NEW;
END;
$$;
COMMENT ON FUNCTION control.fn_approval_case_guard() IS '审批内容不可变、终态不可恢复、满足人数且未过期才可 APPROVED。';

CREATE OR REPLACE FUNCTION workload.fn_machine_state_guard()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF OLD.principal_state = 'RETIRED' AND NEW.principal_state <> 'RETIRED' THEN
        RAISE EXCEPTION 'INVALID_STATE_TRANSITION: RETIRED Machine Principal 不得恢复' USING ERRCODE = '23514';
    END IF;
    IF OLD.principal_state = 'COMPROMISED' AND NEW.principal_state NOT IN ('COMPROMISED', 'RETIRED') THEN
        RAISE EXCEPTION 'INVALID_STATE_TRANSITION: COMPROMISED Machine Principal 只能退役' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;
COMMENT ON FUNCTION workload.fn_machine_state_guard() IS 'REQ-MACHINE-017：受损机器主体不得原地恢复，退役记录不可复活。';

CREATE OR REPLACE FUNCTION assurance.fn_delegation_guard()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.delegation_state = 'ACTIVE' THEN
        IF TG_OP = 'UPDATE' AND OLD.delegation_state = 'ACTIVE' THEN RETURN NEW; END IF;
        IF NEW.valid_from > clock_timestamp() OR NEW.valid_until <= clock_timestamp() THEN RAISE EXCEPTION 'DELEGATION_OUTSIDE_WINDOW' USING ERRCODE = '23514'; END IF;
        IF NEW.approval_case_id IS NOT NULL AND NOT EXISTS (SELECT 1 FROM control.approval_case WHERE id = NEW.approval_case_id AND approval_state = 'EXECUTED') THEN
            RAISE EXCEPTION 'DELEGATION_APPROVAL_NOT_EXECUTED' USING ERRCODE = '23514';
        END IF;
    END IF;
    RETURN NEW;
END;
$$;
COMMENT ON FUNCTION assurance.fn_delegation_guard() IS '委托激活时校验有效期与需要的已执行审批；权限不扩张由 PDP 交集计算。';

CREATE TRIGGER trg_approval_case_public_id BEFORE INSERT ON control.approval_case FOR EACH ROW EXECUTE FUNCTION core.fn_register_public_id('APPROVAL_CASE');
CREATE TRIGGER trg_approval_case_guard BEFORE UPDATE ON control.approval_case FOR EACH ROW EXECUTE FUNCTION control.fn_approval_case_guard();
CREATE TRIGGER trg_approval_case_touch BEFORE UPDATE ON control.approval_case FOR EACH ROW EXECUTE FUNCTION core.fn_touch_updated_at();
CREATE TRIGGER trg_approval_case_version BEFORE UPDATE ON control.approval_case FOR EACH ROW EXECUTE FUNCTION core.fn_increment_row_version();
CREATE TRIGGER trg_approval_decision_guard BEFORE INSERT ON control.approval_decision FOR EACH ROW EXECUTE FUNCTION control.fn_approval_decision_guard();
CREATE TRIGGER trg_approval_decision_append_only BEFORE UPDATE OR DELETE ON control.approval_decision FOR EACH STATEMENT EXECUTE FUNCTION core.fn_append_only();
CREATE TRIGGER trg_config_release_public_id BEFORE INSERT ON control.config_release FOR EACH ROW EXECUTE FUNCTION core.fn_register_public_id('CONFIG_RELEASE');
CREATE TRIGGER trg_security_exception_public_id BEFORE INSERT ON control.security_exception FOR EACH ROW EXECUTE FUNCTION core.fn_register_public_id('SECURITY_EXCEPTION');
CREATE TRIGGER trg_security_exception_touch BEFORE UPDATE ON control.security_exception FOR EACH ROW EXECUTE FUNCTION core.fn_touch_updated_at();
CREATE TRIGGER trg_security_exception_version BEFORE UPDATE ON control.security_exception FOR EACH ROW EXECUTE FUNCTION core.fn_increment_row_version();
CREATE TRIGGER trg_break_glass_public_id BEFORE INSERT ON control.break_glass_grant FOR EACH ROW EXECUTE FUNCTION core.fn_register_public_id('BREAK_GLASS');
CREATE TRIGGER trg_client_certification_public_id BEFORE INSERT ON control.client_certification_run FOR EACH ROW EXECUTE FUNCTION core.fn_register_public_id('CLIENT_CERTIFICATION');
CREATE TRIGGER trg_risk_policy_public_id BEFORE INSERT ON risk.risk_policy_release FOR EACH ROW EXECUTE FUNCTION core.fn_register_public_id('RISK_POLICY');
CREATE TRIGGER trg_risk_signal_append_only BEFORE UPDATE OR DELETE ON risk.risk_signal FOR EACH STATEMENT EXECUTE FUNCTION core.fn_append_only();
CREATE TRIGGER trg_risk_assessment_public_id BEFORE INSERT ON risk.risk_assessment FOR EACH ROW EXECUTE FUNCTION core.fn_register_public_id('RISK_ASSESSMENT');
CREATE TRIGGER trg_risk_assessment_append_only BEFORE UPDATE OR DELETE ON risk.risk_assessment FOR EACH STATEMENT EXECUTE FUNCTION core.fn_append_only();
CREATE TRIGGER trg_security_case_public_id BEFORE INSERT ON risk.security_case FOR EACH ROW EXECUTE FUNCTION core.fn_register_public_id('SECURITY_CASE');
CREATE TRIGGER trg_security_case_touch BEFORE UPDATE ON risk.security_case FOR EACH ROW EXECUTE FUNCTION core.fn_touch_updated_at();
CREATE TRIGGER trg_security_case_version BEFORE UPDATE ON risk.security_case FOR EACH ROW EXECUTE FUNCTION core.fn_increment_row_version();
CREATE TRIGGER trg_assurance_assertion_append_only BEFORE UPDATE OR DELETE ON assurance.identity_assurance_assertion FOR EACH STATEMENT EXECUTE FUNCTION core.fn_append_only();
CREATE TRIGGER trg_recovery_public_id BEFORE INSERT ON assurance.recovery_request FOR EACH ROW EXECUTE FUNCTION core.fn_register_public_id('RECOVERY_REQUEST');
CREATE TRIGGER trg_recovery_touch BEFORE UPDATE ON assurance.recovery_request FOR EACH ROW EXECUTE FUNCTION core.fn_touch_updated_at();
CREATE TRIGGER trg_recovery_version BEFORE UPDATE ON assurance.recovery_request FOR EACH ROW EXECUTE FUNCTION core.fn_increment_row_version();
CREATE TRIGGER trg_delegation_public_id BEFORE INSERT ON assurance.delegation FOR EACH ROW EXECUTE FUNCTION core.fn_register_public_id('DELEGATION');
CREATE TRIGGER trg_delegation_guard BEFORE INSERT OR UPDATE ON assurance.delegation FOR EACH ROW EXECUTE FUNCTION assurance.fn_delegation_guard();
CREATE TRIGGER trg_delegation_touch BEFORE UPDATE ON assurance.delegation FOR EACH ROW EXECUTE FUNCTION core.fn_touch_updated_at();
CREATE TRIGGER trg_delegation_version BEFORE UPDATE ON assurance.delegation FOR EACH ROW EXECUTE FUNCTION core.fn_increment_row_version();
CREATE TRIGGER trg_delegation_terminal BEFORE UPDATE ON assurance.delegation FOR EACH ROW EXECUTE FUNCTION core.fn_terminal_state_guard('delegation_state', 'REJECTED', 'REVOKED', 'EXPIRED');
CREATE TRIGGER trg_machine_public_id BEFORE INSERT ON workload.machine_principal FOR EACH ROW EXECUTE FUNCTION core.fn_register_public_id('MACHINE_PRINCIPAL');
CREATE TRIGGER trg_machine_state BEFORE UPDATE ON workload.machine_principal FOR EACH ROW EXECUTE FUNCTION workload.fn_machine_state_guard();
CREATE TRIGGER trg_machine_touch BEFORE UPDATE ON workload.machine_principal FOR EACH ROW EXECUTE FUNCTION core.fn_touch_updated_at();
CREATE TRIGGER trg_machine_version BEFORE UPDATE ON workload.machine_principal FOR EACH ROW EXECUTE FUNCTION core.fn_increment_row_version();
CREATE TRIGGER trg_machine_epoch BEFORE UPDATE ON workload.machine_principal FOR EACH ROW EXECUTE FUNCTION core.fn_forbid_epoch_decrease('principal_security_epoch');
CREATE TRIGGER trg_machine_credential_touch BEFORE UPDATE ON workload.machine_credential FOR EACH ROW EXECUTE FUNCTION core.fn_touch_updated_at();
CREATE TRIGGER trg_machine_credential_version BEFORE UPDATE ON workload.machine_credential FOR EACH ROW EXECUTE FUNCTION core.fn_increment_row_version();
CREATE TRIGGER trg_trust_bundle_public_id BEFORE INSERT ON workload.trust_bundle FOR EACH ROW EXECUTE FUNCTION core.fn_register_public_id('TRUST_BUNDLE');
CREATE TRIGGER trg_attestation_public_id BEFORE INSERT ON workload.workload_attestation FOR EACH ROW EXECUTE FUNCTION core.fn_register_public_id('WORKLOAD_ATTESTATION');
CREATE TRIGGER trg_attestation_terminal BEFORE UPDATE ON workload.workload_attestation FOR EACH ROW EXECUTE FUNCTION core.fn_terminal_state_guard('attestation_state', 'EXPIRED', 'REVOKED', 'REJECTED');
CREATE TRIGGER trg_token_exchange_public_id BEFORE INSERT ON workload.token_exchange FOR EACH ROW EXECUTE FUNCTION core.fn_register_public_id('TOKEN_EXCHANGE');
CREATE TRIGGER trg_key_asset_public_id BEFORE INSERT ON crypto.key_asset FOR EACH ROW EXECUTE FUNCTION core.fn_register_public_id('KEY_ASSET');
CREATE TRIGGER trg_key_asset_touch BEFORE UPDATE ON crypto.key_asset FOR EACH ROW EXECUTE FUNCTION core.fn_touch_updated_at();
CREATE TRIGGER trg_key_asset_version BEFORE UPDATE ON crypto.key_asset FOR EACH ROW EXECUTE FUNCTION core.fn_increment_row_version();
CREATE TRIGGER trg_key_asset_terminal BEFORE UPDATE ON crypto.key_asset FOR EACH ROW EXECUTE FUNCTION core.fn_terminal_state_guard('key_state', 'REVOKED', 'DESTROYED');
CREATE TRIGGER trg_certificate_public_id BEFORE INSERT ON crypto.certificate_asset FOR EACH ROW EXECUTE FUNCTION core.fn_register_public_id('CERTIFICATE');
CREATE TRIGGER trg_jwks_public_id BEFORE INSERT ON crypto.jwks_release FOR EACH ROW EXECUTE FUNCTION core.fn_register_public_id('JWKS_RELEASE');

SELECT core.fn_register_migration('050', '控制面审批、风险、保证等级、委托、机器身份、密钥与证书', NULLIF(current_setting('kuc.migration_sha256', true), ''));
COMMIT;
