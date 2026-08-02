-- =============================================================================
-- baseline/schemas/privacy/tables.sql
-- privacy Schema 的最终基表、同 Schema 约束、索引及内联 COMMENT
-- PostgreSQL 16+；应用技术栈：.NET 10 + SqlSugar
-- =============================================================================

CREATE TABLE privacy.purpose (
    purpose_code text        NOT NULL,
    purpose_version integer     NOT NULL,
    display_name text        NOT NULL,
    legal_basis text        NOT NULL,
    notice_uri text        NOT NULL,
    notice_hash bytea       NOT NULL,
    owner_ref text        NOT NULL,
    is_high_risk boolean     NOT NULL DEFAULT false,
    effective_at timestamptz NOT NULL,
    retired_at timestamptz NULL,
    CONSTRAINT pk_purpose PRIMARY KEY (purpose_code, purpose_version),
    CONSTRAINT ck_purpose_basis CHECK (legal_basis IN ('CONSENT', 'CONTRACT', 'LEGAL_OBLIGATION', 'PUBLIC_INTEREST', 'LEGITIMATE_INTEREST', 'VITAL_INTEREST')),
    CONSTRAINT ck_purpose_hash CHECK (octet_length(notice_hash) = 32),
    CONSTRAINT ck_purpose_window CHECK (retired_at IS NULL OR retired_at > effective_at)
);

COMMENT ON TABLE privacy.purpose IS 'CAP-PRIV-001/002：处理用途、合法依据、告知版本与责任人的不可变目录。';

CREATE TABLE privacy.data_category (
    category_code text        NOT NULL,
    display_name text        NOT NULL,
    classification_code text        NOT NULL,
    is_sensitive_personal boolean     NOT NULL DEFAULT false,
    requires_separate_consent boolean NOT NULL DEFAULT false,
    description text        NOT NULL,
    CONSTRAINT pk_data_category PRIMARY KEY (category_code)
);

COMMENT ON TABLE privacy.data_category IS 'REQ-PRIV-002/004：个人信息数据类别、敏感属性与单独同意要求。';

CREATE TABLE privacy.purpose_data_mapping (
    purpose_code text        NOT NULL,
    purpose_version integer     NOT NULL,
    category_code text        NOT NULL,
    recipient_code text        NOT NULL,
    scope_codes text[]      NOT NULL DEFAULT '{}',
    claim_codes text[]      NOT NULL DEFAULT '{}',
    downstream_systems text[]      NOT NULL DEFAULT '{}',
    subscription_topics text[]      NOT NULL DEFAULT '{}',
    retention_policy_code text        NOT NULL,
    CONSTRAINT pk_purpose_data_mapping PRIMARY KEY (purpose_code, purpose_version, category_code, recipient_code),
    CONSTRAINT fk_purpose_data_mapping_purpose FOREIGN KEY (purpose_code, purpose_version) REFERENCES privacy.purpose(purpose_code, purpose_version),
    CONSTRAINT fk_purpose_data_mapping_category FOREIGN KEY (category_code) REFERENCES privacy.data_category(category_code)
);

COMMENT ON TABLE privacy.purpose_data_mapping IS 'REQ-PRIV-005：用途、数据类别、接收方到 scope、claim、订阅和下游副本的可审计映射。';

CREATE TABLE privacy.agreement (
    id uuid        NOT NULL DEFAULT gen_random_uuid(),
    agreement_code text        NOT NULL,
    agreement_version integer     NOT NULL,
    agreement_kind text        NOT NULL,
    locale text        NOT NULL,
    content_uri text        NOT NULL,
    content_hash bytea       NOT NULL,
    effective_at timestamptz NOT NULL,
    retired_at timestamptz NULL,
    CONSTRAINT pk_agreement PRIMARY KEY (id),
    CONSTRAINT uq_agreement_version UNIQUE (agreement_code, agreement_version, locale),
    CONSTRAINT ck_agreement_kind CHECK (agreement_kind IN ('TERMS', 'PRIVACY_NOTICE', 'SERVICE_RULE', 'MARKETING_NOTICE', 'BIOMETRIC_NOTICE', 'CROSS_BORDER_NOTICE', 'MINOR_NOTICE')),
    CONSTRAINT ck_agreement_hash CHECK (octet_length(content_hash) = 32),
    CONSTRAINT ck_agreement_window CHECK (retired_at IS NULL OR retired_at > effective_at)
);

COMMENT ON TABLE privacy.agreement IS 'CAP-PRIV-003：协议与告知文本版本；与 Consent、营销订阅、OAuth Grant 分开建模。';

CREATE TABLE privacy.agreement_acceptance (
    id uuid        NOT NULL DEFAULT gen_random_uuid(),
    agreement_id uuid        NOT NULL,
    user_id uuid        NOT NULL,
    client_id uuid        NULL,
    tenant_id uuid        NOT NULL DEFAULT '00000000-0000-0000-0000-000000000000',
    acceptance_action text        NOT NULL,
    evidence_hash bytea       NOT NULL,
    source_ip_hash bytea       NULL,
    user_agent_hash bytea       NULL,
    accepted_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    revoked_at timestamptz NULL,
    CONSTRAINT pk_agreement_acceptance PRIMARY KEY (id),
    CONSTRAINT fk_agreement_acceptance_agreement FOREIGN KEY (agreement_id) REFERENCES privacy.agreement(id),
    CONSTRAINT ck_agreement_acceptance_action CHECK (acceptance_action IN ('CHECKBOX', 'SIGNATURE', 'ADMIN_RECORDED', 'MIGRATED')),
    CONSTRAINT ck_agreement_acceptance_hash CHECK (octet_length(evidence_hash) = 32),
    CONSTRAINT uq_agreement_acceptance UNIQUE NULLS NOT DISTINCT (agreement_id, user_id, client_id, tenant_id)
);

COMMENT ON TABLE privacy.agreement_acceptance IS '用户接受协议的版本、肯定动作与最小化环境证据。';

CREATE TABLE privacy.consent_aggregate (
    id uuid        NOT NULL DEFAULT gen_random_uuid(),
    public_id text        NOT NULL,
    user_id uuid        NOT NULL,
    purpose_code text        NOT NULL,
    data_categories_hash bytea       NOT NULL,
    recipient_code text        NOT NULL,
    tenant_id uuid        NOT NULL DEFAULT '00000000-0000-0000-0000-000000000000',
    aggregate_key_hash bytea       NOT NULL,
    current_epoch bigint      NOT NULL DEFAULT 0,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    row_version bigint      NOT NULL DEFAULT 1,
    CONSTRAINT pk_consent_aggregate PRIMARY KEY (id),
    CONSTRAINT uq_consent_aggregate_public_id UNIQUE (public_id),
    CONSTRAINT uq_consent_aggregate_key UNIQUE (user_id, aggregate_key_hash),
    CONSTRAINT ck_consent_aggregate_hash CHECK (octet_length(data_categories_hash) = 32 AND octet_length(aggregate_key_hash) = 32),
    CONSTRAINT ck_consent_aggregate_epoch CHECK (current_epoch >= 0)
);

COMMENT ON TABLE privacy.consent_aggregate IS 'REQ-PRIV-012：按 subject + purpose + data categories + recipient 隔离的单调 consent epoch 聚合。';

CREATE TABLE privacy.consent (
    id uuid        NOT NULL DEFAULT gen_random_uuid(),
    public_id text        NOT NULL,
    aggregate_id uuid        NOT NULL,
    purpose_code text        NOT NULL,
    purpose_version integer     NOT NULL,
    data_category_codes text[]      NOT NULL,
    recipient_code text        NOT NULL,
    requested_scope_codes text[]      NOT NULL DEFAULT '{}',
    consent_context_hash bytea       NOT NULL,
    consent_state text        NOT NULL DEFAULT 'PENDING',
    consent_epoch bigint      NOT NULL DEFAULT 0,
    affirmative_action boolean     NOT NULL DEFAULT false,
    action_kind text        NULL,
    action_evidence_hash bytea       NULL,
    source_client_id uuid        NULL,
    source_login_transaction_id uuid  NULL,
    granted_at timestamptz NULL,
    denied_at timestamptz NULL,
    withdrawn_at timestamptz NULL,
    expired_at timestamptz NULL,
    superseded_at timestamptz NULL,
    expires_at timestamptz NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    row_version bigint      NOT NULL DEFAULT 1,
    consent_version bigint NOT NULL DEFAULT 1,
    CONSTRAINT pk_consent PRIMARY KEY (id),
    CONSTRAINT uq_consent_public_id UNIQUE (public_id),
    CONSTRAINT fk_consent_aggregate FOREIGN KEY (aggregate_id) REFERENCES privacy.consent_aggregate(id),
    CONSTRAINT fk_consent_purpose FOREIGN KEY (purpose_code, purpose_version) REFERENCES privacy.purpose(purpose_code, purpose_version),
    CONSTRAINT ck_consent_state CHECK (consent_state IN ('PENDING', 'GRANTED', 'DENIED', 'WITHDRAWN', 'EXPIRED', 'SUPERSEDED')),
    CONSTRAINT ck_consent_categories CHECK (cardinality(data_category_codes) > 0),
    CONSTRAINT ck_consent_context_hash CHECK (octet_length(consent_context_hash) = 32),
    CONSTRAINT ck_consent_epoch CHECK (consent_epoch >= 0),
    CONSTRAINT ck_consent_action CHECK (
    (affirmative_action AND action_kind IS NOT NULL AND action_evidence_hash IS NOT NULL)
    OR (NOT affirmative_action AND action_kind IS NULL AND action_evidence_hash IS NULL)
    ),
    CONSTRAINT ck_consent_granted CHECK (consent_state <> 'GRANTED' OR (affirmative_action AND granted_at IS NOT NULL)),
    CONSTRAINT ck_consent_denied CHECK ((consent_state = 'DENIED') = (denied_at IS NOT NULL)),
    CONSTRAINT ck_consent_withdrawn CHECK ((consent_state = 'WITHDRAWN') = (withdrawn_at IS NOT NULL)),
    CONSTRAINT ck_consent_expired CHECK ((consent_state = 'EXPIRED') = (expired_at IS NOT NULL)),
    CONSTRAINT ck_consent_superseded CHECK ((consent_state = 'SUPERSEDED') = (superseded_at IS NOT NULL)),
    CONSTRAINT uq_consent_version UNIQUE (aggregate_id, consent_version),
    CONSTRAINT ck_consent_version CHECK (consent_version >= 1)
);

COMMENT ON TABLE privacy.consent IS 'REQ-PRIV-004/014：明确用途、类别、接收方、版本、肯定动作与终态的 Consent；PENDING/DENIED 不构成处理依据。';

CREATE TABLE privacy.marketing_subscription (
    id uuid        NOT NULL DEFAULT gen_random_uuid(),
    user_id uuid        NOT NULL,
    channel_code text        NOT NULL,
    topic_code text        NOT NULL,
    recipient_code text        NOT NULL,
    subscription_state text        NOT NULL DEFAULT 'PENDING',
    consent_id uuid        NULL,
    consent_epoch bigint      NULL,
    source_kind text        NOT NULL,
    subscribed_at timestamptz NULL,
    unsubscribed_at timestamptz NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    row_version bigint      NOT NULL DEFAULT 1,
    CONSTRAINT pk_marketing_subscription PRIMARY KEY (id),
    CONSTRAINT uq_marketing_subscription UNIQUE (user_id, channel_code, topic_code, recipient_code),
    CONSTRAINT fk_marketing_subscription_consent FOREIGN KEY (consent_id) REFERENCES privacy.consent(id),
    CONSTRAINT ck_marketing_subscription_channel CHECK (channel_code IN ('EMAIL', 'SMS', 'PUSH', 'IN_APP')),
    CONSTRAINT ck_marketing_subscription_state CHECK (subscription_state IN ('PENDING', 'SUBSCRIBED', 'UNSUBSCRIBED', 'SUPPRESSED')),
    CONSTRAINT ck_marketing_subscription_consent CHECK (subscription_state <> 'SUBSCRIBED' OR (consent_id IS NOT NULL AND consent_epoch IS NOT NULL AND subscribed_at IS NOT NULL))
);

COMMENT ON TABLE privacy.marketing_subscription IS 'REQ-PRIV-003/005：营销订阅独立状态，并绑定构成依据的 Consent epoch。';

CREATE TABLE privacy.privacy_request (
    id uuid        NOT NULL DEFAULT gen_random_uuid(),
    public_id text        NOT NULL,
    user_id uuid        NOT NULL,
    request_kind text        NOT NULL,
    request_state text        NOT NULL DEFAULT 'SUBMITTED',
    operation_id uuid        NOT NULL,
    identity_verification_tx_id uuid  NULL,
    requested_scope jsonb       NOT NULL,
    legal_deadline_at timestamptz NOT NULL,
    blocked_reason_code text        NULL,
    rejection_reason_code text        NULL,
    submitted_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    verified_at timestamptz NULL,
    completed_at timestamptz NULL,
    rejected_at timestamptz NULL,
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    row_version bigint      NOT NULL DEFAULT 1,
    started_at timestamptz NULL,
    blocked_at timestamptz NULL,
    partial_at timestamptz NULL,
    CONSTRAINT pk_privacy_request PRIMARY KEY (id),
    CONSTRAINT uq_privacy_request_public_id UNIQUE (public_id),
    CONSTRAINT uq_privacy_request_operation UNIQUE (operation_id),
    CONSTRAINT ck_privacy_request_kind CHECK (request_kind IN ('ACCESS', 'EXPORT', 'CORRECT', 'DELETE', 'RESTRICT', 'OBJECT_AUTOMATED_DECISION', 'WITHDRAW_CONSENT')),
    CONSTRAINT ck_privacy_request_state CHECK (request_state IN ('SUBMITTED', 'IDENTITY_VERIFIED', 'IN_PROGRESS', 'BLOCKED', 'PARTIAL', 'COMPLETED', 'REJECTED')),
    CONSTRAINT ck_privacy_request_blocked CHECK (request_state <> 'BLOCKED' OR blocked_reason_code IS NOT NULL),
    CONSTRAINT ck_privacy_request_completed CHECK ((request_state = 'COMPLETED') = (completed_at IS NOT NULL)),
    CONSTRAINT ck_privacy_request_rejected CHECK ((request_state = 'REJECTED') = (rejected_at IS NOT NULL)),
    CONSTRAINT ck_privacy_request_deadline CHECK (legal_deadline_at > submitted_at),
    CONSTRAINT ck_privacy_request_verified CHECK (request_state IN ('SUBMITTED', 'REJECTED') OR verified_at IS NOT NULL),
    CONSTRAINT ck_privacy_request_started CHECK (request_state NOT IN ('IN_PROGRESS', 'BLOCKED', 'PARTIAL', 'COMPLETED') OR started_at IS NOT NULL),
    CONSTRAINT ck_privacy_request_blocked_time CHECK (request_state <> 'BLOCKED' OR blocked_at IS NOT NULL),
    CONSTRAINT ck_privacy_request_partial_time CHECK (request_state <> 'PARTIAL' OR partial_at IS NOT NULL)
);

COMMENT ON TABLE privacy.privacy_request IS 'CAP-PRIV-008/012：访问、导出、更正、删除、限制处理等个人权利请求及法定期限。';

CREATE TABLE privacy.privacy_request_task (
    id uuid        NOT NULL DEFAULT gen_random_uuid(),
    privacy_request_id uuid        NOT NULL,
    target_system_code text        NOT NULL,
    task_kind text        NOT NULL,
    task_state text        NOT NULL DEFAULT 'PENDING',
    idempotency_key text        NOT NULL,
    checkpoint jsonb       NULL,
    legal_hold_id uuid        NULL,
    attempt_count integer     NOT NULL DEFAULT 0,
    next_attempt_at timestamptz NULL,
    last_error_code text        NULL,
    completion_evidence_hash bytea    NULL,
    completed_at timestamptz NULL,
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT pk_privacy_request_task PRIMARY KEY (id),
    CONSTRAINT uq_privacy_request_task UNIQUE (privacy_request_id, target_system_code, task_kind),
    CONSTRAINT uq_privacy_request_task_key UNIQUE (idempotency_key),
    CONSTRAINT fk_privacy_request_task_request FOREIGN KEY (privacy_request_id) REFERENCES privacy.privacy_request(id) ON DELETE CASCADE,
    CONSTRAINT ck_privacy_request_task_kind CHECK (task_kind IN ('DISCOVER', 'EXPORT', 'CORRECT', 'DELETE', 'ANONYMIZE', 'RESTRICT', 'REVOKE', 'PROVE', 'BACKUP_MARK')),
    CONSTRAINT ck_privacy_request_task_state CHECK (task_state IN ('PENDING', 'RUNNING', 'BLOCKED', 'COMPLETED', 'FAILED', 'NOT_APPLICABLE')),
    CONSTRAINT ck_privacy_request_task_attempt CHECK (attempt_count >= 0),
    CONSTRAINT ck_privacy_request_task_evidence CHECK (completion_evidence_hash IS NULL OR octet_length(completion_evidence_hash) = 32)
);

COMMENT ON TABLE privacy.privacy_request_task IS 'REQ-PRIV-007/008：跨系统隐私 Saga 子任务、检查点、Legal Hold、重试与完成证据。';

CREATE TABLE privacy.legal_hold (
    id uuid        NOT NULL DEFAULT gen_random_uuid(),
    public_id text        NOT NULL,
    subject_kind text        NOT NULL,
    subject_ref text        NOT NULL,
    data_category_codes text[]      NOT NULL,
    legal_basis text        NOT NULL,
    case_reference text        NOT NULL,
    approved_by_ref text        NOT NULL,
    hold_state text        NOT NULL DEFAULT 'ACTIVE',
    starts_at timestamptz NOT NULL,
    expires_at timestamptz NULL,
    released_at timestamptz NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT pk_legal_hold PRIMARY KEY (id),
    CONSTRAINT uq_legal_hold_public_id UNIQUE (public_id),
    CONSTRAINT ck_legal_hold_state CHECK (hold_state IN ('ACTIVE', 'RELEASED', 'EXPIRED')),
    CONSTRAINT ck_legal_hold_categories CHECK (cardinality(data_category_codes) > 0),
    CONSTRAINT ck_legal_hold_window CHECK (expires_at IS NULL OR expires_at > starts_at),
    CONSTRAINT ck_legal_hold_released CHECK ((hold_state = 'RELEASED') = (released_at IS NOT NULL))
);

COMMENT ON TABLE privacy.legal_hold IS 'REQ-PRIV-008：法律保留的依据、范围、期限、审批人和解除证据。';

CREATE TABLE privacy.export_job (
    id uuid        NOT NULL DEFAULT gen_random_uuid(),
    privacy_request_id uuid        NOT NULL,
    export_state text        NOT NULL DEFAULT 'PENDING',
    classification_code text        NOT NULL,
    encryption_key_ref text        NOT NULL,
    object_uri text        NULL,
    object_hash bytea       NULL,
    download_token_hash bytea       NULL,
    download_expires_at timestamptz NULL,
    download_count integer     NOT NULL DEFAULT 0,
    max_download_count integer     NOT NULL DEFAULT 1,
    generated_at timestamptz NULL,
    destroyed_at timestamptz NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT pk_export_job PRIMARY KEY (id),
    CONSTRAINT uq_export_job_request UNIQUE (privacy_request_id),
    CONSTRAINT fk_export_job_request FOREIGN KEY (privacy_request_id) REFERENCES privacy.privacy_request(id),
    CONSTRAINT ck_export_job_state CHECK (export_state IN ('PENDING', 'GENERATING', 'READY', 'DOWNLOADED', 'EXPIRED', 'DESTROYED', 'FAILED')),
    CONSTRAINT ck_export_job_hash CHECK (object_hash IS NULL OR octet_length(object_hash) = 32),
    CONSTRAINT ck_export_job_token CHECK (download_token_hash IS NULL OR octet_length(download_token_hash) = 32),
    CONSTRAINT ck_export_job_count CHECK (download_count >= 0 AND max_download_count BETWEEN 1 AND 5 AND download_count <= max_download_count),
    CONSTRAINT ck_export_job_ready CHECK (export_state <> 'READY' OR (object_uri IS NOT NULL AND object_hash IS NOT NULL AND download_token_hash IS NOT NULL AND download_expires_at IS NOT NULL)),
    CONSTRAINT ck_export_job_ttl CHECK (download_expires_at IS NULL OR generated_at IS NULL OR download_expires_at <= generated_at + interval '24 hours')
);

COMMENT ON TABLE privacy.export_job IS 'REQ-PRIV-006：强认证后的异步加密导出、短期单次下载和到期销毁。';

CREATE TABLE privacy.retention_rule (
    id uuid        NOT NULL DEFAULT gen_random_uuid(),
    rule_code text        NOT NULL,
    rule_version integer     NOT NULL,
    schema_name text        NOT NULL,
    table_name text        NOT NULL,
    category_code text        NOT NULL,
    legal_basis text        NOT NULL,
    retention_interval interval    NOT NULL,
    disposition_kind text        NOT NULL,
    key_destruction_required boolean  NOT NULL DEFAULT false,
    owner_ref text        NOT NULL,
    approval_case_id uuid        NULL,
    effective_at timestamptz NOT NULL,
    retired_at timestamptz NULL,
    CONSTRAINT pk_retention_rule PRIMARY KEY (id),
    CONSTRAINT uq_retention_rule_version UNIQUE (rule_code, rule_version),
    CONSTRAINT fk_retention_rule_category FOREIGN KEY (category_code) REFERENCES privacy.data_category(category_code),
    CONSTRAINT ck_retention_rule_interval CHECK (retention_interval > interval '0'),
    CONSTRAINT ck_retention_rule_disposition CHECK (disposition_kind IN ('DELETE', 'ANONYMIZE', 'ARCHIVE', 'CRYPTO_SHRED', 'REVIEW'))
);

COMMENT ON TABLE privacy.retention_rule IS 'CAP-PRIV-004/005：按数据对象与类别登记的版本化保留、匿名化和密码学销毁规则。';

CREATE TABLE privacy.deletion_proof (
    id uuid        NOT NULL DEFAULT gen_random_uuid(),
    privacy_request_id uuid        NOT NULL,
    proof_version integer     NOT NULL,
    subject_tombstone_ref text        NOT NULL,
    completed_systems jsonb       NOT NULL,
    retained_items jsonb       NOT NULL,
    backup_policy_evidence jsonb      NOT NULL,
    proof_hash bytea       NOT NULL,
    signed_by_key_ref text        NOT NULL,
    issued_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT pk_deletion_proof PRIMARY KEY (id),
    CONSTRAINT uq_deletion_proof UNIQUE (privacy_request_id, proof_version),
    CONSTRAINT fk_deletion_proof_request FOREIGN KEY (privacy_request_id) REFERENCES privacy.privacy_request(id),
    CONSTRAINT ck_deletion_proof_hash CHECK (octet_length(proof_hash) = 32)
);

COMMENT ON TABLE privacy.deletion_proof IS 'REQ-PRIV-013：删除/匿名化完成证明，明确完成系统、依法保留项、期限、责任方和备份策略。';

CREATE TABLE privacy.cross_border_authorization (
    id uuid        NOT NULL DEFAULT gen_random_uuid(),
    public_id text        NOT NULL,
    authorization_code text        NOT NULL,
    authorization_state text        NOT NULL DEFAULT 'DRAFT',
    source_region text        NOT NULL,
    destination_region text        NOT NULL,
    recipient_code text        NOT NULL,
    purpose_code text        NOT NULL,
    data_category_codes text[]      NOT NULL,
    transfer_mechanism text        NOT NULL,
    assessment_reference text        NOT NULL,
    route_policy jsonb       NOT NULL,
    owner_ref text        NOT NULL,
    approval_case_id uuid        NOT NULL,
    valid_from timestamptz NOT NULL,
    valid_until timestamptz NOT NULL,
    revoked_at timestamptz NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    row_version bigint      NOT NULL DEFAULT 1,
    CONSTRAINT pk_cross_border_authorization PRIMARY KEY (id),
    CONSTRAINT uq_cross_border_authorization_public_id UNIQUE (public_id),
    CONSTRAINT uq_cross_border_authorization_code UNIQUE (authorization_code),
    CONSTRAINT ck_cross_border_authorization_regions CHECK (source_region <> destination_region),
    CONSTRAINT ck_cross_border_authorization_state CHECK (authorization_state IN ('DRAFT', 'APPROVED', 'ACTIVE', 'SUSPENDED', 'EXPIRED', 'REVOKED')),
    CONSTRAINT ck_cross_border_authorization_categories CHECK (cardinality(data_category_codes) > 0),
    CONSTRAINT ck_cross_border_authorization_mechanism CHECK (transfer_mechanism IN ('SECURITY_ASSESSMENT', 'STANDARD_CONTRACT', 'CERTIFICATION', 'LEGAL_EXCEPTION')),
    CONSTRAINT ck_cross_border_authorization_window CHECK (valid_until > valid_from),
    CONSTRAINT ck_cross_border_authorization_revoked CHECK ((authorization_state = 'REVOKED') = (revoked_at IS NOT NULL))
);

COMMENT ON TABLE privacy.cross_border_authorization IS 'CAP-PRIV-015：跨境/跨地域数据类别、用途、接收方、合法机制、评估、路由、审批和有效期授权。';

CREATE TABLE privacy.minor_protection (
    id uuid        NOT NULL DEFAULT gen_random_uuid(),
    minor_user_id uuid        NOT NULL,
    protection_state text        NOT NULL DEFAULT 'AGE_UNKNOWN',
    age_band text        NOT NULL DEFAULT 'UNKNOWN',
    age_assurance_method text        NULL,
    age_evidence_hash bytea       NULL,
    guardian_user_id uuid        NULL,
    guardian_delegation_id uuid       NULL,
    guardian_consent_id uuid        NULL,
    restriction_policy_code text      NOT NULL,
    verified_at timestamptz NULL,
    expires_at timestamptz NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    row_version bigint      NOT NULL DEFAULT 1,
    CONSTRAINT pk_minor_protection PRIMARY KEY (id),
    CONSTRAINT uq_minor_protection_user UNIQUE (minor_user_id),
    CONSTRAINT fk_minor_protection_consent FOREIGN KEY (guardian_consent_id) REFERENCES privacy.consent(id),
    CONSTRAINT ck_minor_protection_parties CHECK (guardian_user_id IS NULL OR guardian_user_id <> minor_user_id),
    CONSTRAINT ck_minor_protection_state CHECK (protection_state IN ('AGE_UNKNOWN', 'AGE_VERIFIED_ADULT', 'GUARDIAN_REQUIRED', 'GUARDIAN_PENDING', 'PROTECTED_ACTIVE', 'PROTECTED_EXPIRED')),
    CONSTRAINT ck_minor_protection_band CHECK (age_band IN ('UNKNOWN', 'CHILD', 'ADOLESCENT', 'ADULT')),
    CONSTRAINT ck_minor_protection_evidence CHECK ((age_assurance_method IS NULL) = (age_evidence_hash IS NULL)),
    CONSTRAINT ck_minor_protection_guardian CHECK (protection_state <> 'PROTECTED_ACTIVE' OR (guardian_user_id IS NOT NULL AND guardian_delegation_id IS NOT NULL AND guardian_consent_id IS NOT NULL AND verified_at IS NOT NULL)),
    CONSTRAINT ck_minor_protection_window CHECK (expires_at IS NULL OR verified_at IS NULL OR expires_at > verified_at)
);

COMMENT ON TABLE privacy.minor_protection IS 'CAP-PRIV-016 / CAP-ASR-010：年龄段、最小化年龄证据、监护关系、监护人 Consent 和特殊功能限制策略。';

CREATE TABLE privacy.privacy_impact_assessment (
    id uuid        NOT NULL DEFAULT gen_random_uuid(),
    public_id text        NOT NULL,
    assessment_code text        NOT NULL,
    assessment_version integer     NOT NULL,
    assessment_state text        NOT NULL DEFAULT 'DRAFT',
    change_kind text        NOT NULL,
    scope_definition jsonb       NOT NULL,
    purpose_codes text[]      NOT NULL,
    data_category_codes text[]      NOT NULL,
    recipient_codes text[]      NOT NULL DEFAULT '{}',
    risk_summary jsonb       NOT NULL,
    mitigations jsonb       NOT NULL,
    residual_risk_level text        NOT NULL,
    owner_ref text        NOT NULL,
    privacy_officer_ref text        NOT NULL,
    approval_case_id uuid        NOT NULL,
    approved_at timestamptz NULL,
    expires_at timestamptz NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT pk_privacy_impact_assessment PRIMARY KEY (id),
    CONSTRAINT uq_privacy_impact_assessment_public_id UNIQUE (public_id),
    CONSTRAINT uq_privacy_impact_assessment_version UNIQUE (assessment_code, assessment_version),
    CONSTRAINT ck_privacy_impact_assessment_state CHECK (assessment_state IN ('DRAFT', 'IN_REVIEW', 'APPROVED', 'REJECTED', 'EXPIRED', 'SUPERSEDED')),
    CONSTRAINT ck_privacy_impact_assessment_change CHECK (change_kind IN ('NEW_PURPOSE', 'NEW_DATA_CATEGORY', 'RISK_FEATURE', 'AUTOMATED_DECISION', 'EXTERNAL_SHARING', 'CROSS_BORDER', 'BIOMETRIC', 'MINOR', 'DELEGATION')),
    CONSTRAINT ck_privacy_impact_assessment_scope CHECK (cardinality(purpose_codes) > 0 AND cardinality(data_category_codes) > 0),
    CONSTRAINT ck_privacy_impact_assessment_risk CHECK (residual_risk_level IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    CONSTRAINT ck_privacy_impact_assessment_approved CHECK (assessment_state <> 'APPROVED' OR approved_at IS NOT NULL)
);

COMMENT ON TABLE privacy.privacy_impact_assessment IS 'CAP-PRIV-017：新增用途、风险特征、自动决策、对外共享、跨境、生物特征、未成年人和委托的 PIA。';

ALTER TABLE privacy.privacy_request_task
    ADD CONSTRAINT fk_privacy_request_task_hold FOREIGN KEY (legal_hold_id) REFERENCES privacy.legal_hold(id);

CREATE INDEX ix_consent_expiry ON privacy.consent(expires_at) WHERE consent_state IN ('PENDING', 'GRANTED');

CREATE INDEX ix_privacy_request_user ON privacy.privacy_request(user_id, request_state, submitted_at DESC);

CREATE INDEX ix_privacy_task_retry ON privacy.privacy_request_task(next_attempt_at) WHERE task_state IN ('PENDING', 'FAILED');

CREATE INDEX ix_legal_hold_subject ON privacy.legal_hold(subject_kind, subject_ref) WHERE hold_state = 'ACTIVE';

CREATE INDEX ix_cross_border_expiry ON privacy.cross_border_authorization(valid_until) WHERE authorization_state = 'ACTIVE';

CREATE INDEX ix_pia_expiry ON privacy.privacy_impact_assessment(expires_at) WHERE assessment_state = 'APPROVED';

CREATE UNIQUE INDEX ux_consent_effective ON privacy.consent(aggregate_id)
    WHERE consent_state = 'GRANTED';

CREATE UNIQUE INDEX ux_consent_pending ON privacy.consent(aggregate_id)
    WHERE consent_state = 'PENDING';

CREATE INDEX ix_fk_purpose_data_mapping_category_code ON privacy.purpose_data_mapping (category_code);

CREATE INDEX ix_fk_consent_purpose_code_purpose_version ON privacy.consent (purpose_code, purpose_version);

CREATE INDEX ix_fk_marketing_subscription_consent_id ON privacy.marketing_subscription (consent_id);

CREATE INDEX ix_fk_privacy_request_task_legal_hold_id ON privacy.privacy_request_task (legal_hold_id);

CREATE INDEX ix_fk_retention_rule_category_code ON privacy.retention_rule (category_code);

CREATE INDEX ix_fk_minor_protection_guardian_consent_id ON privacy.minor_protection (guardian_consent_id);

COMMENT ON COLUMN privacy.purpose.purpose_code IS '稳定机器可读代码；展示文本由资源或目录解析。';
COMMENT ON COLUMN privacy.purpose.purpose_version IS '对象、策略或源数据的显式版本；不得以不可信客户端时间戳替代。';
COMMENT ON COLUMN privacy.purpose.display_name IS 'privacy.purpose.display_name 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN privacy.purpose.legal_basis IS 'privacy.purpose.legal_basis 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN privacy.purpose.notice_uri IS '受控 URI；写入前必须执行协议、主机、重定向与 SSRF 安全校验。';
COMMENT ON COLUMN privacy.purpose.notice_hash IS '不可逆摘要；用于等值匹配、幂等、完整性或最小化证据，不保存原始敏感值。';
COMMENT ON COLUMN privacy.purpose.owner_ref IS '不透明对象引用；不得从格式推断手机号、邮箱或其他业务事实。';
COMMENT ON COLUMN privacy.purpose.is_high_risk IS '显式布尔开关；启用前置条件与失效行为由约束和版本化策略控制。';
COMMENT ON COLUMN privacy.purpose.effective_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN privacy.purpose.retired_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN privacy.data_category.category_code IS '稳定机器可读代码；展示文本由资源或目录解析。';
COMMENT ON COLUMN privacy.data_category.display_name IS 'privacy.data_category.display_name 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN privacy.data_category.classification_code IS '稳定机器可读代码；展示文本由资源或目录解析。';
COMMENT ON COLUMN privacy.data_category.is_sensitive_personal IS '显式布尔开关；启用前置条件与失效行为由约束和版本化策略控制。';
COMMENT ON COLUMN privacy.data_category.requires_separate_consent IS 'privacy.data_category.requires_separate_consent 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN privacy.data_category.description IS 'privacy.data_category.description 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN privacy.purpose_data_mapping.purpose_code IS '稳定机器可读代码；展示文本由资源或目录解析。';
COMMENT ON COLUMN privacy.purpose_data_mapping.purpose_version IS '对象、策略或源数据的显式版本；不得以不可信客户端时间戳替代。';
COMMENT ON COLUMN privacy.purpose_data_mapping.category_code IS '稳定机器可读代码；展示文本由资源或目录解析。';
COMMENT ON COLUMN privacy.purpose_data_mapping.recipient_code IS '稳定机器可读代码；展示文本由资源或目录解析。';
COMMENT ON COLUMN privacy.purpose_data_mapping.scope_codes IS '代码或引用集合；写入前去重、校验 allowlist，并满足表约束。';
COMMENT ON COLUMN privacy.purpose_data_mapping.claim_codes IS '代码或引用集合；写入前去重、校验 allowlist，并满足表约束。';
COMMENT ON COLUMN privacy.purpose_data_mapping.downstream_systems IS '代码或引用集合；写入前去重、校验 allowlist，并满足表约束。';
COMMENT ON COLUMN privacy.purpose_data_mapping.subscription_topics IS '代码或引用集合；写入前去重、校验 allowlist，并满足表约束。';
COMMENT ON COLUMN privacy.purpose_data_mapping.retention_policy_code IS '稳定机器可读代码；展示文本由资源或目录解析。';
COMMENT ON COLUMN privacy.agreement.id IS '内部 UUID 主键；仅用于数据库关系，不作为跨域公开标识。';
COMMENT ON COLUMN privacy.agreement.agreement_code IS '稳定机器可读代码；展示文本由资源或目录解析。';
COMMENT ON COLUMN privacy.agreement.agreement_version IS '对象、策略或源数据的显式版本；不得以不可信客户端时间戳替代。';
COMMENT ON COLUMN privacy.agreement.agreement_kind IS '对象类别判别字段；允许值由 CHECK 或对应注册表限定。';
COMMENT ON COLUMN privacy.agreement.locale IS 'privacy.agreement.locale 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN privacy.agreement.content_uri IS '受控 URI；写入前必须执行协议、主机、重定向与 SSRF 安全校验。';
COMMENT ON COLUMN privacy.agreement.content_hash IS '不可逆摘要；用于等值匹配、幂等、完整性或最小化证据，不保存原始敏感值。';
COMMENT ON COLUMN privacy.agreement.effective_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN privacy.agreement.retired_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN privacy.agreement_acceptance.id IS '内部 UUID 主键；仅用于数据库关系，不作为跨域公开标识。';
COMMENT ON COLUMN privacy.agreement_acceptance.agreement_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN privacy.agreement_acceptance.user_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN privacy.agreement_acceptance.client_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN privacy.agreement_acceptance.tenant_id IS '租户隔离键；全零 UUID 表示平台范围，应用查询必须显式携带可信租户上下文。';
COMMENT ON COLUMN privacy.agreement_acceptance.acceptance_action IS 'privacy.agreement_acceptance.acceptance_action 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN privacy.agreement_acceptance.evidence_hash IS '不可逆摘要；用于等值匹配、幂等、完整性或最小化证据，不保存原始敏感值。';
COMMENT ON COLUMN privacy.agreement_acceptance.source_ip_hash IS '不可逆摘要；用于等值匹配、幂等、完整性或最小化证据，不保存原始敏感值。';
COMMENT ON COLUMN privacy.agreement_acceptance.user_agent_hash IS '不可逆摘要；用于等值匹配、幂等、完整性或最小化证据，不保存原始敏感值。';
COMMENT ON COLUMN privacy.agreement_acceptance.accepted_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN privacy.agreement_acceptance.revoked_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN privacy.consent_aggregate.id IS '内部 UUID 主键；仅用于数据库关系，不作为跨域公开标识。';
COMMENT ON COLUMN privacy.consent_aggregate.public_id IS '不可复用的公开稳定标识；插入时登记到 core.public_id_ledger。';
COMMENT ON COLUMN privacy.consent_aggregate.user_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN privacy.consent_aggregate.purpose_code IS '稳定机器可读代码；展示文本由资源或目录解析。';
COMMENT ON COLUMN privacy.consent_aggregate.data_categories_hash IS '不可逆摘要；用于等值匹配、幂等、完整性或最小化证据，不保存原始敏感值。';
COMMENT ON COLUMN privacy.consent_aggregate.recipient_code IS '稳定机器可读代码；展示文本由资源或目录解析。';
COMMENT ON COLUMN privacy.consent_aggregate.tenant_id IS '租户隔离键；全零 UUID 表示平台范围，应用查询必须显式携带可信租户上下文。';
COMMENT ON COLUMN privacy.consent_aggregate.aggregate_key_hash IS '不可逆摘要；用于等值匹配、幂等、完整性或最小化证据，不保存原始敏感值。';
COMMENT ON COLUMN privacy.consent_aggregate.current_epoch IS '安全或同意水位版本；只能单调递增，用于令牌、缓存与撤销新鲜度校验。';
COMMENT ON COLUMN privacy.consent_aggregate.created_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN privacy.consent_aggregate.updated_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN privacy.consent_aggregate.row_version IS '乐观并发版本；更新必须使用原值 compare-and-set，成功后由数据库单调递增。';
COMMENT ON COLUMN privacy.consent.id IS '内部 UUID 主键；仅用于数据库关系，不作为跨域公开标识。';
COMMENT ON COLUMN privacy.consent.public_id IS '不可复用的公开稳定标识；插入时登记到 core.public_id_ledger。';
COMMENT ON COLUMN privacy.consent.aggregate_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN privacy.consent.purpose_code IS '稳定机器可读代码；展示文本由资源或目录解析。';
COMMENT ON COLUMN privacy.consent.purpose_version IS '对象、策略或源数据的显式版本；不得以不可信客户端时间戳替代。';
COMMENT ON COLUMN privacy.consent.data_category_codes IS '代码或引用集合；写入前去重、校验 allowlist，并满足表约束。';
COMMENT ON COLUMN privacy.consent.recipient_code IS '稳定机器可读代码；展示文本由资源或目录解析。';
COMMENT ON COLUMN privacy.consent.requested_scope_codes IS '代码或引用集合；写入前去重、校验 allowlist，并满足表约束。';
COMMENT ON COLUMN privacy.consent.consent_context_hash IS '不可逆摘要；用于等值匹配、幂等、完整性或最小化证据，不保存原始敏感值。';
COMMENT ON COLUMN privacy.consent.consent_state IS '显式状态当前值；合法取值见 CHECK，完整状态转换由 .NET 领域策略执行。';
COMMENT ON COLUMN privacy.consent.consent_epoch IS '安全或同意水位版本；只能单调递增，用于令牌、缓存与撤销新鲜度校验。';
COMMENT ON COLUMN privacy.consent.affirmative_action IS 'privacy.consent.affirmative_action 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN privacy.consent.action_kind IS '对象类别判别字段；允许值由 CHECK 或对应注册表限定。';
COMMENT ON COLUMN privacy.consent.action_evidence_hash IS '不可逆摘要；用于等值匹配、幂等、完整性或最小化证据，不保存原始敏感值。';
COMMENT ON COLUMN privacy.consent.source_client_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN privacy.consent.source_login_transaction_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN privacy.consent.granted_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN privacy.consent.denied_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN privacy.consent.withdrawn_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN privacy.consent.expired_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN privacy.consent.superseded_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN privacy.consent.expires_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN privacy.consent.created_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN privacy.consent.updated_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN privacy.consent.row_version IS '乐观并发版本；更新必须使用原值 compare-and-set，成功后由数据库单调递增。';
COMMENT ON COLUMN privacy.consent.consent_version IS '对象、策略或源数据的显式版本；不得以不可信客户端时间戳替代。';
COMMENT ON COLUMN privacy.marketing_subscription.id IS '内部 UUID 主键；仅用于数据库关系，不作为跨域公开标识。';
COMMENT ON COLUMN privacy.marketing_subscription.user_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN privacy.marketing_subscription.channel_code IS '稳定机器可读代码；展示文本由资源或目录解析。';
COMMENT ON COLUMN privacy.marketing_subscription.topic_code IS '稳定机器可读代码；展示文本由资源或目录解析。';
COMMENT ON COLUMN privacy.marketing_subscription.recipient_code IS '稳定机器可读代码；展示文本由资源或目录解析。';
COMMENT ON COLUMN privacy.marketing_subscription.subscription_state IS '显式状态当前值；合法取值见 CHECK，完整状态转换由 .NET 领域策略执行。';
COMMENT ON COLUMN privacy.marketing_subscription.consent_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN privacy.marketing_subscription.consent_epoch IS '安全或同意水位版本；只能单调递增，用于令牌、缓存与撤销新鲜度校验。';
COMMENT ON COLUMN privacy.marketing_subscription.source_kind IS '对象类别判别字段；允许值由 CHECK 或对应注册表限定。';
COMMENT ON COLUMN privacy.marketing_subscription.subscribed_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN privacy.marketing_subscription.unsubscribed_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN privacy.marketing_subscription.created_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN privacy.marketing_subscription.updated_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN privacy.marketing_subscription.row_version IS '乐观并发版本；更新必须使用原值 compare-and-set，成功后由数据库单调递增。';
COMMENT ON COLUMN privacy.privacy_request.id IS '内部 UUID 主键；仅用于数据库关系，不作为跨域公开标识。';
COMMENT ON COLUMN privacy.privacy_request.public_id IS '不可复用的公开稳定标识；插入时登记到 core.public_id_ledger。';
COMMENT ON COLUMN privacy.privacy_request.user_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN privacy.privacy_request.request_kind IS '对象类别判别字段；允许值由 CHECK 或对应注册表限定。';
COMMENT ON COLUMN privacy.privacy_request.request_state IS '显式状态当前值；合法取值见 CHECK，完整状态转换由 .NET 领域策略执行。';
COMMENT ON COLUMN privacy.privacy_request.operation_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN privacy.privacy_request.identity_verification_tx_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN privacy.privacy_request.requested_scope IS '版本化结构化扩展数据；必须由 .NET 按对应 JSON Schema 校验，不得替代核心状态或外键。';
COMMENT ON COLUMN privacy.privacy_request.legal_deadline_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN privacy.privacy_request.blocked_reason_code IS '稳定机器可读代码；展示文本由资源或目录解析。';
COMMENT ON COLUMN privacy.privacy_request.rejection_reason_code IS '稳定机器可读代码；展示文本由资源或目录解析。';
COMMENT ON COLUMN privacy.privacy_request.submitted_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN privacy.privacy_request.verified_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN privacy.privacy_request.completed_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN privacy.privacy_request.rejected_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN privacy.privacy_request.updated_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN privacy.privacy_request.row_version IS '乐观并发版本；更新必须使用原值 compare-and-set，成功后由数据库单调递增。';
COMMENT ON COLUMN privacy.privacy_request.started_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN privacy.privacy_request.blocked_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN privacy.privacy_request.partial_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN privacy.privacy_request_task.id IS '内部 UUID 主键；仅用于数据库关系，不作为跨域公开标识。';
COMMENT ON COLUMN privacy.privacy_request_task.privacy_request_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN privacy.privacy_request_task.target_system_code IS '稳定机器可读代码；展示文本由资源或目录解析。';
COMMENT ON COLUMN privacy.privacy_request_task.task_kind IS '对象类别判别字段；允许值由 CHECK 或对应注册表限定。';
COMMENT ON COLUMN privacy.privacy_request_task.task_state IS '显式状态当前值；合法取值见 CHECK，完整状态转换由 .NET 领域策略执行。';
COMMENT ON COLUMN privacy.privacy_request_task.idempotency_key IS 'privacy.privacy_request_task.idempotency_key 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN privacy.privacy_request_task.checkpoint IS '版本化结构化扩展数据；必须由 .NET 按对应 JSON Schema 校验，不得替代核心状态或外键。';
COMMENT ON COLUMN privacy.privacy_request_task.legal_hold_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN privacy.privacy_request_task.attempt_count IS '非负计数器；并发更新使用原子 SQL 或乐观并发控制。';
COMMENT ON COLUMN privacy.privacy_request_task.next_attempt_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN privacy.privacy_request_task.last_error_code IS '稳定机器可读代码；展示文本由资源或目录解析。';
COMMENT ON COLUMN privacy.privacy_request_task.completion_evidence_hash IS '不可逆摘要；用于等值匹配、幂等、完整性或最小化证据，不保存原始敏感值。';
COMMENT ON COLUMN privacy.privacy_request_task.completed_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN privacy.privacy_request_task.updated_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN privacy.legal_hold.id IS '内部 UUID 主键；仅用于数据库关系，不作为跨域公开标识。';
COMMENT ON COLUMN privacy.legal_hold.public_id IS '不可复用的公开稳定标识；插入时登记到 core.public_id_ledger。';
COMMENT ON COLUMN privacy.legal_hold.subject_kind IS '对象类别判别字段；允许值由 CHECK 或对应注册表限定。';
COMMENT ON COLUMN privacy.legal_hold.subject_ref IS '不透明对象引用；不得从格式推断手机号、邮箱或其他业务事实。';
COMMENT ON COLUMN privacy.legal_hold.data_category_codes IS '代码或引用集合；写入前去重、校验 allowlist，并满足表约束。';
COMMENT ON COLUMN privacy.legal_hold.legal_basis IS 'privacy.legal_hold.legal_basis 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN privacy.legal_hold.case_reference IS 'privacy.legal_hold.case_reference 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN privacy.legal_hold.approved_by_ref IS '不透明对象引用；不得从格式推断手机号、邮箱或其他业务事实。';
COMMENT ON COLUMN privacy.legal_hold.hold_state IS '显式状态当前值；合法取值见 CHECK，完整状态转换由 .NET 领域策略执行。';
COMMENT ON COLUMN privacy.legal_hold.starts_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN privacy.legal_hold.expires_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN privacy.legal_hold.released_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN privacy.legal_hold.created_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN privacy.export_job.id IS '内部 UUID 主键；仅用于数据库关系，不作为跨域公开标识。';
COMMENT ON COLUMN privacy.export_job.privacy_request_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN privacy.export_job.export_state IS '显式状态当前值；合法取值见 CHECK，完整状态转换由 .NET 领域策略执行。';
COMMENT ON COLUMN privacy.export_job.classification_code IS '稳定机器可读代码；展示文本由资源或目录解析。';
COMMENT ON COLUMN privacy.export_job.encryption_key_ref IS '外部 KMS/HSM 或受控密钥资产引用；不得保存私钥或 Secret 明文。';
COMMENT ON COLUMN privacy.export_job.object_uri IS '受控 URI；写入前必须执行协议、主机、重定向与 SSRF 安全校验。';
COMMENT ON COLUMN privacy.export_job.object_hash IS '不可逆摘要；用于等值匹配、幂等、完整性或最小化证据，不保存原始敏感值。';
COMMENT ON COLUMN privacy.export_job.download_token_hash IS '不可逆摘要；用于等值匹配、幂等、完整性或最小化证据，不保存原始敏感值。';
COMMENT ON COLUMN privacy.export_job.download_expires_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN privacy.export_job.download_count IS '非负计数器；并发更新使用原子 SQL 或乐观并发控制。';
COMMENT ON COLUMN privacy.export_job.max_download_count IS '非负计数器；并发更新使用原子 SQL 或乐观并发控制。';
COMMENT ON COLUMN privacy.export_job.generated_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN privacy.export_job.destroyed_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN privacy.export_job.created_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN privacy.export_job.updated_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN privacy.retention_rule.id IS '内部 UUID 主键；仅用于数据库关系，不作为跨域公开标识。';
COMMENT ON COLUMN privacy.retention_rule.rule_code IS '稳定机器可读代码；展示文本由资源或目录解析。';
COMMENT ON COLUMN privacy.retention_rule.rule_version IS '对象、策略或源数据的显式版本；不得以不可信客户端时间戳替代。';
COMMENT ON COLUMN privacy.retention_rule.schema_name IS 'privacy.retention_rule.schema_name 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN privacy.retention_rule.table_name IS 'privacy.retention_rule.table_name 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN privacy.retention_rule.category_code IS '稳定机器可读代码；展示文本由资源或目录解析。';
COMMENT ON COLUMN privacy.retention_rule.legal_basis IS 'privacy.retention_rule.legal_basis 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN privacy.retention_rule.retention_interval IS 'privacy.retention_rule.retention_interval 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN privacy.retention_rule.disposition_kind IS '对象类别判别字段；允许值由 CHECK 或对应注册表限定。';
COMMENT ON COLUMN privacy.retention_rule.key_destruction_required IS 'privacy.retention_rule.key_destruction_required 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN privacy.retention_rule.owner_ref IS '不透明对象引用；不得从格式推断手机号、邮箱或其他业务事实。';
COMMENT ON COLUMN privacy.retention_rule.approval_case_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN privacy.retention_rule.effective_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN privacy.retention_rule.retired_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN privacy.deletion_proof.id IS '内部 UUID 主键；仅用于数据库关系，不作为跨域公开标识。';
COMMENT ON COLUMN privacy.deletion_proof.privacy_request_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN privacy.deletion_proof.proof_version IS '对象、策略或源数据的显式版本；不得以不可信客户端时间戳替代。';
COMMENT ON COLUMN privacy.deletion_proof.subject_tombstone_ref IS '不透明对象引用；不得从格式推断手机号、邮箱或其他业务事实。';
COMMENT ON COLUMN privacy.deletion_proof.completed_systems IS '版本化结构化扩展数据；必须由 .NET 按对应 JSON Schema 校验，不得替代核心状态或外键。';
COMMENT ON COLUMN privacy.deletion_proof.retained_items IS '版本化结构化扩展数据；必须由 .NET 按对应 JSON Schema 校验，不得替代核心状态或外键。';
COMMENT ON COLUMN privacy.deletion_proof.backup_policy_evidence IS '版本化结构化扩展数据；必须由 .NET 按对应 JSON Schema 校验，不得替代核心状态或外键。';
COMMENT ON COLUMN privacy.deletion_proof.proof_hash IS '不可逆摘要；用于等值匹配、幂等、完整性或最小化证据，不保存原始敏感值。';
COMMENT ON COLUMN privacy.deletion_proof.signed_by_key_ref IS '外部 KMS/HSM 或受控密钥资产引用；不得保存私钥或 Secret 明文。';
COMMENT ON COLUMN privacy.deletion_proof.issued_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN privacy.cross_border_authorization.id IS '内部 UUID 主键；仅用于数据库关系，不作为跨域公开标识。';
COMMENT ON COLUMN privacy.cross_border_authorization.public_id IS '不可复用的公开稳定标识；插入时登记到 core.public_id_ledger。';
COMMENT ON COLUMN privacy.cross_border_authorization.authorization_code IS '稳定机器可读代码；展示文本由资源或目录解析。';
COMMENT ON COLUMN privacy.cross_border_authorization.authorization_state IS '显式状态当前值；合法取值见 CHECK，完整状态转换由 .NET 领域策略执行。';
COMMENT ON COLUMN privacy.cross_border_authorization.source_region IS 'privacy.cross_border_authorization.source_region 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN privacy.cross_border_authorization.destination_region IS 'privacy.cross_border_authorization.destination_region 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN privacy.cross_border_authorization.recipient_code IS '稳定机器可读代码；展示文本由资源或目录解析。';
COMMENT ON COLUMN privacy.cross_border_authorization.purpose_code IS '稳定机器可读代码；展示文本由资源或目录解析。';
COMMENT ON COLUMN privacy.cross_border_authorization.data_category_codes IS '代码或引用集合；写入前去重、校验 allowlist，并满足表约束。';
COMMENT ON COLUMN privacy.cross_border_authorization.transfer_mechanism IS 'privacy.cross_border_authorization.transfer_mechanism 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN privacy.cross_border_authorization.assessment_reference IS 'privacy.cross_border_authorization.assessment_reference 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN privacy.cross_border_authorization.route_policy IS '版本化结构化扩展数据；必须由 .NET 按对应 JSON Schema 校验，不得替代核心状态或外键。';
COMMENT ON COLUMN privacy.cross_border_authorization.owner_ref IS '不透明对象引用；不得从格式推断手机号、邮箱或其他业务事实。';
COMMENT ON COLUMN privacy.cross_border_authorization.approval_case_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN privacy.cross_border_authorization.valid_from IS 'privacy.cross_border_authorization.valid_from 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN privacy.cross_border_authorization.valid_until IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN privacy.cross_border_authorization.revoked_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN privacy.cross_border_authorization.created_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN privacy.cross_border_authorization.updated_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN privacy.cross_border_authorization.row_version IS '乐观并发版本；更新必须使用原值 compare-and-set，成功后由数据库单调递增。';
COMMENT ON COLUMN privacy.minor_protection.id IS '内部 UUID 主键；仅用于数据库关系，不作为跨域公开标识。';
COMMENT ON COLUMN privacy.minor_protection.minor_user_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN privacy.minor_protection.protection_state IS '显式状态当前值；合法取值见 CHECK，完整状态转换由 .NET 领域策略执行。';
COMMENT ON COLUMN privacy.minor_protection.age_band IS 'privacy.minor_protection.age_band 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN privacy.minor_protection.age_assurance_method IS 'privacy.minor_protection.age_assurance_method 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN privacy.minor_protection.age_evidence_hash IS '不可逆摘要；用于等值匹配、幂等、完整性或最小化证据，不保存原始敏感值。';
COMMENT ON COLUMN privacy.minor_protection.guardian_user_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN privacy.minor_protection.guardian_delegation_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN privacy.minor_protection.guardian_consent_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN privacy.minor_protection.restriction_policy_code IS '稳定机器可读代码；展示文本由资源或目录解析。';
COMMENT ON COLUMN privacy.minor_protection.verified_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN privacy.minor_protection.expires_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN privacy.minor_protection.created_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN privacy.minor_protection.updated_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN privacy.minor_protection.row_version IS '乐观并发版本；更新必须使用原值 compare-and-set，成功后由数据库单调递增。';
COMMENT ON COLUMN privacy.privacy_impact_assessment.id IS '内部 UUID 主键；仅用于数据库关系，不作为跨域公开标识。';
COMMENT ON COLUMN privacy.privacy_impact_assessment.public_id IS '不可复用的公开稳定标识；插入时登记到 core.public_id_ledger。';
COMMENT ON COLUMN privacy.privacy_impact_assessment.assessment_code IS '稳定机器可读代码；展示文本由资源或目录解析。';
COMMENT ON COLUMN privacy.privacy_impact_assessment.assessment_version IS '对象、策略或源数据的显式版本；不得以不可信客户端时间戳替代。';
COMMENT ON COLUMN privacy.privacy_impact_assessment.assessment_state IS '显式状态当前值；合法取值见 CHECK，完整状态转换由 .NET 领域策略执行。';
COMMENT ON COLUMN privacy.privacy_impact_assessment.change_kind IS '对象类别判别字段；允许值由 CHECK 或对应注册表限定。';
COMMENT ON COLUMN privacy.privacy_impact_assessment.scope_definition IS '版本化结构化扩展数据；必须由 .NET 按对应 JSON Schema 校验，不得替代核心状态或外键。';
COMMENT ON COLUMN privacy.privacy_impact_assessment.purpose_codes IS '代码或引用集合；写入前去重、校验 allowlist，并满足表约束。';
COMMENT ON COLUMN privacy.privacy_impact_assessment.data_category_codes IS '代码或引用集合；写入前去重、校验 allowlist，并满足表约束。';
COMMENT ON COLUMN privacy.privacy_impact_assessment.recipient_codes IS '代码或引用集合；写入前去重、校验 allowlist，并满足表约束。';
COMMENT ON COLUMN privacy.privacy_impact_assessment.risk_summary IS '版本化结构化扩展数据；必须由 .NET 按对应 JSON Schema 校验，不得替代核心状态或外键。';
COMMENT ON COLUMN privacy.privacy_impact_assessment.mitigations IS '版本化结构化扩展数据；必须由 .NET 按对应 JSON Schema 校验，不得替代核心状态或外键。';
COMMENT ON COLUMN privacy.privacy_impact_assessment.residual_risk_level IS 'privacy.privacy_impact_assessment.residual_risk_level 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN privacy.privacy_impact_assessment.owner_ref IS '不透明对象引用；不得从格式推断手机号、邮箱或其他业务事实。';
COMMENT ON COLUMN privacy.privacy_impact_assessment.privacy_officer_ref IS '不透明对象引用；不得从格式推断手机号、邮箱或其他业务事实。';
COMMENT ON COLUMN privacy.privacy_impact_assessment.approval_case_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN privacy.privacy_impact_assessment.approved_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN privacy.privacy_impact_assessment.expires_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN privacy.privacy_impact_assessment.created_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';

COMMENT ON CONSTRAINT pk_purpose ON privacy.purpose IS '主键约束：唯一标识 privacy.purpose 记录。';
COMMENT ON CONSTRAINT ck_purpose_basis ON privacy.purpose IS '检查约束：限制 privacy.purpose 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_purpose_hash ON privacy.purpose IS '检查约束：限制 privacy.purpose 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_purpose_window ON privacy.purpose IS '检查约束：限制 privacy.purpose 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT pk_data_category ON privacy.data_category IS '主键约束：唯一标识 privacy.data_category 记录。';
COMMENT ON CONSTRAINT pk_purpose_data_mapping ON privacy.purpose_data_mapping IS '主键约束：唯一标识 privacy.purpose_data_mapping 记录。';
COMMENT ON CONSTRAINT fk_purpose_data_mapping_purpose ON privacy.purpose_data_mapping IS '外键约束：privacy.purpose_data_mapping 的 purpose_code、purpose_version 必须引用 privacy.purpose；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT fk_purpose_data_mapping_category ON privacy.purpose_data_mapping IS '外键约束：privacy.purpose_data_mapping 的 category_code 必须引用 privacy.data_category；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT pk_agreement ON privacy.agreement IS '主键约束：唯一标识 privacy.agreement 记录。';
COMMENT ON CONSTRAINT uq_agreement_version ON privacy.agreement IS '唯一约束：保证 agreement_code、agreement_version、locale 在 privacy.agreement 范围内不重复。';
COMMENT ON CONSTRAINT ck_agreement_kind ON privacy.agreement IS '检查约束：限制 privacy.agreement 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_agreement_hash ON privacy.agreement IS '检查约束：限制 privacy.agreement 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_agreement_window ON privacy.agreement IS '检查约束：限制 privacy.agreement 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT pk_agreement_acceptance ON privacy.agreement_acceptance IS '主键约束：唯一标识 privacy.agreement_acceptance 记录。';
COMMENT ON CONSTRAINT fk_agreement_acceptance_agreement ON privacy.agreement_acceptance IS '外键约束：privacy.agreement_acceptance 的 agreement_id 必须引用 privacy.agreement；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT ck_agreement_acceptance_action ON privacy.agreement_acceptance IS '检查约束：限制 privacy.agreement_acceptance 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_agreement_acceptance_hash ON privacy.agreement_acceptance IS '检查约束：限制 privacy.agreement_acceptance 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT uq_agreement_acceptance ON privacy.agreement_acceptance IS '唯一约束：保证 agreement_id、user_id、client_id、tenant_id 在 privacy.agreement_acceptance 范围内不重复。';
COMMENT ON CONSTRAINT pk_consent_aggregate ON privacy.consent_aggregate IS '主键约束：唯一标识 privacy.consent_aggregate 记录。';
COMMENT ON CONSTRAINT uq_consent_aggregate_public_id ON privacy.consent_aggregate IS '唯一约束：保证 public_id 在 privacy.consent_aggregate 范围内不重复。';
COMMENT ON CONSTRAINT uq_consent_aggregate_key ON privacy.consent_aggregate IS '唯一约束：保证 user_id、aggregate_key_hash 在 privacy.consent_aggregate 范围内不重复。';
COMMENT ON CONSTRAINT ck_consent_aggregate_hash ON privacy.consent_aggregate IS '检查约束：限制 privacy.consent_aggregate 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_consent_aggregate_epoch ON privacy.consent_aggregate IS '检查约束：限制 privacy.consent_aggregate 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT pk_consent ON privacy.consent IS '主键约束：唯一标识 privacy.consent 记录。';
COMMENT ON CONSTRAINT uq_consent_public_id ON privacy.consent IS '唯一约束：保证 public_id 在 privacy.consent 范围内不重复。';
COMMENT ON CONSTRAINT fk_consent_aggregate ON privacy.consent IS '外键约束：privacy.consent 的 aggregate_id 必须引用 privacy.consent_aggregate；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT fk_consent_purpose ON privacy.consent IS '外键约束：privacy.consent 的 purpose_code、purpose_version 必须引用 privacy.purpose；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT ck_consent_state ON privacy.consent IS '检查约束：限制 privacy.consent 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_consent_categories ON privacy.consent IS '检查约束：限制 privacy.consent 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_consent_context_hash ON privacy.consent IS '检查约束：限制 privacy.consent 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_consent_epoch ON privacy.consent IS '检查约束：限制 privacy.consent 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_consent_action ON privacy.consent IS '检查约束：限制 privacy.consent 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_consent_granted ON privacy.consent IS '检查约束：限制 privacy.consent 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_consent_denied ON privacy.consent IS '检查约束：限制 privacy.consent 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_consent_withdrawn ON privacy.consent IS '检查约束：限制 privacy.consent 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_consent_expired ON privacy.consent IS '检查约束：限制 privacy.consent 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_consent_superseded ON privacy.consent IS '检查约束：限制 privacy.consent 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT uq_consent_version ON privacy.consent IS '唯一约束：保证 aggregate_id、consent_version 在 privacy.consent 范围内不重复。';
COMMENT ON CONSTRAINT ck_consent_version ON privacy.consent IS '检查约束：限制 privacy.consent 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT pk_marketing_subscription ON privacy.marketing_subscription IS '主键约束：唯一标识 privacy.marketing_subscription 记录。';
COMMENT ON CONSTRAINT uq_marketing_subscription ON privacy.marketing_subscription IS '唯一约束：保证 user_id、channel_code、topic_code、recipient_code 在 privacy.marketing_subscription 范围内不重复。';
COMMENT ON CONSTRAINT fk_marketing_subscription_consent ON privacy.marketing_subscription IS '外键约束：privacy.marketing_subscription 的 consent_id 必须引用 privacy.consent；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT ck_marketing_subscription_channel ON privacy.marketing_subscription IS '检查约束：限制 privacy.marketing_subscription 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_marketing_subscription_state ON privacy.marketing_subscription IS '检查约束：限制 privacy.marketing_subscription 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_marketing_subscription_consent ON privacy.marketing_subscription IS '检查约束：限制 privacy.marketing_subscription 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT pk_privacy_request ON privacy.privacy_request IS '主键约束：唯一标识 privacy.privacy_request 记录。';
COMMENT ON CONSTRAINT uq_privacy_request_public_id ON privacy.privacy_request IS '唯一约束：保证 public_id 在 privacy.privacy_request 范围内不重复。';
COMMENT ON CONSTRAINT uq_privacy_request_operation ON privacy.privacy_request IS '唯一约束：保证 operation_id 在 privacy.privacy_request 范围内不重复。';
COMMENT ON CONSTRAINT ck_privacy_request_kind ON privacy.privacy_request IS '检查约束：限制 privacy.privacy_request 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_privacy_request_state ON privacy.privacy_request IS '检查约束：限制 privacy.privacy_request 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_privacy_request_blocked ON privacy.privacy_request IS '检查约束：限制 privacy.privacy_request 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_privacy_request_completed ON privacy.privacy_request IS '检查约束：限制 privacy.privacy_request 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_privacy_request_rejected ON privacy.privacy_request IS '检查约束：限制 privacy.privacy_request 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_privacy_request_deadline ON privacy.privacy_request IS '检查约束：限制 privacy.privacy_request 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_privacy_request_verified ON privacy.privacy_request IS '检查约束：限制 privacy.privacy_request 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_privacy_request_started ON privacy.privacy_request IS '检查约束：限制 privacy.privacy_request 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_privacy_request_blocked_time ON privacy.privacy_request IS '检查约束：限制 privacy.privacy_request 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_privacy_request_partial_time ON privacy.privacy_request IS '检查约束：限制 privacy.privacy_request 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT pk_privacy_request_task ON privacy.privacy_request_task IS '主键约束：唯一标识 privacy.privacy_request_task 记录。';
COMMENT ON CONSTRAINT uq_privacy_request_task ON privacy.privacy_request_task IS '唯一约束：保证 privacy_request_id、target_system_code、task_kind 在 privacy.privacy_request_task 范围内不重复。';
COMMENT ON CONSTRAINT uq_privacy_request_task_key ON privacy.privacy_request_task IS '唯一约束：保证 idempotency_key 在 privacy.privacy_request_task 范围内不重复。';
COMMENT ON CONSTRAINT fk_privacy_request_task_request ON privacy.privacy_request_task IS '外键约束：privacy.privacy_request_task 的 privacy_request_id 必须引用 privacy.privacy_request；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT ck_privacy_request_task_kind ON privacy.privacy_request_task IS '检查约束：限制 privacy.privacy_request_task 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_privacy_request_task_state ON privacy.privacy_request_task IS '检查约束：限制 privacy.privacy_request_task 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_privacy_request_task_attempt ON privacy.privacy_request_task IS '检查约束：限制 privacy.privacy_request_task 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_privacy_request_task_evidence ON privacy.privacy_request_task IS '检查约束：限制 privacy.privacy_request_task 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT fk_privacy_request_task_hold ON privacy.privacy_request_task IS '外键约束：privacy.privacy_request_task 的 legal_hold_id 必须引用 privacy.legal_hold；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT pk_legal_hold ON privacy.legal_hold IS '主键约束：唯一标识 privacy.legal_hold 记录。';
COMMENT ON CONSTRAINT uq_legal_hold_public_id ON privacy.legal_hold IS '唯一约束：保证 public_id 在 privacy.legal_hold 范围内不重复。';
COMMENT ON CONSTRAINT ck_legal_hold_state ON privacy.legal_hold IS '检查约束：限制 privacy.legal_hold 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_legal_hold_categories ON privacy.legal_hold IS '检查约束：限制 privacy.legal_hold 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_legal_hold_window ON privacy.legal_hold IS '检查约束：限制 privacy.legal_hold 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_legal_hold_released ON privacy.legal_hold IS '检查约束：限制 privacy.legal_hold 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT pk_export_job ON privacy.export_job IS '主键约束：唯一标识 privacy.export_job 记录。';
COMMENT ON CONSTRAINT uq_export_job_request ON privacy.export_job IS '唯一约束：保证 privacy_request_id 在 privacy.export_job 范围内不重复。';
COMMENT ON CONSTRAINT fk_export_job_request ON privacy.export_job IS '外键约束：privacy.export_job 的 privacy_request_id 必须引用 privacy.privacy_request；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT ck_export_job_state ON privacy.export_job IS '检查约束：限制 privacy.export_job 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_export_job_hash ON privacy.export_job IS '检查约束：限制 privacy.export_job 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_export_job_token ON privacy.export_job IS '检查约束：限制 privacy.export_job 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_export_job_count ON privacy.export_job IS '检查约束：限制 privacy.export_job 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_export_job_ready ON privacy.export_job IS '检查约束：限制 privacy.export_job 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_export_job_ttl ON privacy.export_job IS '检查约束：限制 privacy.export_job 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT pk_retention_rule ON privacy.retention_rule IS '主键约束：唯一标识 privacy.retention_rule 记录。';
COMMENT ON CONSTRAINT uq_retention_rule_version ON privacy.retention_rule IS '唯一约束：保证 rule_code、rule_version 在 privacy.retention_rule 范围内不重复。';
COMMENT ON CONSTRAINT fk_retention_rule_category ON privacy.retention_rule IS '外键约束：privacy.retention_rule 的 category_code 必须引用 privacy.data_category；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT ck_retention_rule_interval ON privacy.retention_rule IS '检查约束：限制 privacy.retention_rule 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_retention_rule_disposition ON privacy.retention_rule IS '检查约束：限制 privacy.retention_rule 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT pk_deletion_proof ON privacy.deletion_proof IS '主键约束：唯一标识 privacy.deletion_proof 记录。';
COMMENT ON CONSTRAINT uq_deletion_proof ON privacy.deletion_proof IS '唯一约束：保证 privacy_request_id、proof_version 在 privacy.deletion_proof 范围内不重复。';
COMMENT ON CONSTRAINT fk_deletion_proof_request ON privacy.deletion_proof IS '外键约束：privacy.deletion_proof 的 privacy_request_id 必须引用 privacy.privacy_request；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT ck_deletion_proof_hash ON privacy.deletion_proof IS '检查约束：限制 privacy.deletion_proof 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT pk_cross_border_authorization ON privacy.cross_border_authorization IS '主键约束：唯一标识 privacy.cross_border_authorization 记录。';
COMMENT ON CONSTRAINT uq_cross_border_authorization_public_id ON privacy.cross_border_authorization IS '唯一约束：保证 public_id 在 privacy.cross_border_authorization 范围内不重复。';
COMMENT ON CONSTRAINT uq_cross_border_authorization_code ON privacy.cross_border_authorization IS '唯一约束：保证 authorization_code 在 privacy.cross_border_authorization 范围内不重复。';
COMMENT ON CONSTRAINT ck_cross_border_authorization_regions ON privacy.cross_border_authorization IS '检查约束：限制 privacy.cross_border_authorization 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_cross_border_authorization_state ON privacy.cross_border_authorization IS '检查约束：限制 privacy.cross_border_authorization 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_cross_border_authorization_categories ON privacy.cross_border_authorization IS '检查约束：限制 privacy.cross_border_authorization 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_cross_border_authorization_mechanism ON privacy.cross_border_authorization IS '检查约束：限制 privacy.cross_border_authorization 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_cross_border_authorization_window ON privacy.cross_border_authorization IS '检查约束：限制 privacy.cross_border_authorization 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_cross_border_authorization_revoked ON privacy.cross_border_authorization IS '检查约束：限制 privacy.cross_border_authorization 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT pk_minor_protection ON privacy.minor_protection IS '主键约束：唯一标识 privacy.minor_protection 记录。';
COMMENT ON CONSTRAINT uq_minor_protection_user ON privacy.minor_protection IS '唯一约束：保证 minor_user_id 在 privacy.minor_protection 范围内不重复。';
COMMENT ON CONSTRAINT fk_minor_protection_consent ON privacy.minor_protection IS '外键约束：privacy.minor_protection 的 guardian_consent_id 必须引用 privacy.consent；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT ck_minor_protection_parties ON privacy.minor_protection IS '检查约束：限制 privacy.minor_protection 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_minor_protection_state ON privacy.minor_protection IS '检查约束：限制 privacy.minor_protection 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_minor_protection_band ON privacy.minor_protection IS '检查约束：限制 privacy.minor_protection 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_minor_protection_evidence ON privacy.minor_protection IS '检查约束：限制 privacy.minor_protection 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_minor_protection_guardian ON privacy.minor_protection IS '检查约束：限制 privacy.minor_protection 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_minor_protection_window ON privacy.minor_protection IS '检查约束：限制 privacy.minor_protection 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT pk_privacy_impact_assessment ON privacy.privacy_impact_assessment IS '主键约束：唯一标识 privacy.privacy_impact_assessment 记录。';
COMMENT ON CONSTRAINT uq_privacy_impact_assessment_public_id ON privacy.privacy_impact_assessment IS '唯一约束：保证 public_id 在 privacy.privacy_impact_assessment 范围内不重复。';
COMMENT ON CONSTRAINT uq_privacy_impact_assessment_version ON privacy.privacy_impact_assessment IS '唯一约束：保证 assessment_code、assessment_version 在 privacy.privacy_impact_assessment 范围内不重复。';
COMMENT ON CONSTRAINT ck_privacy_impact_assessment_state ON privacy.privacy_impact_assessment IS '检查约束：限制 privacy.privacy_impact_assessment 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_privacy_impact_assessment_change ON privacy.privacy_impact_assessment IS '检查约束：限制 privacy.privacy_impact_assessment 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_privacy_impact_assessment_scope ON privacy.privacy_impact_assessment IS '检查约束：限制 privacy.privacy_impact_assessment 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_privacy_impact_assessment_risk ON privacy.privacy_impact_assessment IS '检查约束：限制 privacy.privacy_impact_assessment 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_privacy_impact_assessment_approved ON privacy.privacy_impact_assessment IS '检查约束：限制 privacy.privacy_impact_assessment 的字段取值或组合满足结构与安全底线。';

COMMENT ON INDEX privacy.ix_consent_expiry IS '查询索引：优化 privacy.consent 按 expires_at 的访问，仅覆盖 WHERE 条件命中的记录。';
COMMENT ON INDEX privacy.ix_privacy_request_user IS '查询索引：优化 privacy.privacy_request 按 user_id、request_state、submitted_at 的访问。';
COMMENT ON INDEX privacy.ix_privacy_task_retry IS '查询索引：优化 privacy.privacy_request_task 按 next_attempt_at 的访问，仅覆盖 WHERE 条件命中的记录。';
COMMENT ON INDEX privacy.ix_legal_hold_subject IS '查询索引：优化 privacy.legal_hold 按 subject_kind、subject_ref 的访问，仅覆盖 WHERE 条件命中的记录。';
COMMENT ON INDEX privacy.ix_cross_border_expiry IS '查询索引：优化 privacy.cross_border_authorization 按 valid_until 的访问，仅覆盖 WHERE 条件命中的记录。';
COMMENT ON INDEX privacy.ix_pia_expiry IS '查询索引：优化 privacy.privacy_impact_assessment 按 expires_at 的访问，仅覆盖 WHERE 条件命中的记录。';
COMMENT ON INDEX privacy.ux_consent_effective IS '查询索引：优化 privacy.consent 按 aggregate_id 的访问，仅覆盖 WHERE 条件命中的记录。';
COMMENT ON INDEX privacy.ux_consent_pending IS '查询索引：优化 privacy.consent 按 aggregate_id 的访问，仅覆盖 WHERE 条件命中的记录。';
COMMENT ON INDEX privacy.pk_purpose IS '约束 pk_purpose 的支撑唯一索引。';
COMMENT ON INDEX privacy.pk_data_category IS '约束 pk_data_category 的支撑唯一索引。';
COMMENT ON INDEX privacy.pk_purpose_data_mapping IS '约束 pk_purpose_data_mapping 的支撑唯一索引。';
COMMENT ON INDEX privacy.pk_agreement IS '约束 pk_agreement 的支撑唯一索引。';
COMMENT ON INDEX privacy.uq_agreement_version IS '约束 uq_agreement_version 的支撑唯一索引。';
COMMENT ON INDEX privacy.pk_agreement_acceptance IS '约束 pk_agreement_acceptance 的支撑唯一索引。';
COMMENT ON INDEX privacy.uq_agreement_acceptance IS '约束 uq_agreement_acceptance 的支撑唯一索引。';
COMMENT ON INDEX privacy.pk_consent_aggregate IS '约束 pk_consent_aggregate 的支撑唯一索引。';
COMMENT ON INDEX privacy.uq_consent_aggregate_public_id IS '约束 uq_consent_aggregate_public_id 的支撑唯一索引。';
COMMENT ON INDEX privacy.uq_consent_aggregate_key IS '约束 uq_consent_aggregate_key 的支撑唯一索引。';
COMMENT ON INDEX privacy.pk_consent IS '约束 pk_consent 的支撑唯一索引。';
COMMENT ON INDEX privacy.uq_consent_public_id IS '约束 uq_consent_public_id 的支撑唯一索引。';
COMMENT ON INDEX privacy.uq_consent_version IS '约束 uq_consent_version 的支撑唯一索引。';
COMMENT ON INDEX privacy.pk_marketing_subscription IS '约束 pk_marketing_subscription 的支撑唯一索引。';
COMMENT ON INDEX privacy.uq_marketing_subscription IS '约束 uq_marketing_subscription 的支撑唯一索引。';
COMMENT ON INDEX privacy.pk_privacy_request IS '约束 pk_privacy_request 的支撑唯一索引。';
COMMENT ON INDEX privacy.uq_privacy_request_public_id IS '约束 uq_privacy_request_public_id 的支撑唯一索引。';
COMMENT ON INDEX privacy.uq_privacy_request_operation IS '约束 uq_privacy_request_operation 的支撑唯一索引。';
COMMENT ON INDEX privacy.pk_privacy_request_task IS '约束 pk_privacy_request_task 的支撑唯一索引。';
COMMENT ON INDEX privacy.uq_privacy_request_task IS '约束 uq_privacy_request_task 的支撑唯一索引。';
COMMENT ON INDEX privacy.uq_privacy_request_task_key IS '约束 uq_privacy_request_task_key 的支撑唯一索引。';
COMMENT ON INDEX privacy.pk_legal_hold IS '约束 pk_legal_hold 的支撑唯一索引。';
COMMENT ON INDEX privacy.uq_legal_hold_public_id IS '约束 uq_legal_hold_public_id 的支撑唯一索引。';
COMMENT ON INDEX privacy.pk_export_job IS '约束 pk_export_job 的支撑唯一索引。';
COMMENT ON INDEX privacy.uq_export_job_request IS '约束 uq_export_job_request 的支撑唯一索引。';
COMMENT ON INDEX privacy.pk_retention_rule IS '约束 pk_retention_rule 的支撑唯一索引。';
COMMENT ON INDEX privacy.uq_retention_rule_version IS '约束 uq_retention_rule_version 的支撑唯一索引。';
COMMENT ON INDEX privacy.pk_deletion_proof IS '约束 pk_deletion_proof 的支撑唯一索引。';
COMMENT ON INDEX privacy.uq_deletion_proof IS '约束 uq_deletion_proof 的支撑唯一索引。';
COMMENT ON INDEX privacy.pk_cross_border_authorization IS '约束 pk_cross_border_authorization 的支撑唯一索引。';
COMMENT ON INDEX privacy.uq_cross_border_authorization_public_id IS '约束 uq_cross_border_authorization_public_id 的支撑唯一索引。';
COMMENT ON INDEX privacy.uq_cross_border_authorization_code IS '约束 uq_cross_border_authorization_code 的支撑唯一索引。';
COMMENT ON INDEX privacy.pk_minor_protection IS '约束 pk_minor_protection 的支撑唯一索引。';
COMMENT ON INDEX privacy.uq_minor_protection_user IS '约束 uq_minor_protection_user 的支撑唯一索引。';
COMMENT ON INDEX privacy.pk_privacy_impact_assessment IS '约束 pk_privacy_impact_assessment 的支撑唯一索引。';
COMMENT ON INDEX privacy.uq_privacy_impact_assessment_public_id IS '约束 uq_privacy_impact_assessment_public_id 的支撑唯一索引。';
COMMENT ON INDEX privacy.uq_privacy_impact_assessment_version IS '约束 uq_privacy_impact_assessment_version 的支撑唯一索引。';
COMMENT ON INDEX privacy.ix_fk_purpose_data_mapping_category_code IS '查询索引：优化 privacy.purpose_data_mapping 按 category_code 的访问。';
COMMENT ON INDEX privacy.ix_fk_consent_purpose_code_purpose_version IS '查询索引：优化 privacy.consent 按 purpose_code、purpose_version 的访问。';
COMMENT ON INDEX privacy.ix_fk_marketing_subscription_consent_id IS '查询索引：优化 privacy.marketing_subscription 按 consent_id 的访问。';
COMMENT ON INDEX privacy.ix_fk_privacy_request_task_legal_hold_id IS '查询索引：优化 privacy.privacy_request_task 按 legal_hold_id 的访问。';
COMMENT ON INDEX privacy.ix_fk_retention_rule_category_code IS '查询索引：优化 privacy.retention_rule 按 category_code 的访问。';
COMMENT ON INDEX privacy.ix_fk_minor_protection_guardian_consent_id IS '查询索引：优化 privacy.minor_protection 按 guardian_consent_id 的访问。';

