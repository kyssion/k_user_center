-- =============================================================================
-- 040_privacy_federation.sql
-- Consent、个人权利、保留/导出，以及 OIDC/SAML/SCIM 联合与目录同步
-- =============================================================================

BEGIN;
SET LOCAL lock_timeout = '10s';
SET LOCAL statement_timeout = '5min';

CREATE TABLE privacy.purpose (
    purpose_code          text        NOT NULL,
    purpose_version       integer     NOT NULL,
    display_name          text        NOT NULL,
    legal_basis           text        NOT NULL,
    notice_uri            text        NOT NULL,
    notice_hash           bytea       NOT NULL,
    owner_ref             text        NOT NULL,
    is_high_risk          boolean     NOT NULL DEFAULT false,
    effective_at          timestamptz NOT NULL,
    retired_at            timestamptz NULL,
    CONSTRAINT pk_purpose PRIMARY KEY (purpose_code, purpose_version),
    CONSTRAINT ck_purpose_basis CHECK (legal_basis IN ('CONSENT', 'CONTRACT', 'LEGAL_OBLIGATION', 'PUBLIC_INTEREST', 'LEGITIMATE_INTEREST', 'VITAL_INTEREST')), 
    CONSTRAINT ck_purpose_hash CHECK (octet_length(notice_hash) = 32),
    CONSTRAINT ck_purpose_window CHECK (retired_at IS NULL OR retired_at > effective_at)
);
COMMENT ON TABLE privacy.purpose IS 'CAP-PRIV-001/002：处理用途、合法依据、告知版本与责任人的不可变目录。';

CREATE TABLE privacy.data_category (
    category_code         text        NOT NULL,
    display_name          text        NOT NULL,
    classification_code   text        NOT NULL,
    is_sensitive_personal boolean     NOT NULL DEFAULT false,
    requires_separate_consent boolean NOT NULL DEFAULT false,
    description           text        NOT NULL,
    CONSTRAINT pk_data_category PRIMARY KEY (category_code),
    CONSTRAINT fk_data_category_class FOREIGN KEY (classification_code) REFERENCES core.data_classification(classification_code)
);
COMMENT ON TABLE privacy.data_category IS 'REQ-PRIV-002/004：个人信息数据类别、敏感属性与单独同意要求。';

CREATE TABLE privacy.purpose_data_mapping (
    purpose_code          text        NOT NULL,
    purpose_version       integer     NOT NULL,
    category_code         text        NOT NULL,
    recipient_code        text        NOT NULL,
    scope_codes           text[]      NOT NULL DEFAULT '{}',
    claim_codes           text[]      NOT NULL DEFAULT '{}',
    downstream_systems    text[]      NOT NULL DEFAULT '{}',
    subscription_topics   text[]      NOT NULL DEFAULT '{}',
    retention_policy_code text        NOT NULL,
    CONSTRAINT pk_purpose_data_mapping PRIMARY KEY (purpose_code, purpose_version, category_code, recipient_code),
    CONSTRAINT fk_purpose_data_mapping_purpose FOREIGN KEY (purpose_code, purpose_version) REFERENCES privacy.purpose(purpose_code, purpose_version),
    CONSTRAINT fk_purpose_data_mapping_category FOREIGN KEY (category_code) REFERENCES privacy.data_category(category_code)
);
COMMENT ON TABLE privacy.purpose_data_mapping IS 'REQ-PRIV-005：用途、数据类别、接收方到 scope、claim、订阅和下游副本的可审计映射。';

CREATE TABLE privacy.agreement (
    id                    uuid        NOT NULL DEFAULT gen_random_uuid(),
    agreement_code        text        NOT NULL,
    agreement_version     integer     NOT NULL,
    agreement_kind        text        NOT NULL,
    locale                text        NOT NULL,
    content_uri           text        NOT NULL,
    content_hash          bytea       NOT NULL,
    effective_at          timestamptz NOT NULL,
    retired_at            timestamptz NULL,
    CONSTRAINT pk_agreement PRIMARY KEY (id),
    CONSTRAINT uq_agreement_version UNIQUE (agreement_code, agreement_version, locale),
    CONSTRAINT ck_agreement_kind CHECK (agreement_kind IN ('TERMS', 'PRIVACY_NOTICE', 'SERVICE_RULE', 'MARKETING_NOTICE', 'BIOMETRIC_NOTICE', 'CROSS_BORDER_NOTICE', 'MINOR_NOTICE')),
    CONSTRAINT ck_agreement_hash CHECK (octet_length(content_hash) = 32),
    CONSTRAINT ck_agreement_window CHECK (retired_at IS NULL OR retired_at > effective_at)
);
COMMENT ON TABLE privacy.agreement IS 'CAP-PRIV-003：协议与告知文本版本；与 Consent、营销订阅、OAuth Grant 分开建模。';

CREATE TABLE privacy.agreement_acceptance (
    id                    uuid        NOT NULL DEFAULT gen_random_uuid(),
    agreement_id          uuid        NOT NULL,
    user_id               uuid        NOT NULL,
    client_id             uuid        NULL,
    tenant_id             uuid        NOT NULL DEFAULT '00000000-0000-0000-0000-000000000000',
    acceptance_action     text        NOT NULL,
    evidence_hash         bytea       NOT NULL,
    source_ip_hash        bytea       NULL,
    user_agent_hash       bytea       NULL,
    accepted_at           timestamptz NOT NULL DEFAULT clock_timestamp(),
    revoked_at            timestamptz NULL,
    CONSTRAINT pk_agreement_acceptance PRIMARY KEY (id),
    CONSTRAINT uq_agreement_acceptance UNIQUE (agreement_id, user_id, client_id, tenant_id),
    CONSTRAINT fk_agreement_acceptance_agreement FOREIGN KEY (agreement_id) REFERENCES privacy.agreement(id),
    CONSTRAINT fk_agreement_acceptance_user FOREIGN KEY (user_id) REFERENCES iam.user_account(id),
    CONSTRAINT fk_agreement_acceptance_client FOREIGN KEY (client_id) REFERENCES oauth.client(id),
    CONSTRAINT ck_agreement_acceptance_action CHECK (acceptance_action IN ('CHECKBOX', 'SIGNATURE', 'ADMIN_RECORDED', 'MIGRATED')),
    CONSTRAINT ck_agreement_acceptance_hash CHECK (octet_length(evidence_hash) = 32)
);
COMMENT ON TABLE privacy.agreement_acceptance IS '用户接受协议的版本、肯定动作与最小化环境证据。';

CREATE TABLE privacy.consent_aggregate (
    id                    uuid        NOT NULL DEFAULT gen_random_uuid(),
    public_id             text        NOT NULL,
    user_id               uuid        NOT NULL,
    purpose_code          text        NOT NULL,
    data_categories_hash  bytea       NOT NULL,
    recipient_code        text        NOT NULL,
    tenant_id             uuid        NOT NULL DEFAULT '00000000-0000-0000-0000-000000000000',
    aggregate_key_hash    bytea       NOT NULL,
    current_epoch         bigint      NOT NULL DEFAULT 0,
    created_at            timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at            timestamptz NOT NULL DEFAULT clock_timestamp(),
    row_version           bigint      NOT NULL DEFAULT 1,
    CONSTRAINT pk_consent_aggregate PRIMARY KEY (id),
    CONSTRAINT uq_consent_aggregate_public_id UNIQUE (public_id),
    CONSTRAINT uq_consent_aggregate_key UNIQUE (user_id, aggregate_key_hash),
    CONSTRAINT fk_consent_aggregate_user FOREIGN KEY (user_id) REFERENCES iam.user_account(id),
    CONSTRAINT ck_consent_aggregate_hash CHECK (octet_length(data_categories_hash) = 32 AND octet_length(aggregate_key_hash) = 32),
    CONSTRAINT ck_consent_aggregate_epoch CHECK (current_epoch >= 0)
);
COMMENT ON TABLE privacy.consent_aggregate IS 'REQ-PRIV-012：按 subject + purpose + data categories + recipient 隔离的单调 consent epoch 聚合。';

CREATE TABLE privacy.consent (
    id                    uuid        NOT NULL DEFAULT gen_random_uuid(),
    public_id             text        NOT NULL,
    aggregate_id          uuid        NOT NULL,
    purpose_code          text        NOT NULL,
    purpose_version       integer     NOT NULL,
    data_category_codes   text[]      NOT NULL,
    recipient_code        text        NOT NULL,
    requested_scope_codes text[]      NOT NULL DEFAULT '{}',
    consent_context_hash  bytea       NOT NULL,
    consent_state         text        NOT NULL DEFAULT 'PENDING',
    consent_epoch         bigint      NOT NULL DEFAULT 0,
    affirmative_action    boolean     NOT NULL DEFAULT false,
    action_kind           text        NULL,
    action_evidence_hash  bytea       NULL,
    source_client_id      uuid        NULL,
    source_login_transaction_id uuid  NULL,
    granted_at            timestamptz NULL,
    denied_at             timestamptz NULL,
    withdrawn_at          timestamptz NULL,
    expired_at            timestamptz NULL,
    superseded_at         timestamptz NULL,
    expires_at            timestamptz NULL,
    created_at            timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at            timestamptz NOT NULL DEFAULT clock_timestamp(),
    row_version           bigint      NOT NULL DEFAULT 1,
    CONSTRAINT pk_consent PRIMARY KEY (id),
    CONSTRAINT uq_consent_public_id UNIQUE (public_id),
    CONSTRAINT uq_consent_context UNIQUE (aggregate_id, consent_context_hash),
    CONSTRAINT fk_consent_aggregate FOREIGN KEY (aggregate_id) REFERENCES privacy.consent_aggregate(id),
    CONSTRAINT fk_consent_purpose FOREIGN KEY (purpose_code, purpose_version) REFERENCES privacy.purpose(purpose_code, purpose_version),
    CONSTRAINT fk_consent_client FOREIGN KEY (source_client_id) REFERENCES oauth.client(id),
    CONSTRAINT fk_consent_login_tx FOREIGN KEY (source_login_transaction_id) REFERENCES authn.login_transaction(id),
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
    CONSTRAINT ck_consent_superseded CHECK ((consent_state = 'SUPERSEDED') = (superseded_at IS NOT NULL))
);
COMMENT ON TABLE privacy.consent IS 'REQ-PRIV-004/014：明确用途、类别、接收方、版本、肯定动作与终态的 Consent；PENDING/DENIED 不构成处理依据。';

CREATE TABLE privacy.marketing_subscription (
    id                    uuid        NOT NULL DEFAULT gen_random_uuid(),
    user_id               uuid        NOT NULL,
    channel_code          text        NOT NULL,
    topic_code            text        NOT NULL,
    recipient_code        text        NOT NULL,
    subscription_state    text        NOT NULL DEFAULT 'PENDING',
    consent_id            uuid        NULL,
    consent_epoch         bigint      NULL,
    source_kind           text        NOT NULL,
    subscribed_at         timestamptz NULL,
    unsubscribed_at       timestamptz NULL,
    created_at            timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at            timestamptz NOT NULL DEFAULT clock_timestamp(),
    row_version           bigint      NOT NULL DEFAULT 1,
    CONSTRAINT pk_marketing_subscription PRIMARY KEY (id),
    CONSTRAINT uq_marketing_subscription UNIQUE (user_id, channel_code, topic_code, recipient_code),
    CONSTRAINT fk_marketing_subscription_user FOREIGN KEY (user_id) REFERENCES iam.user_account(id),
    CONSTRAINT fk_marketing_subscription_consent FOREIGN KEY (consent_id) REFERENCES privacy.consent(id),
    CONSTRAINT ck_marketing_subscription_channel CHECK (channel_code IN ('EMAIL', 'SMS', 'PUSH', 'IN_APP')),
    CONSTRAINT ck_marketing_subscription_state CHECK (subscription_state IN ('PENDING', 'SUBSCRIBED', 'UNSUBSCRIBED', 'SUPPRESSED')),
    CONSTRAINT ck_marketing_subscription_consent CHECK (subscription_state <> 'SUBSCRIBED' OR (consent_id IS NOT NULL AND consent_epoch IS NOT NULL AND subscribed_at IS NOT NULL))
);
COMMENT ON TABLE privacy.marketing_subscription IS 'REQ-PRIV-003/005：营销订阅独立状态，并绑定构成依据的 Consent epoch。';

CREATE TABLE privacy.privacy_request (
    id                    uuid        NOT NULL DEFAULT gen_random_uuid(),
    public_id             text        NOT NULL,
    user_id               uuid        NOT NULL,
    request_kind          text        NOT NULL,
    request_state         text        NOT NULL DEFAULT 'SUBMITTED',
    operation_id          uuid        NOT NULL,
    identity_verification_tx_id uuid  NULL,
    requested_scope       jsonb       NOT NULL,
    legal_deadline_at     timestamptz NOT NULL,
    blocked_reason_code   text        NULL,
    rejection_reason_code text        NULL,
    submitted_at          timestamptz NOT NULL DEFAULT clock_timestamp(),
    verified_at           timestamptz NULL,
    completed_at          timestamptz NULL,
    rejected_at           timestamptz NULL,
    updated_at            timestamptz NOT NULL DEFAULT clock_timestamp(),
    row_version           bigint      NOT NULL DEFAULT 1,
    CONSTRAINT pk_privacy_request PRIMARY KEY (id),
    CONSTRAINT uq_privacy_request_public_id UNIQUE (public_id),
    CONSTRAINT uq_privacy_request_operation UNIQUE (operation_id),
    CONSTRAINT fk_privacy_request_user FOREIGN KEY (user_id) REFERENCES iam.user_account(id),
    CONSTRAINT fk_privacy_request_operation FOREIGN KEY (operation_id) REFERENCES core.async_operation(id),
    CONSTRAINT fk_privacy_request_tx FOREIGN KEY (identity_verification_tx_id) REFERENCES authn.login_transaction(id),
    CONSTRAINT ck_privacy_request_kind CHECK (request_kind IN ('ACCESS', 'EXPORT', 'CORRECT', 'DELETE', 'RESTRICT', 'OBJECT_AUTOMATED_DECISION', 'WITHDRAW_CONSENT')),
    CONSTRAINT ck_privacy_request_state CHECK (request_state IN ('SUBMITTED', 'IDENTITY_VERIFIED', 'IN_PROGRESS', 'BLOCKED', 'PARTIAL', 'COMPLETED', 'REJECTED')),
    CONSTRAINT ck_privacy_request_blocked CHECK (request_state <> 'BLOCKED' OR blocked_reason_code IS NOT NULL),
    CONSTRAINT ck_privacy_request_completed CHECK ((request_state = 'COMPLETED') = (completed_at IS NOT NULL)),
    CONSTRAINT ck_privacy_request_rejected CHECK ((request_state = 'REJECTED') = (rejected_at IS NOT NULL)),
    CONSTRAINT ck_privacy_request_deadline CHECK (legal_deadline_at > submitted_at)
);
COMMENT ON TABLE privacy.privacy_request IS 'CAP-PRIV-008/012：访问、导出、更正、删除、限制处理等个人权利请求及法定期限。';

CREATE TABLE privacy.privacy_request_task (
    id                    uuid        NOT NULL DEFAULT gen_random_uuid(),
    privacy_request_id    uuid        NOT NULL,
    target_system_code    text        NOT NULL,
    task_kind             text        NOT NULL,
    task_state            text        NOT NULL DEFAULT 'PENDING',
    idempotency_key       text        NOT NULL,
    checkpoint            jsonb       NULL,
    legal_hold_id         uuid        NULL,
    attempt_count         integer     NOT NULL DEFAULT 0,
    next_attempt_at       timestamptz NULL,
    last_error_code       text        NULL,
    completion_evidence_hash bytea    NULL,
    completed_at          timestamptz NULL,
    updated_at            timestamptz NOT NULL DEFAULT clock_timestamp(),
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
    id                    uuid        NOT NULL DEFAULT gen_random_uuid(),
    public_id             text        NOT NULL,
    subject_kind          text        NOT NULL,
    subject_ref           text        NOT NULL,
    data_category_codes   text[]      NOT NULL,
    legal_basis           text        NOT NULL,
    case_reference        text        NOT NULL,
    approved_by_ref       text        NOT NULL,
    hold_state            text        NOT NULL DEFAULT 'ACTIVE',
    starts_at             timestamptz NOT NULL,
    expires_at            timestamptz NULL,
    released_at           timestamptz NULL,
    created_at            timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT pk_legal_hold PRIMARY KEY (id),
    CONSTRAINT uq_legal_hold_public_id UNIQUE (public_id),
    CONSTRAINT ck_legal_hold_state CHECK (hold_state IN ('ACTIVE', 'RELEASED', 'EXPIRED')),
    CONSTRAINT ck_legal_hold_categories CHECK (cardinality(data_category_codes) > 0),
    CONSTRAINT ck_legal_hold_window CHECK (expires_at IS NULL OR expires_at > starts_at),
    CONSTRAINT ck_legal_hold_released CHECK ((hold_state = 'RELEASED') = (released_at IS NOT NULL))
);
COMMENT ON TABLE privacy.legal_hold IS 'REQ-PRIV-008：法律保留的依据、范围、期限、审批人和解除证据。';

ALTER TABLE privacy.privacy_request_task
    ADD CONSTRAINT fk_privacy_request_task_hold FOREIGN KEY (legal_hold_id) REFERENCES privacy.legal_hold(id);

CREATE TABLE privacy.export_job (
    id                    uuid        NOT NULL DEFAULT gen_random_uuid(),
    privacy_request_id    uuid        NOT NULL,
    export_state          text        NOT NULL DEFAULT 'PENDING',
    classification_code   text        NOT NULL,
    encryption_key_ref    text        NOT NULL,
    object_uri            text        NULL,
    object_hash           bytea       NULL,
    download_token_hash   bytea       NULL,
    download_expires_at   timestamptz NULL,
    download_count        integer     NOT NULL DEFAULT 0,
    max_download_count    integer     NOT NULL DEFAULT 1,
    generated_at          timestamptz NULL,
    destroyed_at          timestamptz NULL,
    created_at            timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at            timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT pk_export_job PRIMARY KEY (id),
    CONSTRAINT uq_export_job_request UNIQUE (privacy_request_id),
    CONSTRAINT fk_export_job_request FOREIGN KEY (privacy_request_id) REFERENCES privacy.privacy_request(id),
    CONSTRAINT fk_export_job_class FOREIGN KEY (classification_code) REFERENCES core.data_classification(classification_code),
    CONSTRAINT ck_export_job_state CHECK (export_state IN ('PENDING', 'GENERATING', 'READY', 'DOWNLOADED', 'EXPIRED', 'DESTROYED', 'FAILED')),
    CONSTRAINT ck_export_job_hash CHECK (object_hash IS NULL OR octet_length(object_hash) = 32),
    CONSTRAINT ck_export_job_token CHECK (download_token_hash IS NULL OR octet_length(download_token_hash) = 32),
    CONSTRAINT ck_export_job_count CHECK (download_count >= 0 AND max_download_count BETWEEN 1 AND 5 AND download_count <= max_download_count),
    CONSTRAINT ck_export_job_ready CHECK (export_state <> 'READY' OR (object_uri IS NOT NULL AND object_hash IS NOT NULL AND download_token_hash IS NOT NULL AND download_expires_at IS NOT NULL)),
    CONSTRAINT ck_export_job_ttl CHECK (download_expires_at IS NULL OR generated_at IS NULL OR download_expires_at <= generated_at + interval '24 hours')
);
COMMENT ON TABLE privacy.export_job IS 'REQ-PRIV-006：强认证后的异步加密导出、短期单次下载和到期销毁。';

CREATE TABLE privacy.retention_rule (
    id                    uuid        NOT NULL DEFAULT gen_random_uuid(),
    rule_code             text        NOT NULL,
    rule_version          integer     NOT NULL,
    schema_name           text        NOT NULL,
    table_name            text        NOT NULL,
    category_code         text        NOT NULL,
    legal_basis           text        NOT NULL,
    retention_interval    interval    NOT NULL,
    disposition_kind      text        NOT NULL,
    key_destruction_required boolean  NOT NULL DEFAULT false,
    owner_ref             text        NOT NULL,
    approval_case_id      uuid        NULL,
    effective_at          timestamptz NOT NULL,
    retired_at            timestamptz NULL,
    CONSTRAINT pk_retention_rule PRIMARY KEY (id),
    CONSTRAINT uq_retention_rule_version UNIQUE (rule_code, rule_version),
    CONSTRAINT fk_retention_rule_category FOREIGN KEY (category_code) REFERENCES privacy.data_category(category_code),
    CONSTRAINT ck_retention_rule_interval CHECK (retention_interval > interval '0'),
    CONSTRAINT ck_retention_rule_disposition CHECK (disposition_kind IN ('DELETE', 'ANONYMIZE', 'ARCHIVE', 'CRYPTO_SHRED', 'REVIEW'))
);
COMMENT ON TABLE privacy.retention_rule IS 'CAP-PRIV-004/005：按数据对象与类别登记的版本化保留、匿名化和密码学销毁规则。';

CREATE TABLE privacy.deletion_proof (
    id                    uuid        NOT NULL DEFAULT gen_random_uuid(),
    privacy_request_id    uuid        NOT NULL,
    proof_version         integer     NOT NULL,
    subject_tombstone_ref text        NOT NULL,
    completed_systems     jsonb       NOT NULL,
    retained_items        jsonb       NOT NULL,
    backup_policy_evidence jsonb      NOT NULL,
    proof_hash            bytea       NOT NULL,
    signed_by_key_ref     text        NOT NULL,
    issued_at             timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT pk_deletion_proof PRIMARY KEY (id),
    CONSTRAINT uq_deletion_proof UNIQUE (privacy_request_id, proof_version),
    CONSTRAINT fk_deletion_proof_request FOREIGN KEY (privacy_request_id) REFERENCES privacy.privacy_request(id),
    CONSTRAINT ck_deletion_proof_hash CHECK (octet_length(proof_hash) = 32)
);
COMMENT ON TABLE privacy.deletion_proof IS 'REQ-PRIV-013：删除/匿名化完成证明，明确完成系统、依法保留项、期限、责任方和备份策略。';

CREATE TABLE privacy.cross_border_authorization (
    id                    uuid        NOT NULL DEFAULT gen_random_uuid(),
    public_id             text        NOT NULL,
    authorization_code    text        NOT NULL,
    authorization_state   text        NOT NULL DEFAULT 'DRAFT',
    source_region         text        NOT NULL,
    destination_region    text        NOT NULL,
    recipient_code        text        NOT NULL,
    purpose_code          text        NOT NULL,
    data_category_codes   text[]      NOT NULL,
    transfer_mechanism    text        NOT NULL,
    assessment_reference text        NOT NULL,
    route_policy          jsonb       NOT NULL,
    owner_ref             text        NOT NULL,
    approval_case_id      uuid        NOT NULL,
    valid_from            timestamptz NOT NULL,
    valid_until           timestamptz NOT NULL,
    revoked_at            timestamptz NULL,
    created_at            timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at            timestamptz NOT NULL DEFAULT clock_timestamp(),
    row_version           bigint      NOT NULL DEFAULT 1,
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
    id                    uuid        NOT NULL DEFAULT gen_random_uuid(),
    minor_user_id         uuid        NOT NULL,
    protection_state      text        NOT NULL DEFAULT 'AGE_UNKNOWN',
    age_band              text        NOT NULL DEFAULT 'UNKNOWN',
    age_assurance_method  text        NULL,
    age_evidence_hash     bytea       NULL,
    guardian_user_id      uuid        NULL,
    guardian_delegation_id uuid       NULL,
    guardian_consent_id   uuid        NULL,
    restriction_policy_code text      NOT NULL,
    verified_at           timestamptz NULL,
    expires_at            timestamptz NULL,
    created_at            timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at            timestamptz NOT NULL DEFAULT clock_timestamp(),
    row_version           bigint      NOT NULL DEFAULT 1,
    CONSTRAINT pk_minor_protection PRIMARY KEY (id),
    CONSTRAINT uq_minor_protection_user UNIQUE (minor_user_id),
    CONSTRAINT fk_minor_protection_user FOREIGN KEY (minor_user_id) REFERENCES iam.user_account(id),
    CONSTRAINT fk_minor_protection_guardian FOREIGN KEY (guardian_user_id) REFERENCES iam.user_account(id),
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
    id                    uuid        NOT NULL DEFAULT gen_random_uuid(),
    public_id             text        NOT NULL,
    assessment_code       text        NOT NULL,
    assessment_version    integer     NOT NULL,
    assessment_state      text        NOT NULL DEFAULT 'DRAFT',
    change_kind           text        NOT NULL,
    scope_definition      jsonb       NOT NULL,
    purpose_codes         text[]      NOT NULL,
    data_category_codes   text[]      NOT NULL,
    recipient_codes       text[]      NOT NULL DEFAULT '{}',
    risk_summary          jsonb       NOT NULL,
    mitigations           jsonb       NOT NULL,
    residual_risk_level   text        NOT NULL,
    owner_ref             text        NOT NULL,
    privacy_officer_ref   text        NOT NULL,
    approval_case_id      uuid        NOT NULL,
    approved_at           timestamptz NULL,
    expires_at            timestamptz NULL,
    created_at            timestamptz NOT NULL DEFAULT clock_timestamp(),
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

ALTER TABLE profile.notification_preference
    ADD CONSTRAINT fk_notification_preference_consent FOREIGN KEY (consent_id) REFERENCES privacy.consent(id);

CREATE TABLE federation.identity_provider (
    id                    uuid        NOT NULL DEFAULT gen_random_uuid(),
    public_id             text        NOT NULL,
    tenant_id             uuid        NOT NULL,
    provider_code         text        NOT NULL,
    protocol_kind         text        NOT NULL,
    provider_state        text        NOT NULL DEFAULT 'DRAFT',
    issuer_or_entity_id   text        NOT NULL,
    metadata_source_uri   text        NOT NULL,
    audience_values       text[]      NOT NULL,
    callback_uri          text        NOT NULL,
    allowed_algorithms    text[]      NOT NULL,
    owner_ref             text        NOT NULL,
    jit_enabled           boolean     NOT NULL DEFAULT false,
    max_clock_skew_seconds integer    NOT NULL DEFAULT 120,
    metadata_version      bigint      NOT NULL DEFAULT 1,
    approval_case_id      uuid        NULL,
    activated_at          timestamptz NULL,
    created_at            timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at            timestamptz NOT NULL DEFAULT clock_timestamp(),
    row_version           bigint      NOT NULL DEFAULT 1,
    CONSTRAINT pk_identity_provider PRIMARY KEY (id),
    CONSTRAINT uq_identity_provider_public_id UNIQUE (public_id),
    CONSTRAINT uq_identity_provider_issuer UNIQUE (tenant_id, protocol_kind, issuer_or_entity_id),
    CONSTRAINT fk_identity_provider_tenant FOREIGN KEY (tenant_id) REFERENCES org.tenant(id),
    CONSTRAINT ck_identity_provider_protocol CHECK (protocol_kind IN ('OIDC', 'SAML', 'SOCIAL', 'DIRECTORY')),
    CONSTRAINT ck_identity_provider_state CHECK (provider_state IN ('DRAFT', 'VALIDATED', 'APPROVED', 'ACTIVE', 'SUSPENDED', 'RETIRED', 'COMPROMISED')),
    CONSTRAINT ck_identity_provider_audience CHECK (cardinality(audience_values) > 0),
    CONSTRAINT ck_identity_provider_alg CHECK (cardinality(allowed_algorithms) > 0 AND NOT ('none' = ANY(allowed_algorithms))),
    CONSTRAINT ck_identity_provider_skew CHECK (max_clock_skew_seconds BETWEEN 0 AND 300)
);
COMMENT ON TABLE federation.identity_provider IS 'REQ-FED-001：租户联合 IdP 的 issuer/entityID、元数据、audience、回调、算法、Owner 与状态。';

CREATE TABLE federation.identity_provider_key (
    id                    uuid        NOT NULL DEFAULT gen_random_uuid(),
    identity_provider_id  uuid        NOT NULL,
    key_id                text        NOT NULL,
    key_kind              text        NOT NULL,
    algorithm             text        NOT NULL,
    public_material       jsonb       NOT NULL,
    certificate_thumbprint bytea      NULL,
    key_state             text        NOT NULL DEFAULT 'PUBLISHED',
    not_before            timestamptz NOT NULL,
    not_after             timestamptz NOT NULL,
    fetched_at            timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT pk_identity_provider_key PRIMARY KEY (id),
    CONSTRAINT uq_identity_provider_key UNIQUE (identity_provider_id, key_id, not_before),
    CONSTRAINT fk_identity_provider_key_provider FOREIGN KEY (identity_provider_id) REFERENCES federation.identity_provider(id),
    CONSTRAINT ck_identity_provider_key_kind CHECK (key_kind IN ('JWK', 'X509')),
    CONSTRAINT ck_identity_provider_key_state CHECK (key_state IN ('PUBLISHED', 'ACTIVE', 'VERIFY_ONLY', 'REVOKED', 'EXPIRED')),
    CONSTRAINT ck_identity_provider_key_window CHECK (not_after > not_before)
);
COMMENT ON TABLE federation.identity_provider_key IS 'REQ-FED-003：IdP JWKS/证书双版本轮换窗口；未知或弱算法密钥不得接受。';

CREATE TABLE federation.external_identity (
    id                    uuid        NOT NULL DEFAULT gen_random_uuid(),
    public_id             text        NOT NULL,
    identity_provider_id  uuid        NOT NULL,
    user_id               uuid        NOT NULL,
    protocol_kind         text        NOT NULL,
    canonical_subject_hash bytea      NOT NULL,
    canonical_subject_ciphertext bytea NOT NULL,
    oidc_subject_hash     bytea       NULL,
    saml_name_id_hash     bytea       NULL,
    saml_name_id_format   text        NULL,
    saml_name_qualifier_hash bytea    NULL,
    saml_sp_name_qualifier_hash bytea NULL,
    saml_sp_provided_id_hash bytea    NULL,
    saml_is_transient     boolean     NULL,
    directory_object_id_hash bytea    NULL,
    binding_state         text        NOT NULL DEFAULT 'PENDING',
    linked_at             timestamptz NULL,
    unlinked_at           timestamptz NULL,
    last_login_at         timestamptz NULL,
    created_at            timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at            timestamptz NOT NULL DEFAULT clock_timestamp(),
    row_version           bigint      NOT NULL DEFAULT 1,
    CONSTRAINT pk_external_identity PRIMARY KEY (id),
    CONSTRAINT uq_external_identity_public_id UNIQUE (public_id),
    CONSTRAINT uq_external_identity_subject UNIQUE (identity_provider_id, canonical_subject_hash),
    CONSTRAINT fk_external_identity_provider FOREIGN KEY (identity_provider_id) REFERENCES federation.identity_provider(id),
    CONSTRAINT fk_external_identity_user FOREIGN KEY (user_id) REFERENCES iam.user_account(id),
    CONSTRAINT ck_external_identity_protocol CHECK (protocol_kind IN ('OIDC', 'SAML', 'SOCIAL', 'DIRECTORY')),
    CONSTRAINT ck_external_identity_hash CHECK (octet_length(canonical_subject_hash) = 32),
    CONSTRAINT ck_external_identity_protocol_key CHECK (
        (protocol_kind IN ('OIDC', 'SOCIAL') AND oidc_subject_hash IS NOT NULL AND saml_name_id_hash IS NULL AND directory_object_id_hash IS NULL)
        OR (protocol_kind = 'SAML' AND saml_name_id_hash IS NOT NULL AND oidc_subject_hash IS NULL AND directory_object_id_hash IS NULL AND saml_is_transient = false)
        OR (protocol_kind = 'DIRECTORY' AND directory_object_id_hash IS NOT NULL AND oidc_subject_hash IS NULL AND saml_name_id_hash IS NULL)
    ),
    CONSTRAINT ck_external_identity_state CHECK (binding_state IN ('PENDING', 'LINKED', 'CONFLICT', 'UNLINKED', 'TOMBSTONED')),
    CONSTRAINT ck_external_identity_linked CHECK (binding_state <> 'LINKED' OR linked_at IS NOT NULL),
    CONSTRAINT ck_external_identity_unlinked CHECK (binding_state NOT IN ('UNLINKED', 'TOMBSTONED') OR unlinked_at IS NOT NULL)
);
COMMENT ON TABLE federation.external_identity IS 'INV-G-004 / REQ-FED-004：按 OIDC sub 或完整 SAML NameID 限定元组等协议稳定键绑定；Transient NameID 禁止永久绑定。';

CREATE TABLE federation.attribute_mapping (
    id                    uuid        NOT NULL DEFAULT gen_random_uuid(),
    identity_provider_id  uuid        NOT NULL,
    mapping_version       integer     NOT NULL,
    source_attribute      text        NOT NULL,
    target_namespace      text        NOT NULL,
    target_field_code     text        NOT NULL,
    transformation        jsonb       NOT NULL,
    value_schema          jsonb       NOT NULL,
    maximum_privilege_tier text       NOT NULL DEFAULT 'STANDARD',
    is_active             boolean     NOT NULL DEFAULT true,
    CONSTRAINT pk_attribute_mapping PRIMARY KEY (id),
    CONSTRAINT uq_attribute_mapping UNIQUE (identity_provider_id, mapping_version, source_attribute, target_namespace, target_field_code),
    CONSTRAINT fk_attribute_mapping_provider FOREIGN KEY (identity_provider_id) REFERENCES federation.identity_provider(id),
    CONSTRAINT ck_attribute_mapping_tier CHECK (maximum_privilege_tier IN ('NONE', 'STANDARD', 'ELEVATED'))
);
COMMENT ON TABLE federation.attribute_mapping IS 'REQ-FED-005：外部属性到 Profile/角色输入的版本化转换、类型校验和权限上限。';

CREATE TABLE federation.directory_connection (
    id                    uuid        NOT NULL DEFAULT gen_random_uuid(),
    public_id             text        NOT NULL,
    tenant_id             uuid        NOT NULL,
    identity_provider_id  uuid        NULL,
    directory_kind        text        NOT NULL,
    connection_state      text        NOT NULL DEFAULT 'DRAFT',
    base_uri              text        NOT NULL,
    credential_key_ref    text        NOT NULL,
    authority_mode        text        NOT NULL,
    supports_sortable_version boolean NOT NULL DEFAULT false,
    owner_ref             text        NOT NULL,
    created_at            timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at            timestamptz NOT NULL DEFAULT clock_timestamp(),
    row_version           bigint      NOT NULL DEFAULT 1,
    CONSTRAINT pk_directory_connection PRIMARY KEY (id),
    CONSTRAINT uq_directory_connection_public_id UNIQUE (public_id),
    CONSTRAINT fk_directory_connection_tenant FOREIGN KEY (tenant_id) REFERENCES org.tenant(id),
    CONSTRAINT fk_directory_connection_provider FOREIGN KEY (identity_provider_id) REFERENCES federation.identity_provider(id),
    CONSTRAINT ck_directory_connection_kind CHECK (directory_kind IN ('SCIM', 'LDAP_BRIDGE', 'HR_CONNECTOR')),
    CONSTRAINT ck_directory_connection_state CHECK (connection_state IN ('DRAFT', 'VALIDATED', 'ACTIVE', 'SUSPENDED', 'RETIRED')),
    CONSTRAINT ck_directory_connection_mode CHECK (authority_mode IN ('DIRECTORY_AUTHORITATIVE', 'PLATFORM_AUTHORITATIVE', 'FIELD_LEVEL'))
);
COMMENT ON TABLE federation.directory_connection IS 'CAP-FED-009/010：SCIM/目录连接、凭证引用、权威模式和源版本能力。';

CREATE TABLE federation.directory_object (
    id                    uuid        NOT NULL DEFAULT gen_random_uuid(),
    directory_connection_id uuid      NOT NULL,
    object_kind           text        NOT NULL,
    external_object_hash  bytea       NOT NULL,
    platform_object_kind  text        NULL,
    platform_object_id    uuid        NULL,
    source_etag           text        NULL,
    source_sortable_version bigint    NULL,
    source_modified_at    timestamptz NULL,
    sync_state            text        NOT NULL DEFAULT 'DISCOVERED',
    tombstone_version     bigint      NULL,
    payload_hash          bytea       NOT NULL,
    last_applied_at       timestamptz NULL,
    created_at            timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at            timestamptz NOT NULL DEFAULT clock_timestamp(),
    row_version           bigint      NOT NULL DEFAULT 1,
    CONSTRAINT pk_directory_object PRIMARY KEY (id),
    CONSTRAINT uq_directory_object UNIQUE (directory_connection_id, object_kind, external_object_hash),
    CONSTRAINT fk_directory_object_connection FOREIGN KEY (directory_connection_id) REFERENCES federation.directory_connection(id),
    CONSTRAINT ck_directory_object_kind CHECK (object_kind IN ('USER', 'GROUP', 'ORGANIZATION')),
    CONSTRAINT ck_directory_object_platform CHECK ((platform_object_kind IS NULL) = (platform_object_id IS NULL)),
    CONSTRAINT ck_directory_object_state CHECK (sync_state IN ('DISCOVERED', 'LINKED', 'APPLIED', 'CONFLICT', 'DISABLED', 'TOMBSTONED')),
    CONSTRAINT ck_directory_object_hash CHECK (octet_length(external_object_hash) = 32 AND octet_length(payload_hash) = 32),
    CONSTRAINT ck_directory_object_tombstone CHECK (sync_state <> 'TOMBSTONED' OR tombstone_version IS NOT NULL)
);
COMMENT ON TABLE federation.directory_object IS 'REQ-FED-006/007：目录对象映射、不透明 ETag、可选可排序源版本和优先级更高的停用墓碑。';

CREATE TABLE federation.directory_sync_run (
    id                    uuid        NOT NULL DEFAULT gen_random_uuid(),
    public_id             text        NOT NULL,
    directory_connection_id uuid      NOT NULL,
    operation_id          uuid        NOT NULL,
    sync_run_state        text        NOT NULL DEFAULT 'PENDING',
    source_cursor         text        NULL,
    next_cursor           text        NULL,
    discovered_count      bigint      NOT NULL DEFAULT 0,
    applied_count         bigint      NOT NULL DEFAULT 0,
    failed_count          bigint      NOT NULL DEFAULT 0,
    started_at            timestamptz NULL,
    completed_at          timestamptz NULL,
    created_at            timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT pk_directory_sync_run PRIMARY KEY (id),
    CONSTRAINT uq_directory_sync_run_public_id UNIQUE (public_id),
    CONSTRAINT uq_directory_sync_run_operation UNIQUE (operation_id),
    CONSTRAINT fk_directory_sync_run_connection FOREIGN KEY (directory_connection_id) REFERENCES federation.directory_connection(id),
    CONSTRAINT fk_directory_sync_run_operation FOREIGN KEY (operation_id) REFERENCES core.async_operation(id),
    CONSTRAINT ck_directory_sync_run_state CHECK (sync_run_state IN ('PENDING', 'RUNNING', 'PARTIAL', 'BLOCKED', 'COMPLETED', 'FAILED', 'CANCELLED')),
    CONSTRAINT ck_directory_sync_run_count CHECK (discovered_count >= 0 AND applied_count >= 0 AND failed_count >= 0 AND applied_count + failed_count <= discovered_count)
);
COMMENT ON TABLE federation.directory_sync_run IS 'REQ-FED-008：SCIM/目录分页、幂等、部分失败、限流与游标同步 Operation。';

CREATE TABLE federation.assertion_replay (
    replay_key_hash       bytea       NOT NULL,
    protocol_kind         text        NOT NULL,
    identity_provider_id  uuid        NOT NULL,
    audience_hash         bytea       NOT NULL,
    environment           text        NOT NULL,
    first_seen_at         timestamptz NOT NULL DEFAULT clock_timestamp(),
    expires_at            timestamptz NOT NULL,
    CONSTRAINT pk_assertion_replay PRIMARY KEY (replay_key_hash),
    CONSTRAINT fk_assertion_replay_provider FOREIGN KEY (identity_provider_id) REFERENCES federation.identity_provider(id),
    CONSTRAINT ck_assertion_replay_protocol CHECK (protocol_kind IN ('OIDC_NONCE', 'SAML_ASSERTION', 'CLIENT_ASSERTION', 'WORKLOAD_ATTESTATION')),
    CONSTRAINT ck_assertion_replay_hash CHECK (octet_length(replay_key_hash) = 32 AND octet_length(audience_hash) = 32),
    CONSTRAINT ck_assertion_replay_expiry CHECK (expires_at > first_seen_at)
);
COMMENT ON TABLE federation.assertion_replay IS 'REQ-FED-002 / REQ-MACHINE-016：nonce、Assertion ID、jti 的协议/Client/环境/audience 绑定防重放窗口。';

CREATE TABLE federation.federation_migration (
    id                    uuid        NOT NULL DEFAULT gen_random_uuid(),
    tenant_id             uuid        NOT NULL,
    source_provider_id    uuid        NOT NULL,
    target_provider_id    uuid        NOT NULL,
    operation_id          uuid        NOT NULL,
    migration_state       text        NOT NULL DEFAULT 'DISCOVERED',
    dual_run_started_at   timestamptz NULL,
    cutover_at            timestamptz NULL,
    rollback_deadline_at  timestamptz NULL,
    completed_at          timestamptz NULL,
    created_at            timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at            timestamptz NOT NULL DEFAULT clock_timestamp(),
    row_version           bigint      NOT NULL DEFAULT 1,
    CONSTRAINT pk_federation_migration PRIMARY KEY (id),
    CONSTRAINT uq_federation_migration_operation UNIQUE (operation_id),
    CONSTRAINT fk_federation_migration_tenant FOREIGN KEY (tenant_id) REFERENCES org.tenant(id),
    CONSTRAINT fk_federation_migration_source FOREIGN KEY (source_provider_id) REFERENCES federation.identity_provider(id),
    CONSTRAINT fk_federation_migration_target FOREIGN KEY (target_provider_id) REFERENCES federation.identity_provider(id),
    CONSTRAINT fk_federation_migration_operation FOREIGN KEY (operation_id) REFERENCES core.async_operation(id),
    CONSTRAINT ck_federation_migration_provider CHECK (source_provider_id <> target_provider_id),
    CONSTRAINT ck_federation_migration_state CHECK (migration_state IN ('DISCOVERED', 'SHADOW', 'DUAL_RUN', 'CANARY', 'CUTOVER', 'OBSERVING', 'COMPLETE', 'PAUSED', 'ROLLED_BACK'))
);
COMMENT ON TABLE federation.federation_migration IS 'CAP-FED-012/013：身份源双跑、逐用户审计、切换、回滚截止点与完成状态。';

CREATE UNIQUE INDEX ux_consent_effective ON privacy.consent(aggregate_id) WHERE consent_state IN ('PENDING', 'GRANTED');
CREATE INDEX ix_consent_expiry ON privacy.consent(expires_at) WHERE consent_state IN ('PENDING', 'GRANTED');
CREATE INDEX ix_privacy_request_user ON privacy.privacy_request(user_id, request_state, submitted_at DESC);
CREATE INDEX ix_privacy_task_retry ON privacy.privacy_request_task(next_attempt_at) WHERE task_state IN ('PENDING', 'FAILED');
CREATE INDEX ix_legal_hold_subject ON privacy.legal_hold(subject_kind, subject_ref) WHERE hold_state = 'ACTIVE';
CREATE INDEX ix_external_identity_user ON federation.external_identity(user_id, binding_state);
CREATE INDEX ix_directory_object_apply ON federation.directory_object(directory_connection_id, sync_state, source_sortable_version);
CREATE INDEX ix_cross_border_expiry ON privacy.cross_border_authorization(valid_until) WHERE authorization_state = 'ACTIVE';
CREATE INDEX ix_pia_expiry ON privacy.privacy_impact_assessment(expires_at) WHERE assessment_state = 'APPROVED';

CREATE OR REPLACE FUNCTION privacy.fn_consent_epoch_guard()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE v_epoch bigint;
BEGIN
    IF TG_OP = 'UPDATE' THEN
        IF OLD.consent_state IN ('DENIED', 'WITHDRAWN', 'EXPIRED', 'SUPERSEDED') AND NEW.consent_state <> OLD.consent_state THEN
            RAISE EXCEPTION 'INVALID_STATE_TRANSITION: Consent 终态不得离开' USING ERRCODE = '23514';
        END IF;
        IF NEW.aggregate_id <> OLD.aggregate_id OR NEW.consent_context_hash <> OLD.consent_context_hash
           OR NEW.purpose_code <> OLD.purpose_code OR NEW.purpose_version <> OLD.purpose_version
           OR NEW.data_category_codes <> OLD.data_category_codes OR NEW.recipient_code <> OLD.recipient_code THEN
            RAISE EXCEPTION 'CONSENT_CONTEXT_IMMUTABLE' USING ERRCODE = '23514';
        END IF;
        IF NEW.consent_state = OLD.consent_state THEN
            NEW.consent_epoch := OLD.consent_epoch;
            RETURN NEW;
        END IF;
    END IF;
    UPDATE privacy.consent_aggregate
       SET current_epoch = current_epoch + 1,
           updated_at = clock_timestamp(),
           row_version = row_version + 1
     WHERE id = NEW.aggregate_id
     RETURNING current_epoch INTO v_epoch;
    IF NOT FOUND THEN RAISE EXCEPTION 'CONSENT_AGGREGATE_NOT_FOUND' USING ERRCODE = '23503'; END IF;
    NEW.consent_epoch := v_epoch;
    RETURN NEW;
END;
$$;
COMMENT ON FUNCTION privacy.fn_consent_epoch_guard() IS 'REQ-PRIV-012：Consent 创建、授予、拒绝、撤回、到期或取代时原子推进聚合 epoch。';

CREATE OR REPLACE FUNCTION privacy.fn_subscription_guard()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.subscription_state = 'SUBSCRIBED' AND NOT EXISTS (
        SELECT 1 FROM privacy.consent c
         WHERE c.id = NEW.consent_id AND c.consent_state = 'GRANTED' AND c.consent_epoch = NEW.consent_epoch
    ) THEN
        RAISE EXCEPTION 'CONSENT_NOT_EFFECTIVE' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;
COMMENT ON FUNCTION privacy.fn_subscription_guard() IS '订阅启用必须绑定当前有效 GRANTED Consent epoch。';

CREATE OR REPLACE FUNCTION privacy.fn_notification_preference_guard()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.notification_category = 'SECURITY' AND NEW.preference_state <> 'ENABLED' THEN
        RAISE EXCEPTION 'SECURITY_NOTIFICATION_MANDATORY' USING ERRCODE = '23514';
    END IF;
    IF NEW.notification_category = 'MARKETING' AND NEW.preference_state = 'ENABLED' AND NOT EXISTS (
        SELECT 1 FROM privacy.consent c
         WHERE c.id = NEW.consent_id AND c.consent_state = 'GRANTED' AND c.consent_epoch = NEW.consent_epoch
    ) THEN
        RAISE EXCEPTION 'MARKETING_CONSENT_NOT_EFFECTIVE' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;
COMMENT ON FUNCTION privacy.fn_notification_preference_guard() IS '安全通知不可关闭；营销通知启用必须绑定有效 GRANTED Consent epoch。';

CREATE OR REPLACE FUNCTION oauth.fn_grant_activation_guard()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE v_state text;
BEGIN
    IF NEW.grant_state = 'ACTIVE' THEN
        IF TG_OP = 'UPDATE' AND OLD.grant_state = 'ACTIVE' THEN RETURN NEW; END IF;
        IF NEW.subject_kind = 'USER' THEN
            SELECT login_transaction_state INTO v_state FROM authn.login_transaction WHERE id = NEW.login_transaction_id;
            IF v_state IS DISTINCT FROM 'COMPLETED' THEN
                RAISE EXCEPTION 'REQ-SESSION-018: 用户 Grant 只能由 COMPLETED Login Transaction 激活' USING ERRCODE = '23514';
            END IF;
        END IF;
        IF NEW.consent_required AND NOT EXISTS (
            SELECT 1 FROM privacy.consent c
             WHERE c.id = NEW.consent_id
               AND c.consent_state = 'GRANTED'
               AND c.consent_context_hash = NEW.consent_context_hash
               AND c.consent_epoch = NEW.consent_epoch_at_grant
        ) THEN
            RAISE EXCEPTION 'REQ-SESSION-018: Grant 所需 Consent 未授予、上下文不匹配或 epoch 过期' USING ERRCODE = '23514';
        END IF;
    END IF;
    RETURN NEW;
END;
$$;
COMMENT ON FUNCTION oauth.fn_grant_activation_guard() IS 'REQ-SESSION-018：Grant 激活校验完成的 Login Transaction 及精确匹配的 GRANTED Consent epoch。';

ALTER TABLE oauth.authorization_grant ADD CONSTRAINT fk_authorization_grant_consent FOREIGN KEY (consent_id) REFERENCES privacy.consent(id);
ALTER TABLE oauth.reference_access_token ADD CONSTRAINT fk_reference_access_token_consent FOREIGN KEY (consent_id) REFERENCES privacy.consent(id);

CREATE TRIGGER trg_consent_aggregate_public_id BEFORE INSERT ON privacy.consent_aggregate FOR EACH ROW EXECUTE FUNCTION core.fn_register_public_id('CONSENT_AGGREGATE');
CREATE TRIGGER trg_consent_aggregate_touch BEFORE UPDATE ON privacy.consent_aggregate FOR EACH ROW EXECUTE FUNCTION core.fn_touch_updated_at();
CREATE TRIGGER trg_consent_aggregate_version BEFORE UPDATE ON privacy.consent_aggregate FOR EACH ROW EXECUTE FUNCTION core.fn_increment_row_version();
CREATE TRIGGER trg_consent_public_id BEFORE INSERT ON privacy.consent FOR EACH ROW EXECUTE FUNCTION core.fn_register_public_id('CONSENT');
CREATE TRIGGER trg_consent_epoch BEFORE INSERT OR UPDATE ON privacy.consent FOR EACH ROW EXECUTE FUNCTION privacy.fn_consent_epoch_guard();
CREATE TRIGGER trg_consent_touch BEFORE UPDATE ON privacy.consent FOR EACH ROW EXECUTE FUNCTION core.fn_touch_updated_at();
CREATE TRIGGER trg_consent_version BEFORE UPDATE ON privacy.consent FOR EACH ROW EXECUTE FUNCTION core.fn_increment_row_version();
CREATE TRIGGER trg_subscription_guard BEFORE INSERT OR UPDATE ON privacy.marketing_subscription FOR EACH ROW EXECUTE FUNCTION privacy.fn_subscription_guard();
CREATE TRIGGER trg_subscription_touch BEFORE UPDATE ON privacy.marketing_subscription FOR EACH ROW EXECUTE FUNCTION core.fn_touch_updated_at();
CREATE TRIGGER trg_subscription_version BEFORE UPDATE ON privacy.marketing_subscription FOR EACH ROW EXECUTE FUNCTION core.fn_increment_row_version();
CREATE TRIGGER trg_notification_preference_privacy BEFORE INSERT OR UPDATE ON profile.notification_preference FOR EACH ROW EXECUTE FUNCTION privacy.fn_notification_preference_guard();
CREATE TRIGGER trg_privacy_request_public_id BEFORE INSERT ON privacy.privacy_request FOR EACH ROW EXECUTE FUNCTION core.fn_register_public_id('PRIVACY_REQUEST');
CREATE TRIGGER trg_privacy_request_touch BEFORE UPDATE ON privacy.privacy_request FOR EACH ROW EXECUTE FUNCTION core.fn_touch_updated_at();
CREATE TRIGGER trg_privacy_request_version BEFORE UPDATE ON privacy.privacy_request FOR EACH ROW EXECUTE FUNCTION core.fn_increment_row_version();
CREATE TRIGGER trg_privacy_request_terminal BEFORE UPDATE ON privacy.privacy_request FOR EACH ROW EXECUTE FUNCTION core.fn_terminal_state_guard('request_state', 'COMPLETED', 'REJECTED');
CREATE TRIGGER trg_privacy_task_touch BEFORE UPDATE ON privacy.privacy_request_task FOR EACH ROW EXECUTE FUNCTION core.fn_touch_updated_at();
CREATE TRIGGER trg_legal_hold_public_id BEFORE INSERT ON privacy.legal_hold FOR EACH ROW EXECUTE FUNCTION core.fn_register_public_id('LEGAL_HOLD');
CREATE TRIGGER trg_legal_hold_terminal BEFORE UPDATE ON privacy.legal_hold FOR EACH ROW EXECUTE FUNCTION core.fn_terminal_state_guard('hold_state', 'RELEASED', 'EXPIRED');
CREATE TRIGGER trg_export_job_touch BEFORE UPDATE ON privacy.export_job FOR EACH ROW EXECUTE FUNCTION core.fn_touch_updated_at();
CREATE TRIGGER trg_deletion_proof_append_only BEFORE UPDATE OR DELETE ON privacy.deletion_proof FOR EACH STATEMENT EXECUTE FUNCTION core.fn_append_only();
CREATE TRIGGER trg_cross_border_public_id BEFORE INSERT ON privacy.cross_border_authorization FOR EACH ROW EXECUTE FUNCTION core.fn_register_public_id('CROSS_BORDER_AUTHORIZATION');
CREATE TRIGGER trg_cross_border_touch BEFORE UPDATE ON privacy.cross_border_authorization FOR EACH ROW EXECUTE FUNCTION core.fn_touch_updated_at();
CREATE TRIGGER trg_cross_border_version BEFORE UPDATE ON privacy.cross_border_authorization FOR EACH ROW EXECUTE FUNCTION core.fn_increment_row_version();
CREATE TRIGGER trg_minor_protection_touch BEFORE UPDATE ON privacy.minor_protection FOR EACH ROW EXECUTE FUNCTION core.fn_touch_updated_at();
CREATE TRIGGER trg_minor_protection_version BEFORE UPDATE ON privacy.minor_protection FOR EACH ROW EXECUTE FUNCTION core.fn_increment_row_version();
CREATE TRIGGER trg_pia_public_id BEFORE INSERT ON privacy.privacy_impact_assessment FOR EACH ROW EXECUTE FUNCTION core.fn_register_public_id('PRIVACY_IMPACT_ASSESSMENT');
CREATE TRIGGER trg_identity_provider_public_id BEFORE INSERT ON federation.identity_provider FOR EACH ROW EXECUTE FUNCTION core.fn_register_public_id('IDENTITY_PROVIDER');
CREATE TRIGGER trg_identity_provider_touch BEFORE UPDATE ON federation.identity_provider FOR EACH ROW EXECUTE FUNCTION core.fn_touch_updated_at();
CREATE TRIGGER trg_identity_provider_version BEFORE UPDATE ON federation.identity_provider FOR EACH ROW EXECUTE FUNCTION core.fn_increment_row_version();
CREATE TRIGGER trg_external_identity_public_id BEFORE INSERT ON federation.external_identity FOR EACH ROW EXECUTE FUNCTION core.fn_register_public_id('EXTERNAL_IDENTITY');
CREATE TRIGGER trg_external_identity_touch BEFORE UPDATE ON federation.external_identity FOR EACH ROW EXECUTE FUNCTION core.fn_touch_updated_at();
CREATE TRIGGER trg_external_identity_version BEFORE UPDATE ON federation.external_identity FOR EACH ROW EXECUTE FUNCTION core.fn_increment_row_version();
CREATE TRIGGER trg_directory_connection_public_id BEFORE INSERT ON federation.directory_connection FOR EACH ROW EXECUTE FUNCTION core.fn_register_public_id('DIRECTORY_CONNECTION');
CREATE TRIGGER trg_directory_connection_touch BEFORE UPDATE ON federation.directory_connection FOR EACH ROW EXECUTE FUNCTION core.fn_touch_updated_at();
CREATE TRIGGER trg_directory_connection_version BEFORE UPDATE ON federation.directory_connection FOR EACH ROW EXECUTE FUNCTION core.fn_increment_row_version();
CREATE TRIGGER trg_directory_object_touch BEFORE UPDATE ON federation.directory_object FOR EACH ROW EXECUTE FUNCTION core.fn_touch_updated_at();
CREATE TRIGGER trg_directory_object_version BEFORE UPDATE ON federation.directory_object FOR EACH ROW EXECUTE FUNCTION core.fn_increment_row_version();
CREATE TRIGGER trg_directory_sync_public_id BEFORE INSERT ON federation.directory_sync_run FOR EACH ROW EXECUTE FUNCTION core.fn_register_public_id('DIRECTORY_SYNC_RUN');
CREATE TRIGGER trg_assertion_replay_append_only BEFORE UPDATE OR DELETE ON federation.assertion_replay FOR EACH STATEMENT EXECUTE FUNCTION core.fn_append_only();
CREATE TRIGGER trg_federation_migration_touch BEFORE UPDATE ON federation.federation_migration FOR EACH ROW EXECUTE FUNCTION core.fn_touch_updated_at();
CREATE TRIGGER trg_federation_migration_version BEFORE UPDATE ON federation.federation_migration FOR EACH ROW EXECUTE FUNCTION core.fn_increment_row_version();

SELECT core.fn_register_migration('040', 'Consent、隐私请求、保留导出、OIDC/SAML/SCIM 联合与目录同步', NULLIF(current_setting('kuc.migration_sha256', true), ''));
COMMIT;
