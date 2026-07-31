-- =============================================================================
-- 100_privacy.sql
-- PRIV 域：数据目录、协议、Consent、用途映射、营销订阅、隐私请求、法律保留、导出任务
-- 依据：能力地图 §4.9、§5.10；蓝图 §11（REQ-PRIV-001 至 011）、§16 隐私编排
-- 关键：Consent、协议接受、营销订阅、OAuth Grant 分别建模，不得一次勾选代替全部依据
-- =============================================================================

SET client_min_messages = warning;

-- -----------------------------------------------------------------------------
-- 1. 数据目录（CAP-PRIV-004：字段用途、合法依据、来源、接收方、地域、保留期）
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS priv.data_catalog_field (
    field_code          text        NOT NULL,
    namespace           text        NOT NULL DEFAULT 'platform',
    purpose_codes       text[]      NOT NULL,
    legal_basis         text        NOT NULL,
    source_kind         text        NOT NULL,
    recipient_codes     text[]      NOT NULL DEFAULT '{}',
    region_scope        text[]      NOT NULL DEFAULT '{}',
    retention_period    interval    NULL,
    retention_rule      text        NULL,
    data_classification text        NOT NULL,
    requires_separate_consent boolean NOT NULL DEFAULT false,
    pia_ref             text        NULL,
    created_at          timestamptz NOT NULL DEFAULT now(),
    updated_at          timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT pk_data_catalog_field PRIMARY KEY (namespace, field_code),
    CONSTRAINT fk_data_catalog_field_classification FOREIGN KEY (data_classification) REFERENCES core.data_classification (classification_code),
    CONSTRAINT ck_data_catalog_field_basis CHECK (legal_basis IN (
        'CONSENT', 'SEPARATE_CONSENT', 'CONTRACT', 'LEGAL_OBLIGATION', 'VITAL_INTEREST', 'PUBLIC_INTEREST', 'LEGITIMATE_INTEREST'
    )),
    CONSTRAINT ck_data_catalog_field_source CHECK (source_kind IN ('USER', 'ADMIN', 'DERIVED', 'IDENTITY_PROVIDER', 'THIRD_PARTY', 'DEVICE')),
    -- 能力地图 §15.1：敏感个人信息与生物特征需要单独同意，不能并入注册协议
    CONSTRAINT ck_data_catalog_field_strict_consent CHECK (
        data_classification <> 'STRICT_SENSITIVE' OR requires_separate_consent
    ),
    -- 必须给出保留期或明确的保留规则，二者不得同时为空（CAP-PRIV-010）
    CONSTRAINT ck_data_catalog_field_retention CHECK (retention_period IS NOT NULL OR retention_rule IS NOT NULL)
);
COMMENT ON TABLE priv.data_catalog_field IS 'CAP-PRIV-004 数据目录；风控特征与新增用途上线前必须先在此登记并完成 CAP-PRIV-017 评估';

CREATE OR REPLACE TRIGGER trg_data_catalog_field_touch
    BEFORE UPDATE ON priv.data_catalog_field
    FOR EACH ROW EXECUTE FUNCTION core.fn_touch_updated_at();

-- 用途到 scope / claim / 订阅 / 下游副本的映射（REQ-PRIV-005）
CREATE TABLE IF NOT EXISTS priv.purpose_mapping (
    purpose_code       text        NOT NULL,
    display_name       text        NOT NULL,
    data_categories    text[]      NOT NULL,
    recipient_codes    text[]      NOT NULL DEFAULT '{}',
    scope_codes        text[]      NOT NULL DEFAULT '{}',
    claim_codes        text[]      NOT NULL DEFAULT '{}',
    subscription_codes text[]      NOT NULL DEFAULT '{}',
    downstream_systems text[]      NOT NULL DEFAULT '{}',
    is_high_risk       boolean     NOT NULL DEFAULT false,
    created_at         timestamptz NOT NULL DEFAULT now(),
    updated_at         timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT pk_purpose_mapping PRIMARY KEY (purpose_code),
    CONSTRAINT ck_purpose_mapping_code CHECK (purpose_code ~ '^[a-z][a-z0-9_.]{2,63}$')
);
COMMENT ON TABLE priv.purpose_mapping IS 'REQ-PRIV-005：purpose + data categories + recipient 到 scope/claim/Grant/订阅/下游副本的可审计映射；撤回按本表精确传播，不得误撤销无关授权';

-- -----------------------------------------------------------------------------
-- 2. 协议与接受记录（CAP-PRIV-001）
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS priv.agreement (
    agreement_code text        NOT NULL,
    version        text        NOT NULL,
    region_scope   text[]      NOT NULL DEFAULT '{}',
    title          text        NOT NULL,
    content_hash   bytea       NOT NULL,
    content_uri    text        NOT NULL,
    effective_from timestamptz NOT NULL,
    effective_to   timestamptz NULL,
    requires_reacceptance boolean NOT NULL DEFAULT false,
    created_at     timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT pk_agreement PRIMARY KEY (agreement_code, version),
    CONSTRAINT ck_agreement_hash CHECK (octet_length(content_hash) = 32),
    CONSTRAINT ck_agreement_window CHECK (effective_to IS NULL OR effective_to > effective_from)
);
COMMENT ON TABLE priv.agreement IS 'CAP-PRIV-001：协议版本、适用地区与内容哈希；接受证据必须能对应到确切版本';

CREATE TABLE IF NOT EXISTS priv.agreement_acceptance (
    id             uuid        NOT NULL DEFAULT core.uuid_generate_v7(),
    user_id        uuid        NOT NULL,
    agreement_code text        NOT NULL,
    version        text        NOT NULL,
    accepted_at    timestamptz NOT NULL DEFAULT now(),
    source_kind    text        NOT NULL,
    client_id      uuid        NULL,
    ip_hash        bytea       NULL,
    evidence       jsonb       NULL,
    CONSTRAINT pk_agreement_acceptance PRIMARY KEY (id),
    CONSTRAINT uq_agreement_acceptance UNIQUE (user_id, agreement_code, version),
    CONSTRAINT fk_agreement_acceptance_user FOREIGN KEY (user_id) REFERENCES id.global_user (id) ON DELETE CASCADE,
    CONSTRAINT fk_agreement_acceptance_agreement FOREIGN KEY (agreement_code, version) REFERENCES priv.agreement (agreement_code, version),
    CONSTRAINT ck_agreement_acceptance_source CHECK (source_kind IN ('REGISTRATION', 'RE_CONSENT', 'SELF_SERVICE', 'MIGRATION'))
);
COMMENT ON TABLE priv.agreement_acceptance IS 'CAP-PRIV-001 接受证据（追加型）；协议接受不等于隐私同意，见 priv.consent';

CREATE OR REPLACE TRIGGER trg_agreement_acceptance_append_only
    BEFORE UPDATE OR DELETE ON priv.agreement_acceptance
    FOR EACH STATEMENT EXECUTE FUNCTION core.fn_append_only();

-- -----------------------------------------------------------------------------
-- 3. 隐私同意（CAP-PRIV-002、REQ-PRIV-003/004、蓝图 §11.1）
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS priv.consent (
    id                 uuid        NOT NULL DEFAULT core.uuid_generate_v7(),
    user_id            uuid        NOT NULL,
    purpose_code       text        NOT NULL,
    consent_state      text        NOT NULL DEFAULT 'PENDING',
    consent_version    text        NOT NULL,
    data_categories    text[]      NOT NULL,
    recipient_codes    text[]      NOT NULL DEFAULT '{}',
    scope_ref_kind     text        NOT NULL DEFAULT 'PLATFORM',
    scope_ref_id       uuid        NOT NULL DEFAULT '00000000-0000-0000-0000-000000000000',
    is_separate_consent boolean    NOT NULL DEFAULT false,
    consent_epoch      bigint      NOT NULL DEFAULT 1,
    granted_at         timestamptz NULL,
    expires_at         timestamptz NULL,
    withdrawn_at       timestamptz NULL,
    withdrawal_source  text        NULL,
    superseded_by_id   uuid        NULL,
    source_kind        text        NOT NULL,
    client_id          uuid        NULL,
    evidence           jsonb       NULL,
    created_at         timestamptz NOT NULL DEFAULT now(),
    updated_at         timestamptz NOT NULL DEFAULT now(),
    row_version        bigint      NOT NULL DEFAULT 1,
    CONSTRAINT pk_consent PRIMARY KEY (id),
    CONSTRAINT fk_consent_user FOREIGN KEY (user_id) REFERENCES id.global_user (id) ON DELETE CASCADE,
    CONSTRAINT fk_consent_purpose FOREIGN KEY (purpose_code) REFERENCES priv.purpose_mapping (purpose_code),
    CONSTRAINT fk_consent_superseded FOREIGN KEY (superseded_by_id) REFERENCES priv.consent (id),
    CONSTRAINT ck_consent_state CHECK (consent_state IN ('PENDING', 'GRANTED', 'WITHDRAWN', 'EXPIRED', 'SUPERSEDED')),
    CONSTRAINT ck_consent_scope_kind CHECK (scope_ref_kind IN ('PLATFORM', 'BUSINESS_LINE', 'TENANT', 'CLIENT')),
    CONSTRAINT ck_consent_source CHECK (source_kind IN ('REGISTRATION', 'AUTHORIZATION_FLOW', 'SELF_SERVICE', 'ADMIN', 'MIGRATION')),
    CONSTRAINT ck_consent_granted CHECK ((consent_state = 'GRANTED') = (granted_at IS NOT NULL AND withdrawn_at IS NULL)),
    CONSTRAINT ck_consent_withdrawn CHECK ((consent_state = 'WITHDRAWN') = (withdrawn_at IS NOT NULL)),
    CONSTRAINT ck_consent_epoch CHECK (consent_epoch >= 1)
);
COMMENT ON TABLE priv.consent IS 'CAP-PRIV-002 / REQ-PRIV-004：记录用途、数据项、接收方、版本、来源与撤回；consent_epoch 供 REQ-PRIV-011 判定存量 Token 是否失效';
COMMENT ON COLUMN priv.consent.consent_epoch IS 'REQ-PRIV-011：撤回后递增，资源服务器据此拒绝包含受影响 scope/claim 的存量 Token（AT-PRIV-007）';

CREATE OR REPLACE TRIGGER trg_consent_touch
    BEFORE UPDATE ON priv.consent
    FOR EACH ROW EXECUTE FUNCTION core.fn_touch_updated_at();
CREATE OR REPLACE TRIGGER trg_consent_epoch
    BEFORE UPDATE ON priv.consent
    FOR EACH ROW EXECUTE FUNCTION core.fn_forbid_epoch_decrease('consent_epoch');

CREATE UNIQUE INDEX IF NOT EXISTS ux_consent_active
    ON priv.consent (user_id, purpose_code, scope_ref_kind, scope_ref_id)
    WHERE consent_state IN ('PENDING', 'GRANTED');

CREATE INDEX IF NOT EXISTS ix_consent_user ON priv.consent (user_id, consent_state);
CREATE INDEX IF NOT EXISTS ix_consent_expiry ON priv.consent (expires_at) WHERE consent_state = 'GRANTED' AND expires_at IS NOT NULL;

-- 营销订阅独立建模（CAP-PROFILE-010、REQ-PRIV-003）
CREATE TABLE IF NOT EXISTS priv.marketing_subscription (
    user_id           uuid        NOT NULL,
    subscription_code text        NOT NULL,
    channel           text        NOT NULL,
    is_subscribed     boolean     NOT NULL DEFAULT false,
    subscribed_at     timestamptz NULL,
    unsubscribed_at   timestamptz NULL,
    source_kind       text        NOT NULL,
    updated_at        timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT pk_marketing_subscription PRIMARY KEY (user_id, subscription_code, channel),
    CONSTRAINT fk_marketing_subscription_user FOREIGN KEY (user_id) REFERENCES id.global_user (id) ON DELETE CASCADE,
    CONSTRAINT ck_marketing_subscription_channel CHECK (channel IN ('SMS', 'EMAIL', 'PUSH', 'IN_APP')),
    CONSTRAINT ck_marketing_subscription_state CHECK (
        (is_subscribed AND subscribed_at IS NOT NULL) OR (NOT is_subscribed)
    )
);
COMMENT ON TABLE priv.marketing_subscription IS 'REQ-PRIV-003：营销订阅与 Consent、协议接受、OAuth Grant 分别建模，撤回互不代替';

-- -----------------------------------------------------------------------------
-- 4. 个人权利请求（CAP-PRIV-007、蓝图 §11.1、SLO-PRIV-001）
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS priv.privacy_request (
    id                    uuid        NOT NULL DEFAULT core.uuid_generate_v7(),
    public_id             text        NOT NULL,
    user_id               uuid        NULL,
    requester_ref         text        NOT NULL,
    requester_kind        text        NOT NULL,
    request_type          text        NOT NULL,
    request_state         text        NOT NULL DEFAULT 'SUBMITTED',
    submitted_at          timestamptz NOT NULL DEFAULT now(),
    identity_verified_at  timestamptz NULL,
    verification_method   text        NULL,
    first_response_due_at timestamptz NOT NULL,
    completion_due_at     timestamptz NOT NULL,
    first_responded_at    timestamptz NULL,
    completed_at          timestamptz NULL,
    blocked_reason_code   text        NULL,
    blocked_owner         text        NULL,
    rejection_reason_code text        NULL,
    operation_id          uuid        NULL,
    response_artifact_ref text        NULL,
    created_at            timestamptz NOT NULL DEFAULT now(),
    updated_at            timestamptz NOT NULL DEFAULT now(),
    row_version           bigint      NOT NULL DEFAULT 1,
    CONSTRAINT pk_privacy_request PRIMARY KEY (id),
    CONSTRAINT uq_privacy_request_public_id UNIQUE (public_id),
    CONSTRAINT fk_privacy_request_user FOREIGN KEY (user_id) REFERENCES id.global_user (id),
    CONSTRAINT fk_privacy_request_operation FOREIGN KEY (operation_id) REFERENCES core.async_operation (id),
    CONSTRAINT ck_privacy_request_type CHECK (request_type IN (
        'ACCESS', 'RECTIFICATION', 'EXPORT', 'RESTRICTION', 'DELETION', 'OBJECTION', 'CONSENT_WITHDRAWAL', 'AUTOMATED_DECISION_EXPLANATION'
    )),
    CONSTRAINT ck_privacy_request_state CHECK (request_state IN (
        'SUBMITTED', 'IDENTITY_VERIFIED', 'IN_PROGRESS', 'BLOCKED', 'PARTIAL', 'COMPLETED', 'REJECTED'
    )),
    CONSTRAINT ck_privacy_request_requester CHECK (requester_kind IN ('DATA_SUBJECT', 'AUTHORIZED_AGENT', 'GUARDIAN', 'REGULATOR')),
    -- REQ-PRIV-008：受理必须先核验请求人身份
    CONSTRAINT ck_privacy_request_verified CHECK (
        request_state IN ('SUBMITTED', 'REJECTED') OR (identity_verified_at IS NOT NULL AND verification_method IS NOT NULL)
    ),
    CONSTRAINT ck_privacy_request_blocked CHECK (
        request_state <> 'BLOCKED' OR (blocked_reason_code IS NOT NULL AND blocked_owner IS NOT NULL)
    ),
    -- 下游未完成不得标记 COMPLETED，由 priv.privacy_request_task 与本状态共同保证
    CONSTRAINT ck_privacy_request_completed CHECK ((request_state = 'COMPLETED') = (completed_at IS NOT NULL)),
    CONSTRAINT ck_privacy_request_due CHECK (completion_due_at >= first_response_due_at)
);
COMMENT ON TABLE priv.privacy_request IS 'CAP-PRIV-007 / SLO-PRIV-001：首次实质响应 ≤ 15 个工作日、完结 ≤ 30 日；下游未完成时只能是 PARTIAL（AT-PRIV-003）';

CREATE OR REPLACE TRIGGER trg_privacy_request_touch
    BEFORE UPDATE ON priv.privacy_request
    FOR EACH ROW EXECUTE FUNCTION core.fn_touch_updated_at();
CREATE OR REPLACE TRIGGER trg_privacy_request_public_id
    BEFORE INSERT ON priv.privacy_request
    FOR EACH ROW EXECUTE FUNCTION core.fn_register_public_id('PRIVACY_REQUEST');

CREATE INDEX IF NOT EXISTS ix_privacy_request_due ON priv.privacy_request (completion_due_at)
    WHERE request_state NOT IN ('COMPLETED', 'REJECTED');
CREATE INDEX IF NOT EXISTS ix_privacy_request_user ON priv.privacy_request (user_id, submitted_at DESC);

-- 逐系统任务与完成证明（CAP-EVENT-013、CAP-EVENT-014）
CREATE TABLE IF NOT EXISTS priv.privacy_request_task (
    id                 uuid        NOT NULL DEFAULT core.uuid_generate_v7(),
    request_id         uuid        NOT NULL,
    target_system_code text        NOT NULL,
    task_type          text        NOT NULL,
    task_state         text        NOT NULL DEFAULT 'PENDING',
    dispatched_at      timestamptz NULL,
    completed_at       timestamptz NULL,
    attempt_count      integer     NOT NULL DEFAULT 0,
    next_attempt_at    timestamptz NULL,
    blocked_reason_code text       NULL,
    proof_ref          text        NULL,
    proof_hash         bytea       NULL,
    last_error_code    text        NULL,
    updated_at         timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT pk_privacy_request_task PRIMARY KEY (id),
    CONSTRAINT uq_privacy_request_task UNIQUE (request_id, target_system_code, task_type),
    CONSTRAINT fk_privacy_request_task_request FOREIGN KEY (request_id) REFERENCES priv.privacy_request (id) ON DELETE CASCADE,
    CONSTRAINT ck_privacy_request_task_type CHECK (task_type IN (
        'STOP_PROCESSING', 'DELETE_DATA', 'ANONYMIZE_DATA', 'EXPORT_DATA', 'REVOKE_SUBSCRIPTION', 'PURGE_BACKUP', 'PURGE_INDEX', 'PURGE_ANALYTICS'
    )),
    CONSTRAINT ck_privacy_request_task_state CHECK (task_state IN ('PENDING', 'DISPATCHED', 'SUCCEEDED', 'FAILED', 'BLOCKED', 'MANUAL')),
    -- CAP-EVENT-014：成功必须有可审计的完成证明
    CONSTRAINT ck_privacy_request_task_proof CHECK (
        task_state <> 'SUCCEEDED' OR (completed_at IS NOT NULL AND proof_ref IS NOT NULL)
    )
);
COMMENT ON TABLE priv.privacy_request_task IS 'CAP-EVENT-013/014：跨系统分派、重试、阻断与逐系统完成证明；存在未完成时不得对用户宣布完成';

CREATE OR REPLACE TRIGGER trg_privacy_request_task_touch
    BEFORE UPDATE ON priv.privacy_request_task
    FOR EACH ROW EXECUTE FUNCTION core.fn_touch_updated_at();

CREATE INDEX IF NOT EXISTS ix_privacy_request_task_retry ON priv.privacy_request_task (next_attempt_at)
    WHERE task_state IN ('PENDING', 'FAILED');

-- -----------------------------------------------------------------------------
-- 5. 法律保留（CAP-PRIV-011、REQ-PRIV-008）
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS priv.legal_hold (
    id                uuid        NOT NULL DEFAULT core.uuid_generate_v7(),
    user_id           uuid        NULL,
    scope_kind        text        NOT NULL,
    scope_ref         text        NULL,
    hold_state        text        NOT NULL DEFAULT 'ACTIVE',
    legal_basis       text        NOT NULL,
    basis_reference   text        NOT NULL,
    approved_by_ref   text        NOT NULL,
    approved_at       timestamptz NOT NULL DEFAULT now(),
    starts_at         timestamptz NOT NULL DEFAULT now(),
    expected_ends_at  timestamptz NULL,
    released_at       timestamptz NULL,
    released_by_ref   text        NULL,
    created_at        timestamptz NOT NULL DEFAULT now(),
    updated_at        timestamptz NOT NULL DEFAULT now(),
    row_version       bigint      NOT NULL DEFAULT 1,
    CONSTRAINT pk_legal_hold PRIMARY KEY (id),
    CONSTRAINT fk_legal_hold_user FOREIGN KEY (user_id) REFERENCES id.global_user (id),
    CONSTRAINT ck_legal_hold_scope CHECK (scope_kind IN ('USER', 'TENANT', 'DATA_CATEGORY', 'GLOBAL')),
    CONSTRAINT ck_legal_hold_state CHECK (hold_state IN ('ACTIVE', 'RELEASED', 'EXPIRED')),
    CONSTRAINT ck_legal_hold_released CHECK ((hold_state = 'RELEASED') = (released_at IS NOT NULL AND released_by_ref IS NOT NULL)),
    CONSTRAINT ck_legal_hold_user_scope CHECK (scope_kind <> 'USER' OR user_id IS NOT NULL)
);
COMMENT ON TABLE priv.legal_hold IS 'CAP-PRIV-011 / REQ-PRIV-008：与删除冲突时记录依据、范围、期限与审批人；解除后流程可继续（AT-PRIV-004）';

CREATE OR REPLACE TRIGGER trg_legal_hold_touch
    BEFORE UPDATE ON priv.legal_hold
    FOR EACH ROW EXECUTE FUNCTION core.fn_touch_updated_at();

CREATE INDEX IF NOT EXISTS ix_legal_hold_user ON priv.legal_hold (user_id) WHERE hold_state = 'ACTIVE';

-- -----------------------------------------------------------------------------
-- 6. 数据导出任务（CAP-PRIV-009、TERM-EXPORT-001：下载链接 ≤ 24 小时）
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS priv.export_job (
    id                  uuid        NOT NULL DEFAULT core.uuid_generate_v7(),
    request_id          uuid        NULL,
    user_id             uuid        NOT NULL,
    job_state           text        NOT NULL DEFAULT 'QUEUED',
    requested_at        timestamptz NOT NULL DEFAULT now(),
    generated_at        timestamptz NULL,
    object_key          text        NULL,
    object_size_bytes   bigint      NULL,
    encryption_key_ref  text        NULL,
    download_token_hash bytea       NULL,
    download_expires_at timestamptz NULL,
    downloaded_at       timestamptz NULL,
    destroyed_at        timestamptz NULL,
    failure_code        text        NULL,
    updated_at          timestamptz NOT NULL DEFAULT now(),
    row_version         bigint      NOT NULL DEFAULT 1,
    CONSTRAINT pk_export_job PRIMARY KEY (id),
    CONSTRAINT fk_export_job_request FOREIGN KEY (request_id) REFERENCES priv.privacy_request (id),
    CONSTRAINT fk_export_job_user FOREIGN KEY (user_id) REFERENCES id.global_user (id) ON DELETE CASCADE,
    CONSTRAINT ck_export_job_state CHECK (job_state IN ('QUEUED', 'GENERATING', 'READY', 'DOWNLOADED', 'EXPIRED', 'DESTROYED', 'FAILED')),
    -- REQ-PRIV-006：加密生成 + 短期下载
    CONSTRAINT ck_export_job_ready CHECK (
        job_state <> 'READY' OR (object_key IS NOT NULL AND encryption_key_ref IS NOT NULL AND download_expires_at IS NOT NULL)
    ),
    -- TERM-EXPORT-001：≤ 24 小时
    CONSTRAINT ck_export_job_download_ttl CHECK (
        download_expires_at IS NULL OR (generated_at IS NOT NULL AND download_expires_at - generated_at <= interval '24 hours')
    )
);
COMMENT ON TABLE priv.export_job IS 'CAP-PRIV-009 / TERM-EXPORT-001：异步生成、加密下载、24 小时内有效、过期销毁并需重新强认证（AT-PRIV-006）';

CREATE OR REPLACE TRIGGER trg_export_job_touch
    BEFORE UPDATE ON priv.export_job
    FOR EACH ROW EXECUTE FUNCTION core.fn_touch_updated_at();

CREATE INDEX IF NOT EXISTS ix_export_job_expiry ON priv.export_job (download_expires_at) WHERE job_state = 'READY';

SELECT core.fn_apply_standard_grants('priv');
SELECT core.fn_apply_append_only_grants('priv', 'agreement_acceptance');

SELECT core.fn_migration_apply('100', 'privacy：数据目录、用途映射、协议、Consent、营销订阅、隐私请求、法律保留、导出任务');
