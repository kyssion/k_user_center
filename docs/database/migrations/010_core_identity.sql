-- =============================================================================
-- 010_core_identity.sql
-- 公共契约、异步 Operation、Global User、Subject、Identifier、合并与注销
-- =============================================================================

BEGIN;
SET LOCAL lock_timeout = '10s';
SET LOCAL statement_timeout = '5min';

CREATE TABLE core.security_profile (
    profile_code       text        NOT NULL,
    profile_version    integer     NOT NULL,
    display_name       text        NOT NULL,
    applicability      text        NOT NULL,
    minimum_controls   jsonb       NOT NULL,
    is_active          boolean     NOT NULL DEFAULT true,
    effective_at       timestamptz NOT NULL,
    retired_at         timestamptz NULL,
    CONSTRAINT pk_security_profile PRIMARY KEY (profile_code, profile_version),
    CONSTRAINT ck_security_profile_code CHECK (profile_code IN ('SP1', 'SP1-D', 'SP2', 'SP3', 'SP4', 'SP5')),
    CONSTRAINT ck_security_profile_window CHECK (retired_at IS NULL OR retired_at > effective_at)
);
COMMENT ON TABLE core.security_profile IS 'REQ-OAP-001/003：Client 安全 Profile 的版本化最小控制集合，含输入受限设备 SP1-D。';

CREATE TABLE core.duration_policy (
    policy_code       text        NOT NULL,
    profile_code      text        NOT NULL,
    duration_seconds  bigint      NOT NULL,
    max_attempts      integer     NULL,
    description       text        NOT NULL,
    effective_at      timestamptz NOT NULL,
    retired_at        timestamptz NULL,
    CONSTRAINT pk_duration_policy PRIMARY KEY (policy_code, profile_code, effective_at),
    CONSTRAINT ck_duration_policy_value CHECK (duration_seconds > 0),
    CONSTRAINT ck_duration_policy_attempts CHECK (max_attempts IS NULL OR max_attempts > 0)
);
COMMENT ON TABLE core.duration_policy IS 'TTL-* / TERM-*：登录事务、Challenge、Token、Device Code、冷静期与下载链接等时长基线。';

CREATE TABLE core.data_classification (
    classification_code text     NOT NULL,
    display_name         text     NOT NULL,
    sensitivity_rank     smallint NOT NULL,
    handling_rules       jsonb    NOT NULL,
    CONSTRAINT pk_data_classification PRIMARY KEY (classification_code),
    CONSTRAINT uq_data_classification_rank UNIQUE (sensitivity_rank),
    CONSTRAINT ck_data_classification_rank CHECK (sensitivity_rank BETWEEN 0 AND 9)
);
COMMENT ON TABLE core.data_classification IS 'CAP-PRIV-005：数据分类分级与默认处理要求。';

CREATE TABLE core.error_registry (
    error_code          text        NOT NULL,
    contract_kind       text        NOT NULL,
    http_status         integer     NULL,
    protocol_error      text        NULL,
    retryable           boolean     NOT NULL,
    user_visible        boolean     NOT NULL,
    description         text        NOT NULL,
    introduced_version  integer     NOT NULL DEFAULT 1,
    deprecated_at       timestamptz NULL,
    CONSTRAINT pk_error_registry PRIMARY KEY (error_code),
    CONSTRAINT ck_error_registry_contract CHECK (contract_kind IN ('DOMAIN_API', 'OAUTH', 'OIDC', 'SCIM', 'SAML', 'OPERATION_REASON')),
    CONSTRAINT ck_error_registry_http CHECK (http_status IS NULL OR http_status BETWEEN 400 AND 599)
);
COMMENT ON TABLE core.error_registry IS 'API-G-006/011/019：领域错误、协议错误和 Operation reason_code 的机器可解析注册表。';

CREATE TABLE core.requirement_trace (
    requirement_id   text        NOT NULL,
    capability_id    text        NOT NULL,
    owner_code       text        NOT NULL,
    profile_codes    text[]      NOT NULL DEFAULT '{}',
    phase_code       text        NOT NULL,
    invariant_ids    text[]      NOT NULL DEFAULT '{}',
    api_event_ids    text[]      NOT NULL DEFAULT '{}',
    test_ids         text[]      NOT NULL DEFAULT '{}',
    slo_ids          text[]      NOT NULL DEFAULT '{}',
    evidence_uri     text        NULL,
    exception_id     uuid        NULL,
    updated_at       timestamptz NOT NULL DEFAULT clock_timestamp(),
    row_version      bigint      NOT NULL DEFAULT 1,
    CONSTRAINT pk_requirement_trace PRIMARY KEY (requirement_id, capability_id, phase_code),
    CONSTRAINT ck_requirement_trace_req CHECK (requirement_id ~ '^(REQ|API-G|EVT-G|INV-G)-[A-Z0-9-]+$'),
    CONSTRAINT ck_requirement_trace_cap CHECK (capability_id ~ '^CAP-[A-Z]+-[0-9]{3}$')
);
COMMENT ON TABLE core.requirement_trace IS '蓝图 §18.4：需求到能力、阶段、测试、SLO、证据与例外的机器可解析追踪矩阵。';

CREATE TABLE core.async_operation (
    id                    uuid        NOT NULL DEFAULT gen_random_uuid(),
    public_id             text        NOT NULL,
    capability_id         text        NOT NULL,
    operation_type        text        NOT NULL,
    operation_state       text        NOT NULL DEFAULT 'PENDING',
    request_hash          bytea       NOT NULL,
    idempotency_key       text        NOT NULL,
    subject_kind          text        NULL,
    subject_ref           text        NULL,
    actor_kind            text        NOT NULL,
    actor_ref             text        NOT NULL,
    tenant_id             uuid        NOT NULL DEFAULT '00000000-0000-0000-0000-000000000000',
    business_line_id      uuid        NULL,
    saga_type             text        NOT NULL,
    current_step          integer     NOT NULL DEFAULT 0,
    total_steps           integer     NOT NULL DEFAULT 0,
    progress_percent      numeric(5,2) NOT NULL DEFAULT 0,
    can_cancel            boolean     NOT NULL DEFAULT true,
    requires_human_action boolean     NOT NULL DEFAULT false,
    reason_code           text        NULL,
    reason_detail         jsonb       NULL,
    policy_version        bigint      NULL,
    irreversible_at       timestamptz NULL,
    result_ref            text        NULL,
    result_payload        jsonb       NULL,
    failure_code          text        NULL,
    retry_count           integer     NOT NULL DEFAULT 0,
    next_retry_at         timestamptz NULL,
    trace_id              text        NULL,
    correlation_id        text        NULL,
    created_at            timestamptz NOT NULL DEFAULT clock_timestamp(),
    started_at            timestamptz NULL,
    completed_at          timestamptz NULL,
    cancelled_at          timestamptz NULL,
    updated_at            timestamptz NOT NULL DEFAULT clock_timestamp(),
    row_version           bigint      NOT NULL DEFAULT 1,
    CONSTRAINT pk_async_operation PRIMARY KEY (id),
    CONSTRAINT uq_async_operation_public_id UNIQUE (public_id),
    CONSTRAINT uq_async_operation_idempotency UNIQUE (actor_kind, actor_ref, tenant_id, idempotency_key),
    CONSTRAINT ck_async_operation_capability CHECK (capability_id ~ '^CAP-[A-Z]+-[0-9]{3}$'),
    CONSTRAINT ck_async_operation_state CHECK (operation_state IN ('PENDING', 'RUNNING', 'BLOCKED', 'PARTIAL', 'COMPLETED', 'FAILED', 'CANCELLED')),
    CONSTRAINT ck_async_operation_actor CHECK (actor_kind IN ('USER', 'ADMIN', 'CLIENT', 'MACHINE', 'SYSTEM')),
    CONSTRAINT ck_async_operation_subject CHECK ((subject_kind IS NULL) = (subject_ref IS NULL)),
    CONSTRAINT ck_async_operation_progress CHECK (current_step >= 0 AND total_steps >= 0 AND current_step <= total_steps AND progress_percent BETWEEN 0 AND 100),
    CONSTRAINT ck_async_operation_blocked CHECK (operation_state <> 'BLOCKED' OR (reason_code IS NOT NULL AND requires_human_action)),
    CONSTRAINT ck_async_operation_terminal CHECK (
        (operation_state IN ('COMPLETED', 'FAILED') AND completed_at IS NOT NULL)
        OR (operation_state = 'CANCELLED' AND cancelled_at IS NOT NULL)
        OR operation_state NOT IN ('COMPLETED', 'FAILED', 'CANCELLED')
    ),
    CONSTRAINT ck_async_operation_cancel CHECK (irreversible_at IS NULL OR NOT can_cancel),
    CONSTRAINT ck_async_operation_hash CHECK (octet_length(request_hash) = 32)
);
COMMENT ON TABLE core.async_operation IS 'CAP-API-018 / API-G-013 至 019：跨事务边界操作的统一状态、幂等、权限上下文、检查点、取消边界和最终结果。';

CREATE TABLE core.async_operation_step (
    id                  uuid        NOT NULL DEFAULT gen_random_uuid(),
    operation_id        uuid        NOT NULL,
    step_no             integer     NOT NULL,
    step_code           text        NOT NULL,
    authority_domain    text        NOT NULL,
    step_state          text        NOT NULL DEFAULT 'PENDING',
    idempotency_key     text        NOT NULL,
    request_hash        bytea       NOT NULL,
    compensatable       boolean     NOT NULL DEFAULT true,
    irreversible_step   boolean     NOT NULL DEFAULT false,
    attempt_count       integer     NOT NULL DEFAULT 0,
    last_error_code     text        NULL,
    checkpoint          jsonb       NULL,
    evidence            jsonb       NULL,
    started_at          timestamptz NULL,
    completed_at        timestamptz NULL,
    next_retry_at       timestamptz NULL,
    created_at          timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at          timestamptz NOT NULL DEFAULT clock_timestamp(),
    row_version         bigint      NOT NULL DEFAULT 1,
    CONSTRAINT pk_async_operation_step PRIMARY KEY (id),
    CONSTRAINT uq_async_operation_step_no UNIQUE (operation_id, step_no),
    CONSTRAINT uq_async_operation_step_key UNIQUE (operation_id, idempotency_key),
    CONSTRAINT fk_async_operation_step_operation FOREIGN KEY (operation_id) REFERENCES core.async_operation(id) ON DELETE CASCADE,
    CONSTRAINT ck_async_operation_step_state CHECK (step_state IN ('PENDING', 'RUNNING', 'BLOCKED', 'SUCCEEDED', 'FAILED', 'COMPENSATING', 'COMPENSATED', 'SKIPPED', 'MANUAL')),
    CONSTRAINT ck_async_operation_step_hash CHECK (octet_length(request_hash) = 32),
    CONSTRAINT ck_async_operation_step_attempt CHECK (attempt_count >= 0)
);
COMMENT ON TABLE core.async_operation_step IS 'API-G-003/017：Operation 的幂等步骤、权威域、检查点、补偿与不可逆边界证据。';

CREATE TABLE core.idempotency_request (
    id                 uuid        NOT NULL DEFAULT gen_random_uuid(),
    scope_code         text        NOT NULL,
    actor_kind         text        NOT NULL,
    actor_ref          text        NOT NULL,
    tenant_id          uuid        NOT NULL DEFAULT '00000000-0000-0000-0000-000000000000',
    idempotency_key    text        NOT NULL,
    request_hash       bytea       NOT NULL,
    operation_id       uuid        NULL,
    response_status    integer     NULL,
    response_headers   jsonb       NULL,
    response_body      jsonb       NULL,
    created_at         timestamptz NOT NULL DEFAULT clock_timestamp(),
    completed_at       timestamptz NULL,
    expires_at         timestamptz NOT NULL,
    CONSTRAINT pk_idempotency_request PRIMARY KEY (id),
    CONSTRAINT uq_idempotency_request UNIQUE (scope_code, actor_kind, actor_ref, tenant_id, idempotency_key),
    CONSTRAINT fk_idempotency_request_operation FOREIGN KEY (operation_id) REFERENCES core.async_operation(id),
    CONSTRAINT ck_idempotency_request_actor CHECK (actor_kind IN ('USER', 'ADMIN', 'CLIENT', 'MACHINE', 'SYSTEM')),
    CONSTRAINT ck_idempotency_request_hash CHECK (octet_length(request_hash) = 32),
    CONSTRAINT ck_idempotency_request_expiry CHECK (expires_at > created_at)
);
COMMENT ON TABLE core.idempotency_request IS 'API-G-001 / INV-G-012：相同幂等键和请求摘要返回原结果，不同请求摘要冲突。';

CREATE TABLE iam.user_account (
    id                    uuid        NOT NULL DEFAULT gen_random_uuid(),
    public_id             text        NOT NULL,
    subject_kind          text        NOT NULL DEFAULT 'HUMAN',
    lifecycle_state       text        NOT NULL DEFAULT 'PROVISIONAL',
    authentication_lock_state text    NOT NULL DEFAULT 'ENABLED',
    security_freeze_state text        NOT NULL DEFAULT 'CLEAR',
    user_security_epoch   bigint      NOT NULL DEFAULT 1,
    aggregate_version     bigint      NOT NULL DEFAULT 1,
    creation_source       text        NOT NULL,
    creation_client_id    uuid        NULL,
    activated_at          timestamptz NULL,
    dormant_at            timestamptz NULL,
    last_authenticated_at timestamptz NULL,
    lock_reason_code      text        NULL,
    lock_until            timestamptz NULL,
    freeze_reason_code    text        NULL,
    frozen_at             timestamptz NULL,
    frozen_by_ref         text        NULL,
    deletion_requested_at timestamptz NULL,
    anonymized_at         timestamptz NULL,
    erased_at             timestamptz NULL,
    merged_into_user_id   uuid        NULL,
    terminal_reason_code  text        NULL,
    created_at            timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at            timestamptz NOT NULL DEFAULT clock_timestamp(),
    row_version           bigint      NOT NULL DEFAULT 1,
    CONSTRAINT pk_user_account PRIMARY KEY (id),
    CONSTRAINT uq_user_account_public_id UNIQUE (public_id),
    CONSTRAINT fk_user_account_merged_into FOREIGN KEY (merged_into_user_id) REFERENCES iam.user_account(id),
    CONSTRAINT ck_user_account_kind CHECK (subject_kind IN ('HUMAN', 'GUEST')),
    CONSTRAINT ck_user_account_lifecycle CHECK (lifecycle_state IN ('PROVISIONAL', 'ACTIVE', 'DORMANT', 'DELETION_PENDING', 'DELETION_BLOCKED', 'ANONYMIZED', 'ERASED', 'MERGED')),
    CONSTRAINT ck_user_account_lock CHECK (authentication_lock_state IN ('ENABLED', 'LOCKED')),
    CONSTRAINT ck_user_account_freeze CHECK (security_freeze_state IN ('CLEAR', 'FROZEN')),
    CONSTRAINT ck_user_account_epoch CHECK (user_security_epoch >= 1),
    CONSTRAINT ck_user_account_frozen CHECK (security_freeze_state <> 'FROZEN' OR (freeze_reason_code IS NOT NULL AND frozen_at IS NOT NULL)),
    CONSTRAINT ck_user_account_merged CHECK ((lifecycle_state = 'MERGED') = (merged_into_user_id IS NOT NULL)),
    CONSTRAINT ck_user_account_anonymized CHECK ((lifecycle_state = 'ANONYMIZED') = (anonymized_at IS NOT NULL)),
    CONSTRAINT ck_user_account_erased CHECK ((lifecycle_state = 'ERASED') = (erased_at IS NOT NULL))
);
COMMENT ON TABLE iam.user_account IS 'CAP-ID-001/013：Global User 主档；生命周期、认证锁定和安全冻结正交，UID 不可变不可复用，终态不可恢复。';

CREATE TABLE iam.subject_assignment (
    id                 uuid        NOT NULL DEFAULT gen_random_uuid(),
    public_id          text        NOT NULL,
    user_id            uuid        NOT NULL,
    audience_kind      text        NOT NULL,
    audience_ref_id    uuid        NOT NULL,
    subject_version    integer     NOT NULL DEFAULT 1,
    created_at         timestamptz NOT NULL DEFAULT clock_timestamp(),
    retired_at         timestamptz NULL,
    CONSTRAINT pk_subject_assignment PRIMARY KEY (id),
    CONSTRAINT uq_subject_assignment_public_id UNIQUE (public_id),
    CONSTRAINT uq_subject_assignment_audience UNIQUE (user_id, audience_kind, audience_ref_id, subject_version),
    CONSTRAINT fk_subject_assignment_user FOREIGN KEY (user_id) REFERENCES iam.user_account(id),
    CONSTRAINT ck_subject_assignment_audience CHECK (audience_kind IN ('CLIENT', 'BUSINESS_LINE', 'TENANT', 'WEBHOOK_RECIPIENT')),
    CONSTRAINT ck_subject_assignment_version CHECK (subject_version >= 1)
);
COMMENT ON TABLE iam.subject_assignment IS 'CAP-ID-001 / REQ-PRIV-010 / EVT-G-012：按 Client、业务、租户或 Webhook 接收方发布无可计算关系的 pairwise Subject。';

CREATE TABLE iam.identifier (
    id                         uuid        NOT NULL DEFAULT gen_random_uuid(),
    user_id                    uuid        NOT NULL,
    identifier_type            text        NOT NULL,
    identifier_state           text        NOT NULL DEFAULT 'PENDING',
    uniqueness_scope           text        NOT NULL,
    scope_ref_id               uuid        NOT NULL DEFAULT '00000000-0000-0000-0000-000000000000',
    value_cipher               bytea       NOT NULL,
    value_blind_index          bytea       NOT NULL,
    value_masked               text        NOT NULL,
    cipher_key_version         integer     NOT NULL,
    blind_index_key_version    integer     NOT NULL,
    normalization_version      integer     NOT NULL,
    normalization_profile_code text        NOT NULL,
    verified_at                timestamptz NULL,
    verification_method        text        NULL,
    unbound_at                 timestamptz NULL,
    quarantine_until           timestamptz NULL,
    released_at                timestamptz NULL,
    is_primary                 boolean     NOT NULL DEFAULT false,
    created_at                 timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at                 timestamptz NOT NULL DEFAULT clock_timestamp(),
    row_version                bigint      NOT NULL DEFAULT 1,
    CONSTRAINT pk_identifier PRIMARY KEY (id),
    CONSTRAINT fk_identifier_user FOREIGN KEY (user_id) REFERENCES iam.user_account(id),
    CONSTRAINT ck_identifier_type CHECK (identifier_type IN ('PHONE', 'EMAIL', 'USERNAME')),
    CONSTRAINT ck_identifier_state CHECK (identifier_state IN ('PENDING', 'VERIFIED', 'UNBOUND', 'QUARANTINED', 'RELEASED')),
    CONSTRAINT ck_identifier_scope CHECK (uniqueness_scope IN ('GLOBAL', 'BUSINESS_LINE', 'TENANT', 'CLIENT')),
    CONSTRAINT ck_identifier_blind_index CHECK (octet_length(value_blind_index) = 32),
    CONSTRAINT ck_identifier_versions CHECK (cipher_key_version > 0 AND blind_index_key_version > 0 AND normalization_version > 0),
    CONSTRAINT ck_identifier_verified CHECK (identifier_state <> 'VERIFIED' OR (verified_at IS NOT NULL AND verification_method IS NOT NULL)),
    CONSTRAINT ck_identifier_quarantine CHECK (identifier_state <> 'QUARANTINED' OR quarantine_until IS NOT NULL)
);
COMMENT ON TABLE iam.identifier IS 'CAP-ID-002 至 009：手机号、邮箱、用户名的加密值、盲索引、版本化规范化、验证、解绑、隔离与释放。';

CREATE TABLE iam.identifier_tombstone (
    id                       uuid        NOT NULL DEFAULT gen_random_uuid(),
    identifier_type          text        NOT NULL,
    uniqueness_scope         text        NOT NULL,
    scope_ref_id             uuid        NOT NULL,
    value_blind_index        bytea       NOT NULL,
    blind_index_key_version  integer     NOT NULL,
    former_user_id           uuid        NOT NULL,
    ownership_digest         bytea       NOT NULL,
    quarantine_until         timestamptz NOT NULL,
    released_at              timestamptz NULL,
    created_at               timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT pk_identifier_tombstone PRIMARY KEY (id),
    CONSTRAINT uq_identifier_tombstone UNIQUE (identifier_type, uniqueness_scope, scope_ref_id, value_blind_index, blind_index_key_version),
    CONSTRAINT fk_identifier_tombstone_user FOREIGN KEY (former_user_id) REFERENCES iam.user_account(id),
    CONSTRAINT ck_identifier_tombstone_hash CHECK (octet_length(value_blind_index) = 32 AND octet_length(ownership_digest) = 32)
);
COMMENT ON TABLE iam.identifier_tombstone IS 'CAP-ID-008/009/012：解绑历史、号码回收隔离和不可逆归属墓碑；释放唯一键也不删除历史。';

CREATE TABLE iam.account_merge (
    id                    uuid        NOT NULL DEFAULT gen_random_uuid(),
    public_id             text        NOT NULL,
    source_user_id        uuid        NOT NULL,
    target_user_id        uuid        NOT NULL,
    merge_state           text        NOT NULL DEFAULT 'CANDIDATE',
    source_verified_at    timestamptz NULL,
    target_verified_at    timestamptz NULL,
    conflict_summary      jsonb       NULL,
    approval_case_id      uuid        NULL,
    operation_id          uuid        NOT NULL,
    irreversible_at       timestamptz NULL,
    completed_at          timestamptz NULL,
    failed_reason_code    text        NULL,
    created_at            timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at            timestamptz NOT NULL DEFAULT clock_timestamp(),
    row_version           bigint      NOT NULL DEFAULT 1,
    CONSTRAINT pk_account_merge PRIMARY KEY (id),
    CONSTRAINT uq_account_merge_public_id UNIQUE (public_id),
    CONSTRAINT fk_account_merge_source FOREIGN KEY (source_user_id) REFERENCES iam.user_account(id),
    CONSTRAINT fk_account_merge_target FOREIGN KEY (target_user_id) REFERENCES iam.user_account(id),
    CONSTRAINT fk_account_merge_operation FOREIGN KEY (operation_id) REFERENCES core.async_operation(id),
    CONSTRAINT ck_account_merge_distinct CHECK (source_user_id <> target_user_id),
    CONSTRAINT ck_account_merge_state CHECK (merge_state IN ('CANDIDATE', 'VERIFYING', 'CONFLICT', 'APPROVED', 'EXECUTING', 'COMPLETED', 'FAILED', 'CANCELLED')),
    CONSTRAINT ck_account_merge_completed CHECK (merge_state <> 'COMPLETED' OR completed_at IS NOT NULL)
);
COMMENT ON TABLE iam.account_merge IS 'CAP-ID-015 至 018：重复候选、双账号验证、冲突处理、审批、不可逆边界与合并 Operation。';

CREATE TABLE iam.account_merge_item (
    id                  uuid        NOT NULL DEFAULT gen_random_uuid(),
    merge_id            uuid        NOT NULL,
    domain_code         text        NOT NULL,
    source_ref          text        NULL,
    target_ref          text        NULL,
    resolution_action   text        NOT NULL,
    resolution_state    text        NOT NULL DEFAULT 'PENDING',
    evidence            jsonb       NULL,
    completed_at        timestamptz NULL,
    CONSTRAINT pk_account_merge_item PRIMARY KEY (id),
    CONSTRAINT uq_account_merge_item UNIQUE (merge_id, domain_code, source_ref, target_ref),
    CONSTRAINT fk_account_merge_item_merge FOREIGN KEY (merge_id) REFERENCES iam.account_merge(id) ON DELETE CASCADE,
    CONSTRAINT ck_account_merge_item_action CHECK (resolution_action IN ('MOVE', 'KEEP_TARGET', 'KEEP_BOTH', 'REVOKE', 'MANUAL', 'REJECT')),
    CONSTRAINT ck_account_merge_item_state CHECK (resolution_state IN ('PENDING', 'RESOLVED', 'BLOCKED', 'FAILED'))
);
COMMENT ON TABLE iam.account_merge_item IS 'CAP-ID-016/017：按权威域记录合并冲突、处置动作、证据与执行结果。';

CREATE TABLE iam.account_deletion (
    id                         uuid        NOT NULL DEFAULT gen_random_uuid(),
    user_id                    uuid        NOT NULL,
    operation_id               uuid        NOT NULL,
    requested_at               timestamptz NOT NULL DEFAULT clock_timestamp(),
    cooling_off_until          timestamptz NOT NULL,
    blocked_reason_code        text        NULL,
    blocked_owner              text        NULL,
    blocked_at                 timestamptz NULL,
    resumed_at                 timestamptz NULL,
    withdrawn_at               timestamptz NULL,
    withdrawal_auth_time       timestamptz NULL,
    irreversible_at            timestamptz NULL,
    completion_kind            text        NULL,
    completion_proof_ref       text        NULL,
    completed_at               timestamptz NULL,
    created_at                 timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at                 timestamptz NOT NULL DEFAULT clock_timestamp(),
    row_version                bigint      NOT NULL DEFAULT 1,
    CONSTRAINT pk_account_deletion PRIMARY KEY (id),
    CONSTRAINT uq_account_deletion_operation UNIQUE (operation_id),
    CONSTRAINT fk_account_deletion_user FOREIGN KEY (user_id) REFERENCES iam.user_account(id),
    CONSTRAINT fk_account_deletion_operation FOREIGN KEY (operation_id) REFERENCES core.async_operation(id),
    CONSTRAINT ck_account_deletion_cooling CHECK (cooling_off_until >= requested_at),
    CONSTRAINT ck_account_deletion_block CHECK (
        (blocked_at IS NULL AND blocked_reason_code IS NULL AND blocked_owner IS NULL)
        OR (blocked_at IS NOT NULL AND blocked_reason_code IS NOT NULL AND blocked_owner IS NOT NULL)
    ),
    CONSTRAINT ck_account_deletion_completion CHECK (completion_kind IS NULL OR completion_kind IN ('ANONYMIZED', 'ERASED'))
);
COMMENT ON TABLE iam.account_deletion IS 'CAP-ID-020 至 023 / REQ-ID-014 至 016：注销冷静期、阻断、恢复原检查点、撤回强认证和完成证明。';

CREATE UNIQUE INDEX ux_identifier_verified_scope
    ON iam.identifier(identifier_type, uniqueness_scope, scope_ref_id, value_blind_index, blind_index_key_version)
    WHERE identifier_state = 'VERIFIED';
CREATE UNIQUE INDEX ux_identifier_primary
    ON iam.identifier(user_id, identifier_type)
    WHERE is_primary AND identifier_state = 'VERIFIED';
CREATE UNIQUE INDEX ux_account_merge_active_source
    ON iam.account_merge(source_user_id)
    WHERE merge_state IN ('CANDIDATE', 'VERIFYING', 'CONFLICT', 'APPROVED', 'EXECUTING');
CREATE UNIQUE INDEX ux_account_deletion_active_user
    ON iam.account_deletion(user_id)
    WHERE completed_at IS NULL AND withdrawn_at IS NULL;

CREATE INDEX ix_operation_actor ON core.async_operation(actor_kind, actor_ref, created_at DESC);
CREATE INDEX ix_operation_subject ON core.async_operation(subject_kind, subject_ref, created_at DESC);
CREATE INDEX ix_operation_tenant_state ON core.async_operation(tenant_id, operation_state, updated_at DESC);
CREATE INDEX ix_operation_retry ON core.async_operation(next_retry_at) WHERE operation_state IN ('RUNNING', 'BLOCKED', 'PARTIAL');
CREATE INDEX ix_idempotency_expiry ON core.idempotency_request(expires_at);
CREATE INDEX ix_user_account_lifecycle ON iam.user_account(lifecycle_state, updated_at DESC);
CREATE INDEX ix_user_account_frozen ON iam.user_account(frozen_at DESC) WHERE security_freeze_state = 'FROZEN';
CREATE INDEX ix_identifier_user ON iam.identifier(user_id, identifier_type, identifier_state);
CREATE INDEX ix_identifier_lookup ON iam.identifier(identifier_type, value_blind_index, blind_index_key_version);
CREATE INDEX ix_identifier_tombstone_quarantine ON iam.identifier_tombstone(quarantine_until);

CREATE TRIGGER trg_operation_touch BEFORE UPDATE ON core.async_operation FOR EACH ROW EXECUTE FUNCTION core.fn_touch_updated_at();
CREATE TRIGGER trg_operation_version BEFORE UPDATE ON core.async_operation FOR EACH ROW EXECUTE FUNCTION core.fn_increment_row_version();
CREATE TRIGGER trg_operation_public_id BEFORE INSERT ON core.async_operation FOR EACH ROW EXECUTE FUNCTION core.fn_register_public_id('OPERATION');
CREATE TRIGGER trg_operation_terminal BEFORE UPDATE ON core.async_operation FOR EACH ROW EXECUTE FUNCTION core.fn_terminal_state_guard('operation_state', 'COMPLETED', 'FAILED', 'CANCELLED');
CREATE TRIGGER trg_operation_step_touch BEFORE UPDATE ON core.async_operation_step FOR EACH ROW EXECUTE FUNCTION core.fn_touch_updated_at();
CREATE TRIGGER trg_operation_step_version BEFORE UPDATE ON core.async_operation_step FOR EACH ROW EXECUTE FUNCTION core.fn_increment_row_version();
CREATE TRIGGER trg_requirement_trace_touch BEFORE UPDATE ON core.requirement_trace FOR EACH ROW EXECUTE FUNCTION core.fn_touch_updated_at();
CREATE TRIGGER trg_requirement_trace_version BEFORE UPDATE ON core.requirement_trace FOR EACH ROW EXECUTE FUNCTION core.fn_increment_row_version();

CREATE TRIGGER trg_user_account_touch BEFORE UPDATE ON iam.user_account FOR EACH ROW EXECUTE FUNCTION core.fn_touch_updated_at();
CREATE TRIGGER trg_user_account_version BEFORE UPDATE ON iam.user_account FOR EACH ROW EXECUTE FUNCTION core.fn_increment_row_version();
CREATE TRIGGER trg_user_account_epoch BEFORE UPDATE ON iam.user_account FOR EACH ROW EXECUTE FUNCTION core.fn_forbid_epoch_decrease('user_security_epoch');
CREATE TRIGGER trg_user_account_public_id BEFORE INSERT ON iam.user_account FOR EACH ROW EXECUTE FUNCTION core.fn_register_public_id('GLOBAL_USER');
CREATE TRIGGER trg_user_account_terminal BEFORE UPDATE ON iam.user_account FOR EACH ROW EXECUTE FUNCTION core.fn_terminal_state_guard('lifecycle_state', 'ANONYMIZED', 'ERASED', 'MERGED');
CREATE TRIGGER trg_subject_assignment_public_id BEFORE INSERT ON iam.subject_assignment FOR EACH ROW EXECUTE FUNCTION core.fn_register_public_id('SUBJECT');
CREATE TRIGGER trg_identifier_touch BEFORE UPDATE ON iam.identifier FOR EACH ROW EXECUTE FUNCTION core.fn_touch_updated_at();
CREATE TRIGGER trg_identifier_version BEFORE UPDATE ON iam.identifier FOR EACH ROW EXECUTE FUNCTION core.fn_increment_row_version();
CREATE TRIGGER trg_account_merge_touch BEFORE UPDATE ON iam.account_merge FOR EACH ROW EXECUTE FUNCTION core.fn_touch_updated_at();
CREATE TRIGGER trg_account_merge_version BEFORE UPDATE ON iam.account_merge FOR EACH ROW EXECUTE FUNCTION core.fn_increment_row_version();
CREATE TRIGGER trg_account_merge_public_id BEFORE INSERT ON iam.account_merge FOR EACH ROW EXECUTE FUNCTION core.fn_register_public_id('ACCOUNT_MERGE');
CREATE TRIGGER trg_account_deletion_touch BEFORE UPDATE ON iam.account_deletion FOR EACH ROW EXECUTE FUNCTION core.fn_touch_updated_at();
CREATE TRIGGER trg_account_deletion_version BEFORE UPDATE ON iam.account_deletion FOR EACH ROW EXECUTE FUNCTION core.fn_increment_row_version();

SELECT core.fn_register_migration('010', '公共契约、Operation、Global User、Subject、Identifier、合并与注销', NULLIF(current_setting('kuc.migration_sha256', true), ''));
COMMIT;
