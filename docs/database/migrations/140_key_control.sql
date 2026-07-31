-- =============================================================================
-- 140_key_control.sql
-- KEY 域：密钥与证书台账、JWKS 发布
-- CTRL 域：配置发布、审批单、安全例外、Break-glass
-- 依据：能力地图 §4.8（KEY）、§4.16；蓝图 §15.1（REQ-KEY-001 至 009、REQ-CTRL-001 至 007）
-- 关键：本库不存任何私钥材料；未审批配置不得激活；例外必须带到期日
-- =============================================================================

SET client_min_messages = warning;

-- -----------------------------------------------------------------------------
-- 1. 密钥台账（REQ-KEY-001/007：只存元数据与 KMS 引用）
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS kms.key_asset (
    id                 uuid        NOT NULL DEFAULT core.uuid_generate_v7(),
    public_id          text        NOT NULL,
    key_id             text        NOT NULL,
    key_purpose        text        NOT NULL,
    key_state          text        NOT NULL DEFAULT 'GENERATED',
    algorithm          text        NOT NULL,
    key_size_bits      integer     NULL,
    environment        text        NOT NULL,
    owner_ref          text        NOT NULL,
    -- 只保存外部受控边界的引用；私钥永不出现在本库（REQ-KEY-001）
    kms_provider       text        NOT NULL,
    kms_key_reference  text        NOT NULL,
    public_jwk         jsonb       NULL,
    generated_at       timestamptz NOT NULL DEFAULT now(),
    published_at       timestamptz NULL,
    signing_from       timestamptz NULL,
    verify_only_from   timestamptz NULL,
    retired_at         timestamptz NULL,
    destroyed_at       timestamptz NULL,
    compromised_at     timestamptz NULL,
    revoked_at         timestamptz NULL,
    rotation_due_at    timestamptz NOT NULL,
    rotated_from_id    uuid        NULL,
    created_at         timestamptz NOT NULL DEFAULT now(),
    updated_at         timestamptz NOT NULL DEFAULT now(),
    row_version        bigint      NOT NULL DEFAULT 1,
    CONSTRAINT pk_key_asset PRIMARY KEY (id),
    CONSTRAINT uq_key_asset_public_id UNIQUE (public_id),
    CONSTRAINT uq_key_asset_kid UNIQUE (key_purpose, environment, key_id),
    CONSTRAINT fk_key_asset_rotated_from FOREIGN KEY (rotated_from_id) REFERENCES kms.key_asset (id),
    CONSTRAINT ck_key_asset_purpose CHECK (key_purpose IN (
        'TOKEN_SIGNING', 'ID_TOKEN_SIGNING', 'LOGOUT_TOKEN_SIGNING', 'WEBHOOK_SIGNING',
        'DATA_ENCRYPTION', 'BLIND_INDEX_HMAC', 'EXPORT_ENCRYPTION', 'AUDIT_SEAL_SIGNING', 'MTLS_SERVER'
    )),
    CONSTRAINT ck_key_asset_state CHECK (key_state IN (
        'GENERATED', 'PUBLISHED', 'SIGNING_AND_VERIFYING', 'VERIFY_ONLY', 'RETIRED', 'DESTROYED', 'COMPROMISED', 'REVOKED'
    )),
    CONSTRAINT ck_key_asset_environment CHECK (environment IN ('DEV', 'TEST', 'STAGING', 'PROD')),
    -- REQ-KEY-004：算法 allowlist，禁止 none 与算法混淆
    CONSTRAINT ck_key_asset_algorithm CHECK (algorithm IN (
        'ES256', 'ES384', 'PS256', 'RS256', 'EdDSA', 'SM2', 'AES256GCM', 'HMAC_SHA256', 'SM4_GCM'
    )),
    -- REQ-KEY-002：先发布后签名
    CONSTRAINT ck_key_asset_publish_before_sign CHECK (
        signing_from IS NULL OR (published_at IS NOT NULL AND signing_from >= published_at)
    ),
    CONSTRAINT ck_key_asset_verify_only CHECK (verify_only_from IS NULL OR signing_from IS NULL OR verify_only_from >= signing_from),
    CONSTRAINT ck_key_asset_destroyed CHECK ((key_state = 'DESTROYED') = (destroyed_at IS NOT NULL)),
    CONSTRAINT ck_key_asset_compromised CHECK (key_state <> 'COMPROMISED' OR compromised_at IS NOT NULL),
    -- TERM-KEY-001：签名密钥常规轮换周期 ≤ 90 天
    CONSTRAINT ck_key_asset_rotation CHECK (
        key_purpose NOT IN ('TOKEN_SIGNING', 'ID_TOKEN_SIGNING', 'LOGOUT_TOKEN_SIGNING', 'WEBHOOK_SIGNING')
        OR rotation_due_at - generated_at <= interval '90 days'
    ),
    -- 结构性保证：本表没有任何私钥列，只有 kms_key_reference
    CONSTRAINT ck_key_asset_reference CHECK (length(kms_key_reference) > 0)
);
COMMENT ON TABLE kms.key_asset IS 'REQ-KEY-001/007：密钥台账，记录 Owner、用途、算法、kid、环境与生命周期证据；私钥在 KMS/HSM 内生成与使用，禁止明文导出';
COMMENT ON COLUMN kms.key_asset.kms_key_reference IS 'KMS/HSM 中的密钥引用（如 ARN 或密钥句柄）；即使本库泄露也无法还原私钥';
COMMENT ON COLUMN kms.key_asset.rotation_due_at IS 'TERM-KEY-001：签名密钥常规轮换周期 ≤ 90 天，逾期由配置扫描告警';

CREATE OR REPLACE TRIGGER trg_key_asset_touch
    BEFORE UPDATE ON kms.key_asset
    FOR EACH ROW EXECUTE FUNCTION core.fn_touch_updated_at();
CREATE OR REPLACE TRIGGER trg_key_asset_public_id
    BEFORE INSERT ON kms.key_asset
    FOR EACH ROW EXECUTE FUNCTION core.fn_register_public_id('KEY_ASSET');

-- REQ-KEY-003：任一时刻每个用途每个环境至多一个正在签名的密钥
CREATE UNIQUE INDEX IF NOT EXISTS ux_key_asset_signing
    ON kms.key_asset (key_purpose, environment)
    WHERE key_state = 'SIGNING_AND_VERIFYING';

CREATE INDEX IF NOT EXISTS ix_key_asset_state ON kms.key_asset (key_state, environment);
CREATE INDEX IF NOT EXISTS ix_key_asset_rotation ON kms.key_asset (rotation_due_at) WHERE key_state IN ('PUBLISHED', 'SIGNING_AND_VERIFYING');

-- 证书生命周期（蓝图 §15.1：不得用通用配置状态代替密码学资产状态）
CREATE TABLE IF NOT EXISTS kms.certificate (
    id                 uuid        NOT NULL DEFAULT core.uuid_generate_v7(),
    key_asset_id       uuid        NULL,
    serial_number      text        NOT NULL,
    subject_dn         text        NOT NULL,
    issuer_dn          text        NOT NULL,
    thumbprint_s256    bytea       NOT NULL,
    certificate_state  text        NOT NULL DEFAULT 'ISSUED',
    certificate_usage  text        NOT NULL,
    issued_at          timestamptz NOT NULL,
    not_before         timestamptz NOT NULL,
    not_after          timestamptz NOT NULL,
    grace_until        timestamptz NULL,
    revoked_at         timestamptz NULL,
    revoke_reason_code text        NULL,
    created_at         timestamptz NOT NULL DEFAULT now(),
    updated_at         timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT pk_certificate PRIMARY KEY (id),
    CONSTRAINT uq_certificate_thumbprint UNIQUE (thumbprint_s256),
    CONSTRAINT uq_certificate_serial UNIQUE (issuer_dn, serial_number),
    CONSTRAINT fk_certificate_key_asset FOREIGN KEY (key_asset_id) REFERENCES kms.key_asset (id),
    CONSTRAINT ck_certificate_state CHECK (certificate_state IN ('ISSUED', 'ACTIVE', 'GRACE', 'EXPIRED', 'REVOKED')),
    CONSTRAINT ck_certificate_usage CHECK (certificate_usage IN ('MTLS_SERVER', 'MTLS_CLIENT', 'SAML_SIGNING', 'WORKLOAD_IDENTITY')),
    CONSTRAINT ck_certificate_window CHECK (not_after > not_before),
    CONSTRAINT ck_certificate_revoked CHECK ((certificate_state = 'REVOKED') = (revoked_at IS NOT NULL))
);
COMMENT ON TABLE kms.certificate IS '蓝图 §15.1：证书独立生命周期 ISSUED → ACTIVE → GRACE/EXPIRED/REVOKED（REQ-KEY-007）';

CREATE OR REPLACE TRIGGER trg_certificate_touch
    BEFORE UPDATE ON kms.certificate
    FOR EACH ROW EXECUTE FUNCTION core.fn_touch_updated_at();

-- JWKS 发布记录（REQ-KEY-002/003、TTL-JWKS-001、AT-KEY-001）
CREATE TABLE IF NOT EXISTS kms.jwks_publication (
    id                      uuid        NOT NULL DEFAULT core.uuid_generate_v7(),
    publication_version     bigint      NOT NULL,
    environment             text        NOT NULL,
    active_key_ids          text[]      NOT NULL,
    signing_key_id          text        NOT NULL,
    content_hash            bytea       NOT NULL,
    published_at            timestamptz NOT NULL DEFAULT now(),
    cache_max_age_seconds   integer     NOT NULL,
    propagation_ends_at     timestamptz NOT NULL,
    superseded_at           timestamptz NULL,
    CONSTRAINT pk_jwks_publication PRIMARY KEY (id),
    CONSTRAINT uq_jwks_publication_version UNIQUE (environment, publication_version),
    CONSTRAINT ck_jwks_publication_keys CHECK (array_length(active_key_ids, 1) >= 1 AND signing_key_id = ANY (active_key_ids)),
    CONSTRAINT ck_jwks_publication_cache CHECK (cache_max_age_seconds BETWEEN 60 AND 3600),
    -- TTL-JWKS-001：新验证键发布到开始签名 ≥ 2 × max-age
    CONSTRAINT ck_jwks_publication_propagation CHECK (
        propagation_ends_at - published_at >= make_interval(secs => 2 * cache_max_age_seconds)
    )
);
COMMENT ON TABLE kms.jwks_publication IS 'REQ-KEY-002 / TTL-JWKS-001：先发布后签名的传播窗口在此登记；AT-KEY-001 依据本表验证轮换顺序';

-- -----------------------------------------------------------------------------
-- 2. 控制面配置发布（REQ-CTRL-001 至 004、INV-G-011）
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ctrl.config_release (
    id                  uuid        NOT NULL DEFAULT core.uuid_generate_v7(),
    public_id           text        NOT NULL,
    config_kind         text        NOT NULL,
    target_scope_kind   text        NOT NULL,
    target_scope_ref    uuid        NOT NULL DEFAULT '00000000-0000-0000-0000-000000000000',
    environment         text        NOT NULL,
    release_version     bigint      NOT NULL,
    release_state       text        NOT NULL DEFAULT 'DRAFT',
    content_hash        bytea       NOT NULL,
    content             jsonb       NOT NULL,
    declarative_source_ref text     NULL,
    impact_summary      jsonb       NULL,
    dry_run_result      jsonb       NULL,
    submitted_by_ref    text        NOT NULL,
    submitted_at        timestamptz NOT NULL DEFAULT now(),
    validated_at        timestamptz NULL,
    approved_by_ref     text        NULL,
    approved_at         timestamptz NULL,
    second_approver_ref text        NULL,
    staged_at           timestamptz NULL,
    activated_at        timestamptz NULL,
    canary_percentage   smallint    NULL,
    deprecated_at       timestamptz NULL,
    revoked_at          timestamptz NULL,
    revoked_by_ref      text        NULL,
    rollback_of_id      uuid        NULL,
    is_emergency        boolean     NOT NULL DEFAULT false,
    post_review_at      timestamptz NULL,
    created_at          timestamptz NOT NULL DEFAULT now(),
    updated_at          timestamptz NOT NULL DEFAULT now(),
    row_version         bigint      NOT NULL DEFAULT 1,
    CONSTRAINT pk_config_release PRIMARY KEY (id),
    CONSTRAINT uq_config_release_public_id UNIQUE (public_id),
    CONSTRAINT uq_config_release_version UNIQUE (config_kind, target_scope_kind, target_scope_ref, environment, release_version),
    CONSTRAINT fk_config_release_rollback FOREIGN KEY (rollback_of_id) REFERENCES ctrl.config_release (id),
    CONSTRAINT ck_config_release_kind CHECK (config_kind IN (
        'CLIENT', 'CLIENT_URI', 'IDENTITY_PROVIDER', 'AUTHZ_POLICY', 'RISK_POLICY', 'RETENTION_RULE',
        'KEY_POLICY', 'RATE_LIMIT', 'TENANT_AUTH_POLICY', 'MESSAGE_TEMPLATE', 'PROFILE_FIELD'
    )),
    CONSTRAINT ck_config_release_scope CHECK (target_scope_kind IN ('PLATFORM', 'BUSINESS_LINE', 'TENANT', 'CLIENT')),
    CONSTRAINT ck_config_release_environment CHECK (environment IN ('DEV', 'TEST', 'STAGING', 'PROD')),
    CONSTRAINT ck_config_release_state CHECK (release_state IN (
        'DRAFT', 'VALIDATED', 'APPROVED', 'STAGED', 'ACTIVE', 'DEPRECATED', 'REVOKED'
    )),
    CONSTRAINT ck_config_release_hash CHECK (octet_length(content_hash) = 32),
    -- INV-G-011 / REQ-CTRL-002：提交人不得自审，双人复核时两位审批人也必须不同
    CONSTRAINT ck_config_release_separation CHECK (
        (approved_by_ref IS NULL OR approved_by_ref <> submitted_by_ref)
        AND (second_approver_ref IS NULL OR (second_approver_ref <> submitted_by_ref AND second_approver_ref <> approved_by_ref))
    ),
    -- 未审批不得进入 STAGED/ACTIVE
    CONSTRAINT ck_config_release_approved CHECK (
        release_state NOT IN ('APPROVED', 'STAGED', 'ACTIVE') OR (approved_at IS NOT NULL AND approved_by_ref IS NOT NULL)
    ),
    CONSTRAINT ck_config_release_validated CHECK (
        release_state = 'DRAFT' OR validated_at IS NOT NULL OR is_emergency
    ),
    CONSTRAINT ck_config_release_active CHECK (release_state <> 'ACTIVE' OR activated_at IS NOT NULL),
    -- 紧急变更允许跳过事前审批，但不允许跳过事后复核（CAP-CTRL-010）。
    -- “已激活但未复核”属于时间相关判定，不能用 CHECK 表达（CHECK 不得含 now()），
    -- 改由 ix_config_release_emergency 索引 + 定时告警兼顾，并进入 verify.sql 的 V-011 检查面。
    CONSTRAINT ck_config_release_canary CHECK (canary_percentage IS NULL OR canary_percentage BETWEEN 1 AND 100)
);
COMMENT ON TABLE ctrl.config_release IS 'INV-G-011 / REQ-CTRL-001 至 004：配置版本化发布与状态机；回滚创建新 Release（rollback_of_id），不得把 DEPRECATED 改回 ACTIVE（AT-CTRL-004）';

CREATE OR REPLACE TRIGGER trg_config_release_touch
    BEFORE UPDATE ON ctrl.config_release
    FOR EACH ROW EXECUTE FUNCTION core.fn_touch_updated_at();
CREATE OR REPLACE TRIGGER trg_config_release_public_id
    BEFORE INSERT ON ctrl.config_release
    FOR EACH ROW EXECUTE FUNCTION core.fn_register_public_id('CONFIG_RELEASE');

-- INV-G-011：每个配置对象每个环境同时只有一个 ACTIVE 版本
CREATE UNIQUE INDEX IF NOT EXISTS ux_config_release_active
    ON ctrl.config_release (config_kind, target_scope_kind, target_scope_ref, environment)
    WHERE release_state = 'ACTIVE';

CREATE INDEX IF NOT EXISTS ix_config_release_state ON ctrl.config_release (release_state, submitted_at DESC);
CREATE INDEX IF NOT EXISTS ix_config_release_emergency ON ctrl.config_release (activated_at DESC) WHERE is_emergency AND post_review_at IS NULL;

-- 状态机方向保护：不得反向转换（蓝图 §15.1）
CREATE OR REPLACE FUNCTION ctrl.fn_config_release_forward_only()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    v_order text[] := ARRAY['DRAFT', 'VALIDATED', 'APPROVED', 'STAGED', 'ACTIVE', 'DEPRECATED'];
    v_old   integer := array_position(v_order, OLD.release_state);
    v_new   integer := array_position(v_order, NEW.release_state);
BEGIN
    -- REVOKED 可从任意非终态进入（AT-CTRL-005）
    IF NEW.release_state = 'REVOKED' THEN
        RETURN NEW;
    END IF;
    IF OLD.release_state = 'REVOKED' AND NEW.release_state <> 'REVOKED' THEN
        RAISE EXCEPTION 'INVALID_STATE_TRANSITION: REVOKED 为终态（蓝图 §15.1）' USING ERRCODE = '23514';
    END IF;
    IF v_old IS NOT NULL AND v_new IS NOT NULL AND v_new < v_old THEN
        RAISE EXCEPTION 'INVALID_STATE_TRANSITION: 控制面状态不得反向转换（% -> %），回滚必须创建新 Release',
            OLD.release_state, NEW.release_state USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE OR REPLACE TRIGGER trg_config_release_forward_only
    BEFORE UPDATE ON ctrl.config_release
    FOR EACH ROW EXECUTE FUNCTION ctrl.fn_config_release_forward_only();

-- -----------------------------------------------------------------------------
-- 3. 审批单（CAP-OPS-009、INV-G-017）
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ctrl.approval_case (
    id                  uuid        NOT NULL DEFAULT core.uuid_generate_v7(),
    public_id           text        NOT NULL,
    case_type           text        NOT NULL,
    case_state          text        NOT NULL DEFAULT 'DRAFT',
    requested_by_ref    text        NOT NULL,
    requested_at        timestamptz NOT NULL DEFAULT now(),
    reason              text        NOT NULL,
    attachments         jsonb       NULL,
    target_kind         text        NOT NULL,
    target_ref          text        NOT NULL,
    tenant_id           uuid        NOT NULL DEFAULT '00000000-0000-0000-0000-000000000000',
    before_value        jsonb       NULL,
    after_value         jsonb       NULL,
    approver_ref        text        NULL,
    approved_at         timestamptz NULL,
    second_approver_ref text        NULL,
    second_approved_at  timestamptz NULL,
    rejected_at         timestamptz NULL,
    reject_reason       text        NULL,
    expires_at          timestamptz NOT NULL,
    executed_at         timestamptz NULL,
    execution_ref       text        NULL,
    created_at          timestamptz NOT NULL DEFAULT now(),
    updated_at          timestamptz NOT NULL DEFAULT now(),
    row_version         bigint      NOT NULL DEFAULT 1,
    CONSTRAINT pk_approval_case PRIMARY KEY (id),
    CONSTRAINT uq_approval_case_public_id UNIQUE (public_id),
    CONSTRAINT ck_approval_case_type CHECK (case_type IN (
        'ACCOUNT_MERGE', 'ACCOUNT_SPLIT', 'MFA_RESET', 'ADMIN_RECOVERY', 'HIGH_RISK_CONFIG',
        'KEY_ROTATION', 'CLIENT_APPROVAL', 'TENANT_OWNERSHIP_TRANSFER', 'PRIVILEGE_GRANT',
        'SECURITY_EXCEPTION', 'BREAK_GLASS', 'DATA_EXPORT_BULK', 'DELEGATION_GRANT'
    )),
    CONSTRAINT ck_approval_case_state CHECK (case_state IN ('DRAFT', 'PENDING_REVIEW', 'APPROVED', 'EXECUTED', 'REJECTED', 'EXPIRED')),
    -- INV-G-017：发起人不得自审
    CONSTRAINT ck_approval_case_separation CHECK (
        (approver_ref IS NULL OR approver_ref <> requested_by_ref)
        AND (second_approver_ref IS NULL OR (second_approver_ref <> requested_by_ref AND second_approver_ref <> approver_ref))
    ),
    CONSTRAINT ck_approval_case_approved CHECK (
        case_state NOT IN ('APPROVED', 'EXECUTED') OR (approved_at IS NOT NULL AND approver_ref IS NOT NULL)
    ),
    -- INV-G-017：执行必须绑定审批单且仅执行一次
    CONSTRAINT ck_approval_case_executed CHECK (
        (case_state = 'EXECUTED') = (executed_at IS NOT NULL AND execution_ref IS NOT NULL)
    ),
    CONSTRAINT ck_approval_case_rejected CHECK ((case_state = 'REJECTED') = (rejected_at IS NOT NULL))
);
COMMENT ON TABLE ctrl.approval_case IS 'CAP-OPS-009 / INV-G-017：双人复核与职责分离；审批通过后的执行绑定本单据且不可重复使用（AT-CTRL-003）';

CREATE OR REPLACE TRIGGER trg_approval_case_touch
    BEFORE UPDATE ON ctrl.approval_case
    FOR EACH ROW EXECUTE FUNCTION core.fn_touch_updated_at();
CREATE OR REPLACE TRIGGER trg_approval_case_public_id
    BEFORE INSERT ON ctrl.approval_case
    FOR EACH ROW EXECUTE FUNCTION core.fn_register_public_id('APPROVAL_CASE');

-- 一个执行引用只能对应一次执行（防止同一审批单被复用）
CREATE UNIQUE INDEX IF NOT EXISTS ux_approval_case_execution
    ON ctrl.approval_case (execution_ref) WHERE execution_ref IS NOT NULL;

CREATE INDEX IF NOT EXISTS ix_approval_case_pending ON ctrl.approval_case (expires_at) WHERE case_state IN ('DRAFT', 'PENDING_REVIEW', 'APPROVED');
CREATE INDEX IF NOT EXISTS ix_approval_case_target ON ctrl.approval_case (target_kind, target_ref, requested_at DESC);

-- -----------------------------------------------------------------------------
-- 4. 安全例外台账（CAP-CTRL-006/007、TERM-EXCEPTION-001）
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ctrl.security_exception (
    id                    uuid        NOT NULL DEFAULT core.uuid_generate_v7(),
    public_id             text        NOT NULL,
    deviated_requirement  text        NOT NULL,
    scope_kind            text        NOT NULL,
    scope_ref             text        NOT NULL,
    exception_state       text        NOT NULL DEFAULT 'ACTIVE',
    description           text        NOT NULL,
    risk_acceptor_ref     text        NOT NULL,
    compensating_control  text        NOT NULL,
    approval_case_id      uuid        NOT NULL,
    approved_at           timestamptz NOT NULL DEFAULT now(),
    expires_at            timestamptz NOT NULL,
    tightened_at          timestamptz NULL,
    renewal_of_id         uuid        NULL,
    review_notes          jsonb       NULL,
    created_at            timestamptz NOT NULL DEFAULT now(),
    updated_at            timestamptz NOT NULL DEFAULT now(),
    row_version           bigint      NOT NULL DEFAULT 1,
    CONSTRAINT pk_security_exception PRIMARY KEY (id),
    CONSTRAINT uq_security_exception_public_id UNIQUE (public_id),
    CONSTRAINT fk_security_exception_approval FOREIGN KEY (approval_case_id) REFERENCES ctrl.approval_case (id),
    CONSTRAINT fk_security_exception_renewal FOREIGN KEY (renewal_of_id) REFERENCES ctrl.security_exception (id),
    CONSTRAINT ck_security_exception_state CHECK (exception_state IN ('ACTIVE', 'EXPIRED', 'TIGHTENED', 'WITHDRAWN')),
    CONSTRAINT ck_security_exception_scope CHECK (scope_kind IN ('PLATFORM', 'BUSINESS_LINE', 'TENANT', 'CLIENT', 'IDENTITY_PROVIDER', 'MACHINE_PRINCIPAL')),
    -- 必须指向具体的规范编号，禁止笼统描述
    CONSTRAINT ck_security_exception_requirement CHECK (
        deviated_requirement ~ '^(REQ|INV|CAP|AT|SLO|TTL|TERM)-[A-Z]+-[0-9]{3}$'
    ),
    -- TERM-EXCEPTION-001：最长 6 个月，到期默认收紧
    CONSTRAINT ck_security_exception_ttl CHECK (expires_at > approved_at AND expires_at - approved_at <= interval '6 months'),
    CONSTRAINT ck_security_exception_tightened CHECK ((exception_state = 'TIGHTENED') = (tightened_at IS NOT NULL))
);
COMMENT ON TABLE ctrl.security_exception IS 'CAP-CTRL-006/007：例外台账是全部 P0 约束的兜底机制；无台账记录的偏离等同违规，到期默认收紧（TERM-EXCEPTION-001）';

CREATE OR REPLACE TRIGGER trg_security_exception_touch
    BEFORE UPDATE ON ctrl.security_exception
    FOR EACH ROW EXECUTE FUNCTION core.fn_touch_updated_at();

CREATE INDEX IF NOT EXISTS ix_security_exception_expiry ON ctrl.security_exception (expires_at) WHERE exception_state = 'ACTIVE';
CREATE INDEX IF NOT EXISTS ix_security_exception_requirement ON ctrl.security_exception (deviated_requirement, exception_state);

-- -----------------------------------------------------------------------------
-- 5. Break-glass（CAP-OPS-011、REQ-CTRL-006：限时、最小权限、使用即告警、事后复核）
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ctrl.break_glass_session (
    id                 uuid        NOT NULL DEFAULT core.uuid_generate_v7(),
    admin_ref          text        NOT NULL,
    session_state      text        NOT NULL DEFAULT 'GRANTED',
    granted_at         timestamptz NOT NULL DEFAULT now(),
    granted_by_ref     text        NOT NULL,
    approval_case_id   uuid        NULL,
    justification      text        NOT NULL,
    scope_permissions  text[]      NOT NULL,
    expires_at         timestamptz NOT NULL,
    first_used_at      timestamptz NULL,
    last_used_at       timestamptz NULL,
    action_count       integer     NOT NULL DEFAULT 0,
    revoked_at         timestamptz NULL,
    post_review_at     timestamptz NULL,
    post_reviewer_ref  text        NULL,
    post_review_result text        NULL,
    CONSTRAINT pk_break_glass_session PRIMARY KEY (id),
    CONSTRAINT fk_break_glass_session_approval FOREIGN KEY (approval_case_id) REFERENCES ctrl.approval_case (id),
    CONSTRAINT ck_break_glass_session_state CHECK (session_state IN ('GRANTED', 'USED', 'EXPIRED', 'REVOKED', 'REVIEWED')),
    CONSTRAINT ck_break_glass_session_separation CHECK (granted_by_ref <> admin_ref),
    -- 限时：最长 4 小时
    CONSTRAINT ck_break_glass_session_ttl CHECK (expires_at > granted_at AND expires_at - granted_at <= interval '4 hours'),
    CONSTRAINT ck_break_glass_session_scope CHECK (array_length(scope_permissions, 1) >= 1),
    -- REQ-CTRL-006：使用后必须事后复核，复核人不得是使用人
    CONSTRAINT ck_break_glass_session_review CHECK (
        (session_state = 'REVIEWED') = (post_review_at IS NOT NULL AND post_reviewer_ref IS NOT NULL)
    ),
    CONSTRAINT ck_break_glass_session_reviewer CHECK (post_reviewer_ref IS NULL OR post_reviewer_ref <> admin_ref)
);
COMMENT ON TABLE ctrl.break_glass_session IS 'CAP-OPS-011 / REQ-CTRL-006：紧急管理员通道，限时、最小权限、使用即告警、到期自动失效并事后复核（AT-CTRL-002）';

CREATE INDEX IF NOT EXISTS ix_break_glass_session_active ON ctrl.break_glass_session (expires_at) WHERE session_state IN ('GRANTED', 'USED');
CREATE INDEX IF NOT EXISTS ix_break_glass_session_review ON ctrl.break_glass_session (granted_at DESC) WHERE post_review_at IS NULL;

SELECT core.fn_apply_standard_grants('kms');
SELECT core.fn_apply_standard_grants('ctrl');

SELECT core.fn_migration_apply('140', 'key_control：密钥与证书台账、JWKS 发布、配置发布、审批单、安全例外、Break-glass');
