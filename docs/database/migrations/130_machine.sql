-- =============================================================================
-- 130_machine.sql
-- MACHINE 域：机器主体、机器凭证、工作负载证明、Token Exchange 委托链
-- 依据：能力地图 §4.15；蓝图 §13（REQ-MACHINE-001 至 016）
-- 关键：机器主体不得拥有自然人的核验断言与恢复能力；委托链深度受限且不得扩权
-- =============================================================================

SET client_min_messages = warning;

-- -----------------------------------------------------------------------------
-- 1. 机器主体（CAP-MACHINE-001/002、REQ-MACHINE-001）
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS machine.machine_principal (
    id                   uuid        NOT NULL DEFAULT core.uuid_generate_v7(),
    public_id            text        NOT NULL,
    principal_kind       text        NOT NULL,
    display_name         text        NOT NULL,
    principal_state      text        NOT NULL DEFAULT 'PROVISIONING',
    business_line_id     uuid        NOT NULL,
    tenant_id            uuid        NOT NULL DEFAULT '00000000-0000-0000-0000-000000000000',
    environment          text        NOT NULL,
    purpose              text        NOT NULL,
    owner_ref            text        NOT NULL,
    owner_backup_ref     text        NULL,
    code_source_ref      text        NULL,
    trust_domain         text        NULL,
    workload_selector    jsonb       NULL,
    max_delegation_depth smallint    NOT NULL DEFAULT 1,
    allowed_audiences    text[]      NOT NULL DEFAULT '{}',
    security_epoch       bigint      NOT NULL DEFAULT 1,
    expires_at           timestamptz NOT NULL,
    last_used_at         timestamptz NULL,
    last_reviewed_at     timestamptz NULL,
    suspended_at         timestamptz NULL,
    suspend_reason_code  text        NULL,
    compromised_at       timestamptz NULL,
    retired_at           timestamptz NULL,
    created_at           timestamptz NOT NULL DEFAULT now(),
    updated_at           timestamptz NOT NULL DEFAULT now(),
    row_version          bigint      NOT NULL DEFAULT 1,
    CONSTRAINT pk_machine_principal PRIMARY KEY (id),
    CONSTRAINT uq_machine_principal_public_id UNIQUE (public_id),
    CONSTRAINT fk_machine_principal_business_line FOREIGN KEY (business_line_id) REFERENCES tenant.business_line (id),
    CONSTRAINT ck_machine_principal_kind CHECK (principal_kind IN (
        'SERVICE_ACCOUNT', 'WORKLOAD', 'BOT', 'AGENT', 'DEVICE', 'CI_CD'
    )),
    CONSTRAINT ck_machine_principal_state CHECK (principal_state IN ('PROVISIONING', 'ACTIVE', 'SUSPENDED', 'COMPROMISED', 'RETIRED')),
    CONSTRAINT ck_machine_principal_environment CHECK (environment IN ('DEV', 'TEST', 'STAGING', 'PROD')),
    -- REQ-MACHINE-001：负责人、用途、环境、到期日缺一不可
    CONSTRAINT ck_machine_principal_expiry CHECK (expires_at > created_at),
    -- REQ-MACHINE-007：委托深度必须有上限
    CONSTRAINT ck_machine_principal_depth CHECK (max_delegation_depth BETWEEN 0 AND 3),
    -- CAP-MACHINE-004：工作负载类主体必须登记 trust domain 与选择器（REQ-MACHINE-012）
    CONSTRAINT ck_machine_principal_workload CHECK (
        principal_kind <> 'WORKLOAD' OR (trust_domain IS NOT NULL AND workload_selector IS NOT NULL)
    ),
    CONSTRAINT ck_machine_principal_suspended CHECK (
        principal_state <> 'SUSPENDED' OR (suspended_at IS NOT NULL AND suspend_reason_code IS NOT NULL)
    ),
    CONSTRAINT ck_machine_principal_epoch CHECK (security_epoch >= 1)
);
COMMENT ON TABLE machine.machine_principal IS 'CAP-MACHINE-001/002：非自然人主体台账；无负责人或到期未复核即进入 SUSPENDED（蓝图 §13.3、AT-MACHINE-005）';
COMMENT ON COLUMN machine.machine_principal.max_delegation_depth IS 'REQ-MACHINE-007：Token Exchange 委托深度上限，0 表示不允许作为委托中继';

CREATE OR REPLACE TRIGGER trg_machine_principal_touch
    BEFORE UPDATE ON machine.machine_principal
    FOR EACH ROW EXECUTE FUNCTION core.fn_touch_updated_at();
CREATE OR REPLACE TRIGGER trg_machine_principal_epoch
    BEFORE UPDATE ON machine.machine_principal
    FOR EACH ROW EXECUTE FUNCTION core.fn_forbid_epoch_decrease('security_epoch');
CREATE OR REPLACE TRIGGER trg_machine_principal_public_id
    BEFORE INSERT ON machine.machine_principal
    FOR EACH ROW EXECUTE FUNCTION core.fn_register_public_id('MACHINE_PRINCIPAL');

CREATE INDEX IF NOT EXISTS ix_machine_principal_owner ON machine.machine_principal (owner_ref, principal_state);
CREATE INDEX IF NOT EXISTS ix_machine_principal_expiry ON machine.machine_principal (expires_at) WHERE principal_state = 'ACTIVE';
CREATE INDEX IF NOT EXISTS ix_machine_principal_idle ON machine.machine_principal (last_used_at) WHERE principal_state = 'ACTIVE';

-- -----------------------------------------------------------------------------
-- 2. 机器凭证（REQ-MACHINE-003：短期凭证优先，减少静态密钥）
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS machine.machine_credential (
    id                 uuid        NOT NULL DEFAULT core.uuid_generate_v7(),
    principal_id       uuid        NOT NULL,
    credential_kind    text        NOT NULL,
    credential_state   text        NOT NULL DEFAULT 'ACTIVE',
    key_id             text        NULL,
    public_jwk         jsonb       NULL,
    cert_thumbprint_s256 bytea     NULL,
    secret_hash        text        NULL,
    federation_subject text        NULL,
    not_before         timestamptz NOT NULL DEFAULT now(),
    not_after          timestamptz NOT NULL,
    rotated_from_id    uuid        NULL,
    last_used_at       timestamptz NULL,
    revoked_at         timestamptz NULL,
    revoke_reason_code text        NULL,
    created_at         timestamptz NOT NULL DEFAULT now(),
    updated_at         timestamptz NOT NULL DEFAULT now(),
    row_version        bigint      NOT NULL DEFAULT 1,
    CONSTRAINT pk_machine_credential PRIMARY KEY (id),
    CONSTRAINT uq_machine_credential_kid UNIQUE (principal_id, key_id),
    CONSTRAINT fk_machine_credential_principal FOREIGN KEY (principal_id) REFERENCES machine.machine_principal (id) ON DELETE CASCADE,
    CONSTRAINT fk_machine_credential_rotated_from FOREIGN KEY (rotated_from_id) REFERENCES machine.machine_credential (id),
    CONSTRAINT ck_machine_credential_kind CHECK (credential_kind IN ('PUBLIC_JWK', 'MTLS_CERT', 'WORKLOAD_FEDERATION', 'SECRET')),
    CONSTRAINT ck_machine_credential_state CHECK (credential_state IN ('ACTIVE', 'GRACE', 'EXPIRED', 'REVOKED')),
    CONSTRAINT ck_machine_credential_material CHECK (
        (credential_kind = 'PUBLIC_JWK' AND public_jwk IS NOT NULL AND key_id IS NOT NULL)
        OR (credential_kind = 'MTLS_CERT' AND cert_thumbprint_s256 IS NOT NULL)
        OR (credential_kind = 'WORKLOAD_FEDERATION' AND federation_subject IS NOT NULL)
        OR (credential_kind = 'SECRET' AND secret_hash IS NOT NULL AND secret_hash LIKE '$%')
    ),
    -- REQ-MACHINE-003：静态密钥必须短期，超过 90 天视为违规配置
    CONSTRAINT ck_machine_credential_static_ttl CHECK (
        credential_kind <> 'SECRET' OR not_after - not_before <= interval '90 days'
    ),
    CONSTRAINT ck_machine_credential_window CHECK (not_after > not_before),
    CONSTRAINT ck_machine_credential_revoked CHECK ((credential_state = 'REVOKED') = (revoked_at IS NOT NULL))
);
COMMENT ON TABLE machine.machine_credential IS 'REQ-MACHINE-003/011：优先 private_key_jwt、mTLS 或工作负载联合；失陷可立即阻止签发并追踪影响（AT-MACHINE-006）';

CREATE OR REPLACE TRIGGER trg_machine_credential_touch
    BEFORE UPDATE ON machine.machine_credential
    FOR EACH ROW EXECUTE FUNCTION core.fn_touch_updated_at();

CREATE INDEX IF NOT EXISTS ix_machine_credential_expiry ON machine.machine_credential (not_after) WHERE credential_state IN ('ACTIVE', 'GRACE');

-- -----------------------------------------------------------------------------
-- 3. 工作负载证明（REQ-MACHINE-012/013：每次签发都是独立短期实例）
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS machine.attestation_record (
    id                    uuid        NOT NULL DEFAULT core.uuid_generate_v7(),
    principal_id          uuid        NULL,
    attestation_state     text        NOT NULL DEFAULT 'ATTESTATION_RECEIVED',
    trust_domain          text        NOT NULL,
    issuer                text        NOT NULL,
    audience_value        text        NOT NULL,
    subject_ref           text        NOT NULL,
    jti                   text        NOT NULL,
    nonce_hash            bytea       NULL,
    environment           text        NOT NULL,
    environment_binding   jsonb       NULL,
    attestation_age_ms    integer     NULL,
    received_at           timestamptz NOT NULL DEFAULT now(),
    verified_at           timestamptz NULL,
    credential_issued_at  timestamptz NULL,
    issued_credential_id  uuid        NULL,
    expires_at            timestamptz NOT NULL,
    rejection_reason_code text        NULL,
    CONSTRAINT pk_attestation_record PRIMARY KEY (id),
    -- REQ-MACHINE-016：jti 在有效窗口内全局防重放，且不得跨端点、环境、主体复用
    CONSTRAINT uq_attestation_record_jti UNIQUE (issuer, jti),
    CONSTRAINT fk_attestation_record_principal FOREIGN KEY (principal_id) REFERENCES machine.machine_principal (id),
    CONSTRAINT fk_attestation_record_credential FOREIGN KEY (issued_credential_id) REFERENCES machine.machine_credential (id),
    CONSTRAINT ck_attestation_record_state CHECK (attestation_state IN (
        'ATTESTATION_RECEIVED', 'VERIFIED', 'CREDENTIAL_ISSUED', 'EXPIRED', 'REVOKED', 'REJECTED'
    )),
    CONSTRAINT ck_attestation_record_environment CHECK (environment IN ('DEV', 'TEST', 'STAGING', 'PROD')),
    CONSTRAINT ck_attestation_record_verified CHECK (attestation_state NOT IN ('VERIFIED', 'CREDENTIAL_ISSUED') OR verified_at IS NOT NULL),
    CONSTRAINT ck_attestation_record_issued CHECK (
        (attestation_state = 'CREDENTIAL_ISSUED') = (credential_issued_at IS NOT NULL AND issued_credential_id IS NOT NULL)
    ),
    CONSTRAINT ck_attestation_record_rejected CHECK (attestation_state <> 'REJECTED' OR rejection_reason_code IS NOT NULL),
    -- 一次通过不得被永久缓存为可信：证明记录本身短期过期
    CONSTRAINT ck_attestation_record_ttl CHECK (expires_at - received_at <= interval '15 minutes')
);
COMMENT ON TABLE machine.attestation_record IS 'REQ-MACHINE-012/013：证明校验含签名、issuer、audience、时间、jti 重放与环境绑定，成功后只签发短期凭证（AT-MACHINE-007/008）';

CREATE INDEX IF NOT EXISTS ix_attestation_record_principal ON machine.attestation_record (principal_id, received_at DESC);
CREATE INDEX IF NOT EXISTS ix_attestation_record_expiry ON machine.attestation_record (expires_at);

-- -----------------------------------------------------------------------------
-- 4. Token Exchange 与委托链（REQ-MACHINE-006/007/008、INV-G-018）
-- 追加型：委托链是不可抵赖证据
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS machine.token_exchange_record (
    id                    uuid        NOT NULL DEFAULT core.uuid_generate_v7(),
    exchanged_at          timestamptz NOT NULL DEFAULT now(),
    requesting_client_id  uuid        NOT NULL,
    actor_kind            text        NOT NULL,
    actor_ref             text        NOT NULL,
    subject_kind          text        NOT NULL,
    subject_ref           text        NOT NULL,
    target_audience       text        NOT NULL,
    requested_scopes      text[]      NOT NULL DEFAULT '{}',
    granted_scopes        text[]      NOT NULL DEFAULT '{}',
    delegation_chain      jsonb       NOT NULL,
    delegation_depth      smallint    NOT NULL,
    delegation_ref        uuid        NULL,
    tenant_id             uuid        NOT NULL DEFAULT '00000000-0000-0000-0000-000000000000',
    result_code           text        NOT NULL,
    trace_id              text        NULL,
    CONSTRAINT pk_token_exchange_record PRIMARY KEY (id),
    CONSTRAINT fk_token_exchange_record_client FOREIGN KEY (requesting_client_id) REFERENCES oap.client (id),
    CONSTRAINT ck_token_exchange_record_actor CHECK (actor_kind IN ('MACHINE_PRINCIPAL', 'USER', 'CLIENT')),
    CONSTRAINT ck_token_exchange_record_subject CHECK (subject_kind IN ('USER', 'MACHINE_PRINCIPAL')),
    CONSTRAINT ck_token_exchange_record_depth CHECK (delegation_depth BETWEEN 1 AND 3),
    CONSTRAINT ck_token_exchange_record_result CHECK (result_code IN ('GRANTED', 'DENIED_DEPTH', 'DENIED_SCOPE', 'DENIED_TENANT', 'DENIED_ACTOR', 'DENIED_DELEGATION_REVOKED')),
    -- REQ-MACHINE-008：授予范围不得超过请求范围（不扩权的最小结构保证）
    CONSTRAINT ck_token_exchange_record_no_escalation CHECK (granted_scopes <@ requested_scopes)
);
COMMENT ON TABLE machine.token_exchange_record IS 'REQ-MACHINE-007/008 与 INV-G-018：保留 Subject、Actor、委托链与深度；禁止无边界 impersonation（AT-MACHINE-004）';

CREATE OR REPLACE TRIGGER trg_token_exchange_record_append_only
    BEFORE UPDATE OR DELETE ON machine.token_exchange_record
    FOR EACH STATEMENT EXECUTE FUNCTION core.fn_append_only();

CREATE INDEX IF NOT EXISTS ix_token_exchange_record_subject ON machine.token_exchange_record (subject_ref, exchanged_at DESC);
CREATE INDEX IF NOT EXISTS ix_token_exchange_record_actor ON machine.token_exchange_record (actor_ref, exchanged_at DESC);
CREATE INDEX IF NOT EXISTS ix_token_exchange_record_denied ON machine.token_exchange_record (exchanged_at DESC) WHERE result_code <> 'GRANTED';

SELECT core.fn_apply_standard_grants('machine');
SELECT core.fn_apply_append_only_grants('machine', 'token_exchange_record');

-- -----------------------------------------------------------------------------
-- 5. 补上 SESSION 域对机器主体的外键（070 层建表时 machine schema 尚未存在）
-- -----------------------------------------------------------------------------
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fk_authorization_grant_machine') THEN
        ALTER TABLE session.authorization_grant
            ADD CONSTRAINT fk_authorization_grant_machine
            FOREIGN KEY (machine_principal_id) REFERENCES machine.machine_principal (id);
    END IF;

    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fk_token_family_machine') THEN
        ALTER TABLE session.token_family
            ADD CONSTRAINT fk_token_family_machine
            FOREIGN KEY (machine_principal_id) REFERENCES machine.machine_principal (id);
    END IF;

    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fk_access_token_reference_machine') THEN
        ALTER TABLE session.access_token_reference
            ADD CONSTRAINT fk_access_token_reference_machine
            FOREIGN KEY (machine_principal_id) REFERENCES machine.machine_principal (id);
    END IF;
END;
$$;

SELECT core.fn_migration_apply('130', 'machine：机器主体、机器凭证、工作负载证明、Token Exchange 委托链');
