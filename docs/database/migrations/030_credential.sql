-- =============================================================================
-- 030_credential.sql
-- 凭证域（独立安全域）：密码、认证器、Passkey 元数据、TOTP、恢复码
-- 依据：能力地图 §4.2、§4.20；蓝图 §8.1 认证器状态、REQ-AUTH-005/007/008/009、REQ-KEY-008
-- 隔离：本 schema 只授权给 uc_cred_app；业务服务不得直连（蓝图 §9.1）
-- =============================================================================

SET client_min_messages = warning;

-- -----------------------------------------------------------------------------
-- 1. 认证器（CAP-AUTH-011 至 CAP-AUTH-018、蓝图 §8.1）
-- 所有认证方式统一建模为认证器，密码是其中一种，便于"最后凭证保护"与保证等级计算
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS cred.authenticator (
    id                        uuid        NOT NULL DEFAULT core.uuid_generate_v7(),
    public_id                 text        NOT NULL,
    user_id                   uuid        NOT NULL,
    authenticator_type        text        NOT NULL,
    authenticator_state       text        NOT NULL DEFAULT 'PENDING',
    display_name              text        NULL,
    max_aal                   text        NOT NULL,
    is_phishing_resistant     boolean     NOT NULL DEFAULT false,
    is_hardware_backed        boolean     NOT NULL DEFAULT false,
    -- WebAuthn / Passkey 元数据（CAP-AUTH-012、REQ-AUTH-009）
    webauthn_credential_id    bytea       NULL,
    webauthn_public_key       bytea       NULL,
    webauthn_aaguid           uuid        NULL,
    webauthn_sign_count       bigint      NULL,
    webauthn_uv_capable       boolean     NULL,
    webauthn_is_discoverable  boolean     NULL,
    webauthn_backup_eligible  boolean     NULL,
    webauthn_backed_up        boolean     NULL,
    webauthn_transports       text[]      NULL,
    attestation_format        text        NULL,
    attestation_trust_level   text        NULL,
    -- TOTP：密钥必须加密存储（蓝图 §9.1）
    totp_secret_cipher        bytea       NULL,
    totp_cipher_key_version   smallint    NULL,
    totp_digits               smallint    NULL,
    totp_period_seconds       smallint    NULL,
    -- 登记证据（REQ-AUTH-005：近期认证、风险检查、安全通知）
    registered_at             timestamptz NOT NULL DEFAULT now(),
    registration_aal          text        NULL,
    registration_session_id   uuid        NULL,
    registration_risk_level   text        NULL,
    activated_at              timestamptz NULL,
    last_used_at              timestamptz NULL,
    failed_attempt_count      integer     NOT NULL DEFAULT 0,
    suspended_at              timestamptz NULL,
    locked_until              timestamptz NULL,
    compromised_at            timestamptz NULL,
    revoked_at                timestamptz NULL,
    revoke_reason_code        text        NULL,
    replaced_by_id            uuid        NULL,
    protection_until          timestamptz NULL,
    expires_at                timestamptz NULL,
    created_at                timestamptz NOT NULL DEFAULT now(),
    updated_at                timestamptz NOT NULL DEFAULT now(),
    row_version               bigint      NOT NULL DEFAULT 1,
    CONSTRAINT pk_authenticator PRIMARY KEY (id),
    CONSTRAINT uq_authenticator_public_id UNIQUE (public_id),
    CONSTRAINT uq_authenticator_webauthn_credential UNIQUE (webauthn_credential_id),
    -- SPLIT-POINT：凭证域拆独立实例时删除本外键，改为应用层校验 + 定期对账
    CONSTRAINT fk_authenticator_user FOREIGN KEY (user_id) REFERENCES id.global_user (id),
    CONSTRAINT fk_authenticator_replaced_by FOREIGN KEY (replaced_by_id) REFERENCES cred.authenticator (id),
    CONSTRAINT ck_authenticator_type CHECK (authenticator_type IN (
        'PASSWORD', 'TOTP', 'PASSKEY', 'SECURITY_KEY', 'RECOVERY_CODE',
        'SMS_OTP', 'EMAIL_OTP', 'CARRIER_ONE_CLICK', 'PUSH_APPROVAL'
    )),
    CONSTRAINT ck_authenticator_state CHECK (authenticator_state IN (
        'PENDING', 'ACTIVE', 'SUSPENDED', 'LOCKED', 'EXPIRED', 'COMPROMISED', 'REVOKED', 'REPLACED'
    )),
    CONSTRAINT ck_authenticator_aal CHECK (max_aal IN ('AAL1', 'AAL2', 'AAL3')),
    -- Passkey/安全密钥必须具备 WebAuthn 三要素
    CONSTRAINT ck_authenticator_webauthn CHECK (
        authenticator_type NOT IN ('PASSKEY', 'SECURITY_KEY')
        OR (webauthn_credential_id IS NOT NULL AND webauthn_public_key IS NOT NULL AND webauthn_aaguid IS NOT NULL)
    ),
    -- TOTP 必须有加密密钥与版本，禁止明文
    CONSTRAINT ck_authenticator_totp CHECK (
        authenticator_type <> 'TOTP'
        OR (totp_secret_cipher IS NOT NULL AND totp_cipher_key_version IS NOT NULL)
    ),
    -- 抗钓鱼只允许 WebAuthn 家族声明（CAP-AUTH-018）
    CONSTRAINT ck_authenticator_phishing_resistant CHECK (
        NOT is_phishing_resistant OR authenticator_type IN ('PASSKEY', 'SECURITY_KEY')
    ),
    -- 终态必须留证据；REPLACED 必须指向后继（能力地图 §5.6 第 4 步）
    CONSTRAINT ck_authenticator_revoked CHECK (
        authenticator_state NOT IN ('REVOKED', 'COMPROMISED') OR revoked_at IS NOT NULL OR compromised_at IS NOT NULL
    ),
    CONSTRAINT ck_authenticator_replaced CHECK (
        (authenticator_state = 'REPLACED') = (replaced_by_id IS NOT NULL)
    ),
    CONSTRAINT ck_authenticator_locked CHECK (authenticator_state <> 'LOCKED' OR locked_until IS NOT NULL)
);
COMMENT ON TABLE cred.authenticator IS 'CAP-AUTH-014/015/016 认证器生命周期；蓝图 §8.1 状态机；REVOKED/REPLACED 为终态且保留审计（AT-AUTH-011）';
COMMENT ON COLUMN cred.authenticator.protection_until IS 'TERM-REBIND-001：替换或挂失后的保护期，期内限制敏感操作并双渠道通知';
COMMENT ON COLUMN cred.authenticator.webauthn_backed_up IS 'REQ-AUTH-009 备份状态；同步型 Passkey 与设备绑定型的保证等级不同，不得混算';

CREATE OR REPLACE TRIGGER trg_authenticator_touch
    BEFORE UPDATE ON cred.authenticator
    FOR EACH ROW EXECUTE FUNCTION core.fn_touch_updated_at();

-- 终态不可复活（AT-AUTH-011）
CREATE OR REPLACE FUNCTION cred.fn_authenticator_terminal_guard()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF OLD.authenticator_state IN ('REVOKED', 'REPLACED')
       AND NEW.authenticator_state <> OLD.authenticator_state THEN
        RAISE EXCEPTION 'INVALID_STATE_TRANSITION: 认证器 % 为终态，不能重新激活（AT-AUTH-011）', OLD.authenticator_state
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE OR REPLACE TRIGGER trg_authenticator_terminal_guard
    BEFORE UPDATE ON cred.authenticator
    FOR EACH ROW EXECUTE FUNCTION cred.fn_authenticator_terminal_guard();

-- 冻结主体不得登记认证器（能力地图不变量 5、INV-G-013）
CREATE OR REPLACE FUNCTION cred.fn_authenticator_register_guard()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    PERFORM id.fn_assert_user_operable(NEW.user_id);
    RETURN NEW;
END;
$$;

CREATE OR REPLACE TRIGGER trg_authenticator_register_guard
    BEFORE INSERT ON cred.authenticator
    FOR EACH ROW EXECUTE FUNCTION cred.fn_authenticator_register_guard();

-- 一个用户同类型只允许一个 ACTIVE 密码认证器
CREATE UNIQUE INDEX IF NOT EXISTS ux_authenticator_active_password
    ON cred.authenticator (user_id)
    WHERE authenticator_type = 'PASSWORD' AND authenticator_state = 'ACTIVE';

CREATE INDEX IF NOT EXISTS ix_authenticator_user_state
    ON cred.authenticator (user_id, authenticator_state, authenticator_type);
CREATE INDEX IF NOT EXISTS ix_authenticator_protection
    ON cred.authenticator (protection_until) WHERE protection_until IS NOT NULL;
CREATE INDEX IF NOT EXISTS ix_authenticator_expiry
    ON cred.authenticator (expires_at) WHERE expires_at IS NOT NULL;

-- -----------------------------------------------------------------------------
-- 2. 密码凭证（CAP-AUTH-004、CAP-AUTH-005、REQ-AUTH-008）
-- 与 cred.authenticator 的 PASSWORD 行一一对应：认证器表管状态，本表管哈希材料
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS cred.password_credential (
    id                    uuid        NOT NULL DEFAULT core.uuid_generate_v7(),
    authenticator_id      uuid        NOT NULL,
    user_id               uuid        NOT NULL,
    -- PHC 字符串，自带算法标识、参数与盐，例如 $argon2id$v=19$m=65536,t=3,p=4$...
    password_hash         text        NOT NULL,
    hash_algorithm        text        NOT NULL,
    hash_param_version    smallint    NOT NULL,
    needs_rehash          boolean     NOT NULL DEFAULT false,
    breach_checked_at     timestamptz NULL,
    set_at                timestamptz NOT NULL DEFAULT now(),
    set_source            text        NOT NULL,
    must_change_at        timestamptz NULL,
    created_at            timestamptz NOT NULL DEFAULT now(),
    updated_at            timestamptz NOT NULL DEFAULT now(),
    row_version           bigint      NOT NULL DEFAULT 1,
    CONSTRAINT pk_password_credential PRIMARY KEY (id),
    CONSTRAINT uq_password_credential_authenticator UNIQUE (authenticator_id),
    CONSTRAINT fk_password_credential_authenticator FOREIGN KEY (authenticator_id) REFERENCES cred.authenticator (id) ON DELETE CASCADE,
    CONSTRAINT ck_password_credential_algorithm CHECK (hash_algorithm IN ('ARGON2ID', 'SCRYPT', 'PBKDF2_SHA256', 'BCRYPT', 'SM3_KDF')),
    CONSTRAINT ck_password_credential_source CHECK (set_source IN ('USER_SET', 'USER_RESET', 'ADMIN_RESET', 'MIGRATION_IMPORT')),
    -- 禁止误存明文：PHC 串必须以 $ 开头
    CONSTRAINT ck_password_credential_phc CHECK (password_hash LIKE '$%' AND length(password_hash) >= 20)
);
COMMENT ON TABLE cred.password_credential IS 'REQ-AUTH-008：可升级的自适应哈希 + 泄漏口令检查；hash_param_version 支持参数升级（CAP-AUTH-005）';
COMMENT ON COLUMN cred.password_credential.hash_algorithm IS '算法取值受 CAP-KEY-006 合规基线约束；境内密评适用时按商用密码要求选型';

CREATE OR REPLACE TRIGGER trg_password_credential_touch
    BEFORE UPDATE ON cred.password_credential
    FOR EACH ROW EXECUTE FUNCTION core.fn_touch_updated_at();

CREATE INDEX IF NOT EXISTS ix_password_credential_rehash ON cred.password_credential (needs_rehash) WHERE needs_rehash;

-- 历史口令（CAP-AUTH-005 历史口令策略），追加型，按策略保留最近 N 条
CREATE TABLE IF NOT EXISTS cred.password_history (
    id              uuid        NOT NULL DEFAULT core.uuid_generate_v7(),
    user_id         uuid        NOT NULL,
    password_hash   text        NOT NULL,
    hash_algorithm  text        NOT NULL,
    retired_at      timestamptz NOT NULL DEFAULT now(),
    retire_reason   text        NOT NULL,
    CONSTRAINT pk_password_history PRIMARY KEY (id),
    CONSTRAINT ck_password_history_reason CHECK (retire_reason IN ('CHANGED', 'RESET', 'COMPROMISED', 'REHASHED')),
    CONSTRAINT ck_password_history_phc CHECK (password_hash LIKE '$%')
);
COMMENT ON TABLE cred.password_history IS 'CAP-AUTH-005 历史口令策略；仅用于"禁止复用最近 N 个口令"判定，不用于认证';

CREATE INDEX IF NOT EXISTS ix_password_history_user ON cred.password_history (user_id, retired_at DESC);

-- -----------------------------------------------------------------------------
-- 3. 恢复码（CAP-AUTH-017、REQ-AUTH-007：哈希存储、单次使用、新批次使旧批次全部失效）
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS cred.recovery_code_batch (
    id              uuid        NOT NULL DEFAULT core.uuid_generate_v7(),
    user_id         uuid        NOT NULL,
    authenticator_id uuid       NOT NULL,
    batch_no        integer     NOT NULL,
    code_count      integer     NOT NULL,
    generated_at    timestamptz NOT NULL DEFAULT now(),
    generated_via   text        NOT NULL,
    invalidated_at  timestamptz NULL,
    CONSTRAINT pk_recovery_code_batch PRIMARY KEY (id),
    CONSTRAINT uq_recovery_code_batch_no UNIQUE (user_id, batch_no),
    CONSTRAINT fk_recovery_code_batch_authenticator FOREIGN KEY (authenticator_id) REFERENCES cred.authenticator (id) ON DELETE CASCADE,
    CONSTRAINT ck_recovery_code_batch_count CHECK (code_count BETWEEN 1 AND 50)
);
COMMENT ON TABLE cred.recovery_code_batch IS 'REQ-AUTH-007：生成新批次时旧批次全部失效，由 ux_recovery_code_batch_active 保证同时只有一个有效批次';

CREATE UNIQUE INDEX IF NOT EXISTS ux_recovery_code_batch_active
    ON cred.recovery_code_batch (user_id) WHERE invalidated_at IS NULL;

CREATE TABLE IF NOT EXISTS cred.recovery_code (
    id            uuid        NOT NULL DEFAULT core.uuid_generate_v7(),
    batch_id      uuid        NOT NULL,
    code_hash     bytea       NOT NULL,
    used_at       timestamptz NULL,
    used_context  jsonb       NULL,
    CONSTRAINT pk_recovery_code PRIMARY KEY (id),
    CONSTRAINT uq_recovery_code_hash UNIQUE (code_hash),
    CONSTRAINT fk_recovery_code_batch FOREIGN KEY (batch_id) REFERENCES cred.recovery_code_batch (id) ON DELETE CASCADE,
    CONSTRAINT ck_recovery_code_hash CHECK (octet_length(code_hash) = 32)
);
COMMENT ON TABLE cred.recovery_code IS 'REQ-AUTH-007：一次展示、哈希存储、单次使用；used_at 由条件更新写入以保证并发下最多一人成功';

CREATE INDEX IF NOT EXISTS ix_recovery_code_batch ON cred.recovery_code (batch_id) WHERE used_at IS NULL;

-- -----------------------------------------------------------------------------
-- 4. 授权：凭证域仅对认证服务角色开放
-- -----------------------------------------------------------------------------
SELECT core.fn_apply_credential_grants('cred');
-- password_history 不设为追加型：“保留最近 N 条”的保留策略要求可删除旧记录

SELECT core.fn_migration_apply('030', 'credential：认证器、密码凭证与历史、恢复码；凭证域独立授权');
