-- =============================================================================
-- 060_login_transaction.sql
-- AUTH 域：登录事务、已完成因子、验证 Challenge
-- 依据：能力地图 §4.2、§5.1；蓝图 §8（INV-G-016、REQ-AUTH-004/013/014/015/016）
-- 关键：登录进度以服务端事务为唯一权威，客户端参数不得声明任何步骤已完成
-- 时长基线在数据库层强制：TTL-LOGINTX-001、TTL-CHALLENGE-001
-- =============================================================================

SET client_min_messages = warning;

-- -----------------------------------------------------------------------------
-- 1. 登录事务（CAP-AUTH-021、INV-G-016）
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS auth.login_transaction (
    id                     uuid        NOT NULL DEFAULT core.uuid_generate_v7(),
    public_id              text        NOT NULL,
    client_id              uuid        NOT NULL,
    business_line_id       uuid        NOT NULL,
    tenant_id              uuid        NOT NULL DEFAULT '00000000-0000-0000-0000-000000000000',
    user_id                uuid        NULL,
    transaction_state      text        NOT NULL DEFAULT 'CREATED',
    profile_code           text        NOT NULL,
    -- 授权请求上下文（只存哈希，不存原值：state/nonce 属于一次性凭据）
    response_type          text        NOT NULL,
    requested_scopes       text[]      NOT NULL DEFAULT '{}',
    requested_resources    text[]      NOT NULL DEFAULT '{}',
    redirect_uri           text        NOT NULL,
    state_hash             bytea       NULL,
    nonce_hash             bytea       NULL,
    code_challenge         text        NOT NULL,
    code_challenge_method  text        NOT NULL DEFAULT 'S256',
    prompt_values          text[]      NOT NULL DEFAULT '{}',
    requested_acr_values   text[]      NOT NULL DEFAULT '{}',
    max_age_seconds        integer     NULL,
    ui_locale              text        NULL,
    login_hint_blind_index bytea       NULL,
    -- 保证等级与风险快照（CAP-ASR-002、CAP-AUTH-019）
    required_aal           text        NOT NULL DEFAULT 'AAL1',
    achieved_aal           text        NULL,
    achieved_ial           text        NULL,
    achieved_acr           text        NULL,
    risk_level             text        NULL,
    risk_snapshot          jsonb       NULL,
    remaining_steps        jsonb       NULL,
    pending_consent_scopes text[]      NOT NULL DEFAULT '{}',
    -- 环境证据：不存明文 IP 与 UA
    ip_hash                bytea       NULL,
    ip_region              text        NULL,
    user_agent_hash        bytea       NULL,
    device_fingerprint_hash bytea      NULL,
    expires_at             timestamptz NOT NULL,
    completed_at           timestamptz NULL,
    consumed_at            timestamptz NULL,
    abandoned_at           timestamptz NULL,
    block_reason_code      text        NULL,
    created_at             timestamptz NOT NULL DEFAULT now(),
    updated_at             timestamptz NOT NULL DEFAULT now(),
    row_version            bigint      NOT NULL DEFAULT 1,
    CONSTRAINT pk_login_transaction PRIMARY KEY (id),
    CONSTRAINT uq_login_transaction_public_id UNIQUE (public_id),
    CONSTRAINT fk_login_transaction_client FOREIGN KEY (client_id) REFERENCES oap.client (id),
    CONSTRAINT fk_login_transaction_user FOREIGN KEY (user_id) REFERENCES id.global_user (id),
    CONSTRAINT ck_login_transaction_state CHECK (transaction_state IN (
        'CREATED', 'IDENTIFIED', 'PARTIALLY_AUTHENTICATED', 'PENDING_CONSENT', 'COMPLETED',
        'EXPIRED', 'ABANDONED', 'BLOCKED'
    )),
    -- CAP-OAP-003：只允许 S256，禁止 plain
    CONSTRAINT ck_login_transaction_pkce CHECK (code_challenge_method = 'S256' AND length(code_challenge) BETWEEN 43 AND 128),
    CONSTRAINT ck_login_transaction_response_type CHECK (response_type = 'code'),
    CONSTRAINT ck_login_transaction_aal CHECK (
        required_aal IN ('AAL1', 'AAL2', 'AAL3')
        AND (achieved_aal IS NULL OR achieved_aal IN ('AAL1', 'AAL2', 'AAL3'))
    ),
    -- IDENTIFIED 起必须已知主体
    CONSTRAINT ck_login_transaction_identified CHECK (
        transaction_state IN ('CREATED', 'EXPIRED', 'ABANDONED', 'BLOCKED') OR user_id IS NOT NULL
    ),
    -- INV-G-016：COMPLETED 必须有主体、完成时间与达成的保证等级
    CONSTRAINT ck_login_transaction_completed CHECK (
        (transaction_state = 'COMPLETED') = (completed_at IS NOT NULL AND user_id IS NOT NULL AND achieved_aal IS NOT NULL)
    ),
    CONSTRAINT ck_login_transaction_blocked CHECK (transaction_state <> 'BLOCKED' OR block_reason_code IS NOT NULL),
    -- TTL-LOGINTX-001：≤ 15 分钟，单次消费（用时间差比较以保证表达式 immutable）
    CONSTRAINT ck_login_transaction_ttl CHECK (expires_at > created_at AND expires_at - created_at <= interval '15 minutes')
);
COMMENT ON TABLE auth.login_transaction IS 'CAP-AUTH-021 / INV-G-016：登录与授权事务的服务端权威状态；未达 COMPLETED 不得签发 Session、Token 或授权码（AT-AUTH-013）';
COMMENT ON COLUMN auth.login_transaction.public_id IS '对外事务标识（ltx_xxx）；禁止被当作会话标识使用（INV-G-016）';
COMMENT ON COLUMN auth.login_transaction.consumed_at IS '换取授权码即消费；已消费或已过期的事务不可重放（TTL-LOGINTX-001）';
COMMENT ON COLUMN auth.login_transaction.ip_hash IS 'IP 属于个人信息，只存加盐哈希与粗粒度地区（INV-G-007、CAP-PRIV-006）';

CREATE OR REPLACE TRIGGER trg_login_transaction_touch
    BEFORE UPDATE ON auth.login_transaction
    FOR EACH ROW EXECUTE FUNCTION core.fn_touch_updated_at();

-- 终态不可重开（AT-AUTH-013：重放已完成或已过期事务必须失败）
CREATE OR REPLACE FUNCTION auth.fn_login_transaction_terminal_guard()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF OLD.transaction_state IN ('COMPLETED', 'EXPIRED', 'ABANDONED', 'BLOCKED')
       AND NEW.transaction_state <> OLD.transaction_state THEN
        RAISE EXCEPTION 'INVALID_STATE_TRANSITION: 登录事务 % 已终结，不得重放（INV-G-016、AT-AUTH-013）', OLD.transaction_state
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE OR REPLACE TRIGGER trg_login_transaction_terminal_guard
    BEFORE UPDATE ON auth.login_transaction
    FOR EACH ROW EXECUTE FUNCTION auth.fn_login_transaction_terminal_guard();

CREATE INDEX IF NOT EXISTS ix_login_transaction_expiry
    ON auth.login_transaction (expires_at)
    WHERE transaction_state IN ('CREATED', 'IDENTIFIED', 'PARTIALLY_AUTHENTICATED', 'PENDING_CONSENT');
CREATE INDEX IF NOT EXISTS ix_login_transaction_user ON auth.login_transaction (user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS ix_login_transaction_client ON auth.login_transaction (client_id, created_at DESC);

-- -----------------------------------------------------------------------------
-- 2. 已完成认证因子（amr 的权威来源，CAP-ASR-001：amr 与 acr 不得混用）
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS auth.login_transaction_factor (
    id                   uuid        NOT NULL DEFAULT core.uuid_generate_v7(),
    login_transaction_id uuid        NOT NULL,
    amr_value            text        NOT NULL,
    authenticator_id     uuid        NULL,
    challenge_id         uuid        NULL,
    achieved_aal         text        NOT NULL,
    is_phishing_resistant boolean    NOT NULL DEFAULT false,
    verified_at          timestamptz NOT NULL DEFAULT now(),
    evidence             jsonb       NULL,
    CONSTRAINT pk_login_transaction_factor PRIMARY KEY (id),
    CONSTRAINT uq_login_transaction_factor UNIQUE (login_transaction_id, amr_value),
    CONSTRAINT fk_login_transaction_factor_tx FOREIGN KEY (login_transaction_id) REFERENCES auth.login_transaction (id) ON DELETE CASCADE,
    -- SPLIT-POINT：凭证域拆独立实例时删除本外键
    CONSTRAINT fk_login_transaction_factor_authenticator FOREIGN KEY (authenticator_id) REFERENCES cred.authenticator (id),
    CONSTRAINT ck_login_transaction_factor_amr CHECK (amr_value IN (
        'pwd', 'otp', 'sms', 'email', 'hwk', 'swk', 'user', 'pin', 'face', 'fpt', 'mfa', 'federated', 'carrier', 'rba'
    )),
    CONSTRAINT ck_login_transaction_factor_aal CHECK (achieved_aal IN ('AAL1', 'AAL2', 'AAL3'))
);
COMMENT ON TABLE auth.login_transaction_factor IS 'CAP-ASR-001：amr 表达实际认证方式，acr 表达达成等级，auth_time 表达认证时间，三者分别落列不得混用';

CREATE INDEX IF NOT EXISTS ix_login_transaction_factor_tx ON auth.login_transaction_factor (login_transaction_id);

-- -----------------------------------------------------------------------------
-- 3. 验证 Challenge（CAP-AUTH-002/003、REQ-AUTH-013/014/015、蓝图 §8.1）
-- 短信、邮件、WebAuthn 挑战统一建模：单次消费、绑定用途与事务
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS auth.verification_challenge (
    id                     uuid        NOT NULL DEFAULT core.uuid_generate_v7(),
    public_id              text        NOT NULL,
    challenge_purpose      text        NOT NULL,
    challenge_state        text        NOT NULL DEFAULT 'ISSUED',
    delivery_channel       text        NOT NULL,
    user_id                uuid        NULL,
    client_id              uuid        NULL,
    login_transaction_id   uuid        NULL,
    target_identifier_id   uuid        NULL,
    target_blind_index     bytea       NULL,
    challenge_hash         bytea       NOT NULL,
    attempt_count          integer     NOT NULL DEFAULT 0,
    max_attempts           smallint    NOT NULL DEFAULT 5,
    message_send_id        uuid        NULL,
    risk_level             text        NULL,
    expires_at             timestamptz NOT NULL,
    verified_at            timestamptz NULL,
    consumed_at            timestamptz NULL,
    locked_at              timestamptz NULL,
    cancelled_at           timestamptz NULL,
    superseded_by_id       uuid        NULL,
    created_at             timestamptz NOT NULL DEFAULT now(),
    updated_at             timestamptz NOT NULL DEFAULT now(),
    row_version            bigint      NOT NULL DEFAULT 1,
    CONSTRAINT pk_verification_challenge PRIMARY KEY (id),
    CONSTRAINT uq_verification_challenge_public_id UNIQUE (public_id),
    CONSTRAINT fk_verification_challenge_user FOREIGN KEY (user_id) REFERENCES id.global_user (id),
    CONSTRAINT fk_verification_challenge_client FOREIGN KEY (client_id) REFERENCES oap.client (id),
    CONSTRAINT fk_verification_challenge_tx FOREIGN KEY (login_transaction_id) REFERENCES auth.login_transaction (id) ON DELETE CASCADE,
    CONSTRAINT fk_verification_challenge_identifier FOREIGN KEY (target_identifier_id) REFERENCES id.identifier (id),
    CONSTRAINT fk_verification_challenge_superseded FOREIGN KEY (superseded_by_id) REFERENCES auth.verification_challenge (id),
    CONSTRAINT ck_verification_challenge_purpose CHECK (challenge_purpose IN (
        'REGISTER', 'LOGIN', 'STEP_UP', 'BIND_IDENTIFIER', 'REBIND_OLD', 'REBIND_NEW',
        'PASSWORD_RESET', 'ACCOUNT_RECOVERY', 'DELETE_ACCOUNT', 'DELETE_WITHDRAW',
        'WEBAUTHN_REGISTRATION', 'WEBAUTHN_ASSERTION', 'CONSENT_CONFIRM', 'DOMAIN_VERIFY'
    )),
    CONSTRAINT ck_verification_challenge_state CHECK (challenge_state IN (
        'ISSUED', 'VERIFIED', 'CONSUMED', 'EXPIRED', 'LOCKED', 'CANCELLED'
    )),
    CONSTRAINT ck_verification_challenge_channel CHECK (delivery_channel IN ('SMS', 'EMAIL', 'VOICE', 'PUSH', 'IN_APP', 'NONE')),
    CONSTRAINT ck_verification_challenge_hash CHECK (octet_length(challenge_hash) = 32),
    -- REQ-AUTH-015：验证与消费必须原子推进，状态必须留时间证据
    CONSTRAINT ck_verification_challenge_verified CHECK (challenge_state NOT IN ('VERIFIED', 'CONSUMED') OR verified_at IS NOT NULL),
    CONSTRAINT ck_verification_challenge_consumed CHECK ((challenge_state = 'CONSUMED') = (consumed_at IS NOT NULL)),
    CONSTRAINT ck_verification_challenge_locked CHECK ((challenge_state = 'LOCKED') = (locked_at IS NOT NULL)),
    -- REQ-AUTH-014：必须绑定用途与目标，二者缺一即无法防跨流程复用
    CONSTRAINT ck_verification_challenge_target CHECK (
        target_blind_index IS NOT NULL OR user_id IS NOT NULL
    ),
    -- TTL-CHALLENGE-001：有效期 ≤ 5 分钟，尝试 ≤ 5 次
    CONSTRAINT ck_verification_challenge_ttl CHECK (
        expires_at > created_at AND expires_at - created_at <= interval '5 minutes'
    ),
    CONSTRAINT ck_verification_challenge_attempts CHECK (max_attempts BETWEEN 1 AND 5 AND attempt_count >= 0)
);
COMMENT ON TABLE auth.verification_challenge IS 'CAP-AUTH-002/003 与 REQ-AUTH-013/014/015：验证码与 WebAuthn 挑战；单次消费、绑定用途/Client/事务，禁止跨流程复用（AT-AUTH-009）';
COMMENT ON COLUMN auth.verification_challenge.challenge_hash IS '验证码或挑战值的加盐哈希；原值只出现在投递通道，不落库不入日志（INV-G-007）';
COMMENT ON COLUMN auth.verification_challenge.superseded_by_id IS 'REQ-AUTH-013：重发时旧 Challenge 按策略作废并指向新 Challenge';

CREATE OR REPLACE TRIGGER trg_verification_challenge_touch
    BEFORE UPDATE ON auth.verification_challenge
    FOR EACH ROW EXECUTE FUNCTION core.fn_touch_updated_at();

-- REQ-AUTH-013：同一目标同一用途同时只允许一个 ISSUED Challenge，重发必须先作废旧的
CREATE UNIQUE INDEX IF NOT EXISTS ux_verification_challenge_active_target
    ON auth.verification_challenge (challenge_purpose, target_blind_index)
    WHERE challenge_state = 'ISSUED' AND target_blind_index IS NOT NULL;

CREATE INDEX IF NOT EXISTS ix_verification_challenge_lookup
    ON auth.verification_challenge (target_blind_index, challenge_purpose, challenge_state);
CREATE INDEX IF NOT EXISTS ix_verification_challenge_tx ON auth.verification_challenge (login_transaction_id);
CREATE INDEX IF NOT EXISTS ix_verification_challenge_expiry
    ON auth.verification_challenge (expires_at) WHERE challenge_state = 'ISSUED';

SELECT core.fn_apply_standard_grants('auth');

-- login_transaction_factor.challenge_id 的外键在 verification_challenge 建表后补上
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'fk_login_transaction_factor_challenge'
    ) THEN
        ALTER TABLE auth.login_transaction_factor
            ADD CONSTRAINT fk_login_transaction_factor_challenge
            FOREIGN KEY (challenge_id) REFERENCES auth.verification_challenge (id);
    END IF;
END;
$$;

SELECT core.fn_migration_apply('060', 'login_transaction：登录事务、已完成认证因子、验证 Challenge');
