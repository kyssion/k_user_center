-- =============================================================================
-- 070_session_token.sql
-- SESSION 域：设备、会话、授权 Grant、Token 家族与实例、授权码、撤销记录、退出对账
-- 依据：能力地图 §4.3、§5.7；蓝图 §9（REQ-SESSION-001 至 016、INV-G-013/014/016）
-- 关键：
--   1) 每个 Token Family 任一时刻最多一个 CURRENT 实例（REQ-SESSION-002）
--   2) 会话只能由 COMPLETED 的登录事务派生（INV-G-016）
--   3) 冻结主体不得新建会话（INV-G-013）
-- =============================================================================

SET client_min_messages = warning;

-- -----------------------------------------------------------------------------
-- 1. 设备（CAP-SESSION-004/006；生命周期独立于会话）
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS session.device (
    id                      uuid        NOT NULL DEFAULT core.uuid_generate_v7(),
    public_id               text        NOT NULL,
    user_id                 uuid        NOT NULL,
    lifecycle_state         text        NOT NULL DEFAULT 'REGISTERED',
    trust_state             text        NOT NULL DEFAULT 'UNTRUSTED',
    device_fingerprint_hash bytea       NOT NULL,
    display_name            text        NULL,
    platform                text        NULL,
    push_token_cipher       bytea       NULL,
    push_cipher_key_version smallint    NULL,
    first_seen_at           timestamptz NOT NULL DEFAULT now(),
    last_seen_at            timestamptz NOT NULL DEFAULT now(),
    trusted_at              timestamptz NULL,
    trust_expires_at        timestamptz NULL,
    lost_at                 timestamptz NULL,
    retired_at              timestamptz NULL,
    revoked_at              timestamptz NULL,
    revoke_reason_code      text        NULL,
    created_at              timestamptz NOT NULL DEFAULT now(),
    updated_at              timestamptz NOT NULL DEFAULT now(),
    row_version             bigint      NOT NULL DEFAULT 1,
    CONSTRAINT pk_device PRIMARY KEY (id),
    CONSTRAINT uq_device_public_id UNIQUE (public_id),
    CONSTRAINT uq_device_fingerprint UNIQUE (user_id, device_fingerprint_hash),
    CONSTRAINT fk_device_user FOREIGN KEY (user_id) REFERENCES id.global_user (id),
    CONSTRAINT ck_device_lifecycle CHECK (lifecycle_state IN ('REGISTERED', 'LOST', 'RETIRED', 'REVOKED')),
    CONSTRAINT ck_device_trust CHECK (trust_state IN ('UNTRUSTED', 'TRUSTED')),
    CONSTRAINT ck_device_trusted CHECK (trust_state <> 'TRUSTED' OR trusted_at IS NOT NULL),
    -- 挂失或撤销的设备不得保留可信标记（能力地图 §3.4 设备状态）
    CONSTRAINT ck_device_lost_untrusted CHECK (lifecycle_state NOT IN ('LOST', 'REVOKED') OR trust_state = 'UNTRUSTED'),
    CONSTRAINT ck_device_lost CHECK ((lifecycle_state = 'LOST') = (lost_at IS NOT NULL)),
    CONSTRAINT ck_device_fingerprint CHECK (octet_length(device_fingerprint_hash) = 32)
);
COMMENT ON TABLE session.device IS 'CAP-SESSION-004/006：设备实体，生命周期独立于会话；挂失即撤销该设备全部会话、Token 家族与可信标记';

CREATE OR REPLACE TRIGGER trg_device_touch
    BEFORE UPDATE ON session.device
    FOR EACH ROW EXECUTE FUNCTION core.fn_touch_updated_at();

CREATE INDEX IF NOT EXISTS ix_device_user ON session.device (user_id, lifecycle_state);
CREATE INDEX IF NOT EXISTS ix_device_trust_expiry ON session.device (trust_expires_at) WHERE trust_state = 'TRUSTED';

-- -----------------------------------------------------------------------------
-- 2. 会话（CAP-SESSION-003；OP Session 与 Device Session）
-- RP 本地会话由业务应用自行保存，平台只通过后通道退出通知其关闭（REQ-SESSION-008）
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS session.user_session (
    id                        uuid        NOT NULL DEFAULT core.uuid_generate_v7(),
    public_id                 text        NOT NULL,
    session_kind              text        NOT NULL DEFAULT 'OP',
    parent_session_id         uuid        NULL,
    user_id                   uuid        NOT NULL,
    device_id                 uuid        NULL,
    login_transaction_id      uuid        NOT NULL,
    origin_client_id          uuid        NOT NULL,
    business_line_id          uuid        NOT NULL,
    tenant_id                 uuid        NOT NULL DEFAULT '00000000-0000-0000-0000-000000000000',
    session_state             text        NOT NULL DEFAULT 'ACTIVE',
    profile_code              text        NOT NULL,
    achieved_aal              text        NOT NULL,
    achieved_ial              text        NULL,
    achieved_acr              text        NULL,
    amr_values                text[]      NOT NULL DEFAULT '{}',
    auth_time                 timestamptz NOT NULL,
    last_reauth_at            timestamptz NULL,
    user_epoch_at_issue       bigint      NOT NULL,
    client_epoch_at_issue     bigint      NOT NULL,
    tenant_epoch_at_issue     bigint      NULL,
    idle_expires_at           timestamptz NOT NULL,
    absolute_expires_at       timestamptz NOT NULL,
    ip_hash                   bytea       NULL,
    ip_region                 text        NULL,
    user_agent_hash           bytea       NULL,
    risk_level                text        NULL,
    compromised_at            timestamptz NULL,
    revoked_at                timestamptz NULL,
    revoke_reason_code        text        NULL,
    created_at                timestamptz NOT NULL DEFAULT now(),
    updated_at                timestamptz NOT NULL DEFAULT now(),
    row_version               bigint      NOT NULL DEFAULT 1,
    CONSTRAINT pk_user_session PRIMARY KEY (id),
    CONSTRAINT uq_user_session_public_id UNIQUE (public_id),
    CONSTRAINT fk_user_session_parent FOREIGN KEY (parent_session_id) REFERENCES session.user_session (id),
    CONSTRAINT fk_user_session_user FOREIGN KEY (user_id) REFERENCES id.global_user (id),
    CONSTRAINT fk_user_session_device FOREIGN KEY (device_id) REFERENCES session.device (id),
    CONSTRAINT fk_user_session_login_tx FOREIGN KEY (login_transaction_id) REFERENCES auth.login_transaction (id),
    CONSTRAINT fk_user_session_client FOREIGN KEY (origin_client_id) REFERENCES oap.client (id),
    CONSTRAINT ck_user_session_kind CHECK (session_kind IN ('OP', 'DEVICE')),
    CONSTRAINT ck_user_session_state CHECK (session_state IN ('ACTIVE', 'EXPIRED', 'COMPROMISED', 'REVOKED')),
    CONSTRAINT ck_user_session_aal CHECK (achieved_aal IN ('AAL1', 'AAL2', 'AAL3')),
    CONSTRAINT ck_user_session_revoked CHECK ((session_state = 'REVOKED') = (revoked_at IS NOT NULL)),
    CONSTRAINT ck_user_session_compromised CHECK (session_state <> 'COMPROMISED' OR compromised_at IS NOT NULL),
    CONSTRAINT ck_user_session_expiry CHECK (absolute_expires_at > created_at AND idle_expires_at <= absolute_expires_at),
    -- TTL-SESSION-001：普通绝对期 ≤ 30 天；SP3 ≤ 12 小时（SP5 不得宽于 SP3）
    CONSTRAINT ck_user_session_ttl CHECK (
        CASE profile_code
            WHEN 'SP3' THEN absolute_expires_at - created_at <= interval '12 hours'
            WHEN 'SP5' THEN absolute_expires_at - created_at <= interval '12 hours'
            ELSE absolute_expires_at - created_at <= interval '30 days'
        END
    ),
    CONSTRAINT ck_user_session_epoch CHECK (user_epoch_at_issue >= 1 AND client_epoch_at_issue >= 1)
);
COMMENT ON TABLE session.user_session IS 'CAP-SESSION-003 会话；public_id 即 OIDC sid；user_epoch_at_issue 供撤销水位比对（CAP-SESSION-013）';
COMMENT ON COLUMN session.user_session.login_transaction_id IS 'INV-G-016：会话必须由 COMPLETED 的登录事务派生，由 trg_user_session_logintx_guard 强制';
COMMENT ON COLUMN session.user_session.auth_time IS 'CAP-ASR-001：auth_time 独立于 acr/amr，Step-up 判定的认证新鲜度基准（TTL-STEPUP-001）';

CREATE OR REPLACE TRIGGER trg_user_session_touch
    BEFORE UPDATE ON session.user_session
    FOR EACH ROW EXECUTE FUNCTION core.fn_touch_updated_at();

-- INV-G-013 + INV-G-016：插入会话前校验主体可操作且登录事务已完成
CREATE OR REPLACE FUNCTION session.fn_user_session_insert_guard()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    v_tx_state text;
    v_tx_user  uuid;
BEGIN
    PERFORM id.fn_assert_user_operable(NEW.user_id);

    SELECT transaction_state, user_id INTO v_tx_state, v_tx_user
      FROM auth.login_transaction WHERE id = NEW.login_transaction_id;

    IF v_tx_state IS DISTINCT FROM 'COMPLETED' THEN
        RAISE EXCEPTION 'INVALID_STATE_TRANSITION: 登录事务状态 % 不允许签发会话（INV-G-016）', COALESCE(v_tx_state, 'MISSING')
            USING ERRCODE = '23514';
    END IF;
    IF v_tx_user IS DISTINCT FROM NEW.user_id THEN
        RAISE EXCEPTION 'INVALID_STATE_TRANSITION: 会话主体与登录事务主体不一致（INV-G-016）'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE OR REPLACE TRIGGER trg_user_session_insert_guard
    BEFORE INSERT ON session.user_session
    FOR EACH ROW EXECUTE FUNCTION session.fn_user_session_insert_guard();

CREATE INDEX IF NOT EXISTS ix_user_session_user_state ON session.user_session (user_id, session_state, created_at DESC);
CREATE INDEX IF NOT EXISTS ix_user_session_device ON session.user_session (device_id) WHERE session_state = 'ACTIVE';
CREATE INDEX IF NOT EXISTS ix_user_session_expiry ON session.user_session (idle_expires_at) WHERE session_state = 'ACTIVE';
CREATE INDEX IF NOT EXISTS ix_user_session_tenant ON session.user_session (tenant_id, session_state);

-- -----------------------------------------------------------------------------
-- 3. 授权 Grant（CAP-SESSION-009、INV-G-014）
-- consent_id 不设外键：PRIV 域在 100 层建表，且 Consent 允许独立于 Grant 撤回
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS session.authorization_grant (
    id                     uuid        NOT NULL DEFAULT core.uuid_generate_v7(),
    public_id              text        NOT NULL,
    user_id                uuid        NULL,
    machine_principal_id   uuid        NULL,
    client_id              uuid        NOT NULL,
    tenant_id              uuid        NOT NULL DEFAULT '00000000-0000-0000-0000-000000000000',
    grant_state            text        NOT NULL DEFAULT 'PENDING',
    granted_scopes         text[]      NOT NULL DEFAULT '{}',
    granted_resources      text[]      NOT NULL DEFAULT '{}',
    authorization_details  jsonb       NULL,
    consent_id             uuid        NULL,
    policy_version         bigint      NULL,
    user_epoch_at_grant    bigint      NULL,
    granted_at             timestamptz NULL,
    expires_at             timestamptz NULL,
    last_used_at           timestamptz NULL,
    revoked_at             timestamptz NULL,
    revoke_reason_code     text        NULL,
    revoked_by_ref         text        NULL,
    created_at             timestamptz NOT NULL DEFAULT now(),
    updated_at             timestamptz NOT NULL DEFAULT now(),
    row_version            bigint      NOT NULL DEFAULT 1,
    CONSTRAINT pk_authorization_grant PRIMARY KEY (id),
    CONSTRAINT uq_authorization_grant_public_id UNIQUE (public_id),
    CONSTRAINT fk_authorization_grant_user FOREIGN KEY (user_id) REFERENCES id.global_user (id),
    CONSTRAINT fk_authorization_grant_client FOREIGN KEY (client_id) REFERENCES oap.client (id),
    CONSTRAINT ck_authorization_grant_state CHECK (grant_state IN ('PENDING', 'ACTIVE', 'REVOKED', 'EXPIRED')),
    -- 主体二选一：自然人授权或机器主体授权（REQ-MACHINE-008 禁止无边界 impersonation）
    CONSTRAINT ck_authorization_grant_subject CHECK (
        (user_id IS NOT NULL AND machine_principal_id IS NULL)
        OR (user_id IS NULL AND machine_principal_id IS NOT NULL)
    ),
    CONSTRAINT ck_authorization_grant_active CHECK (grant_state <> 'ACTIVE' OR granted_at IS NOT NULL),
    CONSTRAINT ck_authorization_grant_revoked CHECK ((grant_state = 'REVOKED') = (revoked_at IS NOT NULL))
);
COMMENT ON TABLE session.authorization_grant IS 'CAP-SESSION-009 授权关系；INV-G-014：撤销后不得继续签发相关 Token；REQ-PRIV-011 的 Consent 撤回传播以本表为执行点';

CREATE OR REPLACE TRIGGER trg_authorization_grant_touch
    BEFORE UPDATE ON session.authorization_grant
    FOR EACH ROW EXECUTE FUNCTION core.fn_touch_updated_at();

CREATE UNIQUE INDEX IF NOT EXISTS ux_authorization_grant_active_user
    ON session.authorization_grant (user_id, client_id)
    WHERE grant_state IN ('PENDING', 'ACTIVE') AND user_id IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS ux_authorization_grant_active_machine
    ON session.authorization_grant (machine_principal_id, client_id)
    WHERE grant_state IN ('PENDING', 'ACTIVE') AND machine_principal_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS ix_authorization_grant_client ON session.authorization_grant (client_id, grant_state);

-- -----------------------------------------------------------------------------
-- 4. Token 家族与 Refresh Token 实例（REQ-SESSION-002/014、CAP-OAP-008）
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS session.token_family (
    id                          uuid        NOT NULL DEFAULT core.uuid_generate_v7(),
    user_id                     uuid        NULL,
    machine_principal_id        uuid        NULL,
    client_id                   uuid        NOT NULL,
    grant_id                    uuid        NOT NULL,
    session_id                  uuid        NULL,
    device_id                   uuid        NULL,
    tenant_id                   uuid        NOT NULL DEFAULT '00000000-0000-0000-0000-000000000000',
    family_state                text        NOT NULL DEFAULT 'ACTIVE',
    profile_code                text        NOT NULL,
    sender_constraint_method    text        NULL,
    sender_constraint_thumbprint bytea      NULL,
    generation_count            integer     NOT NULL DEFAULT 1,
    idle_expires_at             timestamptz NOT NULL,
    absolute_expires_at         timestamptz NOT NULL,
    compromised_at              timestamptz NULL,
    compromise_reason_code      text        NULL,
    revoked_at                  timestamptz NULL,
    revoke_reason_code          text        NULL,
    created_at                  timestamptz NOT NULL DEFAULT now(),
    updated_at                  timestamptz NOT NULL DEFAULT now(),
    row_version                 bigint      NOT NULL DEFAULT 1,
    CONSTRAINT pk_token_family PRIMARY KEY (id),
    CONSTRAINT fk_token_family_user FOREIGN KEY (user_id) REFERENCES id.global_user (id),
    CONSTRAINT fk_token_family_client FOREIGN KEY (client_id) REFERENCES oap.client (id),
    CONSTRAINT fk_token_family_grant FOREIGN KEY (grant_id) REFERENCES session.authorization_grant (id),
    CONSTRAINT fk_token_family_session FOREIGN KEY (session_id) REFERENCES session.user_session (id),
    CONSTRAINT fk_token_family_device FOREIGN KEY (device_id) REFERENCES session.device (id),
    CONSTRAINT ck_token_family_state CHECK (family_state IN ('ACTIVE', 'COMPROMISED', 'REVOKED', 'EXPIRED')),
    CONSTRAINT ck_token_family_compromised CHECK (
        family_state <> 'COMPROMISED' OR (compromised_at IS NOT NULL AND compromise_reason_code IS NOT NULL)
    ),
    CONSTRAINT ck_token_family_sender_constraint CHECK (
        (sender_constraint_method IS NULL AND sender_constraint_thumbprint IS NULL)
        OR (sender_constraint_method IN ('DPOP', 'MTLS') AND sender_constraint_thumbprint IS NOT NULL)
    ),
    -- TTL-TOKEN-003：SP1 绝对期 ≤ 90 天；SP2 ≤ 30 天；SP3/SP5 ≤ 1 天；SP4 不签发 Refresh Token
    CONSTRAINT ck_token_family_ttl CHECK (
        CASE profile_code
            WHEN 'SP1' THEN absolute_expires_at - created_at <= interval '90 days'
            WHEN 'SP2' THEN absolute_expires_at - created_at <= interval '30 days'
            WHEN 'SP3' THEN absolute_expires_at - created_at <= interval '1 day'
            WHEN 'SP5' THEN absolute_expires_at - created_at <= interval '1 day'
            ELSE false
        END
    ),
    CONSTRAINT ck_token_family_expiry CHECK (idle_expires_at <= absolute_expires_at)
);
COMMENT ON TABLE session.token_family IS 'CAP-SESSION-008 / CAP-OAP-008：Refresh Token 家族；重放检测触发家族级吊销（AT-SESSION-001）。SP4 机器主体不签发 Refresh Token，故 ck_token_family_ttl 直接拒绝';

CREATE OR REPLACE TRIGGER trg_token_family_touch
    BEFORE UPDATE ON session.token_family
    FOR EACH ROW EXECUTE FUNCTION core.fn_touch_updated_at();

CREATE INDEX IF NOT EXISTS ix_token_family_user ON session.token_family (user_id, family_state);
CREATE INDEX IF NOT EXISTS ix_token_family_session ON session.token_family (session_id) WHERE family_state = 'ACTIVE';
CREATE INDEX IF NOT EXISTS ix_token_family_grant ON session.token_family (grant_id);
CREATE INDEX IF NOT EXISTS ix_token_family_expiry ON session.token_family (absolute_expires_at) WHERE family_state = 'ACTIVE';

CREATE TABLE IF NOT EXISTS session.refresh_token_instance (
    id                    uuid        NOT NULL DEFAULT core.uuid_generate_v7(),
    family_id             uuid        NOT NULL,
    generation            integer     NOT NULL,
    token_hash            bytea       NOT NULL,
    instance_state        text        NOT NULL DEFAULT 'CURRENT',
    issued_at             timestamptz NOT NULL DEFAULT now(),
    expires_at            timestamptz NOT NULL,
    used_at               timestamptz NULL,
    successor_id          uuid        NULL,
    -- REQ-SESSION-014：SP1 允许同绑定上下文的受控短重试窗口，用于区分丢包重试与重放
    retry_window_until    timestamptz NULL,
    binding_context_hash  bytea       NULL,
    revoked_at            timestamptz NULL,
    revoke_reason_code    text        NULL,
    CONSTRAINT pk_refresh_token_instance PRIMARY KEY (id),
    CONSTRAINT uq_refresh_token_instance_hash UNIQUE (token_hash),
    CONSTRAINT uq_refresh_token_instance_generation UNIQUE (family_id, generation),
    CONSTRAINT fk_refresh_token_instance_family FOREIGN KEY (family_id) REFERENCES session.token_family (id) ON DELETE CASCADE,
    CONSTRAINT fk_refresh_token_instance_successor FOREIGN KEY (successor_id) REFERENCES session.refresh_token_instance (id),
    CONSTRAINT ck_refresh_token_instance_state CHECK (instance_state IN ('CURRENT', 'USED', 'REVOKED', 'EXPIRED')),
    CONSTRAINT ck_refresh_token_instance_hash CHECK (octet_length(token_hash) = 32),
    CONSTRAINT ck_refresh_token_instance_used CHECK ((instance_state = 'USED') = (used_at IS NOT NULL)),
    CONSTRAINT ck_refresh_token_instance_generation_positive CHECK (generation >= 1)
);
COMMENT ON TABLE session.refresh_token_instance IS 'REQ-SESSION-002：轮换用原子 compare-and-set 完成；ux_refresh_token_current 保证任一时刻每家族最多一个 CURRENT（AT-SESSION-007）';
COMMENT ON COLUMN session.refresh_token_instance.token_hash IS 'Refresh Token 只存哈希；原值仅存在于客户端（INV-G-007）';

-- REQ-SESSION-002 核心执行点
CREATE UNIQUE INDEX IF NOT EXISTS ux_refresh_token_current
    ON session.refresh_token_instance (family_id)
    WHERE instance_state = 'CURRENT';

CREATE INDEX IF NOT EXISTS ix_refresh_token_instance_expiry ON session.refresh_token_instance (expires_at) WHERE instance_state = 'CURRENT';

-- -----------------------------------------------------------------------------
-- 5. 授权码（REQ-AUTH-004、TTL-CODE-001）
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS session.authorization_code (
    id                     uuid        NOT NULL DEFAULT core.uuid_generate_v7(),
    code_hash              bytea       NOT NULL,
    code_state             text        NOT NULL DEFAULT 'ISSUED',
    client_id              uuid        NOT NULL,
    user_id                uuid        NOT NULL,
    login_transaction_id   uuid        NOT NULL,
    session_id             uuid        NULL,
    grant_id               uuid        NULL,
    redirect_uri           text        NOT NULL,
    code_challenge         text        NOT NULL,
    code_challenge_method  text        NOT NULL DEFAULT 'S256',
    nonce_hash             bytea       NULL,
    requested_scopes       text[]      NOT NULL DEFAULT '{}',
    requested_resources    text[]      NOT NULL DEFAULT '{}',
    issued_at              timestamptz NOT NULL DEFAULT now(),
    expires_at             timestamptz NOT NULL,
    consumed_at            timestamptz NULL,
    replay_detected_at     timestamptz NULL,
    revoked_at             timestamptz NULL,
    CONSTRAINT pk_authorization_code PRIMARY KEY (id),
    CONSTRAINT uq_authorization_code_hash UNIQUE (code_hash),
    CONSTRAINT fk_authorization_code_client FOREIGN KEY (client_id) REFERENCES oap.client (id),
    CONSTRAINT fk_authorization_code_user FOREIGN KEY (user_id) REFERENCES id.global_user (id),
    CONSTRAINT fk_authorization_code_login_tx FOREIGN KEY (login_transaction_id) REFERENCES auth.login_transaction (id),
    CONSTRAINT fk_authorization_code_session FOREIGN KEY (session_id) REFERENCES session.user_session (id),
    CONSTRAINT ck_authorization_code_state CHECK (code_state IN ('ISSUED', 'CONSUMED', 'EXPIRED', 'REVOKED')),
    CONSTRAINT ck_authorization_code_hash CHECK (octet_length(code_hash) = 32),
    CONSTRAINT ck_authorization_code_pkce CHECK (code_challenge_method = 'S256'),
    CONSTRAINT ck_authorization_code_consumed CHECK ((code_state = 'CONSUMED') = (consumed_at IS NOT NULL)),
    -- TTL-CODE-001：≤ 60 秒且单次使用
    CONSTRAINT ck_authorization_code_ttl CHECK (expires_at > issued_at AND expires_at - issued_at <= interval '60 seconds')
);
COMMENT ON TABLE session.authorization_code IS 'REQ-AUTH-004：授权码单次使用并绑定 Client、redirect URI 与 PKCE；重放即撤销关联授权（AT-AUTH-003）';

CREATE INDEX IF NOT EXISTS ix_authorization_code_expiry ON session.authorization_code (expires_at) WHERE code_state = 'ISSUED';
CREATE INDEX IF NOT EXISTS ix_authorization_code_login_tx ON session.authorization_code (login_transaction_id);

-- -----------------------------------------------------------------------------
-- 6. Access Token 引用（仅 REFERENCE 格式或需内省时使用；JWT 模式不落库）
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS session.access_token_reference (
    jti                    text        NOT NULL,
    token_hash             bytea       NOT NULL,
    client_id              uuid        NOT NULL,
    user_id                uuid        NULL,
    machine_principal_id   uuid        NULL,
    grant_id               uuid        NULL,
    family_id              uuid        NULL,
    session_id             uuid        NULL,
    tenant_id              uuid        NOT NULL DEFAULT '00000000-0000-0000-0000-000000000000',
    audiences              text[]      NOT NULL,
    scopes                 text[]      NOT NULL DEFAULT '{}',
    profile_code           text        NOT NULL,
    sender_constraint_thumbprint bytea NULL,
    issued_at              timestamptz NOT NULL DEFAULT now(),
    expires_at             timestamptz NOT NULL,
    revoked_at             timestamptz NULL,
    CONSTRAINT pk_access_token_reference PRIMARY KEY (jti),
    CONSTRAINT uq_access_token_reference_hash UNIQUE (token_hash),
    CONSTRAINT fk_access_token_reference_client FOREIGN KEY (client_id) REFERENCES oap.client (id),
    CONSTRAINT fk_access_token_reference_family FOREIGN KEY (family_id) REFERENCES session.token_family (id) ON DELETE CASCADE,
    -- TTL-TOKEN-001/002：SP1 ≤ 15 分钟；SP2/SP3/SP4 ≤ 5 分钟；SP5 ≤ 2 分钟
    CONSTRAINT ck_access_token_reference_ttl CHECK (
        CASE profile_code
            WHEN 'SP1' THEN expires_at - issued_at <= interval '15 minutes'
            WHEN 'SP5' THEN expires_at - issued_at <= interval '2 minutes'
            ELSE expires_at - issued_at <= interval '5 minutes'
        END
    ),
    CONSTRAINT ck_access_token_reference_audience CHECK (array_length(audiences, 1) >= 1)
);
COMMENT ON TABLE session.access_token_reference IS 'CAP-SESSION-011 内省支持；TTL 上限由 TTL-TOKEN-001/002 在数据库层强制';

CREATE INDEX IF NOT EXISTS ix_access_token_reference_expiry ON session.access_token_reference (expires_at);
CREATE INDEX IF NOT EXISTS ix_access_token_reference_subject ON session.access_token_reference (user_id, issued_at DESC);

-- -----------------------------------------------------------------------------
-- 7. 撤销记录（CAP-SESSION-010、REQ-SESSION-012、INV-G-014）
-- 追加型：资源服务器可按 revoked_at 与 effective_epoch 判断 Token 是否早于撤销时点
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS session.revocation_record (
    id                uuid        NOT NULL DEFAULT core.uuid_generate_v7(),
    revocation_kind   text        NOT NULL,
    target_ref        text        NOT NULL,
    user_id           uuid        NULL,
    client_id         uuid        NULL,
    tenant_id         uuid        NOT NULL DEFAULT '00000000-0000-0000-0000-000000000000',
    effective_epoch   bigint      NULL,
    reason_code       text        NOT NULL,
    source_kind       text        NOT NULL,
    source_ref        text        NULL,
    revoked_at        timestamptz NOT NULL DEFAULT now(),
    prunable_after    timestamptz NOT NULL,
    CONSTRAINT pk_revocation_record PRIMARY KEY (id),
    CONSTRAINT ck_revocation_record_kind CHECK (revocation_kind IN (
        'SESSION', 'TOKEN_FAMILY', 'GRANT', 'CLIENT', 'USER_EPOCH', 'TENANT_EPOCH', 'JTI', 'DEVICE', 'AUTHENTICATOR'
    )),
    CONSTRAINT ck_revocation_record_source CHECK (source_kind IN ('USER', 'ADMIN', 'RISK', 'SYSTEM', 'IDENTITY_PROVIDER', 'PRIVACY')),
    CONSTRAINT ck_revocation_record_prunable CHECK (prunable_after > revoked_at)
);
COMMENT ON TABLE session.revocation_record IS 'CAP-SESSION-010 撤销表；prunable_after 至少覆盖最大 Token TTL，早于该时点不得清理（REQ-SESSION-012）';

CREATE OR REPLACE TRIGGER trg_revocation_record_append_only
    BEFORE UPDATE OR DELETE ON session.revocation_record
    FOR EACH STATEMENT EXECUTE FUNCTION core.fn_append_only();

CREATE INDEX IF NOT EXISTS ix_revocation_record_target ON session.revocation_record (revocation_kind, target_ref, revoked_at DESC);
CREATE INDEX IF NOT EXISTS ix_revocation_record_recent ON session.revocation_record (revoked_at DESC);
CREATE INDEX IF NOT EXISTS ix_revocation_record_prune ON session.revocation_record (prunable_after);

-- -----------------------------------------------------------------------------
-- 8. 退出请求与逐 RP 对账（CAP-SESSION-002、能力地图 §5.7、AT-SESSION-006）
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS session.logout_request (
    id               uuid        NOT NULL DEFAULT core.uuid_generate_v7(),
    user_id          uuid        NOT NULL,
    scope_kind       text        NOT NULL,
    scope_ref_id     uuid        NULL,
    initiator_kind   text        NOT NULL,
    initiator_ref    text        NULL,
    request_state    text        NOT NULL DEFAULT 'IN_PROGRESS',
    operation_id     uuid        NULL,
    requested_at     timestamptz NOT NULL DEFAULT now(),
    completed_at     timestamptz NULL,
    updated_at       timestamptz NOT NULL DEFAULT now(),
    row_version      bigint      NOT NULL DEFAULT 1,
    CONSTRAINT pk_logout_request PRIMARY KEY (id),
    CONSTRAINT fk_logout_request_user FOREIGN KEY (user_id) REFERENCES id.global_user (id),
    CONSTRAINT fk_logout_request_operation FOREIGN KEY (operation_id) REFERENCES core.async_operation (id),
    CONSTRAINT ck_logout_request_scope CHECK (scope_kind IN ('CLIENT', 'SESSION', 'DEVICE', 'TENANT', 'ALL_DEVICES', 'GLOBAL')),
    CONSTRAINT ck_logout_request_initiator CHECK (initiator_kind IN ('USER', 'ADMIN', 'RISK', 'IDENTITY_PROVIDER', 'SYSTEM')),
    CONSTRAINT ck_logout_request_state CHECK (request_state IN ('IN_PROGRESS', 'PARTIAL', 'COMPLETED'))
);
COMMENT ON TABLE session.logout_request IS 'CAP-SESSION-002 退出编排；PARTIAL 必须可见、可重试、可对账（AT-SESSION-006）';

CREATE OR REPLACE TRIGGER trg_logout_request_touch
    BEFORE UPDATE ON session.logout_request
    FOR EACH ROW EXECUTE FUNCTION core.fn_touch_updated_at();

CREATE TABLE IF NOT EXISTS session.logout_rp_result (
    id                     uuid        NOT NULL DEFAULT core.uuid_generate_v7(),
    logout_request_id      uuid        NOT NULL,
    client_id              uuid        NOT NULL,
    channel                text        NOT NULL,
    delivery_state         text        NOT NULL DEFAULT 'PENDING',
    unconfirmed_reason_class text      NULL,
    attempt_count          integer     NOT NULL DEFAULT 0,
    next_attempt_at        timestamptz NULL,
    confirmed_at           timestamptz NULL,
    last_error_code        text        NULL,
    dead_lettered_at       timestamptz NULL,
    updated_at             timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT pk_logout_rp_result PRIMARY KEY (id),
    CONSTRAINT uq_logout_rp_result UNIQUE (logout_request_id, client_id, channel),
    CONSTRAINT fk_logout_rp_result_request FOREIGN KEY (logout_request_id) REFERENCES session.logout_request (id) ON DELETE CASCADE,
    CONSTRAINT fk_logout_rp_result_client FOREIGN KEY (client_id) REFERENCES oap.client (id),
    CONSTRAINT ck_logout_rp_result_channel CHECK (channel IN ('BACK_CHANNEL', 'FRONT_CHANNEL')),
    CONSTRAINT ck_logout_rp_result_state CHECK (delivery_state IN ('PENDING', 'CONFIRMED', 'FAILED', 'DEAD_LETTER', 'NOT_APPLICABLE')),
    -- 能力地图 §5.7 第 6 步：必须区分"后通道未确认"与"前通道未生效"，只有前者触发安全告警
    CONSTRAINT ck_logout_rp_result_reason CHECK (
        unconfirmed_reason_class IS NULL
        OR unconfirmed_reason_class IN ('BACK_CHANNEL_UNCONFIRMED', 'FRONT_CHANNEL_INEFFECTIVE')
    ),
    CONSTRAINT ck_logout_rp_result_confirmed CHECK ((delivery_state = 'CONFIRMED') = (confirmed_at IS NOT NULL))
);
COMMENT ON TABLE session.logout_rp_result IS '能力地图 §5.7：逐 RP 退出结果；BACK_CHANNEL_UNCONFIRMED 计入 CAP-EVENT-012 消费方合规度并告警，FRONT_CHANNEL_INEFFECTIVE 计为预期情形';

CREATE OR REPLACE TRIGGER trg_logout_rp_result_touch
    BEFORE UPDATE ON session.logout_rp_result
    FOR EACH ROW EXECUTE FUNCTION core.fn_touch_updated_at();

CREATE INDEX IF NOT EXISTS ix_logout_rp_result_pending
    ON session.logout_rp_result (next_attempt_at) WHERE delivery_state = 'PENDING';

SELECT core.fn_apply_standard_grants('session');
SELECT core.fn_apply_append_only_grants('session', 'revocation_record');

SELECT core.fn_migration_apply('070', 'session_token：设备、会话、Grant、Token 家族与实例、授权码、撤销记录、退出对账');
