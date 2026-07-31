-- =============================================================================
-- 020_identity.sql
-- ID 域：Global User、Subject 分配、Identifier、墓碑、注销请求、合并别名
-- 依据：能力地图 §3.1-§3.4、§4.1；蓝图 §7、§4.2（INV-G-001/002/003/009/013）、REQ-KEY-008/009
-- =============================================================================

SET client_min_messages = warning;

-- -----------------------------------------------------------------------------
-- 1. 全局用户主档（CAP-ID-001、CAP-ID-013）
-- 三个状态维度正交：lifecycle_state / lock_state / freeze_state（蓝图 §4.1、§7.1）
-- 本表不含任何 PII：手机号、邮箱在 id.identifier，昵称头像在 profile.user_profile
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS id.global_user (
    id                    uuid        NOT NULL DEFAULT core.uuid_generate_v7(),
    public_id             text        NOT NULL,
    subject_kind          text        NOT NULL DEFAULT 'HUMAN',
    lifecycle_state       text        NOT NULL DEFAULT 'PROVISIONAL',
    lock_state            text        NOT NULL DEFAULT 'ENABLED',
    freeze_state          text        NOT NULL DEFAULT 'CLEAR',
    security_epoch        bigint      NOT NULL DEFAULT 1,
    aggregate_version     bigint      NOT NULL DEFAULT 1,
    lock_reason_code      text        NULL,
    lock_until            timestamptz NULL,
    freeze_reason_code    text        NULL,
    frozen_at             timestamptz NULL,
    frozen_by_ref         text        NULL,
    created_source        text        NOT NULL,
    created_client_id     uuid        NULL,
    activated_at          timestamptz NULL,
    dormant_since         timestamptz NULL,
    last_authenticated_at timestamptz NULL,
    deletion_pending_at   timestamptz NULL,
    terminal_reason_code  text        NULL,
    anonymized_at         timestamptz NULL,
    erased_at             timestamptz NULL,
    merged_into_user_id   uuid        NULL,
    created_at            timestamptz NOT NULL DEFAULT now(),
    updated_at            timestamptz NOT NULL DEFAULT now(),
    row_version           bigint      NOT NULL DEFAULT 1,
    CONSTRAINT pk_global_user PRIMARY KEY (id),
    CONSTRAINT uq_global_user_public_id UNIQUE (public_id),
    CONSTRAINT fk_global_user_merged_into FOREIGN KEY (merged_into_user_id) REFERENCES id.global_user (id),
    CONSTRAINT ck_global_user_kind CHECK (subject_kind IN ('HUMAN', 'GUEST')),
    CONSTRAINT ck_global_user_lifecycle CHECK (lifecycle_state IN (
        'PROVISIONAL', 'ACTIVE', 'DORMANT', 'DELETION_PENDING', 'DELETION_BLOCKED',
        'ANONYMIZED', 'ERASED', 'MERGED'
    )),
    CONSTRAINT ck_global_user_lock CHECK (lock_state IN ('ENABLED', 'LOCKED')),
    CONSTRAINT ck_global_user_freeze CHECK (freeze_state IN ('CLEAR', 'FROZEN')),
    CONSTRAINT ck_global_user_freeze_evidence CHECK (
        freeze_state = 'CLEAR' OR (freeze_reason_code IS NOT NULL AND frozen_at IS NOT NULL)
    ),
    -- MERGED 必须指向主账号，非 MERGED 不得残留指针（REQ-ID-007）
    CONSTRAINT ck_global_user_merged CHECK (
        (lifecycle_state = 'MERGED' AND merged_into_user_id IS NOT NULL AND merged_into_user_id <> id)
        OR (lifecycle_state <> 'MERGED' AND merged_into_user_id IS NULL)
    ),
    CONSTRAINT ck_global_user_anonymized CHECK ((lifecycle_state = 'ANONYMIZED') = (anonymized_at IS NOT NULL)),
    CONSTRAINT ck_global_user_erased CHECK ((lifecycle_state = 'ERASED') = (erased_at IS NOT NULL)),
    CONSTRAINT ck_global_user_epoch CHECK (security_epoch >= 1)
);
COMMENT ON TABLE id.global_user IS 'CAP-ID-001/CAP-ID-013 全局用户主档；三状态正交（INV-G-005），终态不可逆（INV-G-009），security_epoch 单调（蓝图 §4.3）';
COMMENT ON COLUMN id.global_user.id IS '内部主键 UUIDv7，禁止出现在 API、Token、日志与 URL 中（能力地图 §3.2）';
COMMENT ON COLUMN id.global_user.public_id IS '对外 Global User ID（usr_xxx），不可推断、不可枚举、永不复用（INV-G-001）';
COMMENT ON COLUMN id.global_user.security_epoch IS '改密、恢复、认证器变更、冻结、合并时递增；进入 Token 并被资源服务器比对（CAP-SESSION-013）';

CREATE OR REPLACE TRIGGER trg_global_user_touch
    BEFORE UPDATE ON id.global_user
    FOR EACH ROW EXECUTE FUNCTION core.fn_touch_updated_at();

CREATE OR REPLACE TRIGGER trg_global_user_epoch
    BEFORE UPDATE ON id.global_user
    FOR EACH ROW EXECUTE FUNCTION core.fn_forbid_epoch_decrease('security_epoch');

CREATE OR REPLACE TRIGGER trg_global_user_public_id
    BEFORE INSERT ON id.global_user
    FOR EACH ROW EXECUTE FUNCTION core.fn_register_public_id('GLOBAL_USER');

-- INV-G-009 / REQ-ID-008：ANONYMIZED、ERASED、MERGED 为终态，任何路径不得回到其他状态
CREATE OR REPLACE FUNCTION id.fn_global_user_terminal_guard()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF OLD.lifecycle_state IN ('ANONYMIZED', 'ERASED', 'MERGED')
       AND NEW.lifecycle_state <> OLD.lifecycle_state THEN
        RAISE EXCEPTION 'INVALID_STATE_TRANSITION: % 为终态，禁止转为 %（INV-G-009 / REQ-ID-008）',
            OLD.lifecycle_state, NEW.lifecycle_state
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE OR REPLACE TRIGGER trg_global_user_terminal_guard
    BEFORE UPDATE ON id.global_user
    FOR EACH ROW EXECUTE FUNCTION id.fn_global_user_terminal_guard();

CREATE INDEX IF NOT EXISTS ix_global_user_lifecycle ON id.global_user (lifecycle_state, updated_at DESC);
CREATE INDEX IF NOT EXISTS ix_global_user_dormant   ON id.global_user (last_authenticated_at) WHERE lifecycle_state = 'ACTIVE';
CREATE INDEX IF NOT EXISTS ix_global_user_frozen    ON id.global_user (frozen_at DESC) WHERE freeze_state = 'FROZEN';

-- 主体可操作性判定：冻结主体不得创建会话、登记认证器、绑定标识、完成找回（能力地图不变量 5、INV-G-013）
CREATE OR REPLACE FUNCTION id.fn_assert_user_operable(p_user_id uuid)
RETURNS void
LANGUAGE plpgsql
AS $$
DECLARE
    v_lifecycle text;
    v_lock      text;
    v_freeze    text;
    v_lock_until timestamptz;
BEGIN
    SELECT lifecycle_state, lock_state, freeze_state, lock_until
      INTO v_lifecycle, v_lock, v_freeze, v_lock_until
      FROM id.global_user WHERE id = p_user_id;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'SUBJECT_NOT_FOUND: %', p_user_id USING ERRCODE = '23503';
    END IF;
    IF v_freeze = 'FROZEN' THEN
        RAISE EXCEPTION 'SUBJECT_FROZEN: 冻结主体不得执行该操作（INV-G-013）' USING ERRCODE = '23514';
    END IF;
    IF v_lock = 'LOCKED' AND (v_lock_until IS NULL OR v_lock_until > now()) THEN
        RAISE EXCEPTION 'SUBJECT_LOCKED: 账号处于锁定状态' USING ERRCODE = '23514';
    END IF;
    IF v_lifecycle NOT IN ('PROVISIONAL', 'ACTIVE', 'DORMANT') THEN
        RAISE EXCEPTION 'INVALID_STATE_TRANSITION: 生命周期 % 不允许该操作', v_lifecycle USING ERRCODE = '23514';
    END IF;
END;
$$;
COMMENT ON FUNCTION id.fn_assert_user_operable(uuid) IS 'INV-G-013 数据库侧兜底；应用层仍须先行判定并返回 423 SUBJECT_FROZEN 等契约错误';

-- -----------------------------------------------------------------------------
-- 2. Subject 分配（CAP-ID-001、REQ-PRIV-010：对外默认 pairwise）
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS id.subject_assignment (
    id               uuid        NOT NULL DEFAULT core.uuid_generate_v7(),
    user_id          uuid        NOT NULL,
    audience_kind    text        NOT NULL,
    audience_ref_id  uuid        NOT NULL DEFAULT '00000000-0000-0000-0000-000000000000',
    subject_id       text        NOT NULL,
    created_at       timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT pk_subject_assignment PRIMARY KEY (id),
    CONSTRAINT uq_subject_assignment_audience UNIQUE (user_id, audience_kind, audience_ref_id),
    CONSTRAINT uq_subject_assignment_subject UNIQUE (subject_id),
    CONSTRAINT fk_subject_assignment_user FOREIGN KEY (user_id) REFERENCES id.global_user (id),
    CONSTRAINT ck_subject_assignment_kind CHECK (audience_kind IN ('CLIENT', 'BUSINESS_LINE', 'GLOBAL')),
    -- GLOBAL Subject 必须用全零 audience，避免同一用户产生多个"全局"标识
    CONSTRAINT ck_subject_assignment_global CHECK (
        audience_kind <> 'GLOBAL' OR audience_ref_id = '00000000-0000-0000-0000-000000000000'
    )
);
COMMENT ON TABLE id.subject_assignment IS 'REQ-PRIV-010：默认按 Client 发布 pairwise Subject；Subject ID 与 public_id 无可计算关系且永不复用（INV-G-001）';

CREATE OR REPLACE TRIGGER trg_subject_assignment_public_id
    BEFORE INSERT ON id.subject_assignment
    FOR EACH ROW EXECUTE FUNCTION core.fn_register_public_id('SUBJECT', 'subject_id');

CREATE INDEX IF NOT EXISTS ix_subject_assignment_user ON id.subject_assignment (user_id);

-- -----------------------------------------------------------------------------
-- 3. 登录标识（CAP-ID-002 至 CAP-ID-009、REQ-ID-002/003/005/011/012/013）
-- 加密与盲索引方案见构建文档 §4：本表不存任何明文
-- 外部身份（OIDC/SAML/社交/企业）不在本表，见 fed.external_identity（CAP-ID-007）
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS id.identifier (
    id                      uuid        NOT NULL DEFAULT core.uuid_generate_v7(),
    public_id               text        NOT NULL,
    user_id                 uuid        NOT NULL,
    identifier_type         text        NOT NULL,
    uniqueness_scope        text        NOT NULL DEFAULT 'GLOBAL',
    scope_ref_id            uuid        NOT NULL DEFAULT '00000000-0000-0000-0000-000000000000',
    identifier_state        text        NOT NULL DEFAULT 'PENDING',
    value_blind_index       bytea       NOT NULL,
    value_cipher            bytea       NOT NULL,
    value_masked            text        NOT NULL,
    cipher_key_version      smallint    NOT NULL,
    blind_index_key_version smallint    NOT NULL,
    normalization_version   smallint    NOT NULL,
    region_hint             text        NULL,
    is_primary_contact      boolean     NOT NULL DEFAULT false,
    verified_at             timestamptz NULL,
    verification_method     text        NULL,
    bound_at                timestamptz NOT NULL DEFAULT now(),
    unbound_at              timestamptz NULL,
    quarantine_until        timestamptz NULL,
    released_at             timestamptz NULL,
    reachability_state      text        NOT NULL DEFAULT 'UNKNOWN',
    created_at              timestamptz NOT NULL DEFAULT now(),
    updated_at              timestamptz NOT NULL DEFAULT now(),
    row_version             bigint      NOT NULL DEFAULT 1,
    CONSTRAINT pk_identifier PRIMARY KEY (id),
    CONSTRAINT uq_identifier_public_id UNIQUE (public_id),
    CONSTRAINT fk_identifier_user FOREIGN KEY (user_id) REFERENCES id.global_user (id),
    CONSTRAINT ck_identifier_type CHECK (identifier_type IN ('PHONE', 'EMAIL', 'USERNAME')),
    CONSTRAINT ck_identifier_scope CHECK (uniqueness_scope IN ('GLOBAL', 'TENANT', 'APPLICATION')),
    CONSTRAINT ck_identifier_state CHECK (identifier_state IN ('PENDING', 'VERIFIED', 'UNBOUND', 'QUARANTINED', 'RELEASED')),
    CONSTRAINT ck_identifier_blind_index CHECK (octet_length(value_blind_index) = 32),
    CONSTRAINT ck_identifier_cipher CHECK (octet_length(value_cipher) BETWEEN 16 AND 4096),
    CONSTRAINT ck_identifier_verified CHECK (identifier_state <> 'VERIFIED' OR verified_at IS NOT NULL),
    CONSTRAINT ck_identifier_unbound CHECK (
        identifier_state NOT IN ('UNBOUND', 'QUARANTINED', 'RELEASED') OR unbound_at IS NOT NULL
    ),
    CONSTRAINT ck_identifier_quarantine CHECK (identifier_state <> 'QUARANTINED' OR quarantine_until IS NOT NULL),
    CONSTRAINT ck_identifier_released CHECK ((identifier_state = 'RELEASED') = (released_at IS NOT NULL)),
    CONSTRAINT ck_identifier_primary CHECK (NOT is_primary_contact OR identifier_state = 'VERIFIED'),
    CONSTRAINT ck_identifier_reachability CHECK (reachability_state IN ('UNKNOWN', 'REACHABLE', 'SOFT_BOUNCE', 'HARD_BOUNCE')),
    CONSTRAINT ck_identifier_global_scope CHECK (
        uniqueness_scope <> 'GLOBAL' OR scope_ref_id = '00000000-0000-0000-0000-000000000000'
    )
);
COMMENT ON TABLE id.identifier IS 'CAP-ID-002/004/005/006 登录标识；REQ-KEY-008 随机化加密 + HMAC 盲索引，等值查找与唯一性仅用 value_blind_index';
COMMENT ON COLUMN id.identifier.value_blind_index IS 'HMAC-SHA256(盲索引密钥, 规范化明文)；盲索引密钥与数据加密密钥分离管理（REQ-KEY-009）';
COMMENT ON COLUMN id.identifier.value_cipher IS '随机化 AEAD 密文，同明文两次写入不同，禁止用于比较；解密在应用侧完成（REQ-KEY-001）';
COMMENT ON COLUMN id.identifier.normalization_version IS 'REQ-ID-002 规范化算法版本；升级时执行双键检测与受控迁移';
COMMENT ON COLUMN id.identifier.reachability_state IS 'CAP-MSG-007 可达性回写；HARD_BOUNCE 后不得继续作为唯一恢复渠道';

-- INV-G-002 核心执行点：同一唯一性作用域内，一个有效标识最多绑定一个用户
CREATE UNIQUE INDEX IF NOT EXISTS ux_identifier_active_scope
    ON id.identifier (uniqueness_scope, scope_ref_id, identifier_type, value_blind_index)
    WHERE identifier_state = 'VERIFIED';

-- 同一用户不得对同一个值重复创建 PENDING 行；跨用户的 PENDING 允许并存，由上面的 VERIFIED 唯一索引决出唯一胜者
CREATE UNIQUE INDEX IF NOT EXISTS ux_identifier_pending_scope
    ON id.identifier (uniqueness_scope, scope_ref_id, identifier_type, value_blind_index, user_id)
    WHERE identifier_state = 'PENDING';

CREATE UNIQUE INDEX IF NOT EXISTS ux_identifier_primary_contact
    ON id.identifier (user_id, identifier_type)
    WHERE is_primary_contact;

CREATE INDEX IF NOT EXISTS ix_identifier_lookup
    ON id.identifier (identifier_type, value_blind_index)
    WHERE identifier_state IN ('PENDING', 'VERIFIED');

CREATE INDEX IF NOT EXISTS ix_identifier_user ON id.identifier (user_id, identifier_type, identifier_state);
CREATE INDEX IF NOT EXISTS ix_identifier_quarantine ON id.identifier (quarantine_until) WHERE identifier_state = 'QUARANTINED';

CREATE OR REPLACE TRIGGER trg_identifier_touch
    BEFORE UPDATE ON id.identifier
    FOR EACH ROW EXECUTE FUNCTION core.fn_touch_updated_at();

-- 冻结主体不得新增绑定（能力地图不变量 5）
CREATE OR REPLACE FUNCTION id.fn_identifier_bind_guard()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    PERFORM id.fn_assert_user_operable(NEW.user_id);
    RETURN NEW;
END;
$$;

CREATE OR REPLACE TRIGGER trg_identifier_bind_guard
    BEFORE INSERT ON id.identifier
    FOR EACH ROW EXECUTE FUNCTION id.fn_identifier_bind_guard();

-- -----------------------------------------------------------------------------
-- 4. 标识墓碑（CAP-ID-008、CAP-ID-009、CAP-ID-012、REQ-ID-006、TERM-IDENTIFIER-001）
-- 追加型：隔离期到期只表示唯一键可再分配，墓碑本身永久保留
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS id.identifier_tombstone (
    id                  uuid        NOT NULL DEFAULT core.uuid_generate_v7(),
    identifier_type     text        NOT NULL,
    uniqueness_scope    text        NOT NULL,
    scope_ref_id        uuid        NOT NULL,
    value_blind_index   bytea       NOT NULL,
    value_digest        bytea       NOT NULL,
    previous_user_id    uuid        NOT NULL,
    previous_identifier_id uuid     NOT NULL,
    unbound_at          timestamptz NOT NULL,
    quarantine_until    timestamptz NOT NULL,
    reason_code         text        NOT NULL,
    created_at          timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT pk_identifier_tombstone PRIMARY KEY (id),
    CONSTRAINT uq_identifier_tombstone_event UNIQUE (identifier_type, uniqueness_scope, scope_ref_id, value_blind_index, unbound_at),
    CONSTRAINT ck_identifier_tombstone_digest CHECK (octet_length(value_digest) = 32),
    CONSTRAINT ck_identifier_tombstone_blind CHECK (octet_length(value_blind_index) = 32),
    CONSTRAINT ck_identifier_tombstone_reason CHECK (reason_code IN (
        'USER_UNBIND', 'REBIND', 'ACCOUNT_DELETED', 'ACCOUNT_MERGED', 'ADMIN_ACTION', 'CARRIER_RECYCLE'
    )),
    CONSTRAINT ck_identifier_tombstone_window CHECK (quarantine_until > unbound_at)
);
COMMENT ON TABLE id.identifier_tombstone IS 'CAP-ID-008/009/012：解绑墓碑与隔离期；新持有人验证回收号码不得继承旧账号（REQ-ID-006、AT-ID-004）。读取本表须写入 obs.data_access_audit';
COMMENT ON COLUMN id.identifier_tombstone.value_digest IS '不可逆摘要（加盐 SHA-256），用于反欺诈比对；不可解密还原（CAP-ID-012）';
COMMENT ON COLUMN id.identifier_tombstone.quarantine_until IS 'TERM-IDENTIFIER-001：手机号 ≥ 90 天、企业邮箱 ≥ 180 天、用户名默认永不复用';

CREATE OR REPLACE TRIGGER trg_identifier_tombstone_append_only
    BEFORE UPDATE OR DELETE ON id.identifier_tombstone
    FOR EACH STATEMENT EXECUTE FUNCTION core.fn_append_only();

CREATE INDEX IF NOT EXISTS ix_identifier_tombstone_lookup
    ON id.identifier_tombstone (identifier_type, value_blind_index, quarantine_until DESC);
CREATE INDEX IF NOT EXISTS ix_identifier_tombstone_user
    ON id.identifier_tombstone (previous_user_id, unbound_at DESC);

-- -----------------------------------------------------------------------------
-- 5. 注销请求（CAP-ID-020、CAP-ID-023、REQ-ID-014、TERM-DELETE-001）
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS id.deletion_request (
    id                      uuid        NOT NULL DEFAULT core.uuid_generate_v7(),
    user_id                 uuid        NOT NULL,
    operation_id            uuid        NULL,
    request_state           text        NOT NULL DEFAULT 'COOLING_OFF',
    terminal_mode           text        NULL,
    requested_at            timestamptz NOT NULL DEFAULT now(),
    requested_via           text        NOT NULL,
    initiated_by_type       text        NOT NULL,
    initiated_by_ref        text        NOT NULL,
    request_assurance_level text        NOT NULL,
    cooling_off_until       timestamptz NOT NULL,
    blocked_reason_code     text        NULL,
    blocked_owner           text        NULL,
    blocked_expected_at     timestamptz NULL,
    withdrawn_at            timestamptz NULL,
    withdraw_assurance_level text       NULL,
    executed_at             timestamptz NULL,
    created_at              timestamptz NOT NULL DEFAULT now(),
    updated_at              timestamptz NOT NULL DEFAULT now(),
    row_version             bigint      NOT NULL DEFAULT 1,
    CONSTRAINT pk_deletion_request PRIMARY KEY (id),
    CONSTRAINT fk_deletion_request_user FOREIGN KEY (user_id) REFERENCES id.global_user (id),
    CONSTRAINT fk_deletion_request_operation FOREIGN KEY (operation_id) REFERENCES core.async_operation (id),
    CONSTRAINT ck_deletion_request_state CHECK (request_state IN ('COOLING_OFF', 'BLOCKED', 'EXECUTING', 'EXECUTED', 'WITHDRAWN')),
    CONSTRAINT ck_deletion_request_terminal CHECK (terminal_mode IS NULL OR terminal_mode IN ('ANONYMIZED', 'ERASED')),
    CONSTRAINT ck_deletion_request_via CHECK (requested_via IN ('SELF_SERVICE', 'AGENT', 'IDENTITY_PROVIDER', 'ADMIN')),
    -- CAP-ID-023：阻断必须带原因、责任方与预计处理方式
    CONSTRAINT ck_deletion_request_blocked CHECK (
        request_state <> 'BLOCKED' OR (blocked_reason_code IS NOT NULL AND blocked_owner IS NOT NULL)
    ),
    -- REQ-ID-014：撤回必须重新完成与发起时同等强度的认证
    CONSTRAINT ck_deletion_request_withdraw CHECK (
        (request_state = 'WITHDRAWN') = (withdrawn_at IS NOT NULL AND withdraw_assurance_level IS NOT NULL)
    ),
    CONSTRAINT ck_deletion_request_executed CHECK (
        (request_state = 'EXECUTED') = (executed_at IS NOT NULL AND terminal_mode IS NOT NULL)
    ),
    CONSTRAINT ck_deletion_request_cooling CHECK (cooling_off_until > requested_at)
);
COMMENT ON TABLE id.deletion_request IS 'CAP-ID-020/023：注销冷静期、冷静期内撤回、法律或业务阻断；冷静期取值见 TERM-DELETE-001';

CREATE OR REPLACE TRIGGER trg_deletion_request_touch
    BEFORE UPDATE ON id.deletion_request
    FOR EACH ROW EXECUTE FUNCTION core.fn_touch_updated_at();

-- 同一用户同时只允许一个在途注销请求
CREATE UNIQUE INDEX IF NOT EXISTS ux_deletion_request_active
    ON id.deletion_request (user_id)
    WHERE request_state IN ('COOLING_OFF', 'BLOCKED', 'EXECUTING');

CREATE INDEX IF NOT EXISTS ix_deletion_request_due
    ON id.deletion_request (cooling_off_until)
    WHERE request_state = 'COOLING_OFF';

-- -----------------------------------------------------------------------------
-- 6. 合并别名映射（CAP-ID-016、REQ-ID-007：旧 UID 保留受控映射，不得复用）
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS id.user_alias (
    alias_public_id   text        NOT NULL,
    primary_user_id   uuid        NOT NULL,
    merged_user_id    uuid        NOT NULL,
    merged_at         timestamptz NOT NULL DEFAULT now(),
    approval_case_id  uuid        NULL,
    CONSTRAINT pk_user_alias PRIMARY KEY (alias_public_id),
    CONSTRAINT fk_user_alias_primary FOREIGN KEY (primary_user_id) REFERENCES id.global_user (id),
    CONSTRAINT fk_user_alias_merged FOREIGN KEY (merged_user_id) REFERENCES id.global_user (id),
    CONSTRAINT ck_user_alias_distinct CHECK (primary_user_id <> merged_user_id)
);
COMMENT ON TABLE id.user_alias IS 'CAP-ID-016/REQ-ID-007：账号合并后旧 UID 到主账号的受控映射，防止历史数据失联；旧 UID 不得复用（INV-G-001）';

CREATE OR REPLACE TRIGGER trg_user_alias_append_only
    BEFORE UPDATE OR DELETE ON id.user_alias
    FOR EACH STATEMENT EXECUTE FUNCTION core.fn_append_only();

CREATE INDEX IF NOT EXISTS ix_user_alias_primary ON id.user_alias (primary_user_id);

-- -----------------------------------------------------------------------------
-- 7. 授权
-- -----------------------------------------------------------------------------
SELECT core.fn_apply_standard_grants('id');
SELECT core.fn_apply_append_only_grants('id', 'identifier_tombstone');
SELECT core.fn_apply_append_only_grants('id', 'user_alias');

SELECT core.fn_migration_apply('020', 'identity：全局用户、Subject 分配、登录标识、墓碑、注销请求、合并别名');
