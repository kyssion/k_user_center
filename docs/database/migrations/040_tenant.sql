-- =============================================================================
-- 040_tenant.sql
-- TENANT 域：业务线、租户、租户域名、组织、Membership、邀请、用户组、计量
-- 依据：能力地图 §4.5；蓝图 §10（REQ-TENANT-001 至 010、INV-G-005、INV-G-015）
-- 约定：tenant_id 全零 UUID 表示"平台级 / 无租户"，使所有查询都能统一按 tenant_id 过滤
-- =============================================================================

SET client_min_messages = warning;

-- -----------------------------------------------------------------------------
-- 1. 业务线（CAP-TENANT-001）
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS tenant.business_line (
    id                  uuid        NOT NULL DEFAULT core.uuid_generate_v7(),
    public_id           text        NOT NULL,
    business_line_code  text        NOT NULL,
    display_name        text        NOT NULL,
    business_line_state text        NOT NULL DEFAULT 'PROVISIONING',
    owner_ref           text        NOT NULL,
    data_domain         text        NOT NULL,
    subject_mode        text        NOT NULL DEFAULT 'PAIRWISE_PER_CLIENT',
    access_policy       jsonb       NULL,
    created_at          timestamptz NOT NULL DEFAULT now(),
    updated_at          timestamptz NOT NULL DEFAULT now(),
    row_version         bigint      NOT NULL DEFAULT 1,
    CONSTRAINT pk_business_line PRIMARY KEY (id),
    CONSTRAINT uq_business_line_public_id UNIQUE (public_id),
    CONSTRAINT uq_business_line_code UNIQUE (business_line_code),
    CONSTRAINT ck_business_line_state CHECK (business_line_state IN ('PROVISIONING', 'ACTIVE', 'SUSPENDED', 'CLOSING', 'CLOSED')),
    CONSTRAINT ck_business_line_code CHECK (business_line_code ~ '^[a-z][a-z0-9_]{1,30}$'),
    -- CAP-ID-001 / REQ-PRIV-010：跨业务共享 Subject 必须显式登记，默认应用级 pairwise
    CONSTRAINT ck_business_line_subject_mode CHECK (subject_mode IN ('PAIRWISE_PER_CLIENT', 'PAIRWISE_PER_BUSINESS_LINE', 'SHARED_GLOBAL'))
);
COMMENT ON TABLE tenant.business_line IS 'CAP-TENANT-001 业务线：应用、权限、数据隔离与管理授权的边界';
COMMENT ON COLUMN tenant.business_line.subject_mode IS 'SHARED_GLOBAL 属于例外，必须按 CAP-CTRL-006 登记并说明跨业务关联的合法依据';

CREATE OR REPLACE TRIGGER trg_business_line_touch
    BEFORE UPDATE ON tenant.business_line
    FOR EACH ROW EXECUTE FUNCTION core.fn_touch_updated_at();
CREATE OR REPLACE TRIGGER trg_business_line_public_id
    BEFORE INSERT ON tenant.business_line
    FOR EACH ROW EXECUTE FUNCTION core.fn_register_public_id('BUSINESS_LINE');

-- -----------------------------------------------------------------------------
-- 2. 租户（CAP-TENANT-004、蓝图 §10.1）
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS tenant.tenant (
    id                    uuid        NOT NULL DEFAULT core.uuid_generate_v7(),
    public_id             text        NOT NULL,
    business_line_id      uuid        NOT NULL,
    display_name          text        NOT NULL,
    tenant_state          text        NOT NULL DEFAULT 'PROVISIONING',
    plan_code             text        NULL,
    security_epoch        bigint      NOT NULL DEFAULT 1,
    owner_user_id         uuid        NULL,
    auth_policy           jsonb       NULL,
    isolation_mode        text        NOT NULL DEFAULT 'LOGICAL',
    closing_started_at    timestamptz NULL,
    closed_at             timestamptz NULL,
    created_at            timestamptz NOT NULL DEFAULT now(),
    updated_at            timestamptz NOT NULL DEFAULT now(),
    row_version           bigint      NOT NULL DEFAULT 1,
    CONSTRAINT pk_tenant PRIMARY KEY (id),
    CONSTRAINT uq_tenant_public_id UNIQUE (public_id),
    CONSTRAINT fk_tenant_business_line FOREIGN KEY (business_line_id) REFERENCES tenant.business_line (id),
    CONSTRAINT fk_tenant_owner FOREIGN KEY (owner_user_id) REFERENCES id.global_user (id),
    CONSTRAINT ck_tenant_state CHECK (tenant_state IN ('PROVISIONING', 'ACTIVE', 'SUSPENDED', 'CLOSING', 'CLOSED')),
    CONSTRAINT ck_tenant_isolation CHECK (isolation_mode IN ('LOGICAL', 'DEDICATED_SCHEMA', 'DEDICATED_INSTANCE')),
    CONSTRAINT ck_tenant_closing CHECK (tenant_state <> 'CLOSING' OR closing_started_at IS NOT NULL),
    CONSTRAINT ck_tenant_closed CHECK ((tenant_state = 'CLOSED') = (closed_at IS NOT NULL)),
    CONSTRAINT ck_tenant_epoch CHECK (security_epoch >= 1)
);
COMMENT ON TABLE tenant.tenant IS 'CAP-TENANT-004 租户；tenant_security_epoch 在租户停用、身份源或管理员安全变更时递增（蓝图 §4.3）';

CREATE OR REPLACE TRIGGER trg_tenant_touch
    BEFORE UPDATE ON tenant.tenant
    FOR EACH ROW EXECUTE FUNCTION core.fn_touch_updated_at();
CREATE OR REPLACE TRIGGER trg_tenant_epoch
    BEFORE UPDATE ON tenant.tenant
    FOR EACH ROW EXECUTE FUNCTION core.fn_forbid_epoch_decrease('security_epoch');
CREATE OR REPLACE TRIGGER trg_tenant_public_id
    BEFORE INSERT ON tenant.tenant
    FOR EACH ROW EXECUTE FUNCTION core.fn_register_public_id('TENANT');

-- CLOSED 为终态（REQ-TENANT-010）
CREATE OR REPLACE FUNCTION tenant.fn_tenant_terminal_guard()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF OLD.tenant_state = 'CLOSED' AND NEW.tenant_state <> 'CLOSED' THEN
        RAISE EXCEPTION 'INVALID_STATE_TRANSITION: CLOSED 为终态，重建必须创建新租户（REQ-TENANT-010、AT-TENANT-007）'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE OR REPLACE TRIGGER trg_tenant_terminal_guard
    BEFORE UPDATE ON tenant.tenant
    FOR EACH ROW EXECUTE FUNCTION tenant.fn_tenant_terminal_guard();

CREATE INDEX IF NOT EXISTS ix_tenant_business_line ON tenant.tenant (business_line_id, tenant_state);

-- 租户域名（CAP-TENANT-005、REQ-TENANT-008：域名所有权持续验证）
CREATE TABLE IF NOT EXISTS tenant.tenant_domain (
    id                 uuid        NOT NULL DEFAULT core.uuid_generate_v7(),
    tenant_id          uuid        NOT NULL,
    domain_name        text        NOT NULL,
    verification_state text        NOT NULL DEFAULT 'PENDING',
    verification_token_hash bytea  NULL,
    verified_at        timestamptz NULL,
    last_checked_at    timestamptz NULL,
    next_check_at      timestamptz NULL,
    revoked_at         timestamptz NULL,
    enables_jit        boolean     NOT NULL DEFAULT false,
    created_at         timestamptz NOT NULL DEFAULT now(),
    updated_at         timestamptz NOT NULL DEFAULT now(),
    row_version        bigint      NOT NULL DEFAULT 1,
    CONSTRAINT pk_tenant_domain PRIMARY KEY (id),
    CONSTRAINT fk_tenant_domain_tenant FOREIGN KEY (tenant_id) REFERENCES tenant.tenant (id),
    CONSTRAINT ck_tenant_domain_state CHECK (verification_state IN ('PENDING', 'VERIFIED', 'FAILED', 'EXPIRED', 'REVOKED')),
    CONSTRAINT ck_tenant_domain_verified CHECK (verification_state <> 'VERIFIED' OR verified_at IS NOT NULL),
    -- REQ-TENANT-008：域名验证失效即停止基于域名的自动路由与 JIT
    CONSTRAINT ck_tenant_domain_jit CHECK (NOT enables_jit OR verification_state = 'VERIFIED'),
    CONSTRAINT ck_tenant_domain_name CHECK (domain_name = lower(domain_name))
);
COMMENT ON TABLE tenant.tenant_domain IS 'CAP-TENANT-005 / CAP-ID-010：域名所有权与持续验证；失效后不得继续用于身份源发现与 JIT';

CREATE UNIQUE INDEX IF NOT EXISTS ux_tenant_domain_verified
    ON tenant.tenant_domain (domain_name) WHERE verification_state = 'VERIFIED';
CREATE INDEX IF NOT EXISTS ix_tenant_domain_recheck ON tenant.tenant_domain (next_check_at) WHERE verification_state = 'VERIFIED';

CREATE OR REPLACE TRIGGER trg_tenant_domain_touch
    BEFORE UPDATE ON tenant.tenant_domain
    FOR EACH ROW EXECUTE FUNCTION core.fn_touch_updated_at();

-- -----------------------------------------------------------------------------
-- 3. 组织（CAP-TENANT-006）
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS tenant.organization (
    id                 uuid        NOT NULL DEFAULT core.uuid_generate_v7(),
    public_id          text        NOT NULL,
    tenant_id          uuid        NOT NULL,
    parent_id          uuid        NULL,
    display_name       text        NOT NULL,
    organization_type  text        NOT NULL DEFAULT 'DEPARTMENT',
    organization_state text        NOT NULL DEFAULT 'ACTIVE',
    materialized_path  text        NOT NULL,
    depth              smallint    NOT NULL DEFAULT 0,
    external_ref       text        NULL,
    created_at         timestamptz NOT NULL DEFAULT now(),
    updated_at         timestamptz NOT NULL DEFAULT now(),
    row_version        bigint      NOT NULL DEFAULT 1,
    CONSTRAINT pk_organization PRIMARY KEY (id),
    CONSTRAINT uq_organization_public_id UNIQUE (public_id),
    CONSTRAINT fk_organization_tenant FOREIGN KEY (tenant_id) REFERENCES tenant.tenant (id),
    CONSTRAINT fk_organization_parent FOREIGN KEY (parent_id) REFERENCES tenant.organization (id),
    CONSTRAINT ck_organization_type CHECK (organization_type IN ('COMPANY', 'DEPARTMENT', 'STORE', 'PROJECT_TEAM', 'OTHER')),
    CONSTRAINT ck_organization_state CHECK (organization_state IN ('PROVISIONING', 'ACTIVE', 'SUSPENDED', 'CLOSING', 'CLOSED')),
    CONSTRAINT ck_organization_depth CHECK (depth BETWEEN 0 AND 32),
    CONSTRAINT ck_organization_path CHECK (materialized_path ~ '^(/[0-9a-f-]{36})+$')
);
COMMENT ON TABLE tenant.organization IS 'CAP-TENANT-006 组织结构；materialized_path 支撑 CAP-AUTHZ-004 的"所在组织及下级"数据范围';

CREATE UNIQUE INDEX IF NOT EXISTS ux_organization_external_ref
    ON tenant.organization (tenant_id, external_ref) WHERE external_ref IS NOT NULL;
CREATE INDEX IF NOT EXISTS ix_organization_tenant_path ON tenant.organization (tenant_id, materialized_path text_pattern_ops);

CREATE OR REPLACE TRIGGER trg_organization_touch
    BEFORE UPDATE ON tenant.organization
    FOR EACH ROW EXECUTE FUNCTION core.fn_touch_updated_at();
CREATE OR REPLACE TRIGGER trg_organization_public_id
    BEFORE INSERT ON tenant.organization
    FOR EACH ROW EXECUTE FUNCTION core.fn_register_public_id('ORGANIZATION');

-- -----------------------------------------------------------------------------
-- 4. Membership（CAP-ID-014、CAP-TENANT-007、蓝图 §10.1）
-- 业务状态只影响目标 Membership，不修改全局用户状态（REQ-TENANT-001、INV-G-005）
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS tenant.membership (
    id                  uuid        NOT NULL DEFAULT core.uuid_generate_v7(),
    public_id           text        NOT NULL,
    user_id             uuid        NOT NULL,
    scope_kind          text        NOT NULL,
    scope_ref_id        uuid        NOT NULL,
    tenant_id           uuid        NOT NULL DEFAULT '00000000-0000-0000-0000-000000000000',
    business_line_id    uuid        NOT NULL,
    membership_state    text        NOT NULL DEFAULT 'INVITED',
    join_source         text        NOT NULL,
    invited_by_user_id  uuid        NULL,
    approved_by_ref     text        NULL,
    external_ref        text        NULL,
    joined_at           timestamptz NULL,
    suspended_at        timestamptz NULL,
    banned_at           timestamptz NULL,
    ban_reason_code     text        NULL,
    left_at             timestamptz NULL,
    directory_version   bigint      NULL,
    aggregate_version   bigint      NOT NULL DEFAULT 1,
    created_at          timestamptz NOT NULL DEFAULT now(),
    updated_at          timestamptz NOT NULL DEFAULT now(),
    row_version         bigint      NOT NULL DEFAULT 1,
    CONSTRAINT pk_membership PRIMARY KEY (id),
    CONSTRAINT uq_membership_public_id UNIQUE (public_id),
    CONSTRAINT fk_membership_user FOREIGN KEY (user_id) REFERENCES id.global_user (id),
    CONSTRAINT fk_membership_business_line FOREIGN KEY (business_line_id) REFERENCES tenant.business_line (id),
    CONSTRAINT ck_membership_scope CHECK (scope_kind IN ('BUSINESS_LINE', 'TENANT', 'ORGANIZATION')),
    CONSTRAINT ck_membership_state CHECK (membership_state IN (
        'INVITED', 'PENDING_APPROVAL', 'ACTIVE', 'SUSPENDED', 'BANNED', 'REJECTED', 'EXPIRED', 'LEFT'
    )),
    CONSTRAINT ck_membership_source CHECK (join_source IN (
        'SELF_REGISTER', 'INVITATION', 'ADMIN_ADD', 'DIRECTORY_SYNC', 'JIT_PROVISION', 'MIGRATION'
    )),
    CONSTRAINT ck_membership_active CHECK (membership_state <> 'ACTIVE' OR joined_at IS NOT NULL),
    CONSTRAINT ck_membership_banned CHECK (membership_state <> 'BANNED' OR (banned_at IS NOT NULL AND ban_reason_code IS NOT NULL)),
    CONSTRAINT ck_membership_left CHECK ((membership_state = 'LEFT') = (left_at IS NOT NULL)),
    -- 租户与组织范围必须落到具体租户；业务线范围用全零租户
    CONSTRAINT ck_membership_tenant_scope CHECK (
        (scope_kind = 'BUSINESS_LINE' AND tenant_id = '00000000-0000-0000-0000-000000000000')
        OR (scope_kind = 'TENANT' AND tenant_id = scope_ref_id)
        OR (scope_kind = 'ORGANIZATION' AND tenant_id <> '00000000-0000-0000-0000-000000000000')
    )
);
COMMENT ON TABLE tenant.membership IS 'CAP-ID-014 业务成员状态；REQ-TENANT-001 业务封禁只改本表；LEFT/REJECTED/EXPIRED 为终态，重新加入必须新建行（REQ-TENANT-010）';
COMMENT ON COLUMN tenant.membership.directory_version IS 'REQ-FED-006：目录源单调版本，用于拒绝乱序 SCIM 更新覆盖新状态';

-- 同一主体在同一范围内最多一条非终态成员关系
CREATE UNIQUE INDEX IF NOT EXISTS ux_membership_active_scope
    ON tenant.membership (user_id, scope_kind, scope_ref_id)
    WHERE membership_state NOT IN ('LEFT', 'REJECTED', 'EXPIRED');

CREATE INDEX IF NOT EXISTS ix_membership_user ON tenant.membership (user_id, membership_state);
CREATE INDEX IF NOT EXISTS ix_membership_tenant ON tenant.membership (tenant_id, membership_state, joined_at DESC);
CREATE INDEX IF NOT EXISTS ix_membership_scope ON tenant.membership (scope_kind, scope_ref_id, membership_state);

CREATE OR REPLACE TRIGGER trg_membership_touch
    BEFORE UPDATE ON tenant.membership
    FOR EACH ROW EXECUTE FUNCTION core.fn_touch_updated_at();
CREATE OR REPLACE TRIGGER trg_membership_public_id
    BEFORE INSERT ON tenant.membership
    FOR EACH ROW EXECUTE FUNCTION core.fn_register_public_id('MEMBERSHIP');

CREATE OR REPLACE FUNCTION tenant.fn_membership_terminal_guard()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF OLD.membership_state IN ('LEFT', 'REJECTED', 'EXPIRED')
       AND NEW.membership_state <> OLD.membership_state THEN
        RAISE EXCEPTION 'INVALID_STATE_TRANSITION: 成员状态 % 为终态（REQ-TENANT-010、AT-TENANT-007）', OLD.membership_state
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE OR REPLACE TRIGGER trg_membership_terminal_guard
    BEFORE UPDATE ON tenant.membership
    FOR EACH ROW EXECUTE FUNCTION tenant.fn_membership_terminal_guard();

-- -----------------------------------------------------------------------------
-- 5. 邀请（CAP-TENANT-008：单次消费、过期、撤回）
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS tenant.invitation (
    id                     uuid        NOT NULL DEFAULT core.uuid_generate_v7(),
    public_id              text        NOT NULL,
    scope_kind             text        NOT NULL,
    scope_ref_id           uuid        NOT NULL,
    tenant_id              uuid        NOT NULL DEFAULT '00000000-0000-0000-0000-000000000000',
    business_line_id       uuid        NOT NULL,
    invitation_state       text        NOT NULL DEFAULT 'PENDING',
    target_blind_index     bytea       NULL,
    target_identifier_type text        NULL,
    target_user_id         uuid        NULL,
    inviter_user_id        uuid        NOT NULL,
    preauthorized_roles    text[]      NOT NULL DEFAULT '{}',
    token_hash             bytea       NOT NULL,
    expires_at             timestamptz NOT NULL,
    accepted_at            timestamptz NULL,
    accepted_membership_id uuid        NULL,
    rejected_at            timestamptz NULL,
    revoked_at             timestamptz NULL,
    revoked_by_ref         text        NULL,
    created_at             timestamptz NOT NULL DEFAULT now(),
    updated_at             timestamptz NOT NULL DEFAULT now(),
    row_version            bigint      NOT NULL DEFAULT 1,
    CONSTRAINT pk_invitation PRIMARY KEY (id),
    CONSTRAINT uq_invitation_public_id UNIQUE (public_id),
    CONSTRAINT uq_invitation_token UNIQUE (token_hash),
    CONSTRAINT fk_invitation_inviter FOREIGN KEY (inviter_user_id) REFERENCES id.global_user (id),
    CONSTRAINT fk_invitation_target_user FOREIGN KEY (target_user_id) REFERENCES id.global_user (id),
    CONSTRAINT fk_invitation_membership FOREIGN KEY (accepted_membership_id) REFERENCES tenant.membership (id),
    CONSTRAINT ck_invitation_scope CHECK (scope_kind IN ('BUSINESS_LINE', 'TENANT', 'ORGANIZATION')),
    CONSTRAINT ck_invitation_state CHECK (invitation_state IN ('PENDING', 'ACCEPTED', 'REJECTED', 'EXPIRED', 'REVOKED')),
    CONSTRAINT ck_invitation_token CHECK (octet_length(token_hash) = 32),
    CONSTRAINT ck_invitation_target CHECK (target_blind_index IS NOT NULL OR target_user_id IS NOT NULL),
    CONSTRAINT ck_invitation_accepted CHECK (
        (invitation_state = 'ACCEPTED') = (accepted_at IS NOT NULL AND accepted_membership_id IS NOT NULL)
    )
);
COMMENT ON TABLE tenant.invitation IS 'CAP-TENANT-008 邀请：预授权角色、单次消费、过期与撤回；token 只存哈希';

CREATE UNIQUE INDEX IF NOT EXISTS ux_invitation_pending_target
    ON tenant.invitation (scope_kind, scope_ref_id, target_blind_index)
    WHERE invitation_state = 'PENDING' AND target_blind_index IS NOT NULL;
CREATE INDEX IF NOT EXISTS ix_invitation_expiry ON tenant.invitation (expires_at) WHERE invitation_state = 'PENDING';

CREATE OR REPLACE TRIGGER trg_invitation_touch
    BEFORE UPDATE ON tenant.invitation
    FOR EACH ROW EXECUTE FUNCTION core.fn_touch_updated_at();
CREATE OR REPLACE TRIGGER trg_invitation_public_id
    BEFORE INSERT ON tenant.invitation
    FOR EACH ROW EXECUTE FUNCTION core.fn_register_public_id('INVITATION');

-- -----------------------------------------------------------------------------
-- 6. 用户组（CAP-TENANT-009）
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS tenant.user_group (
    id            uuid        NOT NULL DEFAULT core.uuid_generate_v7(),
    public_id     text        NOT NULL,
    tenant_id     uuid        NOT NULL DEFAULT '00000000-0000-0000-0000-000000000000',
    business_line_id uuid     NOT NULL,
    group_code    text        NOT NULL,
    display_name  text        NOT NULL,
    group_type    text        NOT NULL DEFAULT 'STATIC',
    dynamic_rule  jsonb       NULL,
    group_state   text        NOT NULL DEFAULT 'ACTIVE',
    created_at    timestamptz NOT NULL DEFAULT now(),
    updated_at    timestamptz NOT NULL DEFAULT now(),
    row_version   bigint      NOT NULL DEFAULT 1,
    CONSTRAINT pk_user_group PRIMARY KEY (id),
    CONSTRAINT uq_user_group_public_id UNIQUE (public_id),
    CONSTRAINT uq_user_group_code UNIQUE (tenant_id, business_line_id, group_code),
    CONSTRAINT ck_user_group_type CHECK (group_type IN ('STATIC', 'DYNAMIC', 'ORGANIZATION')),
    CONSTRAINT ck_user_group_state CHECK (group_state IN ('ACTIVE', 'SUSPENDED', 'RETIRED')),
    CONSTRAINT ck_user_group_dynamic CHECK (group_type <> 'DYNAMIC' OR dynamic_rule IS NOT NULL)
);
COMMENT ON TABLE tenant.user_group IS 'CAP-TENANT-009 用户组；作为 CAP-AUTHZ-002 的授权主体之一，启用触发见能力地图 §4.5';

CREATE OR REPLACE TRIGGER trg_user_group_touch
    BEFORE UPDATE ON tenant.user_group
    FOR EACH ROW EXECUTE FUNCTION core.fn_touch_updated_at();

CREATE TABLE IF NOT EXISTS tenant.user_group_member (
    group_id    uuid        NOT NULL,
    user_id     uuid        NOT NULL,
    tenant_id   uuid        NOT NULL,
    added_at    timestamptz NOT NULL DEFAULT now(),
    added_by_ref text       NOT NULL,
    CONSTRAINT pk_user_group_member PRIMARY KEY (group_id, user_id),
    CONSTRAINT fk_user_group_member_group FOREIGN KEY (group_id) REFERENCES tenant.user_group (id) ON DELETE CASCADE,
    CONSTRAINT fk_user_group_member_user FOREIGN KEY (user_id) REFERENCES id.global_user (id)
);
COMMENT ON TABLE tenant.user_group_member IS 'CAP-TENANT-009 静态组成员；动态组由规则实时计算，不落本表';

CREATE INDEX IF NOT EXISTS ix_user_group_member_user ON tenant.user_group_member (user_id, tenant_id);

-- -----------------------------------------------------------------------------
-- 7. 计量（CAP-TENANT-013：限流配额与成本归属的共同输入）
-- client_id 不设外键：本表是跨域汇总表，允许 Client 下线后保留历史用量
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS tenant.usage_metering (
    id               uuid        NOT NULL DEFAULT core.uuid_generate_v7(),
    tenant_id        uuid        NOT NULL DEFAULT '00000000-0000-0000-0000-000000000000',
    business_line_id uuid        NOT NULL,
    client_id        uuid        NOT NULL DEFAULT '00000000-0000-0000-0000-000000000000',
    metric_code      text        NOT NULL,
    period_start     date        NOT NULL,
    metric_value     bigint      NOT NULL DEFAULT 0,
    unit             text        NOT NULL,
    updated_at       timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT pk_usage_metering PRIMARY KEY (id),
    CONSTRAINT uq_usage_metering_slot UNIQUE (tenant_id, business_line_id, client_id, metric_code, period_start),
    CONSTRAINT ck_usage_metering_metric CHECK (metric_code IN (
        'ACTIVE_USER', 'TOKEN_ISSUED', 'API_CALL', 'SMS_SENT', 'EMAIL_SENT', 'STORAGE_BYTE', 'WEBHOOK_DELIVERY'
    )),
    CONSTRAINT ck_usage_metering_value CHECK (metric_value >= 0)
);
COMMENT ON TABLE tenant.usage_metering IS 'CAP-TENANT-013：未计量的维度不得对外承诺配额；CAP-OBS-015/016 的用量输入只来自本表';

CREATE INDEX IF NOT EXISTS ix_usage_metering_period ON tenant.usage_metering (period_start DESC, metric_code);

SELECT core.fn_apply_standard_grants('tenant');

SELECT core.fn_migration_apply('040', 'tenant：业务线、租户、域名、组织、Membership、邀请、用户组、计量');
