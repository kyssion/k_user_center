-- =============================================================================
-- 080_authz.sql
-- AUTHZ 域：权限目录、角色、授权关系、职责分离、策略发布、义务契约、决策日志
-- 依据：能力地图 §4.6；蓝图 §12（REQ-AUTHZ-001 至 016、INV-G-006/011/015）
-- 说明：role_assignment.subject_id 为多态引用（用户/用户组/机器主体），故不设外键，
--       由 subject_kind + 应用层保证引用完整性，并由 verify.sql 抽样对账
-- =============================================================================

SET client_min_messages = warning;

-- -----------------------------------------------------------------------------
-- 1. 权限目录（CAP-AUTHZ-001）
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS authz.permission (
    permission_code           text        NOT NULL,
    resource_type             text        NOT NULL,
    action_code               text        NOT NULL,
    display_name              text        NOT NULL,
    is_high_risk              boolean     NOT NULL DEFAULT false,
    requires_realtime_decision boolean    NOT NULL DEFAULT false,
    min_profile_code          text        NOT NULL DEFAULT 'SP1',
    data_classification       text        NOT NULL DEFAULT 'INTERNAL',
    deprecated_at             timestamptz NULL,
    created_at                timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT pk_permission PRIMARY KEY (permission_code),
    CONSTRAINT uq_permission_resource_action UNIQUE (resource_type, action_code),
    CONSTRAINT fk_permission_classification FOREIGN KEY (data_classification) REFERENCES core.data_classification (classification_code),
    CONSTRAINT ck_permission_code CHECK (permission_code ~ '^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$'),
    CONSTRAINT ck_permission_profile CHECK (min_profile_code IN ('SP1', 'SP2', 'SP3', 'SP4', 'SP5')),
    -- 能力地图 §4.6：高风险权限必须实时决策，不得使用缓存放行
    CONSTRAINT ck_permission_high_risk_realtime CHECK (NOT is_high_risk OR requires_realtime_decision)
);
COMMENT ON TABLE authz.permission IS 'CAP-AUTHZ-001 权限目录；is_high_risk 决定 REQ-AUTHZ-013 是否禁止缓存复用';

-- -----------------------------------------------------------------------------
-- 2. 角色与角色权限（CAP-AUTHZ-002、CAP-AUTHZ-003、CAP-AUTHZ-004）
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS authz.role (
    id                uuid        NOT NULL DEFAULT core.uuid_generate_v7(),
    role_code         text        NOT NULL,
    display_name      text        NOT NULL,
    scope_kind        text        NOT NULL,
    tenant_id         uuid        NOT NULL DEFAULT '00000000-0000-0000-0000-000000000000',
    business_line_id  uuid        NULL,
    role_state        text        NOT NULL DEFAULT 'ACTIVE',
    is_privileged     boolean     NOT NULL DEFAULT false,
    subject_kind_limit text       NOT NULL DEFAULT 'HUMAN',
    max_assignment_days integer   NULL,
    created_at        timestamptz NOT NULL DEFAULT now(),
    updated_at        timestamptz NOT NULL DEFAULT now(),
    row_version       bigint      NOT NULL DEFAULT 1,
    CONSTRAINT pk_role PRIMARY KEY (id),
    CONSTRAINT uq_role_code UNIQUE (scope_kind, tenant_id, role_code),
    CONSTRAINT fk_role_business_line FOREIGN KEY (business_line_id) REFERENCES tenant.business_line (id),
    CONSTRAINT ck_role_scope CHECK (scope_kind IN ('PLATFORM', 'BUSINESS_LINE', 'APPLICATION', 'TENANT', 'ORGANIZATION')),
    CONSTRAINT ck_role_state CHECK (role_state IN ('ACTIVE', 'DEPRECATED', 'RETIRED')),
    -- REQ-MACHINE-009 / CAP-MACHINE-008：人机角色分离
    CONSTRAINT ck_role_subject_kind CHECK (subject_kind_limit IN ('HUMAN', 'MACHINE', 'ANY')),
    -- 特权角色必须有最长授予期限，配合 CAP-AUTHZ-008 到期自动回收
    CONSTRAINT ck_role_privileged_expiry CHECK (NOT is_privileged OR max_assignment_days IS NOT NULL)
);
COMMENT ON TABLE authz.role IS 'CAP-AUTHZ-002 角色；scope_kind 落实 CAP-AUTHZ-003 作用域隔离；特权角色强制到期（CAP-AUTHZ-008）';

CREATE OR REPLACE TRIGGER trg_role_touch
    BEFORE UPDATE ON authz.role
    FOR EACH ROW EXECUTE FUNCTION core.fn_touch_updated_at();

CREATE TABLE IF NOT EXISTS authz.role_permission (
    role_id         uuid        NOT NULL,
    permission_code text        NOT NULL,
    data_scope      text        NOT NULL DEFAULT 'SELF',
    scope_condition jsonb       NULL,
    granted_at      timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT pk_role_permission PRIMARY KEY (role_id, permission_code),
    CONSTRAINT fk_role_permission_role FOREIGN KEY (role_id) REFERENCES authz.role (id) ON DELETE CASCADE,
    CONSTRAINT fk_role_permission_permission FOREIGN KEY (permission_code) REFERENCES authz.permission (permission_code),
    -- CAP-AUTHZ-004 数据范围：全部、组织及下级、所在组织、指定集合、本人
    CONSTRAINT ck_role_permission_data_scope CHECK (data_scope IN ('ALL', 'ORG_AND_BELOW', 'OWN_ORG', 'EXPLICIT_SET', 'SELF'))
);
COMMENT ON TABLE authz.role_permission IS 'CAP-AUTHZ-004 数据范围；ALL 属于高风险配置，应由 CAP-CTRL-003 双人复核';

-- 互斥角色（CAP-AUTHZ-009 职责分离）
CREATE TABLE IF NOT EXISTS authz.role_exclusion (
    role_id          uuid        NOT NULL,
    excluded_role_id uuid        NOT NULL,
    reason           text        NOT NULL,
    created_at       timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT pk_role_exclusion PRIMARY KEY (role_id, excluded_role_id),
    CONSTRAINT fk_role_exclusion_role FOREIGN KEY (role_id) REFERENCES authz.role (id) ON DELETE CASCADE,
    CONSTRAINT fk_role_exclusion_excluded FOREIGN KEY (excluded_role_id) REFERENCES authz.role (id) ON DELETE CASCADE,
    CONSTRAINT ck_role_exclusion_distinct CHECK (role_id <> excluded_role_id)
);
COMMENT ON TABLE authz.role_exclusion IS 'CAP-AUTHZ-009：互斥角色；授予时必须校验，避免同一主体同时持有申请与审批角色';

-- -----------------------------------------------------------------------------
-- 3. 授权关系（CAP-AUTHZ-002、CAP-AUTHZ-008、REQ-AUTHZ-012）
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS authz.role_assignment (
    id                 uuid        NOT NULL DEFAULT core.uuid_generate_v7(),
    subject_kind       text        NOT NULL,
    subject_id         uuid        NOT NULL,
    role_id            uuid        NOT NULL,
    scope_kind         text        NOT NULL,
    scope_ref_id       uuid        NOT NULL DEFAULT '00000000-0000-0000-0000-000000000000',
    tenant_id          uuid        NOT NULL DEFAULT '00000000-0000-0000-0000-000000000000',
    data_scope_override text       NULL,
    assignment_state   text        NOT NULL DEFAULT 'ACTIVE',
    is_temporary       boolean     NOT NULL DEFAULT false,
    justification      text        NULL,
    approval_case_id   uuid        NULL,
    granted_at         timestamptz NOT NULL DEFAULT now(),
    granted_by_ref     text        NOT NULL,
    expires_at         timestamptz NULL,
    last_used_at       timestamptz NULL,
    last_reviewed_at   timestamptz NULL,
    revoked_at         timestamptz NULL,
    revoke_reason_code text        NULL,
    created_at         timestamptz NOT NULL DEFAULT now(),
    updated_at         timestamptz NOT NULL DEFAULT now(),
    row_version        bigint      NOT NULL DEFAULT 1,
    CONSTRAINT pk_role_assignment PRIMARY KEY (id),
    CONSTRAINT fk_role_assignment_role FOREIGN KEY (role_id) REFERENCES authz.role (id),
    CONSTRAINT ck_role_assignment_subject_kind CHECK (subject_kind IN ('USER', 'USER_GROUP', 'MACHINE_PRINCIPAL')),
    CONSTRAINT ck_role_assignment_scope CHECK (scope_kind IN ('PLATFORM', 'BUSINESS_LINE', 'APPLICATION', 'TENANT', 'ORGANIZATION')),
    CONSTRAINT ck_role_assignment_state CHECK (assignment_state IN ('ACTIVE', 'EXPIRED', 'REVOKED')),
    CONSTRAINT ck_role_assignment_data_scope CHECK (
        data_scope_override IS NULL OR data_scope_override IN ('ALL', 'ORG_AND_BELOW', 'OWN_ORG', 'EXPLICIT_SET', 'SELF')
    ),
    -- CAP-AUTHZ-008：临时授权必须有理由与到期时间
    CONSTRAINT ck_role_assignment_temporary CHECK (
        NOT is_temporary OR (expires_at IS NOT NULL AND justification IS NOT NULL)
    ),
    CONSTRAINT ck_role_assignment_revoked CHECK ((assignment_state = 'REVOKED') = (revoked_at IS NOT NULL))
);
COMMENT ON TABLE authz.role_assignment IS 'CAP-AUTHZ-002 授权关系；subject_id 为多态引用故无外键；INV-G-006：无本表记录即拒绝';
COMMENT ON COLUMN authz.role_assignment.last_used_at IS 'CAP-AUTHZ-024 闲置权限识别与自动回收的输入';

CREATE OR REPLACE TRIGGER trg_role_assignment_touch
    BEFORE UPDATE ON authz.role_assignment
    FOR EACH ROW EXECUTE FUNCTION core.fn_touch_updated_at();

CREATE UNIQUE INDEX IF NOT EXISTS ux_role_assignment_active
    ON authz.role_assignment (subject_kind, subject_id, role_id, scope_kind, scope_ref_id)
    WHERE assignment_state = 'ACTIVE';

CREATE INDEX IF NOT EXISTS ix_role_assignment_subject ON authz.role_assignment (subject_kind, subject_id, assignment_state);
CREATE INDEX IF NOT EXISTS ix_role_assignment_tenant ON authz.role_assignment (tenant_id, assignment_state);
CREATE INDEX IF NOT EXISTS ix_role_assignment_expiry ON authz.role_assignment (expires_at) WHERE assignment_state = 'ACTIVE' AND expires_at IS NOT NULL;
CREATE INDEX IF NOT EXISTS ix_role_assignment_review ON authz.role_assignment (last_reviewed_at) WHERE assignment_state = 'ACTIVE';

-- -----------------------------------------------------------------------------
-- 4. 策略发布（CAP-AUTHZ-010、REQ-AUTHZ-010、INV-G-011）
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS authz.policy_release (
    id                 uuid        NOT NULL DEFAULT core.uuid_generate_v7(),
    policy_scope_kind  text        NOT NULL,
    policy_scope_ref   uuid        NOT NULL DEFAULT '00000000-0000-0000-0000-000000000000',
    policy_version     bigint      NOT NULL,
    release_state      text        NOT NULL DEFAULT 'DRAFT',
    content_hash       bytea       NOT NULL,
    content            jsonb       NOT NULL,
    test_report_ref    text        NULL,
    shadow_result      jsonb       NULL,
    submitted_by_ref   text        NOT NULL,
    submitted_at       timestamptz NOT NULL DEFAULT now(),
    validated_at       timestamptz NULL,
    approved_by_ref    text        NULL,
    approved_at        timestamptz NULL,
    staged_at          timestamptz NULL,
    activated_at       timestamptz NULL,
    deprecated_at      timestamptz NULL,
    revoked_at         timestamptz NULL,
    rollback_of_id     uuid        NULL,
    canary_percentage  smallint    NULL,
    CONSTRAINT pk_policy_release PRIMARY KEY (id),
    CONSTRAINT uq_policy_release_version UNIQUE (policy_scope_kind, policy_scope_ref, policy_version),
    CONSTRAINT fk_policy_release_rollback FOREIGN KEY (rollback_of_id) REFERENCES authz.policy_release (id),
    CONSTRAINT ck_policy_release_state CHECK (release_state IN (
        'DRAFT', 'VALIDATED', 'APPROVED', 'STAGED', 'ACTIVE', 'DEPRECATED', 'REVOKED'
    )),
    -- INV-G-011 / REQ-CTRL-002：提交人不得自审
    CONSTRAINT ck_policy_release_separation CHECK (
        approved_by_ref IS NULL OR approved_by_ref <> submitted_by_ref
    ),
    CONSTRAINT ck_policy_release_approved CHECK (
        release_state NOT IN ('APPROVED', 'STAGED', 'ACTIVE') OR (approved_at IS NOT NULL AND approved_by_ref IS NOT NULL)
    ),
    CONSTRAINT ck_policy_release_active CHECK (release_state <> 'ACTIVE' OR activated_at IS NOT NULL),
    CONSTRAINT ck_policy_release_hash CHECK (octet_length(content_hash) = 32),
    CONSTRAINT ck_policy_release_canary CHECK (canary_percentage IS NULL OR canary_percentage BETWEEN 1 AND 100),
    CONSTRAINT ck_policy_release_version_positive CHECK (policy_version >= 1)
);
COMMENT ON TABLE authz.policy_release IS 'CAP-AUTHZ-010 / REQ-AUTHZ-010：策略版本化发布；回滚必须生成新版本（rollback_of_id），不得改写历史（AT-CTRL-004）';

-- INV-G-006：每个作用域同时只能有一个 ACTIVE 策略版本
CREATE UNIQUE INDEX IF NOT EXISTS ux_policy_release_active
    ON authz.policy_release (policy_scope_kind, policy_scope_ref)
    WHERE release_state = 'ACTIVE';

CREATE INDEX IF NOT EXISTS ix_policy_release_state ON authz.policy_release (release_state, submitted_at DESC);

-- -----------------------------------------------------------------------------
-- 5. 义务契约与 PEP 能力声明（REQ-AUTHZ-014/015/016）
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS authz.obligation_type (
    obligation_code   text        NOT NULL,
    schema_version    integer     NOT NULL,
    display_name      text        NOT NULL,
    params_schema     jsonb       NOT NULL,
    enforcement_point text        NOT NULL,
    is_mandatory      boolean     NOT NULL DEFAULT true,
    deprecated_at     timestamptz NULL,
    CONSTRAINT pk_obligation_type PRIMARY KEY (obligation_code, schema_version),
    CONSTRAINT ck_obligation_enforcement CHECK (enforcement_point IN ('PRE_HANDLER', 'DATA_ACCESS', 'RESPONSE', 'POST_COMMIT'))
);
COMMENT ON TABLE authz.obligation_type IS 'REQ-AUTHZ-014：义务使用版本化 Schema，至少含类型、参数、适用资源与执行时点';

CREATE TABLE IF NOT EXISTS authz.pep_capability (
    pep_code              text        NOT NULL,
    display_name          text        NOT NULL,
    supported_obligations text[]      NOT NULL DEFAULT '{}',
    obligation_schema_versions jsonb  NOT NULL DEFAULT '{}'::jsonb,
    last_reported_at      timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT pk_pep_capability PRIMARY KEY (pep_code)
);
COMMENT ON TABLE authz.pep_capability IS 'REQ-AUTHZ-015：PDP 不得向不支持该义务的 PEP 返回允许结果（AT-AUTHZ-008）';

-- -----------------------------------------------------------------------------
-- 6. 决策日志（CAP-AUTHZ-018/019，按月分区，追加型）
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS authz.decision_log (
    id                  uuid        NOT NULL DEFAULT core.uuid_generate_v7(),
    occurred_at         timestamptz NOT NULL DEFAULT now(),
    decision_ref        text        NOT NULL,
    subject_ref         text        NOT NULL,
    actor_ref           text        NULL,
    resource_type       text        NOT NULL,
    resource_ref        text        NULL,
    resource_version    text        NULL,
    action_code         text        NOT NULL,
    tenant_id           uuid        NOT NULL DEFAULT '00000000-0000-0000-0000-000000000000',
    decision_result     text        NOT NULL,
    reason_code         text        NOT NULL,
    matched_rules       text[]      NOT NULL DEFAULT '{}',
    obligations         jsonb       NULL,
    policy_version      bigint      NOT NULL,
    profile_code        text        NOT NULL,
    assurance_snapshot  jsonb       NULL,
    pip_freshness       jsonb       NULL,
    cache_key_hash      bytea       NULL,
    decision_ttl_seconds integer    NULL,
    latency_micros      integer     NULL,
    trace_id            text        NULL,
    CONSTRAINT pk_decision_log PRIMARY KEY (id, occurred_at),
    CONSTRAINT ck_decision_log_result CHECK (decision_result IN ('ALLOW', 'DENY', 'INDETERMINATE')),
    -- REQ-AUTHZ-008：不可确定必须按拒绝执行，因此不允许出现"不可确定但放行"
    CONSTRAINT ck_decision_log_fail_closed CHECK (decision_result <> 'INDETERMINATE' OR decision_ttl_seconds IS NULL)
) PARTITION BY RANGE (occurred_at);
COMMENT ON TABLE authz.decision_log IS 'CAP-AUTHZ-018/019：决策证据；cache_key_hash 对应 REQ-AUTHZ-007 的完整缓存键摘要（AT-AUTHZ-007）';

SELECT core.fn_ensure_monthly_partitions('authz', 'decision_log', 3, true);
SELECT core.fn_ensure_default_partition('authz', 'decision_log', true);

CREATE INDEX IF NOT EXISTS ix_decision_log_subject ON authz.decision_log (subject_ref, occurred_at DESC);
CREATE INDEX IF NOT EXISTS ix_decision_log_deny ON authz.decision_log (occurred_at DESC) WHERE decision_result <> 'ALLOW';

SELECT core.fn_apply_standard_grants('authz');
SELECT core.fn_apply_append_only_grants('authz', 'decision_log');

SELECT core.fn_migration_apply('080', 'authz：权限目录、角色、授权关系、职责分离、策略发布、义务契约、决策日志');
