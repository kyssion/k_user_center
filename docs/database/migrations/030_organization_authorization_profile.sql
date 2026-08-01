-- =============================================================================
-- 030_organization_authorization_profile.sql
-- 业务线、租户、组织、Membership、RBAC/PDP 契约与 Profile
-- =============================================================================

BEGIN;
SET LOCAL lock_timeout = '10s';
SET LOCAL statement_timeout = '5min';

CREATE TABLE org.business_line (
    id                    uuid        NOT NULL DEFAULT gen_random_uuid(),
    public_id             text        NOT NULL,
    business_line_code    text        NOT NULL,
    display_name          text        NOT NULL,
    business_line_state   text        NOT NULL DEFAULT 'PROVISIONING',
    owner_ref             text        NOT NULL,
    data_residency_region text        NOT NULL,
    default_locale        text        NOT NULL DEFAULT 'zh-CN',
    created_at            timestamptz NOT NULL DEFAULT clock_timestamp(),
    activated_at          timestamptz NULL,
    closed_at             timestamptz NULL,
    updated_at            timestamptz NOT NULL DEFAULT clock_timestamp(),
    row_version           bigint      NOT NULL DEFAULT 1,
    CONSTRAINT pk_business_line PRIMARY KEY (id),
    CONSTRAINT uq_business_line_public_id UNIQUE (public_id),
    CONSTRAINT uq_business_line_code UNIQUE (business_line_code),
    CONSTRAINT ck_business_line_code CHECK (business_line_code ~ '^[a-z][a-z0-9_-]{1,62}$'),
    CONSTRAINT ck_business_line_state CHECK (business_line_state IN ('PROVISIONING', 'ACTIVE', 'SUSPENDED', 'CLOSING', 'CLOSED')),
    CONSTRAINT ck_business_line_closed CHECK ((business_line_state = 'CLOSED') = (closed_at IS NOT NULL))
);
COMMENT ON TABLE org.business_line IS 'CAP-TENANT-001：业务线隔离根、数据驻留与责任人台账；不承载业务事实数据。';

CREATE TABLE org.tenant (
    id                    uuid        NOT NULL DEFAULT gen_random_uuid(),
    public_id             text        NOT NULL,
    business_line_id      uuid        NOT NULL,
    tenant_code           text        NOT NULL,
    display_name          text        NOT NULL,
    tenant_state          text        NOT NULL DEFAULT 'PROVISIONING',
    tenant_type           text        NOT NULL DEFAULT 'ENTERPRISE',
    owner_membership_id   uuid        NULL,
    data_residency_region text        NOT NULL,
    tenant_security_epoch bigint      NOT NULL DEFAULT 1,
    close_operation_id    uuid        NULL,
    irreversible_at       timestamptz NULL,
    created_at            timestamptz NOT NULL DEFAULT clock_timestamp(),
    activated_at          timestamptz NULL,
    closing_at            timestamptz NULL,
    closed_at             timestamptz NULL,
    updated_at            timestamptz NOT NULL DEFAULT clock_timestamp(),
    row_version           bigint      NOT NULL DEFAULT 1,
    CONSTRAINT pk_tenant PRIMARY KEY (id),
    CONSTRAINT uq_tenant_public_id UNIQUE (public_id),
    CONSTRAINT uq_tenant_code UNIQUE (business_line_id, tenant_code),
    CONSTRAINT fk_tenant_business_line FOREIGN KEY (business_line_id) REFERENCES org.business_line(id),
    CONSTRAINT fk_tenant_close_operation FOREIGN KEY (close_operation_id) REFERENCES core.async_operation(id),
    CONSTRAINT ck_tenant_code CHECK (tenant_code ~ '^[a-z][a-z0-9_-]{1,62}$'),
    CONSTRAINT ck_tenant_state CHECK (tenant_state IN ('PROVISIONING', 'ACTIVE', 'SUSPENDED', 'CLOSING', 'CLOSED')),
    CONSTRAINT ck_tenant_type CHECK (tenant_type IN ('ENTERPRISE', 'CONSUMER_SEGMENT', 'PARTNER', 'PLATFORM')),
    CONSTRAINT ck_tenant_epoch CHECK (tenant_security_epoch >= 1),
    CONSTRAINT ck_tenant_closed CHECK ((tenant_state = 'CLOSED') = (closed_at IS NOT NULL)),
    CONSTRAINT ck_tenant_irreversible CHECK (irreversible_at IS NULL OR tenant_state IN ('CLOSING', 'CLOSED'))
);
COMMENT ON TABLE org.tenant IS 'CAP-TENANT-002/010：租户生命周期、数据驻留与 security epoch；CLOSED 为不可恢复终态。';

CREATE TABLE org.tenant_domain (
    id                    uuid        NOT NULL DEFAULT gen_random_uuid(),
    tenant_id             uuid        NOT NULL,
    normalized_domain     text        NOT NULL,
    domain_state          text        NOT NULL DEFAULT 'PENDING',
    verification_method   text        NOT NULL,
    verification_token_hash bytea     NOT NULL,
    auto_route_enabled    boolean     NOT NULL DEFAULT false,
    jit_enabled           boolean     NOT NULL DEFAULT false,
    last_verified_at      timestamptz NULL,
    verification_expires_at timestamptz NULL,
    revoked_at            timestamptz NULL,
    created_at            timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at            timestamptz NOT NULL DEFAULT clock_timestamp(),
    row_version           bigint      NOT NULL DEFAULT 1,
    CONSTRAINT pk_tenant_domain PRIMARY KEY (id),
    CONSTRAINT uq_tenant_domain UNIQUE (normalized_domain),
    CONSTRAINT fk_tenant_domain_tenant FOREIGN KEY (tenant_id) REFERENCES org.tenant(id),
    CONSTRAINT ck_tenant_domain_value CHECK (normalized_domain = lower(normalized_domain) AND normalized_domain ~ '^[a-z0-9.-]+$'),
    CONSTRAINT ck_tenant_domain_state CHECK (domain_state IN ('PENDING', 'VERIFIED', 'EXPIRED', 'REVOKED')),
    CONSTRAINT ck_tenant_domain_method CHECK (verification_method IN ('DNS_TXT', 'HTTPS_WELL_KNOWN', 'MANUAL_EXCEPTION')),
    CONSTRAINT ck_tenant_domain_hash CHECK (octet_length(verification_token_hash) = 32),
    CONSTRAINT ck_tenant_domain_route CHECK (NOT auto_route_enabled OR domain_state = 'VERIFIED')
);
COMMENT ON TABLE org.tenant_domain IS 'REQ-TENANT-008：租户域名所有权持续验证、自动路由与 JIT 开关。';

CREATE TABLE org.organization (
    id                    uuid        NOT NULL DEFAULT gen_random_uuid(),
    public_id             text        NOT NULL,
    tenant_id             uuid        NOT NULL,
    parent_id             uuid        NULL,
    organization_code     text        NOT NULL,
    display_name          text        NOT NULL,
    organization_kind     text        NOT NULL DEFAULT 'UNIT',
    organization_state    text        NOT NULL DEFAULT 'ACTIVE',
    hierarchy_path        text        NOT NULL,
    source_kind           text        NOT NULL DEFAULT 'PLATFORM',
    source_ref            text        NULL,
    created_at            timestamptz NOT NULL DEFAULT clock_timestamp(),
    closed_at             timestamptz NULL,
    updated_at            timestamptz NOT NULL DEFAULT clock_timestamp(),
    row_version           bigint      NOT NULL DEFAULT 1,
    CONSTRAINT pk_organization PRIMARY KEY (id),
    CONSTRAINT uq_organization_public_id UNIQUE (public_id),
    CONSTRAINT uq_organization_code UNIQUE (tenant_id, organization_code),
    CONSTRAINT uq_organization_path UNIQUE (tenant_id, hierarchy_path),
    CONSTRAINT fk_organization_tenant FOREIGN KEY (tenant_id) REFERENCES org.tenant(id),
    CONSTRAINT fk_organization_parent FOREIGN KEY (parent_id) REFERENCES org.organization(id),
    CONSTRAINT ck_organization_kind CHECK (organization_kind IN ('ROOT', 'COMPANY', 'DIVISION', 'DEPARTMENT', 'TEAM', 'UNIT')),
    CONSTRAINT ck_organization_state CHECK (organization_state IN ('ACTIVE', 'SUSPENDED', 'CLOSED')),
    CONSTRAINT ck_organization_source CHECK (source_kind IN ('PLATFORM', 'SCIM', 'DIRECTORY', 'MIGRATION')),
    CONSTRAINT ck_organization_closed CHECK ((organization_state = 'CLOSED') = (closed_at IS NOT NULL))
);
COMMENT ON TABLE org.organization IS 'CAP-TENANT-005：租户内组织层级、权威来源和稳定外部引用。';

CREATE TABLE org.membership (
    id                    uuid        NOT NULL DEFAULT gen_random_uuid(),
    public_id             text        NOT NULL,
    user_id               uuid        NOT NULL,
    business_line_id      uuid        NOT NULL,
    tenant_id             uuid        NOT NULL,
    organization_id       uuid        NULL,
    membership_state      text        NOT NULL DEFAULT 'INVITED',
    membership_kind       text        NOT NULL DEFAULT 'MEMBER',
    source_kind           text        NOT NULL DEFAULT 'DIRECT',
    source_ref            text        NULL,
    joined_at             timestamptz NULL,
    suspended_at          timestamptz NULL,
    banned_at             timestamptz NULL,
    left_at               timestamptz NULL,
    expires_at            timestamptz NULL,
    state_reason_code     text        NULL,
    created_at            timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at            timestamptz NOT NULL DEFAULT clock_timestamp(),
    row_version           bigint      NOT NULL DEFAULT 1,
    CONSTRAINT pk_membership PRIMARY KEY (id),
    CONSTRAINT uq_membership_public_id UNIQUE (public_id),
    CONSTRAINT fk_membership_user FOREIGN KEY (user_id) REFERENCES iam.user_account(id),
    CONSTRAINT fk_membership_business_line FOREIGN KEY (business_line_id) REFERENCES org.business_line(id),
    CONSTRAINT fk_membership_tenant FOREIGN KEY (tenant_id) REFERENCES org.tenant(id),
    CONSTRAINT fk_membership_organization FOREIGN KEY (organization_id) REFERENCES org.organization(id),
    CONSTRAINT ck_membership_state CHECK (membership_state IN ('INVITED', 'PENDING_APPROVAL', 'ACTIVE', 'SUSPENDED', 'BANNED', 'LEFT', 'REJECTED', 'EXPIRED')),
    CONSTRAINT ck_membership_kind CHECK (membership_kind IN ('OWNER', 'ADMIN', 'MEMBER', 'GUEST', 'SERVICE_CONTACT')),
    CONSTRAINT ck_membership_source CHECK (source_kind IN ('DIRECT', 'INVITATION', 'SCIM', 'JIT', 'MIGRATION')),
    CONSTRAINT ck_membership_joined CHECK (membership_state NOT IN ('ACTIVE', 'SUSPENDED', 'BANNED', 'LEFT') OR joined_at IS NOT NULL),
    CONSTRAINT ck_membership_left CHECK ((membership_state = 'LEFT') = (left_at IS NOT NULL))
);
COMMENT ON TABLE org.membership IS 'CAP-TENANT-003/004：用户在业务线、租户及可选组织范围内的成员关系；业务封禁仅修改本记录。';

CREATE TABLE org.invitation (
    id                    uuid        NOT NULL DEFAULT gen_random_uuid(),
    public_id             text        NOT NULL,
    business_line_id      uuid        NOT NULL,
    tenant_id             uuid        NOT NULL,
    organization_id       uuid        NULL,
    invitation_state      text        NOT NULL DEFAULT 'PENDING',
    target_identifier_kind text       NOT NULL,
    target_normalized_hash bytea      NOT NULL,
    invitation_token_hash bytea       NOT NULL,
    inviter_membership_id uuid        NOT NULL,
    preauthorized_role_ids uuid[]     NOT NULL DEFAULT '{}',
    preauthorization_hash bytea       NOT NULL,
    accepted_by_user_id   uuid        NULL,
    accepted_membership_id uuid       NULL,
    expires_at            timestamptz NOT NULL,
    accepted_at           timestamptz NULL,
    rejected_at           timestamptz NULL,
    revoked_at            timestamptz NULL,
    created_at            timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at            timestamptz NOT NULL DEFAULT clock_timestamp(),
    row_version           bigint      NOT NULL DEFAULT 1,
    CONSTRAINT pk_invitation PRIMARY KEY (id),
    CONSTRAINT uq_invitation_public_id UNIQUE (public_id),
    CONSTRAINT uq_invitation_token_hash UNIQUE (invitation_token_hash),
    CONSTRAINT fk_invitation_business_line FOREIGN KEY (business_line_id) REFERENCES org.business_line(id),
    CONSTRAINT fk_invitation_tenant FOREIGN KEY (tenant_id) REFERENCES org.tenant(id),
    CONSTRAINT fk_invitation_organization FOREIGN KEY (organization_id) REFERENCES org.organization(id),
    CONSTRAINT fk_invitation_inviter FOREIGN KEY (inviter_membership_id) REFERENCES org.membership(id),
    CONSTRAINT fk_invitation_user FOREIGN KEY (accepted_by_user_id) REFERENCES iam.user_account(id),
    CONSTRAINT fk_invitation_membership FOREIGN KEY (accepted_membership_id) REFERENCES org.membership(id),
    CONSTRAINT ck_invitation_state CHECK (invitation_state IN ('PENDING', 'ACCEPTED', 'REJECTED', 'EXPIRED', 'REVOKED')),
    CONSTRAINT ck_invitation_identifier_kind CHECK (target_identifier_kind IN ('EMAIL', 'PHONE', 'USERNAME', 'EXTERNAL_ID')),
    CONSTRAINT ck_invitation_hashes CHECK (octet_length(target_normalized_hash) = 32 AND octet_length(invitation_token_hash) = 32 AND octet_length(preauthorization_hash) = 32),
    CONSTRAINT ck_invitation_expiry CHECK (expires_at > created_at),
    CONSTRAINT ck_invitation_accept CHECK (invitation_state <> 'ACCEPTED' OR (accepted_at IS NOT NULL AND accepted_by_user_id IS NOT NULL AND accepted_membership_id IS NOT NULL))
);
COMMENT ON TABLE org.invitation IS 'REQ-TENANT-011：绑定租户范围、目标摘要、邀请人权限上限与过期时间的单次消费邀请。';

CREATE TABLE org.user_group (
    id                    uuid        NOT NULL DEFAULT gen_random_uuid(),
    public_id             text        NOT NULL,
    tenant_id             uuid        NOT NULL,
    organization_id       uuid        NULL,
    group_code            text        NOT NULL,
    display_name          text        NOT NULL,
    group_state           text        NOT NULL DEFAULT 'ACTIVE',
    source_kind           text        NOT NULL DEFAULT 'PLATFORM',
    source_ref            text        NULL,
    created_at            timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at            timestamptz NOT NULL DEFAULT clock_timestamp(),
    row_version           bigint      NOT NULL DEFAULT 1,
    CONSTRAINT pk_user_group PRIMARY KEY (id),
    CONSTRAINT uq_user_group_public_id UNIQUE (public_id),
    CONSTRAINT uq_user_group_code UNIQUE (tenant_id, group_code),
    CONSTRAINT fk_user_group_tenant FOREIGN KEY (tenant_id) REFERENCES org.tenant(id),
    CONSTRAINT fk_user_group_org FOREIGN KEY (organization_id) REFERENCES org.organization(id),
    CONSTRAINT ck_user_group_state CHECK (group_state IN ('ACTIVE', 'SUSPENDED', 'CLOSED')),
    CONSTRAINT ck_user_group_source CHECK (source_kind IN ('PLATFORM', 'SCIM', 'DIRECTORY'))
);
COMMENT ON TABLE org.user_group IS 'CAP-TENANT-006：租户内用户组及其目录来源映射。';

CREATE TABLE org.group_member (
    id                    uuid        NOT NULL DEFAULT gen_random_uuid(),
    group_id              uuid        NOT NULL,
    user_id               uuid        NULL,
    nested_group_id       uuid        NULL,
    membership_state      text        NOT NULL DEFAULT 'ACTIVE',
    source_ref            text        NULL,
    valid_from            timestamptz NOT NULL DEFAULT clock_timestamp(),
    valid_until           timestamptz NULL,
    created_at            timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT pk_group_member PRIMARY KEY (id),
    CONSTRAINT fk_group_member_group FOREIGN KEY (group_id) REFERENCES org.user_group(id),
    CONSTRAINT fk_group_member_user FOREIGN KEY (user_id) REFERENCES iam.user_account(id),
    CONSTRAINT fk_group_member_nested FOREIGN KEY (nested_group_id) REFERENCES org.user_group(id),
    CONSTRAINT ck_group_member_target CHECK (num_nonnulls(user_id, nested_group_id) = 1),
    CONSTRAINT ck_group_member_self CHECK (nested_group_id IS NULL OR nested_group_id <> group_id),
    CONSTRAINT ck_group_member_state CHECK (membership_state IN ('ACTIVE', 'SUSPENDED', 'REMOVED')),
    CONSTRAINT ck_group_member_window CHECK (valid_until IS NULL OR valid_until > valid_from)
);
COMMENT ON TABLE org.group_member IS '组织用户组成员与有限嵌套关系；循环检测由写服务事务内递归查询完成。';

CREATE TABLE org.usage_meter (
    id                    uuid        NOT NULL DEFAULT gen_random_uuid(),
    tenant_id             uuid        NOT NULL,
    meter_code            text        NOT NULL,
    period_start          timestamptz NOT NULL,
    period_end            timestamptz NOT NULL,
    measured_value        numeric(20,4) NOT NULL,
    source_version        bigint      NOT NULL,
    measured_at           timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT pk_usage_meter PRIMARY KEY (id),
    CONSTRAINT uq_usage_meter UNIQUE (tenant_id, meter_code, period_start, source_version),
    CONSTRAINT fk_usage_meter_tenant FOREIGN KEY (tenant_id) REFERENCES org.tenant(id),
    CONSTRAINT ck_usage_meter_window CHECK (period_end > period_start),
    CONSTRAINT ck_usage_meter_value CHECK (measured_value >= 0 AND source_version >= 1)
);
COMMENT ON TABLE org.usage_meter IS 'CAP-TENANT-011：租户配额与计量快照；不作为计费业务事实的权威来源。';

CREATE TABLE authz.permission (
    id                    uuid        NOT NULL DEFAULT gen_random_uuid(),
    permission_code       text        NOT NULL,
    resource_type         text        NOT NULL,
    action_code           text        NOT NULL,
    risk_tier             text        NOT NULL DEFAULT 'NORMAL',
    required_profile_code text        NOT NULL DEFAULT 'SP1',
    description           text        NOT NULL,
    is_active             boolean     NOT NULL DEFAULT true,
    created_at            timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT pk_permission PRIMARY KEY (id),
    CONSTRAINT uq_permission_code UNIQUE (permission_code),
    CONSTRAINT uq_permission_tuple UNIQUE (resource_type, action_code),
    CONSTRAINT ck_permission_code CHECK (permission_code ~ '^[a-z][a-z0-9_.:-]{2,127}$'),
    CONSTRAINT ck_permission_risk CHECK (risk_tier IN ('LOW', 'NORMAL', 'HIGH', 'CRITICAL'))
);
COMMENT ON TABLE authz.permission IS 'CAP-AUTHZ-002：版本外稳定的原子资源动作权限目录。';

CREATE TABLE authz.role (
    id                    uuid        NOT NULL DEFAULT gen_random_uuid(),
    public_id             text        NOT NULL,
    role_code             text        NOT NULL,
    display_name          text        NOT NULL,
    scope_kind            text        NOT NULL,
    business_line_id      uuid        NULL,
    tenant_id             uuid        NULL,
    role_state            text        NOT NULL DEFAULT 'DRAFT',
    privilege_tier        text        NOT NULL DEFAULT 'STANDARD',
    owner_ref             text        NOT NULL,
    expires_at            timestamptz NULL,
    created_at            timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at            timestamptz NOT NULL DEFAULT clock_timestamp(),
    row_version           bigint      NOT NULL DEFAULT 1,
    CONSTRAINT pk_role PRIMARY KEY (id),
    CONSTRAINT uq_role_public_id UNIQUE (public_id),
    CONSTRAINT uq_role_code_scope UNIQUE NULLS NOT DISTINCT (role_code, scope_kind, business_line_id, tenant_id),
    CONSTRAINT fk_role_business_line FOREIGN KEY (business_line_id) REFERENCES org.business_line(id),
    CONSTRAINT fk_role_tenant FOREIGN KEY (tenant_id) REFERENCES org.tenant(id),
    CONSTRAINT ck_role_scope CHECK (scope_kind IN ('PLATFORM', 'BUSINESS_LINE', 'TENANT', 'ORGANIZATION')),
    CONSTRAINT ck_role_scope_value CHECK (
        (scope_kind = 'PLATFORM' AND business_line_id IS NULL AND tenant_id IS NULL)
        OR (scope_kind = 'BUSINESS_LINE' AND business_line_id IS NOT NULL AND tenant_id IS NULL)
        OR (scope_kind IN ('TENANT', 'ORGANIZATION') AND tenant_id IS NOT NULL)
    ),
    CONSTRAINT ck_role_state CHECK (role_state IN ('DRAFT', 'ACTIVE', 'SUSPENDED', 'RETIRED')),
    CONSTRAINT ck_role_tier CHECK (privilege_tier IN ('STANDARD', 'ELEVATED', 'PRIVILEGED', 'BREAK_GLASS'))
);
COMMENT ON TABLE authz.role IS 'CAP-AUTHZ-003：平台、业务线、租户或组织作用域角色与权限级别。';

CREATE TABLE authz.role_permission (
    role_id               uuid        NOT NULL,
    permission_id         uuid        NOT NULL,
    effect                text        NOT NULL DEFAULT 'ALLOW',
    data_scope_expression jsonb       NULL,
    obligation_codes      text[]      NOT NULL DEFAULT '{}',
    valid_from            timestamptz NOT NULL DEFAULT clock_timestamp(),
    valid_until           timestamptz NULL,
    CONSTRAINT pk_role_permission PRIMARY KEY (role_id, permission_id),
    CONSTRAINT fk_role_permission_role FOREIGN KEY (role_id) REFERENCES authz.role(id) ON DELETE CASCADE,
    CONSTRAINT fk_role_permission_permission FOREIGN KEY (permission_id) REFERENCES authz.permission(id),
    CONSTRAINT ck_role_permission_effect CHECK (effect IN ('ALLOW', 'DENY')),
    CONSTRAINT ck_role_permission_window CHECK (valid_until IS NULL OR valid_until > valid_from)
);
COMMENT ON TABLE authz.role_permission IS 'CAP-AUTHZ-004/005：角色的允许/显式拒绝、数据范围及强制义务；拒绝优先。';

CREATE TABLE authz.role_exclusion (
    role_id               uuid        NOT NULL,
    excluded_role_id      uuid        NOT NULL,
    exclusion_reason      text        NOT NULL,
    CONSTRAINT pk_role_exclusion PRIMARY KEY (role_id, excluded_role_id),
    CONSTRAINT fk_role_exclusion_role FOREIGN KEY (role_id) REFERENCES authz.role(id),
    CONSTRAINT fk_role_exclusion_other FOREIGN KEY (excluded_role_id) REFERENCES authz.role(id),
    CONSTRAINT ck_role_exclusion_self CHECK (role_id <> excluded_role_id)
);
COMMENT ON TABLE authz.role_exclusion IS '职责分离与互斥角色约束目录；双向完整性由发布校验保证。';

CREATE TABLE authz.role_assignment (
    id                    uuid        NOT NULL DEFAULT gen_random_uuid(),
    role_id               uuid        NOT NULL,
    subject_kind          text        NOT NULL,
    subject_id            uuid        NOT NULL,
    business_line_id      uuid        NULL,
    tenant_id             uuid        NULL,
    organization_id       uuid        NULL,
    assignment_state      text        NOT NULL DEFAULT 'ACTIVE',
    granted_by_ref        text        NOT NULL,
    approval_case_id      uuid        NULL,
    valid_from            timestamptz NOT NULL DEFAULT clock_timestamp(),
    valid_until           timestamptz NULL,
    revoked_at            timestamptz NULL,
    revoke_reason_code    text        NULL,
    created_at            timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at            timestamptz NOT NULL DEFAULT clock_timestamp(),
    row_version           bigint      NOT NULL DEFAULT 1,
    CONSTRAINT pk_role_assignment PRIMARY KEY (id),
    CONSTRAINT fk_role_assignment_role FOREIGN KEY (role_id) REFERENCES authz.role(id),
    CONSTRAINT fk_role_assignment_business_line FOREIGN KEY (business_line_id) REFERENCES org.business_line(id),
    CONSTRAINT fk_role_assignment_tenant FOREIGN KEY (tenant_id) REFERENCES org.tenant(id),
    CONSTRAINT fk_role_assignment_org FOREIGN KEY (organization_id) REFERENCES org.organization(id),
    CONSTRAINT ck_role_assignment_subject CHECK (subject_kind IN ('USER', 'MEMBERSHIP', 'GROUP', 'CLIENT', 'MACHINE')),
    CONSTRAINT ck_role_assignment_state CHECK (assignment_state IN ('ACTIVE', 'SUSPENDED', 'REVOKED', 'EXPIRED')),
    CONSTRAINT ck_role_assignment_window CHECK (valid_until IS NULL OR valid_until > valid_from),
    CONSTRAINT ck_role_assignment_revoked CHECK ((assignment_state = 'REVOKED') = (revoked_at IS NOT NULL))
);
COMMENT ON TABLE authz.role_assignment IS 'CAP-AUTHZ-006/016：主体在明确范围内的角色授予、临时有效期、审批与撤回证据。';

CREATE TABLE authz.policy_release (
    id                    uuid        NOT NULL DEFAULT gen_random_uuid(),
    public_id             text        NOT NULL,
    policy_code           text        NOT NULL,
    policy_version        bigint      NOT NULL,
    policy_state          text        NOT NULL DEFAULT 'DRAFT',
    policy_language       text        NOT NULL,
    content_hash          bytea       NOT NULL,
    content_uri           text        NOT NULL,
    owner_ref             text        NOT NULL,
    approval_case_id      uuid        NULL,
    activated_at          timestamptz NULL,
    retired_at            timestamptz NULL,
    created_at            timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT pk_policy_release PRIMARY KEY (id),
    CONSTRAINT uq_policy_release_public_id UNIQUE (public_id),
    CONSTRAINT uq_policy_release_version UNIQUE (policy_code, policy_version),
    CONSTRAINT ck_policy_release_state CHECK (policy_state IN ('DRAFT', 'VALIDATED', 'APPROVED', 'STAGED', 'ACTIVE', 'DEPRECATED', 'REVOKED')),
    CONSTRAINT ck_policy_release_language CHECK (policy_language IN ('CEL', 'REGO', 'CEDAR', 'CUSTOM_IR')),
    CONSTRAINT ck_policy_release_hash CHECK (octet_length(content_hash) = 32),
    CONSTRAINT ck_policy_release_active CHECK (policy_state <> 'ACTIVE' OR (approval_case_id IS NOT NULL AND activated_at IS NOT NULL))
);
COMMENT ON TABLE authz.policy_release IS 'REQ-AUTHZ-010 / INV-G-011：不可变、测试、审批、灰度和发布的 PDP 策略版本。';

CREATE TABLE authz.obligation_type (
    obligation_code       text        NOT NULL,
    schema_version        integer     NOT NULL,
    display_name          text        NOT NULL,
    parameter_schema      jsonb       NOT NULL,
    execution_point       text        NOT NULL,
    is_mandatory          boolean     NOT NULL DEFAULT true,
    is_active             boolean     NOT NULL DEFAULT true,
    CONSTRAINT pk_obligation_type PRIMARY KEY (obligation_code, schema_version),
    CONSTRAINT ck_obligation_execution CHECK (execution_point IN ('BEFORE_QUERY', 'QUERY_FILTER', 'BEFORE_COMMIT', 'RESPONSE_TRANSFORM', 'AFTER_COMMIT'))
);
COMMENT ON TABLE authz.obligation_type IS 'REQ-AUTHZ-014：Step-up、脱敏、行过滤、水印和附加审计等版本化义务 Schema。';

CREATE TABLE authz.pep_capability (
    pep_id                text        NOT NULL,
    environment           text        NOT NULL,
    supported_obligations jsonb       NOT NULL,
    capability_version    bigint      NOT NULL,
    last_reported_at      timestamptz NOT NULL,
    expires_at            timestamptz NOT NULL,
    CONSTRAINT pk_pep_capability PRIMARY KEY (pep_id, environment),
    CONSTRAINT ck_pep_capability_version CHECK (capability_version >= 1),
    CONSTRAINT ck_pep_capability_expiry CHECK (expires_at > last_reported_at)
);
COMMENT ON TABLE authz.pep_capability IS 'REQ-AUTHZ-015/016：PEP 声明可执行义务与新鲜度，能力缺失时 PDP 不得允许。';

CREATE TABLE authz.authorization_decision (
    id                    uuid        NOT NULL DEFAULT gen_random_uuid(),
    public_id             text        NOT NULL,
    subject_kind          text        NOT NULL,
    subject_ref           text        NOT NULL,
    actor_kind            text        NULL,
    actor_ref             text        NULL,
    resource_type         text        NOT NULL,
    resource_ref          text        NULL,
    resource_version      text        NULL,
    action_code           text        NOT NULL,
    tenant_id             uuid        NOT NULL DEFAULT '00000000-0000-0000-0000-000000000000',
    environment           text        NOT NULL,
    risk_level            text        NOT NULL,
    achieved_aal          text        NULL,
    input_hash            bytea       NOT NULL,
    decision_effect       text        NOT NULL,
    reason_codes          text[]      NOT NULL DEFAULT '{}',
    obligations           jsonb       NOT NULL DEFAULT '[]',
    policy_version        bigint      NOT NULL,
    pip_versions          jsonb       NOT NULL,
    security_epochs       jsonb       NOT NULL,
    valid_until           timestamptz NOT NULL,
    decided_at            timestamptz NOT NULL DEFAULT clock_timestamp(),
    trace_id              text        NULL,
    CONSTRAINT pk_authorization_decision PRIMARY KEY (id),
    CONSTRAINT uq_authorization_decision_public_id UNIQUE (public_id),
    CONSTRAINT ck_authorization_decision_actor CHECK ((actor_kind IS NULL) = (actor_ref IS NULL)),
    CONSTRAINT ck_authorization_decision_risk CHECK (risk_level IN ('UNKNOWN', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    CONSTRAINT ck_authorization_decision_aal CHECK (achieved_aal IS NULL OR achieved_aal IN ('AAL1', 'AAL2', 'AAL3')),
    CONSTRAINT ck_authorization_decision_effect CHECK (decision_effect IN ('ALLOW', 'DENY')),
    CONSTRAINT ck_authorization_decision_hash CHECK (octet_length(input_hash) = 32),
    CONSTRAINT ck_authorization_decision_ttl CHECK (valid_until >= decided_at)
);
COMMENT ON TABLE authz.authorization_decision IS 'REQ-AUTHZ-002/007/011：不可变授权决策证据，含完整输入摘要、原因、义务、策略/PIP/security epoch 与有效期。';

CREATE TABLE profile.field_definition (
    field_code            text        NOT NULL,
    namespace_code        text        NOT NULL,
    schema_version        integer     NOT NULL,
    value_type            text        NOT NULL,
    authority_domain      text        NOT NULL,
    classification_code   text        NOT NULL,
    purpose_codes         text[]      NOT NULL,
    visibility_rule       jsonb       NOT NULL,
    mutability_rule       jsonb       NOT NULL,
    retention_policy_code text        NOT NULL,
    validation_schema     jsonb       NOT NULL,
    is_active             boolean     NOT NULL DEFAULT true,
    CONSTRAINT pk_field_definition PRIMARY KEY (namespace_code, field_code, schema_version),
    CONSTRAINT fk_field_definition_class FOREIGN KEY (classification_code) REFERENCES core.data_classification(classification_code),
    CONSTRAINT ck_field_definition_type CHECK (value_type IN ('STRING', 'NUMBER', 'BOOLEAN', 'DATE', 'DATETIME', 'OBJECT', 'ARRAY', 'ENCRYPTED'))
);
COMMENT ON TABLE profile.field_definition IS 'REQ-PRIV-002：Profile 字段的命名空间、类型、权威方、分类、用途、可见/可改与保留元数据。';

CREATE TABLE profile.user_profile (
    user_id               uuid        NOT NULL,
    display_name          text        NULL,
    avatar_uri            text        NULL,
    locale                text        NOT NULL DEFAULT 'zh-CN',
    time_zone             text        NOT NULL DEFAULT 'Asia/Shanghai',
    profile_version       bigint      NOT NULL DEFAULT 1,
    updated_at            timestamptz NOT NULL DEFAULT clock_timestamp(),
    row_version           bigint      NOT NULL DEFAULT 1,
    CONSTRAINT pk_user_profile PRIMARY KEY (user_id),
    CONSTRAINT fk_user_profile_user FOREIGN KEY (user_id) REFERENCES iam.user_account(id),
    CONSTRAINT ck_user_profile_version CHECK (profile_version >= 1)
);
COMMENT ON TABLE profile.user_profile IS 'CAP-PROFILE-001/003：Global User 的最小公共资料；业务事实与业务扩展字段不进入本表。';

CREATE TABLE profile.sensitive_attribute (
    id                    uuid        NOT NULL DEFAULT gen_random_uuid(),
    user_id               uuid        NOT NULL,
    namespace_code        text        NOT NULL,
    field_code            text        NOT NULL,
    field_schema_version  integer     NOT NULL,
    encrypted_value       bytea       NOT NULL,
    encryption_key_ref    text        NOT NULL,
    value_hash            bytea       NULL,
    source_kind           text        NOT NULL,
    valid_from            timestamptz NOT NULL DEFAULT clock_timestamp(),
    valid_until           timestamptz NULL,
    created_at            timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at            timestamptz NOT NULL DEFAULT clock_timestamp(),
    row_version           bigint      NOT NULL DEFAULT 1,
    CONSTRAINT pk_sensitive_attribute PRIMARY KEY (id),
    CONSTRAINT uq_sensitive_attribute UNIQUE (user_id, namespace_code, field_code),
    CONSTRAINT fk_sensitive_attribute_user FOREIGN KEY (user_id) REFERENCES iam.user_account(id),
    CONSTRAINT fk_sensitive_attribute_definition FOREIGN KEY (namespace_code, field_code, field_schema_version) REFERENCES profile.field_definition(namespace_code, field_code, schema_version),
    CONSTRAINT ck_sensitive_attribute_source CHECK (source_kind IN ('USER', 'VERIFIED_SOURCE', 'TENANT', 'MIGRATION')),
    CONSTRAINT ck_sensitive_attribute_window CHECK (valid_until IS NULL OR valid_until > valid_from)
);
COMMENT ON TABLE profile.sensitive_attribute IS 'CAP-PROFILE-004/005：随机化加密保存的敏感扩展属性；不支持模糊或前缀检索。';

CREATE TABLE profile.business_profile (
    id                    uuid        NOT NULL DEFAULT gen_random_uuid(),
    membership_id         uuid        NOT NULL,
    namespace_code        text        NOT NULL,
    field_code            text        NOT NULL,
    field_schema_version  integer     NOT NULL,
    value_json            jsonb       NULL,
    encrypted_value       bytea       NULL,
    encryption_key_ref    text        NULL,
    authority_domain      text        NOT NULL,
    value_version         bigint      NOT NULL DEFAULT 1,
    created_at            timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at            timestamptz NOT NULL DEFAULT clock_timestamp(),
    row_version           bigint      NOT NULL DEFAULT 1,
    CONSTRAINT pk_business_profile PRIMARY KEY (id),
    CONSTRAINT uq_business_profile UNIQUE (membership_id, namespace_code, field_code),
    CONSTRAINT fk_business_profile_membership FOREIGN KEY (membership_id) REFERENCES org.membership(id),
    CONSTRAINT fk_business_profile_definition FOREIGN KEY (namespace_code, field_code, field_schema_version) REFERENCES profile.field_definition(namespace_code, field_code, schema_version),
    CONSTRAINT ck_business_profile_value CHECK (num_nonnulls(value_json, encrypted_value) = 1),
    CONSTRAINT ck_business_profile_key CHECK ((encrypted_value IS NULL) = (encryption_key_ref IS NULL)),
    CONSTRAINT ck_business_profile_version CHECK (value_version >= 1)
);
COMMENT ON TABLE profile.business_profile IS 'REQ-PRIV-001：按 Membership 隔离的业务扩展资料，受字段定义的权威域与可改规则约束。';

CREATE TABLE profile.profile_change (
    id                    uuid        NOT NULL DEFAULT gen_random_uuid(),
    user_id               uuid        NULL,
    membership_id         uuid        NULL,
    namespace_code        text        NOT NULL,
    field_code            text        NOT NULL,
    old_value_hash        bytea       NULL,
    new_value_hash        bytea       NULL,
    actor_kind            text        NOT NULL,
    actor_ref             text        NOT NULL,
    source_version        bigint      NOT NULL,
    trace_id              text        NULL,
    changed_at            timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT pk_profile_change PRIMARY KEY (id),
    CONSTRAINT fk_profile_change_user FOREIGN KEY (user_id) REFERENCES iam.user_account(id),
    CONSTRAINT fk_profile_change_membership FOREIGN KEY (membership_id) REFERENCES org.membership(id),
    CONSTRAINT ck_profile_change_subject CHECK (num_nonnulls(user_id, membership_id) = 1),
    CONSTRAINT ck_profile_change_actor CHECK (actor_kind IN ('USER', 'ADMIN', 'TENANT_ADMIN', 'SYSTEM', 'DIRECTORY')),
    CONSTRAINT ck_profile_change_version CHECK (source_version >= 1)
);
COMMENT ON TABLE profile.profile_change IS 'CAP-PROFILE-007 / CAP-EVENT-007：Profile 变更的版本、摘要、操作者和事件重放依据。';

CREATE TABLE profile.user_preference (
    id                    uuid        NOT NULL DEFAULT gen_random_uuid(),
    user_id               uuid        NOT NULL,
    preference_namespace  text        NOT NULL,
    preference_key        text        NOT NULL,
    preference_value      jsonb       NOT NULL,
    value_schema_version  integer     NOT NULL,
    source_kind           text        NOT NULL DEFAULT 'USER',
    updated_at            timestamptz NOT NULL DEFAULT clock_timestamp(),
    row_version           bigint      NOT NULL DEFAULT 1,
    CONSTRAINT pk_user_preference PRIMARY KEY (id),
    CONSTRAINT uq_user_preference UNIQUE (user_id, preference_namespace, preference_key),
    CONSTRAINT fk_user_preference_user FOREIGN KEY (user_id) REFERENCES iam.user_account(id),
    CONSTRAINT ck_user_preference_namespace CHECK (preference_namespace ~ '^[a-z][a-z0-9_.-]{1,63}$'),
    CONSTRAINT ck_user_preference_key CHECK (preference_key ~ '^[a-z][a-z0-9_.-]{1,63}$'),
    CONSTRAINT ck_user_preference_source CHECK (source_kind IN ('USER', 'SYSTEM_DEFAULT', 'TENANT_POLICY')),
    CONSTRAINT ck_user_preference_version CHECK (value_schema_version >= 1)
);
COMMENT ON TABLE profile.user_preference IS 'CAP-PROFILE-009：主题、语言、时区和其他非安全偏好的命名空间键值；安全约束不得被偏好覆盖。';

CREATE TABLE profile.notification_preference (
    id                    uuid        NOT NULL DEFAULT gen_random_uuid(),
    user_id               uuid        NOT NULL,
    notification_category text        NOT NULL,
    channel_code          text        NOT NULL,
    preference_state      text        NOT NULL DEFAULT 'ENABLED',
    mandatory             boolean     NOT NULL DEFAULT false,
    quiet_hours           jsonb       NULL,
    consent_id            uuid        NULL,
    consent_epoch         bigint      NULL,
    updated_at            timestamptz NOT NULL DEFAULT clock_timestamp(),
    row_version           bigint      NOT NULL DEFAULT 1,
    CONSTRAINT pk_notification_preference PRIMARY KEY (id),
    CONSTRAINT uq_notification_preference UNIQUE (user_id, notification_category, channel_code),
    CONSTRAINT fk_notification_preference_user FOREIGN KEY (user_id) REFERENCES iam.user_account(id),
    CONSTRAINT ck_notification_preference_category CHECK (notification_category IN ('SECURITY', 'TRANSACTIONAL', 'SERVICE', 'MARKETING')),
    CONSTRAINT ck_notification_preference_channel CHECK (channel_code IN ('SMS', 'EMAIL', 'PUSH', 'IN_APP', 'VOICE')),
    CONSTRAINT ck_notification_preference_state CHECK (preference_state IN ('ENABLED', 'DISABLED', 'SUPPRESSED')),
    CONSTRAINT ck_notification_preference_mandatory CHECK (NOT mandatory OR preference_state = 'ENABLED'),
    CONSTRAINT ck_notification_preference_consent CHECK (
        (consent_id IS NULL AND consent_epoch IS NULL) OR (consent_id IS NOT NULL AND consent_epoch IS NOT NULL)
    )
);
COMMENT ON TABLE profile.notification_preference IS 'CAP-PROFILE-010 / CAP-SSC-011：事务、安全、服务与营销通知分离；强制安全通知不可完全关闭。';

CREATE TABLE authz.relationship_tuple (
    id                    uuid        NOT NULL DEFAULT gen_random_uuid(),
    tenant_id             uuid        NOT NULL,
    subject_kind          text        NOT NULL,
    subject_ref           text        NOT NULL,
    relation_code         text        NOT NULL,
    object_kind           text        NOT NULL,
    object_ref            text        NOT NULL,
    relationship_state    text        NOT NULL DEFAULT 'ACTIVE',
    source_kind           text        NOT NULL,
    source_ref            text        NULL,
    valid_from            timestamptz NOT NULL DEFAULT clock_timestamp(),
    valid_until           timestamptz NULL,
    revoked_at            timestamptz NULL,
    created_at            timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at            timestamptz NOT NULL DEFAULT clock_timestamp(),
    row_version           bigint      NOT NULL DEFAULT 1,
    CONSTRAINT pk_relationship_tuple PRIMARY KEY (id),
    CONSTRAINT ck_relationship_tuple_subject CHECK (subject_kind IN ('USER', 'MEMBERSHIP', 'GROUP', 'CLIENT', 'MACHINE')),
    CONSTRAINT ck_relationship_tuple_state CHECK (relationship_state IN ('ACTIVE', 'SUSPENDED', 'REVOKED', 'EXPIRED')),
    CONSTRAINT ck_relationship_tuple_source CHECK (source_kind IN ('PLATFORM', 'BUSINESS_DOMAIN', 'DIRECTORY', 'MIGRATION')),
    CONSTRAINT ck_relationship_tuple_window CHECK (valid_until IS NULL OR valid_until > valid_from),
    CONSTRAINT ck_relationship_tuple_revoked CHECK ((relationship_state = 'REVOKED') = (revoked_at IS NOT NULL))
);
COMMENT ON TABLE authz.relationship_tuple IS 'CAP-AUTHZ-023：Owner、Member、Collaborator、Parent 等租户内关系型授权元组。';

CREATE TABLE authz.access_review (
    id                    uuid        NOT NULL DEFAULT gen_random_uuid(),
    public_id             text        NOT NULL,
    review_kind           text        NOT NULL,
    scope_definition      jsonb       NOT NULL,
    review_state          text        NOT NULL DEFAULT 'DRAFT',
    owner_ref             text        NOT NULL,
    operation_id          uuid        NOT NULL,
    due_at                timestamptz NOT NULL,
    reviewed_count        bigint      NOT NULL DEFAULT 0,
    retained_count        bigint      NOT NULL DEFAULT 0,
    revoked_count         bigint      NOT NULL DEFAULT 0,
    completed_at          timestamptz NULL,
    created_at            timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at            timestamptz NOT NULL DEFAULT clock_timestamp(),
    row_version           bigint      NOT NULL DEFAULT 1,
    CONSTRAINT pk_access_review PRIMARY KEY (id),
    CONSTRAINT uq_access_review_public_id UNIQUE (public_id),
    CONSTRAINT uq_access_review_operation UNIQUE (operation_id),
    CONSTRAINT fk_access_review_operation FOREIGN KEY (operation_id) REFERENCES core.async_operation(id),
    CONSTRAINT ck_access_review_kind CHECK (review_kind IN ('ROLE_ASSIGNMENT', 'PRIVILEGED_ACCESS', 'MACHINE_PERMISSION', 'CLIENT_SCOPE', 'RELATIONSHIP')),
    CONSTRAINT ck_access_review_state CHECK (review_state IN ('DRAFT', 'RUNNING', 'BLOCKED', 'COMPLETED', 'CANCELLED')),
    CONSTRAINT ck_access_review_counts CHECK (reviewed_count >= 0 AND retained_count >= 0 AND revoked_count >= 0 AND retained_count + revoked_count <= reviewed_count),
    CONSTRAINT ck_access_review_complete CHECK ((review_state = 'COMPLETED') = (completed_at IS NOT NULL))
);
COMMENT ON TABLE authz.access_review IS 'CAP-AUTHZ-024：角色、特权、机器权限、Client scope 与关系授权的定期复核和自动回收 Operation。';

CREATE TABLE authz.permission_simulation (
    id                    uuid        NOT NULL DEFAULT gen_random_uuid(),
    public_id             text        NOT NULL,
    requested_by_ref      text        NOT NULL,
    input_hash            bytea       NOT NULL,
    policy_version        bigint      NOT NULL,
    simulation_result     jsonb       NOT NULL,
    result_hash           bytea       NOT NULL,
    trace_id              text        NULL,
    simulated_at          timestamptz NOT NULL DEFAULT clock_timestamp(),
    expires_at            timestamptz NOT NULL,
    CONSTRAINT pk_permission_simulation PRIMARY KEY (id),
    CONSTRAINT uq_permission_simulation_public_id UNIQUE (public_id),
    CONSTRAINT ck_permission_simulation_hash CHECK (octet_length(input_hash) = 32 AND octet_length(result_hash) = 32),
    CONSTRAINT ck_permission_simulation_expiry CHECK (expires_at > simulated_at)
);
COMMENT ON TABLE authz.permission_simulation IS 'CAP-AUTHZ-020：上线前权限模拟的规范化输入、策略版本、结果与短期证据，不产生真实授权。';

ALTER TABLE oauth.application ADD CONSTRAINT fk_application_business_line FOREIGN KEY (business_line_id) REFERENCES org.business_line(id);
ALTER TABLE oauth.client ADD CONSTRAINT fk_client_business_line FOREIGN KEY (business_line_id) REFERENCES org.business_line(id);
ALTER TABLE oauth.api_resource ADD CONSTRAINT fk_api_resource_business_line FOREIGN KEY (business_line_id) REFERENCES org.business_line(id);

CREATE UNIQUE INDEX ux_membership_effective ON org.membership(user_id, tenant_id, COALESCE(organization_id, '00000000-0000-0000-0000-000000000000'::uuid)) WHERE membership_state NOT IN ('LEFT', 'REJECTED', 'EXPIRED');
CREATE INDEX ix_membership_tenant_state ON org.membership(tenant_id, membership_state, user_id);
CREATE INDEX ix_invitation_target ON org.invitation(tenant_id, target_normalized_hash) WHERE invitation_state = 'PENDING';
CREATE UNIQUE INDEX ux_group_member_user ON org.group_member(group_id, user_id) WHERE user_id IS NOT NULL AND membership_state <> 'REMOVED';
CREATE UNIQUE INDEX ux_group_member_group ON org.group_member(group_id, nested_group_id) WHERE nested_group_id IS NOT NULL AND membership_state <> 'REMOVED';
CREATE INDEX ix_role_assignment_subject ON authz.role_assignment(subject_kind, subject_id, assignment_state);
CREATE INDEX ix_role_assignment_scope ON authz.role_assignment(tenant_id, organization_id) WHERE assignment_state = 'ACTIVE';
CREATE UNIQUE INDEX ux_policy_release_active ON authz.policy_release(policy_code) WHERE policy_state = 'ACTIVE';
CREATE INDEX ix_authorization_decision_lookup ON authz.authorization_decision(subject_kind, subject_ref, action_code, decided_at DESC);
CREATE UNIQUE INDEX ux_relationship_tuple_active ON authz.relationship_tuple(tenant_id, subject_kind, subject_ref, relation_code, object_kind, object_ref) WHERE relationship_state = 'ACTIVE';
CREATE INDEX ix_access_review_due ON authz.access_review(due_at) WHERE review_state IN ('DRAFT', 'RUNNING', 'BLOCKED');

CREATE OR REPLACE FUNCTION org.fn_membership_scope_guard()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM org.tenant t WHERE t.id = NEW.tenant_id AND t.business_line_id = NEW.business_line_id) THEN
        RAISE EXCEPTION 'TENANT_SCOPE_MISMATCH' USING ERRCODE = '23514';
    END IF;
    IF NEW.organization_id IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM org.organization o WHERE o.id = NEW.organization_id AND o.tenant_id = NEW.tenant_id
    ) THEN
        RAISE EXCEPTION 'ORGANIZATION_SCOPE_MISMATCH' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;
COMMENT ON FUNCTION org.fn_membership_scope_guard() IS 'INV-G-015：Membership 的业务线、租户、组织必须属于同一隔离范围。';

CREATE OR REPLACE FUNCTION org.fn_invitation_scope_guard()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM org.tenant t WHERE t.id = NEW.tenant_id AND t.business_line_id = NEW.business_line_id AND t.tenant_state = 'ACTIVE') THEN
        RAISE EXCEPTION 'INVITATION_SCOPE_INVALID' USING ERRCODE = '23514';
    END IF;
    IF NEW.organization_id IS NOT NULL AND NOT EXISTS (SELECT 1 FROM org.organization o WHERE o.id = NEW.organization_id AND o.tenant_id = NEW.tenant_id AND o.organization_state = 'ACTIVE') THEN
        RAISE EXCEPTION 'INVITATION_ORGANIZATION_INVALID' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;
COMMENT ON FUNCTION org.fn_invitation_scope_guard() IS '邀请创建和消费时的租户、组织范围守卫。';

CREATE TRIGGER trg_business_line_public_id BEFORE INSERT ON org.business_line FOR EACH ROW EXECUTE FUNCTION core.fn_register_public_id('BUSINESS_LINE');
CREATE TRIGGER trg_business_line_touch BEFORE UPDATE ON org.business_line FOR EACH ROW EXECUTE FUNCTION core.fn_touch_updated_at();
CREATE TRIGGER trg_business_line_version BEFORE UPDATE ON org.business_line FOR EACH ROW EXECUTE FUNCTION core.fn_increment_row_version();
CREATE TRIGGER trg_business_line_terminal BEFORE UPDATE ON org.business_line FOR EACH ROW EXECUTE FUNCTION core.fn_terminal_state_guard('business_line_state', 'CLOSED');
CREATE TRIGGER trg_tenant_public_id BEFORE INSERT ON org.tenant FOR EACH ROW EXECUTE FUNCTION core.fn_register_public_id('TENANT');
CREATE TRIGGER trg_tenant_touch BEFORE UPDATE ON org.tenant FOR EACH ROW EXECUTE FUNCTION core.fn_touch_updated_at();
CREATE TRIGGER trg_tenant_version BEFORE UPDATE ON org.tenant FOR EACH ROW EXECUTE FUNCTION core.fn_increment_row_version();
CREATE TRIGGER trg_tenant_epoch BEFORE UPDATE ON org.tenant FOR EACH ROW EXECUTE FUNCTION core.fn_forbid_epoch_decrease('tenant_security_epoch');
CREATE TRIGGER trg_tenant_terminal BEFORE UPDATE ON org.tenant FOR EACH ROW EXECUTE FUNCTION core.fn_terminal_state_guard('tenant_state', 'CLOSED');
CREATE TRIGGER trg_tenant_domain_touch BEFORE UPDATE ON org.tenant_domain FOR EACH ROW EXECUTE FUNCTION core.fn_touch_updated_at();
CREATE TRIGGER trg_tenant_domain_version BEFORE UPDATE ON org.tenant_domain FOR EACH ROW EXECUTE FUNCTION core.fn_increment_row_version();
CREATE TRIGGER trg_organization_public_id BEFORE INSERT ON org.organization FOR EACH ROW EXECUTE FUNCTION core.fn_register_public_id('ORGANIZATION');
CREATE TRIGGER trg_organization_touch BEFORE UPDATE ON org.organization FOR EACH ROW EXECUTE FUNCTION core.fn_touch_updated_at();
CREATE TRIGGER trg_organization_version BEFORE UPDATE ON org.organization FOR EACH ROW EXECUTE FUNCTION core.fn_increment_row_version();
CREATE TRIGGER trg_organization_terminal BEFORE UPDATE ON org.organization FOR EACH ROW EXECUTE FUNCTION core.fn_terminal_state_guard('organization_state', 'CLOSED');
CREATE TRIGGER trg_membership_public_id BEFORE INSERT ON org.membership FOR EACH ROW EXECUTE FUNCTION core.fn_register_public_id('MEMBERSHIP');
CREATE TRIGGER trg_membership_scope BEFORE INSERT OR UPDATE ON org.membership FOR EACH ROW EXECUTE FUNCTION org.fn_membership_scope_guard();
CREATE TRIGGER trg_membership_touch BEFORE UPDATE ON org.membership FOR EACH ROW EXECUTE FUNCTION core.fn_touch_updated_at();
CREATE TRIGGER trg_membership_version BEFORE UPDATE ON org.membership FOR EACH ROW EXECUTE FUNCTION core.fn_increment_row_version();
CREATE TRIGGER trg_membership_terminal BEFORE UPDATE ON org.membership FOR EACH ROW EXECUTE FUNCTION core.fn_terminal_state_guard('membership_state', 'LEFT', 'REJECTED', 'EXPIRED');
CREATE TRIGGER trg_invitation_public_id BEFORE INSERT ON org.invitation FOR EACH ROW EXECUTE FUNCTION core.fn_register_public_id('INVITATION');
CREATE TRIGGER trg_invitation_scope BEFORE INSERT OR UPDATE ON org.invitation FOR EACH ROW EXECUTE FUNCTION org.fn_invitation_scope_guard();
CREATE TRIGGER trg_invitation_touch BEFORE UPDATE ON org.invitation FOR EACH ROW EXECUTE FUNCTION core.fn_touch_updated_at();
CREATE TRIGGER trg_invitation_version BEFORE UPDATE ON org.invitation FOR EACH ROW EXECUTE FUNCTION core.fn_increment_row_version();
CREATE TRIGGER trg_invitation_terminal BEFORE UPDATE ON org.invitation FOR EACH ROW EXECUTE FUNCTION core.fn_terminal_state_guard('invitation_state', 'ACCEPTED', 'REJECTED', 'EXPIRED', 'REVOKED');
CREATE TRIGGER trg_group_public_id BEFORE INSERT ON org.user_group FOR EACH ROW EXECUTE FUNCTION core.fn_register_public_id('GROUP');
CREATE TRIGGER trg_group_touch BEFORE UPDATE ON org.user_group FOR EACH ROW EXECUTE FUNCTION core.fn_touch_updated_at();
CREATE TRIGGER trg_group_version BEFORE UPDATE ON org.user_group FOR EACH ROW EXECUTE FUNCTION core.fn_increment_row_version();
CREATE TRIGGER trg_role_public_id BEFORE INSERT ON authz.role FOR EACH ROW EXECUTE FUNCTION core.fn_register_public_id('ROLE');
CREATE TRIGGER trg_role_touch BEFORE UPDATE ON authz.role FOR EACH ROW EXECUTE FUNCTION core.fn_touch_updated_at();
CREATE TRIGGER trg_role_version BEFORE UPDATE ON authz.role FOR EACH ROW EXECUTE FUNCTION core.fn_increment_row_version();
CREATE TRIGGER trg_role_assignment_touch BEFORE UPDATE ON authz.role_assignment FOR EACH ROW EXECUTE FUNCTION core.fn_touch_updated_at();
CREATE TRIGGER trg_role_assignment_version BEFORE UPDATE ON authz.role_assignment FOR EACH ROW EXECUTE FUNCTION core.fn_increment_row_version();
CREATE TRIGGER trg_policy_release_public_id BEFORE INSERT ON authz.policy_release FOR EACH ROW EXECUTE FUNCTION core.fn_register_public_id('POLICY_RELEASE');
CREATE TRIGGER trg_authorization_decision_public_id BEFORE INSERT ON authz.authorization_decision FOR EACH ROW EXECUTE FUNCTION core.fn_register_public_id('AUTHZ_DECISION');
CREATE TRIGGER trg_authorization_decision_append_only BEFORE UPDATE OR DELETE ON authz.authorization_decision FOR EACH STATEMENT EXECUTE FUNCTION core.fn_append_only();
CREATE TRIGGER trg_profile_user_touch BEFORE UPDATE ON profile.user_profile FOR EACH ROW EXECUTE FUNCTION core.fn_touch_updated_at();
CREATE TRIGGER trg_profile_user_version BEFORE UPDATE ON profile.user_profile FOR EACH ROW EXECUTE FUNCTION core.fn_increment_row_version();
CREATE TRIGGER trg_sensitive_attribute_touch BEFORE UPDATE ON profile.sensitive_attribute FOR EACH ROW EXECUTE FUNCTION core.fn_touch_updated_at();
CREATE TRIGGER trg_sensitive_attribute_version BEFORE UPDATE ON profile.sensitive_attribute FOR EACH ROW EXECUTE FUNCTION core.fn_increment_row_version();
CREATE TRIGGER trg_business_profile_touch BEFORE UPDATE ON profile.business_profile FOR EACH ROW EXECUTE FUNCTION core.fn_touch_updated_at();
CREATE TRIGGER trg_business_profile_version BEFORE UPDATE ON profile.business_profile FOR EACH ROW EXECUTE FUNCTION core.fn_increment_row_version();
CREATE TRIGGER trg_profile_change_append_only BEFORE UPDATE OR DELETE ON profile.profile_change FOR EACH STATEMENT EXECUTE FUNCTION core.fn_append_only();
CREATE TRIGGER trg_user_preference_touch BEFORE UPDATE ON profile.user_preference FOR EACH ROW EXECUTE FUNCTION core.fn_touch_updated_at();
CREATE TRIGGER trg_user_preference_version BEFORE UPDATE ON profile.user_preference FOR EACH ROW EXECUTE FUNCTION core.fn_increment_row_version();
CREATE TRIGGER trg_notification_preference_touch BEFORE UPDATE ON profile.notification_preference FOR EACH ROW EXECUTE FUNCTION core.fn_touch_updated_at();
CREATE TRIGGER trg_notification_preference_version BEFORE UPDATE ON profile.notification_preference FOR EACH ROW EXECUTE FUNCTION core.fn_increment_row_version();
CREATE TRIGGER trg_relationship_tuple_touch BEFORE UPDATE ON authz.relationship_tuple FOR EACH ROW EXECUTE FUNCTION core.fn_touch_updated_at();
CREATE TRIGGER trg_relationship_tuple_version BEFORE UPDATE ON authz.relationship_tuple FOR EACH ROW EXECUTE FUNCTION core.fn_increment_row_version();
CREATE TRIGGER trg_access_review_public_id BEFORE INSERT ON authz.access_review FOR EACH ROW EXECUTE FUNCTION core.fn_register_public_id('ACCESS_REVIEW');
CREATE TRIGGER trg_access_review_touch BEFORE UPDATE ON authz.access_review FOR EACH ROW EXECUTE FUNCTION core.fn_touch_updated_at();
CREATE TRIGGER trg_access_review_version BEFORE UPDATE ON authz.access_review FOR EACH ROW EXECUTE FUNCTION core.fn_increment_row_version();
CREATE TRIGGER trg_permission_simulation_public_id BEFORE INSERT ON authz.permission_simulation FOR EACH ROW EXECUTE FUNCTION core.fn_register_public_id('PERMISSION_SIMULATION');
CREATE TRIGGER trg_permission_simulation_append_only BEFORE UPDATE OR DELETE ON authz.permission_simulation FOR EACH STATEMENT EXECUTE FUNCTION core.fn_append_only();

SELECT core.fn_register_migration('030', '业务线、租户、组织、Membership、授权策略与 Profile', NULLIF(current_setting('kuc.migration_sha256', true), ''));
COMMIT;
