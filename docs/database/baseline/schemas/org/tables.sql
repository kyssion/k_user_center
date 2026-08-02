-- =============================================================================
-- baseline/schemas/org/tables.sql
-- org Schema 的最终基表、同 Schema 约束、索引及内联 COMMENT
-- PostgreSQL 16+；应用技术栈：.NET 10 + SqlSugar
-- =============================================================================

CREATE TABLE org.business_line (
    id uuid        NOT NULL DEFAULT gen_random_uuid(),
    public_id text        NOT NULL,
    business_line_code text        NOT NULL,
    display_name text        NOT NULL,
    business_line_state text        NOT NULL DEFAULT 'PROVISIONING',
    owner_ref text        NOT NULL,
    data_residency_region text        NOT NULL,
    default_locale text        NOT NULL DEFAULT 'zh-CN',
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    activated_at timestamptz NULL,
    closed_at timestamptz NULL,
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    row_version bigint      NOT NULL DEFAULT 1,
    suspended_at timestamptz NULL,
    closing_at timestamptz NULL,
    irreversible_at timestamptz NULL,
    state_reason_code text NULL,
    CONSTRAINT pk_business_line PRIMARY KEY (id),
    CONSTRAINT uq_business_line_public_id UNIQUE (public_id),
    CONSTRAINT uq_business_line_code UNIQUE (business_line_code),
    CONSTRAINT ck_business_line_code CHECK (business_line_code ~ '^[a-z][a-z0-9_-]{1,62}$'),
    CONSTRAINT ck_business_line_state CHECK (business_line_state IN ('PROVISIONING', 'ACTIVE', 'SUSPENDED', 'CLOSING', 'CLOSED')),
    CONSTRAINT ck_business_line_closed CHECK ((business_line_state = 'CLOSED') = (closed_at IS NOT NULL)),
    CONSTRAINT ck_business_line_activation CHECK (business_line_state <> 'ACTIVE' OR activated_at IS NOT NULL),
    CONSTRAINT ck_business_line_closing CHECK (business_line_state NOT IN ('CLOSING', 'CLOSED') OR closing_at IS NOT NULL),
    CONSTRAINT ck_business_line_irreversible CHECK (irreversible_at IS NULL OR business_line_state IN ('CLOSING', 'CLOSED'))
);

COMMENT ON TABLE org.business_line IS 'CAP-TENANT-001：业务线隔离根、数据驻留与责任人台账；不承载业务事实数据。';

CREATE TABLE org.tenant (
    id uuid        NOT NULL DEFAULT gen_random_uuid(),
    public_id text        NOT NULL,
    business_line_id uuid        NOT NULL,
    tenant_code text        NOT NULL,
    display_name text        NOT NULL,
    tenant_state text        NOT NULL DEFAULT 'PROVISIONING',
    tenant_type text        NOT NULL DEFAULT 'ENTERPRISE',
    owner_membership_id uuid        NULL,
    data_residency_region text        NOT NULL,
    tenant_security_epoch bigint      NOT NULL DEFAULT 1,
    close_operation_id uuid        NULL,
    irreversible_at timestamptz NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    activated_at timestamptz NULL,
    closing_at timestamptz NULL,
    closed_at timestamptz NULL,
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    row_version bigint      NOT NULL DEFAULT 1,
    suspended_at timestamptz NULL,
    state_reason_code text NULL,
    CONSTRAINT pk_tenant PRIMARY KEY (id),
    CONSTRAINT uq_tenant_public_id UNIQUE (public_id),
    CONSTRAINT uq_tenant_code UNIQUE (business_line_id, tenant_code),
    CONSTRAINT fk_tenant_business_line FOREIGN KEY (business_line_id) REFERENCES org.business_line(id),
    CONSTRAINT ck_tenant_code CHECK (tenant_code ~ '^[a-z][a-z0-9_-]{1,62}$'),
    CONSTRAINT ck_tenant_state CHECK (tenant_state IN ('PROVISIONING', 'ACTIVE', 'SUSPENDED', 'CLOSING', 'CLOSED')),
    CONSTRAINT ck_tenant_type CHECK (tenant_type IN ('ENTERPRISE', 'CONSUMER_SEGMENT', 'PARTNER', 'PLATFORM')),
    CONSTRAINT ck_tenant_epoch CHECK (tenant_security_epoch >= 1),
    CONSTRAINT ck_tenant_closed CHECK ((tenant_state = 'CLOSED') = (closed_at IS NOT NULL)),
    CONSTRAINT ck_tenant_irreversible CHECK (irreversible_at IS NULL OR tenant_state IN ('CLOSING', 'CLOSED')),
    CONSTRAINT uq_tenant_id_business_line UNIQUE (id, business_line_id),
    CONSTRAINT ck_tenant_activation CHECK (tenant_state <> 'ACTIVE' OR activated_at IS NOT NULL),
    CONSTRAINT ck_tenant_closing CHECK (tenant_state NOT IN ('CLOSING', 'CLOSED') OR (closing_at IS NOT NULL AND close_operation_id IS NOT NULL))
);

COMMENT ON TABLE org.tenant IS 'CAP-TENANT-002/010：租户生命周期、数据驻留与 security epoch；CLOSED 为不可恢复终态。';

CREATE TABLE org.tenant_domain (
    id uuid        NOT NULL DEFAULT gen_random_uuid(),
    tenant_id uuid        NOT NULL,
    normalized_domain text        NOT NULL,
    domain_state text        NOT NULL DEFAULT 'PENDING',
    verification_method text        NOT NULL,
    verification_token_hash bytea     NOT NULL,
    auto_route_enabled boolean     NOT NULL DEFAULT false,
    jit_enabled boolean     NOT NULL DEFAULT false,
    last_verified_at timestamptz NULL,
    verification_expires_at timestamptz NULL,
    revoked_at timestamptz NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    row_version bigint      NOT NULL DEFAULT 1,
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
    id uuid        NOT NULL DEFAULT gen_random_uuid(),
    public_id text        NOT NULL,
    tenant_id uuid        NOT NULL,
    parent_id uuid        NULL,
    organization_code text        NOT NULL,
    display_name text        NOT NULL,
    organization_kind text        NOT NULL DEFAULT 'UNIT',
    organization_state text        NOT NULL DEFAULT 'ACTIVE',
    hierarchy_path text        NOT NULL,
    source_kind text        NOT NULL DEFAULT 'PLATFORM',
    source_ref text        NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    closed_at timestamptz NULL,
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    row_version bigint      NOT NULL DEFAULT 1,
    suspended_at timestamptz NULL,
    state_reason_code text NULL,
    CONSTRAINT pk_organization PRIMARY KEY (id),
    CONSTRAINT uq_organization_public_id UNIQUE (public_id),
    CONSTRAINT uq_organization_code UNIQUE (tenant_id, organization_code),
    CONSTRAINT uq_organization_path UNIQUE (tenant_id, hierarchy_path),
    CONSTRAINT fk_organization_tenant FOREIGN KEY (tenant_id) REFERENCES org.tenant(id),
    CONSTRAINT fk_organization_parent FOREIGN KEY (parent_id) REFERENCES org.organization(id),
    CONSTRAINT ck_organization_kind CHECK (organization_kind IN ('ROOT', 'COMPANY', 'DIVISION', 'DEPARTMENT', 'TEAM', 'UNIT')),
    CONSTRAINT ck_organization_state CHECK (organization_state IN ('ACTIVE', 'SUSPENDED', 'CLOSED')),
    CONSTRAINT ck_organization_source CHECK (source_kind IN ('PLATFORM', 'SCIM', 'DIRECTORY', 'MIGRATION')),
    CONSTRAINT ck_organization_closed CHECK ((organization_state = 'CLOSED') = (closed_at IS NOT NULL)),
    CONSTRAINT uq_organization_id_tenant UNIQUE (id, tenant_id)
);

COMMENT ON TABLE org.organization IS 'CAP-TENANT-005：租户内组织层级、权威来源和稳定外部引用。';

CREATE TABLE org.membership (
    id uuid        NOT NULL DEFAULT gen_random_uuid(),
    public_id text        NOT NULL,
    user_id uuid        NOT NULL,
    business_line_id uuid        NOT NULL,
    tenant_id uuid        NOT NULL,
    organization_id uuid        NULL,
    membership_state text        NOT NULL DEFAULT 'INVITED',
    membership_kind text        NOT NULL DEFAULT 'MEMBER',
    source_kind text        NOT NULL DEFAULT 'DIRECT',
    source_ref text        NULL,
    joined_at timestamptz NULL,
    suspended_at timestamptz NULL,
    banned_at timestamptz NULL,
    left_at timestamptz NULL,
    expires_at timestamptz NULL,
    state_reason_code text        NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    row_version bigint      NOT NULL DEFAULT 1,
    rejected_at timestamptz NULL,
    state_expired_at timestamptz NULL,
    CONSTRAINT pk_membership PRIMARY KEY (id),
    CONSTRAINT uq_membership_public_id UNIQUE (public_id),
    CONSTRAINT fk_membership_business_line FOREIGN KEY (business_line_id) REFERENCES org.business_line(id),
    CONSTRAINT fk_membership_tenant FOREIGN KEY (tenant_id) REFERENCES org.tenant(id),
    CONSTRAINT fk_membership_organization FOREIGN KEY (organization_id) REFERENCES org.organization(id),
    CONSTRAINT ck_membership_state CHECK (membership_state IN ('INVITED', 'PENDING_APPROVAL', 'ACTIVE', 'SUSPENDED', 'BANNED', 'LEFT', 'REJECTED', 'EXPIRED')),
    CONSTRAINT ck_membership_kind CHECK (membership_kind IN ('OWNER', 'ADMIN', 'MEMBER', 'GUEST', 'SERVICE_CONTACT')),
    CONSTRAINT ck_membership_source CHECK (source_kind IN ('DIRECT', 'INVITATION', 'SCIM', 'JIT', 'MIGRATION')),
    CONSTRAINT ck_membership_joined CHECK (membership_state NOT IN ('ACTIVE', 'SUSPENDED', 'BANNED', 'LEFT') OR joined_at IS NOT NULL),
    CONSTRAINT ck_membership_left CHECK ((membership_state = 'LEFT') = (left_at IS NOT NULL)),
    CONSTRAINT ck_membership_rejected CHECK ((membership_state = 'REJECTED') = (rejected_at IS NOT NULL)),
    CONSTRAINT ck_membership_expired_state CHECK ((membership_state = 'EXPIRED') = (state_expired_at IS NOT NULL))
);

COMMENT ON TABLE org.membership IS 'CAP-TENANT-003/004：用户在业务线、租户及可选组织范围内的成员关系；业务封禁仅修改本记录。';

CREATE TABLE org.invitation (
    id uuid        NOT NULL DEFAULT gen_random_uuid(),
    public_id text        NOT NULL,
    business_line_id uuid        NOT NULL,
    tenant_id uuid        NOT NULL,
    organization_id uuid        NULL,
    invitation_state text        NOT NULL DEFAULT 'PENDING',
    target_identifier_kind text       NOT NULL,
    target_normalized_hash bytea      NOT NULL,
    invitation_token_hash bytea       NOT NULL,
    inviter_membership_id uuid        NOT NULL,
    preauthorized_role_ids uuid[]     NOT NULL DEFAULT '{}',
    preauthorization_hash bytea       NOT NULL,
    accepted_by_user_id uuid        NULL,
    accepted_membership_id uuid       NULL,
    expires_at timestamptz NOT NULL,
    accepted_at timestamptz NULL,
    rejected_at timestamptz NULL,
    revoked_at timestamptz NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    row_version bigint      NOT NULL DEFAULT 1,
    state_expired_at timestamptz NULL,
    state_reason_code text NULL,
    creation_authorization_decision_id uuid NOT NULL,
    acceptance_authorization_decision_id uuid NULL,
    CONSTRAINT pk_invitation PRIMARY KEY (id),
    CONSTRAINT uq_invitation_public_id UNIQUE (public_id),
    CONSTRAINT uq_invitation_token_hash UNIQUE (invitation_token_hash),
    CONSTRAINT fk_invitation_business_line FOREIGN KEY (business_line_id) REFERENCES org.business_line(id),
    CONSTRAINT fk_invitation_tenant FOREIGN KEY (tenant_id) REFERENCES org.tenant(id),
    CONSTRAINT fk_invitation_organization FOREIGN KEY (organization_id) REFERENCES org.organization(id),
    CONSTRAINT fk_invitation_inviter FOREIGN KEY (inviter_membership_id) REFERENCES org.membership(id),
    CONSTRAINT fk_invitation_membership FOREIGN KEY (accepted_membership_id) REFERENCES org.membership(id),
    CONSTRAINT ck_invitation_state CHECK (invitation_state IN ('PENDING', 'ACCEPTED', 'REJECTED', 'EXPIRED', 'REVOKED')),
    CONSTRAINT ck_invitation_identifier_kind CHECK (target_identifier_kind IN ('EMAIL', 'PHONE', 'USERNAME', 'EXTERNAL_ID')),
    CONSTRAINT ck_invitation_hashes CHECK (octet_length(target_normalized_hash) = 32 AND octet_length(invitation_token_hash) = 32 AND octet_length(preauthorization_hash) = 32),
    CONSTRAINT ck_invitation_expiry CHECK (expires_at > created_at),
    CONSTRAINT ck_invitation_accept CHECK (invitation_state <> 'ACCEPTED' OR (accepted_at IS NOT NULL AND accepted_by_user_id IS NOT NULL AND accepted_membership_id IS NOT NULL)),
    CONSTRAINT ck_invitation_decision_distinct CHECK (
    acceptance_authorization_decision_id IS NULL OR acceptance_authorization_decision_id <> creation_authorization_decision_id
    ),
    CONSTRAINT ck_invitation_rejected CHECK ((invitation_state = 'REJECTED') = (rejected_at IS NOT NULL)),
    CONSTRAINT ck_invitation_expired_state CHECK ((invitation_state = 'EXPIRED') = (state_expired_at IS NOT NULL)),
    CONSTRAINT ck_invitation_revoked CHECK ((invitation_state = 'REVOKED') = (revoked_at IS NOT NULL))
);

COMMENT ON TABLE org.invitation IS 'REQ-TENANT-011：绑定租户范围、目标摘要、邀请人权限上限与过期时间的单次消费邀请。';

CREATE TABLE org.user_group (
    id uuid        NOT NULL DEFAULT gen_random_uuid(),
    public_id text        NOT NULL,
    tenant_id uuid        NOT NULL,
    organization_id uuid        NULL,
    group_code text        NOT NULL,
    display_name text        NOT NULL,
    group_state text        NOT NULL DEFAULT 'ACTIVE',
    source_kind text        NOT NULL DEFAULT 'PLATFORM',
    source_ref text        NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    row_version bigint      NOT NULL DEFAULT 1,
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
    id uuid        NOT NULL DEFAULT gen_random_uuid(),
    group_id uuid        NOT NULL,
    user_id uuid        NULL,
    nested_group_id uuid        NULL,
    membership_state text        NOT NULL DEFAULT 'ACTIVE',
    source_ref text        NULL,
    valid_from timestamptz NOT NULL DEFAULT clock_timestamp(),
    valid_until timestamptz NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT pk_group_member PRIMARY KEY (id),
    CONSTRAINT fk_group_member_group FOREIGN KEY (group_id) REFERENCES org.user_group(id),
    CONSTRAINT fk_group_member_nested FOREIGN KEY (nested_group_id) REFERENCES org.user_group(id),
    CONSTRAINT ck_group_member_target CHECK (num_nonnulls(user_id, nested_group_id) = 1),
    CONSTRAINT ck_group_member_self CHECK (nested_group_id IS NULL OR nested_group_id <> group_id),
    CONSTRAINT ck_group_member_state CHECK (membership_state IN ('ACTIVE', 'SUSPENDED', 'REMOVED')),
    CONSTRAINT ck_group_member_window CHECK (valid_until IS NULL OR valid_until > valid_from)
);

COMMENT ON TABLE org.group_member IS '组织用户组成员与有限嵌套关系；循环检测由写服务事务内递归查询完成。';

CREATE TABLE org.usage_meter (
    id uuid        NOT NULL DEFAULT gen_random_uuid(),
    tenant_id uuid        NOT NULL,
    meter_code text        NOT NULL,
    period_start timestamptz NOT NULL,
    period_end timestamptz NOT NULL,
    measured_value numeric(20,4) NOT NULL,
    source_version bigint      NOT NULL,
    measured_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT pk_usage_meter PRIMARY KEY (id),
    CONSTRAINT uq_usage_meter UNIQUE (tenant_id, meter_code, period_start, source_version),
    CONSTRAINT fk_usage_meter_tenant FOREIGN KEY (tenant_id) REFERENCES org.tenant(id),
    CONSTRAINT ck_usage_meter_window CHECK (period_end > period_start),
    CONSTRAINT ck_usage_meter_value CHECK (measured_value >= 0 AND source_version >= 1)
);

COMMENT ON TABLE org.usage_meter IS 'CAP-TENANT-011：租户配额与计量快照；不作为计费业务事实的权威来源。';

CREATE UNIQUE INDEX ux_membership_effective ON org.membership(user_id, tenant_id, COALESCE(organization_id, '00000000-0000-0000-0000-000000000000'::uuid)) WHERE membership_state NOT IN ('LEFT', 'REJECTED', 'EXPIRED');

CREATE INDEX ix_membership_tenant_state ON org.membership(tenant_id, membership_state, user_id);

CREATE INDEX ix_invitation_target ON org.invitation(tenant_id, target_normalized_hash) WHERE invitation_state = 'PENDING';

CREATE UNIQUE INDEX ux_group_member_user ON org.group_member(group_id, user_id) WHERE user_id IS NOT NULL AND membership_state <> 'REMOVED';

CREATE UNIQUE INDEX ux_group_member_group ON org.group_member(group_id, nested_group_id) WHERE nested_group_id IS NOT NULL AND membership_state <> 'REMOVED';

CREATE INDEX ix_fk_tenant_domain_tenant_id ON org.tenant_domain (tenant_id);

CREATE INDEX ix_fk_organization_parent_id ON org.organization (parent_id);

CREATE INDEX ix_fk_membership_business_line_id ON org.membership (business_line_id);

CREATE INDEX ix_fk_membership_organization_id ON org.membership (organization_id);

CREATE INDEX ix_fk_invitation_business_line_id ON org.invitation (business_line_id);

CREATE INDEX ix_fk_invitation_tenant_id ON org.invitation (tenant_id);

CREATE INDEX ix_fk_invitation_organization_id ON org.invitation (organization_id);

CREATE INDEX ix_fk_invitation_inviter_membership_id ON org.invitation (inviter_membership_id);

CREATE INDEX ix_fk_invitation_accepted_membership_id ON org.invitation (accepted_membership_id);

CREATE INDEX ix_fk_user_group_organization_id ON org.user_group (organization_id);

CREATE INDEX ix_fk_group_member_group_id ON org.group_member (group_id);

CREATE INDEX ix_fk_group_member_nested_group_id ON org.group_member (nested_group_id);

COMMENT ON COLUMN org.business_line.id IS '内部 UUID 主键；仅用于数据库关系，不作为跨域公开标识。';
COMMENT ON COLUMN org.business_line.public_id IS '不可复用的公开稳定标识；插入时登记到 core.public_id_ledger。';
COMMENT ON COLUMN org.business_line.business_line_code IS '稳定机器可读代码；展示文本由资源或目录解析。';
COMMENT ON COLUMN org.business_line.display_name IS 'org.business_line.display_name 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN org.business_line.business_line_state IS '显式状态当前值；合法取值见 CHECK，完整状态转换由 .NET 领域策略执行。';
COMMENT ON COLUMN org.business_line.owner_ref IS '不透明对象引用；不得从格式推断手机号、邮箱或其他业务事实。';
COMMENT ON COLUMN org.business_line.data_residency_region IS 'org.business_line.data_residency_region 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN org.business_line.default_locale IS 'org.business_line.default_locale 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN org.business_line.created_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN org.business_line.activated_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN org.business_line.closed_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN org.business_line.updated_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN org.business_line.row_version IS '乐观并发版本；更新必须使用原值 compare-and-set，成功后由数据库单调递增。';
COMMENT ON COLUMN org.business_line.suspended_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN org.business_line.closing_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN org.business_line.irreversible_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN org.business_line.state_reason_code IS '稳定机器可读代码；展示文本由资源或目录解析。';
COMMENT ON COLUMN org.tenant.id IS '内部 UUID 主键；仅用于数据库关系，不作为跨域公开标识。';
COMMENT ON COLUMN org.tenant.public_id IS '不可复用的公开稳定标识；插入时登记到 core.public_id_ledger。';
COMMENT ON COLUMN org.tenant.business_line_id IS '业务线隔离键；关联 org.business_line，用于业务线范围隔离。';
COMMENT ON COLUMN org.tenant.tenant_code IS '稳定机器可读代码；展示文本由资源或目录解析。';
COMMENT ON COLUMN org.tenant.display_name IS 'org.tenant.display_name 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN org.tenant.tenant_state IS '显式状态当前值；合法取值见 CHECK，完整状态转换由 .NET 领域策略执行。';
COMMENT ON COLUMN org.tenant.tenant_type IS '对象类别判别字段；允许值由 CHECK 或对应注册表限定。';
COMMENT ON COLUMN org.tenant.owner_membership_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN org.tenant.data_residency_region IS 'org.tenant.data_residency_region 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN org.tenant.tenant_security_epoch IS '安全或同意水位版本；只能单调递增，用于令牌、缓存与撤销新鲜度校验。';
COMMENT ON COLUMN org.tenant.close_operation_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN org.tenant.irreversible_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN org.tenant.created_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN org.tenant.activated_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN org.tenant.closing_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN org.tenant.closed_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN org.tenant.updated_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN org.tenant.row_version IS '乐观并发版本；更新必须使用原值 compare-and-set，成功后由数据库单调递增。';
COMMENT ON COLUMN org.tenant.suspended_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN org.tenant.state_reason_code IS '稳定机器可读代码；展示文本由资源或目录解析。';
COMMENT ON COLUMN org.tenant_domain.id IS '内部 UUID 主键；仅用于数据库关系，不作为跨域公开标识。';
COMMENT ON COLUMN org.tenant_domain.tenant_id IS '租户隔离键；全零 UUID 表示平台范围，应用查询必须显式携带可信租户上下文。';
COMMENT ON COLUMN org.tenant_domain.normalized_domain IS 'org.tenant_domain.normalized_domain 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN org.tenant_domain.domain_state IS '显式状态当前值；合法取值见 CHECK，完整状态转换由 .NET 领域策略执行。';
COMMENT ON COLUMN org.tenant_domain.verification_method IS 'org.tenant_domain.verification_method 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN org.tenant_domain.verification_token_hash IS '不可逆摘要；用于等值匹配、幂等、完整性或最小化证据，不保存原始敏感值。';
COMMENT ON COLUMN org.tenant_domain.auto_route_enabled IS '显式布尔开关；启用前置条件与失效行为由约束和版本化策略控制。';
COMMENT ON COLUMN org.tenant_domain.jit_enabled IS '显式布尔开关；启用前置条件与失效行为由约束和版本化策略控制。';
COMMENT ON COLUMN org.tenant_domain.last_verified_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN org.tenant_domain.verification_expires_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN org.tenant_domain.revoked_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN org.tenant_domain.created_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN org.tenant_domain.updated_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN org.tenant_domain.row_version IS '乐观并发版本；更新必须使用原值 compare-and-set，成功后由数据库单调递增。';
COMMENT ON COLUMN org.organization.id IS '内部 UUID 主键；仅用于数据库关系，不作为跨域公开标识。';
COMMENT ON COLUMN org.organization.public_id IS '不可复用的公开稳定标识；插入时登记到 core.public_id_ledger。';
COMMENT ON COLUMN org.organization.tenant_id IS '租户隔离键；全零 UUID 表示平台范围，应用查询必须显式携带可信租户上下文。';
COMMENT ON COLUMN org.organization.parent_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN org.organization.organization_code IS '稳定机器可读代码；展示文本由资源或目录解析。';
COMMENT ON COLUMN org.organization.display_name IS 'org.organization.display_name 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN org.organization.organization_kind IS '对象类别判别字段；允许值由 CHECK 或对应注册表限定。';
COMMENT ON COLUMN org.organization.organization_state IS '显式状态当前值；合法取值见 CHECK，完整状态转换由 .NET 领域策略执行。';
COMMENT ON COLUMN org.organization.hierarchy_path IS 'org.organization.hierarchy_path 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN org.organization.source_kind IS '对象类别判别字段；允许值由 CHECK 或对应注册表限定。';
COMMENT ON COLUMN org.organization.source_ref IS '不透明对象引用；不得从格式推断手机号、邮箱或其他业务事实。';
COMMENT ON COLUMN org.organization.created_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN org.organization.closed_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN org.organization.updated_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN org.organization.row_version IS '乐观并发版本；更新必须使用原值 compare-and-set，成功后由数据库单调递增。';
COMMENT ON COLUMN org.organization.suspended_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN org.organization.state_reason_code IS '稳定机器可读代码；展示文本由资源或目录解析。';
COMMENT ON COLUMN org.membership.id IS '内部 UUID 主键；仅用于数据库关系，不作为跨域公开标识。';
COMMENT ON COLUMN org.membership.public_id IS '不可复用的公开稳定标识；插入时登记到 core.public_id_ledger。';
COMMENT ON COLUMN org.membership.user_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN org.membership.business_line_id IS '业务线隔离键；关联 org.business_line，用于业务线范围隔离。';
COMMENT ON COLUMN org.membership.tenant_id IS '租户隔离键；全零 UUID 表示平台范围，应用查询必须显式携带可信租户上下文。';
COMMENT ON COLUMN org.membership.organization_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN org.membership.membership_state IS '显式状态当前值；合法取值见 CHECK，完整状态转换由 .NET 领域策略执行。';
COMMENT ON COLUMN org.membership.membership_kind IS '对象类别判别字段；允许值由 CHECK 或对应注册表限定。';
COMMENT ON COLUMN org.membership.source_kind IS '对象类别判别字段；允许值由 CHECK 或对应注册表限定。';
COMMENT ON COLUMN org.membership.source_ref IS '不透明对象引用；不得从格式推断手机号、邮箱或其他业务事实。';
COMMENT ON COLUMN org.membership.joined_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN org.membership.suspended_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN org.membership.banned_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN org.membership.left_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN org.membership.expires_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN org.membership.state_reason_code IS '稳定机器可读代码；展示文本由资源或目录解析。';
COMMENT ON COLUMN org.membership.created_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN org.membership.updated_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN org.membership.row_version IS '乐观并发版本；更新必须使用原值 compare-and-set，成功后由数据库单调递增。';
COMMENT ON COLUMN org.membership.rejected_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN org.membership.state_expired_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN org.invitation.id IS '内部 UUID 主键；仅用于数据库关系，不作为跨域公开标识。';
COMMENT ON COLUMN org.invitation.public_id IS '不可复用的公开稳定标识；插入时登记到 core.public_id_ledger。';
COMMENT ON COLUMN org.invitation.business_line_id IS '业务线隔离键；关联 org.business_line，用于业务线范围隔离。';
COMMENT ON COLUMN org.invitation.tenant_id IS '租户隔离键；全零 UUID 表示平台范围，应用查询必须显式携带可信租户上下文。';
COMMENT ON COLUMN org.invitation.organization_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN org.invitation.invitation_state IS '显式状态当前值；合法取值见 CHECK，完整状态转换由 .NET 领域策略执行。';
COMMENT ON COLUMN org.invitation.target_identifier_kind IS '对象类别判别字段；允许值由 CHECK 或对应注册表限定。';
COMMENT ON COLUMN org.invitation.target_normalized_hash IS '不可逆摘要；用于等值匹配、幂等、完整性或最小化证据，不保存原始敏感值。';
COMMENT ON COLUMN org.invitation.invitation_token_hash IS '不可逆摘要；用于等值匹配、幂等、完整性或最小化证据，不保存原始敏感值。';
COMMENT ON COLUMN org.invitation.inviter_membership_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN org.invitation.preauthorized_role_ids IS '代码或引用集合；写入前去重、校验 allowlist，并满足表约束。';
COMMENT ON COLUMN org.invitation.preauthorization_hash IS '不可逆摘要；用于等值匹配、幂等、完整性或最小化证据，不保存原始敏感值。';
COMMENT ON COLUMN org.invitation.accepted_by_user_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN org.invitation.accepted_membership_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN org.invitation.expires_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN org.invitation.accepted_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN org.invitation.rejected_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN org.invitation.revoked_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN org.invitation.created_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN org.invitation.updated_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN org.invitation.row_version IS '乐观并发版本；更新必须使用原值 compare-and-set，成功后由数据库单调递增。';
COMMENT ON COLUMN org.invitation.state_expired_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN org.invitation.state_reason_code IS '稳定机器可读代码；展示文本由资源或目录解析。';
COMMENT ON COLUMN org.invitation.creation_authorization_decision_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN org.invitation.acceptance_authorization_decision_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN org.user_group.id IS '内部 UUID 主键；仅用于数据库关系，不作为跨域公开标识。';
COMMENT ON COLUMN org.user_group.public_id IS '不可复用的公开稳定标识；插入时登记到 core.public_id_ledger。';
COMMENT ON COLUMN org.user_group.tenant_id IS '租户隔离键；全零 UUID 表示平台范围，应用查询必须显式携带可信租户上下文。';
COMMENT ON COLUMN org.user_group.organization_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN org.user_group.group_code IS '稳定机器可读代码；展示文本由资源或目录解析。';
COMMENT ON COLUMN org.user_group.display_name IS 'org.user_group.display_name 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN org.user_group.group_state IS '显式状态当前值；合法取值见 CHECK，完整状态转换由 .NET 领域策略执行。';
COMMENT ON COLUMN org.user_group.source_kind IS '对象类别判别字段；允许值由 CHECK 或对应注册表限定。';
COMMENT ON COLUMN org.user_group.source_ref IS '不透明对象引用；不得从格式推断手机号、邮箱或其他业务事实。';
COMMENT ON COLUMN org.user_group.created_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN org.user_group.updated_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN org.user_group.row_version IS '乐观并发版本；更新必须使用原值 compare-and-set，成功后由数据库单调递增。';
COMMENT ON COLUMN org.group_member.id IS '内部 UUID 主键；仅用于数据库关系，不作为跨域公开标识。';
COMMENT ON COLUMN org.group_member.group_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN org.group_member.user_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN org.group_member.nested_group_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN org.group_member.membership_state IS '显式状态当前值；合法取值见 CHECK，完整状态转换由 .NET 领域策略执行。';
COMMENT ON COLUMN org.group_member.source_ref IS '不透明对象引用；不得从格式推断手机号、邮箱或其他业务事实。';
COMMENT ON COLUMN org.group_member.valid_from IS 'org.group_member.valid_from 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN org.group_member.valid_until IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN org.group_member.created_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN org.usage_meter.id IS '内部 UUID 主键；仅用于数据库关系，不作为跨域公开标识。';
COMMENT ON COLUMN org.usage_meter.tenant_id IS '租户隔离键；全零 UUID 表示平台范围，应用查询必须显式携带可信租户上下文。';
COMMENT ON COLUMN org.usage_meter.meter_code IS '稳定机器可读代码；展示文本由资源或目录解析。';
COMMENT ON COLUMN org.usage_meter.period_start IS 'org.usage_meter.period_start 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN org.usage_meter.period_end IS 'org.usage_meter.period_end 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN org.usage_meter.measured_value IS 'org.usage_meter.measured_value 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN org.usage_meter.source_version IS '对象、策略或源数据的显式版本；不得以不可信客户端时间戳替代。';
COMMENT ON COLUMN org.usage_meter.measured_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';

COMMENT ON CONSTRAINT pk_business_line ON org.business_line IS '主键约束：唯一标识 org.business_line 记录。';
COMMENT ON CONSTRAINT uq_business_line_public_id ON org.business_line IS '唯一约束：保证 public_id 在 org.business_line 范围内不重复。';
COMMENT ON CONSTRAINT uq_business_line_code ON org.business_line IS '唯一约束：保证 business_line_code 在 org.business_line 范围内不重复。';
COMMENT ON CONSTRAINT ck_business_line_code ON org.business_line IS '检查约束：限制 org.business_line 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_business_line_state ON org.business_line IS '检查约束：限制 org.business_line 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_business_line_closed ON org.business_line IS '检查约束：限制 org.business_line 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_business_line_activation ON org.business_line IS '检查约束：限制 org.business_line 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_business_line_closing ON org.business_line IS '检查约束：限制 org.business_line 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_business_line_irreversible ON org.business_line IS '检查约束：限制 org.business_line 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT pk_tenant ON org.tenant IS '主键约束：唯一标识 org.tenant 记录。';
COMMENT ON CONSTRAINT uq_tenant_public_id ON org.tenant IS '唯一约束：保证 public_id 在 org.tenant 范围内不重复。';
COMMENT ON CONSTRAINT uq_tenant_code ON org.tenant IS '唯一约束：保证 business_line_id、tenant_code 在 org.tenant 范围内不重复。';
COMMENT ON CONSTRAINT fk_tenant_business_line ON org.tenant IS '外键约束：org.tenant 的 business_line_id 必须引用 org.business_line；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT ck_tenant_code ON org.tenant IS '检查约束：限制 org.tenant 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_tenant_state ON org.tenant IS '检查约束：限制 org.tenant 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_tenant_type ON org.tenant IS '检查约束：限制 org.tenant 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_tenant_epoch ON org.tenant IS '检查约束：限制 org.tenant 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_tenant_closed ON org.tenant IS '检查约束：限制 org.tenant 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_tenant_irreversible ON org.tenant IS '检查约束：限制 org.tenant 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT uq_tenant_id_business_line ON org.tenant IS '唯一约束：保证 id、business_line_id 在 org.tenant 范围内不重复。';
COMMENT ON CONSTRAINT ck_tenant_activation ON org.tenant IS '检查约束：限制 org.tenant 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_tenant_closing ON org.tenant IS '检查约束：限制 org.tenant 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT pk_tenant_domain ON org.tenant_domain IS '主键约束：唯一标识 org.tenant_domain 记录。';
COMMENT ON CONSTRAINT uq_tenant_domain ON org.tenant_domain IS '唯一约束：保证 normalized_domain 在 org.tenant_domain 范围内不重复。';
COMMENT ON CONSTRAINT fk_tenant_domain_tenant ON org.tenant_domain IS '外键约束：org.tenant_domain 的 tenant_id 必须引用 org.tenant；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT ck_tenant_domain_value ON org.tenant_domain IS '检查约束：限制 org.tenant_domain 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_tenant_domain_state ON org.tenant_domain IS '检查约束：限制 org.tenant_domain 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_tenant_domain_method ON org.tenant_domain IS '检查约束：限制 org.tenant_domain 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_tenant_domain_hash ON org.tenant_domain IS '检查约束：限制 org.tenant_domain 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_tenant_domain_route ON org.tenant_domain IS '检查约束：限制 org.tenant_domain 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT pk_organization ON org.organization IS '主键约束：唯一标识 org.organization 记录。';
COMMENT ON CONSTRAINT uq_organization_public_id ON org.organization IS '唯一约束：保证 public_id 在 org.organization 范围内不重复。';
COMMENT ON CONSTRAINT uq_organization_code ON org.organization IS '唯一约束：保证 tenant_id、organization_code 在 org.organization 范围内不重复。';
COMMENT ON CONSTRAINT uq_organization_path ON org.organization IS '唯一约束：保证 tenant_id、hierarchy_path 在 org.organization 范围内不重复。';
COMMENT ON CONSTRAINT fk_organization_tenant ON org.organization IS '外键约束：org.organization 的 tenant_id 必须引用 org.tenant；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT fk_organization_parent ON org.organization IS '外键约束：org.organization 的 parent_id 必须引用 org.organization；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT ck_organization_kind ON org.organization IS '检查约束：限制 org.organization 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_organization_state ON org.organization IS '检查约束：限制 org.organization 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_organization_source ON org.organization IS '检查约束：限制 org.organization 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_organization_closed ON org.organization IS '检查约束：限制 org.organization 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT uq_organization_id_tenant ON org.organization IS '唯一约束：保证 id、tenant_id 在 org.organization 范围内不重复。';
COMMENT ON CONSTRAINT pk_membership ON org.membership IS '主键约束：唯一标识 org.membership 记录。';
COMMENT ON CONSTRAINT uq_membership_public_id ON org.membership IS '唯一约束：保证 public_id 在 org.membership 范围内不重复。';
COMMENT ON CONSTRAINT fk_membership_business_line ON org.membership IS '外键约束：org.membership 的 business_line_id 必须引用 org.business_line；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT fk_membership_tenant ON org.membership IS '外键约束：org.membership 的 tenant_id 必须引用 org.tenant；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT fk_membership_organization ON org.membership IS '外键约束：org.membership 的 organization_id 必须引用 org.organization；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT ck_membership_state ON org.membership IS '检查约束：限制 org.membership 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_membership_kind ON org.membership IS '检查约束：限制 org.membership 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_membership_source ON org.membership IS '检查约束：限制 org.membership 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_membership_joined ON org.membership IS '检查约束：限制 org.membership 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_membership_left ON org.membership IS '检查约束：限制 org.membership 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_membership_rejected ON org.membership IS '检查约束：限制 org.membership 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_membership_expired_state ON org.membership IS '检查约束：限制 org.membership 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT pk_invitation ON org.invitation IS '主键约束：唯一标识 org.invitation 记录。';
COMMENT ON CONSTRAINT uq_invitation_public_id ON org.invitation IS '唯一约束：保证 public_id 在 org.invitation 范围内不重复。';
COMMENT ON CONSTRAINT uq_invitation_token_hash ON org.invitation IS '唯一约束：保证 invitation_token_hash 在 org.invitation 范围内不重复。';
COMMENT ON CONSTRAINT fk_invitation_business_line ON org.invitation IS '外键约束：org.invitation 的 business_line_id 必须引用 org.business_line；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT fk_invitation_tenant ON org.invitation IS '外键约束：org.invitation 的 tenant_id 必须引用 org.tenant；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT fk_invitation_organization ON org.invitation IS '外键约束：org.invitation 的 organization_id 必须引用 org.organization；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT fk_invitation_inviter ON org.invitation IS '外键约束：org.invitation 的 inviter_membership_id 必须引用 org.membership；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT fk_invitation_membership ON org.invitation IS '外键约束：org.invitation 的 accepted_membership_id 必须引用 org.membership；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT ck_invitation_state ON org.invitation IS '检查约束：限制 org.invitation 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_invitation_identifier_kind ON org.invitation IS '检查约束：限制 org.invitation 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_invitation_hashes ON org.invitation IS '检查约束：限制 org.invitation 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_invitation_expiry ON org.invitation IS '检查约束：限制 org.invitation 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_invitation_accept ON org.invitation IS '检查约束：限制 org.invitation 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_invitation_decision_distinct ON org.invitation IS '检查约束：限制 org.invitation 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_invitation_rejected ON org.invitation IS '检查约束：限制 org.invitation 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_invitation_expired_state ON org.invitation IS '检查约束：限制 org.invitation 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_invitation_revoked ON org.invitation IS '检查约束：限制 org.invitation 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT pk_user_group ON org.user_group IS '主键约束：唯一标识 org.user_group 记录。';
COMMENT ON CONSTRAINT uq_user_group_public_id ON org.user_group IS '唯一约束：保证 public_id 在 org.user_group 范围内不重复。';
COMMENT ON CONSTRAINT uq_user_group_code ON org.user_group IS '唯一约束：保证 tenant_id、group_code 在 org.user_group 范围内不重复。';
COMMENT ON CONSTRAINT fk_user_group_tenant ON org.user_group IS '外键约束：org.user_group 的 tenant_id 必须引用 org.tenant；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT fk_user_group_org ON org.user_group IS '外键约束：org.user_group 的 organization_id 必须引用 org.organization；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT ck_user_group_state ON org.user_group IS '检查约束：限制 org.user_group 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_user_group_source ON org.user_group IS '检查约束：限制 org.user_group 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT pk_group_member ON org.group_member IS '主键约束：唯一标识 org.group_member 记录。';
COMMENT ON CONSTRAINT fk_group_member_group ON org.group_member IS '外键约束：org.group_member 的 group_id 必须引用 org.user_group；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT fk_group_member_nested ON org.group_member IS '外键约束：org.group_member 的 nested_group_id 必须引用 org.user_group；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT ck_group_member_target ON org.group_member IS '检查约束：限制 org.group_member 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_group_member_self ON org.group_member IS '检查约束：限制 org.group_member 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_group_member_state ON org.group_member IS '检查约束：限制 org.group_member 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_group_member_window ON org.group_member IS '检查约束：限制 org.group_member 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT pk_usage_meter ON org.usage_meter IS '主键约束：唯一标识 org.usage_meter 记录。';
COMMENT ON CONSTRAINT uq_usage_meter ON org.usage_meter IS '唯一约束：保证 tenant_id、meter_code、period_start、source_version 在 org.usage_meter 范围内不重复。';
COMMENT ON CONSTRAINT fk_usage_meter_tenant ON org.usage_meter IS '外键约束：org.usage_meter 的 tenant_id 必须引用 org.tenant；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT ck_usage_meter_window ON org.usage_meter IS '检查约束：限制 org.usage_meter 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_usage_meter_value ON org.usage_meter IS '检查约束：限制 org.usage_meter 的字段取值或组合满足结构与安全底线。';

COMMENT ON INDEX org.ux_membership_effective IS '查询索引：优化 org.membership 按 user_id、tenant_id 的访问，仅覆盖 WHERE 条件命中的记录。';
COMMENT ON INDEX org.ix_membership_tenant_state IS '查询索引：优化 org.membership 按 tenant_id、membership_state、user_id 的访问。';
COMMENT ON INDEX org.ix_invitation_target IS '查询索引：优化 org.invitation 按 tenant_id、target_normalized_hash 的访问，仅覆盖 WHERE 条件命中的记录。';
COMMENT ON INDEX org.ux_group_member_user IS '查询索引：优化 org.group_member 按 group_id、user_id 的访问，仅覆盖 WHERE 条件命中的记录。';
COMMENT ON INDEX org.ux_group_member_group IS '查询索引：优化 org.group_member 按 group_id、nested_group_id 的访问，仅覆盖 WHERE 条件命中的记录。';
COMMENT ON INDEX org.pk_business_line IS '约束 pk_business_line 的支撑唯一索引。';
COMMENT ON INDEX org.uq_business_line_public_id IS '约束 uq_business_line_public_id 的支撑唯一索引。';
COMMENT ON INDEX org.uq_business_line_code IS '约束 uq_business_line_code 的支撑唯一索引。';
COMMENT ON INDEX org.pk_tenant IS '约束 pk_tenant 的支撑唯一索引。';
COMMENT ON INDEX org.uq_tenant_public_id IS '约束 uq_tenant_public_id 的支撑唯一索引。';
COMMENT ON INDEX org.uq_tenant_code IS '约束 uq_tenant_code 的支撑唯一索引。';
COMMENT ON INDEX org.uq_tenant_id_business_line IS '约束 uq_tenant_id_business_line 的支撑唯一索引。';
COMMENT ON INDEX org.pk_tenant_domain IS '约束 pk_tenant_domain 的支撑唯一索引。';
COMMENT ON INDEX org.uq_tenant_domain IS '约束 uq_tenant_domain 的支撑唯一索引。';
COMMENT ON INDEX org.pk_organization IS '约束 pk_organization 的支撑唯一索引。';
COMMENT ON INDEX org.uq_organization_public_id IS '约束 uq_organization_public_id 的支撑唯一索引。';
COMMENT ON INDEX org.uq_organization_code IS '约束 uq_organization_code 的支撑唯一索引。';
COMMENT ON INDEX org.uq_organization_path IS '约束 uq_organization_path 的支撑唯一索引。';
COMMENT ON INDEX org.uq_organization_id_tenant IS '约束 uq_organization_id_tenant 的支撑唯一索引。';
COMMENT ON INDEX org.pk_membership IS '约束 pk_membership 的支撑唯一索引。';
COMMENT ON INDEX org.uq_membership_public_id IS '约束 uq_membership_public_id 的支撑唯一索引。';
COMMENT ON INDEX org.pk_invitation IS '约束 pk_invitation 的支撑唯一索引。';
COMMENT ON INDEX org.uq_invitation_public_id IS '约束 uq_invitation_public_id 的支撑唯一索引。';
COMMENT ON INDEX org.uq_invitation_token_hash IS '约束 uq_invitation_token_hash 的支撑唯一索引。';
COMMENT ON INDEX org.pk_user_group IS '约束 pk_user_group 的支撑唯一索引。';
COMMENT ON INDEX org.uq_user_group_public_id IS '约束 uq_user_group_public_id 的支撑唯一索引。';
COMMENT ON INDEX org.uq_user_group_code IS '约束 uq_user_group_code 的支撑唯一索引。';
COMMENT ON INDEX org.pk_group_member IS '约束 pk_group_member 的支撑唯一索引。';
COMMENT ON INDEX org.pk_usage_meter IS '约束 pk_usage_meter 的支撑唯一索引。';
COMMENT ON INDEX org.uq_usage_meter IS '约束 uq_usage_meter 的支撑唯一索引。';
COMMENT ON INDEX org.ix_fk_tenant_domain_tenant_id IS '查询索引：优化 org.tenant_domain 按 tenant_id 的访问。';
COMMENT ON INDEX org.ix_fk_organization_parent_id IS '查询索引：优化 org.organization 按 parent_id 的访问。';
COMMENT ON INDEX org.ix_fk_membership_business_line_id IS '查询索引：优化 org.membership 按 business_line_id 的访问。';
COMMENT ON INDEX org.ix_fk_membership_organization_id IS '查询索引：优化 org.membership 按 organization_id 的访问。';
COMMENT ON INDEX org.ix_fk_invitation_business_line_id IS '查询索引：优化 org.invitation 按 business_line_id 的访问。';
COMMENT ON INDEX org.ix_fk_invitation_tenant_id IS '查询索引：优化 org.invitation 按 tenant_id 的访问。';
COMMENT ON INDEX org.ix_fk_invitation_organization_id IS '查询索引：优化 org.invitation 按 organization_id 的访问。';
COMMENT ON INDEX org.ix_fk_invitation_inviter_membership_id IS '查询索引：优化 org.invitation 按 inviter_membership_id 的访问。';
COMMENT ON INDEX org.ix_fk_invitation_accepted_membership_id IS '查询索引：优化 org.invitation 按 accepted_membership_id 的访问。';
COMMENT ON INDEX org.ix_fk_user_group_organization_id IS '查询索引：优化 org.user_group 按 organization_id 的访问。';
COMMENT ON INDEX org.ix_fk_group_member_group_id IS '查询索引：优化 org.group_member 按 group_id 的访问。';
COMMENT ON INDEX org.ix_fk_group_member_nested_group_id IS '查询索引：优化 org.group_member 按 nested_group_id 的访问。';

