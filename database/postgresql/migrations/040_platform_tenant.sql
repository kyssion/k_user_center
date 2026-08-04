\set ON_ERROR_STOP on

SET ROLE iam_owner;

-- 业务线、应用、OAuth 资源、租户、组织与成员关系。

CREATE TABLE iam.business_lines (
    id uuid PRIMARY KEY,
    public_id varchar(64) NOT NULL,
    name varchar(160) NOT NULL,
    owner_type varchar(40) NOT NULL,
    owner_id uuid NOT NULL,
    state varchar(40) NOT NULL,
    active_configuration_id uuid,
    state_changed_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    row_version bigint NOT NULL DEFAULT 0,
    CONSTRAINT uq_business_lines_public UNIQUE (public_id),
    CONSTRAINT ck_business_lines_version CHECK (row_version >= 0)
);
COMMENT ON TABLE iam.business_lines IS '业务线根对象；只保存接入边界和配置引用，不保存具体业务会员状态。';
COMMENT ON COLUMN iam.business_lines.id IS '应用生成的业务线 UUIDv7。';
COMMENT ON COLUMN iam.business_lines.public_id IS '稳定且不可推断的业务线公开标识。';
COMMENT ON COLUMN iam.business_lines.name IS '业务线展示名称。';
COMMENT ON COLUMN iam.business_lines.owner_type IS '所有者类型。';
COMMENT ON COLUMN iam.business_lines.owner_id IS '按 owner_type 逻辑引用责任主体，数据库不创建外键。';
COMMENT ON COLUMN iam.business_lines.state IS '业务线接入状态；由 PLT 领域代码维护。';
COMMENT ON COLUMN iam.business_lines.active_configuration_id IS '可空；逻辑引用 iam.configuration_versions.id。';
COMMENT ON COLUMN iam.business_lines.state_changed_at IS '状态最近变化业务时间。';
COMMENT ON COLUMN iam.business_lines.created_at IS '数据库插入时间。';
COMMENT ON COLUMN iam.business_lines.updated_at IS '数据库更新时间；由技术 Trigger 自动刷新。';
COMMENT ON COLUMN iam.business_lines.row_version IS '乐观锁版本。';

CREATE TABLE iam.applications (
    id uuid PRIMARY KEY,
    business_line_id uuid NOT NULL,
    public_id varchar(64) NOT NULL,
    name varchar(160) NOT NULL,
    application_type varchar(40) NOT NULL,
    owner_type varchar(40) NOT NULL,
    owner_id uuid NOT NULL,
    state varchar(40) NOT NULL,
    metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    row_version bigint NOT NULL DEFAULT 0,
    CONSTRAINT uq_applications_public UNIQUE (public_id),
    CONSTRAINT ck_applications_version CHECK (row_version >= 0)
);
COMMENT ON TABLE iam.applications IS '接入应用登记；OAuth Client、消息发送方和资源归属可逻辑引用该对象。';
COMMENT ON COLUMN iam.applications.id IS '应用生成的应用 UUIDv7。';
COMMENT ON COLUMN iam.applications.business_line_id IS '逻辑引用 iam.business_lines.id。';
COMMENT ON COLUMN iam.applications.public_id IS '稳定应用公开标识。';
COMMENT ON COLUMN iam.applications.name IS '应用展示名称。';
COMMENT ON COLUMN iam.applications.application_type IS '应用类型，例如 WEB、NATIVE、SERVICE。';
COMMENT ON COLUMN iam.applications.owner_type IS '所有者类型。';
COMMENT ON COLUMN iam.applications.owner_id IS '所有者逻辑 ID。';
COMMENT ON COLUMN iam.applications.state IS '应用接入状态；由 PLT 代码维护。';
COMMENT ON COLUMN iam.applications.metadata IS '非秘密应用元数据，代码按 Schema 校验。';
COMMENT ON COLUMN iam.applications.created_at IS '数据库插入时间。';
COMMENT ON COLUMN iam.applications.updated_at IS '数据库更新时间；由技术 Trigger 自动刷新。';
COMMENT ON COLUMN iam.applications.row_version IS '乐观锁版本。';

CREATE TABLE iam.oauth_clients (
    id uuid PRIMARY KEY,
    application_id uuid NOT NULL,
    client_id varchar(128) NOT NULL,
    client_type varchar(40) NOT NULL,
    owner_type varchar(40) NOT NULL,
    owner_id uuid NOT NULL,
    state varchar(40) NOT NULL,
    client_security_epoch bigint NOT NULL DEFAULT 0,
    active_configuration_id uuid,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    row_version bigint NOT NULL DEFAULT 0,
    CONSTRAINT uq_oauth_clients_client_id UNIQUE (client_id),
    CONSTRAINT ck_oauth_clients_epoch CHECK (client_security_epoch >= 0),
    CONSTRAINT ck_oauth_clients_version CHECK (row_version >= 0)
);
COMMENT ON TABLE iam.oauth_clients IS 'OAuth/OIDC Client 根对象；协议校验、重定向匹配和认证方法由 OAP 代码执行。';
COMMENT ON COLUMN iam.oauth_clients.id IS '应用生成的 Client 内部 UUIDv7。';
COMMENT ON COLUMN iam.oauth_clients.application_id IS '逻辑引用 iam.applications.id。';
COMMENT ON COLUMN iam.oauth_clients.client_id IS '协议公开 Client ID，全局唯一。';
COMMENT ON COLUMN iam.oauth_clients.client_type IS 'Client 类型，例如 PUBLIC、CONFIDENTIAL。';
COMMENT ON COLUMN iam.oauth_clients.owner_type IS 'Client 所有者类型。';
COMMENT ON COLUMN iam.oauth_clients.owner_id IS 'Client 所有者逻辑 ID。';
COMMENT ON COLUMN iam.oauth_clients.state IS 'Client 状态；生命周期由 OAP 领域持有，CTRL 只提供配置审批事实。';
COMMENT ON COLUMN iam.oauth_clients.client_security_epoch IS 'Client 安全水位；密钥或安全配置变化时由代码递增。';
COMMENT ON COLUMN iam.oauth_clients.active_configuration_id IS '可空；逻辑引用 iam.configuration_versions.id；协议配置内容只保存在不可变配置版本中。';
COMMENT ON COLUMN iam.oauth_clients.created_at IS '数据库插入时间。';
COMMENT ON COLUMN iam.oauth_clients.updated_at IS '数据库更新时间；由技术 Trigger 自动刷新。';
COMMENT ON COLUMN iam.oauth_clients.row_version IS '乐观锁版本。';

CREATE TABLE iam.api_resources (
    id uuid PRIMARY KEY,
    business_line_id uuid NOT NULL,
    audience varchar(256) NOT NULL,
    name varchar(160) NOT NULL,
    owner_type varchar(40) NOT NULL,
    owner_id uuid NOT NULL,
    state varchar(40) NOT NULL,
    token_profile varchar(80) NOT NULL,
    active_configuration_id uuid,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    row_version bigint NOT NULL DEFAULT 0,
    CONSTRAINT uq_api_resources_audience UNIQUE (audience),
    CONSTRAINT ck_api_resources_version CHECK (row_version >= 0)
);
COMMENT ON TABLE iam.api_resources IS '受保护 API 资源和 Token Audience 目录。';
COMMENT ON COLUMN iam.api_resources.id IS '应用生成的资源 UUIDv7。';
COMMENT ON COLUMN iam.api_resources.business_line_id IS '逻辑引用 iam.business_lines.id。';
COMMENT ON COLUMN iam.api_resources.audience IS 'Token Audience 稳定值，全局唯一。';
COMMENT ON COLUMN iam.api_resources.name IS '资源展示名称。';
COMMENT ON COLUMN iam.api_resources.owner_type IS '资源所有者类型。';
COMMENT ON COLUMN iam.api_resources.owner_id IS '资源所有者逻辑 ID。';
COMMENT ON COLUMN iam.api_resources.state IS '资源状态；生命周期由 OAP 领域持有，API 领域只消费资源登记事实。';
COMMENT ON COLUMN iam.api_resources.token_profile IS '引用的 Token Profile 代码。';
COMMENT ON COLUMN iam.api_resources.active_configuration_id IS '可空；逻辑引用 iam.configuration_versions.id；资源验证配置内容只保存在不可变配置版本中。';
COMMENT ON COLUMN iam.api_resources.created_at IS '数据库插入时间。';
COMMENT ON COLUMN iam.api_resources.updated_at IS '数据库更新时间；由技术 Trigger 自动刷新。';
COMMENT ON COLUMN iam.api_resources.row_version IS '乐观锁版本。';

CREATE TABLE iam.oauth_scopes (
    id uuid PRIMARY KEY,
    resource_id uuid,
    scope_code varchar(160) NOT NULL,
    display_name varchar(160) NOT NULL,
    description text,
    sensitivity varchar(40) NOT NULL,
    consent_required boolean NOT NULL DEFAULT false,
    state varchar(40) NOT NULL,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    row_version bigint NOT NULL DEFAULT 0,
    CONSTRAINT uq_oauth_scopes_code UNIQUE (scope_code),
    CONSTRAINT ck_oauth_scopes_version CHECK (row_version >= 0)
);
COMMENT ON TABLE iam.oauth_scopes IS 'OAuth Scope 稳定目录；目录生命周期由 OAP 领域持有，AUTHZ 使用 Scope 执行授权判断。';
COMMENT ON COLUMN iam.oauth_scopes.id IS '应用生成的 Scope UUIDv7。';
COMMENT ON COLUMN iam.oauth_scopes.resource_id IS '可空；逻辑引用 iam.api_resources.id，跨资源标准 Scope 可为空。';
COMMENT ON COLUMN iam.oauth_scopes.scope_code IS '协议 Scope 稳定代码，全局唯一。';
COMMENT ON COLUMN iam.oauth_scopes.display_name IS 'Scope 展示名称。';
COMMENT ON COLUMN iam.oauth_scopes.description IS '可空；面向管理员或用户的说明。';
COMMENT ON COLUMN iam.oauth_scopes.sensitivity IS '敏感级别代码。';
COMMENT ON COLUMN iam.oauth_scopes.consent_required IS '是否通常需要用户同意；最终判断由代码和策略完成。';
COMMENT ON COLUMN iam.oauth_scopes.state IS 'Scope 状态。';
COMMENT ON COLUMN iam.oauth_scopes.created_at IS '数据库插入时间。';
COMMENT ON COLUMN iam.oauth_scopes.updated_at IS '数据库更新时间；由技术 Trigger 自动刷新。';
COMMENT ON COLUMN iam.oauth_scopes.row_version IS '乐观锁版本。';

CREATE TABLE iam.tenants (
    id uuid PRIMARY KEY,
    business_line_id uuid NOT NULL,
    tenant_id varchar(64) NOT NULL,
    name varchar(160) NOT NULL,
    owner_type varchar(40) NOT NULL,
    owner_id uuid NOT NULL,
    state varchar(40) NOT NULL,
    tenant_security_epoch bigint NOT NULL DEFAULT 0,
    active_configuration_id uuid,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    row_version bigint NOT NULL DEFAULT 0,
    CONSTRAINT uq_tenants_public UNIQUE (tenant_id),
    CONSTRAINT ck_tenants_epoch CHECK (tenant_security_epoch >= 0),
    CONSTRAINT ck_tenants_version CHECK (row_version >= 0)
);
COMMENT ON TABLE iam.tenants IS '租户根对象；租户策略、隔离和生命周期由 TENANT 代码执行。';
COMMENT ON COLUMN iam.tenants.id IS '应用生成的租户内部 UUIDv7。';
COMMENT ON COLUMN iam.tenants.business_line_id IS '逻辑引用 iam.business_lines.id。';
COMMENT ON COLUMN iam.tenants.tenant_id IS '稳定租户公开标识。';
COMMENT ON COLUMN iam.tenants.name IS '租户展示名称。';
COMMENT ON COLUMN iam.tenants.owner_type IS '租户所有者类型。';
COMMENT ON COLUMN iam.tenants.owner_id IS '租户所有者逻辑 ID。';
COMMENT ON COLUMN iam.tenants.state IS '租户状态；合法转换由 TENANT 代码维护。';
COMMENT ON COLUMN iam.tenants.tenant_security_epoch IS '租户安全水位，由代码在全局撤销或安全变更时递增。';
COMMENT ON COLUMN iam.tenants.active_configuration_id IS '可空；逻辑引用 iam.configuration_versions.id。';
COMMENT ON COLUMN iam.tenants.created_at IS '数据库插入时间。';
COMMENT ON COLUMN iam.tenants.updated_at IS '数据库更新时间；由技术 Trigger 自动刷新。';
COMMENT ON COLUMN iam.tenants.row_version IS '乐观锁版本。';

CREATE TABLE iam.tenant_domains (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    normalized_domain varchar(253) NOT NULL,
    purpose varchar(40) NOT NULL,
    verification_state varchar(40) NOT NULL,
    verification_token_hash varchar(256),
    verified_at timestamptz,
    state varchar(40) NOT NULL,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    row_version bigint NOT NULL DEFAULT 0,
    CONSTRAINT uq_tenant_domains_domain UNIQUE (normalized_domain),
    CONSTRAINT ck_tenant_domains_version CHECK (row_version >= 0)
);
COMMENT ON TABLE iam.tenant_domains IS '租户域名和所有权验证事实；发现、路由和验证流程由 TENANT/FED 代码处理。';
COMMENT ON COLUMN iam.tenant_domains.id IS '应用生成的域名记录 UUIDv7。';
COMMENT ON COLUMN iam.tenant_domains.tenant_id IS '逻辑引用 iam.tenants.id。';
COMMENT ON COLUMN iam.tenant_domains.normalized_domain IS '小写 ASCII/Punycode 规范化域名，全局唯一。';
COMMENT ON COLUMN iam.tenant_domains.purpose IS '域名用途，例如 LOGIN_DISCOVERY、EMAIL_OWNERSHIP。';
COMMENT ON COLUMN iam.tenant_domains.verification_state IS '所有权验证状态。';
COMMENT ON COLUMN iam.tenant_domains.verification_token_hash IS '可空；域名验证 Token 摘要，不保存原值。';
COMMENT ON COLUMN iam.tenant_domains.verified_at IS '可空；验证成功时间。';
COMMENT ON COLUMN iam.tenant_domains.state IS '域名使用状态。';
COMMENT ON COLUMN iam.tenant_domains.created_at IS '数据库插入时间。';
COMMENT ON COLUMN iam.tenant_domains.updated_at IS '数据库更新时间；由技术 Trigger 自动刷新。';
COMMENT ON COLUMN iam.tenant_domains.row_version IS '乐观锁版本。';

CREATE TABLE iam.organizations (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    parent_organization_id uuid,
    organization_code varchar(128) NOT NULL,
    name varchar(200) NOT NULL,
    external_mapping_digest varchar(128),
    state varchar(40) NOT NULL,
    path_hint text,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    row_version bigint NOT NULL DEFAULT 0,
    CONSTRAINT uq_organizations_code UNIQUE (tenant_id, organization_code),
    CONSTRAINT ck_organizations_version CHECK (row_version >= 0),
    CONSTRAINT ck_organizations_not_self CHECK (parent_organization_id IS NULL OR parent_organization_id <> id)
);
COMMENT ON TABLE iam.organizations IS '租户组织节点；树闭环、移动、深度和路径一致性由 TENANT 代码维护。';
COMMENT ON COLUMN iam.organizations.id IS '应用生成的组织 UUIDv7。';
COMMENT ON COLUMN iam.organizations.tenant_id IS '逻辑引用 iam.tenants.id。';
COMMENT ON COLUMN iam.organizations.parent_organization_id IS '可空；逻辑引用 iam.organizations.id，根节点为空。';
COMMENT ON COLUMN iam.organizations.organization_code IS '租户内稳定组织代码。';
COMMENT ON COLUMN iam.organizations.name IS '组织展示名称。';
COMMENT ON COLUMN iam.organizations.external_mapping_digest IS '可空；外部目录稳定键摘要。';
COMMENT ON COLUMN iam.organizations.state IS '组织状态。';
COMMENT ON COLUMN iam.organizations.path_hint IS '可空；查询优化路径快照，不作为权威层级规则。';
COMMENT ON COLUMN iam.organizations.created_at IS '数据库插入时间。';
COMMENT ON COLUMN iam.organizations.updated_at IS '数据库更新时间；由技术 Trigger 自动刷新。';
COMMENT ON COLUMN iam.organizations.row_version IS '乐观锁版本。';

CREATE TABLE iam.memberships (
    id uuid PRIMARY KEY,
    user_id uuid NOT NULL,
    scope_type varchar(40) NOT NULL,
    scope_id uuid NOT NULL,
    business_line_id uuid NOT NULL,
    tenant_id uuid,
    organization_id uuid,
    state varchar(40) NOT NULL,
    joined_at timestamptz,
    left_at timestamptz,
    current_occupancy_slot smallint DEFAULT 1,
    attributes jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    row_version bigint NOT NULL DEFAULT 0,
    CONSTRAINT uq_memberships_current UNIQUE (scope_type, scope_id, user_id, current_occupancy_slot),
    CONSTRAINT ck_memberships_current_slot CHECK (current_occupancy_slot IS NULL OR current_occupancy_slot = 1),
    CONSTRAINT ck_memberships_version CHECK (row_version >= 0)
);
COMMENT ON TABLE iam.memberships IS '用户与业务线、租户或组织的成员关系；作用域一致性和业务资格由 TENANT 代码校验。';
COMMENT ON COLUMN iam.memberships.id IS '应用生成的 Membership UUIDv7。';
COMMENT ON COLUMN iam.memberships.user_id IS '逻辑引用 iam.global_users.id。';
COMMENT ON COLUMN iam.memberships.scope_type IS '成员作用域类型。';
COMMENT ON COLUMN iam.memberships.scope_id IS '按 scope_type 逻辑引用业务线、租户或组织。';
COMMENT ON COLUMN iam.memberships.business_line_id IS '逻辑引用 iam.business_lines.id；便于隔离查询。';
COMMENT ON COLUMN iam.memberships.tenant_id IS '可空；逻辑引用 iam.tenants.id。';
COMMENT ON COLUMN iam.memberships.organization_id IS '可空；逻辑引用 iam.organizations.id。';
COMMENT ON COLUMN iam.memberships.state IS '成员状态；邀请、加入、暂停和离开由 TENANT 代码维护。';
COMMENT ON COLUMN iam.memberships.joined_at IS '可空；成员关系生效时间。';
COMMENT ON COLUMN iam.memberships.left_at IS '可空；成员关系结束时间。';
COMMENT ON COLUMN iam.memberships.current_occupancy_slot IS '可空；新记录默认占位 1，终态历史记录写 NULL。数据库只保证同一作用域和用户最多一个当前 Membership；何时释放占位由 TENANT 状态机决定。';
COMMENT ON COLUMN iam.memberships.attributes IS '作用域内成员扩展属性；代码按 Schema 校验。';
COMMENT ON COLUMN iam.memberships.created_at IS '数据库插入时间。';
COMMENT ON COLUMN iam.memberships.updated_at IS '数据库更新时间；由技术 Trigger 自动刷新。';
COMMENT ON COLUMN iam.memberships.row_version IS '乐观锁版本。';

CREATE TABLE iam.invitations (
    id uuid PRIMARY KEY,
    scope_type varchar(40) NOT NULL,
    scope_id uuid NOT NULL,
    target_digest varchar(128) NOT NULL,
    inviter_user_id uuid,
    inviter_machine_id uuid,
    token_hash varchar(256) NOT NULL,
    role_upper_bound jsonb NOT NULL DEFAULT '[]'::jsonb,
    state varchar(40) NOT NULL,
    expires_at timestamptz NOT NULL,
    accepted_by_user_id uuid,
    accepted_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    row_version bigint NOT NULL DEFAULT 0,
    CONSTRAINT uq_invitations_token UNIQUE (token_hash),
    CONSTRAINT ck_invitations_inviter CHECK ((inviter_user_id IS NOT NULL) <> (inviter_machine_id IS NOT NULL)),
    CONSTRAINT ck_invitations_version CHECK (row_version >= 0),
    CONSTRAINT ck_invitations_expiry CHECK (expires_at > created_at)
);
COMMENT ON TABLE iam.invitations IS '作用域成员邀请；只保存目标和 Token 摘要，权限上界、一次性消费和注册联动由 TENANT 代码执行。';
COMMENT ON COLUMN iam.invitations.id IS '应用生成的邀请码 UUIDv7。';
COMMENT ON COLUMN iam.invitations.scope_type IS '邀请目标作用域类型。';
COMMENT ON COLUMN iam.invitations.scope_id IS '按 scope_type 逻辑引用作用域对象。';
COMMENT ON COLUMN iam.invitations.target_digest IS '邀请目标联系方式的 HMAC 摘要。';
COMMENT ON COLUMN iam.invitations.inviter_user_id IS '可空；逻辑引用 iam.global_users.id。';
COMMENT ON COLUMN iam.invitations.inviter_machine_id IS '可空；逻辑引用 iam.machine_principals.id。';
COMMENT ON COLUMN iam.invitations.token_hash IS '一次性邀请 Token 摘要。';
COMMENT ON COLUMN iam.invitations.role_upper_bound IS '邀请可授予角色上界快照；最终授权由代码判断。';
COMMENT ON COLUMN iam.invitations.state IS '邀请状态。';
COMMENT ON COLUMN iam.invitations.expires_at IS '邀请过期时间。';
COMMENT ON COLUMN iam.invitations.accepted_by_user_id IS '可空；接受者逻辑引用 iam.global_users.id。';
COMMENT ON COLUMN iam.invitations.accepted_at IS '可空；接受时间。';
COMMENT ON COLUMN iam.invitations.created_at IS '数据库插入时间。';
COMMENT ON COLUMN iam.invitations.updated_at IS '数据库更新时间；由技术 Trigger 自动刷新。';
COMMENT ON COLUMN iam.invitations.row_version IS '乐观锁版本。';

CREATE TABLE iam.groups (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    organization_id uuid,
    group_code varchar(128) NOT NULL,
    name varchar(200) NOT NULL,
    group_type varchar(40) NOT NULL,
    state varchar(40) NOT NULL,
    source_connector_id uuid,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    row_version bigint NOT NULL DEFAULT 0,
    CONSTRAINT uq_groups_code UNIQUE (tenant_id, group_code),
    CONSTRAINT ck_groups_version CHECK (row_version >= 0)
);
COMMENT ON TABLE iam.groups IS '租户用户组；动态计算、目录同步和成员管理由 TENANT/FED 代码处理。';
COMMENT ON COLUMN iam.groups.id IS '应用生成的用户组 UUIDv7。';
COMMENT ON COLUMN iam.groups.tenant_id IS '逻辑引用 iam.tenants.id。';
COMMENT ON COLUMN iam.groups.organization_id IS '可空；逻辑引用 iam.organizations.id。';
COMMENT ON COLUMN iam.groups.group_code IS '租户内稳定用户组代码。';
COMMENT ON COLUMN iam.groups.name IS '用户组展示名称。';
COMMENT ON COLUMN iam.groups.group_type IS '用户组类型，例如 STATIC、DIRECTORY。';
COMMENT ON COLUMN iam.groups.state IS '用户组状态。';
COMMENT ON COLUMN iam.groups.source_connector_id IS '可空；逻辑引用 iam.directory_connectors.id。';
COMMENT ON COLUMN iam.groups.created_at IS '数据库插入时间。';
COMMENT ON COLUMN iam.groups.updated_at IS '数据库更新时间；由技术 Trigger 自动刷新。';
COMMENT ON COLUMN iam.groups.row_version IS '乐观锁版本。';

CREATE TABLE iam.group_members (
    id uuid PRIMARY KEY,
    group_id uuid NOT NULL,
    user_id uuid NOT NULL,
    membership_id uuid,
    source_type varchar(40) NOT NULL,
    source_id uuid,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    removed_at timestamptz,
    CONSTRAINT uq_group_members_group_user UNIQUE (group_id, user_id)
);
COMMENT ON TABLE iam.group_members IS '用户组成员关系；目录权威、手工成员和移除规则由 TENANT/FED 代码处理。';
COMMENT ON COLUMN iam.group_members.id IS '应用生成的关系 UUIDv7。';
COMMENT ON COLUMN iam.group_members.group_id IS '逻辑引用 iam.groups.id。';
COMMENT ON COLUMN iam.group_members.user_id IS '逻辑引用 iam.global_users.id。';
COMMENT ON COLUMN iam.group_members.membership_id IS '可空；逻辑引用 iam.memberships.id。';
COMMENT ON COLUMN iam.group_members.source_type IS '成员来源类型。';
COMMENT ON COLUMN iam.group_members.source_id IS '可空；目录映射或操作等来源逻辑 ID。';
COMMENT ON COLUMN iam.group_members.created_at IS '数据库插入时间。';
COMMENT ON COLUMN iam.group_members.removed_at IS '可空；关系移除时间。';

CREATE TABLE iam.usage_records (
    id uuid PRIMARY KEY,
    business_line_id uuid,
    tenant_id uuid,
    application_id uuid,
    metric_code varchar(100) NOT NULL,
    window_start timestamptz NOT NULL,
    window_end timestamptz NOT NULL,
    quantity numeric(20,4) NOT NULL,
    source_event_id uuid,
    dimensions jsonb NOT NULL DEFAULT '{}'::jsonb,
    recorded_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT uq_usage_source UNIQUE (metric_code, source_event_id),
    CONSTRAINT ck_usage_quantity CHECK (quantity >= 0),
    CONSTRAINT ck_usage_window CHECK (window_end > window_start)
);
COMMENT ON TABLE iam.usage_records IS 'API、Token、消息等计量事实；模型与历史记录由 PLT 领域持有，各使用域按幂等计量契约提交事实。';
COMMENT ON COLUMN iam.usage_records.id IS '应用生成的计量 UUIDv7。';
COMMENT ON COLUMN iam.usage_records.business_line_id IS '可空；逻辑引用 iam.business_lines.id。';
COMMENT ON COLUMN iam.usage_records.tenant_id IS '可空；逻辑引用 iam.tenants.id。';
COMMENT ON COLUMN iam.usage_records.application_id IS '可空；逻辑引用 iam.applications.id。';
COMMENT ON COLUMN iam.usage_records.metric_code IS '稳定计量指标代码。';
COMMENT ON COLUMN iam.usage_records.window_start IS '计量窗口开始时间。';
COMMENT ON COLUMN iam.usage_records.window_end IS '计量窗口结束时间。';
COMMENT ON COLUMN iam.usage_records.quantity IS '非负计量数量。';
COMMENT ON COLUMN iam.usage_records.source_event_id IS '可空；来源事件 ID，用于代码幂等。';
COMMENT ON COLUMN iam.usage_records.dimensions IS '受控低基数维度，代码限制键和值。';
COMMENT ON COLUMN iam.usage_records.recorded_at IS '数据库落库时间。';

CREATE TABLE iam.resource_quotas (
    id uuid PRIMARY KEY,
    scope_type varchar(40) NOT NULL,
    scope_id uuid NOT NULL,
    metric_code varchar(100) NOT NULL,
    limit_value numeric(20,4) NOT NULL,
    period_code varchar(40) NOT NULL,
    configuration_version_id uuid,
    state varchar(40) NOT NULL,
    effective_at timestamptz NOT NULL,
    expires_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    row_version bigint NOT NULL DEFAULT 0,
    CONSTRAINT uq_resource_quota UNIQUE (scope_type, scope_id, metric_code, period_code),
    CONSTRAINT ck_resource_quota_limit CHECK (limit_value >= 0),
    CONSTRAINT ck_resource_quota_version CHECK (row_version >= 0),
    CONSTRAINT ck_resource_quota_expiry CHECK (expires_at IS NULL OR expires_at > effective_at)
);
COMMENT ON TABLE iam.resource_quotas IS '作用域计量配额事实；模型与版本由 PLT 领域持有，窗口计算、超额动作和降级属于非数据库职责。';
COMMENT ON COLUMN iam.resource_quotas.id IS '应用生成的配额 UUIDv7。';
COMMENT ON COLUMN iam.resource_quotas.scope_type IS '配额作用域类型。';
COMMENT ON COLUMN iam.resource_quotas.scope_id IS '按 scope_type 逻辑引用作用域对象。';
COMMENT ON COLUMN iam.resource_quotas.metric_code IS '稳定计量指标代码。';
COMMENT ON COLUMN iam.resource_quotas.limit_value IS '非负配额上限。';
COMMENT ON COLUMN iam.resource_quotas.period_code IS '配额周期代码。';
COMMENT ON COLUMN iam.resource_quotas.configuration_version_id IS '可空；逻辑引用 iam.configuration_versions.id。';
COMMENT ON COLUMN iam.resource_quotas.state IS '配额记录状态。';
COMMENT ON COLUMN iam.resource_quotas.effective_at IS '生效时间。';
COMMENT ON COLUMN iam.resource_quotas.expires_at IS '可空；失效时间。';
COMMENT ON COLUMN iam.resource_quotas.created_at IS '数据库插入时间。';
COMMENT ON COLUMN iam.resource_quotas.updated_at IS '数据库更新时间；由技术 Trigger 自动刷新。';
COMMENT ON COLUMN iam.resource_quotas.row_version IS '乐观锁版本。';

CREATE INDEX ix_applications_business_line ON iam.applications (business_line_id, state);
CREATE INDEX ix_oauth_clients_application ON iam.oauth_clients (application_id, state);
CREATE INDEX ix_tenants_business_line ON iam.tenants (business_line_id, state);
CREATE INDEX ix_organizations_parent ON iam.organizations (tenant_id, parent_organization_id, state);
CREATE INDEX ix_memberships_user ON iam.memberships (user_id, state, tenant_id);
CREATE INDEX ix_memberships_tenant ON iam.memberships (tenant_id, organization_id, state);
CREATE INDEX ix_invitations_target ON iam.invitations (target_digest, state, expires_at);
CREATE INDEX ix_group_members_user ON iam.group_members (user_id, removed_at);
CREATE INDEX ix_usage_scope_metric ON iam.usage_records (tenant_id, metric_code, window_start);
COMMENT ON INDEX iam.ix_memberships_tenant IS '租户和组织内按状态查询成员关系。';
