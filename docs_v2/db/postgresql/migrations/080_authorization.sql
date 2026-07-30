-- Authorization scope graph, RBAC, relation tuples, policy and decision evidence.
-- Hierarchy cycle checks, cross-tenant consistency and PDP transaction functions
-- are deferred to 110_constraints_functions.sql.

BEGIN;

CREATE TABLE public.authz_scope_nodes (
    scope_node_pk bigint GENERATED ALWAYS AS IDENTITY,
    scope_node_id uuid NOT NULL DEFAULT pg_catalog.gen_random_uuid(),
    parent_scope_node_pk bigint,
    scope_type text COLLATE "C" NOT NULL,
    scope_code text COLLATE "C" NOT NULL,
    status text COLLATE "C" NOT NULL DEFAULT 'ACTIVE',
    row_version bigint NOT NULL DEFAULT 1,
    created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    CONSTRAINT authz_scope_nodes_pkey PRIMARY KEY (scope_node_pk),
    CONSTRAINT authz_scope_nodes_id_key UNIQUE (scope_node_id),
    CONSTRAINT authz_scope_nodes_parent_code_key UNIQUE NULLS NOT DISTINCT (
        parent_scope_node_pk, scope_type, scope_code
    ),
    CONSTRAINT authz_scope_nodes_id_v4_ck CHECK (public.iam_uuid_is_v4(scope_node_id)),
    CONSTRAINT authz_scope_nodes_parent_fk FOREIGN KEY (parent_scope_node_pk)
        REFERENCES public.authz_scope_nodes (scope_node_pk) ON DELETE RESTRICT,
    CONSTRAINT authz_scope_nodes_no_self_ck CHECK (
        parent_scope_node_pk IS NULL OR parent_scope_node_pk <> scope_node_pk
    ),
    CONSTRAINT authz_scope_nodes_type_ck CHECK (
        scope_type IN ('PLATFORM', 'BUSINESS_LINE', 'APPLICATION', 'TENANT', 'ORGANIZATION')
    ),
    CONSTRAINT authz_scope_nodes_code_ck CHECK (
        pg_catalog.length(scope_code) BETWEEN 1 AND 96
        AND scope_code ~ '^[A-Za-z0-9][A-Za-z0-9_.:-]*$'
    ),
    CONSTRAINT authz_scope_nodes_status_ck CHECK (status IN ('ACTIVE', 'SUSPENDED', 'RETIRED')),
    CONSTRAINT authz_scope_nodes_version_ck CHECK (row_version > 0),
    CONSTRAINT authz_scope_nodes_time_ck CHECK (updated_at >= created_at)
);

COMMENT ON TABLE public.authz_scope_nodes IS
    'Authorization scope hierarchy shared by platform, business, application, tenant and organization boundaries; S2.';

CREATE INDEX authz_scope_nodes_parent_idx
    ON public.authz_scope_nodes (parent_scope_node_pk, status)
    WHERE parent_scope_node_pk IS NOT NULL;

CREATE TRIGGER authz_scope_nodes_immutable_trg
BEFORE UPDATE ON public.authz_scope_nodes
FOR EACH ROW EXECUTE FUNCTION public.iam_reject_column_changes(
    'scope_node_pk', 'scope_node_id', 'scope_type', 'scope_code', 'created_at'
);

CREATE TRIGGER authz_scope_nodes_version_trg
BEFORE UPDATE ON public.authz_scope_nodes
FOR EACH ROW EXECUTE FUNCTION public.iam_guard_nondecreasing_bigint('row_version');

CREATE TABLE public.authz_scope_business_lines (
    scope_business_line_pk bigint GENERATED ALWAYS AS IDENTITY,
    scope_node_pk bigint NOT NULL,
    business_line_pk bigint NOT NULL,
    created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    CONSTRAINT authz_scope_business_lines_pkey PRIMARY KEY (scope_business_line_pk),
    CONSTRAINT authz_scope_business_lines_scope_key UNIQUE (scope_node_pk),
    CONSTRAINT authz_scope_business_lines_business_key UNIQUE (business_line_pk),
    CONSTRAINT authz_scope_business_lines_scope_fk FOREIGN KEY (scope_node_pk)
        REFERENCES public.authz_scope_nodes (scope_node_pk) ON DELETE RESTRICT,
    CONSTRAINT authz_scope_business_lines_business_fk FOREIGN KEY (business_line_pk)
        REFERENCES public.app_business_lines (business_line_pk) ON DELETE RESTRICT
);

COMMENT ON TABLE public.authz_scope_business_lines IS
    'One-to-one bridge from authorization scope nodes to business-line aggregates; S2.';

CREATE TABLE public.authz_scope_tenants (
    scope_tenant_pk bigint GENERATED ALWAYS AS IDENTITY,
    scope_node_pk bigint NOT NULL,
    tenant_pk bigint NOT NULL,
    created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    CONSTRAINT authz_scope_tenants_pkey PRIMARY KEY (scope_tenant_pk),
    CONSTRAINT authz_scope_tenants_scope_key UNIQUE (scope_node_pk),
    CONSTRAINT authz_scope_tenants_tenant_key UNIQUE (tenant_pk),
    CONSTRAINT authz_scope_tenants_scope_fk FOREIGN KEY (scope_node_pk)
        REFERENCES public.authz_scope_nodes (scope_node_pk) ON DELETE RESTRICT,
    CONSTRAINT authz_scope_tenants_tenant_fk FOREIGN KEY (tenant_pk)
        REFERENCES public.org_tenants (tenant_pk) ON DELETE RESTRICT
);

COMMENT ON TABLE public.authz_scope_tenants IS
    'One-to-one bridge from authorization scope nodes to tenant aggregates; S2.';

CREATE TABLE public.authz_resources (
    resource_pk bigint GENERATED ALWAYS AS IDENTITY,
    resource_id uuid NOT NULL DEFAULT pg_catalog.gen_random_uuid(),
    scope_node_pk bigint NOT NULL,
    tenant_pk bigint,
    resource_type text COLLATE "C" NOT NULL,
    external_key_digest bytea NOT NULL,
    state text COLLATE "C" NOT NULL DEFAULT 'ACTIVE',
    resource_version bigint NOT NULL DEFAULT 1,
    created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    CONSTRAINT authz_resources_pkey PRIMARY KEY (resource_pk),
    CONSTRAINT authz_resources_id_key UNIQUE (resource_id),
    CONSTRAINT authz_resources_stable_key UNIQUE (
        scope_node_pk, resource_type, external_key_digest
    ),
    CONSTRAINT authz_resources_id_v4_ck CHECK (public.iam_uuid_is_v4(resource_id)),
    CONSTRAINT authz_resources_scope_fk FOREIGN KEY (scope_node_pk)
        REFERENCES public.authz_scope_nodes (scope_node_pk) ON DELETE RESTRICT,
    CONSTRAINT authz_resources_tenant_fk FOREIGN KEY (tenant_pk)
        REFERENCES public.org_tenants (tenant_pk) ON DELETE RESTRICT,
    CONSTRAINT authz_resources_type_ck CHECK (
        pg_catalog.length(resource_type) BETWEEN 1 AND 96
        AND resource_type ~ '^[A-Za-z][A-Za-z0-9_.:-]*$'
    ),
    CONSTRAINT authz_resources_key_digest_ck CHECK (pg_catalog.octet_length(external_key_digest) = 32),
    CONSTRAINT authz_resources_state_ck CHECK (state IN ('ACTIVE', 'SUSPENDED', 'RETIRED')),
    CONSTRAINT authz_resources_version_ck CHECK (resource_version > 0),
    CONSTRAINT authz_resources_time_ck CHECK (updated_at >= created_at)
);

COMMENT ON TABLE public.authz_resources IS
    'Typed authorization resource instances with opaque stable business keys and optional tenant ownership; S2.';

CREATE INDEX authz_resources_tenant_type_idx
    ON public.authz_resources (tenant_pk, resource_type, state)
    WHERE tenant_pk IS NOT NULL;
CREATE INDEX authz_resources_scope_idx
    ON public.authz_resources (scope_node_pk, state, resource_pk);

CREATE TRIGGER authz_resources_immutable_trg
BEFORE UPDATE ON public.authz_resources
FOR EACH ROW EXECUTE FUNCTION public.iam_reject_column_changes(
    'resource_pk', 'resource_id', 'scope_node_pk', 'tenant_pk',
    'resource_type', 'external_key_digest', 'created_at'
);

CREATE TRIGGER authz_resources_version_trg
BEFORE UPDATE ON public.authz_resources
FOR EACH ROW EXECUTE FUNCTION public.iam_guard_nondecreasing_bigint('resource_version');

CREATE TABLE public.authz_actions (
    action_pk bigint GENERATED ALWAYS AS IDENTITY,
    action_id uuid NOT NULL DEFAULT pg_catalog.gen_random_uuid(),
    action_code text COLLATE "C" NOT NULL,
    risk_level text COLLATE "C" NOT NULL DEFAULT 'LOW',
    status text COLLATE "C" NOT NULL DEFAULT 'ACTIVE',
    created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    CONSTRAINT authz_actions_pkey PRIMARY KEY (action_pk),
    CONSTRAINT authz_actions_id_key UNIQUE (action_id),
    CONSTRAINT authz_actions_code_key UNIQUE (action_code),
    CONSTRAINT authz_actions_id_v4_ck CHECK (public.iam_uuid_is_v4(action_id)),
    CONSTRAINT authz_actions_code_ck CHECK (
        pg_catalog.length(action_code) BETWEEN 1 AND 96
        AND action_code ~ '^[a-z][a-z0-9_.:-]*$'
    ),
    CONSTRAINT authz_actions_risk_ck CHECK (risk_level IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    CONSTRAINT authz_actions_status_ck CHECK (status IN ('ACTIVE', 'RETIRED'))
);

COMMENT ON TABLE public.authz_actions IS
    'Stable action catalogue; codes are never repurposed after publication; S1.';

CREATE INDEX authz_actions_status_idx ON public.authz_actions (status, risk_level, action_code);

CREATE TABLE public.authz_permissions (
    permission_pk bigint GENERATED ALWAYS AS IDENTITY,
    permission_id uuid NOT NULL DEFAULT pg_catalog.gen_random_uuid(),
    permission_code text COLLATE "C" NOT NULL,
    resource_type text COLLATE "C" NOT NULL,
    action_pk bigint NOT NULL,
    risk_level text COLLATE "C" NOT NULL,
    status text COLLATE "C" NOT NULL DEFAULT 'ACTIVE',
    created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    CONSTRAINT authz_permissions_pkey PRIMARY KEY (permission_pk),
    CONSTRAINT authz_permissions_id_key UNIQUE (permission_id),
    CONSTRAINT authz_permissions_code_key UNIQUE (permission_code),
    CONSTRAINT authz_permissions_resource_action_key UNIQUE (resource_type, action_pk),
    CONSTRAINT authz_permissions_id_v4_ck CHECK (public.iam_uuid_is_v4(permission_id)),
    CONSTRAINT authz_permissions_action_fk FOREIGN KEY (action_pk)
        REFERENCES public.authz_actions (action_pk) ON DELETE RESTRICT,
    CONSTRAINT authz_permissions_code_ck CHECK (
        pg_catalog.length(permission_code) BETWEEN 1 AND 128
        AND permission_code ~ '^[a-z][a-z0-9_.:-]*$'
    ),
    CONSTRAINT authz_permissions_resource_type_ck CHECK (
        pg_catalog.length(resource_type) BETWEEN 1 AND 96
        AND resource_type ~ '^[A-Za-z][A-Za-z0-9_.:-]*$'
    ),
    CONSTRAINT authz_permissions_risk_ck CHECK (risk_level IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    CONSTRAINT authz_permissions_status_ck CHECK (status IN ('ACTIVE', 'RETIRED'))
);

COMMENT ON TABLE public.authz_permissions IS
    'Permission catalogue relating one resource type to one governed action; S1.';

CREATE INDEX authz_permissions_action_idx ON public.authz_permissions (action_pk, status);

CREATE TABLE public.authz_roles (
    role_pk bigint GENERATED ALWAYS AS IDENTITY,
    role_id uuid NOT NULL DEFAULT pg_catalog.gen_random_uuid(),
    scope_node_pk bigint NOT NULL,
    tenant_pk bigint,
    role_code text COLLATE "C" NOT NULL,
    principal_type_limit text COLLATE "C" NOT NULL DEFAULT 'ANY',
    state text COLLATE "C" NOT NULL DEFAULT 'DRAFT',
    role_version bigint NOT NULL DEFAULT 1,
    created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    CONSTRAINT authz_roles_pkey PRIMARY KEY (role_pk),
    CONSTRAINT authz_roles_id_key UNIQUE (role_id),
    CONSTRAINT authz_roles_scope_code_key UNIQUE (scope_node_pk, role_code),
    CONSTRAINT authz_roles_id_v4_ck CHECK (public.iam_uuid_is_v4(role_id)),
    CONSTRAINT authz_roles_scope_fk FOREIGN KEY (scope_node_pk)
        REFERENCES public.authz_scope_nodes (scope_node_pk) ON DELETE RESTRICT,
    CONSTRAINT authz_roles_tenant_fk FOREIGN KEY (tenant_pk)
        REFERENCES public.org_tenants (tenant_pk) ON DELETE RESTRICT,
    CONSTRAINT authz_roles_code_ck CHECK (
        pg_catalog.length(role_code) BETWEEN 1 AND 96
        AND role_code ~ '^[A-Z][A-Z0-9_.:-]*$'
    ),
    CONSTRAINT authz_roles_principal_limit_ck CHECK (
        principal_type_limit IN ('ANY', 'USER_ONLY', 'MACHINE_ONLY')
    ),
    CONSTRAINT authz_roles_state_ck CHECK (
        state IN ('DRAFT', 'ACTIVE', 'SUSPENDED', 'RETIRED')
    ),
    CONSTRAINT authz_roles_version_ck CHECK (role_version > 0),
    CONSTRAINT authz_roles_time_ck CHECK (updated_at >= created_at)
);

COMMENT ON TABLE public.authz_roles IS
    'Scoped platform, business or tenant RBAC role with optional human/machine restriction; S2.';

CREATE INDEX authz_roles_tenant_state_idx
    ON public.authz_roles (tenant_pk, state, role_code)
    WHERE tenant_pk IS NOT NULL;

CREATE TRIGGER authz_roles_immutable_trg
BEFORE UPDATE ON public.authz_roles
FOR EACH ROW EXECUTE FUNCTION public.iam_reject_column_changes(
    'role_pk', 'role_id', 'scope_node_pk', 'tenant_pk', 'role_code', 'created_at'
);

CREATE TRIGGER authz_roles_version_trg
BEFORE UPDATE ON public.authz_roles
FOR EACH ROW EXECUTE FUNCTION public.iam_guard_nondecreasing_bigint('role_version');

CREATE TABLE public.authz_role_permissions (
    role_permission_pk bigint GENERATED ALWAYS AS IDENTITY,
    role_pk bigint NOT NULL,
    permission_pk bigint NOT NULL,
    effect text COLLATE "C" NOT NULL DEFAULT 'ALLOW',
    condition_schema_version integer,
    condition_expression jsonb,
    created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    CONSTRAINT authz_role_permissions_pkey PRIMARY KEY (role_permission_pk),
    CONSTRAINT authz_role_permissions_role_permission_key UNIQUE (role_pk, permission_pk),
    CONSTRAINT authz_role_permissions_role_fk FOREIGN KEY (role_pk)
        REFERENCES public.authz_roles (role_pk) ON DELETE RESTRICT,
    CONSTRAINT authz_role_permissions_permission_fk FOREIGN KEY (permission_pk)
        REFERENCES public.authz_permissions (permission_pk) ON DELETE RESTRICT,
    CONSTRAINT authz_role_permissions_effect_ck CHECK (effect IN ('ALLOW', 'DENY')),
    CONSTRAINT authz_role_permissions_condition_ck CHECK (
        (condition_schema_version IS NULL AND condition_expression IS NULL)
        OR (condition_schema_version > 0 AND condition_expression IS NOT NULL
            AND pg_catalog.jsonb_typeof(condition_expression) = 'object'
            AND pg_catalog.octet_length(condition_expression::text) <= 65536)
    )
);

COMMENT ON TABLE public.authz_role_permissions IS
    'Relational role-to-permission grants with explicit deny-overrides and optional bounded condition expression; S2.';

CREATE INDEX authz_role_permissions_permission_idx
    ON public.authz_role_permissions (permission_pk, role_pk);

CREATE TABLE public.authz_data_scopes (
    data_scope_pk bigint GENERATED ALWAYS AS IDENTITY,
    data_scope_id uuid NOT NULL DEFAULT pg_catalog.gen_random_uuid(),
    scope_node_pk bigint NOT NULL,
    tenant_pk bigint,
    data_scope_code text COLLATE "C" NOT NULL,
    scope_kind text COLLATE "C" NOT NULL,
    anchor_resource_pk bigint,
    expression_schema_version integer,
    expression jsonb,
    state text COLLATE "C" NOT NULL DEFAULT 'ACTIVE',
    version_no integer NOT NULL DEFAULT 1,
    created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    CONSTRAINT authz_data_scopes_pkey PRIMARY KEY (data_scope_pk),
    CONSTRAINT authz_data_scopes_id_key UNIQUE (data_scope_id),
    CONSTRAINT authz_data_scopes_code_key UNIQUE (scope_node_pk, data_scope_code, version_no),
    CONSTRAINT authz_data_scopes_id_v4_ck CHECK (public.iam_uuid_is_v4(data_scope_id)),
    CONSTRAINT authz_data_scopes_scope_fk FOREIGN KEY (scope_node_pk)
        REFERENCES public.authz_scope_nodes (scope_node_pk) ON DELETE RESTRICT,
    CONSTRAINT authz_data_scopes_tenant_fk FOREIGN KEY (tenant_pk)
        REFERENCES public.org_tenants (tenant_pk) ON DELETE RESTRICT,
    CONSTRAINT authz_data_scopes_anchor_fk FOREIGN KEY (anchor_resource_pk)
        REFERENCES public.authz_resources (resource_pk) ON DELETE RESTRICT,
    CONSTRAINT authz_data_scopes_code_ck CHECK (
        pg_catalog.length(data_scope_code) BETWEEN 1 AND 96
        AND data_scope_code ~ '^[A-Z][A-Z0-9_.:-]*$'
    ),
    CONSTRAINT authz_data_scopes_kind_ck CHECK (
        scope_kind IN ('ALL', 'ORG_SUBTREE', 'ORGANIZATION', 'RESOURCE_SET', 'SELF', 'DYNAMIC')
    ),
    CONSTRAINT authz_data_scopes_shape_ck CHECK (
        (scope_kind IN ('ALL', 'SELF') AND anchor_resource_pk IS NULL
            AND expression_schema_version IS NULL AND expression IS NULL)
        OR (scope_kind IN ('ORG_SUBTREE', 'ORGANIZATION') AND anchor_resource_pk IS NOT NULL
            AND expression_schema_version IS NULL AND expression IS NULL)
        OR (scope_kind = 'RESOURCE_SET' AND anchor_resource_pk IS NULL
            AND expression_schema_version IS NULL AND expression IS NULL)
        OR (scope_kind = 'DYNAMIC' AND anchor_resource_pk IS NULL
            AND expression_schema_version > 0 AND expression IS NOT NULL
            AND pg_catalog.jsonb_typeof(expression) = 'object'
            AND pg_catalog.octet_length(expression::text) <= 65536)
    ),
    CONSTRAINT authz_data_scopes_state_ck CHECK (state IN ('ACTIVE', 'RETIRED')),
    CONSTRAINT authz_data_scopes_version_ck CHECK (version_no > 0),
    CONSTRAINT authz_data_scopes_time_ck CHECK (updated_at >= created_at)
);

COMMENT ON TABLE public.authz_data_scopes IS
    'Versioned ALL, organization, set, self or controlled dynamic data scope; core members remain relational; S2.';

CREATE INDEX authz_data_scopes_tenant_kind_idx
    ON public.authz_data_scopes (tenant_pk, scope_kind, state)
    WHERE tenant_pk IS NOT NULL;

CREATE TABLE public.authz_data_scope_resources (
    data_scope_resource_pk bigint GENERATED ALWAYS AS IDENTITY,
    data_scope_pk bigint NOT NULL,
    resource_pk bigint NOT NULL,
    created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    CONSTRAINT authz_data_scope_resources_pkey PRIMARY KEY (data_scope_resource_pk),
    CONSTRAINT authz_data_scope_resources_member_key UNIQUE (data_scope_pk, resource_pk),
    CONSTRAINT authz_data_scope_resources_scope_fk FOREIGN KEY (data_scope_pk)
        REFERENCES public.authz_data_scopes (data_scope_pk) ON DELETE RESTRICT,
    CONSTRAINT authz_data_scope_resources_resource_fk FOREIGN KEY (resource_pk)
        REFERENCES public.authz_resources (resource_pk) ON DELETE RESTRICT
);

COMMENT ON TABLE public.authz_data_scope_resources IS
    'Relational members of RESOURCE_SET data scopes; S2.';

CREATE INDEX authz_data_scope_resources_resource_idx
    ON public.authz_data_scope_resources (resource_pk, data_scope_pk);

CREATE TABLE public.authz_role_permission_data_scopes (
    role_permission_data_scope_pk bigint GENERATED ALWAYS AS IDENTITY,
    role_permission_pk bigint NOT NULL,
    data_scope_pk bigint NOT NULL,
    created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    CONSTRAINT authz_role_permission_data_scopes_pkey PRIMARY KEY (role_permission_data_scope_pk),
    CONSTRAINT authz_role_permission_data_scopes_key UNIQUE (role_permission_pk, data_scope_pk),
    CONSTRAINT authz_role_permission_data_scopes_role_permission_fk FOREIGN KEY (role_permission_pk)
        REFERENCES public.authz_role_permissions (role_permission_pk) ON DELETE RESTRICT,
    CONSTRAINT authz_role_permission_data_scopes_data_scope_fk FOREIGN KEY (data_scope_pk)
        REFERENCES public.authz_data_scopes (data_scope_pk) ON DELETE RESTRICT
);

COMMENT ON TABLE public.authz_role_permission_data_scopes IS
    'Relational data-scope templates attached to role permissions; S2.';

CREATE INDEX authz_role_permission_data_scopes_scope_idx
    ON public.authz_role_permission_data_scopes (data_scope_pk, role_permission_pk);

CREATE TABLE public.authz_assignments (
    assignment_pk bigint GENERATED ALWAYS AS IDENTITY,
    assignment_id uuid NOT NULL DEFAULT pg_catalog.gen_random_uuid(),
    principal_pk bigint NOT NULL,
    role_pk bigint NOT NULL,
    scope_node_pk bigint NOT NULL,
    tenant_pk bigint,
    state text COLLATE "C" NOT NULL DEFAULT 'PENDING',
    grant_type text COLLATE "C" NOT NULL DEFAULT 'DIRECT',
    grantor_principal_pk bigint NOT NULL,
    reason_code text COLLATE "C" NOT NULL,
    valid_from timestamptz NOT NULL,
    valid_until timestamptz,
    revoked_at timestamptz,
    row_version bigint NOT NULL DEFAULT 1,
    created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    CONSTRAINT authz_assignments_pkey PRIMARY KEY (assignment_pk),
    CONSTRAINT authz_assignments_id_key UNIQUE (assignment_id),
    CONSTRAINT authz_assignments_id_v4_ck CHECK (public.iam_uuid_is_v4(assignment_id)),
    CONSTRAINT authz_assignments_principal_fk FOREIGN KEY (principal_pk)
        REFERENCES public.iam_principals (principal_pk) ON DELETE RESTRICT,
    CONSTRAINT authz_assignments_role_fk FOREIGN KEY (role_pk)
        REFERENCES public.authz_roles (role_pk) ON DELETE RESTRICT,
    CONSTRAINT authz_assignments_scope_fk FOREIGN KEY (scope_node_pk)
        REFERENCES public.authz_scope_nodes (scope_node_pk) ON DELETE RESTRICT,
    CONSTRAINT authz_assignments_tenant_fk FOREIGN KEY (tenant_pk)
        REFERENCES public.org_tenants (tenant_pk) ON DELETE RESTRICT,
    CONSTRAINT authz_assignments_grantor_fk FOREIGN KEY (grantor_principal_pk)
        REFERENCES public.iam_principals (principal_pk) ON DELETE RESTRICT,
    CONSTRAINT authz_assignments_no_self_grant_ck CHECK (grantor_principal_pk <> principal_pk OR grant_type <> 'DELEGATED'),
    CONSTRAINT authz_assignments_state_ck CHECK (
        state IN ('PENDING', 'ACTIVE', 'SUSPENDED', 'REVOKED', 'EXPIRED')
    ),
    CONSTRAINT authz_assignments_grant_type_ck CHECK (
        grant_type IN ('DIRECT', 'GROUP', 'FEDERATED', 'DELEGATED', 'JUST_IN_TIME')
    ),
    CONSTRAINT authz_assignments_reason_ck CHECK (
        pg_catalog.length(reason_code) BETWEEN 1 AND 64
        AND reason_code ~ '^[A-Z][A-Z0-9_]*$'
    ),
    CONSTRAINT authz_assignments_temporary_ck CHECK (
        grant_type <> 'JUST_IN_TIME' OR valid_until IS NOT NULL
    ),
    CONSTRAINT authz_assignments_revoked_ck CHECK (
        (state = 'REVOKED') = (revoked_at IS NOT NULL)
    ),
    CONSTRAINT authz_assignments_version_ck CHECK (row_version > 0),
    CONSTRAINT authz_assignments_time_ck CHECK (
        updated_at >= created_at AND valid_from >= created_at
        AND (valid_until IS NULL OR valid_until > valid_from)
        AND (revoked_at IS NULL OR revoked_at >= valid_from)
    )
);

COMMENT ON TABLE public.authz_assignments IS
    'Scoped principal-to-role assignment with grant provenance, validity and explicit lifecycle; S3.';

CREATE UNIQUE INDEX authz_assignments_active_uidx
    ON public.authz_assignments (principal_pk, role_pk, scope_node_pk)
    WHERE state IN ('PENDING', 'ACTIVE', 'SUSPENDED');
CREATE INDEX authz_assignments_principal_active_idx
    ON public.authz_assignments (principal_pk, valid_until, assignment_pk)
    WHERE state = 'ACTIVE';
CREATE INDEX authz_assignments_role_state_idx
    ON public.authz_assignments (role_pk, state, assignment_pk);

CREATE TRIGGER authz_assignments_immutable_trg
BEFORE UPDATE ON public.authz_assignments
FOR EACH ROW EXECUTE FUNCTION public.iam_reject_column_changes(
    'assignment_pk', 'assignment_id', 'principal_pk', 'role_pk',
    'scope_node_pk', 'tenant_pk', 'grant_type', 'grantor_principal_pk',
    'valid_from', 'created_at'
);

CREATE TRIGGER authz_assignments_version_trg
BEFORE UPDATE ON public.authz_assignments
FOR EACH ROW EXECUTE FUNCTION public.iam_guard_nondecreasing_bigint('row_version');

CREATE TABLE public.authz_assignment_data_scopes (
    assignment_data_scope_pk bigint GENERATED ALWAYS AS IDENTITY,
    assignment_pk bigint NOT NULL,
    role_permission_pk bigint NOT NULL,
    data_scope_pk bigint NOT NULL,
    effect text COLLATE "C" NOT NULL DEFAULT 'ALLOW',
    created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    CONSTRAINT authz_assignment_data_scopes_pkey PRIMARY KEY (assignment_data_scope_pk),
    CONSTRAINT authz_assignment_data_scopes_key UNIQUE (
        assignment_pk, role_permission_pk, data_scope_pk
    ),
    CONSTRAINT authz_assignment_data_scopes_assignment_fk FOREIGN KEY (assignment_pk)
        REFERENCES public.authz_assignments (assignment_pk) ON DELETE RESTRICT,
    CONSTRAINT authz_assignment_data_scopes_role_permission_fk FOREIGN KEY (role_permission_pk)
        REFERENCES public.authz_role_permissions (role_permission_pk) ON DELETE RESTRICT,
    CONSTRAINT authz_assignment_data_scopes_scope_fk FOREIGN KEY (data_scope_pk)
        REFERENCES public.authz_data_scopes (data_scope_pk) ON DELETE RESTRICT,
    CONSTRAINT authz_assignment_data_scopes_effect_ck CHECK (effect IN ('ALLOW', 'DENY'))
);

COMMENT ON TABLE public.authz_assignment_data_scopes IS
    'Assignment-specific relational data-scope narrowing or explicit denial; S3.';

CREATE INDEX authz_assignment_data_scopes_scope_idx
    ON public.authz_assignment_data_scopes (data_scope_pk, assignment_pk);

CREATE TABLE public.authz_relation_tuples (
    relation_tuple_pk bigint GENERATED ALWAYS AS IDENTITY,
    relation_tuple_id uuid NOT NULL DEFAULT pg_catalog.gen_random_uuid(),
    tenant_pk bigint,
    scope_node_pk bigint NOT NULL,
    subject_principal_pk bigint NOT NULL,
    relation_code text COLLATE "C" NOT NULL,
    object_resource_pk bigint NOT NULL,
    source_type text COLLATE "C" NOT NULL,
    valid_from timestamptz NOT NULL,
    valid_until timestamptz,
    revoked_at timestamptz,
    tuple_version bigint NOT NULL DEFAULT 1,
    created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    CONSTRAINT authz_relation_tuples_pkey PRIMARY KEY (relation_tuple_pk),
    CONSTRAINT authz_relation_tuples_id_key UNIQUE (relation_tuple_id),
    CONSTRAINT authz_relation_tuples_id_v4_ck CHECK (public.iam_uuid_is_v4(relation_tuple_id)),
    CONSTRAINT authz_relation_tuples_tenant_fk FOREIGN KEY (tenant_pk)
        REFERENCES public.org_tenants (tenant_pk) ON DELETE RESTRICT,
    CONSTRAINT authz_relation_tuples_scope_fk FOREIGN KEY (scope_node_pk)
        REFERENCES public.authz_scope_nodes (scope_node_pk) ON DELETE RESTRICT,
    CONSTRAINT authz_relation_tuples_subject_fk FOREIGN KEY (subject_principal_pk)
        REFERENCES public.iam_principals (principal_pk) ON DELETE RESTRICT,
    CONSTRAINT authz_relation_tuples_object_fk FOREIGN KEY (object_resource_pk)
        REFERENCES public.authz_resources (resource_pk) ON DELETE RESTRICT,
    CONSTRAINT authz_relation_tuples_relation_ck CHECK (
        pg_catalog.length(relation_code) BETWEEN 1 AND 64
        AND relation_code ~ '^[a-z][a-z0-9_.:-]*$'
    ),
    CONSTRAINT authz_relation_tuples_source_ck CHECK (
        source_type IN ('DIRECT', 'FEDERATED', 'SYSTEM', 'MIGRATION')
    ),
    CONSTRAINT authz_relation_tuples_version_ck CHECK (tuple_version > 0),
    CONSTRAINT authz_relation_tuples_time_ck CHECK (
        valid_from >= created_at
        AND (valid_until IS NULL OR valid_until > valid_from)
        AND (revoked_at IS NULL OR revoked_at >= valid_from)
    )
);

COMMENT ON TABLE public.authz_relation_tuples IS
    'Principal-relation-resource tuples with typed FKs, scope, validity and revocation history; S2.';

CREATE UNIQUE INDEX authz_relation_tuples_active_uidx
    ON public.authz_relation_tuples (
        scope_node_pk, subject_principal_pk, relation_code, object_resource_pk
    )
    WHERE revoked_at IS NULL;
CREATE INDEX authz_relation_tuples_subject_idx
    ON public.authz_relation_tuples (subject_principal_pk, relation_code, valid_until)
    WHERE revoked_at IS NULL;
CREATE INDEX authz_relation_tuples_object_idx
    ON public.authz_relation_tuples (object_resource_pk, relation_code, valid_until)
    WHERE revoked_at IS NULL;

CREATE TRIGGER authz_relation_tuples_immutable_trg
BEFORE UPDATE ON public.authz_relation_tuples
FOR EACH ROW EXECUTE FUNCTION public.iam_reject_column_changes(
    'relation_tuple_pk', 'relation_tuple_id', 'tenant_pk', 'scope_node_pk',
    'subject_principal_pk', 'relation_code', 'object_resource_pk',
    'source_type', 'valid_from', 'created_at'
);

CREATE TRIGGER authz_relation_tuples_version_trg
BEFORE UPDATE ON public.authz_relation_tuples
FOR EACH ROW EXECUTE FUNCTION public.iam_guard_nondecreasing_bigint('tuple_version');

CREATE TABLE public.authz_policy_sets (
    policy_set_pk bigint GENERATED ALWAYS AS IDENTITY,
    policy_set_id uuid NOT NULL DEFAULT pg_catalog.gen_random_uuid(),
    policy_code text COLLATE "C" NOT NULL,
    scope_node_pk bigint NOT NULL,
    tenant_pk bigint,
    policy_kind text COLLATE "C" NOT NULL,
    state text COLLATE "C" NOT NULL DEFAULT 'DRAFT',
    row_version bigint NOT NULL DEFAULT 1,
    created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    CONSTRAINT authz_policy_sets_pkey PRIMARY KEY (policy_set_pk),
    CONSTRAINT authz_policy_sets_id_key UNIQUE (policy_set_id),
    CONSTRAINT authz_policy_sets_code_key UNIQUE (scope_node_pk, policy_code),
    CONSTRAINT authz_policy_sets_id_v4_ck CHECK (public.iam_uuid_is_v4(policy_set_id)),
    CONSTRAINT authz_policy_sets_scope_fk FOREIGN KEY (scope_node_pk)
        REFERENCES public.authz_scope_nodes (scope_node_pk) ON DELETE RESTRICT,
    CONSTRAINT authz_policy_sets_tenant_fk FOREIGN KEY (tenant_pk)
        REFERENCES public.org_tenants (tenant_pk) ON DELETE RESTRICT,
    CONSTRAINT authz_policy_sets_code_ck CHECK (
        pg_catalog.length(policy_code) BETWEEN 1 AND 128
        AND policy_code ~ '^[A-Za-z][A-Za-z0-9_.:-]*$'
    ),
    CONSTRAINT authz_policy_sets_kind_ck CHECK (
        policy_kind IN ('RBAC', 'ABAC', 'RELATION', 'COMPOSITE')
    ),
    CONSTRAINT authz_policy_sets_state_ck CHECK (
        state IN ('DRAFT', 'ACTIVE', 'SUSPENDED', 'RETIRED')
    ),
    CONSTRAINT authz_policy_sets_version_ck CHECK (row_version > 0),
    CONSTRAINT authz_policy_sets_time_ck CHECK (updated_at >= created_at)
);

COMMENT ON TABLE public.authz_policy_sets IS
    'Policy identity and scope root; executable contents are immutable policy versions; S2.';

CREATE INDEX authz_policy_sets_scope_state_idx
    ON public.authz_policy_sets (scope_node_pk, state, policy_code);

CREATE TABLE public.authz_policy_versions (
    policy_version_pk bigint GENERATED ALWAYS AS IDENTITY,
    policy_version_id uuid NOT NULL DEFAULT pg_catalog.gen_random_uuid(),
    policy_set_pk bigint NOT NULL,
    version_no bigint NOT NULL,
    language text COLLATE "C" NOT NULL,
    ast_schema_version integer NOT NULL,
    policy_ast jsonb NOT NULL,
    input_schema_version integer NOT NULL,
    input_schema jsonb NOT NULL,
    obligation_schema_version integer NOT NULL,
    obligation_schema jsonb NOT NULL,
    content_hash bytea NOT NULL,
    compiled_artifact_hash bytea,
    state text COLLATE "C" NOT NULL DEFAULT 'DRAFT',
    validated_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    CONSTRAINT authz_policy_versions_pkey PRIMARY KEY (policy_version_pk),
    CONSTRAINT authz_policy_versions_id_key UNIQUE (policy_version_id),
    CONSTRAINT authz_policy_versions_number_key UNIQUE (policy_set_pk, version_no),
    CONSTRAINT authz_policy_versions_content_hash_key UNIQUE (content_hash),
    CONSTRAINT authz_policy_versions_id_v4_ck CHECK (public.iam_uuid_is_v4(policy_version_id)),
    CONSTRAINT authz_policy_versions_set_fk FOREIGN KEY (policy_set_pk)
        REFERENCES public.authz_policy_sets (policy_set_pk) ON DELETE RESTRICT,
    CONSTRAINT authz_policy_versions_number_ck CHECK (version_no > 0),
    CONSTRAINT authz_policy_versions_language_ck CHECK (
        language IN ('CEL', 'REGO', 'CEDAR', 'INTERNAL_AST')
    ),
    CONSTRAINT authz_policy_versions_ast_ck CHECK (
        ast_schema_version > 0 AND pg_catalog.jsonb_typeof(policy_ast) = 'object'
        AND pg_catalog.octet_length(policy_ast::text) <= 1048576
    ),
    CONSTRAINT authz_policy_versions_input_schema_ck CHECK (
        input_schema_version > 0 AND pg_catalog.jsonb_typeof(input_schema) = 'object'
        AND pg_catalog.octet_length(input_schema::text) <= 262144
    ),
    CONSTRAINT authz_policy_versions_obligation_schema_ck CHECK (
        obligation_schema_version > 0 AND pg_catalog.jsonb_typeof(obligation_schema) = 'object'
        AND pg_catalog.octet_length(obligation_schema::text) <= 262144
    ),
    CONSTRAINT authz_policy_versions_content_hash_ck CHECK (pg_catalog.octet_length(content_hash) = 32),
    CONSTRAINT authz_policy_versions_artifact_hash_ck CHECK (
        compiled_artifact_hash IS NULL OR pg_catalog.octet_length(compiled_artifact_hash) = 32
    ),
    CONSTRAINT authz_policy_versions_state_ck CHECK (
        state IN ('DRAFT', 'VALIDATED', 'REJECTED', 'RETIRED')
    ),
    CONSTRAINT authz_policy_versions_validated_ck CHECK (
        (state = 'DRAFT' AND validated_at IS NULL)
        OR (state <> 'DRAFT' AND validated_at IS NOT NULL)
    )
);

COMMENT ON TABLE public.authz_policy_versions IS
    'Immutable policy AST, input schema, obligation schema and canonical content hash; JSON is bounded and versioned; S2.';

CREATE INDEX authz_policy_versions_set_state_idx
    ON public.authz_policy_versions (policy_set_pk, state, version_no DESC);

CREATE TRIGGER authz_policy_versions_immutable_trg
BEFORE UPDATE ON public.authz_policy_versions
FOR EACH ROW
WHEN (OLD.state <> 'DRAFT')
EXECUTE FUNCTION public.iam_reject_column_changes(
    'policy_version_pk', 'policy_version_id', 'policy_set_pk', 'version_no',
    'language', 'ast_schema_version', 'policy_ast', 'input_schema_version',
    'input_schema', 'obligation_schema_version', 'obligation_schema',
    'content_hash', 'compiled_artifact_hash', 'validated_at', 'created_at'
);

CREATE TABLE public.authz_policy_releases (
    policy_release_pk bigint GENERATED ALWAYS AS IDENTITY,
    policy_release_id uuid NOT NULL DEFAULT pg_catalog.gen_random_uuid(),
    policy_version_pk bigint NOT NULL,
    scope_node_pk bigint NOT NULL,
    tenant_pk bigint,
    environment text COLLATE "C" NOT NULL,
    release_no bigint NOT NULL,
    state text COLLATE "C" NOT NULL DEFAULT 'STAGED',
    approval_reference text COLLATE "C" NOT NULL,
    rollback_of_release_pk bigint,
    staged_at timestamptz NOT NULL,
    activated_at timestamptz,
    deactivated_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    CONSTRAINT authz_policy_releases_pkey PRIMARY KEY (policy_release_pk),
    CONSTRAINT authz_policy_releases_id_key UNIQUE (policy_release_id),
    CONSTRAINT authz_policy_releases_number_key UNIQUE (scope_node_pk, environment, release_no),
    CONSTRAINT authz_policy_releases_id_v4_ck CHECK (public.iam_uuid_is_v4(policy_release_id)),
    CONSTRAINT authz_policy_releases_version_fk FOREIGN KEY (policy_version_pk)
        REFERENCES public.authz_policy_versions (policy_version_pk) ON DELETE RESTRICT,
    CONSTRAINT authz_policy_releases_scope_fk FOREIGN KEY (scope_node_pk)
        REFERENCES public.authz_scope_nodes (scope_node_pk) ON DELETE RESTRICT,
    CONSTRAINT authz_policy_releases_tenant_fk FOREIGN KEY (tenant_pk)
        REFERENCES public.org_tenants (tenant_pk) ON DELETE RESTRICT,
    CONSTRAINT authz_policy_releases_rollback_fk FOREIGN KEY (rollback_of_release_pk)
        REFERENCES public.authz_policy_releases (policy_release_pk) ON DELETE RESTRICT,
    CONSTRAINT authz_policy_releases_no_self_ck CHECK (
        rollback_of_release_pk IS NULL OR rollback_of_release_pk <> policy_release_pk
    ),
    CONSTRAINT authz_policy_releases_environment_ck CHECK (
        environment IN ('DEVELOPMENT', 'TEST', 'STAGING', 'PRODUCTION')
    ),
    CONSTRAINT authz_policy_releases_number_ck CHECK (release_no > 0),
    CONSTRAINT authz_policy_releases_state_ck CHECK (
        state IN ('STAGED', 'CANARY', 'ACTIVE', 'DEPRECATED', 'REVOKED', 'FAILED')
    ),
    CONSTRAINT authz_policy_releases_approval_ck CHECK (
        pg_catalog.length(approval_reference) BETWEEN 1 AND 512
    ),
    CONSTRAINT authz_policy_releases_activation_ck CHECK (
        (state = 'STAGED' AND activated_at IS NULL AND deactivated_at IS NULL)
        OR (state IN ('CANARY', 'ACTIVE') AND activated_at IS NOT NULL AND deactivated_at IS NULL)
        OR (state IN ('DEPRECATED', 'REVOKED', 'FAILED') AND deactivated_at IS NOT NULL)
    ),
    CONSTRAINT authz_policy_releases_time_ck CHECK (
        staged_at >= created_at
        AND (activated_at IS NULL OR activated_at >= staged_at)
        AND (deactivated_at IS NULL OR deactivated_at >= staged_at)
    )
);

COMMENT ON TABLE public.authz_policy_releases IS
    'Approved immutable policy-version release by scope and environment; rollback creates a new release; S2.';

CREATE UNIQUE INDEX authz_policy_releases_active_uidx
    ON public.authz_policy_releases (scope_node_pk, environment)
    WHERE state = 'ACTIVE';
CREATE INDEX authz_policy_releases_version_idx
    ON public.authz_policy_releases (policy_version_pk, state);

CREATE TABLE public.authz_attribute_sources (
    attribute_source_pk bigint GENERATED ALWAYS AS IDENTITY,
    attribute_source_id uuid NOT NULL DEFAULT pg_catalog.gen_random_uuid(),
    source_code text COLLATE "C" NOT NULL,
    scope_node_pk bigint NOT NULL,
    source_type text COLLATE "C" NOT NULL,
    trust_level text COLLATE "C" NOT NULL,
    failure_mode text COLLATE "C" NOT NULL,
    max_age_seconds integer NOT NULL,
    schema_version integer NOT NULL,
    attribute_schema jsonb NOT NULL,
    schema_hash bytea NOT NULL,
    state text COLLATE "C" NOT NULL DEFAULT 'ACTIVE',
    row_version bigint NOT NULL DEFAULT 1,
    created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    CONSTRAINT authz_attribute_sources_pkey PRIMARY KEY (attribute_source_pk),
    CONSTRAINT authz_attribute_sources_id_key UNIQUE (attribute_source_id),
    CONSTRAINT authz_attribute_sources_code_key UNIQUE (scope_node_pk, source_code),
    CONSTRAINT authz_attribute_sources_id_v4_ck CHECK (public.iam_uuid_is_v4(attribute_source_id)),
    CONSTRAINT authz_attribute_sources_scope_fk FOREIGN KEY (scope_node_pk)
        REFERENCES public.authz_scope_nodes (scope_node_pk) ON DELETE RESTRICT,
    CONSTRAINT authz_attribute_sources_code_ck CHECK (
        pg_catalog.length(source_code) BETWEEN 1 AND 96
        AND source_code ~ '^[A-Z][A-Z0-9_.:-]*$'
    ),
    CONSTRAINT authz_attribute_sources_type_ck CHECK (
        source_type IN ('IDENTITY', 'TENANT', 'RESOURCE', 'RISK', 'ASSURANCE', 'EXTERNAL_PIP')
    ),
    CONSTRAINT authz_attribute_sources_trust_ck CHECK (
        trust_level IN ('AUTHORITATIVE', 'VERIFIED', 'ADVISORY', 'UNTRUSTED')
    ),
    CONSTRAINT authz_attribute_sources_failure_ck CHECK (
        failure_mode IN ('DENY', 'NOT_APPLICABLE', 'USE_BOUNDED_CACHE')
    ),
    CONSTRAINT authz_attribute_sources_age_ck CHECK (max_age_seconds BETWEEN 0 AND 86400),
    CONSTRAINT authz_attribute_sources_schema_ck CHECK (
        schema_version > 0 AND pg_catalog.jsonb_typeof(attribute_schema) = 'object'
        AND pg_catalog.octet_length(attribute_schema::text) <= 262144
    ),
    CONSTRAINT authz_attribute_sources_hash_ck CHECK (pg_catalog.octet_length(schema_hash) = 32),
    CONSTRAINT authz_attribute_sources_state_ck CHECK (state IN ('ACTIVE', 'SUSPENDED', 'RETIRED')),
    CONSTRAINT authz_attribute_sources_version_ck CHECK (row_version > 0),
    CONSTRAINT authz_attribute_sources_time_ck CHECK (updated_at >= created_at)
);

COMMENT ON TABLE public.authz_attribute_sources IS
    'PIP source catalogue with trust, freshness, failure semantics and versioned attribute schema; S2.';

CREATE INDEX authz_attribute_sources_scope_state_idx
    ON public.authz_attribute_sources (scope_node_pk, state, source_type);

CREATE TABLE public.authz_decisions (
    decision_pk bigint GENERATED ALWAYS AS IDENTITY,
    decision_id uuid NOT NULL DEFAULT pg_catalog.gen_random_uuid(),
    policy_release_pk bigint NOT NULL,
    subject_principal_pk bigint NOT NULL,
    actor_principal_pk bigint,
    resource_pk bigint NOT NULL,
    action_pk bigint NOT NULL,
    tenant_pk bigint,
    environment text COLLATE "C" NOT NULL,
    risk_level text COLLATE "C" NOT NULL,
    assurance_level smallint NOT NULL,
    resource_version bigint NOT NULL,
    user_security_epoch bigint,
    tenant_security_epoch bigint,
    input_digest bytea NOT NULL,
    attribute_snapshot_digest bytea NOT NULL,
    decision_effect text COLLATE "C" NOT NULL,
    reason_code text COLLATE "C" NOT NULL,
    explanation_schema_version integer NOT NULL,
    explanation jsonb NOT NULL,
    decided_at timestamptz NOT NULL,
    valid_until timestamptz NOT NULL,
    trace_id uuid,
    created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    CONSTRAINT authz_decisions_pkey PRIMARY KEY (decision_pk),
    CONSTRAINT authz_decisions_id_key UNIQUE (decision_id),
    CONSTRAINT authz_decisions_id_v4_ck CHECK (public.iam_uuid_is_v4(decision_id)),
    CONSTRAINT authz_decisions_release_fk FOREIGN KEY (policy_release_pk)
        REFERENCES public.authz_policy_releases (policy_release_pk) ON DELETE RESTRICT,
    CONSTRAINT authz_decisions_subject_fk FOREIGN KEY (subject_principal_pk)
        REFERENCES public.iam_principals (principal_pk) ON DELETE RESTRICT,
    CONSTRAINT authz_decisions_actor_fk FOREIGN KEY (actor_principal_pk)
        REFERENCES public.iam_principals (principal_pk) ON DELETE RESTRICT,
    CONSTRAINT authz_decisions_resource_fk FOREIGN KEY (resource_pk)
        REFERENCES public.authz_resources (resource_pk) ON DELETE RESTRICT,
    CONSTRAINT authz_decisions_action_fk FOREIGN KEY (action_pk)
        REFERENCES public.authz_actions (action_pk) ON DELETE RESTRICT,
    CONSTRAINT authz_decisions_tenant_fk FOREIGN KEY (tenant_pk)
        REFERENCES public.org_tenants (tenant_pk) ON DELETE RESTRICT,
    CONSTRAINT authz_decisions_environment_ck CHECK (
        environment IN ('DEVELOPMENT', 'TEST', 'STAGING', 'PRODUCTION')
    ),
    CONSTRAINT authz_decisions_risk_ck CHECK (
        risk_level IN ('UNKNOWN', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL')
    ),
    CONSTRAINT authz_decisions_assurance_ck CHECK (assurance_level BETWEEN 0 AND 3),
    CONSTRAINT authz_decisions_versions_ck CHECK (
        resource_version > 0
        AND (user_security_epoch IS NULL OR user_security_epoch > 0)
        AND (tenant_security_epoch IS NULL OR tenant_security_epoch > 0)
    ),
    CONSTRAINT authz_decisions_input_digest_ck CHECK (pg_catalog.octet_length(input_digest) = 32),
    CONSTRAINT authz_decisions_attribute_digest_ck CHECK (pg_catalog.octet_length(attribute_snapshot_digest) = 32),
    CONSTRAINT authz_decisions_effect_ck CHECK (
        decision_effect IN ('ALLOW', 'DENY', 'INDETERMINATE', 'NOT_APPLICABLE')
    ),
    CONSTRAINT authz_decisions_reason_ck CHECK (
        pg_catalog.length(reason_code) BETWEEN 1 AND 96
        AND reason_code ~ '^[A-Z][A-Z0-9_]*$'
    ),
    CONSTRAINT authz_decisions_explanation_ck CHECK (
        explanation_schema_version > 0 AND pg_catalog.jsonb_typeof(explanation) = 'object'
        AND pg_catalog.octet_length(explanation::text) <= 131072
    ),
    CONSTRAINT authz_decisions_time_ck CHECK (
        decided_at <= created_at AND valid_until > decided_at
    ),
    CONSTRAINT authz_decisions_trace_v4_ck CHECK (
        trace_id IS NULL OR public.iam_uuid_is_v4(trace_id)
    )
);

COMMENT ON TABLE public.authz_decisions IS
    'Append-only PDP evidence containing normalized input digests, versions, effect, explanation and cache validity; S3.';

CREATE INDEX authz_decisions_subject_time_idx
    ON public.authz_decisions (subject_principal_pk, decided_at DESC);
CREATE INDEX authz_decisions_resource_time_idx
    ON public.authz_decisions (resource_pk, decided_at DESC);
CREATE INDEX authz_decisions_trace_idx
    ON public.authz_decisions (trace_id)
    WHERE trace_id IS NOT NULL;

CREATE TRIGGER authz_decisions_append_only_trg
BEFORE UPDATE OR DELETE ON public.authz_decisions
FOR EACH ROW EXECUTE FUNCTION public.iam_reject_row_mutation();

CREATE TABLE public.authz_decision_obligations (
    decision_obligation_pk bigint GENERATED ALWAYS AS IDENTITY,
    decision_pk bigint NOT NULL,
    obligation_type text COLLATE "C" NOT NULL,
    schema_version integer NOT NULL,
    parameters jsonb NOT NULL,
    mandatory boolean NOT NULL DEFAULT true,
    execution_point text COLLATE "C" NOT NULL,
    execution_state text COLLATE "C" NOT NULL DEFAULT 'PENDING',
    result_digest bytea,
    executed_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    CONSTRAINT authz_decision_obligations_pkey PRIMARY KEY (decision_obligation_pk),
    CONSTRAINT authz_decision_obligations_type_key UNIQUE (
        decision_pk, obligation_type, execution_point
    ),
    CONSTRAINT authz_decision_obligations_decision_fk FOREIGN KEY (decision_pk)
        REFERENCES public.authz_decisions (decision_pk) ON DELETE RESTRICT,
    CONSTRAINT authz_decision_obligations_type_ck CHECK (
        obligation_type IN ('STEP_UP', 'MASK_FIELDS', 'ROW_FILTER', 'WATERMARK', 'AUDIT', 'RATE_LIMIT', 'NOTIFY')
    ),
    CONSTRAINT authz_decision_obligations_schema_ck CHECK (
        schema_version > 0 AND pg_catalog.jsonb_typeof(parameters) = 'object'
        AND pg_catalog.octet_length(parameters::text) <= 65536
    ),
    CONSTRAINT authz_decision_obligations_point_ck CHECK (
        execution_point IN ('PRE_REQUEST', 'PRE_COMMIT', 'POST_COMMIT', 'RESPONSE')
    ),
    CONSTRAINT authz_decision_obligations_state_ck CHECK (
        execution_state IN ('PENDING', 'EXECUTED', 'FAILED', 'NOT_SUPPORTED', 'SKIPPED')
    ),
    CONSTRAINT authz_decision_obligations_result_ck CHECK (
        result_digest IS NULL OR pg_catalog.octet_length(result_digest) = 32
    ),
    CONSTRAINT authz_decision_obligations_execution_ck CHECK (
        (execution_state = 'PENDING' AND executed_at IS NULL)
        OR (execution_state <> 'PENDING' AND executed_at IS NOT NULL)
    ),
    CONSTRAINT authz_decision_obligations_time_ck CHECK (
        executed_at IS NULL OR executed_at >= created_at
    )
);

COMMENT ON TABLE public.authz_decision_obligations IS
    'Versioned PDP obligations and PEP execution result; mandatory unknown or failed obligations require fail-closed behavior; S3.';

CREATE INDEX authz_decision_obligations_state_idx
    ON public.authz_decision_obligations (decision_pk, execution_state);

COMMIT;
