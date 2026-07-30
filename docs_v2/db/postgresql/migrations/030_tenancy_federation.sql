-- Business, tenant, organization, membership, federation, and directory objects.

BEGIN;

CREATE TABLE public.app_business_lines (
    business_line_pk bigint GENERATED ALWAYS AS IDENTITY,
    business_line_id uuid NOT NULL DEFAULT pg_catalog.gen_random_uuid(),
    code text COLLATE "C" NOT NULL,
    display_name text NOT NULL,
    data_domain text COLLATE "C" NOT NULL,
    status text COLLATE "C" NOT NULL DEFAULT 'ACTIVE',
    owner_principal_pk bigint NOT NULL,
    row_version bigint NOT NULL DEFAULT 1,
    created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    CONSTRAINT app_business_lines_pkey PRIMARY KEY (business_line_pk),
    CONSTRAINT app_business_lines_id_key UNIQUE (business_line_id),
    CONSTRAINT app_business_lines_code_key UNIQUE (code),
    CONSTRAINT app_business_lines_id_v4_ck CHECK (public.iam_uuid_is_v4(business_line_id)),
    CONSTRAINT app_business_lines_code_ck
        CHECK (pg_catalog.length(code) BETWEEN 2 AND 64 AND code ~ '^[a-z][a-z0-9_-]*$'),
    CONSTRAINT app_business_lines_name_ck CHECK (pg_catalog.length(display_name) BETWEEN 1 AND 200),
    CONSTRAINT app_business_lines_domain_ck
        CHECK (pg_catalog.length(data_domain) BETWEEN 1 AND 128),
    CONSTRAINT app_business_lines_status_ck CHECK (status IN ('ACTIVE', 'SUSPENDED', 'RETIRED')),
    CONSTRAINT app_business_lines_owner_fk FOREIGN KEY (owner_principal_pk)
        REFERENCES public.iam_principals (principal_pk) ON DELETE RESTRICT,
    CONSTRAINT app_business_lines_row_version_ck CHECK (row_version > 0),
    CONSTRAINT app_business_lines_time_ck CHECK (updated_at >= created_at)
);

COMMENT ON TABLE public.app_business_lines IS
    'Permanent business-line catalog and administration boundary; codes are never reused; S1.';
CREATE INDEX app_business_lines_status_idx ON public.app_business_lines (status, business_line_pk);
CREATE INDEX app_business_lines_owner_idx ON public.app_business_lines (owner_principal_pk);

CREATE TABLE public.app_applications (
    application_pk bigint GENERATED ALWAYS AS IDENTITY,
    application_id uuid NOT NULL DEFAULT pg_catalog.gen_random_uuid(),
    business_line_pk bigint NOT NULL,
    code text COLLATE "C" NOT NULL,
    display_name text NOT NULL,
    application_type text COLLATE "C" NOT NULL,
    environment text COLLATE "C" NOT NULL,
    status text COLLATE "C" NOT NULL DEFAULT 'DRAFT',
    owner_principal_pk bigint NOT NULL,
    row_version bigint NOT NULL DEFAULT 1,
    created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    CONSTRAINT app_applications_pkey PRIMARY KEY (application_pk),
    CONSTRAINT app_applications_id_key UNIQUE (application_id),
    CONSTRAINT app_applications_catalog_key UNIQUE (business_line_pk, code, environment),
    CONSTRAINT app_applications_id_v4_ck CHECK (public.iam_uuid_is_v4(application_id)),
    CONSTRAINT app_applications_business_line_fk FOREIGN KEY (business_line_pk)
        REFERENCES public.app_business_lines (business_line_pk) ON DELETE RESTRICT,
    CONSTRAINT app_applications_owner_fk FOREIGN KEY (owner_principal_pk)
        REFERENCES public.iam_principals (principal_pk) ON DELETE RESTRICT,
    CONSTRAINT app_applications_code_ck
        CHECK (pg_catalog.length(code) BETWEEN 2 AND 64 AND code ~ '^[a-z][a-z0-9_-]*$'),
    CONSTRAINT app_applications_name_ck CHECK (pg_catalog.length(display_name) BETWEEN 1 AND 200),
    CONSTRAINT app_applications_type_ck
        CHECK (application_type IN ('WEB', 'SPA', 'NATIVE', 'MINI_PROGRAM', 'SERVICE', 'DEVICE')),
    CONSTRAINT app_applications_environment_ck
        CHECK (environment IN ('DEVELOPMENT', 'TEST', 'STAGING', 'PRODUCTION')),
    CONSTRAINT app_applications_status_ck
        CHECK (status IN ('DRAFT', 'ACTIVE', 'SUSPENDED', 'RETIRED')),
    CONSTRAINT app_applications_row_version_ck CHECK (row_version > 0),
    CONSTRAINT app_applications_time_ck CHECK (updated_at >= created_at)
);

COMMENT ON TABLE public.app_applications IS
    'User-visible application catalog beneath a business line; OAuth Clients are registered in migration 060; S1.';
CREATE INDEX app_applications_business_status_idx
    ON public.app_applications (business_line_pk, status);
CREATE INDEX app_applications_owner_idx ON public.app_applications (owner_principal_pk);

CREATE TABLE public.org_tenants (
    tenant_pk bigint GENERATED ALWAYS AS IDENTITY,
    tenant_id uuid NOT NULL DEFAULT pg_catalog.gen_random_uuid(),
    business_line_pk bigint NOT NULL,
    code text COLLATE "C" NOT NULL,
    display_name text NOT NULL,
    status text COLLATE "C" NOT NULL DEFAULT 'PROVISIONING',
    security_epoch bigint NOT NULL DEFAULT 1,
    owner_principal_pk bigint NOT NULL,
    closing_started_at timestamptz,
    closed_at timestamptz,
    row_version bigint NOT NULL DEFAULT 1,
    created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    CONSTRAINT org_tenants_pkey PRIMARY KEY (tenant_pk),
    CONSTRAINT org_tenants_id_key UNIQUE (tenant_id),
    CONSTRAINT org_tenants_code_key UNIQUE (business_line_pk, code),
    CONSTRAINT org_tenants_tenant_pair_key UNIQUE (tenant_pk, business_line_pk),
    CONSTRAINT org_tenants_id_v4_ck CHECK (public.iam_uuid_is_v4(tenant_id)),
    CONSTRAINT org_tenants_business_line_fk FOREIGN KEY (business_line_pk)
        REFERENCES public.app_business_lines (business_line_pk) ON DELETE RESTRICT,
    CONSTRAINT org_tenants_owner_fk FOREIGN KEY (owner_principal_pk)
        REFERENCES public.iam_principals (principal_pk) ON DELETE RESTRICT,
    CONSTRAINT org_tenants_code_ck
        CHECK (pg_catalog.length(code) BETWEEN 2 AND 64 AND code ~ '^[a-z][a-z0-9_-]*$'),
    CONSTRAINT org_tenants_name_ck CHECK (pg_catalog.length(display_name) BETWEEN 1 AND 200),
    CONSTRAINT org_tenants_status_ck
        CHECK (status IN ('PROVISIONING', 'ACTIVE', 'SUSPENDED', 'CLOSING', 'CLOSED')),
    CONSTRAINT org_tenants_security_epoch_ck CHECK (security_epoch > 0),
    CONSTRAINT org_tenants_closing_ck CHECK (
        (status IN ('CLOSING', 'CLOSED')) = (closing_started_at IS NOT NULL)
        AND (status = 'CLOSED') = (closed_at IS NOT NULL)
    ),
    CONSTRAINT org_tenants_row_version_ck CHECK (row_version > 0),
    CONSTRAINT org_tenants_time_ck CHECK (
        updated_at >= created_at
        AND (closing_started_at IS NULL OR closing_started_at >= created_at)
        AND (closed_at IS NULL OR closed_at >= closing_started_at)
    )
);

COMMENT ON TABLE public.org_tenants IS
    'Tenant aggregate with orthogonal lifecycle and monotonic security epoch; CLOSED is terminal; S2.';
CREATE INDEX org_tenants_business_status_idx ON public.org_tenants (business_line_pk, status);
CREATE INDEX org_tenants_owner_idx ON public.org_tenants (owner_principal_pk);

CREATE TABLE public.org_tenant_domains (
    tenant_domain_pk bigint GENERATED ALWAYS AS IDENTITY,
    tenant_domain_id uuid NOT NULL DEFAULT pg_catalog.gen_random_uuid(),
    tenant_pk bigint NOT NULL,
    domain_ciphertext bytea NOT NULL,
    encryption_key_ref text COLLATE "C" NOT NULL,
    encryption_key_version integer NOT NULL,
    domain_digest bytea NOT NULL,
    digest_key_ref text COLLATE "C" NOT NULL,
    digest_key_version integer NOT NULL,
    normalization_version integer NOT NULL,
    status text COLLATE "C" NOT NULL DEFAULT 'PENDING',
    verification_evidence_digest bytea,
    verified_at timestamptz,
    verification_expires_at timestamptz,
    row_version bigint NOT NULL DEFAULT 1,
    created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    CONSTRAINT org_tenant_domains_pkey PRIMARY KEY (tenant_domain_pk),
    CONSTRAINT org_tenant_domains_id_key UNIQUE (tenant_domain_id),
    CONSTRAINT org_tenant_domains_tenant_pair_key UNIQUE (tenant_pk, tenant_domain_pk),
    CONSTRAINT org_tenant_domains_id_v4_ck CHECK (public.iam_uuid_is_v4(tenant_domain_id)),
    CONSTRAINT org_tenant_domains_tenant_fk FOREIGN KEY (tenant_pk)
        REFERENCES public.org_tenants (tenant_pk) ON DELETE RESTRICT,
    CONSTRAINT org_tenant_domains_cipher_ck CHECK (
        pg_catalog.octet_length(domain_ciphertext) >= 28
        AND pg_catalog.length(encryption_key_ref) BETWEEN 1 AND 512
        AND encryption_key_version > 0
    ),
    CONSTRAINT org_tenant_domains_digest_ck CHECK (
        pg_catalog.octet_length(domain_digest) = 32
        AND pg_catalog.length(digest_key_ref) BETWEEN 1 AND 512
        AND digest_key_version > 0
        AND normalization_version > 0
    ),
    CONSTRAINT org_tenant_domains_status_ck
        CHECK (status IN ('PENDING', 'VERIFIED', 'EXPIRED', 'REVOKED')),
    CONSTRAINT org_tenant_domains_verification_ck CHECK (
        (status = 'VERIFIED' AND verified_at IS NOT NULL
         AND verification_evidence_digest IS NOT NULL
         AND pg_catalog.octet_length(verification_evidence_digest) = 32
         AND verification_expires_at > verified_at)
        OR status <> 'VERIFIED'
    ),
    CONSTRAINT org_tenant_domains_row_version_ck CHECK (row_version > 0),
    CONSTRAINT org_tenant_domains_time_ck CHECK (updated_at >= created_at)
);

COMMENT ON TABLE public.org_tenant_domains IS
    'Encrypted, continuously verified tenant login-discovery domains; no plaintext domain is stored; S3.';
CREATE UNIQUE INDEX org_tenant_domains_verified_uidx
    ON public.org_tenant_domains (digest_key_version, domain_digest)
    WHERE status = 'VERIFIED';
CREATE INDEX org_tenant_domains_expiry_idx
    ON public.org_tenant_domains (verification_expires_at)
    WHERE status = 'VERIFIED';

CREATE TABLE public.org_organizations (
    organization_pk bigint GENERATED ALWAYS AS IDENTITY,
    organization_id uuid NOT NULL DEFAULT pg_catalog.gen_random_uuid(),
    tenant_pk bigint NOT NULL,
    parent_organization_pk bigint,
    code text COLLATE "C" NOT NULL,
    display_name text NOT NULL,
    organization_type text COLLATE "C" NOT NULL,
    state text COLLATE "C" NOT NULL DEFAULT 'ACTIVE',
    hierarchy_version bigint NOT NULL DEFAULT 1,
    row_version bigint NOT NULL DEFAULT 1,
    created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    CONSTRAINT org_organizations_pkey PRIMARY KEY (organization_pk),
    CONSTRAINT org_organizations_id_key UNIQUE (organization_id),
    CONSTRAINT org_organizations_tenant_pk_key UNIQUE (tenant_pk, organization_pk),
    CONSTRAINT org_organizations_tenant_id_key UNIQUE (tenant_pk, organization_id),
    CONSTRAINT org_organizations_code_key UNIQUE (tenant_pk, code),
    CONSTRAINT org_organizations_id_v4_ck CHECK (public.iam_uuid_is_v4(organization_id)),
    CONSTRAINT org_organizations_tenant_fk FOREIGN KEY (tenant_pk)
        REFERENCES public.org_tenants (tenant_pk) ON DELETE RESTRICT,
    CONSTRAINT org_organizations_parent_fk FOREIGN KEY (tenant_pk, parent_organization_pk)
        REFERENCES public.org_organizations (tenant_pk, organization_pk) ON DELETE RESTRICT,
    CONSTRAINT org_organizations_not_self_ck
        CHECK (parent_organization_pk IS NULL OR parent_organization_pk <> organization_pk),
    CONSTRAINT org_organizations_code_ck
        CHECK (pg_catalog.length(code) BETWEEN 1 AND 128),
    CONSTRAINT org_organizations_name_ck CHECK (pg_catalog.length(display_name) BETWEEN 1 AND 200),
    CONSTRAINT org_organizations_type_ck
        CHECK (organization_type IN ('COMPANY', 'DEPARTMENT', 'STORE', 'TEAM', 'PROJECT', 'OTHER')),
    CONSTRAINT org_organizations_state_ck CHECK (state IN ('ACTIVE', 'SUSPENDED', 'TERMINATED')),
    CONSTRAINT org_organizations_versions_ck CHECK (hierarchy_version > 0 AND row_version > 0),
    CONSTRAINT org_organizations_time_ck CHECK (updated_at >= created_at)
);

COMMENT ON TABLE public.org_organizations IS
    'Tenant-scoped organization hierarchy; composite parent FK prevents cross-tenant attachment; cycle checks are deferred to 110; S2.';
CREATE INDEX org_organizations_parent_idx
    ON public.org_organizations (tenant_pk, parent_organization_pk);
CREATE INDEX org_organizations_state_idx ON public.org_organizations (tenant_pk, state);

CREATE TABLE public.org_memberships (
    membership_pk bigint GENERATED ALWAYS AS IDENTITY,
    membership_id uuid NOT NULL DEFAULT pg_catalog.gen_random_uuid(),
    tenant_pk bigint NOT NULL,
    user_pk bigint NOT NULL,
    state text COLLATE "C" NOT NULL DEFAULT 'INVITED',
    source_type text COLLATE "C" NOT NULL,
    source_reference_digest bytea,
    source_version bigint,
    joined_at timestamptz,
    left_at timestamptz,
    row_version bigint NOT NULL DEFAULT 1,
    created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    CONSTRAINT org_memberships_pkey PRIMARY KEY (membership_pk),
    CONSTRAINT org_memberships_id_key UNIQUE (membership_id),
    CONSTRAINT org_memberships_tenant_pk_key UNIQUE (tenant_pk, membership_pk),
    CONSTRAINT org_memberships_id_v4_ck CHECK (public.iam_uuid_is_v4(membership_id)),
    CONSTRAINT org_memberships_tenant_fk FOREIGN KEY (tenant_pk)
        REFERENCES public.org_tenants (tenant_pk) ON DELETE RESTRICT,
    CONSTRAINT org_memberships_user_fk FOREIGN KEY (user_pk)
        REFERENCES public.iam_users (user_pk) ON DELETE RESTRICT,
    CONSTRAINT org_memberships_state_ck CHECK (
        state IN ('INVITED', 'PENDING_APPROVAL', 'ACTIVE', 'SUSPENDED',
                  'BANNED', 'LEFT', 'REJECTED', 'EXPIRED')
    ),
    CONSTRAINT org_memberships_source_ck
        CHECK (source_type IN ('SELF_SERVICE', 'INVITATION', 'ADMIN', 'DIRECTORY', 'JIT', 'MIGRATION')),
    CONSTRAINT org_memberships_source_digest_ck
        CHECK (source_reference_digest IS NULL OR pg_catalog.octet_length(source_reference_digest) = 32),
    CONSTRAINT org_memberships_source_version_ck CHECK (source_version IS NULL OR source_version > 0),
    CONSTRAINT org_memberships_joined_ck CHECK (
        state IN ('INVITED', 'PENDING_APPROVAL', 'REJECTED', 'EXPIRED') OR joined_at IS NOT NULL
    ),
    CONSTRAINT org_memberships_left_ck CHECK (
        (state = 'LEFT') = (left_at IS NOT NULL)
    ),
    CONSTRAINT org_memberships_row_version_ck CHECK (row_version > 0),
    CONSTRAINT org_memberships_time_ck CHECK (
        updated_at >= created_at
        AND (joined_at IS NULL OR joined_at >= created_at)
        AND (left_at IS NULL OR left_at >= joined_at)
    )
);

COMMENT ON TABLE public.org_memberships IS
    'Tenant-local business membership state, separate from global user security state; terminal records are retained; S2.';
CREATE UNIQUE INDEX org_memberships_current_user_uidx
    ON public.org_memberships (tenant_pk, user_pk)
    WHERE state NOT IN ('LEFT', 'REJECTED', 'EXPIRED');
CREATE INDEX org_memberships_user_state_idx ON public.org_memberships (user_pk, state);
CREATE INDEX org_memberships_tenant_state_idx ON public.org_memberships (tenant_pk, state);

CREATE TABLE public.org_membership_organizations (
    membership_organization_pk bigint GENERATED ALWAYS AS IDENTITY,
    tenant_pk bigint NOT NULL,
    membership_pk bigint NOT NULL,
    organization_pk bigint NOT NULL,
    relationship_type text COLLATE "C" NOT NULL DEFAULT 'MEMBER',
    is_primary boolean NOT NULL DEFAULT false,
    valid_from timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    valid_until timestamptz,
    CONSTRAINT org_membership_organizations_pkey PRIMARY KEY (membership_organization_pk),
    CONSTRAINT org_membership_organizations_pair_key
        UNIQUE (tenant_pk, membership_pk, organization_pk, valid_from),
    CONSTRAINT org_membership_organizations_membership_fk FOREIGN KEY (tenant_pk, membership_pk)
        REFERENCES public.org_memberships (tenant_pk, membership_pk) ON DELETE RESTRICT,
    CONSTRAINT org_membership_organizations_organization_fk FOREIGN KEY (tenant_pk, organization_pk)
        REFERENCES public.org_organizations (tenant_pk, organization_pk) ON DELETE RESTRICT,
    CONSTRAINT org_membership_organizations_type_ck
        CHECK (relationship_type IN ('MEMBER', 'MANAGER', 'OWNER')),
    CONSTRAINT org_membership_organizations_time_ck
        CHECK (valid_until IS NULL OR valid_until > valid_from)
);

COMMENT ON TABLE public.org_membership_organizations IS
    'Tenant-safe membership-to-organization assignments with independently retained history; S2.';
CREATE UNIQUE INDEX org_membership_organizations_primary_uidx
    ON public.org_membership_organizations (tenant_pk, membership_pk)
    WHERE is_primary AND valid_until IS NULL;
CREATE INDEX org_membership_organizations_org_idx
    ON public.org_membership_organizations (tenant_pk, organization_pk);

CREATE TABLE public.org_groups (
    group_pk bigint GENERATED ALWAYS AS IDENTITY,
    group_id uuid NOT NULL DEFAULT pg_catalog.gen_random_uuid(),
    tenant_pk bigint NOT NULL,
    code text COLLATE "C" NOT NULL,
    display_name text NOT NULL,
    group_type text COLLATE "C" NOT NULL,
    state text COLLATE "C" NOT NULL DEFAULT 'ACTIVE',
    definition_schema_version integer,
    dynamic_definition jsonb,
    row_version bigint NOT NULL DEFAULT 1,
    created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    CONSTRAINT org_groups_pkey PRIMARY KEY (group_pk),
    CONSTRAINT org_groups_id_key UNIQUE (group_id),
    CONSTRAINT org_groups_tenant_pk_key UNIQUE (tenant_pk, group_pk),
    CONSTRAINT org_groups_code_key UNIQUE (tenant_pk, code),
    CONSTRAINT org_groups_id_v4_ck CHECK (public.iam_uuid_is_v4(group_id)),
    CONSTRAINT org_groups_tenant_fk FOREIGN KEY (tenant_pk)
        REFERENCES public.org_tenants (tenant_pk) ON DELETE RESTRICT,
    CONSTRAINT org_groups_code_ck CHECK (pg_catalog.length(code) BETWEEN 1 AND 128),
    CONSTRAINT org_groups_name_ck CHECK (pg_catalog.length(display_name) BETWEEN 1 AND 200),
    CONSTRAINT org_groups_type_ck CHECK (group_type IN ('STATIC', 'DYNAMIC', 'DIRECTORY')),
    CONSTRAINT org_groups_state_ck CHECK (state IN ('ACTIVE', 'SUSPENDED', 'RETIRED')),
    CONSTRAINT org_groups_definition_ck CHECK (
        (group_type = 'DYNAMIC' AND definition_schema_version > 0
         AND pg_catalog.jsonb_typeof(dynamic_definition) = 'object')
        OR (group_type <> 'DYNAMIC' AND definition_schema_version IS NULL
            AND dynamic_definition IS NULL)
    ),
    CONSTRAINT org_groups_row_version_ck CHECK (row_version > 0),
    CONSTRAINT org_groups_time_ck CHECK (updated_at >= created_at)
);

COMMENT ON TABLE public.org_groups IS
    'Tenant-scoped static, dynamic, or directory-managed user groups; dynamic schemas are release-validated; S2.';

CREATE TABLE public.org_group_memberships (
    group_membership_pk bigint GENERATED ALWAYS AS IDENTITY,
    tenant_pk bigint NOT NULL,
    group_pk bigint NOT NULL,
    membership_pk bigint NOT NULL,
    source_type text COLLATE "C" NOT NULL,
    valid_from timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    valid_until timestamptz,
    CONSTRAINT org_group_memberships_pkey PRIMARY KEY (group_membership_pk),
    CONSTRAINT org_group_memberships_group_fk FOREIGN KEY (tenant_pk, group_pk)
        REFERENCES public.org_groups (tenant_pk, group_pk) ON DELETE RESTRICT,
    CONSTRAINT org_group_memberships_membership_fk FOREIGN KEY (tenant_pk, membership_pk)
        REFERENCES public.org_memberships (tenant_pk, membership_pk) ON DELETE RESTRICT,
    CONSTRAINT org_group_memberships_source_ck
        CHECK (source_type IN ('DIRECT', 'DYNAMIC', 'DIRECTORY')),
    CONSTRAINT org_group_memberships_time_ck
        CHECK (valid_until IS NULL OR valid_until > valid_from)
);

COMMENT ON TABLE public.org_group_memberships IS
    'Historical tenant-safe group membership assignments; S2.';
CREATE UNIQUE INDEX org_group_memberships_active_uidx
    ON public.org_group_memberships (tenant_pk, group_pk, membership_pk)
    WHERE valid_until IS NULL;
CREATE INDEX org_group_memberships_member_idx
    ON public.org_group_memberships (tenant_pk, membership_pk);

CREATE TABLE public.org_invitations (
    invitation_pk bigint GENERATED ALWAYS AS IDENTITY,
    invitation_id uuid NOT NULL DEFAULT pg_catalog.gen_random_uuid(),
    tenant_pk bigint NOT NULL,
    membership_pk bigint,
    target_kind text COLLATE "C" NOT NULL,
    target_blind_index bytea NOT NULL,
    target_key_ref text COLLATE "C" NOT NULL,
    target_key_version integer NOT NULL,
    token_digest bytea NOT NULL,
    token_pepper_ref text COLLATE "C" NOT NULL,
    state text COLLATE "C" NOT NULL DEFAULT 'ISSUED',
    inviter_principal_pk bigint NOT NULL,
    expires_at timestamptz NOT NULL,
    accepted_at timestamptz,
    cancelled_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    CONSTRAINT org_invitations_pkey PRIMARY KEY (invitation_pk),
    CONSTRAINT org_invitations_id_key UNIQUE (invitation_id),
    CONSTRAINT org_invitations_token_key UNIQUE (token_digest),
    CONSTRAINT org_invitations_id_v4_ck CHECK (public.iam_uuid_is_v4(invitation_id)),
    CONSTRAINT org_invitations_tenant_fk FOREIGN KEY (tenant_pk)
        REFERENCES public.org_tenants (tenant_pk) ON DELETE RESTRICT,
    CONSTRAINT org_invitations_membership_fk FOREIGN KEY (tenant_pk, membership_pk)
        REFERENCES public.org_memberships (tenant_pk, membership_pk) ON DELETE RESTRICT,
    CONSTRAINT org_invitations_inviter_fk FOREIGN KEY (inviter_principal_pk)
        REFERENCES public.iam_principals (principal_pk) ON DELETE RESTRICT,
    CONSTRAINT org_invitations_target_kind_ck CHECK (target_kind IN ('PHONE', 'EMAIL')),
    CONSTRAINT org_invitations_digests_ck CHECK (
        pg_catalog.octet_length(target_blind_index) = 32
        AND pg_catalog.octet_length(token_digest) = 32
    ),
    CONSTRAINT org_invitations_key_refs_ck CHECK (
        pg_catalog.length(target_key_ref) BETWEEN 1 AND 512
        AND target_key_version > 0
        AND pg_catalog.length(token_pepper_ref) BETWEEN 1 AND 512
    ),
    CONSTRAINT org_invitations_state_ck
        CHECK (state IN ('ISSUED', 'ACCEPTED', 'REJECTED', 'EXPIRED', 'CANCELLED')),
    CONSTRAINT org_invitations_terminal_time_ck CHECK (
        (state = 'ACCEPTED') = (accepted_at IS NOT NULL)
        AND (state = 'CANCELLED') = (cancelled_at IS NOT NULL)
    ),
    CONSTRAINT org_invitations_time_ck CHECK (
        expires_at > created_at
        AND (accepted_at IS NULL OR accepted_at BETWEEN created_at AND expires_at)
        AND (cancelled_at IS NULL OR cancelled_at >= created_at)
    )
);

COMMENT ON TABLE public.org_invitations IS
    'Single-use tenant invitation tokens and target HMACs; neither invitation token nor target PII is stored plaintext; S3.';
CREATE INDEX org_invitations_target_state_idx
    ON public.org_invitations (tenant_pk, target_key_version, target_blind_index, state);
CREATE INDEX org_invitations_expiry_idx
    ON public.org_invitations (expires_at) WHERE state = 'ISSUED';

CREATE TABLE public.fed_identity_providers (
    provider_pk bigint GENERATED ALWAYS AS IDENTITY,
    provider_id uuid NOT NULL DEFAULT pg_catalog.gen_random_uuid(),
    tenant_pk bigint NOT NULL,
    protocol_party_pk bigint NOT NULL,
    code text COLLATE "C" NOT NULL,
    protocol text COLLATE "C" NOT NULL,
    metadata_uri text COLLATE "C",
    status text COLLATE "C" NOT NULL DEFAULT 'DRAFT',
    owner_principal_pk bigint NOT NULL,
    active_version_no integer,
    row_version bigint NOT NULL DEFAULT 1,
    created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    CONSTRAINT fed_identity_providers_pkey PRIMARY KEY (provider_pk),
    CONSTRAINT fed_identity_providers_id_key UNIQUE (provider_id),
    CONSTRAINT fed_identity_providers_tenant_pk_key UNIQUE (tenant_pk, provider_pk),
    CONSTRAINT fed_identity_providers_code_key UNIQUE (tenant_pk, code),
    CONSTRAINT fed_identity_providers_party_key UNIQUE (tenant_pk, protocol_party_pk),
    CONSTRAINT fed_identity_providers_id_v4_ck CHECK (public.iam_uuid_is_v4(provider_id)),
    CONSTRAINT fed_identity_providers_tenant_fk FOREIGN KEY (tenant_pk)
        REFERENCES public.org_tenants (tenant_pk) ON DELETE RESTRICT,
    CONSTRAINT fed_identity_providers_party_fk FOREIGN KEY (protocol_party_pk)
        REFERENCES public.fed_protocol_parties (protocol_party_pk) ON DELETE RESTRICT,
    CONSTRAINT fed_identity_providers_owner_fk FOREIGN KEY (owner_principal_pk)
        REFERENCES public.iam_principals (principal_pk) ON DELETE RESTRICT,
    CONSTRAINT fed_identity_providers_code_ck
        CHECK (pg_catalog.length(code) BETWEEN 1 AND 64 AND code ~ '^[a-z][a-z0-9_-]*$'),
    CONSTRAINT fed_identity_providers_protocol_ck CHECK (protocol IN ('OIDC', 'SAML')),
    CONSTRAINT fed_identity_providers_metadata_uri_ck
        CHECK (metadata_uri IS NULL OR
               (pg_catalog.length(metadata_uri) BETWEEN 8 AND 2048 AND metadata_uri ~ '^https://')),
    CONSTRAINT fed_identity_providers_status_ck
        CHECK (status IN ('DRAFT', 'VALIDATED', 'APPROVED', 'ACTIVE', 'SUSPENDED', 'RETIRED')),
    CONSTRAINT fed_identity_providers_active_version_ck
        CHECK ((status = 'ACTIVE' AND active_version_no > 0) OR status <> 'ACTIVE'),
    CONSTRAINT fed_identity_providers_row_version_ck CHECK (row_version > 0),
    CONSTRAINT fed_identity_providers_time_ck CHECK (updated_at >= created_at)
);

COMMENT ON TABLE public.fed_identity_providers IS
    'Tenant IdP configuration root linked to the immutable protocol-party stable key; secrets are prohibited from metadata_uri; S2.';
CREATE INDEX fed_identity_providers_tenant_status_idx
    ON public.fed_identity_providers (tenant_pk, status);

CREATE TABLE public.fed_provider_versions (
    provider_version_pk bigint GENERATED ALWAYS AS IDENTITY,
    tenant_pk bigint NOT NULL,
    provider_pk bigint NOT NULL,
    version_no integer NOT NULL,
    content_hash bytea NOT NULL,
    schema_version integer NOT NULL,
    configuration jsonb NOT NULL,
    signing_key_reference text COLLATE "C",
    status text COLLATE "C" NOT NULL DEFAULT 'DRAFT',
    published_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    created_by_principal_pk bigint NOT NULL,
    CONSTRAINT fed_provider_versions_pkey PRIMARY KEY (provider_version_pk),
    CONSTRAINT fed_provider_versions_number_key UNIQUE (provider_pk, version_no),
    CONSTRAINT fed_provider_versions_hash_key UNIQUE (content_hash),
    CONSTRAINT fed_provider_versions_provider_fk FOREIGN KEY (tenant_pk, provider_pk)
        REFERENCES public.fed_identity_providers (tenant_pk, provider_pk) ON DELETE RESTRICT,
    CONSTRAINT fed_provider_versions_actor_fk FOREIGN KEY (created_by_principal_pk)
        REFERENCES public.iam_principals (principal_pk) ON DELETE RESTRICT,
    CONSTRAINT fed_provider_versions_version_ck CHECK (version_no > 0 AND schema_version > 0),
    CONSTRAINT fed_provider_versions_hash_ck CHECK (pg_catalog.octet_length(content_hash) = 32),
    CONSTRAINT fed_provider_versions_json_ck CHECK (pg_catalog.jsonb_typeof(configuration) = 'object'),
    CONSTRAINT fed_provider_versions_key_ref_ck
        CHECK (signing_key_reference IS NULL OR pg_catalog.length(signing_key_reference) BETWEEN 1 AND 512),
    CONSTRAINT fed_provider_versions_status_ck CHECK (status IN ('DRAFT', 'PUBLISHED', 'RETIRED')),
    CONSTRAINT fed_provider_versions_published_ck
        CHECK ((status IN ('PUBLISHED', 'RETIRED')) = (published_at IS NOT NULL)),
    CONSTRAINT fed_provider_versions_time_ck CHECK (published_at IS NULL OR published_at >= created_at)
);

COMMENT ON TABLE public.fed_provider_versions IS
    'Versioned IdP validation policy, audience, algorithm allowlist, certificate references, and attribute mapping; no secret material; S2/S3.';
CREATE INDEX fed_provider_versions_provider_status_idx
    ON public.fed_provider_versions (provider_pk, status);

CREATE TABLE public.fed_directory_sources (
    directory_source_pk bigint GENERATED ALWAYS AS IDENTITY,
    directory_source_id uuid NOT NULL DEFAULT pg_catalog.gen_random_uuid(),
    tenant_pk bigint NOT NULL,
    code text COLLATE "C" NOT NULL,
    source_type text COLLATE "C" NOT NULL,
    external_source_key_digest bytea NOT NULL,
    digest_key_ref text COLLATE "C" NOT NULL,
    digest_key_version integer NOT NULL,
    authentication_key_ref text COLLATE "C" NOT NULL,
    status text COLLATE "C" NOT NULL DEFAULT 'ACTIVE',
    source_epoch bigint NOT NULL DEFAULT 1,
    owner_principal_pk bigint NOT NULL,
    row_version bigint NOT NULL DEFAULT 1,
    created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    CONSTRAINT fed_directory_sources_pkey PRIMARY KEY (directory_source_pk),
    CONSTRAINT fed_directory_sources_id_key UNIQUE (directory_source_id),
    CONSTRAINT fed_directory_sources_tenant_pk_key UNIQUE (tenant_pk, directory_source_pk),
    CONSTRAINT fed_directory_sources_code_key UNIQUE (tenant_pk, code),
    CONSTRAINT fed_directory_sources_external_key
        UNIQUE (tenant_pk, digest_key_version, external_source_key_digest),
    CONSTRAINT fed_directory_sources_id_v4_ck CHECK (public.iam_uuid_is_v4(directory_source_id)),
    CONSTRAINT fed_directory_sources_tenant_fk FOREIGN KEY (tenant_pk)
        REFERENCES public.org_tenants (tenant_pk) ON DELETE RESTRICT,
    CONSTRAINT fed_directory_sources_owner_fk FOREIGN KEY (owner_principal_pk)
        REFERENCES public.iam_principals (principal_pk) ON DELETE RESTRICT,
    CONSTRAINT fed_directory_sources_code_ck
        CHECK (pg_catalog.length(code) BETWEEN 1 AND 64),
    CONSTRAINT fed_directory_sources_type_ck CHECK (source_type IN ('SCIM', 'API')),
    CONSTRAINT fed_directory_sources_digest_ck
        CHECK (pg_catalog.octet_length(external_source_key_digest) = 32),
    CONSTRAINT fed_directory_sources_refs_ck CHECK (
        pg_catalog.length(digest_key_ref) BETWEEN 1 AND 512
        AND digest_key_version > 0
        AND pg_catalog.length(authentication_key_ref) BETWEEN 1 AND 512
    ),
    CONSTRAINT fed_directory_sources_status_ck
        CHECK (status IN ('ACTIVE', 'SUSPENDED', 'RETIRED')),
    CONSTRAINT fed_directory_sources_versions_ck CHECK (source_epoch > 0 AND row_version > 0),
    CONSTRAINT fed_directory_sources_time_ck CHECK (updated_at >= created_at)
);

COMMENT ON TABLE public.fed_directory_sources IS
    'Tenant SCIM/API directory source; credentials are KMS/key-asset references only; S3.';
CREATE INDEX fed_directory_sources_tenant_status_idx
    ON public.fed_directory_sources (tenant_pk, status);

CREATE TABLE public.fed_directory_objects (
    directory_object_pk bigint GENERATED ALWAYS AS IDENTITY,
    directory_object_id uuid NOT NULL DEFAULT pg_catalog.gen_random_uuid(),
    tenant_pk bigint NOT NULL,
    directory_source_pk bigint NOT NULL,
    object_type text COLLATE "C" NOT NULL,
    external_id_digest bytea NOT NULL,
    digest_key_ref text COLLATE "C" NOT NULL,
    digest_key_version integer NOT NULL,
    local_membership_pk bigint,
    local_group_pk bigint,
    state text COLLATE "C" NOT NULL DEFAULT 'ACTIVE',
    source_version bigint NOT NULL,
    source_etag_digest bytea,
    disabled_source_version bigint,
    disabled_at timestamptz,
    row_version bigint NOT NULL DEFAULT 1,
    created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    CONSTRAINT fed_directory_objects_pkey PRIMARY KEY (directory_object_pk),
    CONSTRAINT fed_directory_objects_id_key UNIQUE (directory_object_id),
    CONSTRAINT fed_directory_objects_external_key
        UNIQUE (directory_source_pk, object_type, digest_key_version, external_id_digest),
    CONSTRAINT fed_directory_objects_id_v4_ck CHECK (public.iam_uuid_is_v4(directory_object_id)),
    CONSTRAINT fed_directory_objects_source_fk FOREIGN KEY (tenant_pk, directory_source_pk)
        REFERENCES public.fed_directory_sources (tenant_pk, directory_source_pk) ON DELETE RESTRICT,
    CONSTRAINT fed_directory_objects_membership_fk FOREIGN KEY (tenant_pk, local_membership_pk)
        REFERENCES public.org_memberships (tenant_pk, membership_pk) ON DELETE RESTRICT,
    CONSTRAINT fed_directory_objects_group_fk FOREIGN KEY (tenant_pk, local_group_pk)
        REFERENCES public.org_groups (tenant_pk, group_pk) ON DELETE RESTRICT,
    CONSTRAINT fed_directory_objects_type_ck CHECK (object_type IN ('USER', 'GROUP')),
    CONSTRAINT fed_directory_objects_local_target_ck CHECK (
        (object_type = 'USER' AND local_membership_pk IS NOT NULL AND local_group_pk IS NULL)
        OR (object_type = 'GROUP' AND local_membership_pk IS NULL AND local_group_pk IS NOT NULL)
    ),
    CONSTRAINT fed_directory_objects_digest_ck CHECK (
        pg_catalog.octet_length(external_id_digest) = 32
        AND pg_catalog.length(digest_key_ref) BETWEEN 1 AND 512
        AND digest_key_version > 0
        AND (source_etag_digest IS NULL OR pg_catalog.octet_length(source_etag_digest) = 32)
    ),
    CONSTRAINT fed_directory_objects_state_ck
        CHECK (state IN ('ACTIVE', 'DISABLED', 'TOMBSTONED')),
    CONSTRAINT fed_directory_objects_source_version_ck CHECK (source_version > 0),
    CONSTRAINT fed_directory_objects_disabled_ck CHECK (
        (state IN ('DISABLED', 'TOMBSTONED'))
        = (disabled_source_version IS NOT NULL AND disabled_at IS NOT NULL)
        AND (disabled_source_version IS NULL OR disabled_source_version <= source_version)
    ),
    CONSTRAINT fed_directory_objects_row_version_ck CHECK (row_version > 0),
    CONSTRAINT fed_directory_objects_time_ck CHECK (
        updated_at >= created_at AND (disabled_at IS NULL OR disabled_at >= created_at)
    )
);

COMMENT ON TABLE public.fed_directory_objects IS
    'SCIM/API stable object mappings with trusted monotonic source version and durable disable tombstone; old updates cannot supersede it; S3.';
CREATE INDEX fed_directory_objects_source_version_idx
    ON public.fed_directory_objects (directory_source_pk, source_version);
CREATE INDEX fed_directory_objects_disabled_idx
    ON public.fed_directory_objects (tenant_pk, disabled_at)
    WHERE state IN ('DISABLED', 'TOMBSTONED');

COMMIT;
