-- OAuth Clients, relational URIs/methods, API resources/scopes, and machine/workload identity.

BEGIN;

CREATE TABLE public.app_clients (
    client_pk bigint GENERATED ALWAYS AS IDENTITY,
    client_id uuid NOT NULL DEFAULT pg_catalog.gen_random_uuid(),
    application_pk bigint NOT NULL,
    client_name text NOT NULL,
    client_type text COLLATE "C" NOT NULL,
    security_profile text COLLATE "C" NOT NULL,
    environment text COLLATE "C" NOT NULL,
    status text COLLATE "C" NOT NULL DEFAULT 'DRAFT',
    security_epoch bigint NOT NULL DEFAULT 1,
    access_token_ttl_seconds integer NOT NULL,
    refresh_token_ttl_seconds integer,
    require_pkce boolean NOT NULL DEFAULT true,
    require_par boolean NOT NULL DEFAULT false,
    require_sender_constraint boolean NOT NULL DEFAULT false,
    sector_identifier_digest bytea,
    owner_principal_pk bigint NOT NULL,
    row_version bigint NOT NULL DEFAULT 1,
    created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    CONSTRAINT app_clients_pkey PRIMARY KEY (client_pk),
    CONSTRAINT app_clients_id_key UNIQUE (client_id),
    CONSTRAINT app_clients_application_pk_key UNIQUE (application_pk, client_pk),
    CONSTRAINT app_clients_id_v4_ck CHECK (public.iam_uuid_is_v4(client_id)),
    CONSTRAINT app_clients_application_fk FOREIGN KEY (application_pk)
        REFERENCES public.app_applications (application_pk) ON DELETE RESTRICT,
    CONSTRAINT app_clients_owner_fk FOREIGN KEY (owner_principal_pk)
        REFERENCES public.iam_principals (principal_pk) ON DELETE RESTRICT,
    CONSTRAINT app_clients_name_ck CHECK (pg_catalog.length(client_name) BETWEEN 1 AND 200),
    CONSTRAINT app_clients_type_ck CHECK (client_type IN ('PUBLIC', 'CONFIDENTIAL')),
    CONSTRAINT app_clients_profile_ck CHECK (security_profile IN ('SP1', 'SP2', 'SP3', 'SP4', 'SP5')),
    CONSTRAINT app_clients_environment_ck
        CHECK (environment IN ('DEVELOPMENT', 'TEST', 'STAGING', 'PRODUCTION')),
    CONSTRAINT app_clients_status_ck CHECK (
        status IN ('DRAFT', 'VALIDATED', 'APPROVED', 'ACTIVE',
                   'SUSPENDED', 'COMPROMISED', 'RETIRED')
    ),
    CONSTRAINT app_clients_security_epoch_ck CHECK (security_epoch > 0),
    CONSTRAINT app_clients_token_ttl_ck CHECK (
        access_token_ttl_seconds BETWEEN 30 AND 3600
        AND (refresh_token_ttl_seconds IS NULL
             OR refresh_token_ttl_seconds BETWEEN 60 AND 31536000)
    ),
    CONSTRAINT app_clients_public_profile_ck CHECK (
        client_type <> 'PUBLIC' OR security_profile IN ('SP1', 'SP2')
    ),
    CONSTRAINT app_clients_sp5_ck CHECK (
        security_profile <> 'SP5' OR (require_par AND require_sender_constraint)
    ),
    CONSTRAINT app_clients_sector_ck
        CHECK (sector_identifier_digest IS NULL OR pg_catalog.octet_length(sector_identifier_digest) = 32),
    CONSTRAINT app_clients_row_version_ck CHECK (row_version > 0),
    CONSTRAINT app_clients_time_ck CHECK (updated_at >= created_at)
);

COMMENT ON TABLE public.app_clients IS
    'OAuth/OIDC Client aggregate with UUIDv4 external ID, security Profile, status, token policy and monotonic security epoch; S2.';
CREATE INDEX app_clients_application_status_idx
    ON public.app_clients (application_pk, status);
CREATE INDEX app_clients_owner_idx ON public.app_clients (owner_principal_pk);

CREATE TABLE public.app_client_uris (
    client_uri_pk bigint GENERATED ALWAYS AS IDENTITY,
    client_uri_id uuid NOT NULL DEFAULT pg_catalog.gen_random_uuid(),
    client_pk bigint NOT NULL,
    uri_type text COLLATE "C" NOT NULL,
    exact_uri text COLLATE "C" NOT NULL,
    uri_digest bytea NOT NULL,
    normalization_version integer NOT NULL,
    status text COLLATE "C" NOT NULL DEFAULT 'ACTIVE',
    is_loopback_exception boolean NOT NULL DEFAULT false,
    created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    retired_at timestamptz,
    CONSTRAINT app_client_uris_pkey PRIMARY KEY (client_uri_pk),
    CONSTRAINT app_client_uris_id_key UNIQUE (client_uri_id),
    CONSTRAINT app_client_uris_client_pk_key UNIQUE (client_pk, client_uri_pk),
    CONSTRAINT app_client_uris_digest_key UNIQUE (client_pk, uri_type, uri_digest),
    CONSTRAINT app_client_uris_id_v4_ck CHECK (public.iam_uuid_is_v4(client_uri_id)),
    CONSTRAINT app_client_uris_client_fk FOREIGN KEY (client_pk)
        REFERENCES public.app_clients (client_pk) ON DELETE RESTRICT,
    CONSTRAINT app_client_uris_type_ck CHECK (
        uri_type IN ('REDIRECT', 'POST_LOGOUT', 'FRONTCHANNEL_LOGOUT',
                     'BACKCHANNEL_LOGOUT', 'SECTOR_IDENTIFIER')
    ),
    CONSTRAINT app_client_uris_uri_ck CHECK (
        pg_catalog.length(exact_uri) BETWEEN 8 AND 2048
        AND exact_uri !~ '[*]'
        AND exact_uri !~ '[[:space:]]'
    ),
    CONSTRAINT app_client_uris_digest_ck CHECK (pg_catalog.octet_length(uri_digest) = 32),
    CONSTRAINT app_client_uris_normalization_ck CHECK (normalization_version > 0),
    CONSTRAINT app_client_uris_status_ck CHECK (status IN ('ACTIVE', 'RETIRED')),
    CONSTRAINT app_client_uris_loopback_ck CHECK (
        NOT is_loopback_exception
        OR (uri_type = 'REDIRECT'
            AND (exact_uri ~ '^http://127[.]0[.]0[.]1([:/]|$)'
                 OR exact_uri ~ '^http://[[]::1[]]([:/]|$)'))
    ),
    CONSTRAINT app_client_uris_retired_ck CHECK ((status = 'RETIRED') = (retired_at IS NOT NULL)),
    CONSTRAINT app_client_uris_time_ck CHECK (retired_at IS NULL OR retired_at >= created_at)
);

COMMENT ON TABLE public.app_client_uris IS
    'Exact relational redirect/logout/sector URIs; wildcards are forbidden and native loopback exceptions are explicit; S2.';
CREATE INDEX app_client_uris_active_idx
    ON public.app_client_uris (client_pk, uri_type) WHERE status = 'ACTIVE';

CREATE TABLE public.app_client_grant_types (
    client_grant_type_pk bigint GENERATED ALWAYS AS IDENTITY,
    client_pk bigint NOT NULL,
    grant_type text COLLATE "C" NOT NULL,
    enabled_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    disabled_at timestamptz,
    CONSTRAINT app_client_grant_types_pkey PRIMARY KEY (client_grant_type_pk),
    CONSTRAINT app_client_grant_types_key UNIQUE (client_pk, grant_type),
    CONSTRAINT app_client_grant_types_client_fk FOREIGN KEY (client_pk)
        REFERENCES public.app_clients (client_pk) ON DELETE RESTRICT,
    CONSTRAINT app_client_grant_types_type_ck CHECK (
        grant_type IN ('AUTHORIZATION_CODE', 'CLIENT_CREDENTIALS',
                       'REFRESH_TOKEN', 'TOKEN_EXCHANGE', 'DEVICE_CODE')
    ),
    CONSTRAINT app_client_grant_types_time_ck CHECK (disabled_at IS NULL OR disabled_at >= enabled_at)
);

COMMENT ON TABLE public.app_client_grant_types IS
    'Relational allowlist of approved OAuth grant types; implicit and password grants cannot be represented.';
CREATE UNIQUE INDEX app_client_grant_types_active_uidx
    ON public.app_client_grant_types (client_pk, grant_type) WHERE disabled_at IS NULL;

CREATE TABLE public.app_client_auth_methods (
    client_auth_method_pk bigint GENERATED ALWAYS AS IDENTITY,
    client_pk bigint NOT NULL,
    auth_method text COLLATE "C" NOT NULL,
    status text COLLATE "C" NOT NULL DEFAULT 'ACTIVE',
    created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    retired_at timestamptz,
    CONSTRAINT app_client_auth_methods_pkey PRIMARY KEY (client_auth_method_pk),
    CONSTRAINT app_client_auth_methods_key UNIQUE (client_pk, auth_method),
    CONSTRAINT app_client_auth_methods_client_fk FOREIGN KEY (client_pk)
        REFERENCES public.app_clients (client_pk) ON DELETE RESTRICT,
    CONSTRAINT app_client_auth_methods_method_ck CHECK (
        auth_method IN ('NONE', 'CLIENT_SECRET_BASIC', 'CLIENT_SECRET_POST',
                        'PRIVATE_KEY_JWT', 'TLS_CLIENT_AUTH', 'SELF_SIGNED_TLS_CLIENT_AUTH')
    ),
    CONSTRAINT app_client_auth_methods_status_ck CHECK (status IN ('ACTIVE', 'RETIRED')),
    CONSTRAINT app_client_auth_methods_retired_ck CHECK ((status = 'RETIRED') = (retired_at IS NOT NULL)),
    CONSTRAINT app_client_auth_methods_time_ck CHECK (retired_at IS NULL OR retired_at >= created_at)
);

COMMENT ON TABLE public.app_client_auth_methods IS
    'Relational Client authentication-method allowlist; public/secret compatibility is enforced by 110 publication functions.';

CREATE TABLE public.app_client_keys (
    client_key_pk bigint GENERATED ALWAYS AS IDENTITY,
    client_key_id uuid NOT NULL DEFAULT pg_catalog.gen_random_uuid(),
    client_pk bigint NOT NULL,
    kid text COLLATE "C" NOT NULL,
    key_use text COLLATE "C" NOT NULL,
    algorithm text COLLATE "C" NOT NULL,
    public_key bytea NOT NULL,
    kms_private_key_ref text COLLATE "C",
    certificate_thumbprint bytea,
    status text COLLATE "C" NOT NULL DEFAULT 'ACTIVE',
    not_before timestamptz NOT NULL,
    not_after timestamptz NOT NULL,
    compromised_at timestamptz,
    revoked_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    CONSTRAINT app_client_keys_pkey PRIMARY KEY (client_key_pk),
    CONSTRAINT app_client_keys_id_key UNIQUE (client_key_id),
    CONSTRAINT app_client_keys_client_kid_key UNIQUE (client_pk, kid),
    CONSTRAINT app_client_keys_client_pk_key UNIQUE (client_pk, client_key_pk),
    CONSTRAINT app_client_keys_id_v4_ck CHECK (public.iam_uuid_is_v4(client_key_id)),
    CONSTRAINT app_client_keys_client_fk FOREIGN KEY (client_pk)
        REFERENCES public.app_clients (client_pk) ON DELETE RESTRICT,
    CONSTRAINT app_client_keys_kid_ck CHECK (pg_catalog.length(kid) BETWEEN 1 AND 128),
    CONSTRAINT app_client_keys_use_ck CHECK (key_use IN ('SIGNATURE', 'MTLS')),
    CONSTRAINT app_client_keys_algorithm_ck
        CHECK (algorithm IN ('RS256', 'PS256', 'ES256', 'ES384', 'EDDSA')),
    CONSTRAINT app_client_keys_public_ck CHECK (pg_catalog.octet_length(public_key) BETWEEN 32 AND 16384),
    CONSTRAINT app_client_keys_kms_ck
        CHECK (kms_private_key_ref IS NULL OR pg_catalog.length(kms_private_key_ref) BETWEEN 1 AND 512),
    CONSTRAINT app_client_keys_thumbprint_ck
        CHECK (certificate_thumbprint IS NULL OR pg_catalog.octet_length(certificate_thumbprint) = 32),
    CONSTRAINT app_client_keys_status_ck
        CHECK (status IN ('ACTIVE', 'VERIFY_ONLY', 'COMPROMISED', 'REVOKED', 'RETIRED')),
    CONSTRAINT app_client_keys_compromised_ck CHECK (
        (status <> 'COMPROMISED' OR compromised_at IS NOT NULL)
        AND (compromised_at IS NULL OR status IN ('COMPROMISED', 'REVOKED'))
    ),
    CONSTRAINT app_client_keys_revoked_ck
        CHECK ((status = 'REVOKED') = (revoked_at IS NOT NULL)),
    CONSTRAINT app_client_keys_time_ck CHECK (
        not_after > not_before
        AND (compromised_at IS NULL OR compromised_at >= created_at)
        AND (revoked_at IS NULL OR revoked_at >= created_at)
    )
);

COMMENT ON TABLE public.app_client_keys IS
    'Client public keys, optional non-exportable KMS/HSM private-key handles, and certificate fingerprints; private key bytes are forbidden; S4.';
CREATE INDEX app_client_keys_active_window_idx
    ON public.app_client_keys (client_pk, status, not_after);

CREATE TABLE public.app_client_credentials (
    client_credential_pk bigint GENERATED ALWAYS AS IDENTITY,
    client_credential_id uuid NOT NULL DEFAULT pg_catalog.gen_random_uuid(),
    client_pk bigint NOT NULL,
    credential_type text COLLATE "C" NOT NULL,
    secret_digest bytea,
    pepper_key_ref text COLLATE "C",
    pepper_key_version integer,
    client_key_pk bigint,
    certificate_thumbprint bytea,
    status text COLLATE "C" NOT NULL DEFAULT 'ACTIVE',
    not_before timestamptz NOT NULL,
    not_after timestamptz NOT NULL,
    last_used_at timestamptz,
    revoked_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    CONSTRAINT app_client_credentials_pkey PRIMARY KEY (client_credential_pk),
    CONSTRAINT app_client_credentials_id_key UNIQUE (client_credential_id),
    CONSTRAINT app_client_credentials_id_v4_ck CHECK (public.iam_uuid_is_v4(client_credential_id)),
    CONSTRAINT app_client_credentials_client_fk FOREIGN KEY (client_pk)
        REFERENCES public.app_clients (client_pk) ON DELETE RESTRICT,
    CONSTRAINT app_client_credentials_key_fk FOREIGN KEY (client_pk, client_key_pk)
        REFERENCES public.app_client_keys (client_pk, client_key_pk) ON DELETE RESTRICT,
    CONSTRAINT app_client_credentials_type_ck
        CHECK (credential_type IN ('CLIENT_SECRET', 'PRIVATE_KEY_JWT', 'MTLS_CERTIFICATE')),
    CONSTRAINT app_client_credentials_material_ck CHECK (
        (credential_type = 'CLIENT_SECRET'
         AND pg_catalog.octet_length(secret_digest) = 32
         AND pg_catalog.length(pepper_key_ref) BETWEEN 1 AND 512
         AND pepper_key_version > 0
         AND client_key_pk IS NULL AND certificate_thumbprint IS NULL)
        OR
        (credential_type = 'PRIVATE_KEY_JWT'
         AND secret_digest IS NULL AND pepper_key_ref IS NULL AND pepper_key_version IS NULL
         AND client_key_pk IS NOT NULL AND certificate_thumbprint IS NULL)
        OR
        (credential_type = 'MTLS_CERTIFICATE'
         AND secret_digest IS NULL AND pepper_key_ref IS NULL AND pepper_key_version IS NULL
         AND client_key_pk IS NULL AND pg_catalog.octet_length(certificate_thumbprint) = 32)
    ),
    CONSTRAINT app_client_credentials_status_ck
        CHECK (status IN ('ACTIVE', 'SUSPENDED', 'COMPROMISED', 'REVOKED', 'EXPIRED')),
    CONSTRAINT app_client_credentials_revoked_ck
        CHECK ((status = 'REVOKED') = (revoked_at IS NOT NULL)),
    CONSTRAINT app_client_credentials_time_ck CHECK (
        not_after > not_before
        AND (last_used_at IS NULL OR last_used_at >= not_before)
        AND (revoked_at IS NULL OR revoked_at >= created_at)
    )
);

COMMENT ON TABLE public.app_client_credentials IS
    'Client secret digest, public-key reference, or mTLS certificate fingerprint; no raw secret or private key; S4.';
CREATE INDEX app_client_credentials_active_idx
    ON public.app_client_credentials (client_pk, status, not_after);

CREATE TABLE public.app_api_resources (
    api_resource_pk bigint GENERATED ALWAYS AS IDENTITY,
    api_resource_id uuid NOT NULL DEFAULT pg_catalog.gen_random_uuid(),
    business_line_pk bigint NOT NULL,
    audience text COLLATE "C" NOT NULL,
    display_name text NOT NULL,
    token_profile text COLLATE "C" NOT NULL,
    revocation_sla_seconds integer NOT NULL,
    status text COLLATE "C" NOT NULL DEFAULT 'ACTIVE',
    owner_principal_pk bigint NOT NULL,
    row_version bigint NOT NULL DEFAULT 1,
    created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    CONSTRAINT app_api_resources_pkey PRIMARY KEY (api_resource_pk),
    CONSTRAINT app_api_resources_id_key UNIQUE (api_resource_id),
    CONSTRAINT app_api_resources_audience_key UNIQUE (audience),
    CONSTRAINT app_api_resources_id_v4_ck CHECK (public.iam_uuid_is_v4(api_resource_id)),
    CONSTRAINT app_api_resources_business_fk FOREIGN KEY (business_line_pk)
        REFERENCES public.app_business_lines (business_line_pk) ON DELETE RESTRICT,
    CONSTRAINT app_api_resources_owner_fk FOREIGN KEY (owner_principal_pk)
        REFERENCES public.iam_principals (principal_pk) ON DELETE RESTRICT,
    CONSTRAINT app_api_resources_audience_ck
        CHECK (pg_catalog.length(audience) BETWEEN 3 AND 512 AND audience !~ '[[:space:]]'),
    CONSTRAINT app_api_resources_name_ck CHECK (pg_catalog.length(display_name) BETWEEN 1 AND 200),
    CONSTRAINT app_api_resources_profile_ck CHECK (token_profile IN ('SP1', 'SP2', 'SP3', 'SP4', 'SP5')),
    CONSTRAINT app_api_resources_sla_ck CHECK (revocation_sla_seconds BETWEEN 1 AND 3600),
    CONSTRAINT app_api_resources_status_ck CHECK (status IN ('ACTIVE', 'SUSPENDED', 'RETIRED')),
    CONSTRAINT app_api_resources_row_version_ck CHECK (row_version > 0),
    CONSTRAINT app_api_resources_time_ck CHECK (updated_at >= created_at)
);

COMMENT ON TABLE public.app_api_resources IS
    'Protected API resource with globally unique audience, token Profile, owner, and revocation SLA; S1.';
CREATE INDEX app_api_resources_status_idx ON public.app_api_resources (status, api_resource_pk);

CREATE TABLE public.app_api_scopes (
    api_scope_pk bigint GENERATED ALWAYS AS IDENTITY,
    api_scope_id uuid NOT NULL DEFAULT pg_catalog.gen_random_uuid(),
    api_resource_pk bigint NOT NULL,
    scope_code text COLLATE "C" NOT NULL,
    display_name text NOT NULL,
    risk_level text COLLATE "C" NOT NULL,
    consent_required boolean NOT NULL DEFAULT false,
    status text COLLATE "C" NOT NULL DEFAULT 'ACTIVE',
    created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    retired_at timestamptz,
    CONSTRAINT app_api_scopes_pkey PRIMARY KEY (api_scope_pk),
    CONSTRAINT app_api_scopes_id_key UNIQUE (api_scope_id),
    CONSTRAINT app_api_scopes_resource_code_key UNIQUE (api_resource_pk, scope_code),
    CONSTRAINT app_api_scopes_resource_pk_key UNIQUE (api_resource_pk, api_scope_pk),
    CONSTRAINT app_api_scopes_id_v4_ck CHECK (public.iam_uuid_is_v4(api_scope_id)),
    CONSTRAINT app_api_scopes_resource_fk FOREIGN KEY (api_resource_pk)
        REFERENCES public.app_api_resources (api_resource_pk) ON DELETE RESTRICT,
    CONSTRAINT app_api_scopes_code_ck
        CHECK (pg_catalog.length(scope_code) BETWEEN 1 AND 128
               AND scope_code ~ '^[A-Za-z0-9][A-Za-z0-9._:/-]*$'),
    CONSTRAINT app_api_scopes_name_ck CHECK (pg_catalog.length(display_name) BETWEEN 1 AND 200),
    CONSTRAINT app_api_scopes_risk_ck CHECK (risk_level IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    CONSTRAINT app_api_scopes_status_ck CHECK (status IN ('ACTIVE', 'RETIRED')),
    CONSTRAINT app_api_scopes_retired_ck CHECK ((status = 'RETIRED') = (retired_at IS NOT NULL)),
    CONSTRAINT app_api_scopes_time_ck CHECK (retired_at IS NULL OR retired_at >= created_at)
);

COMMENT ON TABLE public.app_api_scopes IS
    'Permanent API scope catalog under an API Resource with risk and Consent metadata; S1.';
CREATE INDEX app_api_scopes_resource_status_idx
    ON public.app_api_scopes (api_resource_pk, status);

CREATE TABLE public.app_client_scope_permissions (
    client_scope_permission_pk bigint GENERATED ALWAYS AS IDENTITY,
    client_pk bigint NOT NULL,
    api_scope_pk bigint NOT NULL,
    status text COLLATE "C" NOT NULL DEFAULT 'ACTIVE',
    max_authorization_age_seconds integer,
    granted_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    revoked_at timestamptz,
    CONSTRAINT app_client_scope_permissions_pkey PRIMARY KEY (client_scope_permission_pk),
    CONSTRAINT app_client_scope_permissions_pair_key UNIQUE (client_pk, api_scope_pk),
    CONSTRAINT app_client_scope_permissions_client_fk FOREIGN KEY (client_pk)
        REFERENCES public.app_clients (client_pk) ON DELETE RESTRICT,
    CONSTRAINT app_client_scope_permissions_scope_fk FOREIGN KEY (api_scope_pk)
        REFERENCES public.app_api_scopes (api_scope_pk) ON DELETE RESTRICT,
    CONSTRAINT app_client_scope_permissions_status_ck CHECK (status IN ('ACTIVE', 'REVOKED')),
    CONSTRAINT app_client_scope_permissions_age_ck
        CHECK (max_authorization_age_seconds IS NULL OR max_authorization_age_seconds BETWEEN 1 AND 86400),
    CONSTRAINT app_client_scope_permissions_revoked_ck
        CHECK ((status = 'REVOKED') = (revoked_at IS NOT NULL)),
    CONSTRAINT app_client_scope_permissions_time_ck CHECK (revoked_at IS NULL OR revoked_at >= granted_at)
);

COMMENT ON TABLE public.app_client_scope_permissions IS
    'Explicit Client-to-API-scope allowlist; absence means deny; S2.';
CREATE INDEX app_client_scope_permissions_scope_idx
    ON public.app_client_scope_permissions (api_scope_pk, status);

CREATE TABLE public.app_machine_principals (
    machine_pk bigint NOT NULL,
    machine_id uuid NOT NULL DEFAULT pg_catalog.gen_random_uuid(),
    machine_type text COLLATE "C" NOT NULL,
    environment text COLLATE "C" NOT NULL,
    purpose text NOT NULL,
    status text COLLATE "C" NOT NULL DEFAULT 'PROVISIONING',
    security_epoch bigint NOT NULL DEFAULT 1,
    expires_at timestamptz NOT NULL,
    last_used_at timestamptz,
    row_version bigint NOT NULL DEFAULT 1,
    created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    CONSTRAINT app_machine_principals_pkey PRIMARY KEY (machine_pk),
    CONSTRAINT app_machine_principals_id_key UNIQUE (machine_id),
    CONSTRAINT app_machine_principals_id_v4_ck CHECK (public.iam_uuid_is_v4(machine_id)),
    CONSTRAINT app_machine_principals_principal_fk FOREIGN KEY (machine_pk)
        REFERENCES public.iam_principals (principal_pk) ON DELETE RESTRICT,
    CONSTRAINT app_machine_principals_type_ck
        CHECK (machine_type IN ('SERVICE_ACCOUNT', 'WORKLOAD', 'ROBOT', 'AGENT', 'DEVICE', 'CI_CD')),
    CONSTRAINT app_machine_principals_environment_ck
        CHECK (environment IN ('DEVELOPMENT', 'TEST', 'STAGING', 'PRODUCTION')),
    CONSTRAINT app_machine_principals_purpose_ck CHECK (pg_catalog.length(purpose) BETWEEN 1 AND 512),
    CONSTRAINT app_machine_principals_status_ck
        CHECK (status IN ('PROVISIONING', 'ACTIVE', 'SUSPENDED', 'COMPROMISED', 'RETIRED')),
    CONSTRAINT app_machine_principals_security_epoch_ck CHECK (security_epoch > 0),
    CONSTRAINT app_machine_principals_row_version_ck CHECK (row_version > 0),
    CONSTRAINT app_machine_principals_time_ck CHECK (
        updated_at >= created_at AND expires_at > created_at
        AND (last_used_at IS NULL OR last_used_at >= created_at)
    )
);

COMMENT ON TABLE public.app_machine_principals IS
    'MACHINE principal extension with purpose, environment, expiry, last use, state, and monotonic security epoch; S2.';
CREATE INDEX app_machine_principals_status_expiry_idx
    ON public.app_machine_principals (status, expires_at);

CREATE TABLE public.app_machine_owners (
    machine_owner_pk bigint GENERATED ALWAYS AS IDENTITY,
    machine_pk bigint NOT NULL,
    owner_principal_pk bigint,
    external_team_reference_digest bytea,
    owner_role text COLLATE "C" NOT NULL,
    status text COLLATE "C" NOT NULL DEFAULT 'ACTIVE',
    valid_from timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    valid_until timestamptz,
    CONSTRAINT app_machine_owners_pkey PRIMARY KEY (machine_owner_pk),
    CONSTRAINT app_machine_owners_machine_fk FOREIGN KEY (machine_pk)
        REFERENCES public.app_machine_principals (machine_pk) ON DELETE RESTRICT,
    CONSTRAINT app_machine_owners_owner_fk FOREIGN KEY (owner_principal_pk)
        REFERENCES public.iam_principals (principal_pk) ON DELETE RESTRICT,
    CONSTRAINT app_machine_owners_target_ck CHECK (
        (owner_principal_pk IS NOT NULL)::integer
        + (external_team_reference_digest IS NOT NULL)::integer = 1
        AND (external_team_reference_digest IS NULL
             OR pg_catalog.octet_length(external_team_reference_digest) = 32)
    ),
    CONSTRAINT app_machine_owners_role_ck CHECK (owner_role IN ('PRIMARY', 'TECHNICAL', 'SECURITY')),
    CONSTRAINT app_machine_owners_status_ck CHECK (status IN ('ACTIVE', 'REVOKED')),
    CONSTRAINT app_machine_owners_time_ck CHECK (
        valid_until IS NULL OR valid_until > valid_from
    )
);

COMMENT ON TABLE public.app_machine_owners IS
    'Human principal or external team accountability for machine identities; production PRIMARY-owner existence is deferred to 110; S2.';
CREATE UNIQUE INDEX app_machine_owners_active_primary_uidx
    ON public.app_machine_owners (machine_pk)
    WHERE owner_role = 'PRIMARY' AND status = 'ACTIVE' AND valid_until IS NULL;
CREATE INDEX app_machine_owners_owner_idx
    ON public.app_machine_owners (owner_principal_pk) WHERE owner_principal_pk IS NOT NULL;

CREATE TABLE public.app_workload_trusts (
    workload_trust_pk bigint GENERATED ALWAYS AS IDENTITY,
    workload_trust_id uuid NOT NULL DEFAULT pg_catalog.gen_random_uuid(),
    machine_pk bigint NOT NULL,
    trust_domain_digest bytea NOT NULL,
    issuer_digest bytea NOT NULL,
    audience_digest bytea NOT NULL,
    digest_key_ref text COLLATE "C" NOT NULL,
    digest_key_version integer NOT NULL,
    environment text COLLATE "C" NOT NULL,
    max_attestation_age_seconds integer NOT NULL,
    trust_bundle_version bigint NOT NULL,
    status text COLLATE "C" NOT NULL DEFAULT 'ACTIVE',
    not_before timestamptz NOT NULL,
    not_after timestamptz NOT NULL,
    row_version bigint NOT NULL DEFAULT 1,
    created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    CONSTRAINT app_workload_trusts_pkey PRIMARY KEY (workload_trust_pk),
    CONSTRAINT app_workload_trusts_id_key UNIQUE (workload_trust_id),
    CONSTRAINT app_workload_trusts_id_v4_ck CHECK (public.iam_uuid_is_v4(workload_trust_id)),
    CONSTRAINT app_workload_trusts_machine_fk FOREIGN KEY (machine_pk)
        REFERENCES public.app_machine_principals (machine_pk) ON DELETE RESTRICT,
    CONSTRAINT app_workload_trusts_digest_ck CHECK (
        pg_catalog.octet_length(trust_domain_digest) = 32
        AND pg_catalog.octet_length(issuer_digest) = 32
        AND pg_catalog.octet_length(audience_digest) = 32
        AND pg_catalog.length(digest_key_ref) BETWEEN 1 AND 512
        AND digest_key_version > 0
    ),
    CONSTRAINT app_workload_trusts_environment_ck
        CHECK (environment IN ('DEVELOPMENT', 'TEST', 'STAGING', 'PRODUCTION')),
    CONSTRAINT app_workload_trusts_age_ck CHECK (max_attestation_age_seconds BETWEEN 1 AND 600),
    CONSTRAINT app_workload_trusts_bundle_ck CHECK (trust_bundle_version > 0),
    CONSTRAINT app_workload_trusts_status_ck
        CHECK (status IN ('ACTIVE', 'SUSPENDED', 'REVOKED', 'RETIRED')),
    CONSTRAINT app_workload_trusts_row_version_ck CHECK (row_version > 0),
    CONSTRAINT app_workload_trusts_time_ck CHECK (
        not_after > not_before AND updated_at >= created_at
    )
);

COMMENT ON TABLE public.app_workload_trusts IS
    'Versioned workload-federation trust domain, issuer, audience, environment and proof-age policy using keyed digests; S3.';
CREATE INDEX app_workload_trusts_machine_status_idx
    ON public.app_workload_trusts (machine_pk, status);

CREATE TABLE public.app_workload_selectors (
    workload_selector_pk bigint GENERATED ALWAYS AS IDENTITY,
    workload_trust_pk bigint NOT NULL,
    selector_type text COLLATE "C" NOT NULL,
    selector_hash bytea NOT NULL,
    selector_schema_version integer NOT NULL,
    selector jsonb NOT NULL,
    status text COLLATE "C" NOT NULL DEFAULT 'ACTIVE',
    created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    retired_at timestamptz,
    CONSTRAINT app_workload_selectors_pkey PRIMARY KEY (workload_selector_pk),
    CONSTRAINT app_workload_selectors_hash_key
        UNIQUE (workload_trust_pk, selector_type, selector_hash),
    CONSTRAINT app_workload_selectors_trust_fk FOREIGN KEY (workload_trust_pk)
        REFERENCES public.app_workload_trusts (workload_trust_pk) ON DELETE RESTRICT,
    CONSTRAINT app_workload_selectors_type_ck
        CHECK (selector_type IN ('SPIFFE', 'KUBERNETES', 'AWS', 'AZURE', 'GCP', 'GITHUB_ACTIONS', 'CUSTOM')),
    CONSTRAINT app_workload_selectors_hash_ck CHECK (pg_catalog.octet_length(selector_hash) = 32),
    CONSTRAINT app_workload_selectors_schema_ck CHECK (
        selector_schema_version > 0 AND pg_catalog.jsonb_typeof(selector) = 'object'
    ),
    CONSTRAINT app_workload_selectors_status_ck CHECK (status IN ('ACTIVE', 'RETIRED')),
    CONSTRAINT app_workload_selectors_retired_ck CHECK ((status = 'RETIRED') = (retired_at IS NOT NULL)),
    CONSTRAINT app_workload_selectors_time_ck CHECK (retired_at IS NULL OR retired_at >= created_at)
);

COMMENT ON TABLE public.app_workload_selectors IS
    'Relational workload selector entries with canonical hash and versioned JSON schema; schema validation occurs at controlled publication; S3.';

CREATE TABLE public.app_workload_attestations (
    workload_attestation_pk bigint GENERATED ALWAYS AS IDENTITY,
    workload_attestation_id uuid NOT NULL DEFAULT pg_catalog.gen_random_uuid(),
    workload_trust_pk bigint NOT NULL,
    machine_pk bigint NOT NULL,
    assertion_digest bytea NOT NULL,
    nonce_digest bytea,
    jti_digest bytea,
    state text COLLATE "C" NOT NULL DEFAULT 'RECEIVED',
    received_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    asserted_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    verified_at timestamptz,
    credential_issued_at timestamptz,
    rejection_reason text COLLATE "C",
    CONSTRAINT app_workload_attestations_pkey PRIMARY KEY (workload_attestation_pk),
    CONSTRAINT app_workload_attestations_id_key UNIQUE (workload_attestation_id),
    CONSTRAINT app_workload_attestations_id_v4_ck CHECK (public.iam_uuid_is_v4(workload_attestation_id)),
    CONSTRAINT app_workload_attestations_trust_fk FOREIGN KEY (workload_trust_pk)
        REFERENCES public.app_workload_trusts (workload_trust_pk) ON DELETE RESTRICT,
    CONSTRAINT app_workload_attestations_machine_fk FOREIGN KEY (machine_pk)
        REFERENCES public.app_machine_principals (machine_pk) ON DELETE RESTRICT,
    CONSTRAINT app_workload_attestations_digest_ck CHECK (
        pg_catalog.octet_length(assertion_digest) = 32
        AND (nonce_digest IS NULL OR pg_catalog.octet_length(nonce_digest) = 32)
        AND (jti_digest IS NULL OR pg_catalog.octet_length(jti_digest) = 32)
        AND (nonce_digest IS NOT NULL OR jti_digest IS NOT NULL)
    ),
    CONSTRAINT app_workload_attestations_state_ck CHECK (
        state IN ('RECEIVED', 'VERIFIED', 'CREDENTIAL_ISSUED', 'REJECTED', 'EXPIRED', 'REVOKED')
    ),
    CONSTRAINT app_workload_attestations_verified_ck CHECK (
        (state IN ('VERIFIED', 'CREDENTIAL_ISSUED')) = (verified_at IS NOT NULL)
    ),
    CONSTRAINT app_workload_attestations_issued_ck CHECK (
        (state = 'CREDENTIAL_ISSUED') = (credential_issued_at IS NOT NULL)
    ),
    CONSTRAINT app_workload_attestations_rejected_ck CHECK (
        (state = 'REJECTED') = (rejection_reason IS NOT NULL)
    ),
    CONSTRAINT app_workload_attestations_time_ck CHECK (
        asserted_at <= received_at AND expires_at > received_at
        AND (verified_at IS NULL OR verified_at >= received_at)
        AND (credential_issued_at IS NULL OR credential_issued_at >= verified_at)
    )
);

COMMENT ON TABLE public.app_workload_attestations IS
    'Per-attempt workload proof state and short-lived credential issuance evidence; complete assertions and credentials are never stored; S3.';
CREATE INDEX app_workload_attestations_machine_time_idx
    ON public.app_workload_attestations (machine_pk, received_at DESC);

CREATE TABLE public.app_attestation_replays (
    attestation_replay_pk bigint GENERATED ALWAYS AS IDENTITY,
    replay_kind text COLLATE "C" NOT NULL,
    principal_pk bigint NOT NULL,
    client_pk bigint,
    endpoint_digest bytea NOT NULL,
    environment text COLLATE "C" NOT NULL,
    issuer_digest bytea NOT NULL,
    jti_digest bytea NOT NULL,
    digest_key_ref text COLLATE "C" NOT NULL,
    digest_key_version integer NOT NULL,
    received_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    expires_at timestamptz NOT NULL,
    CONSTRAINT app_attestation_replays_pkey PRIMARY KEY (attestation_replay_pk),
    CONSTRAINT app_attestation_replays_key
        UNIQUE NULLS NOT DISTINCT
        (replay_kind, principal_pk, client_pk, endpoint_digest,
         environment, digest_key_version, jti_digest),
    CONSTRAINT app_attestation_replays_principal_fk FOREIGN KEY (principal_pk)
        REFERENCES public.iam_principals (principal_pk) ON DELETE RESTRICT,
    CONSTRAINT app_attestation_replays_client_fk FOREIGN KEY (client_pk)
        REFERENCES public.app_clients (client_pk) ON DELETE RESTRICT,
    CONSTRAINT app_attestation_replays_kind_ck
        CHECK (replay_kind IN ('WORKLOAD_ATTESTATION', 'CLIENT_ASSERTION')),
    CONSTRAINT app_attestation_replays_binding_ck CHECK (
        (replay_kind = 'CLIENT_ASSERTION' AND client_pk IS NOT NULL)
        OR replay_kind = 'WORKLOAD_ATTESTATION'
    ),
    CONSTRAINT app_attestation_replays_environment_ck
        CHECK (environment IN ('DEVELOPMENT', 'TEST', 'STAGING', 'PRODUCTION')),
    CONSTRAINT app_attestation_replays_digest_ck CHECK (
        pg_catalog.octet_length(endpoint_digest) = 32
        AND pg_catalog.octet_length(issuer_digest) = 32
        AND pg_catalog.octet_length(jti_digest) = 32
        AND pg_catalog.length(digest_key_ref) BETWEEN 1 AND 512
        AND digest_key_version > 0
    ),
    CONSTRAINT app_attestation_replays_expiry_ck CHECK (
        expires_at > received_at AND expires_at <= received_at + interval '10 minutes'
    )
);

COMMENT ON TABLE public.app_attestation_replays IS
    'Endpoint-, environment-, principal-, and Client-bound JTI replay registry for workload proofs and private_key_jwt assertions; S3.';
CREATE INDEX app_attestation_replays_expiry_idx
    ON public.app_attestation_replays (expires_at, attestation_replay_pk);

-- Resolve the deliberate 040/050 forward references now that Client, URI,
-- API Resource, and API Scope tables exist. All deletes remain restrictive.
ALTER TABLE public.auth_transactions
    ADD CONSTRAINT auth_transactions_client_fk
    FOREIGN KEY (client_pk) REFERENCES public.app_clients (client_pk) ON DELETE RESTRICT;

ALTER TABLE public.auth_challenges
    ADD CONSTRAINT auth_challenges_client_fk
    FOREIGN KEY (client_pk) REFERENCES public.app_clients (client_pk) ON DELETE RESTRICT;

ALTER TABLE public.oauth_rp_sessions
    ADD CONSTRAINT oauth_rp_sessions_client_fk
        FOREIGN KEY (client_pk) REFERENCES public.app_clients (client_pk) ON DELETE RESTRICT,
    ADD CONSTRAINT oauth_rp_sessions_front_uri_fk
        FOREIGN KEY (client_pk, frontchannel_logout_uri_pk)
        REFERENCES public.app_client_uris (client_pk, client_uri_pk) ON DELETE RESTRICT,
    ADD CONSTRAINT oauth_rp_sessions_back_uri_fk
        FOREIGN KEY (client_pk, backchannel_logout_uri_pk)
        REFERENCES public.app_client_uris (client_pk, client_uri_pk) ON DELETE RESTRICT;

ALTER TABLE public.oauth_pairwise_subjects
    ADD CONSTRAINT oauth_pairwise_subjects_client_fk
    FOREIGN KEY (client_pk) REFERENCES public.app_clients (client_pk) ON DELETE RESTRICT;

ALTER TABLE public.oauth_grants
    ADD CONSTRAINT oauth_grants_client_fk
    FOREIGN KEY (client_pk) REFERENCES public.app_clients (client_pk) ON DELETE RESTRICT;

ALTER TABLE public.oauth_grant_resources
    ADD CONSTRAINT oauth_grant_resources_resource_fk
    FOREIGN KEY (resource_pk) REFERENCES public.app_api_resources (api_resource_pk) ON DELETE RESTRICT;

ALTER TABLE public.oauth_grant_scopes
    ADD CONSTRAINT oauth_grant_scopes_resource_fk
        FOREIGN KEY (resource_pk) REFERENCES public.app_api_resources (api_resource_pk) ON DELETE RESTRICT,
    ADD CONSTRAINT oauth_grant_scopes_scope_resource_fk
        FOREIGN KEY (resource_pk, scope_pk)
        REFERENCES public.app_api_scopes (api_resource_pk, api_scope_pk) ON DELETE RESTRICT;

ALTER TABLE public.oauth_authorization_codes
    ADD CONSTRAINT oauth_authorization_codes_client_fk
        FOREIGN KEY (client_pk) REFERENCES public.app_clients (client_pk) ON DELETE RESTRICT,
    ADD CONSTRAINT oauth_authorization_codes_redirect_uri_fk
        FOREIGN KEY (client_pk, redirect_uri_pk)
        REFERENCES public.app_client_uris (client_pk, client_uri_pk) ON DELETE RESTRICT;

ALTER TABLE public.oauth_token_families
    ADD CONSTRAINT oauth_token_families_client_fk
    FOREIGN KEY (client_pk) REFERENCES public.app_clients (client_pk) ON DELETE RESTRICT;

ALTER TABLE public.oauth_access_token_records
    ADD CONSTRAINT oauth_access_token_records_client_fk
        FOREIGN KEY (client_pk) REFERENCES public.app_clients (client_pk) ON DELETE RESTRICT,
    ADD CONSTRAINT oauth_access_token_records_resource_fk
        FOREIGN KEY (resource_pk) REFERENCES public.app_api_resources (api_resource_pk) ON DELETE RESTRICT;

ALTER TABLE public.oauth_token_exchanges
    ADD CONSTRAINT oauth_token_exchanges_client_fk
        FOREIGN KEY (client_pk) REFERENCES public.app_clients (client_pk) ON DELETE RESTRICT,
    ADD CONSTRAINT oauth_token_exchanges_source_resource_fk
        FOREIGN KEY (source_resource_pk) REFERENCES public.app_api_resources (api_resource_pk) ON DELETE RESTRICT,
    ADD CONSTRAINT oauth_token_exchanges_target_resource_fk
        FOREIGN KEY (target_resource_pk) REFERENCES public.app_api_resources (api_resource_pk) ON DELETE RESTRICT;

COMMIT;
