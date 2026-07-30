-- Devices, sessions, grants, authorization codes, token families, revocation, and delegation.
-- Client/resource/scope references are positive bigint placeholders until their 060 tables exist.

BEGIN;

CREATE TABLE public.oauth_devices (
    device_pk bigint GENERATED ALWAYS AS IDENTITY,
    device_id uuid NOT NULL DEFAULT pg_catalog.gen_random_uuid(),
    principal_pk bigint NOT NULL,
    device_identifier_digest bytea NOT NULL,
    digest_key_ref text COLLATE "C" NOT NULL,
    digest_key_version integer NOT NULL,
    display_name_ciphertext bytea,
    encryption_key_ref text COLLATE "C",
    encryption_key_version integer,
    trust_state text COLLATE "C" NOT NULL DEFAULT 'UNTRUSTED',
    first_seen_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    last_seen_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    trusted_at timestamptz,
    revoked_at timestamptz,
    row_version bigint NOT NULL DEFAULT 1,
    CONSTRAINT oauth_devices_pkey PRIMARY KEY (device_pk),
    CONSTRAINT oauth_devices_id_key UNIQUE (device_id),
    CONSTRAINT oauth_devices_owner_digest_key
        UNIQUE (principal_pk, digest_key_version, device_identifier_digest),
    CONSTRAINT oauth_devices_id_v4_ck CHECK (public.iam_uuid_is_v4(device_id)),
    CONSTRAINT oauth_devices_principal_fk FOREIGN KEY (principal_pk)
        REFERENCES public.iam_principals (principal_pk) ON DELETE RESTRICT,
    CONSTRAINT oauth_devices_digest_ck CHECK (
        pg_catalog.octet_length(device_identifier_digest) = 32
        AND pg_catalog.length(digest_key_ref) BETWEEN 1 AND 512
        AND digest_key_version > 0
    ),
    CONSTRAINT oauth_devices_cipher_ck CHECK (
        (display_name_ciphertext IS NULL AND encryption_key_ref IS NULL AND encryption_key_version IS NULL)
        OR (pg_catalog.octet_length(display_name_ciphertext) >= 28
            AND pg_catalog.length(encryption_key_ref) BETWEEN 1 AND 512
            AND encryption_key_version > 0)
    ),
    CONSTRAINT oauth_devices_trust_ck
        CHECK (trust_state IN ('UNTRUSTED', 'TRUSTED', 'SUSPICIOUS', 'REVOKED')),
    CONSTRAINT oauth_devices_trusted_time_ck
        CHECK ((trust_state = 'TRUSTED') = (trusted_at IS NOT NULL)),
    CONSTRAINT oauth_devices_revoked_time_ck
        CHECK ((trust_state = 'REVOKED') = (revoked_at IS NOT NULL)),
    CONSTRAINT oauth_devices_row_version_ck CHECK (row_version > 0),
    CONSTRAINT oauth_devices_time_ck CHECK (
        last_seen_at >= first_seen_at
        AND (trusted_at IS NULL OR trusted_at >= first_seen_at)
        AND (revoked_at IS NULL OR revoked_at >= first_seen_at)
    )
);

COMMENT ON TABLE public.oauth_devices IS
    'Principal-owned device registry using keyed device digest and optional encrypted display name; S3.';
CREATE INDEX oauth_devices_principal_state_idx
    ON public.oauth_devices (principal_pk, trust_state, last_seen_at DESC);

CREATE TABLE public.oauth_sessions (
    session_pk bigint GENERATED ALWAYS AS IDENTITY,
    session_id uuid NOT NULL DEFAULT pg_catalog.gen_random_uuid(),
    principal_pk bigint NOT NULL,
    user_pk bigint,
    tenant_pk bigint,
    device_pk bigint,
    auth_context_pk bigint,
    state text COLLATE "C" NOT NULL DEFAULT 'ACTIVE',
    network_address inet,
    device_binding_digest bytea,
    user_security_epoch_snapshot bigint,
    tenant_security_epoch_snapshot bigint,
    started_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    last_activity_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    idle_expires_at timestamptz NOT NULL,
    absolute_expires_at timestamptz NOT NULL,
    compromised_at timestamptz,
    revoked_at timestamptz,
    row_version bigint NOT NULL DEFAULT 1,
    CONSTRAINT oauth_sessions_pkey PRIMARY KEY (session_pk),
    CONSTRAINT oauth_sessions_id_key UNIQUE (session_id),
    CONSTRAINT oauth_sessions_id_v4_ck CHECK (public.iam_uuid_is_v4(session_id)),
    CONSTRAINT oauth_sessions_principal_fk FOREIGN KEY (principal_pk)
        REFERENCES public.iam_principals (principal_pk) ON DELETE RESTRICT,
    CONSTRAINT oauth_sessions_user_fk FOREIGN KEY (user_pk)
        REFERENCES public.iam_users (user_pk) ON DELETE RESTRICT,
    CONSTRAINT oauth_sessions_tenant_fk FOREIGN KEY (tenant_pk)
        REFERENCES public.org_tenants (tenant_pk) ON DELETE RESTRICT,
    CONSTRAINT oauth_sessions_device_fk FOREIGN KEY (device_pk)
        REFERENCES public.oauth_devices (device_pk) ON DELETE RESTRICT,
    CONSTRAINT oauth_sessions_auth_context_fk FOREIGN KEY (auth_context_pk)
        REFERENCES public.auth_contexts (auth_context_pk) ON DELETE RESTRICT,
    CONSTRAINT oauth_sessions_subject_shape_ck CHECK (
        (user_pk IS NOT NULL AND auth_context_pk IS NOT NULL)
        OR (user_pk IS NULL AND auth_context_pk IS NULL)
    ),
    CONSTRAINT oauth_sessions_state_ck
        CHECK (state IN ('ACTIVE', 'COMPROMISED', 'EXPIRED', 'REVOKED')),
    CONSTRAINT oauth_sessions_binding_ck
        CHECK (device_binding_digest IS NULL OR pg_catalog.octet_length(device_binding_digest) = 32),
    CONSTRAINT oauth_sessions_epoch_ck CHECK (
        (user_security_epoch_snapshot IS NULL OR user_security_epoch_snapshot > 0)
        AND (tenant_security_epoch_snapshot IS NULL OR tenant_security_epoch_snapshot > 0)
    ),
    CONSTRAINT oauth_sessions_user_epoch_ck CHECK (
        (user_pk IS NULL AND user_security_epoch_snapshot IS NULL)
        OR (user_pk IS NOT NULL AND user_security_epoch_snapshot IS NOT NULL)
    ),
    CONSTRAINT oauth_sessions_tenant_epoch_ck CHECK (
        (tenant_pk IS NULL AND tenant_security_epoch_snapshot IS NULL)
        OR (tenant_pk IS NOT NULL AND tenant_security_epoch_snapshot IS NOT NULL)
    ),
    CONSTRAINT oauth_sessions_compromised_ck CHECK (
        (state <> 'COMPROMISED' OR compromised_at IS NOT NULL)
        AND (compromised_at IS NULL OR state IN ('COMPROMISED', 'REVOKED'))
    ),
    CONSTRAINT oauth_sessions_revoked_ck
        CHECK ((state = 'REVOKED') = (revoked_at IS NOT NULL)),
    CONSTRAINT oauth_sessions_row_version_ck CHECK (row_version > 0),
    CONSTRAINT oauth_sessions_time_ck CHECK (
        last_activity_at >= started_at
        AND idle_expires_at > last_activity_at
        AND absolute_expires_at >= idle_expires_at
        AND (compromised_at IS NULL OR compromised_at >= started_at)
        AND (revoked_at IS NULL OR revoked_at >= started_at)
    )
);

COMMENT ON TABLE public.oauth_sessions IS
    'USER sessions carry matching user/authentication context; MACHINE sessions carry neither. Principal/device consistency is enforced in 110; S3.';
CREATE INDEX oauth_sessions_principal_state_idx
    ON public.oauth_sessions (principal_pk, state, last_activity_at DESC);
CREATE INDEX oauth_sessions_active_expiry_idx
    ON public.oauth_sessions (absolute_expires_at, session_pk) WHERE state = 'ACTIVE';
CREATE INDEX oauth_sessions_device_state_idx
    ON public.oauth_sessions (device_pk, state) WHERE device_pk IS NOT NULL;

CREATE TABLE public.oauth_rp_sessions (
    rp_session_pk bigint GENERATED ALWAYS AS IDENTITY,
    rp_session_id uuid NOT NULL DEFAULT pg_catalog.gen_random_uuid(),
    session_pk bigint NOT NULL,
    client_pk bigint NOT NULL,
    sid_digest bytea NOT NULL,
    sid_key_ref text COLLATE "C" NOT NULL,
    sid_key_version integer NOT NULL,
    frontchannel_logout_uri_pk bigint,
    backchannel_logout_uri_pk bigint,
    status text COLLATE "C" NOT NULL DEFAULT 'ACTIVE',
    created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    ended_at timestamptz,
    CONSTRAINT oauth_rp_sessions_pkey PRIMARY KEY (rp_session_pk),
    CONSTRAINT oauth_rp_sessions_id_key UNIQUE (rp_session_id),
    CONSTRAINT oauth_rp_sessions_id_v4_ck CHECK (public.iam_uuid_is_v4(rp_session_id)),
    CONSTRAINT oauth_rp_sessions_session_fk FOREIGN KEY (session_pk)
        REFERENCES public.oauth_sessions (session_pk) ON DELETE RESTRICT,
    CONSTRAINT oauth_rp_sessions_placeholder_ck CHECK (
        client_pk > 0
        AND (frontchannel_logout_uri_pk IS NULL OR frontchannel_logout_uri_pk > 0)
        AND (backchannel_logout_uri_pk IS NULL OR backchannel_logout_uri_pk > 0)
    ),
    CONSTRAINT oauth_rp_sessions_sid_ck CHECK (
        pg_catalog.octet_length(sid_digest) = 32
        AND pg_catalog.length(sid_key_ref) BETWEEN 1 AND 512
        AND sid_key_version > 0
    ),
    CONSTRAINT oauth_rp_sessions_status_ck
        CHECK (status IN ('ACTIVE', 'LOGOUT_PENDING', 'ENDED', 'FAILED')),
    CONSTRAINT oauth_rp_sessions_ended_ck
        CHECK ((status = 'ENDED') = (ended_at IS NOT NULL)),
    CONSTRAINT oauth_rp_sessions_time_ck CHECK (ended_at IS NULL OR ended_at >= created_at)
);

COMMENT ON TABLE public.oauth_rp_sessions IS
    'RP sid mapping and registered front/back-channel logout URI references; Client/URI FKs are added in 060; S3.';
CREATE UNIQUE INDEX oauth_rp_sessions_client_sid_uidx
    ON public.oauth_rp_sessions (client_pk, sid_key_version, sid_digest);
CREATE INDEX oauth_rp_sessions_session_status_idx
    ON public.oauth_rp_sessions (session_pk, status);

CREATE TABLE public.oauth_pairwise_subjects (
    pairwise_subject_pk bigint GENERATED ALWAYS AS IDENTITY,
    subject_id uuid NOT NULL DEFAULT pg_catalog.gen_random_uuid(),
    user_pk bigint NOT NULL,
    client_pk bigint,
    sector_identifier_digest bytea NOT NULL,
    sector_key_ref text COLLATE "C" NOT NULL,
    sector_key_version integer NOT NULL,
    created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    CONSTRAINT oauth_pairwise_subjects_pkey PRIMARY KEY (pairwise_subject_pk),
    CONSTRAINT oauth_pairwise_subjects_id_key UNIQUE (subject_id),
    CONSTRAINT oauth_pairwise_subjects_user_sector_key
        UNIQUE (user_pk, sector_key_version, sector_identifier_digest),
    CONSTRAINT oauth_pairwise_subjects_id_v4_ck CHECK (public.iam_uuid_is_v4(subject_id)),
    CONSTRAINT oauth_pairwise_subjects_user_fk FOREIGN KEY (user_pk)
        REFERENCES public.iam_users (user_pk) ON DELETE RESTRICT,
    CONSTRAINT oauth_pairwise_subjects_client_placeholder_ck CHECK (client_pk IS NULL OR client_pk > 0),
    CONSTRAINT oauth_pairwise_subjects_sector_ck CHECK (
        pg_catalog.octet_length(sector_identifier_digest) = 32
        AND pg_catalog.length(sector_key_ref) BETWEEN 1 AND 512
        AND sector_key_version > 0
    )
);

COMMENT ON TABLE public.oauth_pairwise_subjects IS
    'Permanent UUIDv4 pairwise subject per user and sector; never reassigned after Client retirement; S2.';
CREATE INDEX oauth_pairwise_subjects_client_idx
    ON public.oauth_pairwise_subjects (client_pk) WHERE client_pk IS NOT NULL;

CREATE TABLE public.oauth_grants (
    grant_pk bigint GENERATED ALWAYS AS IDENTITY,
    grant_id uuid NOT NULL DEFAULT pg_catalog.gen_random_uuid(),
    principal_pk bigint NOT NULL,
    client_pk bigint NOT NULL,
    tenant_pk bigint,
    session_pk bigint,
    state text COLLATE "C" NOT NULL DEFAULT 'PENDING',
    authorization_method text COLLATE "C" NOT NULL,
    user_security_epoch_snapshot bigint,
    client_security_epoch_snapshot bigint NOT NULL,
    tenant_security_epoch_snapshot bigint,
    consent_epoch_snapshot bigint,
    valid_from timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    valid_until timestamptz,
    revoked_at timestamptz,
    row_version bigint NOT NULL DEFAULT 1,
    created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    CONSTRAINT oauth_grants_pkey PRIMARY KEY (grant_pk),
    CONSTRAINT oauth_grants_id_key UNIQUE (grant_id),
    CONSTRAINT oauth_grants_id_v4_ck CHECK (public.iam_uuid_is_v4(grant_id)),
    CONSTRAINT oauth_grants_principal_fk FOREIGN KEY (principal_pk)
        REFERENCES public.iam_principals (principal_pk) ON DELETE RESTRICT,
    CONSTRAINT oauth_grants_tenant_fk FOREIGN KEY (tenant_pk)
        REFERENCES public.org_tenants (tenant_pk) ON DELETE RESTRICT,
    CONSTRAINT oauth_grants_session_fk FOREIGN KEY (session_pk)
        REFERENCES public.oauth_sessions (session_pk) ON DELETE RESTRICT,
    CONSTRAINT oauth_grants_client_placeholder_ck CHECK (client_pk > 0),
    CONSTRAINT oauth_grants_state_ck CHECK (state IN ('PENDING', 'ACTIVE', 'REVOKED', 'EXPIRED')),
    CONSTRAINT oauth_grants_method_ck
        CHECK (authorization_method IN ('AUTHORIZATION_CODE', 'CLIENT_CREDENTIALS', 'TOKEN_EXCHANGE', 'DEVICE_CODE')),
    CONSTRAINT oauth_grants_epoch_ck CHECK (
        (user_security_epoch_snapshot IS NULL OR user_security_epoch_snapshot > 0)
        AND client_security_epoch_snapshot > 0
        AND (tenant_security_epoch_snapshot IS NULL OR tenant_security_epoch_snapshot > 0)
        AND (consent_epoch_snapshot IS NULL OR consent_epoch_snapshot > 0)
    ),
    CONSTRAINT oauth_grants_tenant_epoch_ck CHECK (
        (tenant_pk IS NULL AND tenant_security_epoch_snapshot IS NULL)
        OR (tenant_pk IS NOT NULL AND tenant_security_epoch_snapshot IS NOT NULL)
    ),
    CONSTRAINT oauth_grants_revoked_ck CHECK ((state = 'REVOKED') = (revoked_at IS NOT NULL)),
    CONSTRAINT oauth_grants_row_version_ck CHECK (row_version > 0),
    CONSTRAINT oauth_grants_time_ck CHECK (
        updated_at >= created_at
        AND valid_from >= created_at
        AND (valid_until IS NULL OR valid_until > valid_from)
        AND (revoked_at IS NULL OR revoked_at >= valid_from)
    )
);

COMMENT ON TABLE public.oauth_grants IS
    'Principal-to-Client authorization root with user/client/tenant/consent epoch snapshots; Client FK is added in 060; S3.';
CREATE INDEX oauth_grants_principal_client_state_idx
    ON public.oauth_grants (principal_pk, client_pk, state);
CREATE INDEX oauth_grants_active_expiry_idx
    ON public.oauth_grants (valid_until) WHERE state = 'ACTIVE' AND valid_until IS NOT NULL;

CREATE TABLE public.oauth_grant_resources (
    grant_resource_pk bigint GENERATED ALWAYS AS IDENTITY,
    grant_pk bigint NOT NULL,
    resource_pk bigint NOT NULL,
    audience_digest bytea NOT NULL,
    authorization_details_digest bytea,
    CONSTRAINT oauth_grant_resources_pkey PRIMARY KEY (grant_resource_pk),
    CONSTRAINT oauth_grant_resources_pair_key UNIQUE (grant_pk, resource_pk),
    CONSTRAINT oauth_grant_resources_grant_fk FOREIGN KEY (grant_pk)
        REFERENCES public.oauth_grants (grant_pk) ON DELETE RESTRICT,
    CONSTRAINT oauth_grant_resources_placeholder_ck CHECK (resource_pk > 0),
    CONSTRAINT oauth_grant_resources_digest_ck CHECK (
        pg_catalog.octet_length(audience_digest) = 32
        AND (authorization_details_digest IS NULL
             OR pg_catalog.octet_length(authorization_details_digest) = 32)
    )
);

COMMENT ON TABLE public.oauth_grant_resources IS
    'Relational resource audiences authorized by a Grant; API Resource FK is added in 060; S3.';

CREATE TABLE public.oauth_grant_scopes (
    grant_scope_pk bigint GENERATED ALWAYS AS IDENTITY,
    grant_pk bigint NOT NULL,
    resource_pk bigint NOT NULL,
    scope_pk bigint NOT NULL,
    consent_reference_pk bigint,
    scope_evidence_digest bytea NOT NULL,
    CONSTRAINT oauth_grant_scopes_pkey PRIMARY KEY (grant_scope_pk),
    CONSTRAINT oauth_grant_scopes_pair_key UNIQUE (grant_pk, scope_pk),
    CONSTRAINT oauth_grant_scopes_grant_fk FOREIGN KEY (grant_pk)
        REFERENCES public.oauth_grants (grant_pk) ON DELETE RESTRICT,
    CONSTRAINT oauth_grant_scopes_placeholder_ck
        CHECK (resource_pk > 0 AND scope_pk > 0 AND (consent_reference_pk IS NULL OR consent_reference_pk > 0)),
    CONSTRAINT oauth_grant_scopes_evidence_ck
        CHECK (pg_catalog.octet_length(scope_evidence_digest) = 32)
);

COMMENT ON TABLE public.oauth_grant_scopes IS
    'Relational API scopes authorized by a Grant; resource/scope FKs and Client allowlist validation are completed in 060/110; S3.';
CREATE INDEX oauth_grant_scopes_scope_idx ON public.oauth_grant_scopes (scope_pk, grant_pk);

CREATE TABLE public.oauth_authorization_codes (
    authorization_code_pk bigint GENERATED ALWAYS AS IDENTITY,
    authorization_code_id uuid NOT NULL DEFAULT pg_catalog.gen_random_uuid(),
    code_digest bytea NOT NULL,
    pepper_key_ref text COLLATE "C" NOT NULL,
    pepper_key_version integer NOT NULL,
    grant_pk bigint NOT NULL,
    client_pk bigint NOT NULL,
    redirect_uri_pk bigint NOT NULL,
    transaction_pk bigint NOT NULL,
    pkce_method text COLLATE "C" NOT NULL,
    pkce_challenge_digest bytea NOT NULL,
    issued_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz,
    CONSTRAINT oauth_authorization_codes_pkey PRIMARY KEY (authorization_code_pk),
    CONSTRAINT oauth_authorization_codes_id_key UNIQUE (authorization_code_id),
    CONSTRAINT oauth_authorization_codes_digest_key UNIQUE (code_digest),
    CONSTRAINT oauth_authorization_codes_id_v4_ck CHECK (public.iam_uuid_is_v4(authorization_code_id)),
    CONSTRAINT oauth_authorization_codes_grant_fk FOREIGN KEY (grant_pk)
        REFERENCES public.oauth_grants (grant_pk) ON DELETE RESTRICT,
    CONSTRAINT oauth_authorization_codes_transaction_fk FOREIGN KEY (transaction_pk)
        REFERENCES public.auth_transactions (transaction_pk) ON DELETE RESTRICT,
    CONSTRAINT oauth_authorization_codes_placeholder_ck CHECK (client_pk > 0 AND redirect_uri_pk > 0),
    CONSTRAINT oauth_authorization_codes_secret_ck CHECK (
        pg_catalog.octet_length(code_digest) = 32
        AND pg_catalog.length(pepper_key_ref) BETWEEN 1 AND 512
        AND pepper_key_version > 0
    ),
    CONSTRAINT oauth_authorization_codes_pkce_ck CHECK (
        pkce_method = 'S256' AND pg_catalog.octet_length(pkce_challenge_digest) = 32
    ),
    CONSTRAINT oauth_authorization_codes_time_ck CHECK (
        expires_at > issued_at AND (consumed_at IS NULL OR consumed_at BETWEEN issued_at AND expires_at)
    )
);

COMMENT ON TABLE public.oauth_authorization_codes IS
    'Peppered one-time authorization-code digest bound to Grant, Client, exact redirect URI, transaction and PKCE S256; FKs added in 060; S4.';
CREATE INDEX oauth_authorization_codes_open_expiry_idx
    ON public.oauth_authorization_codes (expires_at, authorization_code_pk)
    WHERE consumed_at IS NULL;

CREATE TABLE public.oauth_token_families (
    token_family_pk bigint GENERATED ALWAYS AS IDENTITY,
    family_id uuid NOT NULL DEFAULT pg_catalog.gen_random_uuid(),
    grant_pk bigint NOT NULL,
    client_pk bigint NOT NULL,
    session_pk bigint,
    device_pk bigint,
    state text COLLATE "C" NOT NULL DEFAULT 'ACTIVE',
    binding_type text COLLATE "C" NOT NULL DEFAULT 'NONE',
    binding_digest bytea,
    rotation_counter bigint NOT NULL DEFAULT 0,
    user_security_epoch_snapshot bigint,
    client_security_epoch_snapshot bigint NOT NULL,
    tenant_security_epoch_snapshot bigint,
    created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    expires_at timestamptz NOT NULL,
    compromised_at timestamptz,
    revoked_at timestamptz,
    row_version bigint NOT NULL DEFAULT 1,
    CONSTRAINT oauth_token_families_pkey PRIMARY KEY (token_family_pk),
    CONSTRAINT oauth_token_families_id_key UNIQUE (family_id),
    CONSTRAINT oauth_token_families_id_v4_ck CHECK (public.iam_uuid_is_v4(family_id)),
    CONSTRAINT oauth_token_families_grant_fk FOREIGN KEY (grant_pk)
        REFERENCES public.oauth_grants (grant_pk) ON DELETE RESTRICT,
    CONSTRAINT oauth_token_families_session_fk FOREIGN KEY (session_pk)
        REFERENCES public.oauth_sessions (session_pk) ON DELETE RESTRICT,
    CONSTRAINT oauth_token_families_device_fk FOREIGN KEY (device_pk)
        REFERENCES public.oauth_devices (device_pk) ON DELETE RESTRICT,
    CONSTRAINT oauth_token_families_client_placeholder_ck CHECK (client_pk > 0),
    CONSTRAINT oauth_token_families_state_ck
        CHECK (state IN ('ACTIVE', 'COMPROMISED', 'REVOKED', 'EXPIRED')),
    CONSTRAINT oauth_token_families_binding_ck CHECK (
        binding_type IN ('NONE', 'DEVICE', 'DPOP', 'MTLS')
        AND ((binding_type = 'NONE' AND binding_digest IS NULL)
             OR (binding_type <> 'NONE' AND pg_catalog.octet_length(binding_digest) = 32))
    ),
    CONSTRAINT oauth_token_families_counter_ck CHECK (rotation_counter >= 0),
    CONSTRAINT oauth_token_families_epoch_ck CHECK (
        (user_security_epoch_snapshot IS NULL OR user_security_epoch_snapshot > 0)
        AND client_security_epoch_snapshot > 0
        AND (tenant_security_epoch_snapshot IS NULL OR tenant_security_epoch_snapshot > 0)
    ),
    CONSTRAINT oauth_token_families_compromised_ck CHECK (
        (state <> 'COMPROMISED' OR compromised_at IS NOT NULL)
        AND (compromised_at IS NULL OR state IN ('COMPROMISED', 'REVOKED'))
    ),
    CONSTRAINT oauth_token_families_revoked_ck
        CHECK ((state = 'REVOKED') = (revoked_at IS NOT NULL)),
    CONSTRAINT oauth_token_families_row_version_ck CHECK (row_version > 0),
    CONSTRAINT oauth_token_families_time_ck CHECK (
        expires_at > created_at
        AND (compromised_at IS NULL OR compromised_at >= created_at)
        AND (revoked_at IS NULL OR revoked_at >= created_at)
    )
);

COMMENT ON TABLE public.oauth_token_families IS
    'Refresh-token family bound immutably to Grant, Client, optional session/device/proof and security epoch snapshots; S3.';
CREATE INDEX oauth_token_families_grant_state_idx
    ON public.oauth_token_families (grant_pk, state);
CREATE INDEX oauth_token_families_active_expiry_idx
    ON public.oauth_token_families (expires_at) WHERE state = 'ACTIVE';

CREATE TABLE public.oauth_refresh_tokens (
    refresh_token_pk bigint GENERATED ALWAYS AS IDENTITY,
    refresh_token_id uuid NOT NULL DEFAULT pg_catalog.gen_random_uuid(),
    token_family_pk bigint NOT NULL,
    generation bigint NOT NULL,
    token_digest bytea NOT NULL,
    pepper_key_ref text COLLATE "C" NOT NULL,
    pepper_key_version integer NOT NULL,
    state text COLLATE "C" NOT NULL DEFAULT 'CURRENT',
    issued_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    expires_at timestamptz NOT NULL,
    used_at timestamptz,
    successor_refresh_token_pk bigint,
    retry_binding_digest bytea,
    retry_result_digest bytea,
    retry_until timestamptz,
    CONSTRAINT oauth_refresh_tokens_pkey PRIMARY KEY (refresh_token_pk),
    CONSTRAINT oauth_refresh_tokens_id_key UNIQUE (refresh_token_id),
    CONSTRAINT oauth_refresh_tokens_digest_key UNIQUE (token_digest),
    CONSTRAINT oauth_refresh_tokens_generation_key UNIQUE (token_family_pk, generation),
    CONSTRAINT oauth_refresh_tokens_family_pk_key UNIQUE (token_family_pk, refresh_token_pk),
    CONSTRAINT oauth_refresh_tokens_id_v4_ck CHECK (public.iam_uuid_is_v4(refresh_token_id)),
    CONSTRAINT oauth_refresh_tokens_family_fk FOREIGN KEY (token_family_pk)
        REFERENCES public.oauth_token_families (token_family_pk) ON DELETE RESTRICT,
    CONSTRAINT oauth_refresh_tokens_successor_fk FOREIGN KEY (token_family_pk, successor_refresh_token_pk)
        REFERENCES public.oauth_refresh_tokens (token_family_pk, refresh_token_pk)
        DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT oauth_refresh_tokens_generation_ck CHECK (generation >= 0),
    CONSTRAINT oauth_refresh_tokens_secret_ck CHECK (
        pg_catalog.octet_length(token_digest) = 32
        AND pg_catalog.length(pepper_key_ref) BETWEEN 1 AND 512
        AND pepper_key_version > 0
    ),
    CONSTRAINT oauth_refresh_tokens_state_ck
        CHECK (state IN ('CURRENT', 'USED', 'REVOKED', 'EXPIRED')),
    CONSTRAINT oauth_refresh_tokens_used_ck CHECK (
        (state = 'USED') = (used_at IS NOT NULL)
        AND (state = 'USED') = (successor_refresh_token_pk IS NOT NULL)
    ),
    CONSTRAINT oauth_refresh_tokens_retry_ck CHECK (
        (retry_binding_digest IS NULL AND retry_result_digest IS NULL AND retry_until IS NULL)
        OR (state = 'USED'
            AND pg_catalog.octet_length(retry_binding_digest) = 32
            AND pg_catalog.octet_length(retry_result_digest) = 32
            AND retry_until >= used_at)
    ),
    CONSTRAINT oauth_refresh_tokens_time_ck CHECK (
        expires_at > issued_at AND (used_at IS NULL OR used_at BETWEEN issued_at AND expires_at)
    )
);

COMMENT ON TABLE public.oauth_refresh_tokens IS
    'One-time peppered Refresh Token instances with generation, same-family successor and bounded lost-response retry evidence; S4.';
CREATE UNIQUE INDEX oauth_refresh_tokens_current_family_uidx
    ON public.oauth_refresh_tokens (token_family_pk) WHERE state = 'CURRENT';
CREATE INDEX oauth_refresh_tokens_expiry_idx
    ON public.oauth_refresh_tokens (expires_at) WHERE state = 'CURRENT';

CREATE TABLE public.oauth_access_token_records (
    access_token_record_pk bigint GENERATED ALWAYS AS IDENTITY,
    access_token_record_id uuid NOT NULL DEFAULT pg_catalog.gen_random_uuid(),
    grant_pk bigint NOT NULL,
    token_family_pk bigint,
    client_pk bigint NOT NULL,
    resource_pk bigint NOT NULL,
    issuer_digest bytea NOT NULL,
    jti_digest bytea NOT NULL,
    scope_set_digest bytea NOT NULL,
    sender_constraint_type text COLLATE "C" NOT NULL DEFAULT 'NONE',
    sender_constraint_digest bytea,
    user_security_epoch_snapshot bigint,
    client_security_epoch_snapshot bigint NOT NULL,
    tenant_security_epoch_snapshot bigint,
    consent_epoch_snapshot bigint,
    status text COLLATE "C" NOT NULL DEFAULT 'ACTIVE',
    issued_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    revoked_at timestamptz,
    CONSTRAINT oauth_access_token_records_pkey PRIMARY KEY (access_token_record_pk),
    CONSTRAINT oauth_access_token_records_id_key UNIQUE (access_token_record_id),
    CONSTRAINT oauth_access_token_records_jti_key UNIQUE (issuer_digest, jti_digest),
    CONSTRAINT oauth_access_token_records_id_v4_ck CHECK (public.iam_uuid_is_v4(access_token_record_id)),
    CONSTRAINT oauth_access_token_records_grant_fk FOREIGN KEY (grant_pk)
        REFERENCES public.oauth_grants (grant_pk) ON DELETE RESTRICT,
    CONSTRAINT oauth_access_token_records_family_fk FOREIGN KEY (token_family_pk)
        REFERENCES public.oauth_token_families (token_family_pk) ON DELETE RESTRICT,
    CONSTRAINT oauth_access_token_records_placeholder_ck CHECK (client_pk > 0 AND resource_pk > 0),
    CONSTRAINT oauth_access_token_records_digest_ck CHECK (
        pg_catalog.octet_length(issuer_digest) = 32
        AND pg_catalog.octet_length(jti_digest) = 32
        AND pg_catalog.octet_length(scope_set_digest) = 32
    ),
    CONSTRAINT oauth_access_token_records_sender_ck CHECK (
        sender_constraint_type IN ('NONE', 'DPOP', 'MTLS')
        AND ((sender_constraint_type = 'NONE' AND sender_constraint_digest IS NULL)
             OR (sender_constraint_type <> 'NONE'
                 AND pg_catalog.octet_length(sender_constraint_digest) = 32))
    ),
    CONSTRAINT oauth_access_token_records_epoch_ck CHECK (
        (user_security_epoch_snapshot IS NULL OR user_security_epoch_snapshot > 0)
        AND client_security_epoch_snapshot > 0
        AND (tenant_security_epoch_snapshot IS NULL OR tenant_security_epoch_snapshot > 0)
        AND (consent_epoch_snapshot IS NULL OR consent_epoch_snapshot > 0)
    ),
    CONSTRAINT oauth_access_token_records_status_ck
        CHECK (status IN ('ACTIVE', 'REVOKED', 'EXPIRED')),
    CONSTRAINT oauth_access_token_records_revoked_ck
        CHECK ((status = 'REVOKED') = (revoked_at IS NOT NULL)),
    CONSTRAINT oauth_access_token_records_time_ck CHECK (
        expires_at > issued_at AND (revoked_at IS NULL OR revoked_at >= issued_at)
    )
);

COMMENT ON TABLE public.oauth_access_token_records IS
    'Optional minimal Access Token introspection/denylist record; complete token bytes are never stored; Client/resource FKs added in 060; S3.';
CREATE INDEX oauth_access_token_records_grant_status_idx
    ON public.oauth_access_token_records (grant_pk, status);
CREATE INDEX oauth_access_token_records_expiry_idx
    ON public.oauth_access_token_records (expires_at, access_token_record_pk);

CREATE TABLE public.oauth_revocation_watermarks (
    revocation_watermark_pk bigint GENERATED ALWAYS AS IDENTITY,
    subject_type text COLLATE "C" NOT NULL,
    subject_pk bigint NOT NULL,
    resource_pk bigint NOT NULL DEFAULT 0,
    revocation_epoch bigint NOT NULL,
    revoked_before timestamptz NOT NULL,
    reason text COLLATE "C" NOT NULL,
    row_version bigint NOT NULL DEFAULT 1,
    created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    CONSTRAINT oauth_revocation_watermarks_pkey PRIMARY KEY (revocation_watermark_pk),
    CONSTRAINT oauth_revocation_watermarks_subject_key
        UNIQUE (subject_type, subject_pk, resource_pk),
    CONSTRAINT oauth_revocation_watermarks_subject_ck
        CHECK (subject_type IN ('USER', 'PRINCIPAL', 'CLIENT', 'TENANT', 'GRANT', 'RESOURCE')),
    CONSTRAINT oauth_revocation_watermarks_subject_pk_ck CHECK (subject_pk > 0 AND resource_pk >= 0),
    CONSTRAINT oauth_revocation_watermarks_epoch_ck CHECK (revocation_epoch > 0),
    CONSTRAINT oauth_revocation_watermarks_reason_ck CHECK (pg_catalog.length(reason) BETWEEN 1 AND 256),
    CONSTRAINT oauth_revocation_watermarks_row_version_ck CHECK (row_version > 0),
    CONSTRAINT oauth_revocation_watermarks_time_ck CHECK (
        updated_at >= created_at AND revoked_before <= updated_at
    )
);

COMMENT ON TABLE public.oauth_revocation_watermarks IS
    'Monotonic revocation epoch/time by typed subject and optional API Resource; typed FK validation is completed by 110; S2.';

CREATE TABLE public.oauth_token_exchanges (
    token_exchange_pk bigint GENERATED ALWAYS AS IDENTITY,
    token_exchange_id uuid NOT NULL DEFAULT pg_catalog.gen_random_uuid(),
    grant_pk bigint NOT NULL,
    subject_principal_pk bigint NOT NULL,
    actor_principal_pk bigint NOT NULL,
    client_pk bigint NOT NULL,
    source_resource_pk bigint NOT NULL,
    target_resource_pk bigint NOT NULL,
    source_token_digest bytea NOT NULL,
    requested_scope_digest bytea NOT NULL,
    chain_depth smallint NOT NULL,
    parent_exchange_pk bigint,
    result_token_jti_digest bytea,
    created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    CONSTRAINT oauth_token_exchanges_pkey PRIMARY KEY (token_exchange_pk),
    CONSTRAINT oauth_token_exchanges_id_key UNIQUE (token_exchange_id),
    CONSTRAINT oauth_token_exchanges_id_v4_ck CHECK (public.iam_uuid_is_v4(token_exchange_id)),
    CONSTRAINT oauth_token_exchanges_grant_fk FOREIGN KEY (grant_pk)
        REFERENCES public.oauth_grants (grant_pk) ON DELETE RESTRICT,
    CONSTRAINT oauth_token_exchanges_subject_fk FOREIGN KEY (subject_principal_pk)
        REFERENCES public.iam_principals (principal_pk) ON DELETE RESTRICT,
    CONSTRAINT oauth_token_exchanges_actor_fk FOREIGN KEY (actor_principal_pk)
        REFERENCES public.iam_principals (principal_pk) ON DELETE RESTRICT,
    CONSTRAINT oauth_token_exchanges_parent_fk FOREIGN KEY (parent_exchange_pk)
        REFERENCES public.oauth_token_exchanges (token_exchange_pk) ON DELETE RESTRICT,
    CONSTRAINT oauth_token_exchanges_placeholder_ck
        CHECK (client_pk > 0 AND source_resource_pk > 0 AND target_resource_pk > 0),
    CONSTRAINT oauth_token_exchanges_actor_subject_ck
        CHECK (actor_principal_pk <> subject_principal_pk),
    CONSTRAINT oauth_token_exchanges_digest_ck CHECK (
        pg_catalog.octet_length(source_token_digest) = 32
        AND pg_catalog.octet_length(requested_scope_digest) = 32
        AND (result_token_jti_digest IS NULL
             OR pg_catalog.octet_length(result_token_jti_digest) = 32)
    ),
    CONSTRAINT oauth_token_exchanges_depth_ck CHECK (chain_depth BETWEEN 1 AND 8)
);

COMMENT ON TABLE public.oauth_token_exchanges IS
    'RFC 8693 delegation evidence retaining separate subject, actor, audiences and bounded chain depth; no complete token; S3.';
CREATE INDEX oauth_token_exchanges_subject_time_idx
    ON public.oauth_token_exchanges (subject_principal_pk, created_at DESC);
CREATE INDEX oauth_token_exchanges_actor_time_idx
    ON public.oauth_token_exchanges (actor_principal_pk, created_at DESC);

CREATE TABLE public.oauth_logout_replays (
    logout_replay_pk bigint GENERATED ALWAYS AS IDENTITY,
    issuer_digest bytea NOT NULL,
    audience_digest bytea NOT NULL,
    jti_digest bytea NOT NULL,
    digest_key_ref text COLLATE "C" NOT NULL,
    digest_key_version integer NOT NULL,
    received_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    expires_at timestamptz NOT NULL,
    result text COLLATE "C" NOT NULL,
    CONSTRAINT oauth_logout_replays_pkey PRIMARY KEY (logout_replay_pk),
    CONSTRAINT oauth_logout_replays_digest_key
        UNIQUE (digest_key_version, issuer_digest, audience_digest, jti_digest),
    CONSTRAINT oauth_logout_replays_digest_ck CHECK (
        pg_catalog.octet_length(issuer_digest) = 32
        AND pg_catalog.octet_length(audience_digest) = 32
        AND pg_catalog.octet_length(jti_digest) = 32
        AND pg_catalog.length(digest_key_ref) BETWEEN 1 AND 512
        AND digest_key_version > 0
    ),
    CONSTRAINT oauth_logout_replays_result_ck
        CHECK (result IN ('ACCEPTED', 'DUPLICATE', 'REJECTED')),
    CONSTRAINT oauth_logout_replays_expiry_ck CHECK (expires_at > received_at)
);

COMMENT ON TABLE public.oauth_logout_replays IS
    'Back-channel logout issuer/audience/JTI replay registry containing only keyed digests; S3.';
CREATE INDEX oauth_logout_replays_expiry_idx
    ON public.oauth_logout_replays (expires_at, logout_replay_pk);

COMMIT;
