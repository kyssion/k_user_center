-- Identity, identifier, protocol-stable identity keys, and replay foundations.
-- PII is stored only as randomized ciphertext plus KMS references and keyed blind indexes.

BEGIN;

CREATE TABLE public.iam_identities (
    identity_pk bigint GENERATED ALWAYS AS IDENTITY,
    identity_id uuid NOT NULL DEFAULT pg_catalog.gen_random_uuid(),
    user_pk bigint NOT NULL,
    identity_type text COLLATE "C" NOT NULL,
    state text COLLATE "C" NOT NULL DEFAULT 'PENDING',
    assurance_level smallint NOT NULL DEFAULT 0,
    verified_at timestamptz,
    retired_at timestamptz,
    row_version bigint NOT NULL DEFAULT 1,
    created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    CONSTRAINT iam_identities_pkey PRIMARY KEY (identity_pk),
    CONSTRAINT iam_identities_identity_id_key UNIQUE (identity_id),
    CONSTRAINT iam_identities_identity_id_v4_ck CHECK (public.iam_uuid_is_v4(identity_id)),
    CONSTRAINT iam_identities_user_fk FOREIGN KEY (user_pk)
        REFERENCES public.iam_users (user_pk) ON DELETE RESTRICT,
    CONSTRAINT iam_identities_type_ck CHECK (identity_type IN ('LOCAL', 'OIDC', 'SAML')),
    CONSTRAINT iam_identities_state_ck
        CHECK (state IN ('PENDING', 'VERIFIED', 'SUSPENDED', 'UNBOUND', 'RETIRED')),
    CONSTRAINT iam_identities_assurance_ck CHECK (assurance_level BETWEEN 0 AND 3),
    CONSTRAINT iam_identities_verified_ck
        CHECK ((state = 'PENDING') = (verified_at IS NULL)),
    CONSTRAINT iam_identities_retired_ck
        CHECK ((state = 'RETIRED') = (retired_at IS NOT NULL)),
    CONSTRAINT iam_identities_row_version_ck CHECK (row_version > 0),
    CONSTRAINT iam_identities_time_ck CHECK (
        updated_at >= created_at
        AND (verified_at IS NULL OR verified_at >= created_at)
        AND (retired_at IS NULL OR retired_at >= created_at)
    )
);

COMMENT ON TABLE public.iam_identities IS
    'User-owned authentication identity containers; identifier values and protocol keys live in dedicated tables; S2.';

CREATE INDEX iam_identities_user_state_idx ON public.iam_identities (user_pk, state);
CREATE INDEX iam_identities_type_state_idx ON public.iam_identities (identity_type, state);

CREATE TABLE public.iam_identifiers (
    identifier_pk bigint GENERATED ALWAYS AS IDENTITY,
    identifier_id uuid NOT NULL DEFAULT pg_catalog.gen_random_uuid(),
    kind text COLLATE "C" NOT NULL,
    state text COLLATE "C" NOT NULL DEFAULT 'ACTIVE',
    ciphertext bytea,
    encryption_key_ref text COLLATE "C",
    encryption_key_version integer,
    masked_value text,
    normalization_version integer NOT NULL,
    rebind_not_before timestamptz,
    verified_at timestamptz,
    anonymized_at timestamptz,
    row_version bigint NOT NULL DEFAULT 1,
    created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    CONSTRAINT iam_identifiers_pkey PRIMARY KEY (identifier_pk),
    CONSTRAINT iam_identifiers_identifier_id_key UNIQUE (identifier_id),
    CONSTRAINT iam_identifiers_identifier_id_v4_ck CHECK (public.iam_uuid_is_v4(identifier_id)),
    CONSTRAINT iam_identifiers_kind_ck
        CHECK (kind IN ('PHONE', 'EMAIL', 'USERNAME', 'EXTERNAL_ID')),
    CONSTRAINT iam_identifiers_state_ck
        CHECK (state IN ('ACTIVE', 'QUARANTINED', 'RETIRED', 'ANONYMIZED')),
    CONSTRAINT iam_identifiers_cipher_group_ck CHECK (
        (ciphertext IS NULL AND encryption_key_ref IS NULL AND encryption_key_version IS NULL)
        OR (
            ciphertext IS NOT NULL
            AND pg_catalog.octet_length(ciphertext) >= 28
            AND encryption_key_ref IS NOT NULL
            AND pg_catalog.length(encryption_key_ref) BETWEEN 1 AND 512
            AND encryption_key_version > 0
        )
    ),
    CONSTRAINT iam_identifiers_anonymized_cipher_ck CHECK (
        (state = 'ANONYMIZED') = (anonymized_at IS NOT NULL)
        AND (state <> 'ANONYMIZED' OR ciphertext IS NULL)
    ),
    CONSTRAINT iam_identifiers_mask_ck CHECK (
        masked_value IS NULL OR pg_catalog.length(masked_value) BETWEEN 1 AND 128
    ),
    CONSTRAINT iam_identifiers_normalization_ck CHECK (normalization_version > 0),
    CONSTRAINT iam_identifiers_row_version_ck CHECK (row_version > 0),
    CONSTRAINT iam_identifiers_time_ck CHECK (
        updated_at >= created_at
        AND (rebind_not_before IS NULL OR rebind_not_before >= created_at)
        AND (verified_at IS NULL OR verified_at >= created_at)
        AND (anonymized_at IS NULL OR anonymized_at >= created_at)
    )
);

COMMENT ON TABLE public.iam_identifiers IS
    'Encrypted phone, email, username, or external identifiers; no searchable plaintext is retained; S3.';
COMMENT ON COLUMN public.iam_identifiers.ciphertext IS
    'Randomized AEAD ciphertext. NULL after anonymization; the encryption key is never stored in PostgreSQL.';

CREATE INDEX iam_identifiers_kind_state_idx ON public.iam_identifiers (kind, state);
CREATE INDEX iam_identifiers_rebind_idx ON public.iam_identifiers (rebind_not_before)
    WHERE rebind_not_before IS NOT NULL;

CREATE TABLE public.iam_identifier_blind_indexes (
    identifier_blind_index_pk bigint GENERATED ALWAYS AS IDENTITY,
    identifier_pk bigint NOT NULL,
    kind text COLLATE "C" NOT NULL,
    scope_type text COLLATE "C" NOT NULL,
    scope_pk bigint NOT NULL DEFAULT 0,
    normalization_version integer NOT NULL,
    blind_index_key_ref text COLLATE "C" NOT NULL,
    blind_index_key_version integer NOT NULL,
    blind_index bytea NOT NULL,
    is_active boolean NOT NULL DEFAULT true,
    created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    retired_at timestamptz,
    CONSTRAINT iam_identifier_blind_indexes_pkey PRIMARY KEY (identifier_blind_index_pk),
    CONSTRAINT iam_identifier_blind_indexes_identifier_fk FOREIGN KEY (identifier_pk)
        REFERENCES public.iam_identifiers (identifier_pk) ON DELETE RESTRICT,
    CONSTRAINT iam_identifier_blind_indexes_kind_ck
        CHECK (kind IN ('PHONE', 'EMAIL', 'USERNAME', 'EXTERNAL_ID')),
    CONSTRAINT iam_identifier_blind_indexes_scope_ck
        CHECK (scope_type IN ('GLOBAL', 'BUSINESS_LINE', 'TENANT', 'APPLICATION')
               AND ((scope_type = 'GLOBAL' AND scope_pk = 0)
                    OR (scope_type <> 'GLOBAL' AND scope_pk > 0))),
    CONSTRAINT iam_identifier_blind_indexes_versions_ck
        CHECK (normalization_version > 0 AND blind_index_key_version > 0),
    CONSTRAINT iam_identifier_blind_indexes_key_ref_ck
        CHECK (pg_catalog.length(blind_index_key_ref) BETWEEN 1 AND 512),
    CONSTRAINT iam_identifier_blind_indexes_digest_ck
        CHECK (pg_catalog.octet_length(blind_index) = 32),
    CONSTRAINT iam_identifier_blind_indexes_retired_ck
        CHECK (is_active = (retired_at IS NULL)),
    CONSTRAINT iam_identifier_blind_indexes_time_ck
        CHECK (retired_at IS NULL OR retired_at >= created_at)
);

COMMENT ON TABLE public.iam_identifier_blind_indexes IS
    'Versioned 32-byte HMAC blind indexes supporting dual-read/write key and normalization rotation; S3.';

CREATE UNIQUE INDEX iam_identifier_blind_indexes_active_value_uidx
    ON public.iam_identifier_blind_indexes
        (scope_type, scope_pk, kind, normalization_version,
         blind_index_key_version, blind_index)
    WHERE is_active;
CREATE UNIQUE INDEX iam_identifier_blind_indexes_active_version_uidx
    ON public.iam_identifier_blind_indexes
        (identifier_pk, normalization_version, blind_index_key_version)
    WHERE is_active;
CREATE INDEX iam_identifier_blind_indexes_identifier_idx
    ON public.iam_identifier_blind_indexes (identifier_pk, is_active);

CREATE TABLE public.iam_identity_bindings (
    identity_binding_pk bigint GENERATED ALWAYS AS IDENTITY,
    identity_pk bigint NOT NULL,
    identifier_pk bigint NOT NULL,
    binding_state text COLLATE "C" NOT NULL DEFAULT 'ACTIVE',
    verification_evidence_digest bytea NOT NULL,
    bound_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    unbound_at timestamptz,
    rebind_not_before timestamptz,
    created_by_principal_pk bigint,
    CONSTRAINT iam_identity_bindings_pkey PRIMARY KEY (identity_binding_pk),
    CONSTRAINT iam_identity_bindings_identity_fk FOREIGN KEY (identity_pk)
        REFERENCES public.iam_identities (identity_pk) ON DELETE RESTRICT,
    CONSTRAINT iam_identity_bindings_identifier_fk FOREIGN KEY (identifier_pk)
        REFERENCES public.iam_identifiers (identifier_pk) ON DELETE RESTRICT,
    CONSTRAINT iam_identity_bindings_actor_fk FOREIGN KEY (created_by_principal_pk)
        REFERENCES public.iam_principals (principal_pk) ON DELETE RESTRICT,
    CONSTRAINT iam_identity_bindings_state_ck
        CHECK (binding_state IN ('ACTIVE', 'UNBOUND', 'REPLACED', 'DISPUTED')),
    CONSTRAINT iam_identity_bindings_evidence_ck
        CHECK (pg_catalog.octet_length(verification_evidence_digest) = 32),
    CONSTRAINT iam_identity_bindings_unbound_ck CHECK (
        (binding_state = 'ACTIVE' AND unbound_at IS NULL)
        OR (binding_state <> 'ACTIVE' AND unbound_at IS NOT NULL)
    ),
    CONSTRAINT iam_identity_bindings_time_ck CHECK (
        unbound_at IS NULL OR unbound_at >= bound_at
    ),
    CONSTRAINT iam_identity_bindings_rebind_ck CHECK (
        rebind_not_before IS NULL
        OR (unbound_at IS NOT NULL AND rebind_not_before >= unbound_at)
    )
);

COMMENT ON TABLE public.iam_identity_bindings IS
    'Historical Identity-to-Identifier bindings with one active owner per Identifier; S3.';

CREATE UNIQUE INDEX iam_identity_bindings_active_identifier_uidx
    ON public.iam_identity_bindings (identifier_pk) WHERE binding_state = 'ACTIVE';
CREATE UNIQUE INDEX iam_identity_bindings_active_pair_uidx
    ON public.iam_identity_bindings (identity_pk, identifier_pk) WHERE binding_state = 'ACTIVE';
CREATE INDEX iam_identity_bindings_identity_state_idx
    ON public.iam_identity_bindings (identity_pk, binding_state);

CREATE TABLE public.iam_identifier_tombstones (
    identifier_tombstone_pk bigint GENERATED ALWAYS AS IDENTITY,
    kind text COLLATE "C" NOT NULL,
    scope_type text COLLATE "C" NOT NULL,
    scope_pk bigint NOT NULL DEFAULT 0,
    normalization_version integer NOT NULL,
    blind_index_key_ref text COLLATE "C" NOT NULL,
    blind_index_key_version integer NOT NULL,
    blind_index bytea NOT NULL,
    prior_owner_digest bytea NOT NULL,
    reason text COLLATE "C" NOT NULL,
    released_at timestamptz NOT NULL,
    reusable_after timestamptz,
    created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    CONSTRAINT iam_identifier_tombstones_pkey PRIMARY KEY (identifier_tombstone_pk),
    CONSTRAINT iam_identifier_tombstones_kind_ck
        CHECK (kind IN ('PHONE', 'EMAIL', 'USERNAME', 'EXTERNAL_ID')),
    CONSTRAINT iam_identifier_tombstones_scope_ck CHECK (
        scope_type IN ('GLOBAL', 'BUSINESS_LINE', 'TENANT', 'APPLICATION')
        AND ((scope_type = 'GLOBAL' AND scope_pk = 0)
             OR (scope_type <> 'GLOBAL' AND scope_pk > 0))
    ),
    CONSTRAINT iam_identifier_tombstones_versions_ck
        CHECK (normalization_version > 0 AND blind_index_key_version > 0),
    CONSTRAINT iam_identifier_tombstones_digest_ck CHECK (
        pg_catalog.octet_length(blind_index) = 32
        AND pg_catalog.octet_length(prior_owner_digest) = 32
    ),
    CONSTRAINT iam_identifier_tombstones_key_ref_ck
        CHECK (pg_catalog.length(blind_index_key_ref) BETWEEN 1 AND 512),
    CONSTRAINT iam_identifier_tombstones_reason_ck
        CHECK (reason IN ('UNBOUND', 'REPLACED', 'ANONYMIZED', 'RECYCLED', 'DISPUTED')),
    CONSTRAINT iam_identifier_tombstones_reuse_ck
        CHECK (reusable_after IS NULL OR reusable_after >= released_at),
    CONSTRAINT iam_identifier_tombstones_created_ck CHECK (created_at >= released_at)
);

COMMENT ON TABLE public.iam_identifier_tombstones IS
    'Non-reversible ownership tombstones preventing unsafe identifier reuse; NULL reusable_after means permanent; S3.';

CREATE UNIQUE INDEX iam_identifier_tombstones_value_uidx
    ON public.iam_identifier_tombstones
       (scope_type, scope_pk, kind, normalization_version,
        blind_index_key_version, blind_index);
CREATE INDEX iam_identifier_tombstones_reusable_idx
    ON public.iam_identifier_tombstones (reusable_after)
    WHERE reusable_after IS NOT NULL;

CREATE TABLE public.fed_protocol_parties (
    protocol_party_pk bigint GENERATED ALWAYS AS IDENTITY,
    protocol_party_id uuid NOT NULL DEFAULT pg_catalog.gen_random_uuid(),
    protocol text COLLATE "C" NOT NULL,
    stable_key_digest bytea NOT NULL,
    stable_key_key_ref text COLLATE "C" NOT NULL,
    stable_key_key_version integer NOT NULL,
    status text COLLATE "C" NOT NULL DEFAULT 'ACTIVE',
    created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    retired_at timestamptz,
    CONSTRAINT fed_protocol_parties_pkey PRIMARY KEY (protocol_party_pk),
    CONSTRAINT fed_protocol_parties_id_key UNIQUE (protocol_party_id),
    CONSTRAINT fed_protocol_parties_id_v4_ck CHECK (public.iam_uuid_is_v4(protocol_party_id)),
    CONSTRAINT fed_protocol_parties_protocol_ck CHECK (protocol IN ('OIDC', 'SAML')),
    CONSTRAINT fed_protocol_parties_digest_ck
        CHECK (pg_catalog.octet_length(stable_key_digest) = 32),
    CONSTRAINT fed_protocol_parties_key_ck CHECK (
        pg_catalog.length(stable_key_key_ref) BETWEEN 1 AND 512
        AND stable_key_key_version > 0
    ),
    CONSTRAINT fed_protocol_parties_status_ck CHECK (status IN ('ACTIVE', 'SUSPENDED', 'RETIRED')),
    CONSTRAINT fed_protocol_parties_retired_ck
        CHECK ((status = 'RETIRED') = (retired_at IS NOT NULL)),
    CONSTRAINT fed_protocol_parties_time_ck
        CHECK (retired_at IS NULL OR retired_at >= created_at),
    CONSTRAINT fed_protocol_parties_protocol_digest_key
        UNIQUE (protocol, stable_key_key_version, stable_key_digest)
);

COMMENT ON TABLE public.fed_protocol_parties IS
    'Protocol issuer registry: OIDC issuer or SAML entityID represented only by a keyed stable digest; S3.';

CREATE TABLE public.fed_external_identities (
    external_identity_pk bigint GENERATED ALWAYS AS IDENTITY,
    external_identity_id uuid NOT NULL DEFAULT pg_catalog.gen_random_uuid(),
    identity_pk bigint NOT NULL,
    user_pk bigint NOT NULL,
    protocol_party_pk bigint NOT NULL,
    protocol text COLLATE "C" NOT NULL,
    state text COLLATE "C" NOT NULL DEFAULT 'ACTIVE',
    oidc_subject_digest bytea,
    saml_name_id_digest bytea,
    saml_name_id_format text COLLATE "C",
    saml_sp_name_qualifier_digest bytea,
    subject_key_ref text COLLATE "C" NOT NULL,
    subject_key_version integer NOT NULL,
    linked_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    unlinked_at timestamptz,
    row_version bigint NOT NULL DEFAULT 1,
    CONSTRAINT fed_external_identities_pkey PRIMARY KEY (external_identity_pk),
    CONSTRAINT fed_external_identities_id_key UNIQUE (external_identity_id),
    CONSTRAINT fed_external_identities_id_v4_ck
        CHECK (public.iam_uuid_is_v4(external_identity_id)),
    CONSTRAINT fed_external_identities_identity_fk FOREIGN KEY (identity_pk)
        REFERENCES public.iam_identities (identity_pk) ON DELETE RESTRICT,
    CONSTRAINT fed_external_identities_user_fk FOREIGN KEY (user_pk)
        REFERENCES public.iam_users (user_pk) ON DELETE RESTRICT,
    CONSTRAINT fed_external_identities_party_fk FOREIGN KEY (protocol_party_pk)
        REFERENCES public.fed_protocol_parties (protocol_party_pk) ON DELETE RESTRICT,
    CONSTRAINT fed_external_identities_protocol_ck CHECK (protocol IN ('OIDC', 'SAML')),
    CONSTRAINT fed_external_identities_state_ck
        CHECK (state IN ('ACTIVE', 'SUSPENDED', 'UNLINKED', 'TOMBSTONED')),
    CONSTRAINT fed_external_identities_key_ck CHECK (
        pg_catalog.length(subject_key_ref) BETWEEN 1 AND 512
        AND subject_key_version > 0
    ),
    CONSTRAINT fed_external_identities_protocol_fields_ck CHECK (
        (
            protocol = 'OIDC'
            AND oidc_subject_digest IS NOT NULL
            AND pg_catalog.octet_length(oidc_subject_digest) = 32
            AND saml_name_id_digest IS NULL
            AND saml_name_id_format IS NULL
            AND saml_sp_name_qualifier_digest IS NULL
        )
        OR
        (
            protocol = 'SAML'
            AND oidc_subject_digest IS NULL
            AND saml_name_id_digest IS NOT NULL
            AND pg_catalog.octet_length(saml_name_id_digest) = 32
            AND saml_name_id_format IS NOT NULL
            AND pg_catalog.length(saml_name_id_format) BETWEEN 1 AND 512
            AND saml_name_id_format <> 'urn:oasis:names:tc:SAML:2.0:nameid-format:transient'
            AND (
                saml_sp_name_qualifier_digest IS NULL
                OR pg_catalog.octet_length(saml_sp_name_qualifier_digest) = 32
            )
        )
    ),
    CONSTRAINT fed_external_identities_unlinked_ck CHECK (
        (state IN ('UNLINKED', 'TOMBSTONED')) = (unlinked_at IS NOT NULL)
    ),
    CONSTRAINT fed_external_identities_row_version_ck CHECK (row_version > 0),
    CONSTRAINT fed_external_identities_time_ck
        CHECK (unlinked_at IS NULL OR unlinked_at >= linked_at)
);

COMMENT ON TABLE public.fed_external_identities IS
    'OIDC issuer+sub and SAML entityID+NameID semantic links; transient NameID is rejected and email is never a key; S3.';

CREATE UNIQUE INDEX fed_external_identities_oidc_key_uidx
    ON public.fed_external_identities
       (protocol_party_pk, subject_key_version, oidc_subject_digest)
    WHERE protocol = 'OIDC';
CREATE UNIQUE INDEX fed_external_identities_saml_key_uidx
    ON public.fed_external_identities
       (protocol_party_pk, subject_key_version, saml_name_id_digest,
        saml_name_id_format, saml_sp_name_qualifier_digest)
    NULLS NOT DISTINCT
    WHERE protocol = 'SAML';
CREATE INDEX fed_external_identities_user_state_idx
    ON public.fed_external_identities (user_pk, state);

CREATE TABLE public.fed_assertion_replays (
    assertion_replay_pk bigint GENERATED ALWAYS AS IDENTITY,
    protocol_party_pk bigint NOT NULL,
    replay_kind text COLLATE "C" NOT NULL,
    digest bytea NOT NULL,
    digest_key_ref text COLLATE "C" NOT NULL,
    digest_key_version integer NOT NULL,
    created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    expires_at timestamptz NOT NULL,
    CONSTRAINT fed_assertion_replays_pkey PRIMARY KEY (assertion_replay_pk),
    CONSTRAINT fed_assertion_replays_party_fk FOREIGN KEY (protocol_party_pk)
        REFERENCES public.fed_protocol_parties (protocol_party_pk) ON DELETE RESTRICT,
    CONSTRAINT fed_assertion_replays_kind_ck
        CHECK (replay_kind IN ('OIDC_NONCE', 'OIDC_JTI', 'SAML_ASSERTION_ID', 'SAML_IN_RESPONSE_TO')),
    CONSTRAINT fed_assertion_replays_digest_ck CHECK (pg_catalog.octet_length(digest) = 32),
    CONSTRAINT fed_assertion_replays_key_ck CHECK (
        pg_catalog.length(digest_key_ref) BETWEEN 1 AND 512
        AND digest_key_version > 0
    ),
    CONSTRAINT fed_assertion_replays_expiry_ck CHECK (expires_at > created_at),
    CONSTRAINT fed_assertion_replays_key
        UNIQUE (protocol_party_pk, replay_kind, digest_key_version, digest)
);

COMMENT ON TABLE public.fed_assertion_replays IS
    'Short-lived keyed replay digests for OIDC nonce/JTI and SAML assertion/InResponseTo values; S3.';

CREATE INDEX fed_assertion_replays_expiry_idx
    ON public.fed_assertion_replays (expires_at, assertion_replay_pk);

COMMIT;
