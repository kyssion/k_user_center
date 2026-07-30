-- Profile, consent, agreement, marketing and privacy orchestration.
-- Cross-row completion, legal-hold and consent propagation guards are deferred
-- to 110_constraints_functions.sql.

BEGIN;

CREATE TABLE public.profile_user_profiles (
    profile_pk bigint GENERATED ALWAYS AS IDENTITY,
    profile_id uuid NOT NULL DEFAULT pg_catalog.gen_random_uuid(),
    user_pk bigint NOT NULL,
    display_name_ciphertext bytea,
    display_name_key_ref text COLLATE "C",
    display_name_key_version integer,
    avatar_reference text COLLATE "C",
    locale text COLLATE "C",
    timezone_name text COLLATE "C",
    row_version bigint NOT NULL DEFAULT 1,
    created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    CONSTRAINT profile_user_profiles_pkey PRIMARY KEY (profile_pk),
    CONSTRAINT profile_user_profiles_profile_id_key UNIQUE (profile_id),
    CONSTRAINT profile_user_profiles_user_key UNIQUE (user_pk),
    CONSTRAINT profile_user_profiles_profile_id_v4_ck CHECK (public.iam_uuid_is_v4(profile_id)),
    CONSTRAINT profile_user_profiles_user_fk FOREIGN KEY (user_pk)
        REFERENCES public.iam_users (user_pk) ON DELETE RESTRICT,
    CONSTRAINT profile_user_profiles_display_name_group_ck CHECK (
        (display_name_ciphertext IS NULL AND display_name_key_ref IS NULL AND display_name_key_version IS NULL)
        OR (display_name_ciphertext IS NOT NULL AND pg_catalog.octet_length(display_name_ciphertext) BETWEEN 17 AND 65536
            AND display_name_key_ref IS NOT NULL AND display_name_key_version > 0)
    ),
    CONSTRAINT profile_user_profiles_display_name_key_ref_ck CHECK (
        display_name_key_ref IS NULL OR pg_catalog.length(display_name_key_ref) BETWEEN 1 AND 255
    ),
    CONSTRAINT profile_user_profiles_avatar_reference_ck CHECK (
        avatar_reference IS NULL OR pg_catalog.length(avatar_reference) BETWEEN 1 AND 1024
    ),
    CONSTRAINT profile_user_profiles_locale_ck CHECK (
        locale IS NULL OR (pg_catalog.length(locale) BETWEEN 2 AND 35 AND locale ~ '^[A-Za-z0-9]+(?:-[A-Za-z0-9]+)*$')
    ),
    CONSTRAINT profile_user_profiles_timezone_ck CHECK (
        timezone_name IS NULL OR (pg_catalog.length(timezone_name) BETWEEN 1 AND 64 AND timezone_name ~ '^[A-Za-z0-9_+./-]+$')
    ),
    CONSTRAINT profile_user_profiles_row_version_ck CHECK (row_version > 0),
    CONSTRAINT profile_user_profiles_time_ck CHECK (updated_at >= created_at)
);

COMMENT ON TABLE public.profile_user_profiles IS
    'Public-profile aggregate; PII display names are encrypted and object-store references contain no credentials; S2/S3.';

CREATE INDEX profile_user_profiles_updated_idx
    ON public.profile_user_profiles (updated_at, profile_pk);

CREATE TRIGGER profile_user_profiles_immutable_trg
BEFORE UPDATE ON public.profile_user_profiles
FOR EACH ROW EXECUTE FUNCTION public.iam_reject_column_changes(
    'profile_pk', 'profile_id', 'user_pk', 'created_at'
);

CREATE TRIGGER profile_user_profiles_version_trg
BEFORE UPDATE ON public.profile_user_profiles
FOR EACH ROW EXECUTE FUNCTION public.iam_guard_nondecreasing_bigint('row_version');

CREATE TABLE public.profile_field_definitions (
    field_definition_pk bigint GENERATED ALWAYS AS IDENTITY,
    field_definition_id uuid NOT NULL DEFAULT pg_catalog.gen_random_uuid(),
    namespace text COLLATE "C" NOT NULL,
    field_code text COLLATE "C" NOT NULL,
    version_no integer NOT NULL,
    status text COLLATE "C" NOT NULL DEFAULT 'DRAFT',
    value_type text COLLATE "C" NOT NULL,
    authority_type text COLLATE "C" NOT NULL,
    sensitivity_level text COLLATE "C" NOT NULL,
    purpose_code text COLLATE "C" NOT NULL,
    visibility text COLLATE "C" NOT NULL,
    mutability text COLLATE "C" NOT NULL,
    retention_days integer,
    value_schema_version integer NOT NULL,
    value_schema jsonb NOT NULL,
    content_hash bytea NOT NULL,
    published_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    CONSTRAINT profile_field_definitions_pkey PRIMARY KEY (field_definition_pk),
    CONSTRAINT profile_field_definitions_id_key UNIQUE (field_definition_id),
    CONSTRAINT profile_field_definitions_version_key UNIQUE (namespace, field_code, version_no),
    CONSTRAINT profile_field_definitions_id_v4_ck CHECK (public.iam_uuid_is_v4(field_definition_id)),
    CONSTRAINT profile_field_definitions_namespace_ck CHECK (
        pg_catalog.length(namespace) BETWEEN 1 AND 96 AND namespace ~ '^[a-z][a-z0-9_.-]*$'
    ),
    CONSTRAINT profile_field_definitions_code_ck CHECK (
        pg_catalog.length(field_code) BETWEEN 1 AND 96 AND field_code ~ '^[a-z][a-z0-9_.-]*$'
    ),
    CONSTRAINT profile_field_definitions_version_ck CHECK (version_no > 0),
    CONSTRAINT profile_field_definitions_status_ck CHECK (status IN ('DRAFT', 'PUBLISHED', 'RETIRED')),
    CONSTRAINT profile_field_definitions_value_type_ck CHECK (
        value_type IN ('STRING', 'INTEGER', 'DECIMAL', 'BOOLEAN', 'DATE', 'TIMESTAMP', 'OBJECT', 'REFERENCE')
    ),
    CONSTRAINT profile_field_definitions_authority_ck CHECK (
        authority_type IN ('USER', 'ADMIN', 'FEDERATED', 'SYSTEM', 'BUSINESS')
    ),
    CONSTRAINT profile_field_definitions_sensitivity_ck CHECK (
        sensitivity_level IN ('S0', 'S1', 'S2', 'S3')
    ),
    CONSTRAINT profile_field_definitions_purpose_ck CHECK (
        pg_catalog.length(purpose_code) BETWEEN 1 AND 96 AND purpose_code ~ '^[A-Z][A-Z0-9_.-]*$'
    ),
    CONSTRAINT profile_field_definitions_visibility_ck CHECK (
        visibility IN ('PRIVATE', 'SUBJECT', 'BUSINESS', 'TENANT_ADMIN', 'PLATFORM_ADMIN', 'PUBLIC')
    ),
    CONSTRAINT profile_field_definitions_mutability_ck CHECK (
        mutability IN ('IMMUTABLE', 'SUBJECT_WRITABLE', 'AUTHORITY_WRITABLE')
    ),
    CONSTRAINT profile_field_definitions_retention_ck CHECK (retention_days IS NULL OR retention_days > 0),
    CONSTRAINT profile_field_definitions_schema_ck CHECK (
        value_schema_version > 0
        AND pg_catalog.jsonb_typeof(value_schema) = 'object'
        AND pg_catalog.octet_length(value_schema::text) <= 262144
    ),
    CONSTRAINT profile_field_definitions_hash_ck CHECK (pg_catalog.octet_length(content_hash) = 32),
    CONSTRAINT profile_field_definitions_publish_ck CHECK (
        (status = 'DRAFT' AND published_at IS NULL) OR (status IN ('PUBLISHED', 'RETIRED') AND published_at IS NOT NULL)
    )
);

COMMENT ON TABLE public.profile_field_definitions IS
    'Versioned profile field metadata, source, sensitivity, purpose, visibility, retention and JSON Schema; published versions are immutable; S1/S2.';

CREATE INDEX profile_field_definitions_namespace_status_idx
    ON public.profile_field_definitions (namespace, status, field_code);

CREATE UNIQUE INDEX profile_field_definitions_hash_uidx
    ON public.profile_field_definitions (content_hash)
    WHERE status IN ('PUBLISHED', 'RETIRED');

CREATE TRIGGER profile_field_definitions_published_immutable_trg
BEFORE UPDATE ON public.profile_field_definitions
FOR EACH ROW
WHEN (OLD.status IN ('PUBLISHED', 'RETIRED'))
EXECUTE FUNCTION public.iam_reject_column_changes(
    'field_definition_pk', 'field_definition_id', 'namespace', 'field_code',
    'version_no', 'value_type', 'authority_type', 'sensitivity_level',
    'purpose_code', 'visibility', 'mutability', 'retention_days',
    'value_schema_version', 'value_schema', 'content_hash', 'published_at', 'created_at'
);

CREATE TABLE public.profile_namespace_values (
    profile_value_pk bigint GENERATED ALWAYS AS IDENTITY,
    profile_value_id uuid NOT NULL DEFAULT pg_catalog.gen_random_uuid(),
    field_definition_pk bigint NOT NULL,
    subject_type text COLLATE "C" NOT NULL,
    user_pk bigint,
    membership_pk bigint,
    value_storage text COLLATE "C" NOT NULL,
    clear_value jsonb,
    ciphertext bytea,
    encryption_key_ref text COLLATE "C",
    encryption_key_version integer,
    reference_uri text COLLATE "C",
    reference_digest bytea,
    source_type text COLLATE "C" NOT NULL,
    source_reference text COLLATE "C",
    value_version bigint NOT NULL DEFAULT 1,
    row_version bigint NOT NULL DEFAULT 1,
    expires_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    CONSTRAINT profile_namespace_values_pkey PRIMARY KEY (profile_value_pk),
    CONSTRAINT profile_namespace_values_id_key UNIQUE (profile_value_id),
    CONSTRAINT profile_namespace_values_id_v4_ck CHECK (public.iam_uuid_is_v4(profile_value_id)),
    CONSTRAINT profile_namespace_values_definition_fk FOREIGN KEY (field_definition_pk)
        REFERENCES public.profile_field_definitions (field_definition_pk) ON DELETE RESTRICT,
    CONSTRAINT profile_namespace_values_user_fk FOREIGN KEY (user_pk)
        REFERENCES public.iam_users (user_pk) ON DELETE RESTRICT,
    CONSTRAINT profile_namespace_values_membership_fk FOREIGN KEY (membership_pk)
        REFERENCES public.org_memberships (membership_pk) ON DELETE RESTRICT,
    CONSTRAINT profile_namespace_values_subject_ck CHECK (
        (subject_type = 'USER' AND user_pk IS NOT NULL AND membership_pk IS NULL)
        OR (subject_type = 'MEMBERSHIP' AND user_pk IS NULL AND membership_pk IS NOT NULL)
    ),
    CONSTRAINT profile_namespace_values_storage_ck CHECK (
        value_storage IN ('CLEAR_JSON', 'ENCRYPTED', 'REFERENCE')
    ),
    CONSTRAINT profile_namespace_values_value_group_ck CHECK (
        (value_storage = 'CLEAR_JSON' AND clear_value IS NOT NULL
            AND pg_catalog.jsonb_typeof(clear_value) = 'object'
            AND pg_catalog.octet_length(clear_value::text) <= 262144
            AND ciphertext IS NULL AND encryption_key_ref IS NULL AND encryption_key_version IS NULL
            AND reference_uri IS NULL AND reference_digest IS NULL)
        OR
        (value_storage = 'ENCRYPTED' AND clear_value IS NULL
            AND ciphertext IS NOT NULL AND pg_catalog.octet_length(ciphertext) BETWEEN 17 AND 1048576
            AND encryption_key_ref IS NOT NULL AND pg_catalog.length(encryption_key_ref) BETWEEN 1 AND 255
            AND encryption_key_version > 0 AND reference_uri IS NULL AND reference_digest IS NULL)
        OR
        (value_storage = 'REFERENCE' AND clear_value IS NULL AND ciphertext IS NULL
            AND encryption_key_ref IS NULL AND encryption_key_version IS NULL
            AND reference_uri IS NOT NULL AND pg_catalog.length(reference_uri) BETWEEN 1 AND 1024
            AND reference_digest IS NOT NULL AND pg_catalog.octet_length(reference_digest) = 32)
    ),
    CONSTRAINT profile_namespace_values_source_type_ck CHECK (
        source_type IN ('USER', 'ADMIN', 'FEDERATED', 'SYSTEM', 'BUSINESS')
    ),
    CONSTRAINT profile_namespace_values_source_ref_ck CHECK (
        source_reference IS NULL OR pg_catalog.length(source_reference) BETWEEN 1 AND 512
    ),
    CONSTRAINT profile_namespace_values_versions_ck CHECK (value_version > 0 AND row_version > 0),
    CONSTRAINT profile_namespace_values_time_ck CHECK (
        updated_at >= created_at AND (expires_at IS NULL OR expires_at > created_at)
    )
);

COMMENT ON TABLE public.profile_namespace_values IS
    'Current user or membership profile field value; low-sensitivity JSON, encrypted PII, and opaque references are mutually exclusive; S1-S3.';

CREATE UNIQUE INDEX profile_namespace_values_user_uidx
    ON public.profile_namespace_values (user_pk, field_definition_pk)
    WHERE user_pk IS NOT NULL;
CREATE UNIQUE INDEX profile_namespace_values_membership_uidx
    ON public.profile_namespace_values (membership_pk, field_definition_pk)
    WHERE membership_pk IS NOT NULL;
CREATE INDEX profile_namespace_values_definition_updated_idx
    ON public.profile_namespace_values (field_definition_pk, updated_at DESC);

CREATE TRIGGER profile_namespace_values_immutable_trg
BEFORE UPDATE ON public.profile_namespace_values
FOR EACH ROW EXECUTE FUNCTION public.iam_reject_column_changes(
    'profile_value_pk', 'profile_value_id', 'field_definition_pk',
    'subject_type', 'user_pk', 'membership_pk', 'created_at'
);

CREATE TRIGGER profile_namespace_values_versions_trg
BEFORE UPDATE ON public.profile_namespace_values
FOR EACH ROW EXECUTE FUNCTION public.iam_guard_nondecreasing_bigint('value_version', 'row_version');

CREATE TABLE public.profile_value_history (
    profile_value_history_pk bigint GENERATED ALWAYS AS IDENTITY,
    profile_value_pk bigint NOT NULL,
    value_version bigint NOT NULL,
    previous_digest bytea,
    new_digest bytea NOT NULL,
    encrypted_evidence bytea,
    encryption_key_ref text COLLATE "C",
    encryption_key_version integer,
    source_type text COLLATE "C" NOT NULL,
    reason_code text COLLATE "C" NOT NULL,
    actor_principal_pk bigint,
    changed_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    CONSTRAINT profile_value_history_pkey PRIMARY KEY (profile_value_history_pk),
    CONSTRAINT profile_value_history_version_key UNIQUE (profile_value_pk, value_version),
    CONSTRAINT profile_value_history_value_fk FOREIGN KEY (profile_value_pk)
        REFERENCES public.profile_namespace_values (profile_value_pk) ON DELETE RESTRICT,
    CONSTRAINT profile_value_history_actor_fk FOREIGN KEY (actor_principal_pk)
        REFERENCES public.iam_principals (principal_pk) ON DELETE RESTRICT,
    CONSTRAINT profile_value_history_version_ck CHECK (value_version > 0),
    CONSTRAINT profile_value_history_previous_digest_ck CHECK (
        previous_digest IS NULL OR pg_catalog.octet_length(previous_digest) = 32
    ),
    CONSTRAINT profile_value_history_new_digest_ck CHECK (pg_catalog.octet_length(new_digest) = 32),
    CONSTRAINT profile_value_history_evidence_group_ck CHECK (
        (encrypted_evidence IS NULL AND encryption_key_ref IS NULL AND encryption_key_version IS NULL)
        OR (encrypted_evidence IS NOT NULL AND pg_catalog.octet_length(encrypted_evidence) BETWEEN 17 AND 1048576
            AND encryption_key_ref IS NOT NULL AND pg_catalog.length(encryption_key_ref) BETWEEN 1 AND 255
            AND encryption_key_version > 0)
    ),
    CONSTRAINT profile_value_history_source_ck CHECK (
        source_type IN ('USER', 'ADMIN', 'FEDERATED', 'SYSTEM', 'BUSINESS')
    ),
    CONSTRAINT profile_value_history_reason_ck CHECK (
        pg_catalog.length(reason_code) BETWEEN 1 AND 64 AND reason_code ~ '^[A-Z][A-Z0-9_]*$'
    )
);

COMMENT ON TABLE public.profile_value_history IS
    'Append-oriented profile value history storing digests by default and optional encrypted evidence; S2/S3.';

CREATE INDEX profile_value_history_actor_idx
    ON public.profile_value_history (actor_principal_pk, changed_at DESC)
    WHERE actor_principal_pk IS NOT NULL;

CREATE TRIGGER profile_value_history_append_only_trg
BEFORE UPDATE OR DELETE ON public.profile_value_history
FOR EACH ROW EXECUTE FUNCTION public.iam_reject_row_mutation();

CREATE TABLE public.priv_purposes (
    purpose_pk bigint GENERATED ALWAYS AS IDENTITY,
    purpose_id uuid NOT NULL DEFAULT pg_catalog.gen_random_uuid(),
    purpose_code text COLLATE "C" NOT NULL,
    version_no integer NOT NULL,
    legal_basis text COLLATE "C" NOT NULL,
    region_code text COLLATE "C" NOT NULL,
    status text COLLATE "C" NOT NULL DEFAULT 'DRAFT',
    retention_days integer,
    content_hash bytea NOT NULL,
    effective_at timestamptz,
    retired_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    CONSTRAINT priv_purposes_pkey PRIMARY KEY (purpose_pk),
    CONSTRAINT priv_purposes_id_key UNIQUE (purpose_id),
    CONSTRAINT priv_purposes_code_version_key UNIQUE (purpose_code, version_no, region_code),
    CONSTRAINT priv_purposes_id_v4_ck CHECK (public.iam_uuid_is_v4(purpose_id)),
    CONSTRAINT priv_purposes_code_ck CHECK (
        pg_catalog.length(purpose_code) BETWEEN 1 AND 96 AND purpose_code ~ '^[A-Z][A-Z0-9_.-]*$'
    ),
    CONSTRAINT priv_purposes_version_ck CHECK (version_no > 0),
    CONSTRAINT priv_purposes_legal_basis_ck CHECK (
        legal_basis IN ('CONSENT', 'CONTRACT', 'LEGAL_OBLIGATION', 'VITAL_INTERESTS', 'PUBLIC_TASK', 'LEGITIMATE_INTERESTS')
    ),
    CONSTRAINT priv_purposes_region_ck CHECK (
        pg_catalog.length(region_code) BETWEEN 2 AND 16 AND region_code ~ '^[A-Z0-9-]+$'
    ),
    CONSTRAINT priv_purposes_status_ck CHECK (status IN ('DRAFT', 'ACTIVE', 'RETIRED')),
    CONSTRAINT priv_purposes_retention_ck CHECK (retention_days IS NULL OR retention_days > 0),
    CONSTRAINT priv_purposes_hash_ck CHECK (pg_catalog.octet_length(content_hash) = 32),
    CONSTRAINT priv_purposes_effective_ck CHECK (
        (status = 'DRAFT' AND effective_at IS NULL AND retired_at IS NULL)
        OR (status = 'ACTIVE' AND effective_at IS NOT NULL AND retired_at IS NULL)
        OR (status = 'RETIRED' AND effective_at IS NOT NULL AND retired_at IS NOT NULL AND retired_at >= effective_at)
    )
);

COMMENT ON TABLE public.priv_purposes IS
    'Immutable-version processing-purpose catalogue with legal basis, region and retention; S1.';

CREATE INDEX priv_purposes_status_idx
    ON public.priv_purposes (status, region_code, purpose_code);

CREATE TABLE public.priv_data_categories (
    data_category_pk bigint GENERATED ALWAYS AS IDENTITY,
    data_category_id uuid NOT NULL DEFAULT pg_catalog.gen_random_uuid(),
    category_code text COLLATE "C" NOT NULL,
    parent_category_pk bigint,
    sensitivity_level text COLLATE "C" NOT NULL,
    status text COLLATE "C" NOT NULL DEFAULT 'ACTIVE',
    created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    CONSTRAINT priv_data_categories_pkey PRIMARY KEY (data_category_pk),
    CONSTRAINT priv_data_categories_id_key UNIQUE (data_category_id),
    CONSTRAINT priv_data_categories_code_key UNIQUE (category_code),
    CONSTRAINT priv_data_categories_id_v4_ck CHECK (public.iam_uuid_is_v4(data_category_id)),
    CONSTRAINT priv_data_categories_parent_fk FOREIGN KEY (parent_category_pk)
        REFERENCES public.priv_data_categories (data_category_pk) ON DELETE RESTRICT,
    CONSTRAINT priv_data_categories_no_self_ck CHECK (
        parent_category_pk IS NULL OR parent_category_pk <> data_category_pk
    ),
    CONSTRAINT priv_data_categories_code_ck CHECK (
        pg_catalog.length(category_code) BETWEEN 1 AND 96 AND category_code ~ '^[A-Z][A-Z0-9_.-]*$'
    ),
    CONSTRAINT priv_data_categories_sensitivity_ck CHECK (
        sensitivity_level IN ('S0', 'S1', 'S2', 'S3', 'S4')
    ),
    CONSTRAINT priv_data_categories_status_ck CHECK (status IN ('ACTIVE', 'RETIRED'))
);

COMMENT ON TABLE public.priv_data_categories IS
    'Hierarchical governed data-category catalogue; cycle detection is deferred to 110; S1.';

CREATE INDEX priv_data_categories_parent_idx
    ON public.priv_data_categories (parent_category_pk)
    WHERE parent_category_pk IS NOT NULL;

CREATE TABLE public.priv_recipients (
    recipient_pk bigint GENERATED ALWAYS AS IDENTITY,
    recipient_id uuid NOT NULL DEFAULT pg_catalog.gen_random_uuid(),
    recipient_code text COLLATE "C" NOT NULL,
    recipient_type text COLLATE "C" NOT NULL,
    legal_name_ciphertext bytea,
    encryption_key_ref text COLLATE "C",
    encryption_key_version integer,
    country_code text COLLATE "C",
    contract_reference text COLLATE "C",
    status text COLLATE "C" NOT NULL DEFAULT 'PENDING_APPROVAL',
    approved_at timestamptz,
    row_version bigint NOT NULL DEFAULT 1,
    created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    CONSTRAINT priv_recipients_pkey PRIMARY KEY (recipient_pk),
    CONSTRAINT priv_recipients_id_key UNIQUE (recipient_id),
    CONSTRAINT priv_recipients_code_key UNIQUE (recipient_code),
    CONSTRAINT priv_recipients_id_v4_ck CHECK (public.iam_uuid_is_v4(recipient_id)),
    CONSTRAINT priv_recipients_code_ck CHECK (
        pg_catalog.length(recipient_code) BETWEEN 1 AND 96 AND recipient_code ~ '^[A-Z][A-Z0-9_.-]*$'
    ),
    CONSTRAINT priv_recipients_type_ck CHECK (
        recipient_type IN ('INTERNAL', 'PROCESSOR', 'CONTROLLER', 'PUBLIC_AUTHORITY', 'OTHER')
    ),
    CONSTRAINT priv_recipients_name_group_ck CHECK (
        (legal_name_ciphertext IS NULL AND encryption_key_ref IS NULL AND encryption_key_version IS NULL)
        OR (legal_name_ciphertext IS NOT NULL AND pg_catalog.octet_length(legal_name_ciphertext) BETWEEN 17 AND 65536
            AND encryption_key_ref IS NOT NULL AND pg_catalog.length(encryption_key_ref) BETWEEN 1 AND 255
            AND encryption_key_version > 0)
    ),
    CONSTRAINT priv_recipients_country_ck CHECK (
        country_code IS NULL OR (pg_catalog.length(country_code) = 2 AND country_code ~ '^[A-Z]{2}$')
    ),
    CONSTRAINT priv_recipients_contract_ck CHECK (
        contract_reference IS NULL OR pg_catalog.length(contract_reference) BETWEEN 1 AND 512
    ),
    CONSTRAINT priv_recipients_status_ck CHECK (
        status IN ('PENDING_APPROVAL', 'ACTIVE', 'SUSPENDED', 'RETIRED')
    ),
    CONSTRAINT priv_recipients_approval_ck CHECK (
        (status = 'PENDING_APPROVAL' AND approved_at IS NULL) OR (status <> 'PENDING_APPROVAL' AND approved_at IS NOT NULL)
    ),
    CONSTRAINT priv_recipients_row_version_ck CHECK (row_version > 0),
    CONSTRAINT priv_recipients_time_ck CHECK (updated_at >= created_at)
);

COMMENT ON TABLE public.priv_recipients IS
    'Approved internal or third-party data recipient directory; legal names may be encrypted; S2/S3.';

CREATE INDEX priv_recipients_status_idx ON public.priv_recipients (status, recipient_type);

CREATE TABLE public.priv_notices (
    notice_pk bigint GENERATED ALWAYS AS IDENTITY,
    notice_id uuid NOT NULL DEFAULT pg_catalog.gen_random_uuid(),
    notice_code text COLLATE "C" NOT NULL,
    notice_type text COLLATE "C" NOT NULL,
    version_no integer NOT NULL,
    locale text COLLATE "C" NOT NULL,
    region_code text COLLATE "C" NOT NULL,
    status text COLLATE "C" NOT NULL DEFAULT 'DRAFT',
    content_reference text COLLATE "C" NOT NULL,
    content_hash bytea NOT NULL,
    effective_at timestamptz,
    supersedes_notice_pk bigint,
    created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    CONSTRAINT priv_notices_pkey PRIMARY KEY (notice_pk),
    CONSTRAINT priv_notices_id_key UNIQUE (notice_id),
    CONSTRAINT priv_notices_version_key UNIQUE (notice_code, version_no, locale, region_code),
    CONSTRAINT priv_notices_id_v4_ck CHECK (public.iam_uuid_is_v4(notice_id)),
    CONSTRAINT priv_notices_supersedes_fk FOREIGN KEY (supersedes_notice_pk)
        REFERENCES public.priv_notices (notice_pk) ON DELETE RESTRICT,
    CONSTRAINT priv_notices_no_self_ck CHECK (supersedes_notice_pk IS NULL OR supersedes_notice_pk <> notice_pk),
    CONSTRAINT priv_notices_code_ck CHECK (
        pg_catalog.length(notice_code) BETWEEN 1 AND 96 AND notice_code ~ '^[A-Z][A-Z0-9_.-]*$'
    ),
    CONSTRAINT priv_notices_type_ck CHECK (
        notice_type IN ('PRIVACY_NOTICE', 'CONSENT_NOTICE', 'COLLECTION_NOTICE', 'CROSS_BORDER_NOTICE')
    ),
    CONSTRAINT priv_notices_version_ck CHECK (version_no > 0),
    CONSTRAINT priv_notices_locale_ck CHECK (
        pg_catalog.length(locale) BETWEEN 2 AND 35 AND locale ~ '^[A-Za-z0-9]+(?:-[A-Za-z0-9]+)*$'
    ),
    CONSTRAINT priv_notices_region_ck CHECK (
        pg_catalog.length(region_code) BETWEEN 2 AND 16 AND region_code ~ '^[A-Z0-9-]+$'
    ),
    CONSTRAINT priv_notices_status_ck CHECK (status IN ('DRAFT', 'PUBLISHED', 'SUPERSEDED', 'RETIRED')),
    CONSTRAINT priv_notices_reference_ck CHECK (pg_catalog.length(content_reference) BETWEEN 1 AND 1024),
    CONSTRAINT priv_notices_hash_ck CHECK (pg_catalog.octet_length(content_hash) = 32),
    CONSTRAINT priv_notices_effective_ck CHECK (
        (status = 'DRAFT' AND effective_at IS NULL) OR (status <> 'DRAFT' AND effective_at IS NOT NULL)
    )
);

COMMENT ON TABLE public.priv_notices IS
    'Immutable-version privacy and consent notices with locale, region, content reference and digest; S1.';

CREATE INDEX priv_notices_effective_idx
    ON public.priv_notices (notice_code, region_code, locale, effective_at DESC)
    WHERE status = 'PUBLISHED';

CREATE TABLE public.priv_purpose_categories (
    purpose_category_pk bigint GENERATED ALWAYS AS IDENTITY,
    purpose_pk bigint NOT NULL,
    data_category_pk bigint NOT NULL,
    collection_required boolean NOT NULL DEFAULT false,
    created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    CONSTRAINT priv_purpose_categories_pkey PRIMARY KEY (purpose_category_pk),
    CONSTRAINT priv_purpose_categories_pair_key UNIQUE (purpose_pk, data_category_pk),
    CONSTRAINT priv_purpose_categories_purpose_fk FOREIGN KEY (purpose_pk)
        REFERENCES public.priv_purposes (purpose_pk) ON DELETE RESTRICT,
    CONSTRAINT priv_purpose_categories_category_fk FOREIGN KEY (data_category_pk)
        REFERENCES public.priv_data_categories (data_category_pk) ON DELETE RESTRICT
);

COMMENT ON TABLE public.priv_purpose_categories IS
    'Relational catalogue of data categories processed for each purpose; S1.';

CREATE INDEX priv_purpose_categories_category_idx
    ON public.priv_purpose_categories (data_category_pk, purpose_pk);

CREATE TABLE public.priv_consents (
    consent_pk bigint GENERATED ALWAYS AS IDENTITY,
    consent_id uuid NOT NULL DEFAULT pg_catalog.gen_random_uuid(),
    user_pk bigint NOT NULL,
    purpose_pk bigint NOT NULL,
    recipient_pk bigint NOT NULL,
    notice_pk bigint NOT NULL,
    status text COLLATE "C" NOT NULL DEFAULT 'PENDING',
    source_type text COLLATE "C" NOT NULL,
    consent_epoch bigint NOT NULL,
    granted_at timestamptz,
    withdrawn_at timestamptz,
    expires_at timestamptz,
    supersedes_consent_pk bigint,
    row_version bigint NOT NULL DEFAULT 1,
    created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    CONSTRAINT priv_consents_pkey PRIMARY KEY (consent_pk),
    CONSTRAINT priv_consents_id_key UNIQUE (consent_id),
    CONSTRAINT priv_consents_id_v4_ck CHECK (public.iam_uuid_is_v4(consent_id)),
    CONSTRAINT priv_consents_user_fk FOREIGN KEY (user_pk)
        REFERENCES public.iam_users (user_pk) ON DELETE RESTRICT,
    CONSTRAINT priv_consents_purpose_fk FOREIGN KEY (purpose_pk)
        REFERENCES public.priv_purposes (purpose_pk) ON DELETE RESTRICT,
    CONSTRAINT priv_consents_recipient_fk FOREIGN KEY (recipient_pk)
        REFERENCES public.priv_recipients (recipient_pk) ON DELETE RESTRICT,
    CONSTRAINT priv_consents_notice_fk FOREIGN KEY (notice_pk)
        REFERENCES public.priv_notices (notice_pk) ON DELETE RESTRICT,
    CONSTRAINT priv_consents_supersedes_fk FOREIGN KEY (supersedes_consent_pk)
        REFERENCES public.priv_consents (consent_pk) ON DELETE RESTRICT,
    CONSTRAINT priv_consents_no_self_ck CHECK (supersedes_consent_pk IS NULL OR supersedes_consent_pk <> consent_pk),
    CONSTRAINT priv_consents_status_ck CHECK (
        status IN ('PENDING', 'GRANTED', 'WITHDRAWN', 'EXPIRED', 'SUPERSEDED')
    ),
    CONSTRAINT priv_consents_source_ck CHECK (
        source_type IN ('WEB', 'MOBILE', 'ADMIN', 'IMPORT', 'API', 'PAPER')
    ),
    CONSTRAINT priv_consents_epoch_ck CHECK (consent_epoch > 0),
    CONSTRAINT priv_consents_state_time_ck CHECK (
        (status = 'PENDING' AND granted_at IS NULL AND withdrawn_at IS NULL)
        OR (status = 'GRANTED' AND granted_at IS NOT NULL AND withdrawn_at IS NULL)
        OR (status = 'WITHDRAWN' AND granted_at IS NOT NULL AND withdrawn_at IS NOT NULL)
        OR (status IN ('EXPIRED', 'SUPERSEDED') AND granted_at IS NOT NULL)
    ),
    CONSTRAINT priv_consents_time_ck CHECK (
        updated_at >= created_at
        AND (granted_at IS NULL OR granted_at >= created_at)
        AND (withdrawn_at IS NULL OR withdrawn_at >= granted_at)
        AND (expires_at IS NULL OR expires_at > granted_at)
    ),
    CONSTRAINT priv_consents_row_version_ck CHECK (row_version > 0)
);

COMMENT ON TABLE public.priv_consents IS
    'Consent record independent from agreement acceptance, marketing subscription and OAuth Grant; withdrawals are terminal; S3.';

CREATE UNIQUE INDEX priv_consents_granted_scope_uidx
    ON public.priv_consents (user_pk, purpose_pk, recipient_pk, notice_pk)
    WHERE status = 'GRANTED';
CREATE INDEX priv_consents_user_status_idx
    ON public.priv_consents (user_pk, status, created_at DESC);
CREATE INDEX priv_consents_expiry_idx
    ON public.priv_consents (expires_at, consent_pk)
    WHERE status = 'GRANTED' AND expires_at IS NOT NULL;

CREATE TRIGGER priv_consents_immutable_trg
BEFORE UPDATE ON public.priv_consents
FOR EACH ROW EXECUTE FUNCTION public.iam_reject_column_changes(
    'consent_pk', 'consent_id', 'user_pk', 'purpose_pk', 'recipient_pk',
    'notice_pk', 'source_type', 'created_at'
);

CREATE TRIGGER priv_consents_versions_trg
BEFORE UPDATE ON public.priv_consents
FOR EACH ROW EXECUTE FUNCTION public.iam_guard_nondecreasing_bigint('consent_epoch', 'row_version');

CREATE TABLE public.priv_consent_categories (
    consent_category_pk bigint GENERATED ALWAYS AS IDENTITY,
    consent_pk bigint NOT NULL,
    data_category_pk bigint NOT NULL,
    is_required boolean NOT NULL DEFAULT false,
    created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    CONSTRAINT priv_consent_categories_pkey PRIMARY KEY (consent_category_pk),
    CONSTRAINT priv_consent_categories_pair_key UNIQUE (consent_pk, data_category_pk),
    CONSTRAINT priv_consent_categories_consent_fk FOREIGN KEY (consent_pk)
        REFERENCES public.priv_consents (consent_pk) ON DELETE RESTRICT,
    CONSTRAINT priv_consent_categories_category_fk FOREIGN KEY (data_category_pk)
        REFERENCES public.priv_data_categories (data_category_pk) ON DELETE RESTRICT
);

COMMENT ON TABLE public.priv_consent_categories IS
    'Relational set of data categories covered by a consent; S3.';

CREATE INDEX priv_consent_categories_category_idx
    ON public.priv_consent_categories (data_category_pk, consent_pk);

CREATE TABLE public.priv_consent_evidence (
    consent_evidence_pk bigint GENERATED ALWAYS AS IDENTITY,
    consent_pk bigint NOT NULL,
    evidence_type text COLLATE "C" NOT NULL,
    evidence_digest bytea NOT NULL,
    encrypted_evidence bytea,
    encryption_key_ref text COLLATE "C",
    encryption_key_version integer,
    source_ip inet,
    user_agent_digest bytea,
    captured_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    CONSTRAINT priv_consent_evidence_pkey PRIMARY KEY (consent_evidence_pk),
    CONSTRAINT priv_consent_evidence_consent_fk FOREIGN KEY (consent_pk)
        REFERENCES public.priv_consents (consent_pk) ON DELETE RESTRICT,
    CONSTRAINT priv_consent_evidence_type_ck CHECK (
        evidence_type IN ('UI_CONFIRMATION', 'SIGNED_DOCUMENT', 'API_ATTESTATION', 'IMPORTED_RECORD', 'WITHDRAWAL')
    ),
    CONSTRAINT priv_consent_evidence_digest_ck CHECK (pg_catalog.octet_length(evidence_digest) = 32),
    CONSTRAINT priv_consent_evidence_encrypted_group_ck CHECK (
        (encrypted_evidence IS NULL AND encryption_key_ref IS NULL AND encryption_key_version IS NULL)
        OR (encrypted_evidence IS NOT NULL AND pg_catalog.octet_length(encrypted_evidence) BETWEEN 17 AND 1048576
            AND encryption_key_ref IS NOT NULL AND pg_catalog.length(encryption_key_ref) BETWEEN 1 AND 255
            AND encryption_key_version > 0)
    ),
    CONSTRAINT priv_consent_evidence_agent_digest_ck CHECK (
        user_agent_digest IS NULL OR pg_catalog.octet_length(user_agent_digest) = 32
    ),
    CONSTRAINT priv_consent_evidence_time_ck CHECK (captured_at <= created_at)
);

COMMENT ON TABLE public.priv_consent_evidence IS
    'Append-oriented consent grant or withdrawal evidence; PII evidence is encrypted and searchable values are not stored; S3.';

CREATE INDEX priv_consent_evidence_consent_time_idx
    ON public.priv_consent_evidence (consent_pk, captured_at DESC);

CREATE TRIGGER priv_consent_evidence_append_only_trg
BEFORE UPDATE OR DELETE ON public.priv_consent_evidence
FOR EACH ROW EXECUTE FUNCTION public.iam_reject_row_mutation();

CREATE TABLE public.priv_agreement_versions (
    agreement_version_pk bigint GENERATED ALWAYS AS IDENTITY,
    agreement_version_id uuid NOT NULL DEFAULT pg_catalog.gen_random_uuid(),
    agreement_code text COLLATE "C" NOT NULL,
    version_no integer NOT NULL,
    locale text COLLATE "C" NOT NULL,
    region_code text COLLATE "C" NOT NULL,
    status text COLLATE "C" NOT NULL DEFAULT 'DRAFT',
    content_reference text COLLATE "C" NOT NULL,
    content_hash bytea NOT NULL,
    effective_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    CONSTRAINT priv_agreement_versions_pkey PRIMARY KEY (agreement_version_pk),
    CONSTRAINT priv_agreement_versions_id_key UNIQUE (agreement_version_id),
    CONSTRAINT priv_agreement_versions_natural_key UNIQUE (agreement_code, version_no, locale, region_code),
    CONSTRAINT priv_agreement_versions_id_v4_ck CHECK (public.iam_uuid_is_v4(agreement_version_id)),
    CONSTRAINT priv_agreement_versions_code_ck CHECK (
        pg_catalog.length(agreement_code) BETWEEN 1 AND 96 AND agreement_code ~ '^[A-Z][A-Z0-9_.-]*$'
    ),
    CONSTRAINT priv_agreement_versions_version_ck CHECK (version_no > 0),
    CONSTRAINT priv_agreement_versions_locale_ck CHECK (
        pg_catalog.length(locale) BETWEEN 2 AND 35 AND locale ~ '^[A-Za-z0-9]+(?:-[A-Za-z0-9]+)*$'
    ),
    CONSTRAINT priv_agreement_versions_region_ck CHECK (
        pg_catalog.length(region_code) BETWEEN 2 AND 16 AND region_code ~ '^[A-Z0-9-]+$'
    ),
    CONSTRAINT priv_agreement_versions_status_ck CHECK (status IN ('DRAFT', 'PUBLISHED', 'RETIRED')),
    CONSTRAINT priv_agreement_versions_reference_ck CHECK (pg_catalog.length(content_reference) BETWEEN 1 AND 1024),
    CONSTRAINT priv_agreement_versions_hash_ck CHECK (pg_catalog.octet_length(content_hash) = 32),
    CONSTRAINT priv_agreement_versions_effective_ck CHECK (
        (status = 'DRAFT' AND effective_at IS NULL) OR (status <> 'DRAFT' AND effective_at IS NOT NULL)
    )
);

COMMENT ON TABLE public.priv_agreement_versions IS
    'Immutable versions of user agreements and terms; separate from privacy consent; S1.';

CREATE INDEX priv_agreement_versions_effective_idx
    ON public.priv_agreement_versions (agreement_code, region_code, locale, effective_at DESC)
    WHERE status = 'PUBLISHED';

CREATE TABLE public.priv_agreement_acceptances (
    agreement_acceptance_pk bigint GENERATED ALWAYS AS IDENTITY,
    agreement_acceptance_id uuid NOT NULL DEFAULT pg_catalog.gen_random_uuid(),
    user_pk bigint NOT NULL,
    agreement_version_pk bigint NOT NULL,
    acceptance_context text COLLATE "C" NOT NULL,
    source_type text COLLATE "C" NOT NULL,
    evidence_digest bytea NOT NULL,
    accepted_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    CONSTRAINT priv_agreement_acceptances_pkey PRIMARY KEY (agreement_acceptance_pk),
    CONSTRAINT priv_agreement_acceptances_id_key UNIQUE (agreement_acceptance_id),
    CONSTRAINT priv_agreement_acceptances_context_key UNIQUE (
        user_pk, agreement_version_pk, acceptance_context
    ),
    CONSTRAINT priv_agreement_acceptances_id_v4_ck CHECK (public.iam_uuid_is_v4(agreement_acceptance_id)),
    CONSTRAINT priv_agreement_acceptances_user_fk FOREIGN KEY (user_pk)
        REFERENCES public.iam_users (user_pk) ON DELETE RESTRICT,
    CONSTRAINT priv_agreement_acceptances_version_fk FOREIGN KEY (agreement_version_pk)
        REFERENCES public.priv_agreement_versions (agreement_version_pk) ON DELETE RESTRICT,
    CONSTRAINT priv_agreement_acceptances_context_ck CHECK (
        pg_catalog.length(acceptance_context) BETWEEN 1 AND 128
        AND acceptance_context ~ '^[A-Za-z0-9][A-Za-z0-9_.:/-]*$'
    ),
    CONSTRAINT priv_agreement_acceptances_source_ck CHECK (
        source_type IN ('WEB', 'MOBILE', 'ADMIN', 'IMPORT', 'API', 'PAPER')
    ),
    CONSTRAINT priv_agreement_acceptances_digest_ck CHECK (pg_catalog.octet_length(evidence_digest) = 32),
    CONSTRAINT priv_agreement_acceptances_time_ck CHECK (accepted_at <= created_at)
);

COMMENT ON TABLE public.priv_agreement_acceptances IS
    'Append-only evidence that a user accepted a specific agreement version; S3.';

CREATE INDEX priv_agreement_acceptances_user_time_idx
    ON public.priv_agreement_acceptances (user_pk, accepted_at DESC);

CREATE TRIGGER priv_agreement_acceptances_append_only_trg
BEFORE UPDATE OR DELETE ON public.priv_agreement_acceptances
FOR EACH ROW EXECUTE FUNCTION public.iam_reject_row_mutation();

CREATE TABLE public.priv_marketing_subscriptions (
    marketing_subscription_pk bigint GENERATED ALWAYS AS IDENTITY,
    marketing_subscription_id uuid NOT NULL DEFAULT pg_catalog.gen_random_uuid(),
    user_pk bigint NOT NULL,
    recipient_pk bigint NOT NULL,
    channel text COLLATE "C" NOT NULL,
    topic_code text COLLATE "C" NOT NULL,
    state text COLLATE "C" NOT NULL DEFAULT 'PENDING',
    source_type text COLLATE "C" NOT NULL,
    consent_pk bigint,
    subscribed_at timestamptz,
    unsubscribed_at timestamptz,
    row_version bigint NOT NULL DEFAULT 1,
    created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    CONSTRAINT priv_marketing_subscriptions_pkey PRIMARY KEY (marketing_subscription_pk),
    CONSTRAINT priv_marketing_subscriptions_id_key UNIQUE (marketing_subscription_id),
    CONSTRAINT priv_marketing_subscriptions_current_key UNIQUE (user_pk, recipient_pk, channel, topic_code),
    CONSTRAINT priv_marketing_subscriptions_id_v4_ck CHECK (public.iam_uuid_is_v4(marketing_subscription_id)),
    CONSTRAINT priv_marketing_subscriptions_user_fk FOREIGN KEY (user_pk)
        REFERENCES public.iam_users (user_pk) ON DELETE RESTRICT,
    CONSTRAINT priv_marketing_subscriptions_recipient_fk FOREIGN KEY (recipient_pk)
        REFERENCES public.priv_recipients (recipient_pk) ON DELETE RESTRICT,
    CONSTRAINT priv_marketing_subscriptions_consent_fk FOREIGN KEY (consent_pk)
        REFERENCES public.priv_consents (consent_pk) ON DELETE RESTRICT,
    CONSTRAINT priv_marketing_subscriptions_channel_ck CHECK (
        channel IN ('EMAIL', 'SMS', 'PUSH', 'PHONE', 'POSTAL', 'IN_APP')
    ),
    CONSTRAINT priv_marketing_subscriptions_topic_ck CHECK (
        pg_catalog.length(topic_code) BETWEEN 1 AND 96 AND topic_code ~ '^[A-Z][A-Z0-9_.-]*$'
    ),
    CONSTRAINT priv_marketing_subscriptions_state_ck CHECK (
        state IN ('PENDING', 'SUBSCRIBED', 'UNSUBSCRIBED', 'BOUNCED', 'SUPPRESSED')
    ),
    CONSTRAINT priv_marketing_subscriptions_source_ck CHECK (
        source_type IN ('WEB', 'MOBILE', 'ADMIN', 'IMPORT', 'API', 'PAPER', 'SYSTEM')
    ),
    CONSTRAINT priv_marketing_subscriptions_state_time_ck CHECK (
        (state = 'PENDING' AND subscribed_at IS NULL AND unsubscribed_at IS NULL)
        OR (state = 'SUBSCRIBED' AND subscribed_at IS NOT NULL AND unsubscribed_at IS NULL)
        OR (state IN ('UNSUBSCRIBED', 'BOUNCED', 'SUPPRESSED') AND subscribed_at IS NOT NULL AND unsubscribed_at IS NOT NULL)
    ),
    CONSTRAINT priv_marketing_subscriptions_time_ck CHECK (
        updated_at >= created_at
        AND (subscribed_at IS NULL OR subscribed_at >= created_at)
        AND (unsubscribed_at IS NULL OR unsubscribed_at >= subscribed_at)
    ),
    CONSTRAINT priv_marketing_subscriptions_row_version_ck CHECK (row_version > 0)
);

COMMENT ON TABLE public.priv_marketing_subscriptions IS
    'Per-channel marketing preference independent from agreement, consent and OAuth Grant; unsubscribe is immediate; S3.';

CREATE INDEX priv_marketing_subscriptions_user_state_idx
    ON public.priv_marketing_subscriptions (user_pk, state, channel);

CREATE TABLE public.priv_scope_claim_mappings (
    scope_claim_mapping_pk bigint GENERATED ALWAYS AS IDENTITY,
    purpose_pk bigint NOT NULL,
    data_category_pk bigint NOT NULL,
    recipient_pk bigint NOT NULL,
    mapping_kind text COLLATE "C" NOT NULL,
    api_scope_pk bigint,
    claim_name text COLLATE "C",
    grant_type text COLLATE "C",
    status text COLLATE "C" NOT NULL DEFAULT 'ACTIVE',
    created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    CONSTRAINT priv_scope_claim_mappings_pkey PRIMARY KEY (scope_claim_mapping_pk),
    CONSTRAINT priv_scope_claim_mappings_purpose_fk FOREIGN KEY (purpose_pk)
        REFERENCES public.priv_purposes (purpose_pk) ON DELETE RESTRICT,
    CONSTRAINT priv_scope_claim_mappings_category_fk FOREIGN KEY (data_category_pk)
        REFERENCES public.priv_data_categories (data_category_pk) ON DELETE RESTRICT,
    CONSTRAINT priv_scope_claim_mappings_recipient_fk FOREIGN KEY (recipient_pk)
        REFERENCES public.priv_recipients (recipient_pk) ON DELETE RESTRICT,
    CONSTRAINT priv_scope_claim_mappings_scope_fk FOREIGN KEY (api_scope_pk)
        REFERENCES public.app_api_scopes (api_scope_pk) ON DELETE RESTRICT,
    CONSTRAINT priv_scope_claim_mappings_kind_ck CHECK (
        mapping_kind IN ('OAUTH_SCOPE', 'OIDC_CLAIM', 'GRANT_TYPE', 'SUBSCRIPTION')
    ),
    CONSTRAINT priv_scope_claim_mappings_target_ck CHECK (
        (mapping_kind = 'OAUTH_SCOPE' AND api_scope_pk IS NOT NULL AND claim_name IS NULL AND grant_type IS NULL)
        OR (mapping_kind = 'OIDC_CLAIM' AND api_scope_pk IS NULL AND claim_name IS NOT NULL
            AND pg_catalog.length(claim_name) BETWEEN 1 AND 128 AND claim_name ~ '^[A-Za-z][A-Za-z0-9_.:-]*$'
            AND grant_type IS NULL)
        OR (mapping_kind IN ('GRANT_TYPE', 'SUBSCRIPTION') AND api_scope_pk IS NULL AND claim_name IS NULL
            AND grant_type IS NOT NULL AND pg_catalog.length(grant_type) BETWEEN 1 AND 128
            AND grant_type ~ '^[A-Za-z][A-Za-z0-9_.:-]*$')
    ),
    CONSTRAINT priv_scope_claim_mappings_status_ck CHECK (status IN ('ACTIVE', 'RETIRED'))
);

COMMENT ON TABLE public.priv_scope_claim_mappings IS
    'Auditable purpose-category-recipient mapping to OAuth scopes, claims, grant semantics or subscription topics; S2.';

CREATE UNIQUE INDEX priv_scope_claim_mappings_scope_uidx
    ON public.priv_scope_claim_mappings (purpose_pk, data_category_pk, recipient_pk, api_scope_pk)
    WHERE mapping_kind = 'OAUTH_SCOPE' AND status = 'ACTIVE';
CREATE UNIQUE INDEX priv_scope_claim_mappings_name_uidx
    ON public.priv_scope_claim_mappings (purpose_pk, data_category_pk, recipient_pk, mapping_kind, claim_name, grant_type)
    NULLS NOT DISTINCT
    WHERE mapping_kind <> 'OAUTH_SCOPE' AND status = 'ACTIVE';

CREATE TABLE public.priv_downstream_systems (
    downstream_system_pk bigint GENERATED ALWAYS AS IDENTITY,
    downstream_system_id uuid NOT NULL DEFAULT pg_catalog.gen_random_uuid(),
    system_code text COLLATE "C" NOT NULL,
    owner_principal_pk bigint,
    system_type text COLLATE "C" NOT NULL,
    status text COLLATE "C" NOT NULL DEFAULT 'ACTIVE',
    privacy_sla_seconds integer NOT NULL,
    row_version bigint NOT NULL DEFAULT 1,
    created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    CONSTRAINT priv_downstream_systems_pkey PRIMARY KEY (downstream_system_pk),
    CONSTRAINT priv_downstream_systems_id_key UNIQUE (downstream_system_id),
    CONSTRAINT priv_downstream_systems_code_key UNIQUE (system_code),
    CONSTRAINT priv_downstream_systems_id_v4_ck CHECK (public.iam_uuid_is_v4(downstream_system_id)),
    CONSTRAINT priv_downstream_systems_owner_fk FOREIGN KEY (owner_principal_pk)
        REFERENCES public.iam_principals (principal_pk) ON DELETE RESTRICT,
    CONSTRAINT priv_downstream_systems_code_ck CHECK (
        pg_catalog.length(system_code) BETWEEN 1 AND 96 AND system_code ~ '^[A-Z][A-Z0-9_.-]*$'
    ),
    CONSTRAINT priv_downstream_systems_type_ck CHECK (
        system_type IN ('DATABASE', 'SEARCH', 'CACHE', 'EVENT_STORE', 'ANALYTICS', 'BACKUP', 'OBJECT_STORE', 'EXTERNAL_PROCESSOR')
    ),
    CONSTRAINT priv_downstream_systems_status_ck CHECK (status IN ('ACTIVE', 'SUSPENDED', 'RETIRED')),
    CONSTRAINT priv_downstream_systems_sla_ck CHECK (privacy_sla_seconds BETWEEN 1 AND 31536000),
    CONSTRAINT priv_downstream_systems_version_ck CHECK (row_version > 0),
    CONSTRAINT priv_downstream_systems_time_ck CHECK (updated_at >= created_at)
);

COMMENT ON TABLE public.priv_downstream_systems IS
    'Privacy orchestration inventory for online, cached, analytical, backup and external processing systems; S2.';

CREATE INDEX priv_downstream_systems_owner_idx
    ON public.priv_downstream_systems (owner_principal_pk)
    WHERE owner_principal_pk IS NOT NULL;

CREATE TABLE public.priv_downstream_mappings (
    downstream_mapping_pk bigint GENERATED ALWAYS AS IDENTITY,
    downstream_system_pk bigint NOT NULL,
    purpose_pk bigint NOT NULL,
    data_category_pk bigint NOT NULL,
    recipient_pk bigint NOT NULL,
    storage_class text COLLATE "C" NOT NULL,
    object_locator_digest bytea NOT NULL,
    retention_days integer,
    status text COLLATE "C" NOT NULL DEFAULT 'ACTIVE',
    created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    CONSTRAINT priv_downstream_mappings_pkey PRIMARY KEY (downstream_mapping_pk),
    CONSTRAINT priv_downstream_mappings_natural_key UNIQUE (
        downstream_system_pk, purpose_pk, data_category_pk, recipient_pk, object_locator_digest
    ),
    CONSTRAINT priv_downstream_mappings_system_fk FOREIGN KEY (downstream_system_pk)
        REFERENCES public.priv_downstream_systems (downstream_system_pk) ON DELETE RESTRICT,
    CONSTRAINT priv_downstream_mappings_purpose_fk FOREIGN KEY (purpose_pk)
        REFERENCES public.priv_purposes (purpose_pk) ON DELETE RESTRICT,
    CONSTRAINT priv_downstream_mappings_category_fk FOREIGN KEY (data_category_pk)
        REFERENCES public.priv_data_categories (data_category_pk) ON DELETE RESTRICT,
    CONSTRAINT priv_downstream_mappings_recipient_fk FOREIGN KEY (recipient_pk)
        REFERENCES public.priv_recipients (recipient_pk) ON DELETE RESTRICT,
    CONSTRAINT priv_downstream_mappings_storage_ck CHECK (
        storage_class IN ('ONLINE', 'CACHE', 'INDEX', 'EVENT', 'ARCHIVE', 'BACKUP', 'TRAINING')
    ),
    CONSTRAINT priv_downstream_mappings_locator_ck CHECK (pg_catalog.octet_length(object_locator_digest) = 32),
    CONSTRAINT priv_downstream_mappings_retention_ck CHECK (retention_days IS NULL OR retention_days > 0),
    CONSTRAINT priv_downstream_mappings_status_ck CHECK (status IN ('ACTIVE', 'RETIRED'))
);

COMMENT ON TABLE public.priv_downstream_mappings IS
    'Relational inventory mapping purposes and categories to downstream storage without persisting raw object locators; S2/S3.';

CREATE INDEX priv_downstream_mappings_category_idx
    ON public.priv_downstream_mappings (data_category_pk, downstream_system_pk);

CREATE TABLE public.priv_privacy_requests (
    privacy_request_pk bigint GENERATED ALWAYS AS IDENTITY,
    privacy_request_id uuid NOT NULL DEFAULT pg_catalog.gen_random_uuid(),
    user_pk bigint NOT NULL,
    operation_pk bigint,
    request_type text COLLATE "C" NOT NULL,
    state text COLLATE "C" NOT NULL DEFAULT 'SUBMITTED',
    jurisdiction text COLLATE "C" NOT NULL,
    identity_assurance_level smallint,
    identity_verified_at timestamptz,
    deadline_at timestamptz NOT NULL,
    blocking_reason_code text COLLATE "C",
    result_reference text COLLATE "C",
    result_digest bytea,
    completed_at timestamptz,
    row_version bigint NOT NULL DEFAULT 1,
    created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    CONSTRAINT priv_privacy_requests_pkey PRIMARY KEY (privacy_request_pk),
    CONSTRAINT priv_privacy_requests_id_key UNIQUE (privacy_request_id),
    CONSTRAINT priv_privacy_requests_id_v4_ck CHECK (public.iam_uuid_is_v4(privacy_request_id)),
    CONSTRAINT priv_privacy_requests_user_fk FOREIGN KEY (user_pk)
        REFERENCES public.iam_users (user_pk) ON DELETE RESTRICT,
    CONSTRAINT priv_privacy_requests_operation_fk FOREIGN KEY (operation_pk)
        REFERENCES public.ops_operations (operation_pk) ON DELETE RESTRICT,
    CONSTRAINT priv_privacy_requests_type_ck CHECK (
        request_type IN ('ACCESS', 'RECTIFICATION', 'EXPORT', 'RESTRICTION', 'DELETION', 'OBJECTION', 'CONSENT_WITHDRAWAL')
    ),
    CONSTRAINT priv_privacy_requests_state_ck CHECK (
        state IN ('SUBMITTED', 'IDENTITY_VERIFIED', 'IN_PROGRESS', 'BLOCKED', 'PARTIAL', 'COMPLETED', 'REJECTED', 'CANCELLED')
    ),
    CONSTRAINT priv_privacy_requests_jurisdiction_ck CHECK (
        pg_catalog.length(jurisdiction) BETWEEN 2 AND 32 AND jurisdiction ~ '^[A-Z0-9_.-]+$'
    ),
    CONSTRAINT priv_privacy_requests_assurance_ck CHECK (
        identity_assurance_level IS NULL OR identity_assurance_level BETWEEN 1 AND 3
    ),
    CONSTRAINT priv_privacy_requests_identity_ck CHECK (
        (state = 'SUBMITTED' AND identity_verified_at IS NULL)
        OR (state <> 'SUBMITTED' AND identity_verified_at IS NOT NULL)
    ),
    CONSTRAINT priv_privacy_requests_blocking_ck CHECK (
        (state IN ('BLOCKED', 'REJECTED') AND blocking_reason_code IS NOT NULL
            AND pg_catalog.length(blocking_reason_code) BETWEEN 1 AND 64
            AND blocking_reason_code ~ '^[A-Z][A-Z0-9_]*$')
        OR (state NOT IN ('BLOCKED', 'REJECTED') AND blocking_reason_code IS NULL)
    ),
    CONSTRAINT priv_privacy_requests_result_ck CHECK (
        (result_reference IS NULL AND result_digest IS NULL)
        OR (result_reference IS NOT NULL AND pg_catalog.length(result_reference) BETWEEN 1 AND 1024
            AND result_digest IS NOT NULL AND pg_catalog.octet_length(result_digest) = 32)
    ),
    CONSTRAINT priv_privacy_requests_completion_ck CHECK (
        (state IN ('COMPLETED', 'REJECTED', 'CANCELLED')) = (completed_at IS NOT NULL)
    ),
    CONSTRAINT priv_privacy_requests_version_ck CHECK (row_version > 0),
    CONSTRAINT priv_privacy_requests_time_ck CHECK (
        updated_at >= created_at AND deadline_at > created_at
        AND (identity_verified_at IS NULL OR identity_verified_at >= created_at)
        AND (completed_at IS NULL OR completed_at >= created_at)
    )
);

COMMENT ON TABLE public.priv_privacy_requests IS
    'Data-subject request aggregate and deadline; task-completion and hold checks are deferred to 110; S3.';

CREATE INDEX priv_privacy_requests_user_time_idx
    ON public.priv_privacy_requests (user_pk, created_at DESC);
CREATE INDEX priv_privacy_requests_deadline_idx
    ON public.priv_privacy_requests (deadline_at, privacy_request_pk)
    WHERE state IN ('SUBMITTED', 'IDENTITY_VERIFIED', 'IN_PROGRESS', 'BLOCKED', 'PARTIAL');

CREATE TABLE public.priv_request_items (
    request_item_pk bigint GENERATED ALWAYS AS IDENTITY,
    privacy_request_pk bigint NOT NULL,
    item_type text COLLATE "C" NOT NULL,
    data_category_pk bigint,
    purpose_pk bigint,
    profile_value_pk bigint,
    requested_action text COLLATE "C" NOT NULL,
    state text COLLATE "C" NOT NULL DEFAULT 'PENDING',
    exception_code text COLLATE "C",
    created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    CONSTRAINT priv_request_items_pkey PRIMARY KEY (request_item_pk),
    CONSTRAINT priv_request_items_request_fk FOREIGN KEY (privacy_request_pk)
        REFERENCES public.priv_privacy_requests (privacy_request_pk) ON DELETE RESTRICT,
    CONSTRAINT priv_request_items_category_fk FOREIGN KEY (data_category_pk)
        REFERENCES public.priv_data_categories (data_category_pk) ON DELETE RESTRICT,
    CONSTRAINT priv_request_items_purpose_fk FOREIGN KEY (purpose_pk)
        REFERENCES public.priv_purposes (purpose_pk) ON DELETE RESTRICT,
    CONSTRAINT priv_request_items_profile_value_fk FOREIGN KEY (profile_value_pk)
        REFERENCES public.profile_namespace_values (profile_value_pk) ON DELETE RESTRICT,
    CONSTRAINT priv_request_items_type_ck CHECK (
        item_type IN ('CATEGORY', 'PURPOSE', 'PROFILE_VALUE', 'ALL_USER_DATA')
    ),
    CONSTRAINT priv_request_items_target_ck CHECK (
        (item_type = 'CATEGORY' AND data_category_pk IS NOT NULL AND purpose_pk IS NULL AND profile_value_pk IS NULL)
        OR (item_type = 'PURPOSE' AND data_category_pk IS NULL AND purpose_pk IS NOT NULL AND profile_value_pk IS NULL)
        OR (item_type = 'PROFILE_VALUE' AND data_category_pk IS NULL AND purpose_pk IS NULL AND profile_value_pk IS NOT NULL)
        OR (item_type = 'ALL_USER_DATA' AND data_category_pk IS NULL AND purpose_pk IS NULL AND profile_value_pk IS NULL)
    ),
    CONSTRAINT priv_request_items_action_ck CHECK (
        requested_action IN ('DISCLOSE', 'CORRECT', 'EXPORT', 'RESTRICT', 'DELETE', 'STOP_PROCESSING')
    ),
    CONSTRAINT priv_request_items_state_ck CHECK (
        state IN ('PENDING', 'IN_PROGRESS', 'BLOCKED', 'COMPLETED', 'REJECTED', 'SKIPPED')
    ),
    CONSTRAINT priv_request_items_exception_ck CHECK (
        exception_code IS NULL OR (
            pg_catalog.length(exception_code) BETWEEN 1 AND 64 AND exception_code ~ '^[A-Z][A-Z0-9_]*$'
        )
    ),
    CONSTRAINT priv_request_items_time_ck CHECK (updated_at >= created_at)
);

COMMENT ON TABLE public.priv_request_items IS
    'Typed relational scope items within a privacy request; S3.';

CREATE INDEX priv_request_items_request_state_idx
    ON public.priv_request_items (privacy_request_pk, state, request_item_pk);

CREATE TABLE public.priv_request_tasks (
    request_task_pk bigint GENERATED ALWAYS AS IDENTITY,
    request_task_id uuid NOT NULL DEFAULT pg_catalog.gen_random_uuid(),
    privacy_request_pk bigint NOT NULL,
    downstream_system_pk bigint NOT NULL,
    task_scope_digest bytea NOT NULL,
    task_type text COLLATE "C" NOT NULL,
    state text COLLATE "C" NOT NULL DEFAULT 'PENDING',
    checkpoint_schema_version integer NOT NULL DEFAULT 1,
    checkpoint jsonb NOT NULL DEFAULT '{}'::jsonb,
    attempt_count integer NOT NULL DEFAULT 0,
    next_attempt_at timestamptz,
    result_digest bytea,
    proof_reference text COLLATE "C",
    finished_at timestamptz,
    row_version bigint NOT NULL DEFAULT 1,
    created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    CONSTRAINT priv_request_tasks_pkey PRIMARY KEY (request_task_pk),
    CONSTRAINT priv_request_tasks_id_key UNIQUE (request_task_id),
    CONSTRAINT priv_request_tasks_scope_key UNIQUE (
        privacy_request_pk, downstream_system_pk, task_type, task_scope_digest
    ),
    CONSTRAINT priv_request_tasks_id_v4_ck CHECK (public.iam_uuid_is_v4(request_task_id)),
    CONSTRAINT priv_request_tasks_request_fk FOREIGN KEY (privacy_request_pk)
        REFERENCES public.priv_privacy_requests (privacy_request_pk) ON DELETE RESTRICT,
    CONSTRAINT priv_request_tasks_system_fk FOREIGN KEY (downstream_system_pk)
        REFERENCES public.priv_downstream_systems (downstream_system_pk) ON DELETE RESTRICT,
    CONSTRAINT priv_request_tasks_scope_digest_ck CHECK (pg_catalog.octet_length(task_scope_digest) = 32),
    CONSTRAINT priv_request_tasks_type_ck CHECK (
        task_type IN ('DISCOVER', 'EXPORT', 'RECTIFY', 'RESTRICT', 'DELETE', 'ANONYMIZE', 'STOP_PROCESSING', 'VERIFY_BACKUP_POLICY')
    ),
    CONSTRAINT priv_request_tasks_state_ck CHECK (
        state IN ('PENDING', 'RUNNING', 'BLOCKED', 'RETRY', 'SUCCEEDED', 'FAILED', 'SKIPPED')
    ),
    CONSTRAINT priv_request_tasks_checkpoint_ck CHECK (
        checkpoint_schema_version > 0 AND pg_catalog.jsonb_typeof(checkpoint) = 'object'
        AND pg_catalog.octet_length(checkpoint::text) <= 262144
    ),
    CONSTRAINT priv_request_tasks_attempt_ck CHECK (attempt_count >= 0),
    CONSTRAINT priv_request_tasks_result_ck CHECK (
        result_digest IS NULL OR pg_catalog.octet_length(result_digest) = 32
    ),
    CONSTRAINT priv_request_tasks_proof_ck CHECK (
        proof_reference IS NULL OR pg_catalog.length(proof_reference) BETWEEN 1 AND 1024
    ),
    CONSTRAINT priv_request_tasks_finish_ck CHECK (
        (state IN ('SUCCEEDED', 'FAILED', 'SKIPPED')) = (finished_at IS NOT NULL)
    ),
    CONSTRAINT priv_request_tasks_version_ck CHECK (row_version > 0),
    CONSTRAINT priv_request_tasks_time_ck CHECK (
        updated_at >= created_at
        AND (next_attempt_at IS NULL OR next_attempt_at >= created_at)
        AND (finished_at IS NULL OR finished_at >= created_at)
    )
);

COMMENT ON TABLE public.priv_request_tasks IS
    'Per-downstream idempotent Saga task with bounded JSON checkpoint and proof reference; S3.';

CREATE INDEX priv_request_tasks_claim_idx
    ON public.priv_request_tasks (state, next_attempt_at, request_task_pk)
    WHERE state IN ('PENDING', 'RETRY', 'BLOCKED');
CREATE INDEX priv_request_tasks_request_state_idx
    ON public.priv_request_tasks (privacy_request_pk, state);

CREATE TABLE public.priv_request_attempts (
    request_attempt_pk bigint GENERATED ALWAYS AS IDENTITY,
    request_task_pk bigint NOT NULL,
    attempt_no integer NOT NULL,
    state text COLLATE "C" NOT NULL,
    request_digest bytea NOT NULL,
    response_digest bytea,
    error_code text COLLATE "C",
    started_at timestamptz NOT NULL,
    finished_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    CONSTRAINT priv_request_attempts_pkey PRIMARY KEY (request_attempt_pk),
    CONSTRAINT priv_request_attempts_number_key UNIQUE (request_task_pk, attempt_no),
    CONSTRAINT priv_request_attempts_task_fk FOREIGN KEY (request_task_pk)
        REFERENCES public.priv_request_tasks (request_task_pk) ON DELETE RESTRICT,
    CONSTRAINT priv_request_attempts_number_ck CHECK (attempt_no > 0),
    CONSTRAINT priv_request_attempts_state_ck CHECK (
        state IN ('STARTED', 'SUCCEEDED', 'FAILED', 'TIMED_OUT')
    ),
    CONSTRAINT priv_request_attempts_request_digest_ck CHECK (pg_catalog.octet_length(request_digest) = 32),
    CONSTRAINT priv_request_attempts_response_digest_ck CHECK (
        response_digest IS NULL OR pg_catalog.octet_length(response_digest) = 32
    ),
    CONSTRAINT priv_request_attempts_error_ck CHECK (
        error_code IS NULL OR (
            pg_catalog.length(error_code) BETWEEN 1 AND 64 AND error_code ~ '^[A-Z][A-Z0-9_]*$'
        )
    ),
    CONSTRAINT priv_request_attempts_finish_ck CHECK (
        (state = 'STARTED' AND finished_at IS NULL)
        OR (state <> 'STARTED' AND finished_at IS NOT NULL)
    ),
    CONSTRAINT priv_request_attempts_time_ck CHECK (
        started_at <= created_at AND (finished_at IS NULL OR finished_at >= started_at)
    )
);

COMMENT ON TABLE public.priv_request_attempts IS
    'Append-oriented attempts for privacy downstream tasks; request and response bodies are represented only by digests; S3.';

CREATE INDEX priv_request_attempts_task_time_idx
    ON public.priv_request_attempts (request_task_pk, started_at DESC);

CREATE TRIGGER priv_request_attempts_append_only_trg
BEFORE UPDATE OR DELETE ON public.priv_request_attempts
FOR EACH ROW EXECUTE FUNCTION public.iam_reject_row_mutation();

CREATE TABLE public.priv_legal_holds (
    legal_hold_pk bigint GENERATED ALWAYS AS IDENTITY,
    legal_hold_id uuid NOT NULL DEFAULT pg_catalog.gen_random_uuid(),
    hold_code text COLLATE "C" NOT NULL,
    legal_basis_code text COLLATE "C" NOT NULL,
    state text COLLATE "C" NOT NULL DEFAULT 'DRAFT',
    scope_summary_digest bytea NOT NULL,
    approved_by_principal_pk bigint,
    starts_at timestamptz,
    ends_at timestamptz,
    released_at timestamptz,
    row_version bigint NOT NULL DEFAULT 1,
    created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    CONSTRAINT priv_legal_holds_pkey PRIMARY KEY (legal_hold_pk),
    CONSTRAINT priv_legal_holds_id_key UNIQUE (legal_hold_id),
    CONSTRAINT priv_legal_holds_code_key UNIQUE (hold_code),
    CONSTRAINT priv_legal_holds_id_v4_ck CHECK (public.iam_uuid_is_v4(legal_hold_id)),
    CONSTRAINT priv_legal_holds_approver_fk FOREIGN KEY (approved_by_principal_pk)
        REFERENCES public.iam_principals (principal_pk) ON DELETE RESTRICT,
    CONSTRAINT priv_legal_holds_code_ck CHECK (
        pg_catalog.length(hold_code) BETWEEN 1 AND 96 AND hold_code ~ '^[A-Z][A-Z0-9_.-]*$'
    ),
    CONSTRAINT priv_legal_holds_basis_ck CHECK (
        pg_catalog.length(legal_basis_code) BETWEEN 1 AND 96 AND legal_basis_code ~ '^[A-Z][A-Z0-9_.-]*$'
    ),
    CONSTRAINT priv_legal_holds_state_ck CHECK (
        state IN ('DRAFT', 'APPROVED', 'ACTIVE', 'RELEASED', 'EXPIRED', 'CANCELLED')
    ),
    CONSTRAINT priv_legal_holds_digest_ck CHECK (pg_catalog.octet_length(scope_summary_digest) = 32),
    CONSTRAINT priv_legal_holds_approval_ck CHECK (
        (state = 'DRAFT' AND approved_by_principal_pk IS NULL AND starts_at IS NULL)
        OR (state <> 'DRAFT' AND approved_by_principal_pk IS NOT NULL AND starts_at IS NOT NULL)
    ),
    CONSTRAINT priv_legal_holds_release_ck CHECK (
        (state = 'RELEASED') = (released_at IS NOT NULL)
    ),
    CONSTRAINT priv_legal_holds_version_ck CHECK (row_version > 0),
    CONSTRAINT priv_legal_holds_time_ck CHECK (
        updated_at >= created_at
        AND (starts_at IS NULL OR starts_at >= created_at)
        AND (ends_at IS NULL OR ends_at > starts_at)
        AND (released_at IS NULL OR released_at >= starts_at)
    )
);

COMMENT ON TABLE public.priv_legal_holds IS
    'Approved legal-hold root; scope membership and release authorization are enforced by 110 functions; S3.';

CREATE INDEX priv_legal_holds_active_idx
    ON public.priv_legal_holds (ends_at, legal_hold_pk)
    WHERE state = 'ACTIVE';

CREATE TABLE public.priv_hold_targets (
    hold_target_pk bigint GENERATED ALWAYS AS IDENTITY,
    legal_hold_pk bigint NOT NULL,
    target_type text COLLATE "C" NOT NULL,
    user_pk bigint,
    data_category_pk bigint,
    downstream_system_pk bigint,
    object_type text COLLATE "C",
    object_key_digest bytea,
    range_start_at timestamptz,
    range_end_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    CONSTRAINT priv_hold_targets_pkey PRIMARY KEY (hold_target_pk),
    CONSTRAINT priv_hold_targets_hold_fk FOREIGN KEY (legal_hold_pk)
        REFERENCES public.priv_legal_holds (legal_hold_pk) ON DELETE RESTRICT,
    CONSTRAINT priv_hold_targets_user_fk FOREIGN KEY (user_pk)
        REFERENCES public.iam_users (user_pk) ON DELETE RESTRICT,
    CONSTRAINT priv_hold_targets_category_fk FOREIGN KEY (data_category_pk)
        REFERENCES public.priv_data_categories (data_category_pk) ON DELETE RESTRICT,
    CONSTRAINT priv_hold_targets_system_fk FOREIGN KEY (downstream_system_pk)
        REFERENCES public.priv_downstream_systems (downstream_system_pk) ON DELETE RESTRICT,
    CONSTRAINT priv_hold_targets_type_ck CHECK (
        target_type IN ('USER', 'DATA_CATEGORY', 'DOWNSTREAM_SYSTEM', 'OBJECT', 'TIME_RANGE')
    ),
    CONSTRAINT priv_hold_targets_target_ck CHECK (
        (target_type = 'USER' AND user_pk IS NOT NULL AND data_category_pk IS NULL
            AND downstream_system_pk IS NULL AND object_type IS NULL AND object_key_digest IS NULL
            AND range_start_at IS NULL AND range_end_at IS NULL)
        OR (target_type = 'DATA_CATEGORY' AND user_pk IS NULL AND data_category_pk IS NOT NULL
            AND downstream_system_pk IS NULL AND object_type IS NULL AND object_key_digest IS NULL
            AND range_start_at IS NULL AND range_end_at IS NULL)
        OR (target_type = 'DOWNSTREAM_SYSTEM' AND user_pk IS NULL AND data_category_pk IS NULL
            AND downstream_system_pk IS NOT NULL AND object_type IS NULL AND object_key_digest IS NULL
            AND range_start_at IS NULL AND range_end_at IS NULL)
        OR (target_type = 'OBJECT' AND user_pk IS NULL AND data_category_pk IS NULL
            AND object_type IS NOT NULL AND pg_catalog.length(object_type) BETWEEN 1 AND 96
            AND object_type ~ '^[A-Za-z][A-Za-z0-9_.:-]*$'
            AND object_key_digest IS NOT NULL AND pg_catalog.octet_length(object_key_digest) = 32)
        OR (target_type = 'TIME_RANGE' AND user_pk IS NULL AND data_category_pk IS NULL
            AND object_type IS NULL AND object_key_digest IS NULL
            AND range_start_at IS NOT NULL AND range_end_at IS NOT NULL AND range_end_at > range_start_at)
    )
);

COMMENT ON TABLE public.priv_hold_targets IS
    'Typed legal-hold targets for users, categories, systems, opaque objects and time ranges; S3.';

CREATE INDEX priv_hold_targets_user_idx
    ON public.priv_hold_targets (user_pk, legal_hold_pk)
    WHERE user_pk IS NOT NULL;
CREATE INDEX priv_hold_targets_category_idx
    ON public.priv_hold_targets (data_category_pk, legal_hold_pk)
    WHERE data_category_pk IS NOT NULL;

CREATE TABLE public.priv_deletion_certificates (
    deletion_certificate_pk bigint GENERATED ALWAYS AS IDENTITY,
    deletion_certificate_id uuid NOT NULL DEFAULT pg_catalog.gen_random_uuid(),
    privacy_request_pk bigint NOT NULL,
    request_task_pk bigint,
    downstream_system_pk bigint NOT NULL,
    certificate_type text COLLATE "C" NOT NULL,
    scope_digest bytea NOT NULL,
    proof_hash bytea NOT NULL,
    proof_reference text COLLATE "C",
    signer_key_ref text COLLATE "C",
    signer_key_version integer,
    signature bytea,
    completed_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    CONSTRAINT priv_deletion_certificates_pkey PRIMARY KEY (deletion_certificate_pk),
    CONSTRAINT priv_deletion_certificates_id_key UNIQUE (deletion_certificate_id),
    CONSTRAINT priv_deletion_certificates_proof_key UNIQUE (proof_hash),
    CONSTRAINT priv_deletion_certificates_scope_key UNIQUE (
        privacy_request_pk, downstream_system_pk, certificate_type, scope_digest
    ),
    CONSTRAINT priv_deletion_certificates_id_v4_ck CHECK (public.iam_uuid_is_v4(deletion_certificate_id)),
    CONSTRAINT priv_deletion_certificates_request_fk FOREIGN KEY (privacy_request_pk)
        REFERENCES public.priv_privacy_requests (privacy_request_pk) ON DELETE RESTRICT,
    CONSTRAINT priv_deletion_certificates_task_fk FOREIGN KEY (request_task_pk)
        REFERENCES public.priv_request_tasks (request_task_pk) ON DELETE RESTRICT,
    CONSTRAINT priv_deletion_certificates_system_fk FOREIGN KEY (downstream_system_pk)
        REFERENCES public.priv_downstream_systems (downstream_system_pk) ON DELETE RESTRICT,
    CONSTRAINT priv_deletion_certificates_type_ck CHECK (
        certificate_type IN ('DELETED', 'ANONYMIZED', 'CACHE_PURGED', 'INDEX_PURGED', 'BACKUP_POLICY_CONFIRMED', 'NOT_APPLICABLE')
    ),
    CONSTRAINT priv_deletion_certificates_scope_digest_ck CHECK (pg_catalog.octet_length(scope_digest) = 32),
    CONSTRAINT priv_deletion_certificates_proof_hash_ck CHECK (pg_catalog.octet_length(proof_hash) = 32),
    CONSTRAINT priv_deletion_certificates_reference_ck CHECK (
        proof_reference IS NULL OR pg_catalog.length(proof_reference) BETWEEN 1 AND 1024
    ),
    CONSTRAINT priv_deletion_certificates_signature_group_ck CHECK (
        (signer_key_ref IS NULL AND signer_key_version IS NULL AND signature IS NULL)
        OR (signer_key_ref IS NOT NULL AND pg_catalog.length(signer_key_ref) BETWEEN 1 AND 255
            AND signer_key_version > 0 AND signature IS NOT NULL AND pg_catalog.octet_length(signature) BETWEEN 32 AND 8192)
    ),
    CONSTRAINT priv_deletion_certificates_time_ck CHECK (completed_at <= created_at)
);

COMMENT ON TABLE public.priv_deletion_certificates IS
    'Append-only deletion, anonymization and backup-policy completion certificates containing no deleted PII; S2/S3.';

CREATE INDEX priv_deletion_certificates_request_idx
    ON public.priv_deletion_certificates (privacy_request_pk, completed_at DESC);

CREATE TRIGGER priv_deletion_certificates_append_only_trg
BEFORE UPDATE OR DELETE ON public.priv_deletion_certificates
FOR EACH ROW EXECUTE FUNCTION public.iam_reject_row_mutation();

COMMIT;
