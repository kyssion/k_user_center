-- Authenticators, credentials, authentication transactions, challenges, and assurance context.

BEGIN;

CREATE TABLE public.auth_authenticators (
    authenticator_pk bigint GENERATED ALWAYS AS IDENTITY,
    authenticator_id uuid NOT NULL DEFAULT pg_catalog.gen_random_uuid(),
    user_pk bigint NOT NULL,
    authenticator_type text COLLATE "C" NOT NULL,
    state text COLLATE "C" NOT NULL DEFAULT 'PENDING',
    aal_capability smallint NOT NULL,
    phishing_resistant boolean NOT NULL DEFAULT false,
    registered_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    activated_at timestamptz,
    last_used_at timestamptz,
    expires_at timestamptz,
    compromised_at timestamptz,
    revoked_at timestamptz,
    replaced_by_authenticator_pk bigint,
    row_version bigint NOT NULL DEFAULT 1,
    created_by_principal_pk bigint,
    updated_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    CONSTRAINT auth_authenticators_pkey PRIMARY KEY (authenticator_pk),
    CONSTRAINT auth_authenticators_id_key UNIQUE (authenticator_id),
    CONSTRAINT auth_authenticators_user_pk_key UNIQUE (user_pk, authenticator_pk),
    CONSTRAINT auth_authenticators_id_v4_ck CHECK (public.iam_uuid_is_v4(authenticator_id)),
    CONSTRAINT auth_authenticators_user_fk FOREIGN KEY (user_pk)
        REFERENCES public.iam_users (user_pk) ON DELETE RESTRICT,
    CONSTRAINT auth_authenticators_replacement_fk FOREIGN KEY (replaced_by_authenticator_pk)
        REFERENCES public.auth_authenticators (authenticator_pk) ON DELETE RESTRICT,
    CONSTRAINT auth_authenticators_actor_fk FOREIGN KEY (created_by_principal_pk)
        REFERENCES public.iam_principals (principal_pk) ON DELETE RESTRICT,
    CONSTRAINT auth_authenticators_type_ck
        CHECK (authenticator_type IN ('PASSWORD', 'WEBAUTHN', 'TOTP', 'RECOVERY_CODES')),
    CONSTRAINT auth_authenticators_state_ck CHECK (
        state IN ('PENDING', 'ACTIVE', 'SUSPENDED', 'LOCKED', 'EXPIRED',
                  'COMPROMISED', 'REVOKED', 'REPLACED')
    ),
    CONSTRAINT auth_authenticators_aal_ck CHECK (aal_capability BETWEEN 1 AND 3),
    CONSTRAINT auth_authenticators_activation_ck
        CHECK ((state = 'PENDING') = (activated_at IS NULL)),
    CONSTRAINT auth_authenticators_compromised_ck CHECK (
        (state <> 'COMPROMISED' OR compromised_at IS NOT NULL)
        AND (compromised_at IS NULL OR state IN ('COMPROMISED', 'REVOKED'))
    ),
    CONSTRAINT auth_authenticators_revoked_ck
        CHECK ((state IN ('REVOKED', 'REPLACED')) = (revoked_at IS NOT NULL)),
    CONSTRAINT auth_authenticators_replaced_ck
        CHECK ((state = 'REPLACED') = (replaced_by_authenticator_pk IS NOT NULL)),
    CONSTRAINT auth_authenticators_row_version_ck CHECK (row_version > 0),
    CONSTRAINT auth_authenticators_time_ck CHECK (
        updated_at >= registered_at
        AND (activated_at IS NULL OR activated_at >= registered_at)
        AND (last_used_at IS NULL OR last_used_at >= registered_at)
        AND (expires_at IS NULL OR expires_at > registered_at)
        AND (compromised_at IS NULL OR compromised_at >= registered_at)
        AND (revoked_at IS NULL OR revoked_at >= registered_at)
    )
);

COMMENT ON TABLE public.auth_authenticators IS
    'User authenticator aggregate with explicit assurance capability and retained terminal-state evidence; S3.';
CREATE INDEX auth_authenticators_user_state_idx
    ON public.auth_authenticators (user_pk, state);
CREATE INDEX auth_authenticators_active_expiry_idx
    ON public.auth_authenticators (expires_at)
    WHERE state = 'ACTIVE' AND expires_at IS NOT NULL;

CREATE TABLE public.auth_password_credentials (
    password_credential_pk bigint GENERATED ALWAYS AS IDENTITY,
    authenticator_pk bigint NOT NULL,
    algorithm text COLLATE "C" NOT NULL,
    algorithm_parameters text COLLATE "C" NOT NULL,
    salt bytea NOT NULL,
    password_hash bytea NOT NULL,
    pepper_key_ref text COLLATE "C" NOT NULL,
    pepper_key_version integer NOT NULL,
    changed_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    breach_checked_at timestamptz,
    needs_rehash boolean NOT NULL DEFAULT false,
    CONSTRAINT auth_password_credentials_pkey PRIMARY KEY (password_credential_pk),
    CONSTRAINT auth_password_credentials_authenticator_key UNIQUE (authenticator_pk),
    CONSTRAINT auth_password_credentials_authenticator_fk FOREIGN KEY (authenticator_pk)
        REFERENCES public.auth_authenticators (authenticator_pk) ON DELETE RESTRICT,
    CONSTRAINT auth_password_credentials_algorithm_ck
        CHECK (algorithm IN ('ARGON2ID', 'SCRYPT', 'PBKDF2_SHA256')),
    CONSTRAINT auth_password_credentials_parameters_ck
        CHECK (pg_catalog.length(algorithm_parameters) BETWEEN 1 AND 512),
    CONSTRAINT auth_password_credentials_material_ck CHECK (
        pg_catalog.octet_length(salt) >= 16
        AND pg_catalog.octet_length(password_hash) >= 16
        AND pg_catalog.length(pepper_key_ref) BETWEEN 1 AND 512
        AND pepper_key_version > 0
    ),
    CONSTRAINT auth_password_credentials_breach_time_ck
        CHECK (breach_checked_at IS NULL OR breach_checked_at >= changed_at)
);

COMMENT ON TABLE public.auth_password_credentials IS
    'One adaptive password hash per PASSWORD authenticator; plaintext and reversible passwords are forbidden; S4.';

CREATE TABLE public.auth_password_history (
    password_history_pk bigint GENERATED ALWAYS AS IDENTITY,
    user_pk bigint NOT NULL,
    sequence_no integer NOT NULL,
    verification_digest bytea NOT NULL,
    pepper_key_ref text COLLATE "C" NOT NULL,
    pepper_key_version integer NOT NULL,
    created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    CONSTRAINT auth_password_history_pkey PRIMARY KEY (password_history_pk),
    CONSTRAINT auth_password_history_sequence_key UNIQUE (user_pk, sequence_no),
    CONSTRAINT auth_password_history_user_fk FOREIGN KEY (user_pk)
        REFERENCES public.iam_users (user_pk) ON DELETE RESTRICT,
    CONSTRAINT auth_password_history_sequence_ck CHECK (sequence_no > 0),
    CONSTRAINT auth_password_history_digest_ck CHECK (
        pg_catalog.octet_length(verification_digest) = 32
        AND pg_catalog.length(pepper_key_ref) BETWEEN 1 AND 512
        AND pepper_key_version > 0
    )
);

COMMENT ON TABLE public.auth_password_history IS
    'Peppered irreversible password-reuse verification history; no password hash used for login is copied here; S4.';
CREATE INDEX auth_password_history_user_created_idx
    ON public.auth_password_history (user_pk, created_at DESC);

CREATE TABLE public.auth_webauthn_credentials (
    webauthn_credential_pk bigint GENERATED ALWAYS AS IDENTITY,
    authenticator_pk bigint NOT NULL,
    credential_id_digest bytea NOT NULL,
    credential_id_ciphertext bytea NOT NULL,
    encryption_key_ref text COLLATE "C" NOT NULL,
    encryption_key_version integer NOT NULL,
    public_key_cose bytea NOT NULL,
    sign_count bigint NOT NULL DEFAULT 0,
    aaguid uuid,
    user_verification_required boolean NOT NULL,
    discoverable boolean NOT NULL,
    backup_eligible boolean NOT NULL,
    backup_state boolean NOT NULL,
    attestation_format text COLLATE "C",
    last_used_at timestamptz,
    CONSTRAINT auth_webauthn_credentials_pkey PRIMARY KEY (webauthn_credential_pk),
    CONSTRAINT auth_webauthn_credentials_authenticator_key UNIQUE (authenticator_pk),
    CONSTRAINT auth_webauthn_credentials_credential_key UNIQUE (credential_id_digest),
    CONSTRAINT auth_webauthn_credentials_authenticator_fk FOREIGN KEY (authenticator_pk)
        REFERENCES public.auth_authenticators (authenticator_pk) ON DELETE RESTRICT,
    CONSTRAINT auth_webauthn_credentials_digest_ck
        CHECK (pg_catalog.octet_length(credential_id_digest) = 32),
    CONSTRAINT auth_webauthn_credentials_cipher_ck CHECK (
        pg_catalog.octet_length(credential_id_ciphertext) >= 28
        AND pg_catalog.length(encryption_key_ref) BETWEEN 1 AND 512
        AND encryption_key_version > 0
    ),
    CONSTRAINT auth_webauthn_credentials_public_key_ck
        CHECK (pg_catalog.octet_length(public_key_cose) BETWEEN 16 AND 4096),
    CONSTRAINT auth_webauthn_credentials_sign_count_ck CHECK (sign_count >= 0),
    CONSTRAINT auth_webauthn_credentials_backup_ck CHECK (NOT backup_state OR backup_eligible),
    CONSTRAINT auth_webauthn_credentials_attestation_ck
        CHECK (attestation_format IS NULL OR pg_catalog.length(attestation_format) BETWEEN 1 AND 64)
);

COMMENT ON TABLE public.auth_webauthn_credentials IS
    'WebAuthn credential digest/ciphertext, public COSE key, counter, UV, discoverability and backup metadata; no private key; S3.';
CREATE INDEX auth_webauthn_credentials_aaguid_idx
    ON public.auth_webauthn_credentials (aaguid) WHERE aaguid IS NOT NULL;

CREATE TABLE public.auth_totp_credentials (
    totp_credential_pk bigint GENERATED ALWAYS AS IDENTITY,
    authenticator_pk bigint NOT NULL,
    secret_ciphertext bytea NOT NULL,
    encryption_key_ref text COLLATE "C" NOT NULL,
    encryption_key_version integer NOT NULL,
    algorithm text COLLATE "C" NOT NULL DEFAULT 'SHA256',
    digits smallint NOT NULL DEFAULT 6,
    period_seconds smallint NOT NULL DEFAULT 30,
    last_accepted_step bigint,
    CONSTRAINT auth_totp_credentials_pkey PRIMARY KEY (totp_credential_pk),
    CONSTRAINT auth_totp_credentials_authenticator_key UNIQUE (authenticator_pk),
    CONSTRAINT auth_totp_credentials_authenticator_fk FOREIGN KEY (authenticator_pk)
        REFERENCES public.auth_authenticators (authenticator_pk) ON DELETE RESTRICT,
    CONSTRAINT auth_totp_credentials_secret_ck CHECK (
        pg_catalog.octet_length(secret_ciphertext) >= 28
        AND pg_catalog.length(encryption_key_ref) BETWEEN 1 AND 512
        AND encryption_key_version > 0
    ),
    CONSTRAINT auth_totp_credentials_algorithm_ck CHECK (algorithm IN ('SHA1', 'SHA256', 'SHA512')),
    CONSTRAINT auth_totp_credentials_digits_ck CHECK (digits IN (6, 8)),
    CONSTRAINT auth_totp_credentials_period_ck CHECK (period_seconds IN (30, 60)),
    CONSTRAINT auth_totp_credentials_step_ck CHECK (last_accepted_step IS NULL OR last_accepted_step >= 0)
);

COMMENT ON TABLE public.auth_totp_credentials IS
    'Randomized encrypted TOTP seed with KMS reference and replay-resistant accepted time step; S4.';

CREATE TABLE public.auth_recovery_code_batches (
    recovery_code_batch_pk bigint GENERATED ALWAYS AS IDENTITY,
    recovery_code_batch_id uuid NOT NULL DEFAULT pg_catalog.gen_random_uuid(),
    user_pk bigint NOT NULL,
    authenticator_pk bigint NOT NULL,
    state text COLLATE "C" NOT NULL DEFAULT 'ACTIVE',
    generated_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    invalidated_at timestamptz,
    expires_at timestamptz,
    CONSTRAINT auth_recovery_code_batches_pkey PRIMARY KEY (recovery_code_batch_pk),
    CONSTRAINT auth_recovery_code_batches_id_key UNIQUE (recovery_code_batch_id),
    CONSTRAINT auth_recovery_code_batches_id_v4_ck CHECK (public.iam_uuid_is_v4(recovery_code_batch_id)),
    CONSTRAINT auth_recovery_code_batches_user_fk FOREIGN KEY (user_pk)
        REFERENCES public.iam_users (user_pk) ON DELETE RESTRICT,
    CONSTRAINT auth_recovery_code_batches_authenticator_fk FOREIGN KEY (user_pk, authenticator_pk)
        REFERENCES public.auth_authenticators (user_pk, authenticator_pk) ON DELETE RESTRICT,
    CONSTRAINT auth_recovery_code_batches_state_ck CHECK (state IN ('ACTIVE', 'EXHAUSTED', 'REVOKED', 'EXPIRED')),
    CONSTRAINT auth_recovery_code_batches_invalidated_ck
        CHECK ((state <> 'ACTIVE') = (invalidated_at IS NOT NULL)),
    CONSTRAINT auth_recovery_code_batches_time_ck CHECK (
        (invalidated_at IS NULL OR invalidated_at >= generated_at)
        AND (expires_at IS NULL OR expires_at > generated_at)
    )
);

COMMENT ON TABLE public.auth_recovery_code_batches IS
    'Recovery-code batch lifecycle; at most one active batch per user; S3.';
CREATE UNIQUE INDEX auth_recovery_code_batches_active_uidx
    ON public.auth_recovery_code_batches (user_pk) WHERE state = 'ACTIVE';

CREATE TABLE public.auth_recovery_codes (
    recovery_code_pk bigint GENERATED ALWAYS AS IDENTITY,
    recovery_code_batch_pk bigint NOT NULL,
    code_digest bytea NOT NULL,
    pepper_key_ref text COLLATE "C" NOT NULL,
    pepper_key_version integer NOT NULL,
    state text COLLATE "C" NOT NULL DEFAULT 'CURRENT',
    used_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    CONSTRAINT auth_recovery_codes_pkey PRIMARY KEY (recovery_code_pk),
    CONSTRAINT auth_recovery_codes_digest_key UNIQUE (code_digest),
    CONSTRAINT auth_recovery_codes_batch_digest_key UNIQUE (recovery_code_batch_pk, code_digest),
    CONSTRAINT auth_recovery_codes_batch_fk FOREIGN KEY (recovery_code_batch_pk)
        REFERENCES public.auth_recovery_code_batches (recovery_code_batch_pk) ON DELETE RESTRICT,
    CONSTRAINT auth_recovery_codes_digest_ck CHECK (
        pg_catalog.octet_length(code_digest) = 32
        AND pg_catalog.length(pepper_key_ref) BETWEEN 1 AND 512
        AND pepper_key_version > 0
    ),
    CONSTRAINT auth_recovery_codes_state_ck CHECK (state IN ('CURRENT', 'USED', 'REVOKED')),
    CONSTRAINT auth_recovery_codes_used_ck CHECK ((state = 'USED') = (used_at IS NOT NULL)),
    CONSTRAINT auth_recovery_codes_time_ck CHECK (used_at IS NULL OR used_at >= created_at)
);

COMMENT ON TABLE public.auth_recovery_codes IS
    'Single-use peppered recovery-code digests; raw recovery codes are never stored; S4.';
CREATE INDEX auth_recovery_codes_batch_state_idx
    ON public.auth_recovery_codes (recovery_code_batch_pk, state);

CREATE TABLE public.auth_transactions (
    transaction_pk bigint GENERATED ALWAYS AS IDENTITY,
    transaction_id uuid NOT NULL DEFAULT pg_catalog.gen_random_uuid(),
    client_pk bigint,
    tenant_pk bigint,
    user_pk bigint,
    purpose text COLLATE "C" NOT NULL,
    state text COLLATE "C" NOT NULL DEFAULT 'PENDING',
    pkce_challenge_digest bytea,
    oidc_nonce_digest bytea,
    oauth_state_digest bytea,
    binding_digest bytea NOT NULL,
    risk_context_digest bytea,
    attempt_count integer NOT NULL DEFAULT 0,
    expires_at timestamptz NOT NULL,
    completed_at timestamptz,
    row_version bigint NOT NULL DEFAULT 1,
    created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    CONSTRAINT auth_transactions_pkey PRIMARY KEY (transaction_pk),
    CONSTRAINT auth_transactions_id_key UNIQUE (transaction_id),
    CONSTRAINT auth_transactions_id_v4_ck CHECK (public.iam_uuid_is_v4(transaction_id)),
    CONSTRAINT auth_transactions_tenant_fk FOREIGN KEY (tenant_pk)
        REFERENCES public.org_tenants (tenant_pk) ON DELETE RESTRICT,
    CONSTRAINT auth_transactions_user_fk FOREIGN KEY (user_pk)
        REFERENCES public.iam_users (user_pk) ON DELETE RESTRICT,
    CONSTRAINT auth_transactions_client_placeholder_ck CHECK (client_pk IS NULL OR client_pk > 0),
    CONSTRAINT auth_transactions_purpose_ck CHECK (
        purpose IN ('REGISTER', 'LOGIN', 'RECOVERY', 'IDENTIFIER_BIND',
                    'IDENTIFIER_REPLACE', 'STEP_UP', 'AUTHORIZE')
    ),
    CONSTRAINT auth_transactions_state_ck
        CHECK (state IN ('PENDING', 'CHALLENGED', 'AUTHENTICATED', 'COMPLETED', 'FAILED', 'EXPIRED', 'CANCELLED')),
    CONSTRAINT auth_transactions_digests_ck CHECK (
        (pkce_challenge_digest IS NULL OR pg_catalog.octet_length(pkce_challenge_digest) = 32)
        AND (oidc_nonce_digest IS NULL OR pg_catalog.octet_length(oidc_nonce_digest) = 32)
        AND (oauth_state_digest IS NULL OR pg_catalog.octet_length(oauth_state_digest) = 32)
        AND pg_catalog.octet_length(binding_digest) = 32
        AND (risk_context_digest IS NULL OR pg_catalog.octet_length(risk_context_digest) = 32)
    ),
    CONSTRAINT auth_transactions_attempt_ck CHECK (attempt_count >= 0),
    CONSTRAINT auth_transactions_completed_ck CHECK (
        (state IN ('COMPLETED', 'FAILED', 'EXPIRED', 'CANCELLED')) = (completed_at IS NOT NULL)
    ),
    CONSTRAINT auth_transactions_row_version_ck CHECK (row_version > 0),
    CONSTRAINT auth_transactions_time_ck CHECK (
        expires_at > created_at AND updated_at >= created_at
        AND (completed_at IS NULL OR completed_at >= created_at)
    )
);

COMMENT ON TABLE public.auth_transactions IS
    'Purpose-, Client-, user-, PKCE-, nonce-, state-, and risk-bound authentication flow; Client FK is added in 060; S3.';
CREATE INDEX auth_transactions_client_state_expiry_idx
    ON public.auth_transactions (client_pk, state, expires_at) WHERE client_pk IS NOT NULL;
CREATE INDEX auth_transactions_user_created_idx
    ON public.auth_transactions (user_pk, created_at DESC) WHERE user_pk IS NOT NULL;

CREATE TABLE public.auth_challenges (
    challenge_pk bigint GENERATED ALWAYS AS IDENTITY,
    challenge_id uuid NOT NULL DEFAULT pg_catalog.gen_random_uuid(),
    transaction_pk bigint NOT NULL,
    client_pk bigint,
    user_pk bigint,
    purpose text COLLATE "C" NOT NULL,
    challenge_type text COLLATE "C" NOT NULL,
    target_kind text COLLATE "C",
    target_blind_index bytea,
    target_key_version integer,
    secret_digest bytea NOT NULL,
    pepper_key_ref text COLLATE "C" NOT NULL,
    pepper_key_version integer NOT NULL,
    binding_digest bytea NOT NULL,
    state text COLLATE "C" NOT NULL DEFAULT 'ISSUED',
    max_attempts integer NOT NULL,
    attempt_count integer NOT NULL DEFAULT 0,
    issued_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    expires_at timestamptz NOT NULL,
    verified_at timestamptz,
    consumed_at timestamptz,
    terminal_at timestamptz,
    row_version bigint NOT NULL DEFAULT 1,
    CONSTRAINT auth_challenges_pkey PRIMARY KEY (challenge_pk),
    CONSTRAINT auth_challenges_id_key UNIQUE (challenge_id),
    CONSTRAINT auth_challenges_secret_key UNIQUE (secret_digest),
    CONSTRAINT auth_challenges_id_v4_ck CHECK (public.iam_uuid_is_v4(challenge_id)),
    CONSTRAINT auth_challenges_transaction_fk FOREIGN KEY (transaction_pk)
        REFERENCES public.auth_transactions (transaction_pk) ON DELETE RESTRICT,
    CONSTRAINT auth_challenges_user_fk FOREIGN KEY (user_pk)
        REFERENCES public.iam_users (user_pk) ON DELETE RESTRICT,
    CONSTRAINT auth_challenges_client_placeholder_ck CHECK (client_pk IS NULL OR client_pk > 0),
    CONSTRAINT auth_challenges_purpose_ck CHECK (
        purpose IN ('REGISTER', 'LOGIN', 'RECOVERY', 'IDENTIFIER_BIND',
                    'IDENTIFIER_REPLACE', 'STEP_UP', 'AUTHORIZE')
    ),
    CONSTRAINT auth_challenges_type_ck
        CHECK (challenge_type IN ('SMS_OTP', 'EMAIL_OTP', 'MAGIC_LINK', 'PUSH', 'WEBAUTHN')),
    CONSTRAINT auth_challenges_target_ck CHECK (
        (challenge_type IN ('SMS_OTP', 'EMAIL_OTP', 'MAGIC_LINK')
         AND target_kind IS NOT NULL AND target_blind_index IS NOT NULL
         AND pg_catalog.octet_length(target_blind_index) = 32 AND target_key_version > 0)
        OR
        (challenge_type IN ('PUSH', 'WEBAUTHN')
         AND target_kind IS NULL AND target_blind_index IS NULL AND target_key_version IS NULL)
    ),
    CONSTRAINT auth_challenges_state_ck
        CHECK (state IN ('ISSUED', 'VERIFIED', 'CONSUMED', 'EXPIRED', 'LOCKED', 'CANCELLED')),
    CONSTRAINT auth_challenges_secret_ck CHECK (
        pg_catalog.octet_length(secret_digest) = 32
        AND pg_catalog.length(pepper_key_ref) BETWEEN 1 AND 512
        AND pepper_key_version > 0
        AND pg_catalog.octet_length(binding_digest) = 32
    ),
    CONSTRAINT auth_challenges_attempt_ck
        CHECK (max_attempts BETWEEN 1 AND 20 AND attempt_count BETWEEN 0 AND max_attempts),
    CONSTRAINT auth_challenges_state_times_ck CHECK (
        ((state IN ('VERIFIED', 'CONSUMED')) = (verified_at IS NOT NULL))
        AND ((state = 'CONSUMED') = (consumed_at IS NOT NULL))
        AND ((state IN ('EXPIRED', 'LOCKED', 'CANCELLED')) = (terminal_at IS NOT NULL))
    ),
    CONSTRAINT auth_challenges_row_version_ck CHECK (row_version > 0),
    CONSTRAINT auth_challenges_time_ck CHECK (
        expires_at > issued_at
        AND (verified_at IS NULL OR verified_at BETWEEN issued_at AND expires_at)
        AND (consumed_at IS NULL OR consumed_at >= verified_at)
        AND (terminal_at IS NULL OR terminal_at >= issued_at)
    )
);

COMMENT ON TABLE public.auth_challenges IS
    'Single-use challenge bound to transaction, purpose, Client, user/target and risk binding; VERIFIED is distinct from CONSUMED; S4.';
CREATE INDEX auth_challenges_open_expiry_idx
    ON public.auth_challenges (expires_at, challenge_pk)
    WHERE state IN ('ISSUED', 'VERIFIED');
CREATE INDEX auth_challenges_target_rate_idx
    ON public.auth_challenges (target_key_version, target_blind_index, issued_at DESC)
    WHERE target_blind_index IS NOT NULL;
CREATE INDEX auth_challenges_transaction_state_idx
    ON public.auth_challenges (transaction_pk, state);

CREATE TABLE public.auth_challenge_deliveries (
    challenge_delivery_pk bigint GENERATED ALWAYS AS IDENTITY,
    challenge_pk bigint NOT NULL,
    delivery_no integer NOT NULL,
    channel text COLLATE "C" NOT NULL,
    provider_reference_digest bytea,
    state text COLLATE "C" NOT NULL DEFAULT 'PENDING',
    requested_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    delivered_at timestamptz,
    failed_at timestamptz,
    CONSTRAINT auth_challenge_deliveries_pkey PRIMARY KEY (challenge_delivery_pk),
    CONSTRAINT auth_challenge_deliveries_number_key UNIQUE (challenge_pk, delivery_no),
    CONSTRAINT auth_challenge_deliveries_challenge_fk FOREIGN KEY (challenge_pk)
        REFERENCES public.auth_challenges (challenge_pk) ON DELETE RESTRICT,
    CONSTRAINT auth_challenge_deliveries_no_ck CHECK (delivery_no > 0),
    CONSTRAINT auth_challenge_deliveries_channel_ck CHECK (channel IN ('SMS', 'EMAIL', 'PUSH', 'IN_BAND')),
    CONSTRAINT auth_challenge_deliveries_reference_ck
        CHECK (provider_reference_digest IS NULL OR pg_catalog.octet_length(provider_reference_digest) = 32),
    CONSTRAINT auth_challenge_deliveries_state_ck
        CHECK (state IN ('PENDING', 'SENT', 'DELIVERED', 'FAILED', 'BOUNCED')),
    CONSTRAINT auth_challenge_deliveries_state_time_ck CHECK (
        (state = 'DELIVERED') = (delivered_at IS NOT NULL)
        AND (state IN ('FAILED', 'BOUNCED')) = (failed_at IS NOT NULL)
    ),
    CONSTRAINT auth_challenge_deliveries_time_ck CHECK (
        (delivered_at IS NULL OR delivered_at >= requested_at)
        AND (failed_at IS NULL OR failed_at >= requested_at)
    )
);

COMMENT ON TABLE public.auth_challenge_deliveries IS
    'Challenge send attempts and minimal provider evidence; message bodies and verification secrets are never stored; S3.';
CREATE INDEX auth_challenge_deliveries_state_idx
    ON public.auth_challenge_deliveries (state, requested_at);

CREATE TABLE public.auth_challenge_attempts (
    challenge_attempt_pk bigint GENERATED ALWAYS AS IDENTITY,
    challenge_pk bigint NOT NULL,
    attempt_no integer NOT NULL,
    result text COLLATE "C" NOT NULL,
    network_address inet,
    device_digest bytea,
    risk_evidence_digest bytea,
    occurred_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    CONSTRAINT auth_challenge_attempts_pkey PRIMARY KEY (challenge_attempt_pk),
    CONSTRAINT auth_challenge_attempts_number_key UNIQUE (challenge_pk, attempt_no),
    CONSTRAINT auth_challenge_attempts_challenge_fk FOREIGN KEY (challenge_pk)
        REFERENCES public.auth_challenges (challenge_pk) ON DELETE RESTRICT,
    CONSTRAINT auth_challenge_attempts_no_ck CHECK (attempt_no > 0),
    CONSTRAINT auth_challenge_attempts_result_ck
        CHECK (result IN ('MATCH', 'MISMATCH', 'EXPIRED', 'LOCKED', 'REPLAY', 'BINDING_MISMATCH')),
    CONSTRAINT auth_challenge_attempts_digests_ck CHECK (
        (device_digest IS NULL OR pg_catalog.octet_length(device_digest) = 32)
        AND (risk_evidence_digest IS NULL OR pg_catalog.octet_length(risk_evidence_digest) = 32)
    )
);

COMMENT ON TABLE public.auth_challenge_attempts IS
    'Append-oriented challenge verification evidence; the submitted code is never retained; S3.';
CREATE INDEX auth_challenge_attempts_occurred_idx
    ON public.auth_challenge_attempts (occurred_at, challenge_attempt_pk);

CREATE TABLE public.auth_contexts (
    auth_context_pk bigint GENERATED ALWAYS AS IDENTITY,
    auth_context_id uuid NOT NULL DEFAULT pg_catalog.gen_random_uuid(),
    transaction_pk bigint NOT NULL,
    user_pk bigint NOT NULL,
    ial smallint NOT NULL,
    aal smallint NOT NULL,
    fal smallint NOT NULL,
    acr text COLLATE "C" NOT NULL,
    auth_time timestamptz NOT NULL,
    risk_level text COLLATE "C" NOT NULL,
    evidence_digest bytea NOT NULL,
    created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    CONSTRAINT auth_contexts_pkey PRIMARY KEY (auth_context_pk),
    CONSTRAINT auth_contexts_id_key UNIQUE (auth_context_id),
    CONSTRAINT auth_contexts_transaction_key UNIQUE (transaction_pk),
    CONSTRAINT auth_contexts_id_v4_ck CHECK (public.iam_uuid_is_v4(auth_context_id)),
    CONSTRAINT auth_contexts_transaction_fk FOREIGN KEY (transaction_pk)
        REFERENCES public.auth_transactions (transaction_pk) ON DELETE RESTRICT,
    CONSTRAINT auth_contexts_user_fk FOREIGN KEY (user_pk)
        REFERENCES public.iam_users (user_pk) ON DELETE RESTRICT,
    CONSTRAINT auth_contexts_levels_ck CHECK (ial BETWEEN 0 AND 3 AND aal BETWEEN 0 AND 3 AND fal BETWEEN 0 AND 3),
    CONSTRAINT auth_contexts_acr_ck CHECK (pg_catalog.length(acr) BETWEEN 1 AND 256),
    CONSTRAINT auth_contexts_risk_ck CHECK (risk_level IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    CONSTRAINT auth_contexts_evidence_ck CHECK (pg_catalog.octet_length(evidence_digest) = 32),
    CONSTRAINT auth_contexts_time_ck CHECK (auth_time <= created_at)
);

COMMENT ON TABLE public.auth_contexts IS
    'Successful authentication assurance result containing distinct IAL/AAL/FAL, acr, auth_time and evidence digest; S3.';
CREATE INDEX auth_contexts_user_time_idx ON public.auth_contexts (user_pk, auth_time DESC);

CREATE TABLE public.auth_context_methods (
    auth_context_method_pk bigint GENERATED ALWAYS AS IDENTITY,
    auth_context_pk bigint NOT NULL,
    method text COLLATE "C" NOT NULL,
    sequence_no integer NOT NULL,
    evidence_digest bytea,
    CONSTRAINT auth_context_methods_pkey PRIMARY KEY (auth_context_method_pk),
    CONSTRAINT auth_context_methods_sequence_key UNIQUE (auth_context_pk, sequence_no),
    CONSTRAINT auth_context_methods_method_key UNIQUE (auth_context_pk, method),
    CONSTRAINT auth_context_methods_context_fk FOREIGN KEY (auth_context_pk)
        REFERENCES public.auth_contexts (auth_context_pk) ON DELETE RESTRICT,
    CONSTRAINT auth_context_methods_method_ck
        CHECK (method IN ('pwd', 'otp', 'sms', 'email', 'totp', 'webauthn', 'hwk', 'federated', 'recovery')),
    CONSTRAINT auth_context_methods_sequence_ck CHECK (sequence_no > 0),
    CONSTRAINT auth_context_methods_evidence_ck
        CHECK (evidence_digest IS NULL OR pg_catalog.octet_length(evidence_digest) = 32)
);

COMMENT ON TABLE public.auth_context_methods IS
    'Ordered AMR methods contributing to an authentication context; S3.';

CREATE TABLE public.auth_context_authenticators (
    auth_context_pk bigint NOT NULL,
    authenticator_pk bigint NOT NULL,
    evidence_digest bytea NOT NULL,
    CONSTRAINT auth_context_authenticators_pkey PRIMARY KEY (auth_context_pk, authenticator_pk),
    CONSTRAINT auth_context_authenticators_context_fk FOREIGN KEY (auth_context_pk)
        REFERENCES public.auth_contexts (auth_context_pk) ON DELETE RESTRICT,
    CONSTRAINT auth_context_authenticators_authenticator_fk FOREIGN KEY (authenticator_pk)
        REFERENCES public.auth_authenticators (authenticator_pk) ON DELETE RESTRICT,
    CONSTRAINT auth_context_authenticators_evidence_ck
        CHECK (pg_catalog.octet_length(evidence_digest) = 32)
);

COMMENT ON TABLE public.auth_context_authenticators IS
    'Authenticator evidence used by a successful context; same-user validation is completed by 110 transaction functions; S3.';
CREATE INDEX auth_context_authenticators_authenticator_idx
    ON public.auth_context_authenticators (authenticator_pk);

COMMIT;
