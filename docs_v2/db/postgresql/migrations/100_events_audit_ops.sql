-- Event delivery, webhook, security event, partitioned audit and migration evidence.
-- Audit append/hash-chain serialization and immutable-row protection may be
-- strengthened in 110_constraints_functions.sql. Outbox remains unpartitioned.

BEGIN;

CREATE TABLE public.evt_outbox (
    event_pk bigint GENERATED ALWAYS AS IDENTITY,
    event_id uuid NOT NULL DEFAULT pg_catalog.gen_random_uuid(),
    event_type text COLLATE "C" NOT NULL,
    schema_version integer NOT NULL,
    producer_principal_pk bigint,
    aggregate_type text COLLATE "C" NOT NULL,
    aggregate_id uuid NOT NULL,
    aggregate_version bigint NOT NULL,
    subject_principal_pk bigint,
    tenant_pk bigint,
    business_line_pk bigint,
    trace_id uuid,
    correlation_id uuid,
    causation_id uuid,
    data_classification text COLLATE "C" NOT NULL,
    ordering_key_digest bytea,
    payload jsonb NOT NULL,
    payload_hash bytea NOT NULL,
    occurred_at timestamptz NOT NULL,
    recorded_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    available_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    archived_at timestamptz,
    CONSTRAINT evt_outbox_pkey PRIMARY KEY (event_pk),
    CONSTRAINT evt_outbox_event_id_key UNIQUE (event_id),
    CONSTRAINT evt_outbox_aggregate_version_key UNIQUE (
        aggregate_type, aggregate_id, aggregate_version
    ),
    CONSTRAINT evt_outbox_event_id_v4_ck CHECK (public.iam_uuid_is_v4(event_id)),
    CONSTRAINT evt_outbox_aggregate_id_v4_ck CHECK (public.iam_uuid_is_v4(aggregate_id)),
    CONSTRAINT evt_outbox_producer_fk FOREIGN KEY (producer_principal_pk)
        REFERENCES public.iam_principals (principal_pk) ON DELETE RESTRICT,
    CONSTRAINT evt_outbox_subject_fk FOREIGN KEY (subject_principal_pk)
        REFERENCES public.iam_principals (principal_pk) ON DELETE RESTRICT,
    CONSTRAINT evt_outbox_tenant_fk FOREIGN KEY (tenant_pk)
        REFERENCES public.org_tenants (tenant_pk) ON DELETE RESTRICT,
    CONSTRAINT evt_outbox_business_line_fk FOREIGN KEY (business_line_pk)
        REFERENCES public.app_business_lines (business_line_pk) ON DELETE RESTRICT,
    CONSTRAINT evt_outbox_event_type_ck CHECK (
        pg_catalog.length(event_type) BETWEEN 3 AND 128
        AND event_type ~ '^[a-z][a-z0-9_.-]*$'
    ),
    CONSTRAINT evt_outbox_schema_version_ck CHECK (schema_version > 0),
    CONSTRAINT evt_outbox_aggregate_type_ck CHECK (
        pg_catalog.length(aggregate_type) BETWEEN 1 AND 96
        AND aggregate_type ~ '^[A-Za-z][A-Za-z0-9_.:-]*$'
    ),
    CONSTRAINT evt_outbox_aggregate_version_ck CHECK (aggregate_version > 0),
    CONSTRAINT evt_outbox_trace_v4_ck CHECK (
        trace_id IS NULL OR public.iam_uuid_is_v4(trace_id)
    ),
    CONSTRAINT evt_outbox_correlation_v4_ck CHECK (
        correlation_id IS NULL OR public.iam_uuid_is_v4(correlation_id)
    ),
    CONSTRAINT evt_outbox_causation_v4_ck CHECK (
        causation_id IS NULL OR public.iam_uuid_is_v4(causation_id)
    ),
    CONSTRAINT evt_outbox_classification_ck CHECK (
        data_classification IN ('S0', 'S1', 'S2', 'S3')
    ),
    CONSTRAINT evt_outbox_ordering_key_ck CHECK (
        ordering_key_digest IS NULL OR pg_catalog.octet_length(ordering_key_digest) = 32
    ),
    CONSTRAINT evt_outbox_payload_ck CHECK (
        pg_catalog.jsonb_typeof(payload) = 'object'
        AND pg_catalog.octet_length(payload::text) <= 1048576
    ),
    CONSTRAINT evt_outbox_payload_hash_ck CHECK (pg_catalog.octet_length(payload_hash) = 32),
    CONSTRAINT evt_outbox_time_ck CHECK (
        occurred_at <= recorded_at AND available_at >= recorded_at
        AND (archived_at IS NULL OR archived_at >= recorded_at)
    )
);

COMMENT ON TABLE public.evt_outbox IS
    'Unpartitioned transactional event envelope; destination state is held in independent delivery rows for global pending claims; S2/S3.';

CREATE INDEX evt_outbox_available_idx
    ON public.evt_outbox (available_at, event_pk)
    WHERE archived_at IS NULL;
CREATE INDEX evt_outbox_subject_time_idx
    ON public.evt_outbox (subject_principal_pk, occurred_at DESC)
    WHERE subject_principal_pk IS NOT NULL;
CREATE INDEX evt_outbox_tenant_time_idx
    ON public.evt_outbox (tenant_pk, occurred_at DESC)
    WHERE tenant_pk IS NOT NULL;

CREATE TRIGGER evt_outbox_immutable_trg
BEFORE UPDATE ON public.evt_outbox
FOR EACH ROW EXECUTE FUNCTION public.iam_reject_column_changes(
    'event_pk', 'event_id', 'event_type', 'schema_version',
    'producer_principal_pk', 'aggregate_type', 'aggregate_id',
    'aggregate_version', 'subject_principal_pk', 'tenant_pk',
    'business_line_pk', 'trace_id', 'correlation_id', 'causation_id',
    'data_classification', 'ordering_key_digest', 'payload',
    'payload_hash', 'occurred_at', 'recorded_at'
);

CREATE TABLE public.evt_outbox_deliveries (
    outbox_delivery_pk bigint GENERATED ALWAYS AS IDENTITY,
    outbox_delivery_id uuid NOT NULL DEFAULT pg_catalog.gen_random_uuid(),
    event_pk bigint NOT NULL,
    destination_type text COLLATE "C" NOT NULL,
    destination_code text COLLATE "C" NOT NULL,
    state text COLLATE "C" NOT NULL DEFAULT 'PENDING',
    attempt_count integer NOT NULL DEFAULT 0,
    next_attempt_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    locked_by text COLLATE "C",
    locked_until timestamptz,
    delivered_at timestamptz,
    dead_lettered_at timestamptz,
    last_error_code text COLLATE "C",
    row_version bigint NOT NULL DEFAULT 1,
    created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    CONSTRAINT evt_outbox_deliveries_pkey PRIMARY KEY (outbox_delivery_pk),
    CONSTRAINT evt_outbox_deliveries_id_key UNIQUE (outbox_delivery_id),
    CONSTRAINT evt_outbox_deliveries_destination_key UNIQUE (
        event_pk, destination_type, destination_code
    ),
    CONSTRAINT evt_outbox_deliveries_id_v4_ck CHECK (public.iam_uuid_is_v4(outbox_delivery_id)),
    CONSTRAINT evt_outbox_deliveries_event_fk FOREIGN KEY (event_pk)
        REFERENCES public.evt_outbox (event_pk) ON DELETE RESTRICT,
    CONSTRAINT evt_outbox_deliveries_destination_type_ck CHECK (
        destination_type IN ('EVENT_BUS', 'SECURITY_STREAM', 'WEBHOOK_ROUTER', 'ARCHIVE')
    ),
    CONSTRAINT evt_outbox_deliveries_destination_code_ck CHECK (
        pg_catalog.length(destination_code) BETWEEN 1 AND 128
        AND destination_code ~ '^[A-Za-z0-9][A-Za-z0-9_.:/-]*$'
    ),
    CONSTRAINT evt_outbox_deliveries_state_ck CHECK (
        state IN ('PENDING', 'CLAIMED', 'RETRY', 'DELIVERED', 'DEAD_LETTERED', 'CANCELLED')
    ),
    CONSTRAINT evt_outbox_deliveries_attempt_ck CHECK (attempt_count >= 0),
    CONSTRAINT evt_outbox_deliveries_lock_ck CHECK (
        (locked_by IS NULL AND locked_until IS NULL)
        OR (locked_by IS NOT NULL AND pg_catalog.length(locked_by) BETWEEN 1 AND 128
            AND locked_by ~ '^[A-Za-z0-9][A-Za-z0-9_.:-]*$'
            AND locked_until IS NOT NULL)
    ),
    CONSTRAINT evt_outbox_deliveries_terminal_ck CHECK (
        (state = 'DELIVERED' AND delivered_at IS NOT NULL AND dead_lettered_at IS NULL)
        OR (state = 'DEAD_LETTERED' AND delivered_at IS NULL AND dead_lettered_at IS NOT NULL)
        OR (state NOT IN ('DELIVERED', 'DEAD_LETTERED') AND delivered_at IS NULL AND dead_lettered_at IS NULL)
    ),
    CONSTRAINT evt_outbox_deliveries_error_ck CHECK (
        last_error_code IS NULL OR (
            pg_catalog.length(last_error_code) BETWEEN 1 AND 96
            AND last_error_code ~ '^[A-Z][A-Z0-9_]*$'
        )
    ),
    CONSTRAINT evt_outbox_deliveries_version_ck CHECK (row_version > 0),
    CONSTRAINT evt_outbox_deliveries_time_ck CHECK (
        updated_at >= created_at AND next_attempt_at >= created_at
        AND (locked_until IS NULL OR locked_until >= created_at)
        AND (delivered_at IS NULL OR delivered_at >= created_at)
        AND (dead_lettered_at IS NULL OR dead_lettered_at >= created_at)
    )
);

COMMENT ON TABLE public.evt_outbox_deliveries IS
    'Independent per-destination delivery state and claim lease for one Outbox event; S2.';

CREATE INDEX evt_outbox_deliveries_claim_idx
    ON public.evt_outbox_deliveries (next_attempt_at, outbox_delivery_pk)
    WHERE state IN ('PENDING', 'RETRY');
CREATE INDEX evt_outbox_deliveries_event_idx
    ON public.evt_outbox_deliveries (event_pk, state);

CREATE TRIGGER evt_outbox_deliveries_immutable_trg
BEFORE UPDATE ON public.evt_outbox_deliveries
FOR EACH ROW EXECUTE FUNCTION public.iam_reject_column_changes(
    'outbox_delivery_pk', 'outbox_delivery_id', 'event_pk',
    'destination_type', 'destination_code', 'created_at'
);

CREATE TRIGGER evt_outbox_deliveries_version_trg
BEFORE UPDATE ON public.evt_outbox_deliveries
FOR EACH ROW EXECUTE FUNCTION public.iam_guard_nondecreasing_bigint('row_version');

CREATE TABLE public.evt_outbox_delivery_attempts (
    outbox_delivery_attempt_pk bigint GENERATED ALWAYS AS IDENTITY,
    outbox_delivery_pk bigint NOT NULL,
    attempt_no integer NOT NULL,
    result text COLLATE "C" NOT NULL,
    request_hash bytea NOT NULL,
    response_hash bytea,
    error_code text COLLATE "C",
    started_at timestamptz NOT NULL,
    finished_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    CONSTRAINT evt_outbox_delivery_attempts_pkey PRIMARY KEY (outbox_delivery_attempt_pk),
    CONSTRAINT evt_outbox_delivery_attempts_number_key UNIQUE (outbox_delivery_pk, attempt_no),
    CONSTRAINT evt_outbox_delivery_attempts_delivery_fk FOREIGN KEY (outbox_delivery_pk)
        REFERENCES public.evt_outbox_deliveries (outbox_delivery_pk) ON DELETE RESTRICT,
    CONSTRAINT evt_outbox_delivery_attempts_number_ck CHECK (attempt_no > 0),
    CONSTRAINT evt_outbox_delivery_attempts_result_ck CHECK (
        result IN ('STARTED', 'SUCCEEDED', 'FAILED', 'TIMED_OUT')
    ),
    CONSTRAINT evt_outbox_delivery_attempts_request_hash_ck CHECK (
        pg_catalog.octet_length(request_hash) = 32
    ),
    CONSTRAINT evt_outbox_delivery_attempts_response_hash_ck CHECK (
        response_hash IS NULL OR pg_catalog.octet_length(response_hash) = 32
    ),
    CONSTRAINT evt_outbox_delivery_attempts_error_ck CHECK (
        error_code IS NULL OR (
            pg_catalog.length(error_code) BETWEEN 1 AND 96
            AND error_code ~ '^[A-Z][A-Z0-9_]*$'
        )
    ),
    CONSTRAINT evt_outbox_delivery_attempts_finish_ck CHECK (
        (result = 'STARTED' AND finished_at IS NULL)
        OR (result <> 'STARTED' AND finished_at IS NOT NULL)
    ),
    CONSTRAINT evt_outbox_delivery_attempts_time_ck CHECK (
        started_at <= created_at AND (finished_at IS NULL OR finished_at >= started_at)
    )
);

COMMENT ON TABLE public.evt_outbox_delivery_attempts IS
    'Append-only transport attempts for independent Outbox deliveries; bodies are represented only by hashes; S2.';

CREATE INDEX evt_outbox_delivery_attempts_delivery_time_idx
    ON public.evt_outbox_delivery_attempts (outbox_delivery_pk, started_at DESC);

CREATE TRIGGER evt_outbox_delivery_attempts_append_only_trg
BEFORE UPDATE OR DELETE ON public.evt_outbox_delivery_attempts
FOR EACH ROW EXECUTE FUNCTION public.iam_reject_row_mutation();

CREATE TABLE public.evt_inbox (
    inbox_pk bigint GENERATED ALWAYS AS IDENTITY,
    consumer_code text COLLATE "C" NOT NULL,
    event_id uuid NOT NULL,
    payload_hash bytea NOT NULL,
    aggregate_type text COLLATE "C" NOT NULL,
    aggregate_id uuid NOT NULL,
    aggregate_version bigint NOT NULL,
    status text COLLATE "C" NOT NULL DEFAULT 'RECEIVED',
    attempt_count integer NOT NULL DEFAULT 0,
    next_attempt_at timestamptz,
    processed_at timestamptz,
    last_error_code text COLLATE "C",
    row_version bigint NOT NULL DEFAULT 1,
    received_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    CONSTRAINT evt_inbox_pkey PRIMARY KEY (inbox_pk),
    CONSTRAINT evt_inbox_consumer_event_key UNIQUE (consumer_code, event_id),
    CONSTRAINT evt_inbox_event_id_v4_ck CHECK (public.iam_uuid_is_v4(event_id)),
    CONSTRAINT evt_inbox_consumer_ck CHECK (
        pg_catalog.length(consumer_code) BETWEEN 1 AND 128
        AND consumer_code ~ '^[A-Za-z0-9][A-Za-z0-9_.:-]*$'
    ),
    CONSTRAINT evt_inbox_payload_hash_ck CHECK (pg_catalog.octet_length(payload_hash) = 32),
    CONSTRAINT evt_inbox_aggregate_type_ck CHECK (
        pg_catalog.length(aggregate_type) BETWEEN 1 AND 96
        AND aggregate_type ~ '^[A-Za-z][A-Za-z0-9_.:-]*$'
    ),
    CONSTRAINT evt_inbox_aggregate_id_v4_ck CHECK (public.iam_uuid_is_v4(aggregate_id)),
    CONSTRAINT evt_inbox_aggregate_version_ck CHECK (aggregate_version > 0),
    CONSTRAINT evt_inbox_status_ck CHECK (
        status IN ('RECEIVED', 'PROCESSING', 'RETRY', 'PROCESSED', 'REJECTED', 'DEAD_LETTERED')
    ),
    CONSTRAINT evt_inbox_attempt_ck CHECK (attempt_count >= 0),
    CONSTRAINT evt_inbox_processed_ck CHECK (
        (status = 'PROCESSED') = (processed_at IS NOT NULL)
    ),
    CONSTRAINT evt_inbox_error_ck CHECK (
        last_error_code IS NULL OR (
            pg_catalog.length(last_error_code) BETWEEN 1 AND 96
            AND last_error_code ~ '^[A-Z][A-Z0-9_]*$'
        )
    ),
    CONSTRAINT evt_inbox_version_ck CHECK (row_version > 0),
    CONSTRAINT evt_inbox_time_ck CHECK (
        updated_at >= received_at
        AND (next_attempt_at IS NULL OR next_attempt_at >= received_at)
        AND (processed_at IS NULL OR processed_at >= received_at)
    )
);

COMMENT ON TABLE public.evt_inbox IS
    'Consumer deduplication, aggregate ordering evidence and retry state; duplicate event IDs with different payload hashes are conflicts; S2.';

CREATE INDEX evt_inbox_retry_idx
    ON public.evt_inbox (next_attempt_at, inbox_pk)
    WHERE status IN ('RECEIVED', 'RETRY');
CREATE INDEX evt_inbox_aggregate_idx
    ON public.evt_inbox (consumer_code, aggregate_type, aggregate_id, aggregate_version DESC);

CREATE TRIGGER evt_inbox_immutable_trg
BEFORE UPDATE ON public.evt_inbox
FOR EACH ROW EXECUTE FUNCTION public.iam_reject_column_changes(
    'inbox_pk', 'consumer_code', 'event_id', 'payload_hash',
    'aggregate_type', 'aggregate_id', 'aggregate_version', 'received_at'
);

CREATE TRIGGER evt_inbox_version_trg
BEFORE UPDATE ON public.evt_inbox
FOR EACH ROW EXECUTE FUNCTION public.iam_guard_nondecreasing_bigint('row_version');

CREATE TABLE public.evt_webhook_subscriptions (
    webhook_subscription_pk bigint GENERATED ALWAYS AS IDENTITY,
    webhook_subscription_id uuid NOT NULL DEFAULT pg_catalog.gen_random_uuid(),
    tenant_pk bigint,
    owner_principal_pk bigint NOT NULL,
    subscription_code text COLLATE "C" NOT NULL,
    target_uri text COLLATE "C" NOT NULL,
    target_uri_digest bytea NOT NULL,
    state text COLLATE "C" NOT NULL DEFAULT 'PENDING_VERIFICATION',
    signing_key_version_pk bigint NOT NULL,
    signature_profile text COLLATE "C" NOT NULL,
    max_clock_skew_seconds integer NOT NULL,
    replay_window_seconds integer NOT NULL,
    verified_at timestamptz,
    suspended_at timestamptz,
    row_version bigint NOT NULL DEFAULT 1,
    created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    CONSTRAINT evt_webhook_subscriptions_pkey PRIMARY KEY (webhook_subscription_pk),
    CONSTRAINT evt_webhook_subscriptions_id_key UNIQUE (webhook_subscription_id),
    CONSTRAINT evt_webhook_subscriptions_code_key UNIQUE NULLS NOT DISTINCT (
        tenant_pk, subscription_code
    ),
    CONSTRAINT evt_webhook_subscriptions_target_key UNIQUE NULLS NOT DISTINCT (
        tenant_pk, target_uri_digest
    ),
    CONSTRAINT evt_webhook_subscriptions_id_v4_ck CHECK (public.iam_uuid_is_v4(webhook_subscription_id)),
    CONSTRAINT evt_webhook_subscriptions_tenant_fk FOREIGN KEY (tenant_pk)
        REFERENCES public.org_tenants (tenant_pk) ON DELETE RESTRICT,
    CONSTRAINT evt_webhook_subscriptions_owner_fk FOREIGN KEY (owner_principal_pk)
        REFERENCES public.iam_principals (principal_pk) ON DELETE RESTRICT,
    CONSTRAINT evt_webhook_subscriptions_signing_key_fk FOREIGN KEY (signing_key_version_pk)
        REFERENCES public.key_crypto_key_versions (crypto_key_version_pk) ON DELETE RESTRICT,
    CONSTRAINT evt_webhook_subscriptions_code_ck CHECK (
        pg_catalog.length(subscription_code) BETWEEN 1 AND 96
        AND subscription_code ~ '^[A-Z][A-Z0-9_.:-]*$'
    ),
    CONSTRAINT evt_webhook_subscriptions_uri_ck CHECK (
        pg_catalog.length(target_uri) BETWEEN 9 AND 2048
        AND target_uri ~ '^https://'
        AND target_uri !~ '[@#]'
    ),
    CONSTRAINT evt_webhook_subscriptions_uri_digest_ck CHECK (
        pg_catalog.octet_length(target_uri_digest) = 32
    ),
    CONSTRAINT evt_webhook_subscriptions_state_ck CHECK (
        state IN ('PENDING_VERIFICATION', 'ACTIVE', 'SUSPENDED', 'RETIRED')
    ),
    CONSTRAINT evt_webhook_subscriptions_profile_ck CHECK (
        signature_profile IN ('HMAC_SHA256_V1', 'HTTP_MESSAGE_SIGNATURES_V1', 'JWS_DETACHED_V1')
    ),
    CONSTRAINT evt_webhook_subscriptions_clock_ck CHECK (
        max_clock_skew_seconds BETWEEN 0 AND 600
        AND replay_window_seconds BETWEEN 1 AND 3600
        AND replay_window_seconds >= max_clock_skew_seconds
    ),
    CONSTRAINT evt_webhook_subscriptions_verification_ck CHECK (
        (state = 'PENDING_VERIFICATION' AND verified_at IS NULL)
        OR (state <> 'PENDING_VERIFICATION' AND verified_at IS NOT NULL)
    ),
    CONSTRAINT evt_webhook_subscriptions_suspension_ck CHECK (
        (state = 'SUSPENDED') = (suspended_at IS NOT NULL)
    ),
    CONSTRAINT evt_webhook_subscriptions_version_ck CHECK (row_version > 0),
    CONSTRAINT evt_webhook_subscriptions_time_ck CHECK (
        updated_at >= created_at
        AND (verified_at IS NULL OR verified_at >= created_at)
        AND (suspended_at IS NULL OR suspended_at >= verified_at)
    )
);

COMMENT ON TABLE public.evt_webhook_subscriptions IS
    'Tenant-aware verified HTTPS webhook endpoint with KMS signing-key version and explicit replay contract; target URLs contain no credentials; S3.';

CREATE INDEX evt_webhook_subscriptions_tenant_state_idx
    ON public.evt_webhook_subscriptions (tenant_pk, state, webhook_subscription_pk);
CREATE INDEX evt_webhook_subscriptions_owner_idx
    ON public.evt_webhook_subscriptions (owner_principal_pk, state);

CREATE TRIGGER evt_webhook_subscriptions_immutable_trg
BEFORE UPDATE ON public.evt_webhook_subscriptions
FOR EACH ROW EXECUTE FUNCTION public.iam_reject_column_changes(
    'webhook_subscription_pk', 'webhook_subscription_id', 'tenant_pk',
    'subscription_code', 'created_at'
);

CREATE TRIGGER evt_webhook_subscriptions_version_trg
BEFORE UPDATE ON public.evt_webhook_subscriptions
FOR EACH ROW EXECUTE FUNCTION public.iam_guard_nondecreasing_bigint('row_version');

CREATE TABLE public.evt_webhook_subscription_events (
    webhook_subscription_event_pk bigint GENERATED ALWAYS AS IDENTITY,
    webhook_subscription_pk bigint NOT NULL,
    event_type text COLLATE "C" NOT NULL,
    min_schema_version integer NOT NULL,
    max_schema_version integer,
    created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    CONSTRAINT evt_webhook_subscription_events_pkey PRIMARY KEY (webhook_subscription_event_pk),
    CONSTRAINT evt_webhook_subscription_events_type_key UNIQUE (
        webhook_subscription_pk, event_type
    ),
    CONSTRAINT evt_webhook_subscription_events_subscription_fk FOREIGN KEY (webhook_subscription_pk)
        REFERENCES public.evt_webhook_subscriptions (webhook_subscription_pk) ON DELETE RESTRICT,
    CONSTRAINT evt_webhook_subscription_events_type_ck CHECK (
        pg_catalog.length(event_type) BETWEEN 3 AND 128
        AND event_type ~ '^[a-z][a-z0-9_.-]*$'
    ),
    CONSTRAINT evt_webhook_subscription_events_version_ck CHECK (
        min_schema_version > 0
        AND (max_schema_version IS NULL OR max_schema_version >= min_schema_version)
    )
);

COMMENT ON TABLE public.evt_webhook_subscription_events IS
    'Relational webhook event allowlist and accepted schema-version interval; S2.';

CREATE TABLE public.evt_webhook_deliveries (
    webhook_delivery_pk bigint GENERATED ALWAYS AS IDENTITY,
    webhook_delivery_id uuid NOT NULL DEFAULT pg_catalog.gen_random_uuid(),
    webhook_subscription_pk bigint NOT NULL,
    event_id uuid NOT NULL,
    event_type text COLLATE "C" NOT NULL,
    event_occurred_at timestamptz NOT NULL,
    payload_hash bytea NOT NULL,
    state text COLLATE "C" NOT NULL DEFAULT 'PENDING',
    attempt_count integer NOT NULL DEFAULT 0,
    next_attempt_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    signing_key_id text COLLATE "C" NOT NULL,
    delivered_at timestamptz,
    dead_lettered_at timestamptz,
    row_version bigint NOT NULL DEFAULT 1,
    created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    CONSTRAINT evt_webhook_deliveries_pkey PRIMARY KEY (webhook_delivery_pk),
    CONSTRAINT evt_webhook_deliveries_id_key UNIQUE (webhook_delivery_id),
    CONSTRAINT evt_webhook_deliveries_subscription_event_key UNIQUE (
        webhook_subscription_pk, event_id
    ),
    CONSTRAINT evt_webhook_deliveries_id_v4_ck CHECK (public.iam_uuid_is_v4(webhook_delivery_id)),
    CONSTRAINT evt_webhook_deliveries_event_id_v4_ck CHECK (public.iam_uuid_is_v4(event_id)),
    CONSTRAINT evt_webhook_deliveries_subscription_fk FOREIGN KEY (webhook_subscription_pk)
        REFERENCES public.evt_webhook_subscriptions (webhook_subscription_pk) ON DELETE RESTRICT,
    CONSTRAINT evt_webhook_deliveries_event_type_ck CHECK (
        pg_catalog.length(event_type) BETWEEN 3 AND 128
        AND event_type ~ '^[a-z][a-z0-9_.-]*$'
    ),
    CONSTRAINT evt_webhook_deliveries_payload_hash_ck CHECK (pg_catalog.octet_length(payload_hash) = 32),
    CONSTRAINT evt_webhook_deliveries_state_ck CHECK (
        state IN ('PENDING', 'DELIVERING', 'RETRY', 'DELIVERED', 'DEAD_LETTERED', 'CANCELLED')
    ),
    CONSTRAINT evt_webhook_deliveries_attempt_ck CHECK (attempt_count >= 0),
    CONSTRAINT evt_webhook_deliveries_signing_kid_ck CHECK (
        pg_catalog.length(signing_key_id) BETWEEN 1 AND 255
        AND signing_key_id ~ '^[A-Za-z0-9][A-Za-z0-9_.:-]*$'
    ),
    CONSTRAINT evt_webhook_deliveries_terminal_ck CHECK (
        (state = 'DELIVERED' AND delivered_at IS NOT NULL AND dead_lettered_at IS NULL)
        OR (state = 'DEAD_LETTERED' AND delivered_at IS NULL AND dead_lettered_at IS NOT NULL)
        OR (state NOT IN ('DELIVERED', 'DEAD_LETTERED') AND delivered_at IS NULL AND dead_lettered_at IS NULL)
    ),
    CONSTRAINT evt_webhook_deliveries_version_ck CHECK (row_version > 0),
    CONSTRAINT evt_webhook_deliveries_time_ck CHECK (
        updated_at >= created_at AND event_occurred_at <= created_at
        AND next_attempt_at >= created_at
        AND (delivered_at IS NULL OR delivered_at >= created_at)
        AND (dead_lettered_at IS NULL OR dead_lettered_at >= created_at)
    )
);

COMMENT ON TABLE public.evt_webhook_deliveries IS
    'Stable webhook business delivery independent from Outbox retention; it stores event identity and hash without a historical FK; S2/S3.';

CREATE INDEX evt_webhook_deliveries_retry_idx
    ON public.evt_webhook_deliveries (next_attempt_at, webhook_delivery_pk)
    WHERE state IN ('PENDING', 'RETRY');
CREATE INDEX evt_webhook_deliveries_event_idx
    ON public.evt_webhook_deliveries (event_id, webhook_subscription_pk);

CREATE TRIGGER evt_webhook_deliveries_immutable_trg
BEFORE UPDATE ON public.evt_webhook_deliveries
FOR EACH ROW EXECUTE FUNCTION public.iam_reject_column_changes(
    'webhook_delivery_pk', 'webhook_delivery_id', 'webhook_subscription_pk',
    'event_id', 'event_type', 'event_occurred_at', 'payload_hash',
    'signing_key_id', 'created_at'
);

CREATE TRIGGER evt_webhook_deliveries_version_trg
BEFORE UPDATE ON public.evt_webhook_deliveries
FOR EACH ROW EXECUTE FUNCTION public.iam_guard_nondecreasing_bigint('row_version');

CREATE TABLE public.evt_webhook_attempts (
    webhook_attempt_pk bigint GENERATED ALWAYS AS IDENTITY,
    webhook_delivery_pk bigint NOT NULL,
    attempt_no integer NOT NULL,
    request_timestamp timestamptz NOT NULL,
    request_hash bytea NOT NULL,
    signature_hash bytea NOT NULL,
    http_status integer,
    response_hash bytea,
    response_class text COLLATE "C",
    error_code text COLLATE "C",
    started_at timestamptz NOT NULL,
    finished_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    CONSTRAINT evt_webhook_attempts_pkey PRIMARY KEY (webhook_attempt_pk),
    CONSTRAINT evt_webhook_attempts_number_key UNIQUE (webhook_delivery_pk, attempt_no),
    CONSTRAINT evt_webhook_attempts_delivery_fk FOREIGN KEY (webhook_delivery_pk)
        REFERENCES public.evt_webhook_deliveries (webhook_delivery_pk) ON DELETE RESTRICT,
    CONSTRAINT evt_webhook_attempts_number_ck CHECK (attempt_no > 0),
    CONSTRAINT evt_webhook_attempts_request_hash_ck CHECK (pg_catalog.octet_length(request_hash) = 32),
    CONSTRAINT evt_webhook_attempts_signature_hash_ck CHECK (pg_catalog.octet_length(signature_hash) = 32),
    CONSTRAINT evt_webhook_attempts_http_status_ck CHECK (
        http_status IS NULL OR http_status BETWEEN 100 AND 599
    ),
    CONSTRAINT evt_webhook_attempts_response_hash_ck CHECK (
        response_hash IS NULL OR pg_catalog.octet_length(response_hash) = 32
    ),
    CONSTRAINT evt_webhook_attempts_response_class_ck CHECK (
        response_class IS NULL OR response_class IN (
            'SUCCESS', 'RETRYABLE_CLIENT', 'NON_RETRYABLE_CLIENT', 'RETRYABLE_SERVER', 'TIMEOUT', 'NETWORK'
        )
    ),
    CONSTRAINT evt_webhook_attempts_error_ck CHECK (
        error_code IS NULL OR (
            pg_catalog.length(error_code) BETWEEN 1 AND 96
            AND error_code ~ '^[A-Z][A-Z0-9_]*$'
        )
    ),
    CONSTRAINT evt_webhook_attempts_time_ck CHECK (
        request_timestamp <= created_at AND started_at <= created_at
        AND (finished_at IS NULL OR finished_at >= started_at)
    )
);

COMMENT ON TABLE public.evt_webhook_attempts IS
    'Append-only signed webhook attempts, HTTP classification and bounded response evidence without response bodies; S2/S3.';

CREATE INDEX evt_webhook_attempts_delivery_time_idx
    ON public.evt_webhook_attempts (webhook_delivery_pk, started_at DESC);

CREATE TRIGGER evt_webhook_attempts_append_only_trg
BEFORE UPDATE OR DELETE ON public.evt_webhook_attempts
FOR EACH ROW EXECUTE FUNCTION public.iam_reject_row_mutation();

CREATE TABLE public.evt_security_events (
    security_event_pk bigint GENERATED ALWAYS AS IDENTITY,
    security_event_id uuid NOT NULL DEFAULT pg_catalog.gen_random_uuid(),
    source_signal_id uuid,
    event_type text COLLATE "C" NOT NULL,
    subject_type text COLLATE "C" NOT NULL,
    subject_principal_pk bigint,
    subject_reference_digest bytea,
    tenant_pk bigint,
    severity text COLLATE "C" NOT NULL,
    security_version bigint NOT NULL,
    schema_version integer NOT NULL,
    payload jsonb NOT NULL,
    payload_hash bytea NOT NULL,
    occurred_at timestamptz NOT NULL,
    published_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    CONSTRAINT evt_security_events_pkey PRIMARY KEY (security_event_pk),
    CONSTRAINT evt_security_events_id_key UNIQUE (security_event_id),
    CONSTRAINT evt_security_events_subject_version_key UNIQUE NULLS NOT DISTINCT (
        subject_type, subject_principal_pk, subject_reference_digest,
        event_type, security_version
    ),
    CONSTRAINT evt_security_events_id_v4_ck CHECK (public.iam_uuid_is_v4(security_event_id)),
    CONSTRAINT evt_security_events_source_id_v4_ck CHECK (
        source_signal_id IS NULL OR public.iam_uuid_is_v4(source_signal_id)
    ),
    CONSTRAINT evt_security_events_subject_fk FOREIGN KEY (subject_principal_pk)
        REFERENCES public.iam_principals (principal_pk) ON DELETE RESTRICT,
    CONSTRAINT evt_security_events_tenant_fk FOREIGN KEY (tenant_pk)
        REFERENCES public.org_tenants (tenant_pk) ON DELETE RESTRICT,
    CONSTRAINT evt_security_events_type_ck CHECK (
        event_type IN ('ACCOUNT_COMPROMISED', 'ASSURANCE_CHANGED', 'SESSION_REVOKED', 'TOKEN_REVOKED', 'CLIENT_COMPROMISED', 'KEY_REVOKED', 'RISK_ESCALATED', 'ACCESS_RESTORED')
    ),
    CONSTRAINT evt_security_events_subject_type_ck CHECK (
        subject_type IN ('PRINCIPAL', 'CLIENT', 'TENANT', 'SESSION', 'TOKEN_FAMILY', 'KEY_VERSION')
    ),
    CONSTRAINT evt_security_events_subject_ck CHECK (
        (subject_type = 'PRINCIPAL' AND subject_principal_pk IS NOT NULL AND subject_reference_digest IS NULL)
        OR (subject_type <> 'PRINCIPAL' AND subject_principal_pk IS NULL
            AND subject_reference_digest IS NOT NULL
            AND pg_catalog.octet_length(subject_reference_digest) = 32)
    ),
    CONSTRAINT evt_security_events_severity_ck CHECK (
        severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')
    ),
    CONSTRAINT evt_security_events_version_ck CHECK (security_version > 0),
    CONSTRAINT evt_security_events_payload_ck CHECK (
        schema_version > 0 AND pg_catalog.jsonb_typeof(payload) = 'object'
        AND pg_catalog.octet_length(payload::text) <= 262144
    ),
    CONSTRAINT evt_security_events_payload_hash_ck CHECK (pg_catalog.octet_length(payload_hash) = 32),
    CONSTRAINT evt_security_events_time_ck CHECK (
        occurred_at <= created_at AND (published_at IS NULL OR published_at >= created_at)
    )
);

COMMENT ON TABLE public.evt_security_events IS
    'Online append-only continuous security event stream with monotonic subject version and minimal bounded payload; S3.';

CREATE INDEX evt_security_events_unpublished_idx
    ON public.evt_security_events (occurred_at, security_event_pk)
    WHERE published_at IS NULL;
CREATE INDEX evt_security_events_principal_idx
    ON public.evt_security_events (subject_principal_pk, security_version DESC)
    WHERE subject_principal_pk IS NOT NULL;

CREATE TRIGGER evt_security_events_immutable_trg
BEFORE UPDATE ON public.evt_security_events
FOR EACH ROW EXECUTE FUNCTION public.iam_reject_column_changes(
    'security_event_pk', 'security_event_id', 'source_signal_id',
    'event_type', 'subject_type', 'subject_principal_pk',
    'subject_reference_digest', 'tenant_pk', 'severity',
    'security_version', 'schema_version', 'payload', 'payload_hash',
    'occurred_at', 'created_at'
);

CREATE TABLE public.evt_event_archive (
    occurred_at timestamptz NOT NULL,
    archive_event_pk bigint GENERATED ALWAYS AS IDENTITY,
    event_id uuid NOT NULL,
    event_class text COLLATE "C" NOT NULL,
    event_type text COLLATE "C" NOT NULL,
    schema_version integer NOT NULL,
    subject_reference_digest bytea,
    tenant_reference_digest bytea,
    payload jsonb NOT NULL,
    payload_hash bytea NOT NULL,
    source_recorded_at timestamptz NOT NULL,
    archived_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    archive_batch_id uuid NOT NULL,
    CONSTRAINT evt_event_archive_pkey PRIMARY KEY (occurred_at, archive_event_pk),
    CONSTRAINT evt_event_archive_event_key UNIQUE (occurred_at, event_id),
    CONSTRAINT evt_event_archive_event_id_v4_ck CHECK (public.iam_uuid_is_v4(event_id)),
    CONSTRAINT evt_event_archive_class_ck CHECK (
        event_class IN ('DOMAIN', 'SECURITY', 'WEBHOOK', 'DELIVERY')
    ),
    CONSTRAINT evt_event_archive_type_ck CHECK (
        pg_catalog.length(event_type) BETWEEN 3 AND 128
        AND event_type ~ '^[A-Za-z][A-Za-z0-9_.:-]*$'
    ),
    CONSTRAINT evt_event_archive_schema_ck CHECK (schema_version > 0),
    CONSTRAINT evt_event_archive_subject_digest_ck CHECK (
        subject_reference_digest IS NULL OR pg_catalog.octet_length(subject_reference_digest) = 32
    ),
    CONSTRAINT evt_event_archive_tenant_digest_ck CHECK (
        tenant_reference_digest IS NULL OR pg_catalog.octet_length(tenant_reference_digest) = 32
    ),
    CONSTRAINT evt_event_archive_payload_ck CHECK (
        pg_catalog.jsonb_typeof(payload) = 'object'
        AND pg_catalog.octet_length(payload::text) <= 1048576
    ),
    CONSTRAINT evt_event_archive_payload_hash_ck CHECK (pg_catalog.octet_length(payload_hash) = 32),
    CONSTRAINT evt_event_archive_batch_id_v4_ck CHECK (public.iam_uuid_is_v4(archive_batch_id)),
    CONSTRAINT evt_event_archive_time_ck CHECK (
        occurred_at <= source_recorded_at AND source_recorded_at <= archived_at
    )
) PARTITION BY RANGE (occurred_at);

COMMENT ON TABLE public.evt_event_archive IS
    'High-volume monthly event archive with no FK back to online aggregates; default partition is only an operational safety net; S2/S3.';

CREATE INDEX evt_event_archive_event_id_idx
    ON public.evt_event_archive (event_id, occurred_at);
CREATE INDEX evt_event_archive_subject_idx
    ON public.evt_event_archive (subject_reference_digest, occurred_at DESC)
    WHERE subject_reference_digest IS NOT NULL;
CREATE INDEX evt_event_archive_time_brin_idx
    ON public.evt_event_archive USING brin (occurred_at);

DO $partitions$
DECLARE
    offset_no integer;
    partition_start date;
    partition_end date;
    partition_name text;
BEGIN
    FOR offset_no IN -1..12 LOOP
        partition_start := (pg_catalog.date_trunc('month', CURRENT_DATE)
            + pg_catalog.make_interval(months => offset_no))::date;
        partition_end := (partition_start + pg_catalog.make_interval(months => 1))::date;
        partition_name := pg_catalog.format(
            'evt_event_archive_%s',
            pg_catalog.to_char(partition_start, 'YYYY_MM')
        );
        EXECUTE pg_catalog.format(
            'CREATE TABLE public.%I PARTITION OF public.evt_event_archive FOR VALUES FROM (%L) TO (%L)',
            partition_name,
            partition_start,
            partition_end
        );
    END LOOP;
END
$partitions$;

CREATE TABLE public.evt_event_archive_default
    PARTITION OF public.evt_event_archive DEFAULT;

COMMENT ON TABLE public.evt_event_archive_default IS
    'Default event archive partition; monitor continuously and drain into monthly partitions.';

CREATE TABLE public.audit_events (
    occurred_at timestamptz NOT NULL,
    audit_event_pk bigint GENERATED ALWAYS AS IDENTITY,
    event_id uuid NOT NULL DEFAULT pg_catalog.gen_random_uuid(),
    event_category text COLLATE "C" NOT NULL,
    action_code text COLLATE "C" NOT NULL,
    actor_type text COLLATE "C" NOT NULL,
    actor_principal_pk bigint,
    actor_reference_digest bytea,
    subject_principal_pk bigint,
    tenant_pk bigint,
    source_service text COLLATE "C" NOT NULL,
    source_ip inet,
    object_type text COLLATE "C" NOT NULL,
    object_id uuid,
    object_reference_digest bytea,
    before_digest bytea,
    after_digest bytea,
    reason_code text COLLATE "C",
    approval_reference text COLLATE "C",
    result text COLLATE "C" NOT NULL,
    error_code text COLLATE "C",
    policy_release_id uuid,
    trace_id uuid NOT NULL,
    correlation_id uuid,
    chain_scope text COLLATE "C" NOT NULL,
    chain_sequence bigint NOT NULL,
    previous_chain_hash bytea,
    canonical_event_hash bytea NOT NULL,
    chain_hash bytea NOT NULL,
    signature_algorithm text COLLATE "C",
    signature_key_ref text COLLATE "C",
    signature_key_version integer,
    signature bytea,
    detail_schema_version integer NOT NULL,
    detail jsonb NOT NULL,
    recorded_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    CONSTRAINT audit_events_pkey PRIMARY KEY (occurred_at, audit_event_pk),
    CONSTRAINT audit_events_event_key UNIQUE (occurred_at, event_id),
    CONSTRAINT audit_events_chain_sequence_key UNIQUE (
        occurred_at, chain_scope, chain_sequence
    ),
    CONSTRAINT audit_events_event_id_v4_ck CHECK (public.iam_uuid_is_v4(event_id)),
    CONSTRAINT audit_events_category_ck CHECK (
        event_category IN ('AUTHENTICATION', 'AUTHORIZATION', 'ADMINISTRATION', 'DATA_ACCESS', 'PRIVACY', 'KEY', 'CONTROL', 'MIGRATION', 'SECURITY')
    ),
    CONSTRAINT audit_events_action_ck CHECK (
        pg_catalog.length(action_code) BETWEEN 1 AND 128
        AND action_code ~ '^[A-Z][A-Z0-9_.:-]*$'
    ),
    CONSTRAINT audit_events_actor_type_ck CHECK (
        actor_type IN ('PRINCIPAL', 'SYSTEM', 'CLIENT', 'BREAKGLASS', 'ANONYMOUS')
    ),
    CONSTRAINT audit_events_actor_ck CHECK (
        (actor_type = 'PRINCIPAL' AND actor_principal_pk IS NOT NULL AND actor_reference_digest IS NULL)
        OR (actor_type <> 'PRINCIPAL' AND actor_principal_pk IS NULL
            AND (actor_type = 'ANONYMOUS' OR (
                actor_reference_digest IS NOT NULL
                AND pg_catalog.octet_length(actor_reference_digest) = 32
            )))
    ),
    CONSTRAINT audit_events_source_service_ck CHECK (
        pg_catalog.length(source_service) BETWEEN 1 AND 96
        AND source_service ~ '^[A-Za-z0-9][A-Za-z0-9_.:-]*$'
    ),
    CONSTRAINT audit_events_object_type_ck CHECK (
        pg_catalog.length(object_type) BETWEEN 1 AND 96
        AND object_type ~ '^[A-Za-z][A-Za-z0-9_.:-]*$'
    ),
    CONSTRAINT audit_events_object_id_v4_ck CHECK (
        object_id IS NULL OR public.iam_uuid_is_v4(object_id)
    ),
    CONSTRAINT audit_events_object_reference_digest_ck CHECK (
        object_reference_digest IS NULL OR pg_catalog.octet_length(object_reference_digest) = 32
    ),
    CONSTRAINT audit_events_before_digest_ck CHECK (
        before_digest IS NULL OR pg_catalog.octet_length(before_digest) = 32
    ),
    CONSTRAINT audit_events_after_digest_ck CHECK (
        after_digest IS NULL OR pg_catalog.octet_length(after_digest) = 32
    ),
    CONSTRAINT audit_events_reason_ck CHECK (
        reason_code IS NULL OR (
            pg_catalog.length(reason_code) BETWEEN 1 AND 96
            AND reason_code ~ '^[A-Z][A-Z0-9_]*$'
        )
    ),
    CONSTRAINT audit_events_approval_ck CHECK (
        approval_reference IS NULL OR pg_catalog.length(approval_reference) BETWEEN 1 AND 512
    ),
    CONSTRAINT audit_events_result_ck CHECK (
        result IN ('SUCCEEDED', 'DENIED', 'FAILED', 'PARTIAL')
    ),
    CONSTRAINT audit_events_error_ck CHECK (
        error_code IS NULL OR (
            pg_catalog.length(error_code) BETWEEN 1 AND 96
            AND error_code ~ '^[A-Z][A-Z0-9_]*$'
        )
    ),
    CONSTRAINT audit_events_policy_release_id_v4_ck CHECK (
        policy_release_id IS NULL OR public.iam_uuid_is_v4(policy_release_id)
    ),
    CONSTRAINT audit_events_trace_id_v4_ck CHECK (public.iam_uuid_is_v4(trace_id)),
    CONSTRAINT audit_events_correlation_id_v4_ck CHECK (
        correlation_id IS NULL OR public.iam_uuid_is_v4(correlation_id)
    ),
    CONSTRAINT audit_events_chain_scope_ck CHECK (
        pg_catalog.length(chain_scope) BETWEEN 1 AND 128
        AND chain_scope ~ '^[A-Za-z0-9][A-Za-z0-9_.:/-]*$'
    ),
    CONSTRAINT audit_events_chain_sequence_ck CHECK (chain_sequence > 0),
    CONSTRAINT audit_events_previous_hash_ck CHECK (
        previous_chain_hash IS NULL OR pg_catalog.octet_length(previous_chain_hash) = 32
    ),
    CONSTRAINT audit_events_canonical_hash_ck CHECK (
        pg_catalog.octet_length(canonical_event_hash) = 32
    ),
    CONSTRAINT audit_events_chain_hash_ck CHECK (pg_catalog.octet_length(chain_hash) = 32),
    CONSTRAINT audit_events_signature_group_ck CHECK (
        (signature_algorithm IS NULL AND signature_key_ref IS NULL
            AND signature_key_version IS NULL AND signature IS NULL)
        OR (signature_algorithm IN ('Ed25519', 'ES256', 'PS256')
            AND signature_key_ref IS NOT NULL
            AND pg_catalog.length(signature_key_ref) BETWEEN 1 AND 255
            AND signature_key_version > 0
            AND signature IS NOT NULL
            AND pg_catalog.octet_length(signature) BETWEEN 32 AND 8192)
    ),
    CONSTRAINT audit_events_detail_ck CHECK (
        detail_schema_version > 0 AND pg_catalog.jsonb_typeof(detail) = 'object'
        AND pg_catalog.octet_length(detail::text) <= 262144
    ),
    CONSTRAINT audit_events_time_ck CHECK (occurred_at <= recorded_at)
) PARTITION BY RANGE (occurred_at);

COMMENT ON TABLE public.audit_events IS
    'Monthly append-only audit evidence with historical locators, canonical hash, per-scope hash chain and optional external-key signature; no historical FKs; S3.';

CREATE INDEX audit_events_event_id_idx
    ON public.audit_events (event_id, occurred_at);
CREATE INDEX audit_events_trace_idx
    ON public.audit_events (trace_id, occurred_at DESC);
CREATE INDEX audit_events_actor_idx
    ON public.audit_events (actor_principal_pk, occurred_at DESC)
    WHERE actor_principal_pk IS NOT NULL;
CREATE INDEX audit_events_subject_idx
    ON public.audit_events (subject_principal_pk, occurred_at DESC)
    WHERE subject_principal_pk IS NOT NULL;
CREATE INDEX audit_events_tenant_idx
    ON public.audit_events (tenant_pk, occurred_at DESC)
    WHERE tenant_pk IS NOT NULL;
CREATE INDEX audit_events_object_idx
    ON public.audit_events (object_type, object_id, occurred_at DESC)
    WHERE object_id IS NOT NULL;
CREATE INDEX audit_events_time_brin_idx
    ON public.audit_events USING brin (occurred_at);

DO $partitions$
DECLARE
    offset_no integer;
    partition_start date;
    partition_end date;
    partition_name text;
BEGIN
    FOR offset_no IN -1..12 LOOP
        partition_start := (pg_catalog.date_trunc('month', CURRENT_DATE)
            + pg_catalog.make_interval(months => offset_no))::date;
        partition_end := (partition_start + pg_catalog.make_interval(months => 1))::date;
        partition_name := pg_catalog.format(
            'audit_events_%s',
            pg_catalog.to_char(partition_start, 'YYYY_MM')
        );
        EXECUTE pg_catalog.format(
            'CREATE TABLE public.%I PARTITION OF public.audit_events FOR VALUES FROM (%L) TO (%L)',
            partition_name,
            partition_start,
            partition_end
        );
    END LOOP;
END
$partitions$;

CREATE TABLE public.audit_events_default
    PARTITION OF public.audit_events DEFAULT;

COMMENT ON TABLE public.audit_events_default IS
    'Default audit partition; monitor continuously, fail deployment if future monthly partitions are missing, and drain promptly.';

-- Safe forward partition replenishment. The default partitions are locked
-- before checking their target month, so concurrent writes cannot race the
-- empty-range assertion. If rows already landed in that month, this function
-- fails closed; follow the documented lock/drain/attach procedure instead.
CREATE FUNCTION public.ops_ensure_event_audit_partitions(
    p_through_month date
)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $function$
DECLARE
    target_month date := pg_catalog.date_trunc('month', CURRENT_DATE)::date;
    maximum_month date := (
        pg_catalog.date_trunc('month', CURRENT_DATE)
        + interval '24 months'
    )::date;
    partition_end date;
    partition_name text;
    parent_row record;
    default_has_rows boolean;
BEGIN
    IF p_through_month IS NULL
       OR p_through_month <> pg_catalog.date_trunc(
           'month', p_through_month
       )::date
       OR p_through_month < target_month
       OR p_through_month > maximum_month THEN
        RAISE EXCEPTION USING
            ERRCODE = '22023',
            MESSAGE = 'through month must be a month boundary from current month through 24 months ahead';
    END IF;

    WHILE target_month <= p_through_month LOOP
        partition_end := (
            target_month + pg_catalog.make_interval(months => 1)
        )::date;

        FOR parent_row IN
            SELECT *
              FROM (VALUES
                  ('evt_event_archive', 'evt_event_archive_default'),
                  ('audit_events', 'audit_events_default')
              ) AS parents(parent_name, default_name)
        LOOP
            partition_name := pg_catalog.format(
                '%s_%s',
                parent_row.parent_name,
                pg_catalog.to_char(target_month, 'YYYY_MM')
            );

            IF pg_catalog.to_regclass(
                'public.' || partition_name
            ) IS NULL THEN
                EXECUTE pg_catalog.format(
                    'LOCK TABLE public.%I IN ACCESS EXCLUSIVE MODE',
                    parent_row.default_name
                );

                -- A concurrent maintainer may have created it while this call
                -- waited for the default-partition lock.
                IF pg_catalog.to_regclass(
                    'public.' || partition_name
                ) IS NULL THEN
                    EXECUTE pg_catalog.format(
                        'SELECT EXISTS (
                            SELECT 1 FROM public.%I
                             WHERE occurred_at >= $1
                               AND occurred_at < $2
                        )',
                        parent_row.default_name
                    )
                    INTO default_has_rows
                    USING target_month::timestamptz,
                          partition_end::timestamptz;

                    IF default_has_rows THEN
                        RAISE EXCEPTION USING
                            ERRCODE = '55000',
                            MESSAGE = pg_catalog.format(
                                'default partition %I contains rows for %s; use the documented lock/drain/attach procedure',
                                parent_row.default_name,
                                target_month
                            );
                    END IF;

                    EXECUTE pg_catalog.format(
                        'CREATE TABLE public.%I PARTITION OF public.%I
                         FOR VALUES FROM (%L) TO (%L)',
                        partition_name,
                        parent_row.parent_name,
                        target_month,
                        partition_end
                    );
                END IF;
            END IF;
        END LOOP;

        target_month := partition_end;
    END LOOP;
END
$function$;

COMMENT ON FUNCTION public.ops_ensure_event_audit_partitions(date) IS
    'Creates missing current/future event and audit monthly partitions only after an ACCESS EXCLUSIVE lock proves the corresponding default ranges empty.';

REVOKE ALL ON FUNCTION public.ops_ensure_event_audit_partitions(date)
FROM PUBLIC;

CREATE TABLE public.audit_sensitive_accesses (
    sensitive_access_pk bigint GENERATED ALWAYS AS IDENTITY,
    sensitive_access_id uuid NOT NULL DEFAULT pg_catalog.gen_random_uuid(),
    audit_event_id uuid NOT NULL,
    actor_principal_pk bigint NOT NULL,
    subject_principal_pk bigint,
    tenant_pk bigint,
    access_type text COLLATE "C" NOT NULL,
    data_category_pk bigint NOT NULL,
    purpose_pk bigint NOT NULL,
    legal_basis text COLLATE "C" NOT NULL,
    field_set_digest bytea NOT NULL,
    object_count bigint NOT NULL,
    result text COLLATE "C" NOT NULL,
    occurred_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    CONSTRAINT audit_sensitive_accesses_pkey PRIMARY KEY (sensitive_access_pk),
    CONSTRAINT audit_sensitive_accesses_id_key UNIQUE (sensitive_access_id),
    CONSTRAINT audit_sensitive_accesses_audit_event_key UNIQUE (audit_event_id),
    CONSTRAINT audit_sensitive_accesses_id_v4_ck CHECK (public.iam_uuid_is_v4(sensitive_access_id)),
    CONSTRAINT audit_sensitive_accesses_audit_event_id_v4_ck CHECK (public.iam_uuid_is_v4(audit_event_id)),
    CONSTRAINT audit_sensitive_accesses_type_ck CHECK (
        access_type IN ('VIEW_MASKED', 'VIEW_CLEAR', 'DECRYPT', 'EXPORT', 'SEARCH', 'BULK_READ', 'BLIND_INDEX_LOOKUP')
    ),
    CONSTRAINT audit_sensitive_accesses_legal_basis_ck CHECK (
        legal_basis IN ('CONSENT', 'CONTRACT', 'LEGAL_OBLIGATION', 'VITAL_INTERESTS', 'PUBLIC_TASK', 'LEGITIMATE_INTERESTS', 'SECURITY')
    ),
    CONSTRAINT audit_sensitive_accesses_field_digest_ck CHECK (
        pg_catalog.octet_length(field_set_digest) = 32
    ),
    CONSTRAINT audit_sensitive_accesses_count_ck CHECK (object_count > 0),
    CONSTRAINT audit_sensitive_accesses_result_ck CHECK (
        result IN ('SUCCEEDED', 'DENIED', 'FAILED', 'PARTIAL')
    ),
    CONSTRAINT audit_sensitive_accesses_time_ck CHECK (occurred_at <= created_at)
);

COMMENT ON TABLE public.audit_sensitive_accesses IS
    'Sensitive field access/decryption/search evidence using historical locators only; no FK ties retention to online or partitioned rows; S3.';

CREATE INDEX audit_sensitive_accesses_actor_time_idx
    ON public.audit_sensitive_accesses (actor_principal_pk, occurred_at DESC);
CREATE INDEX audit_sensitive_accesses_subject_time_idx
    ON public.audit_sensitive_accesses (subject_principal_pk, occurred_at DESC)
    WHERE subject_principal_pk IS NOT NULL;

CREATE TRIGGER audit_sensitive_accesses_append_only_trg
BEFORE UPDATE OR DELETE ON public.audit_sensitive_accesses
FOR EACH ROW EXECUTE FUNCTION public.iam_reject_row_mutation();

CREATE TABLE public.audit_chain_checkpoints (
    chain_checkpoint_pk bigint GENERATED ALWAYS AS IDENTITY,
    chain_checkpoint_id uuid NOT NULL DEFAULT pg_catalog.gen_random_uuid(),
    chain_scope text COLLATE "C" NOT NULL,
    partition_month date NOT NULL,
    sequence_no bigint NOT NULL,
    first_chain_sequence bigint NOT NULL,
    last_chain_sequence bigint NOT NULL,
    event_count bigint NOT NULL,
    merkle_root bytea NOT NULL,
    chain_head_hash bytea NOT NULL,
    archive_object_reference text COLLATE "C" NOT NULL,
    archive_object_version text COLLATE "C" NOT NULL,
    archive_hash bytea NOT NULL,
    signature_algorithm text COLLATE "C" NOT NULL,
    signature_key_ref text COLLATE "C" NOT NULL,
    signature_key_version integer NOT NULL,
    signature bytea NOT NULL,
    checkpointed_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    CONSTRAINT audit_chain_checkpoints_pkey PRIMARY KEY (chain_checkpoint_pk),
    CONSTRAINT audit_chain_checkpoints_id_key UNIQUE (chain_checkpoint_id),
    CONSTRAINT audit_chain_checkpoints_sequence_key UNIQUE (
        chain_scope, partition_month, sequence_no
    ),
    CONSTRAINT audit_chain_checkpoints_archive_key UNIQUE (
        archive_object_reference, archive_object_version
    ),
    CONSTRAINT audit_chain_checkpoints_id_v4_ck CHECK (public.iam_uuid_is_v4(chain_checkpoint_id)),
    CONSTRAINT audit_chain_checkpoints_scope_ck CHECK (
        pg_catalog.length(chain_scope) BETWEEN 1 AND 128
        AND chain_scope ~ '^[A-Za-z0-9][A-Za-z0-9_.:/-]*$'
    ),
    CONSTRAINT audit_chain_checkpoints_partition_month_ck CHECK (
        partition_month = pg_catalog.date_trunc('month', partition_month)::date
    ),
    CONSTRAINT audit_chain_checkpoints_sequence_ck CHECK (
        sequence_no > 0 AND first_chain_sequence > 0
        AND last_chain_sequence >= first_chain_sequence
        AND event_count = last_chain_sequence - first_chain_sequence + 1
    ),
    CONSTRAINT audit_chain_checkpoints_merkle_ck CHECK (pg_catalog.octet_length(merkle_root) = 32),
    CONSTRAINT audit_chain_checkpoints_head_ck CHECK (pg_catalog.octet_length(chain_head_hash) = 32),
    CONSTRAINT audit_chain_checkpoints_archive_reference_ck CHECK (
        pg_catalog.length(archive_object_reference) BETWEEN 1 AND 1024
    ),
    CONSTRAINT audit_chain_checkpoints_archive_version_ck CHECK (
        pg_catalog.length(archive_object_version) BETWEEN 1 AND 255
    ),
    CONSTRAINT audit_chain_checkpoints_archive_hash_ck CHECK (
        pg_catalog.octet_length(archive_hash) = 32
    ),
    CONSTRAINT audit_chain_checkpoints_algorithm_ck CHECK (
        signature_algorithm IN ('Ed25519', 'ES256', 'PS256')
    ),
    CONSTRAINT audit_chain_checkpoints_key_ref_ck CHECK (
        pg_catalog.length(signature_key_ref) BETWEEN 1 AND 255
    ),
    CONSTRAINT audit_chain_checkpoints_key_version_ck CHECK (signature_key_version > 0),
    CONSTRAINT audit_chain_checkpoints_signature_ck CHECK (
        pg_catalog.octet_length(signature) BETWEEN 32 AND 8192
    ),
    CONSTRAINT audit_chain_checkpoints_time_ck CHECK (checkpointed_at <= created_at)
);

COMMENT ON TABLE public.audit_chain_checkpoints IS
    'Append-only signed audit Merkle/chain checkpoint and external WORM object version; S3.';

CREATE INDEX audit_chain_checkpoints_month_idx
    ON public.audit_chain_checkpoints (partition_month, chain_scope, sequence_no);

CREATE TRIGGER audit_chain_checkpoints_append_only_trg
BEFORE UPDATE OR DELETE ON public.audit_chain_checkpoints
FOR EACH ROW EXECUTE FUNCTION public.iam_reject_row_mutation();

CREATE TABLE public.ops_migration_batches (
    migration_batch_pk bigint GENERATED ALWAYS AS IDENTITY,
    migration_batch_id uuid NOT NULL DEFAULT pg_catalog.gen_random_uuid(),
    source_system text COLLATE "C" NOT NULL,
    entity_type text COLLATE "C" NOT NULL,
    state text COLLATE "C" NOT NULL DEFAULT 'DISCOVERED',
    authoritative_writer text COLLATE "C" NOT NULL,
    rollback_deadline_at timestamptz,
    irreversible_boundary_reached boolean NOT NULL DEFAULT false,
    irreversible_boundary_reached_at timestamptz,
    total_count bigint NOT NULL DEFAULT 0,
    mapped_count bigint NOT NULL DEFAULT 0,
    succeeded_count bigint NOT NULL DEFAULT 0,
    failed_count bigint NOT NULL DEFAULT 0,
    exception_count bigint NOT NULL DEFAULT 0,
    reconciliation_hash bytea,
    cutover_at timestamptz,
    completed_at timestamptz,
    row_version bigint NOT NULL DEFAULT 1,
    created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    CONSTRAINT ops_migration_batches_pkey PRIMARY KEY (migration_batch_pk),
    CONSTRAINT ops_migration_batches_id_key UNIQUE (migration_batch_id),
    CONSTRAINT ops_migration_batches_id_v4_ck CHECK (public.iam_uuid_is_v4(migration_batch_id)),
    CONSTRAINT ops_migration_batches_source_ck CHECK (
        pg_catalog.length(source_system) BETWEEN 1 AND 96
        AND source_system ~ '^[A-Z][A-Z0-9_.:-]*$'
    ),
    CONSTRAINT ops_migration_batches_entity_ck CHECK (
        entity_type IN ('USER', 'IDENTITY', 'IDENTIFIER', 'MEMBERSHIP', 'PROFILE', 'ROLE_ASSIGNMENT', 'CLIENT')
    ),
    CONSTRAINT ops_migration_batches_state_ck CHECK (
        state IN ('DISCOVERED', 'CLEANSED', 'MAPPED', 'SHADOW', 'CANARY', 'CUTOVER', 'OBSERVING', 'COMPLETE', 'PAUSED', 'ROLLED_BACK', 'FAILED')
    ),
    CONSTRAINT ops_migration_batches_writer_ck CHECK (
        authoritative_writer IN ('LEGACY', 'NEW_PLATFORM', 'PAUSED')
    ),
    CONSTRAINT ops_migration_batches_boundary_ck CHECK (
        irreversible_boundary_reached = (irreversible_boundary_reached_at IS NOT NULL)
    ),
    CONSTRAINT ops_migration_batches_counts_ck CHECK (
        total_count >= 0 AND mapped_count >= 0 AND succeeded_count >= 0
        AND failed_count >= 0 AND exception_count >= 0
        AND mapped_count <= total_count
        AND succeeded_count + failed_count <= total_count
    ),
    CONSTRAINT ops_migration_batches_reconciliation_hash_ck CHECK (
        reconciliation_hash IS NULL OR pg_catalog.octet_length(reconciliation_hash) = 32
    ),
    CONSTRAINT ops_migration_batches_completion_ck CHECK (
        (state = 'COMPLETE') = (completed_at IS NOT NULL)
    ),
    CONSTRAINT ops_migration_batches_version_ck CHECK (row_version > 0),
    CONSTRAINT ops_migration_batches_time_ck CHECK (
        updated_at >= created_at
        AND (rollback_deadline_at IS NULL OR rollback_deadline_at > created_at)
        AND (irreversible_boundary_reached_at IS NULL OR irreversible_boundary_reached_at >= created_at)
        AND (cutover_at IS NULL OR cutover_at >= created_at)
        AND (completed_at IS NULL OR completed_at >= created_at)
    )
);

COMMENT ON TABLE public.ops_migration_batches IS
    'Migration phase, single authoritative writer, reconciliation counters and irreversible forward-only boundary; S2/S3.';

CREATE INDEX ops_migration_batches_state_idx
    ON public.ops_migration_batches (state, created_at);

CREATE TRIGGER ops_migration_batches_immutable_trg
BEFORE UPDATE ON public.ops_migration_batches
FOR EACH ROW EXECUTE FUNCTION public.iam_reject_column_changes(
    'migration_batch_pk', 'migration_batch_id', 'source_system',
    'entity_type', 'created_at'
);

CREATE TRIGGER ops_migration_batches_version_trg
BEFORE UPDATE ON public.ops_migration_batches
FOR EACH ROW EXECUTE FUNCTION public.iam_guard_nondecreasing_bigint('row_version');

CREATE TRIGGER ops_migration_batches_irreversible_trg
BEFORE UPDATE ON public.ops_migration_batches
FOR EACH ROW EXECUTE FUNCTION public.ops_guard_irreversible_boundary();

CREATE TABLE public.ops_legacy_id_mappings (
    legacy_id_mapping_pk bigint GENERATED ALWAYS AS IDENTITY,
    legacy_id_mapping_id uuid NOT NULL DEFAULT pg_catalog.gen_random_uuid(),
    migration_batch_pk bigint NOT NULL,
    source_system text COLLATE "C" NOT NULL,
    source_entity_type text COLLATE "C" NOT NULL,
    source_id_blind_index bytea NOT NULL,
    blind_index_key_ref text COLLATE "C" NOT NULL,
    blind_index_key_version integer NOT NULL,
    normalization_version integer NOT NULL,
    target_type text COLLATE "C" NOT NULL,
    target_user_pk bigint,
    target_membership_pk bigint,
    target_principal_pk bigint,
    state text COLLATE "C" NOT NULL DEFAULT 'MAPPED',
    mapping_version bigint NOT NULL DEFAULT 1,
    mapped_at timestamptz NOT NULL,
    retired_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    CONSTRAINT ops_legacy_id_mappings_pkey PRIMARY KEY (legacy_id_mapping_pk),
    CONSTRAINT ops_legacy_id_mappings_id_key UNIQUE (legacy_id_mapping_id),
    CONSTRAINT ops_legacy_id_mappings_source_key UNIQUE (
        source_system, source_entity_type, normalization_version,
        blind_index_key_version, source_id_blind_index
    ),
    CONSTRAINT ops_legacy_id_mappings_id_v4_ck CHECK (public.iam_uuid_is_v4(legacy_id_mapping_id)),
    CONSTRAINT ops_legacy_id_mappings_batch_fk FOREIGN KEY (migration_batch_pk)
        REFERENCES public.ops_migration_batches (migration_batch_pk) ON DELETE RESTRICT,
    CONSTRAINT ops_legacy_id_mappings_user_fk FOREIGN KEY (target_user_pk)
        REFERENCES public.iam_users (user_pk) ON DELETE RESTRICT,
    CONSTRAINT ops_legacy_id_mappings_membership_fk FOREIGN KEY (target_membership_pk)
        REFERENCES public.org_memberships (membership_pk) ON DELETE RESTRICT,
    CONSTRAINT ops_legacy_id_mappings_principal_fk FOREIGN KEY (target_principal_pk)
        REFERENCES public.iam_principals (principal_pk) ON DELETE RESTRICT,
    CONSTRAINT ops_legacy_id_mappings_source_system_ck CHECK (
        pg_catalog.length(source_system) BETWEEN 1 AND 96
        AND source_system ~ '^[A-Z][A-Z0-9_.:-]*$'
    ),
    CONSTRAINT ops_legacy_id_mappings_source_type_ck CHECK (
        pg_catalog.length(source_entity_type) BETWEEN 1 AND 96
        AND source_entity_type ~ '^[A-Z][A-Z0-9_.:-]*$'
    ),
    CONSTRAINT ops_legacy_id_mappings_blind_index_ck CHECK (
        pg_catalog.octet_length(source_id_blind_index) = 32
    ),
    CONSTRAINT ops_legacy_id_mappings_key_ref_ck CHECK (
        pg_catalog.length(blind_index_key_ref) BETWEEN 1 AND 255
    ),
    CONSTRAINT ops_legacy_id_mappings_versions_ck CHECK (
        blind_index_key_version > 0 AND normalization_version > 0 AND mapping_version > 0
    ),
    CONSTRAINT ops_legacy_id_mappings_target_ck CHECK (
        (target_type = 'USER' AND target_user_pk IS NOT NULL
            AND target_membership_pk IS NULL AND target_principal_pk IS NULL)
        OR (target_type = 'MEMBERSHIP' AND target_user_pk IS NULL
            AND target_membership_pk IS NOT NULL AND target_principal_pk IS NULL)
        OR (target_type = 'PRINCIPAL' AND target_user_pk IS NULL
            AND target_membership_pk IS NULL AND target_principal_pk IS NOT NULL)
    ),
    CONSTRAINT ops_legacy_id_mappings_state_ck CHECK (
        state IN ('MAPPED', 'VERIFIED', 'CONFLICT', 'RETIRED')
    ),
    CONSTRAINT ops_legacy_id_mappings_retired_ck CHECK (
        (state = 'RETIRED') = (retired_at IS NOT NULL)
    ),
    CONSTRAINT ops_legacy_id_mappings_time_ck CHECK (
        mapped_at <= created_at AND (retired_at IS NULL OR retired_at >= mapped_at)
    )
);

COMMENT ON TABLE public.ops_legacy_id_mappings IS
    'Permanent keyed-digest mapping from legacy IDs to typed platform targets; raw legacy IDs never become primary keys; S3.';

CREATE INDEX ops_legacy_id_mappings_batch_state_idx
    ON public.ops_legacy_id_mappings (migration_batch_pk, state, legacy_id_mapping_pk);
CREATE INDEX ops_legacy_id_mappings_target_user_idx
    ON public.ops_legacy_id_mappings (target_user_pk)
    WHERE target_user_pk IS NOT NULL;
CREATE INDEX ops_legacy_id_mappings_target_membership_idx
    ON public.ops_legacy_id_mappings (target_membership_pk)
    WHERE target_membership_pk IS NOT NULL;

CREATE TRIGGER ops_legacy_id_mappings_immutable_trg
BEFORE UPDATE ON public.ops_legacy_id_mappings
FOR EACH ROW EXECUTE FUNCTION public.iam_reject_column_changes(
    'legacy_id_mapping_pk', 'legacy_id_mapping_id', 'migration_batch_pk',
    'source_system', 'source_entity_type', 'source_id_blind_index',
    'blind_index_key_ref', 'blind_index_key_version',
    'normalization_version', 'target_type', 'target_user_pk',
    'target_membership_pk', 'target_principal_pk', 'mapped_at', 'created_at'
);

CREATE TRIGGER ops_legacy_id_mappings_version_trg
BEFORE UPDATE ON public.ops_legacy_id_mappings
FOR EACH ROW EXECUTE FUNCTION public.iam_guard_nondecreasing_bigint('mapping_version');

CREATE TABLE public.ops_change_log (
    change_log_pk bigint GENERATED ALWAYS AS IDENTITY,
    change_log_id uuid NOT NULL DEFAULT pg_catalog.gen_random_uuid(),
    migration_batch_pk bigint NOT NULL,
    source_system text COLLATE "C" NOT NULL,
    aggregate_type text COLLATE "C" NOT NULL,
    aggregate_id uuid NOT NULL,
    aggregate_version bigint NOT NULL,
    authority text COLLATE "C" NOT NULL,
    idempotency_key_digest bytea NOT NULL,
    payload_hash bytea NOT NULL,
    payload_reference text COLLATE "C" NOT NULL,
    state text COLLATE "C" NOT NULL DEFAULT 'PENDING',
    occurred_at timestamptz NOT NULL,
    synchronized_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    CONSTRAINT ops_change_log_pkey PRIMARY KEY (change_log_pk),
    CONSTRAINT ops_change_log_id_key UNIQUE (change_log_id),
    CONSTRAINT ops_change_log_aggregate_version_key UNIQUE (
        migration_batch_pk, aggregate_type, aggregate_id, aggregate_version
    ),
    CONSTRAINT ops_change_log_id_v4_ck CHECK (public.iam_uuid_is_v4(change_log_id)),
    CONSTRAINT ops_change_log_batch_fk FOREIGN KEY (migration_batch_pk)
        REFERENCES public.ops_migration_batches (migration_batch_pk) ON DELETE RESTRICT,
    CONSTRAINT ops_change_log_source_ck CHECK (
        pg_catalog.length(source_system) BETWEEN 1 AND 96
        AND source_system ~ '^[A-Z][A-Z0-9_.:-]*$'
    ),
    CONSTRAINT ops_change_log_aggregate_type_ck CHECK (
        pg_catalog.length(aggregate_type) BETWEEN 1 AND 96
        AND aggregate_type ~ '^[A-Za-z][A-Za-z0-9_.:-]*$'
    ),
    CONSTRAINT ops_change_log_aggregate_id_v4_ck CHECK (public.iam_uuid_is_v4(aggregate_id)),
    CONSTRAINT ops_change_log_aggregate_version_ck CHECK (aggregate_version > 0),
    CONSTRAINT ops_change_log_authority_ck CHECK (
        authority IN ('LEGACY', 'NEW_PLATFORM')
    ),
    CONSTRAINT ops_change_log_idempotency_ck CHECK (
        pg_catalog.octet_length(idempotency_key_digest) = 32
    ),
    CONSTRAINT ops_change_log_payload_hash_ck CHECK (pg_catalog.octet_length(payload_hash) = 32),
    CONSTRAINT ops_change_log_payload_reference_ck CHECK (
        pg_catalog.length(payload_reference) BETWEEN 1 AND 1024
    ),
    CONSTRAINT ops_change_log_state_ck CHECK (
        state IN ('PENDING', 'SYNCHRONIZING', 'SYNCHRONIZED', 'CONFLICT', 'FAILED', 'IGNORED')
    ),
    CONSTRAINT ops_change_log_synchronized_ck CHECK (
        (state = 'SYNCHRONIZED') = (synchronized_at IS NOT NULL)
    ),
    CONSTRAINT ops_change_log_time_ck CHECK (
        occurred_at <= created_at
        AND (synchronized_at IS NULL OR synchronized_at >= created_at)
    )
);

COMMENT ON TABLE public.ops_change_log IS
    'Append-oriented cutover change log for reverse synchronization; payload is an opaque reference plus hash and contains no credentials; S3.';

CREATE INDEX ops_change_log_pending_idx
    ON public.ops_change_log (migration_batch_pk, occurred_at, change_log_pk)
    WHERE state IN ('PENDING', 'FAILED');
CREATE INDEX ops_change_log_aggregate_idx
    ON public.ops_change_log (aggregate_type, aggregate_id, aggregate_version DESC);

COMMIT;
