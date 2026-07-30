-- Foundational IAM objects. All objects are deliberately qualified in public;
-- no extension, enum, additional schema, or ORM metadata is required.

BEGIN;

CREATE FUNCTION public.iam_uuid_is_v4(value uuid)
RETURNS boolean
LANGUAGE sql
IMMUTABLE
STRICT
PARALLEL SAFE
SET search_path = pg_catalog
AS $function$
    SELECT (pg_catalog.get_byte(pg_catalog.uuid_send(value), 6) >> 4) = 4
       AND (pg_catalog.get_byte(pg_catalog.uuid_send(value), 8) & 192) = 128
$function$;

COMMENT ON FUNCTION public.iam_uuid_is_v4(uuid) IS
    'Returns true only for an RFC 4122 variant UUID whose version nibble is 4.';

CREATE FUNCTION public.iam_reject_column_changes()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $function$
DECLARE
    column_name text;
BEGIN
    IF TG_OP <> 'UPDATE' THEN
        RETURN NEW;
    END IF;

    FOREACH column_name IN ARRAY TG_ARGV LOOP
        IF (pg_catalog.to_jsonb(OLD) -> column_name)
           IS DISTINCT FROM
           (pg_catalog.to_jsonb(NEW) -> column_name) THEN
            RAISE EXCEPTION
                USING
                    ERRCODE = '22000',
                    MESSAGE = format(
                        'column %I.%I is immutable',
                        TG_TABLE_NAME,
                        column_name
                    );
        END IF;
    END LOOP;

    RETURN NEW;
END
$function$;

COMMENT ON FUNCTION public.iam_reject_column_changes() IS
    'Generic trigger helper that rejects updates to columns named in trigger arguments.';

CREATE FUNCTION public.iam_guard_nondecreasing_bigint()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $function$
DECLARE
    column_name text;
    old_value bigint;
    new_value bigint;
BEGIN
    FOREACH column_name IN ARRAY TG_ARGV LOOP
        old_value := (pg_catalog.to_jsonb(OLD) ->> column_name)::bigint;
        new_value := (pg_catalog.to_jsonb(NEW) ->> column_name)::bigint;

        IF new_value < old_value THEN
            RAISE EXCEPTION
                USING
                    ERRCODE = '22000',
                    MESSAGE = format(
                        'column %I.%I must not decrease (%s -> %s)',
                        TG_TABLE_NAME,
                        column_name,
                        old_value,
                        new_value
                    );
        END IF;
    END LOOP;

    RETURN NEW;
END
$function$;

COMMENT ON FUNCTION public.iam_guard_nondecreasing_bigint() IS
    'Generic trigger helper that prevents bigint epochs and versions named in trigger arguments from decreasing.';

CREATE FUNCTION public.iam_reject_row_mutation()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $function$
BEGIN
    RAISE EXCEPTION
        USING
            ERRCODE = '22000',
            MESSAGE = format(
                '%s is not allowed on append-only table %I',
                TG_OP,
                TG_TABLE_NAME
            );
    RETURN NULL;
END
$function$;

COMMENT ON FUNCTION public.iam_reject_row_mutation() IS
    'Generic trigger helper that rejects UPDATE and DELETE on append-only rows.';

CREATE FUNCTION public.ops_guard_irreversible_boundary()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $function$
BEGIN
    IF OLD.irreversible_boundary_reached
       AND (
           NOT NEW.irreversible_boundary_reached
           OR NEW.irreversible_boundary_reached_at
              IS DISTINCT FROM OLD.irreversible_boundary_reached_at
       ) THEN
        RAISE EXCEPTION
            USING
                ERRCODE = '22000',
                MESSAGE = 'an operation step irreversible boundary cannot move backward or be rewritten';
    END IF;

    RETURN NEW;
END
$function$;

COMMENT ON FUNCTION public.ops_guard_irreversible_boundary() IS
    'Allows an operation step to cross its irreversible boundary once and prevents reversal or timestamp rewriting.';

CREATE TABLE public.iam_principals (
    principal_pk bigint GENERATED ALWAYS AS IDENTITY,
    principal_id uuid NOT NULL DEFAULT pg_catalog.gen_random_uuid(),
    principal_type text COLLATE "C" NOT NULL,
    status text COLLATE "C" NOT NULL DEFAULT 'ACTIVE',
    row_version bigint NOT NULL DEFAULT 1,
    created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    created_by_principal_pk bigint,
    updated_by_principal_pk bigint,
    CONSTRAINT iam_principals_pkey PRIMARY KEY (principal_pk),
    CONSTRAINT iam_principals_principal_id_key UNIQUE (principal_id),
    CONSTRAINT iam_principals_principal_id_v4_ck
        CHECK (public.iam_uuid_is_v4(principal_id)),
    CONSTRAINT iam_principals_principal_type_ck
        CHECK (principal_type IN ('USER', 'MACHINE')),
    CONSTRAINT iam_principals_status_ck
        CHECK (status IN ('ACTIVE', 'SUSPENDED', 'RETIRED')),
    CONSTRAINT iam_principals_row_version_ck CHECK (row_version > 0),
    CONSTRAINT iam_principals_time_order_ck CHECK (updated_at >= created_at),
    CONSTRAINT iam_principals_created_by_fk
        FOREIGN KEY (created_by_principal_pk)
        REFERENCES public.iam_principals (principal_pk)
        ON DELETE RESTRICT,
    CONSTRAINT iam_principals_updated_by_fk
        FOREIGN KEY (updated_by_principal_pk)
        REFERENCES public.iam_principals (principal_pk)
        ON DELETE RESTRICT
);

COMMENT ON TABLE public.iam_principals IS
    'Unified authorization principals for human users and machine identities; S1.';
COMMENT ON COLUMN public.iam_principals.principal_pk IS
    'Internal bigint identity key; never expose as an API identifier.';
COMMENT ON COLUMN public.iam_principals.principal_id IS
    'Immutable external UUIDv4 for the principal.';
COMMENT ON COLUMN public.iam_principals.principal_type IS
    'Closed principal kind: USER or MACHINE.';
COMMENT ON COLUMN public.iam_principals.status IS
    'Authorization-level principal availability, separate from user and membership state.';
COMMENT ON COLUMN public.iam_principals.row_version IS
    'Positive optimistic-concurrency version.';
COMMENT ON COLUMN public.iam_principals.created_at IS
    'UTC creation instant.';
COMMENT ON COLUMN public.iam_principals.updated_at IS
    'UTC last-update instant, set explicitly by the writer.';
COMMENT ON COLUMN public.iam_principals.created_by_principal_pk IS
    'Optional principal that created the row; NULL denotes a system/bootstrap action.';
COMMENT ON COLUMN public.iam_principals.updated_by_principal_pk IS
    'Optional principal that most recently updated the row.';

CREATE INDEX iam_principals_type_status_idx
    ON public.iam_principals (principal_type, status);
CREATE INDEX iam_principals_created_by_idx
    ON public.iam_principals (created_by_principal_pk)
    WHERE created_by_principal_pk IS NOT NULL;
CREATE INDEX iam_principals_updated_by_idx
    ON public.iam_principals (updated_by_principal_pk)
    WHERE updated_by_principal_pk IS NOT NULL;

CREATE TRIGGER iam_principals_immutable_columns_trg
BEFORE UPDATE ON public.iam_principals
FOR EACH ROW
EXECUTE FUNCTION public.iam_reject_column_changes(
    'principal_pk',
    'principal_id',
    'principal_type',
    'created_at'
);

CREATE TRIGGER iam_principals_nondecreasing_version_trg
BEFORE UPDATE ON public.iam_principals
FOR EACH ROW
EXECUTE FUNCTION public.iam_guard_nondecreasing_bigint('row_version');

CREATE TABLE public.iam_users (
    user_pk bigint NOT NULL,
    user_id uuid NOT NULL DEFAULT pg_catalog.gen_random_uuid(),
    lifecycle_state text COLLATE "C" NOT NULL DEFAULT 'PROVISIONAL',
    lock_state text COLLATE "C" NOT NULL DEFAULT 'ENABLED',
    freeze_state text COLLATE "C" NOT NULL DEFAULT 'CLEAR',
    security_epoch bigint NOT NULL DEFAULT 1,
    consent_epoch bigint NOT NULL DEFAULT 1,
    aggregate_version bigint NOT NULL DEFAULT 1,
    row_version bigint NOT NULL DEFAULT 1,
    deletion_due_at timestamptz,
    anonymized_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    created_by_principal_pk bigint,
    updated_by_principal_pk bigint,
    CONSTRAINT iam_users_pkey PRIMARY KEY (user_pk),
    CONSTRAINT iam_users_user_id_key UNIQUE (user_id),
    CONSTRAINT iam_users_principal_fk
        FOREIGN KEY (user_pk)
        REFERENCES public.iam_principals (principal_pk)
        ON DELETE RESTRICT,
    CONSTRAINT iam_users_created_by_fk
        FOREIGN KEY (created_by_principal_pk)
        REFERENCES public.iam_principals (principal_pk)
        ON DELETE RESTRICT,
    CONSTRAINT iam_users_updated_by_fk
        FOREIGN KEY (updated_by_principal_pk)
        REFERENCES public.iam_principals (principal_pk)
        ON DELETE RESTRICT,
    CONSTRAINT iam_users_user_id_v4_ck
        CHECK (public.iam_uuid_is_v4(user_id)),
    CONSTRAINT iam_users_lifecycle_state_ck
        CHECK (
            lifecycle_state IN (
                'PROVISIONAL',
                'ACTIVE',
                'DELETION_PENDING',
                'ANONYMIZED'
            )
        ),
    CONSTRAINT iam_users_lock_state_ck
        CHECK (lock_state IN ('ENABLED', 'LOCKED')),
    CONSTRAINT iam_users_freeze_state_ck
        CHECK (freeze_state IN ('CLEAR', 'FROZEN')),
    CONSTRAINT iam_users_security_epoch_ck CHECK (security_epoch > 0),
    CONSTRAINT iam_users_consent_epoch_ck CHECK (consent_epoch > 0),
    CONSTRAINT iam_users_aggregate_version_ck CHECK (aggregate_version > 0),
    CONSTRAINT iam_users_row_version_ck CHECK (row_version > 0),
    CONSTRAINT iam_users_deletion_due_state_ck
        CHECK (
            (lifecycle_state = 'DELETION_PENDING' AND deletion_due_at IS NOT NULL)
            OR (lifecycle_state IN ('PROVISIONAL', 'ACTIVE') AND deletion_due_at IS NULL)
            OR lifecycle_state = 'ANONYMIZED'
        ),
    CONSTRAINT iam_users_anonymized_state_ck
        CHECK (
            (lifecycle_state = 'ANONYMIZED')
            = (anonymized_at IS NOT NULL)
        ),
    CONSTRAINT iam_users_time_order_ck
        CHECK (
            updated_at >= created_at
            AND (deletion_due_at IS NULL OR deletion_due_at >= created_at)
            AND (anonymized_at IS NULL OR anonymized_at >= created_at)
        )
);

COMMENT ON TABLE public.iam_users IS
    'Global human-user aggregate extending one USER principal with orthogonal lifecycle, lock, and freeze states; S2.';
COMMENT ON COLUMN public.iam_users.user_pk IS
    'Shared internal PK/FK whose identity is allocated by iam_principals.';
COMMENT ON COLUMN public.iam_users.user_id IS
    'Immutable, non-reusable external Global User UUIDv4.';
COMMENT ON COLUMN public.iam_users.lifecycle_state IS
    'Lifecycle dimension independent of authentication lock and security freeze.';
COMMENT ON COLUMN public.iam_users.lock_state IS
    'Authentication lock dimension; unfreezing never clears this value.';
COMMENT ON COLUMN public.iam_users.freeze_state IS
    'Global security freeze dimension independent of lifecycle and lock.';
COMMENT ON COLUMN public.iam_users.security_epoch IS
    'Monotonic cache/revocation epoch for security-relevant user changes.';
COMMENT ON COLUMN public.iam_users.consent_epoch IS
    'Monotonic epoch for consent-dependent authorization and token invalidation.';
COMMENT ON COLUMN public.iam_users.aggregate_version IS
    'Monotonic user aggregate event version.';
COMMENT ON COLUMN public.iam_users.row_version IS
    'Positive optimistic-concurrency version.';
COMMENT ON COLUMN public.iam_users.deletion_due_at IS
    'UTC cooling-period deadline while lifecycle_state is DELETION_PENDING.';
COMMENT ON COLUMN public.iam_users.anonymized_at IS
    'UTC instant at which irreversible anonymization completed.';
COMMENT ON COLUMN public.iam_users.created_at IS
    'UTC creation instant.';
COMMENT ON COLUMN public.iam_users.updated_at IS
    'UTC last-update instant, set explicitly by the writer.';
COMMENT ON COLUMN public.iam_users.created_by_principal_pk IS
    'Optional actor that created the user aggregate.';
COMMENT ON COLUMN public.iam_users.updated_by_principal_pk IS
    'Optional actor that most recently updated the user aggregate.';

CREATE INDEX iam_users_active_security_idx
    ON public.iam_users (lock_state, freeze_state, user_pk)
    WHERE lifecycle_state = 'ACTIVE';
CREATE INDEX iam_users_deletion_due_idx
    ON public.iam_users (deletion_due_at, user_pk)
    WHERE lifecycle_state = 'DELETION_PENDING';
CREATE INDEX iam_users_created_by_idx
    ON public.iam_users (created_by_principal_pk)
    WHERE created_by_principal_pk IS NOT NULL;
CREATE INDEX iam_users_updated_by_idx
    ON public.iam_users (updated_by_principal_pk)
    WHERE updated_by_principal_pk IS NOT NULL;

CREATE FUNCTION public.iam_enforce_user_principal_type()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $function$
BEGIN
    PERFORM 1
      FROM public.iam_principals
     WHERE principal_pk = NEW.user_pk
       AND principal_type = 'USER';

    IF NOT FOUND THEN
        RAISE EXCEPTION
            USING
                ERRCODE = '23514',
                MESSAGE = format(
                    'iam_users.user_pk %s must reference a USER principal',
                    NEW.user_pk
                );
    END IF;

    RETURN NEW;
END
$function$;

COMMENT ON FUNCTION public.iam_enforce_user_principal_type() IS
    'Ensures each iam_users extension row references a principal of type USER.';

CREATE TRIGGER iam_users_principal_type_trg
BEFORE INSERT OR UPDATE OF user_pk ON public.iam_users
FOR EACH ROW
EXECUTE FUNCTION public.iam_enforce_user_principal_type();

CREATE TRIGGER iam_users_immutable_columns_trg
BEFORE UPDATE ON public.iam_users
FOR EACH ROW
EXECUTE FUNCTION public.iam_reject_column_changes(
    'user_pk',
    'user_id',
    'created_at'
);

CREATE TRIGGER iam_users_nondecreasing_versions_trg
BEFORE UPDATE ON public.iam_users
FOR EACH ROW
EXECUTE FUNCTION public.iam_guard_nondecreasing_bigint(
    'security_epoch',
    'consent_epoch',
    'aggregate_version',
    'row_version'
);

CREATE TABLE public.ops_operations (
    operation_pk bigint GENERATED ALWAYS AS IDENTITY,
    operation_id uuid NOT NULL DEFAULT pg_catalog.gen_random_uuid(),
    operation_type text COLLATE "C" NOT NULL,
    state text COLLATE "C" NOT NULL DEFAULT 'PENDING',
    subject_principal_pk bigint,
    idempotency_scope text COLLATE "C",
    idempotency_key_digest bytea,
    request_hash bytea NOT NULL,
    checkpoint_schema_version integer NOT NULL DEFAULT 1,
    checkpoint jsonb NOT NULL DEFAULT '{}'::jsonb,
    attempt_count integer NOT NULL DEFAULT 0,
    next_action_at timestamptz,
    deadline_at timestamptz,
    result_reference text COLLATE "C",
    result_digest bytea,
    error_code text COLLATE "C",
    error_detail_schema_version integer,
    error_detail jsonb,
    completed_at timestamptz,
    row_version bigint NOT NULL DEFAULT 1,
    created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    created_by_principal_pk bigint,
    updated_by_principal_pk bigint,
    CONSTRAINT ops_operations_pkey PRIMARY KEY (operation_pk),
    CONSTRAINT ops_operations_operation_id_key UNIQUE (operation_id),
    CONSTRAINT ops_operations_operation_id_v4_ck
        CHECK (public.iam_uuid_is_v4(operation_id)),
    CONSTRAINT ops_operations_operation_type_ck
        CHECK (
            pg_catalog.length(operation_type) BETWEEN 1 AND 64
            AND operation_type ~ '^[A-Z][A-Z0-9_]*$'
        ),
    CONSTRAINT ops_operations_state_ck
        CHECK (
            state IN (
                'PENDING',
                'RUNNING',
                'BLOCKED',
                'PARTIAL',
                'SUCCEEDED',
                'FAILED',
                'CANCELLED'
            )
        ),
    CONSTRAINT ops_operations_idempotency_scope_ck
        CHECK (
            idempotency_scope IS NULL
            OR (
                pg_catalog.length(idempotency_scope) BETWEEN 1 AND 200
                AND idempotency_scope ~ '^[A-Za-z0-9][A-Za-z0-9_.:/-]*$'
            )
        ),
    CONSTRAINT ops_operations_idempotency_group_ck
        CHECK (
            (idempotency_scope IS NULL AND idempotency_key_digest IS NULL)
            OR
            (idempotency_scope IS NOT NULL AND idempotency_key_digest IS NOT NULL)
        ),
    CONSTRAINT ops_operations_idempotency_digest_ck
        CHECK (
            idempotency_key_digest IS NULL
            OR pg_catalog.octet_length(idempotency_key_digest) = 32
        ),
    CONSTRAINT ops_operations_request_hash_ck
        CHECK (pg_catalog.octet_length(request_hash) = 32),
    CONSTRAINT ops_operations_checkpoint_schema_ck
        CHECK (
            checkpoint_schema_version > 0
            AND pg_catalog.jsonb_typeof(checkpoint) = 'object'
        ),
    CONSTRAINT ops_operations_attempt_count_ck CHECK (attempt_count >= 0),
    CONSTRAINT ops_operations_result_reference_ck
        CHECK (
            result_reference IS NULL
            OR pg_catalog.length(result_reference) BETWEEN 1 AND 1024
        ),
    CONSTRAINT ops_operations_result_digest_ck
        CHECK (
            result_digest IS NULL
            OR pg_catalog.octet_length(result_digest) = 32
        ),
    CONSTRAINT ops_operations_error_code_ck
        CHECK (
            error_code IS NULL
            OR (
                pg_catalog.length(error_code) BETWEEN 1 AND 64
                AND error_code ~ '^[A-Z][A-Z0-9_]*$'
            )
        ),
    CONSTRAINT ops_operations_error_detail_schema_ck
        CHECK (
            (error_detail_schema_version IS NULL AND error_detail IS NULL)
            OR (
                error_detail_schema_version IS NOT NULL
                AND error_detail IS NOT NULL
                AND error_detail_schema_version > 0
                AND pg_catalog.jsonb_typeof(error_detail) = 'object'
            )
        ),
    CONSTRAINT ops_operations_completion_state_ck
        CHECK (
            (state IN ('SUCCEEDED', 'FAILED', 'CANCELLED'))
            = (completed_at IS NOT NULL)
        ),
    CONSTRAINT ops_operations_row_version_ck CHECK (row_version > 0),
    CONSTRAINT ops_operations_time_order_ck
        CHECK (
            updated_at >= created_at
            AND (next_action_at IS NULL OR next_action_at >= created_at)
            AND (deadline_at IS NULL OR deadline_at >= created_at)
            AND (completed_at IS NULL OR completed_at >= created_at)
        ),
    CONSTRAINT ops_operations_subject_principal_fk
        FOREIGN KEY (subject_principal_pk)
        REFERENCES public.iam_principals (principal_pk)
        ON DELETE RESTRICT,
    CONSTRAINT ops_operations_created_by_fk
        FOREIGN KEY (created_by_principal_pk)
        REFERENCES public.iam_principals (principal_pk)
        ON DELETE RESTRICT,
    CONSTRAINT ops_operations_updated_by_fk
        FOREIGN KEY (updated_by_principal_pk)
        REFERENCES public.iam_principals (principal_pk)
        ON DELETE RESTRICT
);

COMMENT ON TABLE public.ops_operations IS
    'Asynchronous and cross-domain Saga operation root with stable idempotency and progress state; S2/S3.';
COMMENT ON COLUMN public.ops_operations.operation_pk IS
    'Internal bigint identity key.';
COMMENT ON COLUMN public.ops_operations.operation_id IS
    'Immutable external UUIDv4 returned by asynchronous APIs.';
COMMENT ON COLUMN public.ops_operations.operation_type IS
    'Versioned application operation code using a constrained portable format.';
COMMENT ON COLUMN public.ops_operations.state IS
    'Current aggregate operation state.';
COMMENT ON COLUMN public.ops_operations.subject_principal_pk IS
    'Optional human or machine subject of the operation.';
COMMENT ON COLUMN public.ops_operations.idempotency_scope IS
    'Stable application-defined uniqueness scope for the idempotency digest.';
COMMENT ON COLUMN public.ops_operations.idempotency_key_digest IS
    'Fixed-length keyed digest of the client idempotency key; never the raw key.';
COMMENT ON COLUMN public.ops_operations.request_hash IS
    'SHA-256-sized digest of a canonically serialized request.';
COMMENT ON COLUMN public.ops_operations.checkpoint_schema_version IS
    'Schema version for the non-core JSON checkpoint.';
COMMENT ON COLUMN public.ops_operations.checkpoint IS
    'Non-core resumable Saga checkpoint; core state remains relational.';
COMMENT ON COLUMN public.ops_operations.attempt_count IS
    'Number of coordinator attempts already started.';
COMMENT ON COLUMN public.ops_operations.next_action_at IS
    'UTC earliest time at which a worker should claim the operation.';
COMMENT ON COLUMN public.ops_operations.deadline_at IS
    'UTC business or regulatory deadline.';
COMMENT ON COLUMN public.ops_operations.result_reference IS
    'Opaque safe reference to a result stored outside this row.';
COMMENT ON COLUMN public.ops_operations.result_digest IS
    'SHA-256-sized integrity digest for the referenced result.';
COMMENT ON COLUMN public.ops_operations.error_code IS
    'Stable, non-sensitive application error code.';
COMMENT ON COLUMN public.ops_operations.error_detail_schema_version IS
    'Schema version for error_detail; NULL when no detail is stored.';
COMMENT ON COLUMN public.ops_operations.error_detail IS
    'Versioned non-sensitive machine detail; credentials and unnecessary PII are forbidden.';
COMMENT ON COLUMN public.ops_operations.completed_at IS
    'UTC terminal completion instant.';
COMMENT ON COLUMN public.ops_operations.row_version IS
    'Positive optimistic-concurrency version.';
COMMENT ON COLUMN public.ops_operations.created_at IS
    'UTC creation instant.';
COMMENT ON COLUMN public.ops_operations.updated_at IS
    'UTC last-update instant.';
COMMENT ON COLUMN public.ops_operations.created_by_principal_pk IS
    'Optional principal that requested or created the operation.';
COMMENT ON COLUMN public.ops_operations.updated_by_principal_pk IS
    'Optional principal that most recently changed the operation.';

CREATE UNIQUE INDEX ops_operations_idempotency_key_uidx
    ON public.ops_operations (idempotency_scope, idempotency_key_digest)
    WHERE idempotency_key_digest IS NOT NULL;
CREATE INDEX ops_operations_claim_idx
    ON public.ops_operations (state, next_action_at, operation_pk)
    WHERE state IN ('PENDING', 'RUNNING', 'BLOCKED', 'PARTIAL');
CREATE INDEX ops_operations_subject_idx
    ON public.ops_operations (subject_principal_pk, created_at DESC)
    WHERE subject_principal_pk IS NOT NULL;
CREATE INDEX ops_operations_created_by_idx
    ON public.ops_operations (created_by_principal_pk)
    WHERE created_by_principal_pk IS NOT NULL;
CREATE INDEX ops_operations_updated_by_idx
    ON public.ops_operations (updated_by_principal_pk)
    WHERE updated_by_principal_pk IS NOT NULL;

CREATE TRIGGER ops_operations_immutable_columns_trg
BEFORE UPDATE ON public.ops_operations
FOR EACH ROW
EXECUTE FUNCTION public.iam_reject_column_changes(
    'operation_pk',
    'operation_id',
    'operation_type',
    'idempotency_scope',
    'idempotency_key_digest',
    'request_hash',
    'created_at'
);

CREATE TRIGGER ops_operations_nondecreasing_version_trg
BEFORE UPDATE ON public.ops_operations
FOR EACH ROW
EXECUTE FUNCTION public.iam_guard_nondecreasing_bigint('row_version');

CREATE TABLE public.ops_operation_steps (
    operation_step_pk bigint GENERATED ALWAYS AS IDENTITY,
    operation_pk bigint NOT NULL,
    step_code text COLLATE "C" NOT NULL,
    authority text COLLATE "C" NOT NULL,
    state text COLLATE "C" NOT NULL DEFAULT 'PENDING',
    attempt_count integer NOT NULL DEFAULT 0,
    compensation_state text COLLATE "C" NOT NULL DEFAULT 'NOT_REQUIRED',
    irreversible_boundary_reached boolean NOT NULL DEFAULT false,
    irreversible_boundary_reached_at timestamptz,
    checkpoint_schema_version integer NOT NULL DEFAULT 1,
    checkpoint jsonb NOT NULL DEFAULT '{}'::jsonb,
    next_attempt_at timestamptz,
    result_reference text COLLATE "C",
    result_digest bytea,
    error_code text COLLATE "C",
    error_detail_schema_version integer,
    error_detail jsonb,
    finished_at timestamptz,
    row_version bigint NOT NULL DEFAULT 1,
    created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    created_by_principal_pk bigint,
    updated_by_principal_pk bigint,
    CONSTRAINT ops_operation_steps_pkey PRIMARY KEY (operation_step_pk),
    CONSTRAINT ops_operation_steps_operation_code_key
        UNIQUE (operation_pk, step_code),
    CONSTRAINT ops_operation_steps_operation_fk
        FOREIGN KEY (operation_pk)
        REFERENCES public.ops_operations (operation_pk)
        ON DELETE RESTRICT,
    CONSTRAINT ops_operation_steps_created_by_fk
        FOREIGN KEY (created_by_principal_pk)
        REFERENCES public.iam_principals (principal_pk)
        ON DELETE RESTRICT,
    CONSTRAINT ops_operation_steps_updated_by_fk
        FOREIGN KEY (updated_by_principal_pk)
        REFERENCES public.iam_principals (principal_pk)
        ON DELETE RESTRICT,
    CONSTRAINT ops_operation_steps_step_code_ck
        CHECK (
            pg_catalog.length(step_code) BETWEEN 1 AND 64
            AND step_code ~ '^[A-Z][A-Z0-9_]*$'
        ),
    CONSTRAINT ops_operation_steps_authority_ck
        CHECK (
            pg_catalog.length(authority) BETWEEN 1 AND 128
            AND authority ~ '^[A-Za-z0-9][A-Za-z0-9_.:/-]*$'
        ),
    CONSTRAINT ops_operation_steps_state_ck
        CHECK (
            state IN (
                'PENDING',
                'RUNNING',
                'BLOCKED',
                'SUCCEEDED',
                'FAILED',
                'COMPENSATING',
                'COMPENSATED',
                'SKIPPED'
            )
        ),
    CONSTRAINT ops_operation_steps_attempt_count_ck CHECK (attempt_count >= 0),
    CONSTRAINT ops_operation_steps_compensation_state_ck
        CHECK (
            compensation_state IN (
                'NOT_REQUIRED',
                'AVAILABLE',
                'PENDING',
                'RUNNING',
                'COMPLETED',
                'FAILED'
            )
        ),
    CONSTRAINT ops_operation_steps_irreversible_boundary_ck
        CHECK (
            irreversible_boundary_reached
            = (irreversible_boundary_reached_at IS NOT NULL)
        ),
    CONSTRAINT ops_operation_steps_checkpoint_schema_ck
        CHECK (
            checkpoint_schema_version > 0
            AND pg_catalog.jsonb_typeof(checkpoint) = 'object'
        ),
    CONSTRAINT ops_operation_steps_result_reference_ck
        CHECK (
            result_reference IS NULL
            OR pg_catalog.length(result_reference) BETWEEN 1 AND 1024
        ),
    CONSTRAINT ops_operation_steps_result_digest_ck
        CHECK (
            result_digest IS NULL
            OR pg_catalog.octet_length(result_digest) = 32
        ),
    CONSTRAINT ops_operation_steps_error_code_ck
        CHECK (
            error_code IS NULL
            OR (
                pg_catalog.length(error_code) BETWEEN 1 AND 64
                AND error_code ~ '^[A-Z][A-Z0-9_]*$'
            )
        ),
    CONSTRAINT ops_operation_steps_error_detail_schema_ck
        CHECK (
            (error_detail_schema_version IS NULL AND error_detail IS NULL)
            OR (
                error_detail_schema_version IS NOT NULL
                AND error_detail IS NOT NULL
                AND error_detail_schema_version > 0
                AND pg_catalog.jsonb_typeof(error_detail) = 'object'
            )
        ),
    CONSTRAINT ops_operation_steps_row_version_ck CHECK (row_version > 0),
    CONSTRAINT ops_operation_steps_time_order_ck
        CHECK (
            updated_at >= created_at
            AND (
                irreversible_boundary_reached_at IS NULL
                OR irreversible_boundary_reached_at >= created_at
            )
            AND (next_attempt_at IS NULL OR next_attempt_at >= created_at)
            AND (finished_at IS NULL OR finished_at >= created_at)
        )
);

COMMENT ON TABLE public.ops_operation_steps IS
    'Durable Saga steps, retries, compensation state, and irreversible-boundary evidence; S2/S3.';
COMMENT ON COLUMN public.ops_operation_steps.operation_step_pk IS
    'Internal bigint identity key.';
COMMENT ON COLUMN public.ops_operation_steps.operation_pk IS
    'Owning asynchronous operation.';
COMMENT ON COLUMN public.ops_operation_steps.step_code IS
    'Stable step code unique within an operation.';
COMMENT ON COLUMN public.ops_operation_steps.authority IS
    'Authoritative service or domain responsible for this step.';
COMMENT ON COLUMN public.ops_operation_steps.state IS
    'Current step execution state.';
COMMENT ON COLUMN public.ops_operation_steps.attempt_count IS
    'Number of attempts already started.';
COMMENT ON COLUMN public.ops_operation_steps.compensation_state IS
    'Independent compensation availability and progress.';
COMMENT ON COLUMN public.ops_operation_steps.irreversible_boundary_reached IS
    'True once this step crosses its declared forward-only boundary.';
COMMENT ON COLUMN public.ops_operation_steps.irreversible_boundary_reached_at IS
    'UTC evidence time for crossing the irreversible boundary.';
COMMENT ON COLUMN public.ops_operation_steps.checkpoint_schema_version IS
    'Schema version for the non-core JSON checkpoint.';
COMMENT ON COLUMN public.ops_operation_steps.checkpoint IS
    'Non-core resumable step checkpoint.';
COMMENT ON COLUMN public.ops_operation_steps.next_attempt_at IS
    'UTC earliest retry time.';
COMMENT ON COLUMN public.ops_operation_steps.result_reference IS
    'Opaque safe reference to the step result.';
COMMENT ON COLUMN public.ops_operation_steps.result_digest IS
    'SHA-256-sized integrity digest for the referenced result.';
COMMENT ON COLUMN public.ops_operation_steps.error_code IS
    'Stable, non-sensitive step error code.';
COMMENT ON COLUMN public.ops_operation_steps.error_detail_schema_version IS
    'Schema version for error_detail; NULL when no detail is stored.';
COMMENT ON COLUMN public.ops_operation_steps.error_detail IS
    'Versioned non-sensitive machine detail.';
COMMENT ON COLUMN public.ops_operation_steps.finished_at IS
    'UTC instant at which the current terminal step outcome was recorded.';
COMMENT ON COLUMN public.ops_operation_steps.row_version IS
    'Positive optimistic-concurrency version.';
COMMENT ON COLUMN public.ops_operation_steps.created_at IS
    'UTC creation instant.';
COMMENT ON COLUMN public.ops_operation_steps.updated_at IS
    'UTC last-update instant.';
COMMENT ON COLUMN public.ops_operation_steps.created_by_principal_pk IS
    'Optional actor that created the step.';
COMMENT ON COLUMN public.ops_operation_steps.updated_by_principal_pk IS
    'Optional actor that most recently changed the step.';

CREATE INDEX ops_operation_steps_state_idx
    ON public.ops_operation_steps (operation_pk, state, operation_step_pk);
CREATE INDEX ops_operation_steps_retry_idx
    ON public.ops_operation_steps (next_attempt_at, operation_step_pk)
    WHERE state IN ('PENDING', 'BLOCKED', 'FAILED');
CREATE INDEX ops_operation_steps_created_by_idx
    ON public.ops_operation_steps (created_by_principal_pk)
    WHERE created_by_principal_pk IS NOT NULL;
CREATE INDEX ops_operation_steps_updated_by_idx
    ON public.ops_operation_steps (updated_by_principal_pk)
    WHERE updated_by_principal_pk IS NOT NULL;

CREATE TRIGGER ops_operation_steps_immutable_columns_trg
BEFORE UPDATE ON public.ops_operation_steps
FOR EACH ROW
EXECUTE FUNCTION public.iam_reject_column_changes(
    'operation_step_pk',
    'operation_pk',
    'step_code',
    'authority',
    'created_at'
);

CREATE TRIGGER ops_operation_steps_nondecreasing_version_trg
BEFORE UPDATE ON public.ops_operation_steps
FOR EACH ROW
EXECUTE FUNCTION public.iam_guard_nondecreasing_bigint('row_version');

CREATE TRIGGER ops_operation_steps_irreversible_trg
BEFORE UPDATE ON public.ops_operation_steps
FOR EACH ROW
EXECUTE FUNCTION public.ops_guard_irreversible_boundary();

CREATE TABLE public.ops_idempotency_records (
    idempotency_record_pk bigint GENERATED ALWAYS AS IDENTITY,
    scope text COLLATE "C" NOT NULL,
    key_digest bytea NOT NULL,
    request_hash bytea NOT NULL,
    state text COLLATE "C" NOT NULL DEFAULT 'PROCESSING',
    operation_pk bigint,
    response_http_status integer,
    response_body_digest bytea,
    response_reference text COLLATE "C",
    completed_at timestamptz,
    expires_at timestamptz NOT NULL,
    row_version bigint NOT NULL DEFAULT 1,
    created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    created_by_principal_pk bigint,
    CONSTRAINT ops_idempotency_records_pkey PRIMARY KEY (idempotency_record_pk),
    CONSTRAINT ops_idempotency_records_scope_key UNIQUE (scope, key_digest),
    CONSTRAINT ops_idempotency_records_operation_fk
        FOREIGN KEY (operation_pk)
        REFERENCES public.ops_operations (operation_pk)
        ON DELETE RESTRICT,
    CONSTRAINT ops_idempotency_records_created_by_fk
        FOREIGN KEY (created_by_principal_pk)
        REFERENCES public.iam_principals (principal_pk)
        ON DELETE RESTRICT,
    CONSTRAINT ops_idempotency_records_scope_ck
        CHECK (
            pg_catalog.length(scope) BETWEEN 1 AND 200
            AND scope ~ '^[A-Za-z0-9][A-Za-z0-9_.:/-]*$'
        ),
    CONSTRAINT ops_idempotency_records_key_digest_ck
        CHECK (pg_catalog.octet_length(key_digest) = 32),
    CONSTRAINT ops_idempotency_records_request_hash_ck
        CHECK (pg_catalog.octet_length(request_hash) = 32),
    CONSTRAINT ops_idempotency_records_state_ck
        CHECK (state IN ('PROCESSING', 'COMPLETED', 'FAILED')),
    CONSTRAINT ops_idempotency_records_response_status_ck
        CHECK (
            response_http_status IS NULL
            OR response_http_status BETWEEN 100 AND 599
        ),
    CONSTRAINT ops_idempotency_records_response_digest_ck
        CHECK (
            response_body_digest IS NULL
            OR pg_catalog.octet_length(response_body_digest) = 32
        ),
    CONSTRAINT ops_idempotency_records_response_reference_ck
        CHECK (
            response_reference IS NULL
            OR pg_catalog.length(response_reference) BETWEEN 1 AND 1024
        ),
    CONSTRAINT ops_idempotency_records_completion_state_ck
        CHECK (
            (
                state = 'PROCESSING'
                AND completed_at IS NULL
                AND response_http_status IS NULL
            )
            OR
            (
                state IN ('COMPLETED', 'FAILED')
                AND completed_at IS NOT NULL
                AND response_http_status IS NOT NULL
            )
        ),
    CONSTRAINT ops_idempotency_records_row_version_ck CHECK (row_version > 0),
    CONSTRAINT ops_idempotency_records_time_order_ck
        CHECK (
            updated_at >= created_at
            AND expires_at > created_at
            AND (completed_at IS NULL OR completed_at >= created_at)
        )
);

COMMENT ON TABLE public.ops_idempotency_records IS
    'Ordinary write-API idempotency claims and safe response references; raw keys and response bodies are not stored; S2.';
COMMENT ON COLUMN public.ops_idempotency_records.idempotency_record_pk IS
    'Internal bigint identity key.';
COMMENT ON COLUMN public.ops_idempotency_records.scope IS
    'Stable uniqueness scope including the endpoint and relevant authorization boundary.';
COMMENT ON COLUMN public.ops_idempotency_records.key_digest IS
    'Fixed-length keyed digest of the client idempotency key.';
COMMENT ON COLUMN public.ops_idempotency_records.request_hash IS
    'SHA-256-sized canonical request digest used to detect same-key conflicts.';
COMMENT ON COLUMN public.ops_idempotency_records.state IS
    'Whether processing is in progress or a stable response has been recorded.';
COMMENT ON COLUMN public.ops_idempotency_records.operation_pk IS
    'Optional asynchronous operation returned by this idempotent request.';
COMMENT ON COLUMN public.ops_idempotency_records.response_http_status IS
    'Stable HTTP response status for completed/failed requests.';
COMMENT ON COLUMN public.ops_idempotency_records.response_body_digest IS
    'SHA-256-sized digest of the safely serialized response.';
COMMENT ON COLUMN public.ops_idempotency_records.response_reference IS
    'Opaque safe reference to a response stored elsewhere.';
COMMENT ON COLUMN public.ops_idempotency_records.completed_at IS
    'UTC instant at which the stable response was recorded.';
COMMENT ON COLUMN public.ops_idempotency_records.expires_at IS
    'UTC expiry, not shorter than the maximum client retry window.';
COMMENT ON COLUMN public.ops_idempotency_records.row_version IS
    'Positive optimistic-concurrency version.';
COMMENT ON COLUMN public.ops_idempotency_records.created_at IS
    'UTC claim creation instant.';
COMMENT ON COLUMN public.ops_idempotency_records.updated_at IS
    'UTC last-update instant.';
COMMENT ON COLUMN public.ops_idempotency_records.created_by_principal_pk IS
    'Optional authenticated principal that initiated the request.';

CREATE INDEX ops_idempotency_records_expiry_idx
    ON public.ops_idempotency_records (expires_at, idempotency_record_pk);
CREATE INDEX ops_idempotency_records_operation_idx
    ON public.ops_idempotency_records (operation_pk)
    WHERE operation_pk IS NOT NULL;
CREATE INDEX ops_idempotency_records_created_by_idx
    ON public.ops_idempotency_records (created_by_principal_pk)
    WHERE created_by_principal_pk IS NOT NULL;

CREATE TRIGGER ops_idempotency_records_immutable_columns_trg
BEFORE UPDATE ON public.ops_idempotency_records
FOR EACH ROW
EXECUTE FUNCTION public.iam_reject_column_changes(
    'idempotency_record_pk',
    'scope',
    'key_digest',
    'request_hash',
    'created_at'
);

CREATE TRIGGER ops_idempotency_records_nondecreasing_version_trg
BEFORE UPDATE ON public.ops_idempotency_records
FOR EACH ROW
EXECUTE FUNCTION public.iam_guard_nondecreasing_bigint('row_version');

CREATE TABLE public.iam_user_aliases (
    user_alias_pk bigint GENERATED ALWAYS AS IDENTITY,
    alias_user_id uuid NOT NULL,
    canonical_user_pk bigint NOT NULL,
    reason text COLLATE "C" NOT NULL,
    source_operation_pk bigint,
    created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    created_by_principal_pk bigint,
    CONSTRAINT iam_user_aliases_pkey PRIMARY KEY (user_alias_pk),
    CONSTRAINT iam_user_aliases_alias_user_id_key UNIQUE (alias_user_id),
    CONSTRAINT iam_user_aliases_alias_user_id_v4_ck
        CHECK (public.iam_uuid_is_v4(alias_user_id)),
    CONSTRAINT iam_user_aliases_reason_ck
        CHECK (reason IN ('MERGE', 'MIGRATION', 'CORRECTION')),
    CONSTRAINT iam_user_aliases_canonical_user_fk
        FOREIGN KEY (canonical_user_pk)
        REFERENCES public.iam_users (user_pk)
        ON DELETE RESTRICT,
    CONSTRAINT iam_user_aliases_source_operation_fk
        FOREIGN KEY (source_operation_pk)
        REFERENCES public.ops_operations (operation_pk)
        ON DELETE RESTRICT,
    CONSTRAINT iam_user_aliases_created_by_fk
        FOREIGN KEY (created_by_principal_pk)
        REFERENCES public.iam_principals (principal_pk)
        ON DELETE RESTRICT
);

COMMENT ON TABLE public.iam_user_aliases IS
    'Permanent append-only mapping from retired/historical Global User UUIDs to canonical users; S2.';
COMMENT ON COLUMN public.iam_user_aliases.user_alias_pk IS
    'Internal bigint identity key.';
COMMENT ON COLUMN public.iam_user_aliases.alias_user_id IS
    'Immutable, globally unique historical UUIDv4 that must never be reissued.';
COMMENT ON COLUMN public.iam_user_aliases.canonical_user_pk IS
    'Current canonical Global User; deletion never cascades.';
COMMENT ON COLUMN public.iam_user_aliases.reason IS
    'Controlled reason for preserving the historical mapping.';
COMMENT ON COLUMN public.iam_user_aliases.source_operation_pk IS
    'Optional merge/migration operation that established the mapping.';
COMMENT ON COLUMN public.iam_user_aliases.created_at IS
    'UTC mapping creation instant.';
COMMENT ON COLUMN public.iam_user_aliases.created_by_principal_pk IS
    'Optional actor that established the mapping.';

CREATE INDEX iam_user_aliases_canonical_user_idx
    ON public.iam_user_aliases (canonical_user_pk, user_alias_pk);
CREATE INDEX iam_user_aliases_source_operation_idx
    ON public.iam_user_aliases (source_operation_pk)
    WHERE source_operation_pk IS NOT NULL;
CREATE INDEX iam_user_aliases_created_by_idx
    ON public.iam_user_aliases (created_by_principal_pk)
    WHERE created_by_principal_pk IS NOT NULL;

CREATE FUNCTION public.iam_enforce_user_alias_target()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $function$
DECLARE
    canonical_user_id uuid;
BEGIN
    SELECT user_id
      INTO canonical_user_id
      FROM public.iam_users
     WHERE user_pk = NEW.canonical_user_pk;

    IF NOT FOUND THEN
        RAISE EXCEPTION
            USING
                ERRCODE = '23503',
                MESSAGE = format(
                    'canonical user %s does not exist',
                    NEW.canonical_user_pk
                );
    END IF;

    IF canonical_user_id = NEW.alias_user_id THEN
        RAISE EXCEPTION
            USING
                ERRCODE = '23514',
                MESSAGE = 'a user alias cannot point to the same Global User UUID';
    END IF;

    RETURN NEW;
END
$function$;

COMMENT ON FUNCTION public.iam_enforce_user_alias_target() IS
    'Rejects self-referential historical Global User aliases.';

CREATE TRIGGER iam_user_aliases_target_trg
BEFORE INSERT ON public.iam_user_aliases
FOR EACH ROW
EXECUTE FUNCTION public.iam_enforce_user_alias_target();

CREATE TRIGGER iam_user_aliases_append_only_trg
BEFORE UPDATE OR DELETE ON public.iam_user_aliases
FOR EACH ROW
EXECUTE FUNCTION public.iam_reject_row_mutation();

COMMIT;
