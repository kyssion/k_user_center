-- Cross-domain invariants and security-critical transaction functions.
-- PostgreSQL 16+, public schema only, no extension dependency.

BEGIN;

-- Generic terminal-state and monotonic-value guards.
CREATE FUNCTION public.iam_guard_terminal_state()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $function$
DECLARE
    old_state text := pg_catalog.to_jsonb(OLD) ->> TG_ARGV[0];
    new_state text := pg_catalog.to_jsonb(NEW) ->> TG_ARGV[0];
    terminal_state text;
BEGIN
    FOREACH terminal_state IN ARRAY TG_ARGV[1:TG_NARGS - 1] LOOP
        IF old_state = terminal_state AND new_state IS DISTINCT FROM old_state THEN
            RAISE EXCEPTION USING
                ERRCODE = '23514',
                MESSAGE = pg_catalog.format(
                    '%I.%I state %s is terminal',
                    TG_TABLE_NAME, TG_ARGV[0], old_state
                );
        END IF;
    END LOOP;
    RETURN NEW;
END
$function$;

COMMENT ON FUNCTION public.iam_guard_terminal_state() IS
    'Rejects recovery from terminal states named in trigger arguments.';

CREATE TRIGGER iam_users_anonymized_terminal_trg
BEFORE UPDATE ON public.iam_users
FOR EACH ROW EXECUTE FUNCTION public.iam_guard_terminal_state(
    'lifecycle_state', 'ANONYMIZED'
);

CREATE TRIGGER iam_identifiers_terminal_trg
BEFORE UPDATE ON public.iam_identifiers
FOR EACH ROW EXECUTE FUNCTION public.iam_guard_terminal_state(
    'state', 'ANONYMIZED'
);

CREATE TRIGGER iam_identity_bindings_terminal_trg
BEFORE UPDATE ON public.iam_identity_bindings
FOR EACH ROW EXECUTE FUNCTION public.iam_guard_terminal_state(
    'binding_state', 'UNBOUND', 'REPLACED', 'DISPUTED'
);

CREATE TRIGGER org_tenants_closed_terminal_trg
BEFORE UPDATE ON public.org_tenants
FOR EACH ROW EXECUTE FUNCTION public.iam_guard_terminal_state(
    'status', 'CLOSED'
);

CREATE TRIGGER org_memberships_terminal_trg
BEFORE UPDATE ON public.org_memberships
FOR EACH ROW EXECUTE FUNCTION public.iam_guard_terminal_state(
    'state', 'LEFT', 'REJECTED', 'EXPIRED'
);

CREATE TRIGGER auth_authenticators_terminal_trg
BEFORE UPDATE ON public.auth_authenticators
FOR EACH ROW EXECUTE FUNCTION public.iam_guard_terminal_state(
    'state', 'EXPIRED', 'COMPROMISED', 'REVOKED', 'REPLACED'
);

CREATE TRIGGER priv_consents_terminal_trg
BEFORE UPDATE ON public.priv_consents
FOR EACH ROW EXECUTE FUNCTION public.iam_guard_terminal_state(
    'status', 'WITHDRAWN', 'EXPIRED', 'SUPERSEDED'
);

CREATE TRIGGER app_clients_retired_terminal_trg
BEFORE UPDATE ON public.app_clients
FOR EACH ROW EXECUTE FUNCTION public.iam_guard_terminal_state(
    'status', 'RETIRED'
);

CREATE TRIGGER app_machine_principals_retired_terminal_trg
BEFORE UPDATE ON public.app_machine_principals
FOR EACH ROW EXECUTE FUNCTION public.iam_guard_terminal_state(
    'status', 'RETIRED'
);

CREATE TRIGGER app_clients_versions_trg
BEFORE UPDATE ON public.app_clients
FOR EACH ROW EXECUTE FUNCTION public.iam_guard_nondecreasing_bigint(
    'security_epoch', 'row_version'
);

CREATE TRIGGER org_tenants_versions_trg
BEFORE UPDATE ON public.org_tenants
FOR EACH ROW EXECUTE FUNCTION public.iam_guard_nondecreasing_bigint(
    'security_epoch', 'row_version'
);

CREATE TRIGGER app_machine_principals_versions_trg
BEFORE UPDATE ON public.app_machine_principals
FOR EACH ROW EXECUTE FUNCTION public.iam_guard_nondecreasing_bigint(
    'security_epoch', 'row_version'
);

CREATE TRIGGER iam_identities_version_trg
BEFORE UPDATE ON public.iam_identities
FOR EACH ROW EXECUTE FUNCTION public.iam_guard_nondecreasing_bigint(
    'row_version'
);

CREATE TRIGGER iam_identifiers_version_trg
BEFORE UPDATE ON public.iam_identifiers
FOR EACH ROW EXECUTE FUNCTION public.iam_guard_nondecreasing_bigint(
    'row_version'
);

CREATE TRIGGER org_organizations_versions_trg
BEFORE UPDATE ON public.org_organizations
FOR EACH ROW EXECUTE FUNCTION public.iam_guard_nondecreasing_bigint(
    'hierarchy_version', 'row_version'
);

CREATE TRIGGER org_memberships_version_trg
BEFORE UPDATE ON public.org_memberships
FOR EACH ROW EXECUTE FUNCTION public.iam_guard_nondecreasing_bigint(
    'row_version'
);

CREATE TRIGGER auth_authenticators_version_trg
BEFORE UPDATE ON public.auth_authenticators
FOR EACH ROW EXECUTE FUNCTION public.iam_guard_nondecreasing_bigint(
    'row_version'
);

CREATE TRIGGER auth_transactions_version_trg
BEFORE UPDATE ON public.auth_transactions
FOR EACH ROW EXECUTE FUNCTION public.iam_guard_nondecreasing_bigint(
    'row_version'
);

CREATE TRIGGER auth_challenges_version_trg
BEFORE UPDATE ON public.auth_challenges
FOR EACH ROW EXECUTE FUNCTION public.iam_guard_nondecreasing_bigint(
    'row_version'
);

CREATE TRIGGER oauth_sessions_version_trg
BEFORE UPDATE ON public.oauth_sessions
FOR EACH ROW EXECUTE FUNCTION public.iam_guard_nondecreasing_bigint(
    'row_version'
);

CREATE TRIGGER oauth_grants_version_trg
BEFORE UPDATE ON public.oauth_grants
FOR EACH ROW EXECUTE FUNCTION public.iam_guard_nondecreasing_bigint(
    'row_version'
);

CREATE TRIGGER oauth_token_families_version_trg
BEFORE UPDATE ON public.oauth_token_families
FOR EACH ROW EXECUTE FUNCTION public.iam_guard_nondecreasing_bigint(
    'rotation_counter', 'row_version'
);

CREATE TRIGGER priv_privacy_requests_version_trg
BEFORE UPDATE ON public.priv_privacy_requests
FOR EACH ROW EXECUTE FUNCTION public.iam_guard_nondecreasing_bigint(
    'row_version'
);

CREATE TRIGGER priv_legal_holds_version_trg
BEFORE UPDATE ON public.priv_legal_holds
FOR EACH ROW EXECUTE FUNCTION public.iam_guard_nondecreasing_bigint(
    'row_version'
);

CREATE TRIGGER key_crypto_keys_version_trg
BEFORE UPDATE ON public.key_crypto_keys
FOR EACH ROW EXECUTE FUNCTION public.iam_guard_nondecreasing_bigint(
    'row_version'
);

CREATE TRIGGER fed_directory_sources_versions_trg
BEFORE UPDATE ON public.fed_directory_sources
FOR EACH ROW EXECUTE FUNCTION public.iam_guard_nondecreasing_bigint(
    'source_epoch', 'row_version'
);

CREATE TRIGGER oauth_revocation_watermarks_versions_trg
BEFORE UPDATE ON public.oauth_revocation_watermarks
FOR EACH ROW EXECUTE FUNCTION public.iam_guard_nondecreasing_bigint(
    'revocation_epoch', 'row_version'
);

CREATE TRIGGER authz_policy_sets_versions_trg
BEFORE UPDATE ON public.authz_policy_sets
FOR EACH ROW EXECUTE FUNCTION public.iam_guard_nondecreasing_bigint(
    'row_version'
);

CREATE TRIGGER authz_policy_versions_number_immutable_trg
BEFORE UPDATE ON public.authz_policy_versions
FOR EACH ROW EXECUTE FUNCTION public.iam_reject_column_changes(
    'policy_version_pk', 'policy_version_id', 'policy_set_pk', 'version_no',
    'created_at'
);

CREATE TRIGGER auth_challenges_terminal_trg
BEFORE UPDATE ON public.auth_challenges
FOR EACH ROW EXECUTE FUNCTION public.iam_guard_terminal_state(
    'state', 'CONSUMED', 'EXPIRED', 'LOCKED', 'CANCELLED'
);

CREATE TRIGGER oauth_sessions_terminal_trg
BEFORE UPDATE ON public.oauth_sessions
FOR EACH ROW EXECUTE FUNCTION public.iam_guard_terminal_state(
    'state', 'EXPIRED', 'REVOKED'
);

CREATE TRIGGER oauth_grants_terminal_trg
BEFORE UPDATE ON public.oauth_grants
FOR EACH ROW EXECUTE FUNCTION public.iam_guard_terminal_state(
    'state', 'REVOKED', 'EXPIRED'
);

CREATE TRIGGER oauth_token_families_terminal_trg
BEFORE UPDATE ON public.oauth_token_families
FOR EACH ROW EXECUTE FUNCTION public.iam_guard_terminal_state(
    'state', 'REVOKED', 'EXPIRED'
);

CREATE TRIGGER iam_users_no_delete_trg
BEFORE DELETE ON public.iam_users
FOR EACH ROW EXECUTE FUNCTION public.iam_reject_row_mutation();

CREATE TRIGGER iam_identifiers_no_delete_trg
BEFORE DELETE ON public.iam_identifiers
FOR EACH ROW EXECUTE FUNCTION public.iam_reject_row_mutation();

CREATE TRIGGER iam_identity_bindings_no_delete_trg
BEFORE DELETE ON public.iam_identity_bindings
FOR EACH ROW EXECUTE FUNCTION public.iam_reject_row_mutation();

CREATE TRIGGER org_tenants_no_delete_trg
BEFORE DELETE ON public.org_tenants
FOR EACH ROW EXECUTE FUNCTION public.iam_reject_row_mutation();

CREATE TRIGGER org_memberships_no_delete_trg
BEFORE DELETE ON public.org_memberships
FOR EACH ROW EXECUTE FUNCTION public.iam_reject_row_mutation();

CREATE TRIGGER auth_authenticators_no_delete_trg
BEFORE DELETE ON public.auth_authenticators
FOR EACH ROW EXECUTE FUNCTION public.iam_reject_row_mutation();

CREATE TRIGGER fed_directory_objects_no_delete_trg
BEFORE DELETE ON public.fed_directory_objects
FOR EACH ROW EXECUTE FUNCTION public.iam_reject_row_mutation();

CREATE UNIQUE INDEX oauth_refresh_tokens_successor_uidx
    ON public.oauth_refresh_tokens (successor_refresh_token_pk)
    WHERE successor_refresh_token_pk IS NOT NULL;

-- Shared-PK extensions are mutually exclusive and must match the immutable
-- principal type. Locking the principal row serializes concurrent attempts to
-- create USER and MACHINE extensions for the same principal.
CREATE FUNCTION public.iam_guard_principal_extension()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $function$
DECLARE
    expected_type text := TG_ARGV[0];
    actual_type text;
    extension_pk bigint := CASE expected_type
        WHEN 'USER' THEN (pg_catalog.to_jsonb(NEW) ->> 'user_pk')::bigint
        WHEN 'MACHINE' THEN (pg_catalog.to_jsonb(NEW) ->> 'machine_pk')::bigint
        ELSE NULL
    END;
BEGIN
    SELECT p.principal_type
      INTO actual_type
      FROM public.iam_principals AS p
     WHERE p.principal_pk = extension_pk
     FOR UPDATE;

    IF actual_type IS DISTINCT FROM expected_type THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = pg_catalog.format(
                '%s extension requires principal_type %s',
                expected_type, expected_type
            );
    END IF;

    IF expected_type = 'USER' AND EXISTS (
        SELECT 1
          FROM public.app_machine_principals AS m
         WHERE m.machine_pk = extension_pk
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'a principal cannot extend both iam_users and app_machine_principals';
    ELSIF expected_type = 'MACHINE' AND EXISTS (
        SELECT 1
          FROM public.iam_users AS u
         WHERE u.user_pk = extension_pk
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'a principal cannot extend both iam_users and app_machine_principals';
    END IF;

    RETURN NEW;
END
$function$;

CREATE TRIGGER iam_users_principal_type_trg
BEFORE INSERT OR UPDATE ON public.iam_users
FOR EACH ROW EXECUTE FUNCTION public.iam_guard_principal_extension('USER');

CREATE TRIGGER app_machine_principals_principal_type_trg
BEFORE INSERT OR UPDATE ON public.app_machine_principals
FOR EACH ROW EXECUTE FUNCTION public.iam_guard_principal_extension('MACHINE');

-- Session rows have one of two explicit shapes. USER sessions must agree with
-- the shared principal/user key, authentication context, and optional device.
-- MACHINE sessions are supported without a human authentication context.
CREATE FUNCTION public.oauth_guard_session_subject()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $function$
DECLARE
    session_principal_type text;
    context_user_pk bigint;
    device_principal_pk bigint;
BEGIN
    SELECT p.principal_type
      INTO session_principal_type
      FROM public.iam_principals AS p
     WHERE p.principal_pk = NEW.principal_pk
     FOR KEY SHARE;

    IF session_principal_type = 'USER' THEN
        IF NEW.user_pk IS DISTINCT FROM NEW.principal_pk
           OR NEW.auth_context_pk IS NULL THEN
            RAISE EXCEPTION USING
                ERRCODE = '23514',
                MESSAGE = 'USER session principal_pk, user_pk, and auth_context must identify one user';
        END IF;

        SELECT c.user_pk
          INTO context_user_pk
          FROM public.auth_contexts AS c
         WHERE c.auth_context_pk = NEW.auth_context_pk
         FOR KEY SHARE;
        IF context_user_pk IS DISTINCT FROM NEW.user_pk THEN
            RAISE EXCEPTION USING
                ERRCODE = '23514',
                MESSAGE = 'session auth_context user does not match session user';
        END IF;
    ELSIF session_principal_type = 'MACHINE' THEN
        IF NEW.user_pk IS NOT NULL OR NEW.auth_context_pk IS NOT NULL THEN
            RAISE EXCEPTION USING
                ERRCODE = '23514',
                MESSAGE = 'MACHINE session cannot carry user_pk or auth_context_pk';
        END IF;
    ELSE
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'session principal must have type USER or MACHINE';
    END IF;

    IF NEW.device_pk IS NOT NULL THEN
        SELECT d.principal_pk
          INTO device_principal_pk
          FROM public.oauth_devices AS d
         WHERE d.device_pk = NEW.device_pk
         FOR KEY SHARE;
        IF device_principal_pk IS DISTINCT FROM NEW.principal_pk THEN
            RAISE EXCEPTION USING
                ERRCODE = '23514',
                MESSAGE = 'session device owner does not match session principal';
        END IF;
    END IF;

    RETURN NEW;
END
$function$;

CREATE TRIGGER oauth_sessions_subject_guard_trg
BEFORE INSERT OR UPDATE OF principal_pk, user_pk, auth_context_pk, device_pk
ON public.oauth_sessions
FOR EACH ROW EXECUTE FUNCTION public.oauth_guard_session_subject();

-- The target and its tenant scope are separate concepts. NULL scope denotes a
-- platform-global target and is inaccessible to ordinary tenant-scoped roles.
ALTER TABLE public.risk_signal_targets
    ADD COLUMN scope_tenant_pk bigint,
    ADD CONSTRAINT risk_signal_targets_scope_tenant_fk
        FOREIGN KEY (scope_tenant_pk)
        REFERENCES public.org_tenants (tenant_pk) ON DELETE RESTRICT,
    ADD CONSTRAINT risk_signal_targets_tenant_scope_ck CHECK (
        target_type <> 'TENANT'
        OR (scope_tenant_pk IS NOT NULL AND scope_tenant_pk = tenant_pk)
    );

CREATE INDEX risk_signal_targets_scope_tenant_idx
    ON public.risk_signal_targets (scope_tenant_pk, risk_signal_pk)
    WHERE scope_tenant_pk IS NOT NULL;

COMMENT ON COLUMN public.risk_signal_targets.scope_tenant_pk IS
    'RLS ownership scope. NULL is platform-global and requires iam_platform/BYPASSRLS; it is not a tenant-client bypass.';

-- Identifier blind-index shape and forward-only retirement.
CREATE FUNCTION public.iam_guard_identifier_blind_index()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $function$
DECLARE
    identifier_kind text;
    identifier_normalization integer;
BEGIN
    SELECT i.kind, i.normalization_version
      INTO identifier_kind, identifier_normalization
      FROM public.iam_identifiers AS i
     WHERE i.identifier_pk = NEW.identifier_pk
     FOR KEY SHARE;

    IF identifier_kind IS NULL
       OR NEW.kind <> identifier_kind
       OR NEW.normalization_version <> identifier_normalization THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'blind index kind and normalization version must match its Identifier';
    END IF;

    IF TG_OP = 'UPDATE' AND NOT OLD.is_active AND NEW.is_active THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'a retired blind index cannot be reactivated';
    END IF;

    RETURN NEW;
END
$function$;

CREATE TRIGGER iam_identifier_blind_indexes_guard_trg
BEFORE INSERT OR UPDATE ON public.iam_identifier_blind_indexes
FOR EACH ROW EXECUTE FUNCTION public.iam_guard_identifier_blind_index();

CREATE TRIGGER iam_identifier_tombstones_append_only_trg
BEFORE UPDATE OR DELETE ON public.iam_identifier_tombstones
FOR EACH ROW EXECUTE FUNCTION public.iam_reject_row_mutation();

-- SCIM/API source versions and disable tombstones are forward-only.
CREATE FUNCTION public.fed_guard_directory_object_version()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $function$
BEGIN
    IF NEW.source_version < OLD.source_version
       OR NEW.row_version < OLD.row_version THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'directory source_version and row_version must not decrease';
    END IF;

    IF OLD.state IN ('DISABLED', 'TOMBSTONED')
       AND (
           NEW.state IS DISTINCT FROM OLD.state
           OR NEW.disabled_source_version IS DISTINCT FROM OLD.disabled_source_version
           OR NEW.disabled_at IS DISTINCT FROM OLD.disabled_at
       ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'a directory disable tombstone cannot be removed or rewritten';
    END IF;

    RETURN NEW;
END
$function$;

CREATE TRIGGER fed_directory_objects_forward_only_trg
BEFORE UPDATE ON public.fed_directory_objects
FOR EACH ROW EXECUTE FUNCTION public.fed_guard_directory_object_version();

-- Organization hierarchy cycle prevention. Locking the tenant tree prevents
-- concurrent A->B/B->A write skew under READ COMMITTED.
CREATE FUNCTION public.org_guard_organization_cycle()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $function$
DECLARE
    cycle_found boolean;
BEGIN
    IF NEW.parent_organization_pk IS NULL THEN
        RETURN NEW;
    END IF;

    PERFORM 1
      FROM public.org_organizations AS lock_row
     WHERE lock_row.tenant_pk = NEW.tenant_pk
     ORDER BY lock_row.organization_pk
     FOR UPDATE;

    WITH RECURSIVE ancestors(
        organization_pk, parent_organization_pk, visited
    ) AS (
        SELECT o.organization_pk, o.parent_organization_pk,
               ARRAY[o.organization_pk]::bigint[]
          FROM public.org_organizations AS o
         WHERE o.tenant_pk = NEW.tenant_pk
           AND o.organization_pk = NEW.parent_organization_pk
        UNION ALL
        SELECT o.organization_pk, o.parent_organization_pk,
               a.visited || o.organization_pk
          FROM public.org_organizations AS o
          JOIN ancestors AS a
            ON o.organization_pk = a.parent_organization_pk
         WHERE o.tenant_pk = NEW.tenant_pk
           AND NOT o.organization_pk = ANY (a.visited)
    )
    SELECT pg_catalog.bool_or(organization_pk = NEW.organization_pk)
      INTO cycle_found
      FROM ancestors;

    IF pg_catalog.coalesce(cycle_found, false) THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'organization hierarchy cycle detected';
    END IF;
    RETURN NEW;
END
$function$;

CREATE TRIGGER org_organizations_cycle_trg
BEFORE INSERT OR UPDATE OF tenant_pk, parent_organization_pk
ON public.org_organizations
FOR EACH ROW EXECUTE FUNCTION public.org_guard_organization_cycle();

-- Append-only audit and an in-database SHA-256 chain. A per-scope advisory
-- transaction lock serializes sequence assignment across monthly partitions.
CREATE FUNCTION public.audit_append_event(
    p_occurred_at timestamptz,
    p_event_category text,
    p_action_code text,
    p_actor_type text,
    p_actor_principal_pk bigint,
    p_actor_reference_digest bytea,
    p_subject_principal_pk bigint,
    p_tenant_pk bigint,
    p_source_service text,
    p_source_ip inet,
    p_object_type text,
    p_object_id uuid,
    p_object_reference_digest bytea,
    p_before_digest bytea,
    p_after_digest bytea,
    p_reason_code text,
    p_approval_reference text,
    p_result text,
    p_error_code text,
    p_policy_release_id uuid,
    p_trace_id uuid,
    p_correlation_id uuid,
    p_chain_scope text,
    p_canonical_event_hash bytea,
    p_detail_schema_version integer,
    p_detail jsonb
)
RETURNS uuid
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $function$
DECLARE
    new_event_id uuid := pg_catalog.gen_random_uuid();
    previous_hash bytea;
    next_sequence bigint;
    new_chain_hash bytea;
BEGIN
    IF pg_catalog.octet_length(p_canonical_event_hash) <> 32 THEN
        RAISE EXCEPTION USING ERRCODE = '22023',
            MESSAGE = 'canonical audit event hash must be 32 bytes';
    END IF;

    PERFORM pg_catalog.pg_advisory_xact_lock(
        pg_catalog.hashtextextended(p_chain_scope, 110)
    );

    SELECT ae.chain_sequence, ae.chain_hash
      INTO next_sequence, previous_hash
      FROM public.audit_events AS ae
     WHERE ae.chain_scope = p_chain_scope
     ORDER BY ae.chain_sequence DESC
     LIMIT 1;

    next_sequence := pg_catalog.coalesce(next_sequence, 0) + 1;
    new_chain_hash := pg_catalog.sha256(
        pg_catalog.coalesce(previous_hash, ''::bytea) || p_canonical_event_hash
    );

    INSERT INTO public.audit_events (
        occurred_at, event_id, event_category, action_code, actor_type,
        actor_principal_pk, actor_reference_digest, subject_principal_pk,
        tenant_pk, source_service, source_ip, object_type, object_id,
        object_reference_digest, before_digest, after_digest, reason_code,
        approval_reference, result, error_code, policy_release_id, trace_id,
        correlation_id, chain_scope, chain_sequence, previous_chain_hash,
        canonical_event_hash, chain_hash, detail_schema_version, detail
    ) VALUES (
        p_occurred_at, new_event_id, p_event_category, p_action_code, p_actor_type,
        p_actor_principal_pk, p_actor_reference_digest, p_subject_principal_pk,
        p_tenant_pk, p_source_service, p_source_ip, p_object_type, p_object_id,
        p_object_reference_digest, p_before_digest, p_after_digest, p_reason_code,
        p_approval_reference, p_result, p_error_code, p_policy_release_id,
        p_trace_id, p_correlation_id, p_chain_scope, next_sequence, previous_hash,
        p_canonical_event_hash, new_chain_hash, p_detail_schema_version, p_detail
    );
    RETURN new_event_id;
END
$function$;

COMMENT ON FUNCTION public.audit_append_event(
    timestamptz, text, text, text, bigint, bytea, bigint, bigint, text, inet,
    text, uuid, bytea, bytea, bytea, text, text, text, text, uuid, uuid, uuid,
    text, bytea, integer, jsonb
) IS
    'Serializes a per-scope SHA-256 audit chain and appends one partition-routed event. Canonicalization and optional signing occur in trusted application/KMS code; external WORM checkpoints remain mandatory.';

CREATE TRIGGER audit_events_append_only_trg
BEFORE UPDATE OR DELETE ON public.audit_events
FOR EACH ROW EXECUTE FUNCTION public.iam_reject_row_mutation();

-- Atomic Identifier binding. Unique partial indexes remain the final
-- concurrency arbiter for both active blind values and active bindings.
CREATE FUNCTION public.iam_bind_identifier(
    p_identity_pk bigint,
    p_identifier_pk bigint,
    p_expected_user_row_version bigint,
    p_verification_evidence_digest bytea,
    p_actor_principal_pk bigint,
    p_trace_id uuid
)
RETURNS bigint
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $function$
DECLARE
    target_user public.iam_users%ROWTYPE;
    identity_user_pk bigint;
    identifier_row public.iam_identifiers%ROWTYPE;
    new_binding_pk bigint;
    new_identifier_version bigint;
    payload jsonb;
BEGIN
    SELECT i.user_pk
      INTO identity_user_pk
      FROM public.iam_identities AS i
     WHERE i.identity_pk = p_identity_pk
       AND i.state IN ('PENDING', 'VERIFIED')
     FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = 'P0002',
            MESSAGE = 'eligible identity not found';
    END IF;

    SELECT * INTO target_user
      FROM public.iam_users AS u
     WHERE u.user_pk = identity_user_pk
     FOR UPDATE;
    IF target_user.row_version <> p_expected_user_row_version THEN
        RAISE EXCEPTION USING ERRCODE = '40001',
            MESSAGE = 'user version conflict';
    END IF;
    IF target_user.lifecycle_state = 'ANONYMIZED'
       OR target_user.freeze_state = 'FROZEN' THEN
        RAISE EXCEPTION USING ERRCODE = '55000',
            MESSAGE = 'user is not eligible for identifier binding';
    END IF;

    SELECT * INTO identifier_row
      FROM public.iam_identifiers AS i
     WHERE i.identifier_pk = p_identifier_pk
     FOR UPDATE;
    IF NOT FOUND OR identifier_row.state <> 'ACTIVE' THEN
        RAISE EXCEPTION USING ERRCODE = '55000',
            MESSAGE = 'identifier is not active';
    END IF;
    IF identifier_row.rebind_not_before IS NOT NULL
       AND identifier_row.rebind_not_before > pg_catalog.clock_timestamp() THEN
        RAISE EXCEPTION USING ERRCODE = '55000',
            MESSAGE = 'identifier is still quarantined';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM public.iam_identifier_blind_indexes AS bi
         WHERE bi.identifier_pk = p_identifier_pk AND bi.is_active
    ) THEN
        RAISE EXCEPTION USING ERRCODE = '23514',
            MESSAGE = 'identifier has no active blind index';
    END IF;
    IF EXISTS (
        SELECT 1
          FROM public.iam_identifier_blind_indexes AS bi
          JOIN public.iam_identifier_tombstones AS t
            ON t.scope_type = bi.scope_type
           AND t.scope_pk = bi.scope_pk
           AND t.kind = bi.kind
           AND t.normalization_version = bi.normalization_version
           AND t.blind_index_key_version = bi.blind_index_key_version
           AND t.blind_index = bi.blind_index
         WHERE bi.identifier_pk = p_identifier_pk
           AND bi.is_active
           AND (t.reusable_after IS NULL
                OR t.reusable_after > pg_catalog.clock_timestamp())
    ) THEN
        RAISE EXCEPTION USING ERRCODE = '55000',
            MESSAGE = 'identifier is protected by a reuse tombstone';
    END IF;

    INSERT INTO public.iam_identity_bindings (
        identity_pk, identifier_pk, verification_evidence_digest,
        created_by_principal_pk
    ) VALUES (
        p_identity_pk, p_identifier_pk, p_verification_evidence_digest,
        p_actor_principal_pk
    )
    RETURNING identity_binding_pk INTO new_binding_pk;

    UPDATE public.iam_identifiers
       SET row_version = row_version + 1,
           updated_at = pg_catalog.clock_timestamp(),
           verified_at = pg_catalog.coalesce(verified_at, pg_catalog.clock_timestamp())
     WHERE identifier_pk = p_identifier_pk
     RETURNING row_version INTO new_identifier_version;

    payload := pg_catalog.jsonb_build_object(
        'identifier_id', identifier_row.identifier_id,
        'binding_id', new_binding_pk
    );
    INSERT INTO public.evt_outbox (
        event_type, schema_version, producer_principal_pk, aggregate_type,
        aggregate_id, aggregate_version, subject_principal_pk, trace_id,
        data_classification, payload, payload_hash, occurred_at
    ) VALUES (
        'iam.identifier.bound', 1, p_actor_principal_pk, 'IAM_IDENTIFIER',
        identifier_row.identifier_id, new_identifier_version, identity_user_pk,
        p_trace_id, 'S2', payload,
        pg_catalog.sha256(pg_catalog.convert_to(payload::text, 'UTF8')),
        pg_catalog.clock_timestamp()
    );
    PERFORM public.audit_append_event(
        pg_catalog.clock_timestamp(), 'ADMINISTRATION', 'IAM.IDENTIFIER.BIND',
        'PRINCIPAL', p_actor_principal_pk, NULL, identity_user_pk, NULL,
        'iam-identity', NULL, 'IAM_IDENTIFIER',
        identifier_row.identifier_id, NULL, NULL,
        p_verification_evidence_digest, 'IDENTIFIER_VERIFIED', NULL,
        'SUCCEEDED', NULL, NULL, p_trace_id, NULL,
        'IAM_IDENTIFIER:' || identifier_row.identifier_id::text,
        pg_catalog.sha256(pg_catalog.convert_to(
            identifier_row.identifier_id::text || ':' ||
            new_identifier_version::text,
            'UTF8'
        )),
        1, payload
    );
    RETURN new_binding_pk;
END
$function$;

-- Challenge consumption is distinct from verification and checks the complete
-- transaction/purpose/Client/user/binding tuple under row locks and CAS.
CREATE FUNCTION public.auth_consume_challenge(
    p_challenge_id uuid,
    p_expected_row_version bigint,
    p_transaction_id uuid,
    p_purpose text,
    p_client_id uuid,
    p_user_id uuid,
    p_binding_digest bytea
)
RETURNS text
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $function$
DECLARE
    challenge_row public.auth_challenges%ROWTYPE;
    transaction_row public.auth_transactions%ROWTYPE;
    expected_client_pk bigint;
    expected_user_pk bigint;
BEGIN
    IF p_purpose IS NULL
       OR p_binding_digest IS NULL
       OR pg_catalog.octet_length(p_binding_digest) <> 32 THEN
        RETURN 'BINDING_MISMATCH';
    END IF;

    SELECT c.* INTO challenge_row
      FROM public.auth_challenges AS c
     WHERE c.challenge_id = p_challenge_id
     FOR UPDATE;
    IF NOT FOUND THEN RETURN 'NOT_FOUND'; END IF;

    SELECT t.* INTO transaction_row
      FROM public.auth_transactions AS t
     WHERE t.transaction_pk = challenge_row.transaction_pk
       AND t.transaction_id = p_transaction_id
     FOR UPDATE;
    IF NOT FOUND THEN RETURN 'BINDING_MISMATCH'; END IF;

    IF p_client_id IS NOT NULL THEN
        SELECT c.client_pk INTO expected_client_pk
          FROM public.app_clients AS c
         WHERE c.client_id = p_client_id;
        IF NOT FOUND THEN RETURN 'BINDING_MISMATCH'; END IF;
    END IF;
    IF p_user_id IS NOT NULL THEN
        SELECT u.user_pk INTO expected_user_pk
          FROM public.iam_users AS u
         WHERE u.user_id = p_user_id;
        IF NOT FOUND THEN RETURN 'BINDING_MISMATCH'; END IF;
    END IF;

    IF challenge_row.row_version <> p_expected_row_version THEN
        RETURN 'VERSION_CONFLICT';
    END IF;
    IF challenge_row.state = 'CONSUMED' THEN RETURN 'ALREADY_CONSUMED'; END IF;
    IF challenge_row.state <> 'VERIFIED' THEN RETURN 'INVALID_STATE'; END IF;
    IF challenge_row.expires_at <= pg_catalog.clock_timestamp()
       OR transaction_row.expires_at <= pg_catalog.clock_timestamp() THEN
        RETURN 'EXPIRED';
    END IF;
    IF challenge_row.purpose IS DISTINCT FROM p_purpose
       OR transaction_row.purpose IS DISTINCT FROM p_purpose
       OR challenge_row.client_pk IS DISTINCT FROM expected_client_pk
       OR transaction_row.client_pk IS DISTINCT FROM expected_client_pk
       OR challenge_row.user_pk IS DISTINCT FROM expected_user_pk
       OR transaction_row.user_pk IS DISTINCT FROM expected_user_pk
       OR challenge_row.binding_digest IS DISTINCT FROM p_binding_digest
       OR transaction_row.binding_digest IS DISTINCT FROM p_binding_digest THEN
        RETURN 'BINDING_MISMATCH';
    END IF;

    UPDATE public.auth_challenges
       SET state = 'CONSUMED',
           consumed_at = pg_catalog.clock_timestamp(),
           row_version = row_version + 1
     WHERE challenge_pk = challenge_row.challenge_pk
       AND state = 'VERIFIED'
       AND row_version = p_expected_row_version;
    IF NOT FOUND THEN RETURN 'VERSION_CONFLICT'; END IF;
    RETURN 'CONSUMED';
END
$function$;

-- Refresh-token rotation result. A bounded matching retry returns the existing
-- successor evidence; any other reuse compromises and revokes the whole family.
CREATE FUNCTION public.oauth_rotate_refresh_token(
    p_token_digest bytea,
    p_new_token_id uuid,
    p_new_token_digest bytea,
    p_new_pepper_key_ref text,
    p_new_pepper_key_version integer,
    p_new_expires_at timestamptz,
    p_retry_binding_digest bytea,
    p_retry_result_digest bytea,
    p_retry_until timestamptz
)
RETURNS TABLE (
    result_code text,
    successor_token_id uuid,
    result_digest bytea
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $function$
DECLARE
    token_row public.oauth_refresh_tokens%ROWTYPE;
    family_row public.oauth_token_families%ROWTYPE;
    grant_row public.oauth_grants%ROWTYPE;
    client_row public.app_clients%ROWTYPE;
    user_row public.iam_users%ROWTYPE;
    tenant_row public.org_tenants%ROWTYPE;
    successor_pk bigint;
BEGIN
    SELECT rt.* INTO token_row
      FROM public.oauth_refresh_tokens AS rt
     WHERE rt.token_digest = p_token_digest
     FOR UPDATE;
    IF NOT FOUND THEN
        RETURN QUERY SELECT 'NOT_FOUND'::text, NULL::uuid, NULL::bytea;
        RETURN;
    END IF;

    SELECT f.* INTO family_row
      FROM public.oauth_token_families AS f
     WHERE f.token_family_pk = token_row.token_family_pk
     FOR UPDATE;

    IF token_row.state = 'USED' THEN
        IF family_row.state <> 'ACTIVE' THEN
            RETURN QUERY SELECT 'INACTIVE'::text, NULL::uuid, NULL::bytea;
            RETURN;
        END IF;
        IF token_row.retry_binding_digest = p_retry_binding_digest
           AND token_row.retry_until >= pg_catalog.clock_timestamp() THEN
            RETURN QUERY
            SELECT 'RETRY'::text, rt.refresh_token_id, token_row.retry_result_digest
              FROM public.oauth_refresh_tokens AS rt
             WHERE rt.refresh_token_pk = token_row.successor_refresh_token_pk;
            RETURN;
        END IF;

        UPDATE public.oauth_token_families
           SET state = 'COMPROMISED',
               compromised_at = pg_catalog.clock_timestamp(),
               row_version = row_version + 1
         WHERE token_family_pk = family_row.token_family_pk
           AND state <> 'COMPROMISED';
        UPDATE public.oauth_refresh_tokens
           SET state = 'REVOKED'
         WHERE token_family_pk = family_row.token_family_pk
           AND state = 'CURRENT';
        RETURN QUERY SELECT 'REPLAY_COMPROMISED'::text, NULL::uuid, NULL::bytea;
        RETURN;
    END IF;

    IF token_row.state <> 'CURRENT'
       OR family_row.state <> 'ACTIVE'
       OR token_row.expires_at <= pg_catalog.clock_timestamp()
       OR family_row.expires_at <= pg_catalog.clock_timestamp() THEN
        RETURN QUERY SELECT 'INACTIVE'::text, NULL::uuid, NULL::bytea;
        RETURN;
    END IF;

    SELECT g.* INTO grant_row
      FROM public.oauth_grants AS g
     WHERE g.grant_pk = family_row.grant_pk
     FOR KEY SHARE;
    SELECT c.* INTO client_row
      FROM public.app_clients AS c
     WHERE c.client_pk = family_row.client_pk
     FOR KEY SHARE;

    IF grant_row.state <> 'ACTIVE'
       OR (grant_row.valid_until IS NOT NULL
           AND grant_row.valid_until <= pg_catalog.clock_timestamp())
       OR client_row.status <> 'ACTIVE'
       OR family_row.client_security_epoch_snapshot <> client_row.security_epoch
       OR grant_row.client_security_epoch_snapshot <> client_row.security_epoch THEN
        RETURN QUERY SELECT 'SECURITY_STATE_CHANGED'::text, NULL::uuid, NULL::bytea;
        RETURN;
    END IF;

    SELECT u.* INTO user_row
      FROM public.iam_users AS u
     WHERE u.user_pk = grant_row.principal_pk
     FOR KEY SHARE;
    IF FOUND AND (
        user_row.lifecycle_state <> 'ACTIVE'
        OR user_row.freeze_state = 'FROZEN'
        OR family_row.user_security_epoch_snapshot <> user_row.security_epoch
        OR grant_row.user_security_epoch_snapshot <> user_row.security_epoch
        OR grant_row.consent_epoch_snapshot IS DISTINCT FROM user_row.consent_epoch
    ) THEN
        RETURN QUERY SELECT 'SECURITY_STATE_CHANGED'::text, NULL::uuid, NULL::bytea;
        RETURN;
    END IF;

    IF grant_row.tenant_pk IS NOT NULL THEN
        SELECT t.* INTO tenant_row
          FROM public.org_tenants AS t
         WHERE t.tenant_pk = grant_row.tenant_pk
         FOR KEY SHARE;
        IF tenant_row.status <> 'ACTIVE'
           OR family_row.tenant_security_epoch_snapshot <> tenant_row.security_epoch
           OR grant_row.tenant_security_epoch_snapshot <> tenant_row.security_epoch THEN
            RETURN QUERY SELECT 'SECURITY_STATE_CHANGED'::text, NULL::uuid, NULL::bytea;
            RETURN;
        END IF;
    END IF;

    -- Insert as REVOKED temporarily to avoid the one-CURRENT unique index,
    -- link the old row, then promote the successor in the same transaction.
    INSERT INTO public.oauth_refresh_tokens (
        refresh_token_id, token_family_pk, generation, token_digest,
        pepper_key_ref, pepper_key_version, state, expires_at
    ) VALUES (
        p_new_token_id, family_row.token_family_pk, token_row.generation + 1,
        p_new_token_digest, p_new_pepper_key_ref, p_new_pepper_key_version,
        'REVOKED', p_new_expires_at
    ) RETURNING refresh_token_pk INTO successor_pk;

    UPDATE public.oauth_refresh_tokens
       SET state = 'USED',
           used_at = pg_catalog.clock_timestamp(),
           successor_refresh_token_pk = successor_pk,
           retry_binding_digest = p_retry_binding_digest,
           retry_result_digest = p_retry_result_digest,
           retry_until = p_retry_until
     WHERE refresh_token_pk = token_row.refresh_token_pk
       AND state = 'CURRENT';
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = '40001',
            MESSAGE = 'refresh token rotation conflict';
    END IF;

    UPDATE public.oauth_refresh_tokens
       SET state = 'CURRENT'
     WHERE refresh_token_pk = successor_pk;
    UPDATE public.oauth_token_families
       SET rotation_counter = rotation_counter + 1,
           row_version = row_version + 1
     WHERE token_family_pk = family_row.token_family_pk;

    RETURN QUERY SELECT 'ROTATED'::text, p_new_token_id, p_retry_result_digest;
END
$function$;

-- Freeze a user and revoke online authority in the same local transaction.
CREATE FUNCTION public.iam_freeze_user(
    p_user_id uuid,
    p_expected_row_version bigint,
    p_actor_principal_pk bigint,
    p_reason_code text,
    p_trace_id uuid
)
RETURNS bigint
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $function$
DECLARE
    user_row public.iam_users%ROWTYPE;
    new_epoch bigint;
    new_aggregate_version bigint;
    payload jsonb;
    canonical_hash bytea;
BEGIN
    SELECT u.* INTO user_row
      FROM public.iam_users AS u
     WHERE u.user_id = p_user_id
     FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = 'P0002', MESSAGE = 'user not found';
    END IF;
    IF user_row.row_version <> p_expected_row_version THEN
        RAISE EXCEPTION USING ERRCODE = '40001', MESSAGE = 'user version conflict';
    END IF;
    IF user_row.lifecycle_state = 'ANONYMIZED' THEN
        RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'anonymized user is terminal';
    END IF;

    UPDATE public.iam_users
       SET freeze_state = 'FROZEN',
           security_epoch = security_epoch + 1,
           aggregate_version = aggregate_version + 1,
           row_version = row_version + 1,
           updated_at = pg_catalog.clock_timestamp(),
           updated_by_principal_pk = p_actor_principal_pk
     WHERE user_pk = user_row.user_pk
     RETURNING security_epoch, aggregate_version
          INTO new_epoch, new_aggregate_version;

    UPDATE public.oauth_sessions
       SET state = 'REVOKED',
           revoked_at = pg_catalog.coalesce(revoked_at, pg_catalog.clock_timestamp()),
           row_version = row_version + 1
     WHERE user_pk = user_row.user_pk
       AND state IN ('ACTIVE', 'COMPROMISED');

    UPDATE public.oauth_token_families AS f
       SET state = 'REVOKED',
           revoked_at = pg_catalog.coalesce(f.revoked_at, pg_catalog.clock_timestamp()),
           row_version = f.row_version + 1
      FROM public.oauth_grants AS g
     WHERE f.grant_pk = g.grant_pk
       AND g.principal_pk = user_row.user_pk
       AND f.state IN ('ACTIVE', 'COMPROMISED');

    INSERT INTO public.oauth_revocation_watermarks (
        subject_type, subject_pk, revocation_epoch, revoked_before, reason
    ) VALUES (
        'USER', user_row.user_pk, new_epoch, pg_catalog.clock_timestamp(),
        p_reason_code
    )
    ON CONFLICT (subject_type, subject_pk, resource_pk) DO UPDATE
       SET revocation_epoch = pg_catalog.greatest(
               public.oauth_revocation_watermarks.revocation_epoch,
               EXCLUDED.revocation_epoch
           ),
           revoked_before = pg_catalog.greatest(
               public.oauth_revocation_watermarks.revoked_before,
               EXCLUDED.revoked_before
           ),
           reason = EXCLUDED.reason,
           row_version = public.oauth_revocation_watermarks.row_version + 1,
           updated_at = pg_catalog.clock_timestamp();

    payload := pg_catalog.jsonb_build_object(
        'user_id', user_row.user_id,
        'security_epoch', new_epoch,
        'reason_code', p_reason_code
    );
    INSERT INTO public.evt_outbox (
        event_type, schema_version, producer_principal_pk, aggregate_type,
        aggregate_id, aggregate_version, subject_principal_pk, trace_id,
        data_classification, payload, payload_hash, occurred_at
    ) VALUES (
        'iam.user.frozen', 1, p_actor_principal_pk, 'IAM_USER',
        user_row.user_id, new_aggregate_version, user_row.user_pk, p_trace_id,
        'S2', payload,
        pg_catalog.sha256(pg_catalog.convert_to(payload::text, 'UTF8')),
        pg_catalog.clock_timestamp()
    );

    canonical_hash := pg_catalog.sha256(pg_catalog.convert_to(
        p_user_id::text || ':' || new_epoch::text || ':' || p_reason_code,
        'UTF8'
    ));
    PERFORM public.audit_append_event(
        pg_catalog.clock_timestamp(), 'SECURITY', 'IAM.USER.FREEZE',
        'PRINCIPAL', p_actor_principal_pk, NULL, user_row.user_pk, NULL,
        'iam-control', NULL, 'IAM_USER', user_row.user_id, NULL,
        NULL, canonical_hash, p_reason_code, NULL, 'SUCCEEDED', NULL, NULL,
        p_trace_id, NULL, 'IAM_USER:' || user_row.user_id::text,
        canonical_hash, 1, payload
    );
    RETURN new_epoch;
END
$function$;

-- Control-plane separation of duties and one ACTIVE release per artifact/env.
CREATE FUNCTION public.ctrl_guard_approval_separation()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $function$
DECLARE
    submitter_pk bigint;
BEGIN
    SELECT cs.submitter_principal_pk INTO submitter_pk
      FROM public.ctrl_change_sets AS cs
     WHERE cs.change_set_pk = NEW.change_set_pk
     FOR KEY SHARE;
    IF NEW.approver_principal_pk = submitter_pk THEN
        RAISE EXCEPTION USING ERRCODE = '23514',
            MESSAGE = 'change submitter cannot approve the same change';
    END IF;
    RETURN NEW;
END
$function$;

CREATE TRIGGER ctrl_approvals_separation_trg
BEFORE INSERT ON public.ctrl_approvals
FOR EACH ROW EXECUTE FUNCTION public.ctrl_guard_approval_separation();

CREATE FUNCTION public.ctrl_guard_active_release()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $function$
DECLARE
    target_artifact_pk bigint;
BEGIN
    IF NEW.status <> 'ACTIVE' THEN RETURN NEW; END IF;
    SELECT av.artifact_pk INTO target_artifact_pk
      FROM public.ctrl_artifact_versions AS av
     WHERE av.artifact_version_pk = NEW.artifact_version_pk
     FOR KEY SHARE;
    PERFORM 1 FROM public.ctrl_artifacts AS a
     WHERE a.artifact_pk = target_artifact_pk FOR UPDATE;
    IF EXISTS (
        SELECT 1
          FROM public.ctrl_releases AS r
          JOIN public.ctrl_artifact_versions AS av
            ON av.artifact_version_pk = r.artifact_version_pk
         WHERE av.artifact_pk = target_artifact_pk
           AND r.environment = NEW.environment
           AND r.status = 'ACTIVE'
           AND r.release_pk <> NEW.release_pk
    ) THEN
        RAISE EXCEPTION USING ERRCODE = '23505',
            MESSAGE = 'only one ACTIVE release is allowed per artifact and environment';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM public.ctrl_approvals AS a
         WHERE a.change_set_pk = NEW.change_set_pk
           AND a.decision = 'APPROVE'
    ) THEN
        RAISE EXCEPTION USING ERRCODE = '23514',
            MESSAGE = 'an ACTIVE release requires approval evidence';
    END IF;
    RETURN NEW;
END
$function$;

CREATE TRIGGER ctrl_releases_active_guard_trg
BEFORE INSERT OR UPDATE OF status, artifact_version_pk, environment
ON public.ctrl_releases
FOR EACH ROW EXECUTE FUNCTION public.ctrl_guard_active_release();

-- Normal retirement/destruction cannot remove the last usable key version.
-- Emergency COMPROMISED/REVOKED transitions remain fail-closed and are not
-- blocked merely to preserve availability.
CREATE FUNCTION public.key_guard_last_usable_version()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $function$
BEGIN
    IF OLD.state IN ('PUBLISHED', 'SIGNING_AND_VERIFYING', 'VERIFY_ONLY')
       AND NEW.state IN ('RETIRED', 'DESTROYED') THEN
        PERFORM 1 FROM public.key_crypto_keys AS k
         WHERE k.crypto_key_pk = OLD.crypto_key_pk FOR UPDATE;
        IF NOT EXISTS (
            SELECT 1 FROM public.key_crypto_key_versions AS v
             WHERE v.crypto_key_pk = OLD.crypto_key_pk
               AND v.crypto_key_version_pk <> OLD.crypto_key_version_pk
               AND v.state IN ('PUBLISHED', 'SIGNING_AND_VERIFYING', 'VERIFY_ONLY')
               AND v.not_before <= pg_catalog.clock_timestamp()
               AND (v.not_after IS NULL OR v.not_after > pg_catalog.clock_timestamp())
        ) THEN
            RAISE EXCEPTION USING ERRCODE = '23514',
                MESSAGE = 'cannot retire or destroy the last usable key version';
        END IF;
    END IF;
    RETURN NEW;
END
$function$;

CREATE TRIGGER key_crypto_key_versions_last_usable_trg
BEFORE UPDATE OF state ON public.key_crypto_key_versions
FOR EACH ROW EXECUTE FUNCTION public.key_guard_last_usable_version();

-- Consent scope, privacy completion and Legal Hold guards.
CREATE FUNCTION public.priv_guard_granted_consent_scope()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $function$
BEGIN
    IF NEW.status = 'GRANTED' AND NOT EXISTS (
        SELECT 1 FROM public.priv_consent_categories AS cc
         WHERE cc.consent_pk = NEW.consent_pk
    ) THEN
        RAISE EXCEPTION USING ERRCODE = '23514',
            MESSAGE = 'a granted consent requires at least one data category';
    END IF;
    RETURN NULL;
END
$function$;

CREATE CONSTRAINT TRIGGER priv_consents_scope_guard_trg
AFTER INSERT OR UPDATE OF status ON public.priv_consents
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION public.priv_guard_granted_consent_scope();

CREATE FUNCTION public.priv_guard_privacy_completion()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $function$
BEGIN
    IF NEW.state <> 'COMPLETED' OR OLD.state = 'COMPLETED' THEN RETURN NEW; END IF;

    IF NOT EXISTS (
        SELECT 1 FROM public.priv_request_tasks AS t
         WHERE t.privacy_request_pk = NEW.privacy_request_pk
    ) OR EXISTS (
        SELECT 1 FROM public.priv_request_tasks AS t
         WHERE t.privacy_request_pk = NEW.privacy_request_pk
           AND t.state NOT IN ('SUCCEEDED', 'SKIPPED')
    ) OR EXISTS (
        SELECT 1 FROM public.priv_request_items AS i
         WHERE i.privacy_request_pk = NEW.privacy_request_pk
           AND i.state NOT IN ('COMPLETED', 'REJECTED', 'SKIPPED')
    ) THEN
        RAISE EXCEPTION USING ERRCODE = '23514',
            MESSAGE = 'privacy request cannot complete before all local items and tasks are terminal';
    END IF;

    IF NEW.request_type = 'DELETION' AND EXISTS (
        SELECT 1
          FROM public.priv_legal_holds AS h
          JOIN public.priv_hold_targets AS ht
            ON ht.legal_hold_pk = h.legal_hold_pk
         WHERE h.state = 'ACTIVE'
           AND (h.ends_at IS NULL OR h.ends_at > pg_catalog.clock_timestamp())
           AND ht.target_type = 'USER'
           AND ht.user_pk = NEW.user_pk
    ) THEN
        RAISE EXCEPTION USING ERRCODE = '23514',
            MESSAGE = 'deletion completion is blocked by an active Legal Hold';
    END IF;
    RETURN NEW;
END
$function$;

CREATE TRIGGER priv_privacy_requests_completion_guard_trg
BEFORE UPDATE OF state ON public.priv_privacy_requests
FOR EACH ROW EXECUTE FUNCTION public.priv_guard_privacy_completion();

CREATE FUNCTION public.priv_guard_legal_hold_activation()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $function$
BEGIN
    IF NEW.state = 'ACTIVE' AND (
        NEW.approved_by_principal_pk IS NULL
        OR NOT EXISTS (
            SELECT 1 FROM public.priv_hold_targets AS ht
             WHERE ht.legal_hold_pk = NEW.legal_hold_pk
        )
    ) THEN
        RAISE EXCEPTION USING ERRCODE = '23514',
            MESSAGE = 'an active Legal Hold requires an approver and at least one typed target';
    END IF;
    IF OLD.state IN ('RELEASED', 'EXPIRED', 'CANCELLED')
       AND NEW.state IS DISTINCT FROM OLD.state THEN
        RAISE EXCEPTION USING ERRCODE = '23514',
            MESSAGE = 'terminal Legal Hold state cannot be restored';
    END IF;
    RETURN NEW;
END
$function$;

CREATE TRIGGER priv_legal_holds_guard_trg
BEFORE UPDATE OF state ON public.priv_legal_holds
FOR EACH ROW EXECUTE FUNCTION public.priv_guard_legal_hold_activation();

COMMENT ON TABLE public.auth_context_authenticators IS
    'Authenticator evidence used by a successful context. Same-user consistency must be enforced by the controlled context-creation command and verified by database contract tests; a direct trigger would be brittle during context assembly.';
COMMENT ON TABLE public.evt_outbox IS
    'Transactional event envelope. PostgreSQL constrains shape and atomic local insertion; schema semantics, credential/PII content scanning, delivery ordering, consumer idempotency and revocation propagation SLO require application and verification tests.';
COMMENT ON TABLE public.audit_events IS
    'Append-only chained audit evidence. Database SHA-256 chaining detects ordinary mutation, but superusers can rewrite data and chain; signed checkpoints must be exported to an independent WORM/object-lock security domain.';
COMMENT ON TABLE public.priv_privacy_requests IS
    'Local task and user Legal Hold completion guards are enforced. Cross-system deletion/export, backup expiry, jurisdictional exceptions and proof authenticity remain Saga/application/verification responsibilities.';
COMMENT ON TABLE public.key_crypto_key_versions IS
    'Normal last-usable-key retirement is guarded. KMS/HSM key existence, non-exportability, actual destruction, JWKS cache propagation and emergency compromise handling require external control-plane verification.';

-- SECURITY DEFINER routines start closed; 120 grants exact EXECUTE privileges.
REVOKE ALL ON FUNCTION public.audit_append_event(
    timestamptz, text, text, text, bigint, bytea, bigint, bigint, text, inet,
    text, uuid, bytea, bytea, bytea, text, text, text, text, uuid, uuid, uuid,
    text, bytea, integer, jsonb
) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.iam_bind_identifier(
    bigint, bigint, bigint, bytea, bigint, uuid
) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.auth_consume_challenge(
    uuid, bigint, uuid, text, uuid, uuid, bytea
) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.oauth_rotate_refresh_token(
    bytea, uuid, bytea, text, integer, timestamptz, bytea, bytea, timestamptz
) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.iam_freeze_user(
    uuid, bigint, bigint, text, uuid
) FROM PUBLIC;

COMMIT;
