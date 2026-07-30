-- Database roles, least-privilege grants, and tenant RLS.
-- Login identities, passwords/certificates, role membership and production
-- break-glass activation are DBA/IAM boundaries and are intentionally not
-- created here. All roles below are NOLOGIN capability/group roles.

BEGIN;

DO $roles$
DECLARE
    role_name text;
BEGIN
    FOREACH role_name IN ARRAY ARRAY[
        'iam_owner', 'iam_migrator', 'iam_api', 'iam_identity',
        'iam_auth', 'iam_tenant', 'iam_authz', 'iam_privacy',
        'iam_risk', 'iam_control', 'iam_dispatcher', 'iam_audit_writer',
        'iam_audit_reader', 'iam_ops', 'iam_readonly', 'iam_breakglass'
    ] LOOP
        IF NOT EXISTS (
            SELECT 1 FROM pg_catalog.pg_roles AS r
             WHERE r.rolname = role_name
        ) THEN
            EXECUTE pg_catalog.format('CREATE ROLE %I NOLOGIN', role_name);
        END IF;
        EXECUTE pg_catalog.format(
            'ALTER ROLE %I NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS INHERIT',
            role_name
        );
    END LOOP;

    IF NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_roles AS r
         WHERE r.rolname = 'iam_platform'
    ) THEN
        CREATE ROLE iam_platform NOLOGIN;
    END IF;
    ALTER ROLE iam_platform
        NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION
        BYPASSRLS INHERIT;
END
$roles$;

COMMENT ON ROLE iam_owner IS
    'NOLOGIN owner of public IAM objects. Never used as a runtime connection role.';
COMMENT ON ROLE iam_migrator IS
    'NOLOGIN deployment capability; may SET ROLE iam_owner. DBA grants it only to controlled migration login identities.';
COMMENT ON ROLE iam_platform IS
    'NOLOGIN cross-tenant background capability with BYPASSRLS; membership is DBA-controlled and every use must be audited.';
COMMENT ON ROLE iam_breakglass IS
    'NOLOGIN emergency capability. Membership must be time-bounded, separately approved and externally alerted.';

GRANT iam_owner TO iam_migrator WITH ADMIN OPTION;

-- Existing migrations may have run as a bootstrap login. Temporarily make that
-- creator a member of the target owner role so PostgreSQL permits ownership
-- transfer, then remove only the membership added by this block.
DO $ownership$
DECLARE
    bootstrap_was_member boolean;
    obj record;
BEGIN
    bootstrap_was_member := pg_catalog.pg_has_role(
        pg_catalog.current_user, 'iam_owner', 'MEMBER'
    );
    IF NOT bootstrap_was_member THEN
        EXECUTE pg_catalog.format(
            'GRANT iam_owner TO %I', pg_catalog.current_user
        );
    END IF;
    PERFORM pg_catalog.set_config(
        'iam.bootstrap_was_owner_member',
        bootstrap_was_member::text,
        true
    );

    ALTER SCHEMA public OWNER TO iam_owner;

    FOR obj IN
        SELECT c.relkind, n.nspname, c.relname
          FROM pg_catalog.pg_class AS c
          JOIN pg_catalog.pg_namespace AS n ON n.oid = c.relnamespace
         WHERE n.nspname = 'public'
           AND c.relkind IN ('r', 'p', 'S', 'v', 'm')
         ORDER BY
               CASE WHEN c.relkind = 'S' THEN 2 ELSE 1 END,
               c.relkind,
               c.relname
    LOOP
        IF obj.relkind = 'S' THEN
            EXECUTE pg_catalog.format(
                'ALTER SEQUENCE %I.%I OWNER TO iam_owner',
                obj.nspname, obj.relname
            );
        ELSIF obj.relkind = 'v' THEN
            EXECUTE pg_catalog.format(
                'ALTER VIEW %I.%I OWNER TO iam_owner',
                obj.nspname, obj.relname
            );
        ELSIF obj.relkind = 'm' THEN
            EXECUTE pg_catalog.format(
                'ALTER MATERIALIZED VIEW %I.%I OWNER TO iam_owner',
                obj.nspname, obj.relname
            );
        ELSE
            EXECUTE pg_catalog.format(
                'ALTER TABLE %I.%I OWNER TO iam_owner',
                obj.nspname, obj.relname
            );
        END IF;
    END LOOP;

    FOR obj IN
        SELECT n.nspname, p.proname,
               pg_catalog.pg_get_function_identity_arguments(p.oid) AS args
          FROM pg_catalog.pg_proc AS p
          JOIN pg_catalog.pg_namespace AS n ON n.oid = p.pronamespace
         WHERE n.nspname = 'public'
         ORDER BY p.proname, p.oid
    LOOP
        EXECUTE pg_catalog.format(
            'ALTER FUNCTION %I.%I(%s) OWNER TO iam_owner',
            obj.nspname, obj.proname, obj.args
        );
    END LOOP;

END
$ownership$;

REVOKE CREATE ON SCHEMA public FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM PUBLIC;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA public FROM PUBLIC;

ALTER DEFAULT PRIVILEGES FOR ROLE iam_owner IN SCHEMA public
    REVOKE ALL ON TABLES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES FOR ROLE iam_owner IN SCHEMA public
    REVOKE ALL ON SEQUENCES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES FOR ROLE iam_owner IN SCHEMA public
    REVOKE ALL ON FUNCTIONS FROM PUBLIC;

GRANT USAGE ON SCHEMA public TO
    iam_migrator, iam_api, iam_identity, iam_auth, iam_tenant, iam_authz,
    iam_privacy, iam_risk, iam_control, iam_dispatcher, iam_audit_writer,
    iam_audit_reader, iam_ops, iam_readonly, iam_breakglass, iam_platform;

-- Tenant context is an external UUIDv4, never a caller-supplied internal PK.
-- Missing, malformed, or unknown context fails closed. Connection pools must
-- issue SET LOCAL app.tenant_id inside every transaction; PostgreSQL cannot
-- distinguish a malicious SET from a trusted service bug, so membership and
-- transaction-context contract tests remain mandatory.
CREATE FUNCTION public.iam_current_tenant_pk()
RETURNS bigint
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $function$
DECLARE
    setting_value text;
    tenant_uuid uuid;
    result_pk bigint;
BEGIN
    setting_value := pg_catalog.current_setting('app.tenant_id', true);
    IF setting_value IS NULL OR pg_catalog.btrim(setting_value) = '' THEN
        RAISE EXCEPTION USING
            ERRCODE = '42501',
            MESSAGE = 'transaction tenant context app.tenant_id is required';
    END IF;
    BEGIN
        tenant_uuid := setting_value::uuid;
    EXCEPTION WHEN invalid_text_representation THEN
        RAISE EXCEPTION USING
            ERRCODE = '42501',
            MESSAGE = 'transaction tenant context app.tenant_id is invalid';
    END;
    IF NOT public.iam_uuid_is_v4(tenant_uuid) THEN
        RAISE EXCEPTION USING
            ERRCODE = '42501',
            MESSAGE = 'transaction tenant context app.tenant_id must be UUIDv4';
    END IF;

    SELECT t.tenant_pk INTO result_pk
      FROM public.org_tenants AS t
     WHERE t.tenant_id = tenant_uuid;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING
            ERRCODE = '42501',
            MESSAGE = 'transaction tenant context is not recognized';
    END IF;
    RETURN result_pk;
END
$function$;

REVOKE ALL ON FUNCTION public.iam_current_tenant_pk() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.iam_current_tenant_pk() TO
    iam_api, iam_tenant, iam_authz, iam_privacy, iam_risk, iam_control,
    iam_readonly;

-- UUID checks appear in table constraints and therefore need EXECUTE for
-- roles that insert rows directly.
GRANT EXECUTE ON FUNCTION public.iam_uuid_is_v4(uuid) TO
    iam_api, iam_identity, iam_auth, iam_tenant, iam_authz, iam_privacy,
    iam_risk, iam_control, iam_dispatcher, iam_ops, iam_platform;

-- Exact execution surface for SECURITY DEFINER commands.
GRANT EXECUTE ON FUNCTION public.iam_bind_identifier(
    bigint, bigint, bigint, bytea, bigint, uuid
) TO iam_identity;
GRANT EXECUTE ON FUNCTION public.auth_consume_challenge(
    uuid, bigint, uuid, text, uuid, uuid, bytea
) TO iam_auth;
GRANT EXECUTE ON FUNCTION public.oauth_rotate_refresh_token(
    bytea, uuid, bytea, text, integer, timestamptz, bytea, bytea, timestamptz
) TO iam_auth;
GRANT EXECUTE ON FUNCTION public.iam_freeze_user(
    uuid, bigint, bigint, text, uuid
) TO iam_control, iam_risk, iam_breakglass;
GRANT EXECUTE ON FUNCTION public.audit_append_event(
    timestamptz, text, text, text, bigint, bytea, bigint, bigint, text, inet,
    text, uuid, bytea, bytea, bytea, text, text, text, text, uuid, uuid, uuid,
    text, bytea, integer, jsonb
) TO iam_audit_writer;

-- Identity service: ciphertext and blind-index values are writable here, but
-- active bindings and freeze transitions are function-only.
GRANT SELECT ON
    public.iam_principals, public.iam_users, public.iam_identities,
    public.iam_identifiers, public.iam_identifier_blind_indexes,
    public.iam_identity_bindings, public.iam_identifier_tombstones
TO iam_identity;
GRANT INSERT, UPDATE ON
    public.iam_identities, public.iam_identifiers,
    public.iam_identifier_blind_indexes
TO iam_identity;
GRANT INSERT ON public.iam_identifier_tombstones TO iam_identity;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO
    iam_identity, iam_auth, iam_tenant, iam_authz, iam_privacy, iam_risk,
    iam_control, iam_dispatcher, iam_ops, iam_platform;

-- Authentication/token service. Challenge consumption and refresh rotation
-- intentionally have no direct UPDATE grant on their critical tables.
GRANT SELECT ON
    public.iam_principals, public.iam_users, public.org_tenants,
    public.app_clients, public.auth_authenticators,
    public.auth_password_credentials, public.auth_webauthn_credentials,
    public.auth_totp_credentials, public.auth_recovery_code_batches,
    public.auth_recovery_codes, public.auth_transactions,
    public.auth_challenges, public.auth_contexts, public.oauth_sessions,
    public.oauth_grants, public.oauth_token_families,
    public.oauth_refresh_tokens, public.oauth_revocation_watermarks
TO iam_auth;
GRANT INSERT ON
    public.auth_transactions, public.auth_challenges,
    public.auth_challenge_deliveries, public.auth_challenge_attempts,
    public.auth_contexts, public.auth_context_methods,
    public.auth_context_authenticators, public.oauth_sessions,
    public.oauth_grants, public.oauth_token_families,
    public.oauth_refresh_tokens
TO iam_auth;
GRANT UPDATE ON
    public.auth_transactions, public.oauth_sessions, public.oauth_grants
TO iam_auth;

-- Tenant administration receives no direct write to the global tenant root;
-- provisioning/closing is a platform control-plane command.
GRANT SELECT ON public.org_tenants TO iam_api, iam_tenant, iam_authz;
GRANT SELECT, INSERT, UPDATE ON
    public.org_tenant_domains, public.org_organizations,
    public.org_memberships, public.org_membership_organizations,
    public.org_groups, public.org_group_memberships, public.org_invitations,
    public.profile_namespace_values,
    public.fed_identity_providers, public.fed_provider_versions,
    public.fed_directory_sources, public.fed_directory_objects
TO iam_tenant;

GRANT SELECT ON
    public.authz_actions, public.authz_permissions, public.authz_scope_nodes,
    public.authz_resources, public.authz_roles, public.authz_role_permissions,
    public.authz_data_scopes, public.authz_assignments,
    public.authz_relation_tuples, public.authz_policy_sets,
    public.authz_policy_versions, public.authz_policy_releases
TO iam_api, iam_authz;
GRANT INSERT, UPDATE ON
    public.authz_resources, public.authz_roles,
    public.authz_role_permissions, public.authz_data_scopes,
    public.authz_data_scope_resources, public.authz_assignments,
    public.authz_assignment_data_scopes, public.authz_relation_tuples,
    public.authz_policy_sets, public.authz_policy_versions,
    public.authz_policy_releases
TO iam_authz;

GRANT SELECT, INSERT, UPDATE ON
    public.priv_consents, public.priv_consent_categories,
    public.priv_consent_evidence, public.priv_marketing_subscriptions,
    public.priv_privacy_requests, public.priv_request_items,
    public.priv_request_tasks, public.priv_request_attempts,
    public.priv_legal_holds, public.priv_hold_targets,
    public.priv_deletion_certificates
TO iam_privacy;
GRANT SELECT ON
    public.priv_purposes, public.priv_data_categories,
    public.priv_recipients, public.priv_notices,
    public.priv_downstream_systems, public.priv_downstream_mappings
TO iam_privacy, iam_api;

GRANT SELECT, INSERT, UPDATE ON
    public.risk_signal_targets, public.risk_assessments,
    public.risk_assessment_signals, public.risk_dispositions,
    public.risk_cases, public.risk_case_entities,
    public.risk_security_signals
TO iam_risk;
GRANT INSERT ON
    public.risk_signals, public.risk_case_actions
TO iam_risk;

GRANT SELECT, INSERT, UPDATE ON
    public.ctrl_change_sets, public.ctrl_artifacts,
    public.ctrl_artifact_versions, public.ctrl_releases,
    public.ctrl_release_targets, public.ctrl_rollouts,
    public.ctrl_emergency_actions, public.ctrl_breakglass_grants
TO iam_control;
GRANT INSERT ON
    public.ctrl_validations, public.ctrl_approvals,
    public.ctrl_breakglass_uses
TO iam_control;
GRANT SELECT ON
    public.key_crypto_keys, public.key_crypto_key_versions,
    public.key_certificates, public.key_lifecycle_events
TO iam_control;

GRANT SELECT ON public.evt_outbox TO iam_dispatcher;
GRANT SELECT, INSERT, UPDATE ON
    public.evt_outbox_deliveries, public.evt_webhook_deliveries
TO iam_dispatcher;
GRANT INSERT ON
    public.evt_outbox_delivery_attempts, public.evt_webhook_attempts
TO iam_dispatcher;
GRANT UPDATE (archived_at) ON public.evt_outbox TO iam_dispatcher;

GRANT SELECT ON
    public.audit_events, public.audit_sensitive_accesses,
    public.audit_chain_checkpoints
TO iam_audit_reader;

GRANT SELECT, INSERT, UPDATE ON
    public.ops_operations, public.ops_operation_steps,
    public.ops_idempotency_records, public.ops_migration_batches,
    public.ops_legacy_id_mappings, public.ops_change_log
TO iam_ops;

GRANT SELECT ON
    public.authz_actions, public.authz_permissions,
    public.priv_data_categories, public.app_api_resources,
    public.app_api_scopes
TO iam_readonly;

-- Cross-tenant background access is isolated in iam_platform; it deliberately
-- excludes credential material and raw Identifier ciphertext.
GRANT SELECT ON
    public.org_tenants, public.org_organizations, public.org_memberships,
    public.org_groups, public.fed_directory_sources,
    public.fed_directory_objects, public.authz_resources,
    public.authz_roles, public.authz_assignments,
    public.authz_relation_tuples, public.risk_cases,
    public.evt_webhook_subscriptions, public.evt_outbox
TO iam_platform;

-- Direct-tenant tables: both USING and WITH CHECK fail closed through the UUID
-- context helper. Platform jobs use iam_platform/BYPASSRLS, never a GUC flag.
ALTER TABLE public.org_tenant_domains ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.org_tenant_domains FORCE ROW LEVEL SECURITY;
CREATE POLICY org_tenant_domains_tenant_policy ON public.org_tenant_domains
    USING (tenant_pk = public.iam_current_tenant_pk())
    WITH CHECK (tenant_pk = public.iam_current_tenant_pk());

ALTER TABLE public.org_organizations ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.org_organizations FORCE ROW LEVEL SECURITY;
CREATE POLICY org_organizations_tenant_policy ON public.org_organizations
    USING (tenant_pk = public.iam_current_tenant_pk())
    WITH CHECK (tenant_pk = public.iam_current_tenant_pk());

ALTER TABLE public.org_memberships ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.org_memberships FORCE ROW LEVEL SECURITY;
CREATE POLICY org_memberships_tenant_policy ON public.org_memberships
    USING (tenant_pk = public.iam_current_tenant_pk())
    WITH CHECK (tenant_pk = public.iam_current_tenant_pk());

ALTER TABLE public.org_membership_organizations ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.org_membership_organizations FORCE ROW LEVEL SECURITY;
CREATE POLICY org_membership_organizations_tenant_policy
ON public.org_membership_organizations
    USING (tenant_pk = public.iam_current_tenant_pk())
    WITH CHECK (tenant_pk = public.iam_current_tenant_pk());

ALTER TABLE public.org_groups ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.org_groups FORCE ROW LEVEL SECURITY;
CREATE POLICY org_groups_tenant_policy ON public.org_groups
    USING (tenant_pk = public.iam_current_tenant_pk())
    WITH CHECK (tenant_pk = public.iam_current_tenant_pk());

ALTER TABLE public.org_group_memberships ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.org_group_memberships FORCE ROW LEVEL SECURITY;
CREATE POLICY org_group_memberships_tenant_policy ON public.org_group_memberships
    USING (tenant_pk = public.iam_current_tenant_pk())
    WITH CHECK (tenant_pk = public.iam_current_tenant_pk());

ALTER TABLE public.org_invitations ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.org_invitations FORCE ROW LEVEL SECURITY;
CREATE POLICY org_invitations_tenant_policy ON public.org_invitations
    USING (tenant_pk = public.iam_current_tenant_pk())
    WITH CHECK (tenant_pk = public.iam_current_tenant_pk());

ALTER TABLE public.fed_identity_providers ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.fed_identity_providers FORCE ROW LEVEL SECURITY;
CREATE POLICY fed_identity_providers_tenant_policy
ON public.fed_identity_providers
    USING (tenant_pk = public.iam_current_tenant_pk())
    WITH CHECK (tenant_pk = public.iam_current_tenant_pk());

ALTER TABLE public.fed_provider_versions ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.fed_provider_versions FORCE ROW LEVEL SECURITY;
CREATE POLICY fed_provider_versions_tenant_policy ON public.fed_provider_versions
    USING (tenant_pk = public.iam_current_tenant_pk())
    WITH CHECK (tenant_pk = public.iam_current_tenant_pk());

ALTER TABLE public.fed_directory_sources ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.fed_directory_sources FORCE ROW LEVEL SECURITY;
CREATE POLICY fed_directory_sources_tenant_policy
ON public.fed_directory_sources
    USING (tenant_pk = public.iam_current_tenant_pk())
    WITH CHECK (tenant_pk = public.iam_current_tenant_pk());

ALTER TABLE public.fed_directory_objects ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.fed_directory_objects FORCE ROW LEVEL SECURITY;
CREATE POLICY fed_directory_objects_tenant_policy
ON public.fed_directory_objects
    USING (tenant_pk = public.iam_current_tenant_pk())
    WITH CHECK (tenant_pk = public.iam_current_tenant_pk());

ALTER TABLE public.authz_resources ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.authz_resources FORCE ROW LEVEL SECURITY;
CREATE POLICY authz_resources_tenant_policy ON public.authz_resources
    USING (tenant_pk = public.iam_current_tenant_pk())
    WITH CHECK (tenant_pk = public.iam_current_tenant_pk());

ALTER TABLE public.authz_roles ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.authz_roles FORCE ROW LEVEL SECURITY;
CREATE POLICY authz_roles_tenant_policy ON public.authz_roles
    USING (tenant_pk = public.iam_current_tenant_pk())
    WITH CHECK (tenant_pk = public.iam_current_tenant_pk());

ALTER TABLE public.authz_data_scopes ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.authz_data_scopes FORCE ROW LEVEL SECURITY;
CREATE POLICY authz_data_scopes_tenant_policy ON public.authz_data_scopes
    USING (tenant_pk = public.iam_current_tenant_pk())
    WITH CHECK (tenant_pk = public.iam_current_tenant_pk());

ALTER TABLE public.authz_assignments ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.authz_assignments FORCE ROW LEVEL SECURITY;
CREATE POLICY authz_assignments_tenant_policy ON public.authz_assignments
    USING (tenant_pk = public.iam_current_tenant_pk())
    WITH CHECK (tenant_pk = public.iam_current_tenant_pk());

ALTER TABLE public.authz_relation_tuples ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.authz_relation_tuples FORCE ROW LEVEL SECURITY;
CREATE POLICY authz_relation_tuples_tenant_policy ON public.authz_relation_tuples
    USING (tenant_pk = public.iam_current_tenant_pk())
    WITH CHECK (tenant_pk = public.iam_current_tenant_pk());

ALTER TABLE public.authz_policy_sets ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.authz_policy_sets FORCE ROW LEVEL SECURITY;
CREATE POLICY authz_policy_sets_tenant_policy ON public.authz_policy_sets
    USING (tenant_pk = public.iam_current_tenant_pk())
    WITH CHECK (tenant_pk = public.iam_current_tenant_pk());

ALTER TABLE public.authz_policy_releases ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.authz_policy_releases FORCE ROW LEVEL SECURITY;
CREATE POLICY authz_policy_releases_tenant_policy
ON public.authz_policy_releases
    USING (tenant_pk = public.iam_current_tenant_pk())
    WITH CHECK (tenant_pk = public.iam_current_tenant_pk());

ALTER TABLE public.risk_signal_targets ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.risk_signal_targets FORCE ROW LEVEL SECURITY;
CREATE POLICY risk_signal_targets_tenant_policy ON public.risk_signal_targets
    USING (tenant_pk = public.iam_current_tenant_pk())
    WITH CHECK (tenant_pk = public.iam_current_tenant_pk());

ALTER TABLE public.risk_assessments ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.risk_assessments FORCE ROW LEVEL SECURITY;
CREATE POLICY risk_assessments_tenant_policy ON public.risk_assessments
    USING (tenant_pk = public.iam_current_tenant_pk())
    WITH CHECK (tenant_pk = public.iam_current_tenant_pk());

ALTER TABLE public.risk_cases ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.risk_cases FORCE ROW LEVEL SECURITY;
CREATE POLICY risk_cases_tenant_policy ON public.risk_cases
    USING (tenant_pk = public.iam_current_tenant_pk())
    WITH CHECK (tenant_pk = public.iam_current_tenant_pk());

ALTER TABLE public.risk_security_signals ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.risk_security_signals FORCE ROW LEVEL SECURITY;
CREATE POLICY risk_security_signals_tenant_policy
ON public.risk_security_signals
    USING (tenant_pk = public.iam_current_tenant_pk())
    WITH CHECK (tenant_pk = public.iam_current_tenant_pk());

ALTER TABLE public.evt_webhook_subscriptions ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.evt_webhook_subscriptions FORCE ROW LEVEL SECURITY;
CREATE POLICY evt_webhook_subscriptions_tenant_policy
ON public.evt_webhook_subscriptions
    USING (tenant_pk = public.iam_current_tenant_pk())
    WITH CHECK (tenant_pk = public.iam_current_tenant_pk());

-- profile_namespace_values has no tenant_pk. Membership-scoped rows derive it
-- through the FK; USER values are visible only while that user has a current
-- membership in the transaction tenant.
ALTER TABLE public.profile_namespace_values ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.profile_namespace_values FORCE ROW LEVEL SECURITY;
CREATE POLICY profile_namespace_values_tenant_policy
ON public.profile_namespace_values
    USING (
        (
            subject_type = 'MEMBERSHIP'
            AND EXISTS (
                SELECT 1 FROM public.org_memberships AS m
                 WHERE m.membership_pk =
                       public.profile_namespace_values.membership_pk
                   AND m.tenant_pk = public.iam_current_tenant_pk()
            )
        )
        OR
        (
            subject_type = 'USER'
            AND EXISTS (
                SELECT 1 FROM public.org_memberships AS m
                 WHERE m.user_pk = public.profile_namespace_values.user_pk
                   AND m.tenant_pk = public.iam_current_tenant_pk()
                   AND m.state NOT IN ('LEFT', 'REJECTED', 'EXPIRED')
            )
        )
    )
    WITH CHECK (
        (
            subject_type = 'MEMBERSHIP'
            AND EXISTS (
                SELECT 1 FROM public.org_memberships AS m
                 WHERE m.membership_pk =
                       public.profile_namespace_values.membership_pk
                   AND m.tenant_pk = public.iam_current_tenant_pk()
            )
        )
        OR
        (
            subject_type = 'USER'
            AND EXISTS (
                SELECT 1 FROM public.org_memberships AS m
                 WHERE m.user_pk = public.profile_namespace_values.user_pk
                   AND m.tenant_pk = public.iam_current_tenant_pk()
                   AND m.state NOT IN ('LEFT', 'REJECTED', 'EXPIRED')
            )
        )
    );

-- Authorization child tables inherit tenant ownership through their typed
-- parent FK; policies repeat that relation so guessing an internal child PK
-- cannot cross the tenant boundary.
ALTER TABLE public.authz_role_permissions ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.authz_role_permissions FORCE ROW LEVEL SECURITY;
CREATE POLICY authz_role_permissions_tenant_policy
ON public.authz_role_permissions
    USING (EXISTS (
        SELECT 1 FROM public.authz_roles AS r
         WHERE r.role_pk = public.authz_role_permissions.role_pk
           AND r.tenant_pk = public.iam_current_tenant_pk()
    ))
    WITH CHECK (EXISTS (
        SELECT 1 FROM public.authz_roles AS r
         WHERE r.role_pk = public.authz_role_permissions.role_pk
           AND r.tenant_pk = public.iam_current_tenant_pk()
    ));

ALTER TABLE public.authz_data_scope_resources ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.authz_data_scope_resources FORCE ROW LEVEL SECURITY;
CREATE POLICY authz_data_scope_resources_tenant_policy
ON public.authz_data_scope_resources
    USING (EXISTS (
        SELECT 1 FROM public.authz_data_scopes AS s
         WHERE s.data_scope_pk =
               public.authz_data_scope_resources.data_scope_pk
           AND s.tenant_pk = public.iam_current_tenant_pk()
    ))
    WITH CHECK (EXISTS (
        SELECT 1 FROM public.authz_data_scopes AS s
         WHERE s.data_scope_pk =
               public.authz_data_scope_resources.data_scope_pk
           AND s.tenant_pk = public.iam_current_tenant_pk()
    ));

ALTER TABLE public.authz_role_permission_data_scopes ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.authz_role_permission_data_scopes FORCE ROW LEVEL SECURITY;
CREATE POLICY authz_role_permission_data_scopes_tenant_policy
ON public.authz_role_permission_data_scopes
    USING (EXISTS (
        SELECT 1
          FROM public.authz_role_permissions AS rp
          JOIN public.authz_roles AS r ON r.role_pk = rp.role_pk
         WHERE rp.role_permission_pk =
               public.authz_role_permission_data_scopes.role_permission_pk
           AND r.tenant_pk = public.iam_current_tenant_pk()
    ))
    WITH CHECK (EXISTS (
        SELECT 1
          FROM public.authz_role_permissions AS rp
          JOIN public.authz_roles AS r ON r.role_pk = rp.role_pk
         WHERE rp.role_permission_pk =
               public.authz_role_permission_data_scopes.role_permission_pk
           AND r.tenant_pk = public.iam_current_tenant_pk()
    ));

ALTER TABLE public.authz_assignment_data_scopes ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.authz_assignment_data_scopes FORCE ROW LEVEL SECURITY;
CREATE POLICY authz_assignment_data_scopes_tenant_policy
ON public.authz_assignment_data_scopes
    USING (EXISTS (
        SELECT 1 FROM public.authz_assignments AS a
         WHERE a.assignment_pk =
               public.authz_assignment_data_scopes.assignment_pk
           AND a.tenant_pk = public.iam_current_tenant_pk()
    ))
    WITH CHECK (EXISTS (
        SELECT 1 FROM public.authz_assignments AS a
         WHERE a.assignment_pk =
               public.authz_assignment_data_scopes.assignment_pk
           AND a.tenant_pk = public.iam_current_tenant_pk()
    ));

ALTER TABLE public.authz_policy_versions ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.authz_policy_versions FORCE ROW LEVEL SECURITY;
CREATE POLICY authz_policy_versions_tenant_policy
ON public.authz_policy_versions
    USING (EXISTS (
        SELECT 1 FROM public.authz_policy_sets AS p
         WHERE p.policy_set_pk =
               public.authz_policy_versions.policy_set_pk
           AND p.tenant_pk = public.iam_current_tenant_pk()
    ))
    WITH CHECK (EXISTS (
        SELECT 1 FROM public.authz_policy_sets AS p
         WHERE p.policy_set_pk =
               public.authz_policy_versions.policy_set_pk
           AND p.tenant_pk = public.iam_current_tenant_pk()
    ));

-- Risk child evidence derives tenant ownership from its assessment/case root.
ALTER TABLE public.risk_assessment_signals ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.risk_assessment_signals FORCE ROW LEVEL SECURITY;
CREATE POLICY risk_assessment_signals_tenant_policy
ON public.risk_assessment_signals
    USING (EXISTS (
        SELECT 1 FROM public.risk_assessments AS a
         WHERE a.risk_assessment_pk =
               public.risk_assessment_signals.risk_assessment_pk
           AND a.tenant_pk = public.iam_current_tenant_pk()
    ))
    WITH CHECK (EXISTS (
        SELECT 1 FROM public.risk_assessments AS a
         WHERE a.risk_assessment_pk =
               public.risk_assessment_signals.risk_assessment_pk
           AND a.tenant_pk = public.iam_current_tenant_pk()
    ));

ALTER TABLE public.risk_dispositions ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.risk_dispositions FORCE ROW LEVEL SECURITY;
CREATE POLICY risk_dispositions_tenant_policy ON public.risk_dispositions
    USING (EXISTS (
        SELECT 1 FROM public.risk_assessments AS a
         WHERE a.risk_assessment_pk =
               public.risk_dispositions.risk_assessment_pk
           AND a.tenant_pk = public.iam_current_tenant_pk()
    ))
    WITH CHECK (EXISTS (
        SELECT 1 FROM public.risk_assessments AS a
         WHERE a.risk_assessment_pk =
               public.risk_dispositions.risk_assessment_pk
           AND a.tenant_pk = public.iam_current_tenant_pk()
    ));

ALTER TABLE public.risk_case_entities ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.risk_case_entities FORCE ROW LEVEL SECURITY;
CREATE POLICY risk_case_entities_tenant_policy ON public.risk_case_entities
    USING (EXISTS (
        SELECT 1 FROM public.risk_cases AS c
         WHERE c.risk_case_pk = public.risk_case_entities.risk_case_pk
           AND c.tenant_pk = public.iam_current_tenant_pk()
    ))
    WITH CHECK (EXISTS (
        SELECT 1 FROM public.risk_cases AS c
         WHERE c.risk_case_pk = public.risk_case_entities.risk_case_pk
           AND c.tenant_pk = public.iam_current_tenant_pk()
    ));

ALTER TABLE public.risk_case_actions ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.risk_case_actions FORCE ROW LEVEL SECURITY;
CREATE POLICY risk_case_actions_tenant_policy ON public.risk_case_actions
    USING (EXISTS (
        SELECT 1 FROM public.risk_cases AS c
         WHERE c.risk_case_pk = public.risk_case_actions.risk_case_pk
           AND c.tenant_pk = public.iam_current_tenant_pk()
    ))
    WITH CHECK (EXISTS (
        SELECT 1 FROM public.risk_cases AS c
         WHERE c.risk_case_pk = public.risk_case_actions.risk_case_pk
           AND c.tenant_pk = public.iam_current_tenant_pk()
    ));

COMMENT ON FUNCTION public.iam_current_tenant_pk() IS
    'Fail-closed transaction tenant UUID resolver. Platform cross-tenant work must use the separately granted iam_platform role, never a client-controlled bypass variable.';

-- The helper was created after the bulk ownership pass.
ALTER FUNCTION public.iam_current_tenant_pk() OWNER TO iam_owner;

DO $drop_temporary_membership$
BEGIN
    IF pg_catalog.current_setting(
        'iam.bootstrap_was_owner_member', true
    ) = 'false' THEN
        EXECUTE pg_catalog.format(
            'REVOKE iam_owner FROM %I', pg_catalog.current_user
        );
    END IF;
END
$drop_temporary_membership$;

COMMIT;
