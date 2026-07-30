\set ON_ERROR_STOP 1

\echo 'Verifying IAM PostgreSQL schema...'

BEGIN;

DO $verify_core_objects$
DECLARE
    missing text[];
BEGIN
    SELECT array_agg(expected.name ORDER BY expected.name)
      INTO missing
      FROM (
        VALUES
            ('iam_principals'),
            ('iam_users'),
            ('iam_identifiers'),
            ('iam_identity_bindings'),
            ('fed_external_identities'),
            ('org_tenants'),
            ('org_memberships'),
            ('auth_authenticators'),
            ('auth_challenges'),
            ('oauth_sessions'),
            ('oauth_grants'),
            ('oauth_token_families'),
            ('oauth_refresh_tokens'),
            ('app_clients'),
            ('app_api_resources'),
            ('app_machine_principals'),
            ('priv_consents'),
            ('priv_privacy_requests'),
            ('authz_roles'),
            ('authz_assignments'),
            ('risk_assessments'),
            ('ctrl_releases'),
            ('key_crypto_key_versions'),
            ('evt_outbox'),
            ('audit_events'),
            ('ops_operations'),
            ('ref_security_profiles')
      ) AS expected(name)
     WHERE pg_catalog.to_regclass('public.' || expected.name) IS NULL;

    IF missing IS NOT NULL THEN
        RAISE EXCEPTION 'missing core tables: %', missing;
    END IF;

    RAISE NOTICE 'core table verification passed';
END
$verify_core_objects$;

DO $verify_functions$
DECLARE
    missing text[];
BEGIN
    SELECT array_agg(expected.name ORDER BY expected.name)
      INTO missing
      FROM (
        VALUES
            ('iam_uuid_is_v4'),
            ('iam_bind_identifier'),
            ('auth_consume_challenge'),
            ('oauth_rotate_refresh_token'),
            ('iam_freeze_user'),
            ('audit_append_event'),
            ('iam_current_tenant_pk')
      ) AS expected(name)
     WHERE NOT EXISTS (
        SELECT 1
          FROM pg_catalog.pg_proc AS p
          JOIN pg_catalog.pg_namespace AS n ON n.oid = p.pronamespace
         WHERE n.nspname = 'public'
           AND p.proname = expected.name
     );

    IF missing IS NOT NULL THEN
        RAISE EXCEPTION 'missing core functions: %', missing;
    END IF;

    IF EXISTS (
        SELECT 1
          FROM pg_catalog.pg_proc AS p
          JOIN pg_catalog.pg_namespace AS n ON n.oid = p.pronamespace
         WHERE n.nspname = 'public'
           AND p.prosecdef
           AND (
               p.proconfig IS NULL
               OR NOT EXISTS (
                   SELECT 1
                     FROM unnest(p.proconfig) AS setting
                    WHERE setting = 'search_path=pg_catalog, public'
                       OR setting = 'search_path=pg_catalog,public'
               )
           )
    ) THEN
        RAISE EXCEPTION
            'one or more SECURITY DEFINER functions do not pin search_path';
    END IF;

    RAISE NOTICE 'function and SECURITY DEFINER verification passed';
END
$verify_functions$;

DO $verify_constraints$
DECLARE
    table_name text;
BEGIN
    FOREACH table_name IN ARRAY ARRAY[
        'iam_users',
        'iam_identity_bindings',
        'fed_external_identities',
        'org_memberships',
        'auth_authenticators',
        'auth_challenges',
        'oauth_token_families',
        'oauth_refresh_tokens',
        'app_clients',
        'priv_consents',
        'authz_assignments',
        'ctrl_releases',
        'key_crypto_key_versions'
    ] LOOP
        IF NOT EXISTS (
            SELECT 1
              FROM pg_catalog.pg_constraint AS c
              JOIN pg_catalog.pg_class AS t ON t.oid = c.conrelid
              JOIN pg_catalog.pg_namespace AS n ON n.oid = t.relnamespace
             WHERE n.nspname = 'public'
               AND t.relname = table_name
               AND c.contype = 'c'
        ) THEN
            RAISE EXCEPTION 'table public.% has no CHECK constraint', table_name;
        END IF;
    END LOOP;

    IF NOT EXISTS (
        SELECT 1
          FROM pg_catalog.pg_indexes
         WHERE schemaname = 'public'
           AND tablename = 'oauth_refresh_tokens'
           AND indexdef ILIKE '%UNIQUE%'
           AND indexdef ILIKE '%WHERE%'
           AND indexdef ILIKE '%CURRENT%'
    ) THEN
        RAISE EXCEPTION
            'missing partial unique index for CURRENT refresh token';
    END IF;

    IF NOT EXISTS (
        SELECT 1
          FROM pg_catalog.pg_indexes
         WHERE schemaname = 'public'
           AND tablename = 'iam_identity_bindings'
           AND indexdef ILIKE '%UNIQUE%'
           AND indexdef ILIKE '%WHERE%'
    ) THEN
        RAISE EXCEPTION
            'missing partial unique index for active identity binding';
    END IF;

    RAISE NOTICE 'CHECK and partial unique verification passed';
END
$verify_constraints$;

DO $verify_roles_and_rls$
DECLARE
    role_name text;
BEGIN
    FOREACH role_name IN ARRAY ARRAY[
        'iam_owner',
        'iam_migrator',
        'iam_api',
        'iam_auth',
        'iam_dispatcher',
        'iam_audit_writer',
        'iam_audit_reader'
    ] LOOP
        IF NOT EXISTS (
            SELECT 1
              FROM pg_catalog.pg_roles
             WHERE rolname = role_name
               AND NOT rolcanlogin
        ) THEN
            RAISE EXCEPTION 'missing NOLOGIN role %', role_name;
        END IF;
    END LOOP;

    IF EXISTS (
        SELECT 1
          FROM pg_catalog.pg_roles
         WHERE rolname IN (
             'iam_api', 'iam_auth', 'iam_dispatcher',
             'iam_audit_writer', 'iam_audit_reader'
         )
           AND rolbypassrls
    ) THEN
        RAISE EXCEPTION 'a runtime role has BYPASSRLS';
    END IF;

    IF NOT EXISTS (
        SELECT 1
          FROM pg_catalog.pg_class AS c
          JOIN pg_catalog.pg_namespace AS n ON n.oid = c.relnamespace
         WHERE n.nspname = 'public'
           AND c.relrowsecurity
           AND c.relforcerowsecurity
    ) THEN
        RAISE EXCEPTION 'no FORCE ROW LEVEL SECURITY table found';
    END IF;

    IF EXISTS (
        SELECT 1
          FROM information_schema.role_table_grants
         WHERE table_schema = 'public'
           AND grantee = 'PUBLIC'
    ) THEN
        RAISE EXCEPTION 'PUBLIC retains table privileges';
    END IF;

    RAISE NOTICE 'role, grant, and RLS verification passed';
END
$verify_roles_and_rls$;

DO $verify_partitioning_and_seed$
BEGIN
    IF NOT EXISTS (
        SELECT 1
          FROM pg_catalog.pg_partitioned_table AS p
          JOIN pg_catalog.pg_class AS c ON c.oid = p.partrelid
          JOIN pg_catalog.pg_namespace AS n ON n.oid = c.relnamespace
         WHERE n.nspname = 'public'
           AND c.relname = 'audit_events'
    ) THEN
        RAISE EXCEPTION 'audit_events is not partitioned';
    END IF;

    IF (SELECT count(*) FROM public.ref_security_profiles) <> 5 THEN
        RAISE EXCEPTION 'expected exactly five SP1-SP5 security profiles';
    END IF;

    IF EXISTS (
        SELECT 1
          FROM public.ref_security_profiles
         WHERE profile_code NOT IN ('SP1', 'SP2', 'SP3', 'SP4', 'SP5')
    ) THEN
        RAISE EXCEPTION 'unexpected security profile seed';
    END IF;

    RAISE NOTICE 'partition and reference-data verification passed';
END
$verify_partitioning_and_seed$;

ROLLBACK;

\echo 'IAM PostgreSQL schema verification completed successfully.'
