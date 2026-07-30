-- Fixed security profiles and governed reference catalogues.
-- This bootstrap is intentionally one-shot: plain INSERT and natural/UUID
-- uniqueness make unexpected pre-existing or drifted rows fail visibly.

BEGIN;

SET LOCAL ROLE iam_owner;

CREATE TABLE public.ref_security_profiles (
    security_profile_pk bigint GENERATED ALWAYS AS IDENTITY,
    security_profile_id uuid NOT NULL,
    profile_code text COLLATE "C" NOT NULL,
    display_name text NOT NULL,
    allowed_client_type text COLLATE "C" NOT NULL,
    minimum_aal smallint NOT NULL,
    require_pkce boolean NOT NULL,
    require_par boolean NOT NULL,
    require_sender_constraint boolean NOT NULL,
    maximum_access_token_ttl_seconds integer NOT NULL,
    maximum_refresh_token_ttl_seconds integer,
    status text COLLATE "C" NOT NULL DEFAULT 'ACTIVE',
    created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    CONSTRAINT ref_security_profiles_pkey PRIMARY KEY (security_profile_pk),
    CONSTRAINT ref_security_profiles_id_key UNIQUE (security_profile_id),
    CONSTRAINT ref_security_profiles_code_key UNIQUE (profile_code),
    CONSTRAINT ref_security_profiles_id_v4_ck
        CHECK (public.iam_uuid_is_v4(security_profile_id)),
    CONSTRAINT ref_security_profiles_code_ck
        CHECK (profile_code IN ('SP1', 'SP2', 'SP3', 'SP4', 'SP5')),
    CONSTRAINT ref_security_profiles_client_type_ck
        CHECK (allowed_client_type IN ('PUBLIC', 'CONFIDENTIAL', 'ANY')),
    CONSTRAINT ref_security_profiles_aal_ck
        CHECK (minimum_aal BETWEEN 1 AND 3),
    CONSTRAINT ref_security_profiles_ttl_ck CHECK (
        maximum_access_token_ttl_seconds BETWEEN 30 AND 3600
        AND (
            maximum_refresh_token_ttl_seconds IS NULL
            OR maximum_refresh_token_ttl_seconds BETWEEN 60 AND 31536000
        )
    ),
    CONSTRAINT ref_security_profiles_status_ck
        CHECK (status IN ('ACTIVE', 'RETIRED'))
);

COMMENT ON TABLE public.ref_security_profiles IS
    'Fixed SP1-SP5 security-profile lookup. Client publication must verify app_clients settings do not exceed these ceilings; the existing text CHECK remains the stable storage contract.';

CREATE TRIGGER ref_security_profiles_immutable_trg
BEFORE UPDATE OR DELETE ON public.ref_security_profiles
FOR EACH ROW EXECUTE FUNCTION public.iam_reject_row_mutation();

INSERT INTO public.ref_security_profiles (
    security_profile_id, profile_code, display_name, allowed_client_type,
    minimum_aal, require_pkce, require_par, require_sender_constraint,
    maximum_access_token_ttl_seconds, maximum_refresh_token_ttl_seconds
) VALUES
    ('40000000-0000-4000-8000-000000000001', 'SP1',
     'Public baseline', 'PUBLIC', 1, true, false, false, 900, 2592000),
    ('40000000-0000-4000-8000-000000000002', 'SP2',
     'Public elevated', 'PUBLIC', 2, true, false, false, 600, 1209600),
    ('40000000-0000-4000-8000-000000000003', 'SP3',
     'Confidential baseline', 'CONFIDENTIAL', 2, true, false, false, 600, 1209600),
    ('40000000-0000-4000-8000-000000000004', 'SP4',
     'Confidential high assurance', 'CONFIDENTIAL', 2, true, true, false, 300, 604800),
    ('40000000-0000-4000-8000-000000000005', 'SP5',
     'High value sender constrained', 'CONFIDENTIAL', 3, true, true, true, 300, 86400);

INSERT INTO public.priv_data_categories (
    data_category_id, category_code, parent_category_pk, sensitivity_level
) VALUES
    ('30000000-0000-4000-8000-000000000001',
     'PUBLIC_DATA', NULL, 'S0'),
    ('30000000-0000-4000-8000-000000000002',
     'INTERNAL_METADATA', NULL, 'S1'),
    ('30000000-0000-4000-8000-000000000003',
     'IDENTITY_DATA', NULL, 'S2'),
    ('30000000-0000-4000-8000-000000000005',
     'AUTHENTICATION_DATA', NULL, 'S4'),
    ('30000000-0000-4000-8000-000000000006',
     'AUTHORIZATION_DATA', NULL, 'S2'),
    ('30000000-0000-4000-8000-000000000007',
     'SECURITY_TELEMETRY', NULL, 'S3'),
    ('30000000-0000-4000-8000-000000000008',
     'PRIVACY_EVIDENCE', NULL, 'S3');

INSERT INTO public.priv_data_categories (
    data_category_id, category_code, parent_category_pk, sensitivity_level
)
SELECT
    '30000000-0000-4000-8000-000000000004'::uuid,
    'CONTACT_PII',
    c.data_category_pk,
    'S3'
FROM public.priv_data_categories AS c
WHERE c.category_code = 'IDENTITY_DATA';

INSERT INTO public.authz_actions (
    action_id, action_code, risk_level
) VALUES
    ('10000000-0000-4000-8000-000000000001', 'read', 'LOW'),
    ('10000000-0000-4000-8000-000000000002', 'create', 'MEDIUM'),
    ('10000000-0000-4000-8000-000000000003', 'update', 'MEDIUM'),
    ('10000000-0000-4000-8000-000000000004', 'delete', 'HIGH'),
    ('10000000-0000-4000-8000-000000000005', 'approve', 'HIGH'),
    ('10000000-0000-4000-8000-000000000006', 'activate', 'CRITICAL'),
    ('10000000-0000-4000-8000-000000000007', 'revoke', 'HIGH'),
    ('10000000-0000-4000-8000-000000000008', 'export', 'HIGH'),
    ('10000000-0000-4000-8000-000000000009', 'freeze', 'CRITICAL'),
    ('10000000-0000-4000-8000-000000000010', 'bind', 'HIGH');

INSERT INTO public.authz_permissions (
    permission_id, permission_code, resource_type, action_pk, risk_level
)
SELECT seed.permission_id, seed.permission_code, seed.resource_type,
       action.action_pk, seed.risk_level
FROM (
    VALUES
        ('20000000-0000-4000-8000-000000000001'::uuid,
         'identity.user.read', 'IAM_USER', 'read', 'MEDIUM'),
        ('20000000-0000-4000-8000-000000000002'::uuid,
         'identity.user.update', 'IAM_USER', 'update', 'HIGH'),
        ('20000000-0000-4000-8000-000000000003'::uuid,
         'identity.user.freeze', 'IAM_USER', 'freeze', 'CRITICAL'),
        ('20000000-0000-4000-8000-000000000004'::uuid,
         'identity.identifier.read', 'IAM_IDENTIFIER', 'read', 'HIGH'),
        ('20000000-0000-4000-8000-000000000005'::uuid,
         'identity.identifier.bind', 'IAM_IDENTIFIER', 'bind', 'HIGH'),
        ('20000000-0000-4000-8000-000000000006'::uuid,
         'authentication.authenticator.read', 'AUTH_AUTHENTICATOR', 'read', 'HIGH'),
        ('20000000-0000-4000-8000-000000000007'::uuid,
         'authentication.authenticator.update', 'AUTH_AUTHENTICATOR', 'update', 'CRITICAL'),
        ('20000000-0000-4000-8000-000000000008'::uuid,
         'session.session.read', 'OAUTH_SESSION', 'read', 'MEDIUM'),
        ('20000000-0000-4000-8000-000000000009'::uuid,
         'session.session.revoke', 'OAUTH_SESSION', 'revoke', 'HIGH'),
        ('20000000-0000-4000-8000-000000000010'::uuid,
         'tenant.tenant.read', 'ORG_TENANT', 'read', 'MEDIUM'),
        ('20000000-0000-4000-8000-000000000011'::uuid,
         'tenant.tenant.update', 'ORG_TENANT', 'update', 'HIGH'),
        ('20000000-0000-4000-8000-000000000012'::uuid,
         'tenant.membership.read', 'ORG_MEMBERSHIP', 'read', 'MEDIUM'),
        ('20000000-0000-4000-8000-000000000013'::uuid,
         'tenant.membership.update', 'ORG_MEMBERSHIP', 'update', 'HIGH'),
        ('20000000-0000-4000-8000-000000000014'::uuid,
         'client.client.read', 'APP_CLIENT', 'read', 'MEDIUM'),
        ('20000000-0000-4000-8000-000000000015'::uuid,
         'client.client.update', 'APP_CLIENT', 'update', 'HIGH'),
        ('20000000-0000-4000-8000-000000000016'::uuid,
         'policy.policy.read', 'AUTHZ_POLICY', 'read', 'MEDIUM'),
        ('20000000-0000-4000-8000-000000000017'::uuid,
         'policy.policy.approve', 'AUTHZ_POLICY', 'approve', 'HIGH'),
        ('20000000-0000-4000-8000-000000000018'::uuid,
         'policy.policy.activate', 'AUTHZ_POLICY', 'activate', 'CRITICAL'),
        ('20000000-0000-4000-8000-000000000019'::uuid,
         'privacy.request.read', 'PRIVACY_REQUEST', 'read', 'HIGH'),
        ('20000000-0000-4000-8000-000000000020'::uuid,
         'privacy.request.export', 'PRIVACY_REQUEST', 'export', 'CRITICAL'),
        ('20000000-0000-4000-8000-000000000021'::uuid,
         'key.key.read', 'CRYPTO_KEY', 'read', 'HIGH'),
        ('20000000-0000-4000-8000-000000000022'::uuid,
         'key.key.revoke', 'CRYPTO_KEY', 'revoke', 'CRITICAL'),
        ('20000000-0000-4000-8000-000000000023'::uuid,
         'audit.event.read', 'AUDIT_EVENT', 'read', 'HIGH'),
        ('20000000-0000-4000-8000-000000000024'::uuid,
         'privacy.request.delete', 'PRIVACY_REQUEST', 'delete', 'CRITICAL')
) AS seed(permission_id, permission_code, resource_type, action_code, risk_level)
JOIN public.authz_actions AS action
  ON action.action_code = seed.action_code;

COMMENT ON TABLE public.priv_data_categories IS
    'Governed hierarchical data categories. Core S0-S4 categories are seeded by 130; additions require privacy/security review and cycle verification.';
COMMENT ON TABLE public.authz_actions IS
    'Stable action catalogue seeded with core read/create/update/delete/approve/activate/revoke/export/freeze/bind actions; codes are never repurposed.';
COMMENT ON TABLE public.authz_permissions IS
    'Core permission catalogue seeded by 130. Absence of an assignment remains deny; application PDP/PEP must enforce deny-overrides, obligations and commit-point re-evaluation.';

GRANT SELECT ON public.ref_security_profiles TO
    iam_api, iam_auth, iam_control, iam_readonly;

COMMIT;
