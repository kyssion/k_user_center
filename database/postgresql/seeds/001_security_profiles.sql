\set ON_ERROR_STOP on

SET ROLE iam_owner;

WITH seed(id, config_code, payload) AS (
    VALUES
        ('10000000-0000-0000-0000-000000000001'::uuid, 'SP1', '{"authentication":{"flow":"authorization_code","pkce":"S256","minimum_aal":"AAL1"},"token":{"access_token_max_seconds":900,"refresh_rotation":"required"},"risk":{"mode":"baseline"}}'::jsonb),
        ('10000000-0000-0000-0000-000000000002'::uuid, 'SP1-D', '{"authentication":{"flow":"device_authorization_grant","minimum_aal":"AAL1","user_confirmation":"required"},"device_authorization":{"device_code":"short_lived","user_code":"short_lived","polling_rate_limit":"required","scope_confirmation":"required","password_fallback":"forbidden"},"token":{"access_token_max_seconds":900,"refresh_rotation":"required"},"risk":{"mode":"baseline"}}'::jsonb),
        ('10000000-0000-0000-0000-000000000003'::uuid, 'SP2', '{"authentication":{"minimum_aal":"AAL2","max_authentication_age_seconds":300,"step_up_for_sensitive":true},"authorization":{"realtime":"required"},"token":{"access_token_max_seconds":300},"risk":{"mode":"adaptive","realtime":"required"}}'::jsonb),
        ('10000000-0000-0000-0000-000000000004'::uuid, 'SP3', '{"authentication":{"phishing_resistant_mfa":"required"},"session":{"absolute_max_seconds":43200,"idle_max_seconds":1800},"token":{"access_token_max_seconds":300},"approval":{"jit_or_approval":"required"},"administration":{"trusted_endpoint":"required"},"audit":{"mode":"strong"},"risk":{"mode":"strict"}}'::jsonb),
        ('10000000-0000-0000-0000-000000000005'::uuid, 'SP4', '{"subject_type":"machine","client_authentication":{"methods":["private_key_jwt","mtls"]},"token":{"access_token_max_seconds":300,"refresh_token":"forbidden","explicit_audience":"required","automatic_key_rotation":"required"}}'::jsonb),
        ('10000000-0000-0000-0000-000000000006'::uuid, 'SP5', '{"protocol":{"profile":"FAPI_2_0","par":"required"},"client_authentication":{"strict":"required"},"token":{"access_token_max_seconds":120,"sender_constraint":{"required":true,"methods":["DPoP","mTLS"]}},"approval":{"dual_control_required":true},"risk":{"mode":"maximum"}}'::jsonb)
), applied AS (
INSERT INTO iam.configuration_versions AS current_version (
    id, config_type, config_code, scope_type, scope_id, version, schema_version,
    payload, payload_digest, state, created_by_type, created_by_id, published_at
)
SELECT
    id, 'SECURITY_PROFILE', config_code, 'PLATFORM', NULL, 1, 2,
    payload, encode(sha256(convert_to(payload::text, 'UTF8')), 'hex'),
    'DRAFT', 'SYSTEM_BOOTSTRAP', '00000000-0000-0000-0000-000000000001'::uuid, NULL
FROM seed
ON CONFLICT ON CONSTRAINT uq_configuration_version DO UPDATE
SET id = current_version.id
WHERE current_version.id = EXCLUDED.id
  AND current_version.schema_version = EXCLUDED.schema_version
  AND current_version.payload_digest = EXCLUDED.payload_digest
RETURNING 1
)
SELECT 1 / CASE WHEN (SELECT count(*) FROM applied) = (SELECT count(*) FROM seed) THEN 1 ELSE 0 END AS seed_content_match;
