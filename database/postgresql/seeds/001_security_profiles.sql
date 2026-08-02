\set ON_ERROR_STOP on

SET ROLE iam_owner;

WITH seed(id, config_code, payload) AS (
    VALUES
        ('10000000-0000-0000-0000-000000000001'::uuid, 'SP1', '{"authentication":{"minimum_aal":"AAL1"},"token":{"access_token_seconds":900},"risk":{"mode":"baseline"}}'::jsonb),
        ('10000000-0000-0000-0000-000000000002'::uuid, 'SP1-D', '{"authentication":{"minimum_aal":"AAL1"},"token":{"access_token_seconds":900},"device":{"binding":"required"},"risk":{"mode":"baseline"}}'::jsonb),
        ('10000000-0000-0000-0000-000000000003'::uuid, 'SP2', '{"authentication":{"minimum_aal":"AAL2","step_up_for_sensitive":true},"token":{"access_token_seconds":600},"risk":{"mode":"adaptive"}}'::jsonb),
        ('10000000-0000-0000-0000-000000000004'::uuid, 'SP3', '{"authentication":{"minimum_aal":"AAL2","phishing_resistant_preferred":true},"token":{"access_token_seconds":300},"risk":{"mode":"strict"}}'::jsonb),
        ('10000000-0000-0000-0000-000000000005'::uuid, 'SP4', '{"authentication":{"minimum_aal":"AAL3","phishing_resistant_required":true},"token":{"access_token_seconds":300},"approval":{"high_risk_required":true}}'::jsonb),
        ('10000000-0000-0000-0000-000000000006'::uuid, 'SP5', '{"authentication":{"minimum_aal":"AAL3","hardware_bound_required":true},"token":{"access_token_seconds":180},"approval":{"dual_control_required":true},"risk":{"mode":"maximum"}}'::jsonb)
)
INSERT INTO iam.configuration_versions (
    id, config_type, config_code, scope_type, scope_id, version, schema_version,
    payload, payload_digest, state, created_by_type, created_by_id, published_at
)
SELECT
    id, 'SECURITY_PROFILE', config_code, 'PLATFORM', NULL, 1, 1,
    payload, encode(sha256(convert_to(payload::text, 'UTF8')), 'hex'),
    'PUBLISHED', 'SYSTEM', '00000000-0000-0000-0000-000000000001'::uuid, CURRENT_TIMESTAMP
FROM seed
ON CONFLICT ON CONSTRAINT uq_configuration_version DO NOTHING;

