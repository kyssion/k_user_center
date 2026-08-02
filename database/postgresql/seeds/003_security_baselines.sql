\set ON_ERROR_STOP on

SET ROLE iam_owner;

WITH seed(id, config_type, config_code, payload) AS (
    VALUES
        ('30000000-0000-0000-0000-000000000001'::uuid, 'ALGORITHM_ALLOWLIST', 'DEFAULT', '{"password_hash":["ARGON2ID"],"signing":["ES256","PS256"],"pkce":["S256"],"forbidden":["none","RS1","plain"]}'::jsonb),
        ('30000000-0000-0000-0000-000000000002'::uuid, 'SLO_BASELINE', 'DEFAULT', '{"availability_target":0.9995,"token_p99_ms":300,"authorization_p99_ms":100,"recovery_rto_minutes":60,"recovery_rpo_minutes":5}'::jsonb),
        ('30000000-0000-0000-0000-000000000003'::uuid, 'DURATION_BASELINE', 'DEFAULT', '{"authorization_code_seconds":60,"login_transaction_seconds":600,"challenge_seconds":300,"access_token_seconds":900,"refresh_token_days":30,"invitation_hours":24}'::jsonb),
        ('30000000-0000-0000-0000-000000000004'::uuid, 'DATA_CATALOG', 'DEFAULT', '{"classes":["PUBLIC","INTERNAL","PERSONAL","SENSITIVE_PERSONAL","SECRET"],"default":"INTERNAL","deny_unknown":true}'::jsonb),
        ('30000000-0000-0000-0000-000000000005'::uuid, 'RETENTION_POLICY', 'DEFAULT', '{"audit_days":2555,"authentication_attempt_days":180,"risk_signal_days":365,"message_delivery_days":180,"legal_hold_overrides":true}'::jsonb),
        ('30000000-0000-0000-0000-000000000006'::uuid, 'DEPENDENCY_FAILURE_POLICY', 'DEFAULT', '{"authorization":"fail_closed","revocation":"fail_closed","risk":"step_up_or_deny","messaging":"queue_and_retry"}'::jsonb)
)
INSERT INTO iam.configuration_versions (
    id, config_type, config_code, scope_type, scope_id, version, schema_version,
    payload, payload_digest, state, created_by_type, created_by_id, published_at
)
SELECT
    id, config_type, config_code, 'PLATFORM', NULL, 1, 1,
    payload, encode(sha256(convert_to(payload::text, 'UTF8')), 'hex'),
    'PUBLISHED', 'SYSTEM', '00000000-0000-0000-0000-000000000001'::uuid, CURRENT_TIMESTAMP
FROM seed
ON CONFLICT ON CONSTRAINT uq_configuration_version DO NOTHING;

