\set ON_ERROR_STOP on

SET ROLE iam_owner;

WITH seed(id, config_type, config_code, payload) AS (
    VALUES
        ('30000000-0000-0000-0000-000000000001'::uuid, 'ALGORITHM_ALLOWLIST', 'DEFAULT', '{"password_hash":["ARGON2ID"],"signing":["ES256","PS256"],"pkce":["S256"],"forbidden":["none","RS1","plain"]}'::jsonb),
        ('30000000-0000-0000-0000-000000000002'::uuid, 'SLO_BASELINE', 'DEFAULT', '{"SLO-AUTH-001":{"monthly_availability_min":0.9999},"SLO-API-001":{"monthly_availability_min":0.999},"SLO-TOKEN-001":{"p95_ms_max":150,"p99_ms_max":300},"SLO-AUTHZ-001":{"p99_ms_max":50},"SLO-REVOKE-001":{"p99_seconds_max":30,"hard_seconds_max":60},"SLO-REVOKE-002":{"staleness_seconds_max":300},"SLO-EVENT-001":{"percentile":0.999,"visible_seconds_max":60},"SLO-PRIV-001":{"substantive_response_workdays_max":15,"completion_days_max":30},"SLO-ALERT-001":{"p1_ack_minutes_max":15,"p1_response_minutes_max":60},"SLO-DR-001":{"regional_rto_minutes_max":30,"c2_rpo_minutes_max":5},"SLO-DR-002":{"c0_c1_security_state_rpo_seconds":0},"SLO-HA-001":{"same_az_database_rpo_seconds":0}}'::jsonb),
        ('30000000-0000-0000-0000-000000000003'::uuid, 'DURATION_BASELINE', 'DEFAULT', '{"TTL-TOKEN-001":{"sp1_access_token_seconds_max":900,"sp2_sp3_access_token_seconds_max":300,"sp5_access_token_seconds_max":120},"TTL-TOKEN-002":{"machine_access_token_seconds_max":300},"TTL-TOKEN-003":{"sp1_absolute_days_max":90,"sp1_idle_days_max":30,"sp2_absolute_days_max":30,"sp3_absolute_days_max":1,"sp4_refresh_token":"forbidden","sp5_sender_constraint":"required"},"TTL-TOKEN-004":{"id_token_seconds_max":300},"TTL-CODE-001":{"authorization_code_seconds_max":60,"single_use":true},"TTL-SESSION-001":{"normal_absolute_days_max":30,"normal_idle_days_max":7,"sp3_absolute_hours_max":12,"sp3_idle_minutes_max":30},"TTL-LOGINTX-001":{"login_transaction_seconds_max":900,"single_use":true},"TTL-CHALLENGE-001":{"challenge_seconds_max":300,"attempts_max":5,"send_interval_seconds_min":60},"TTL-STEPUP-001":{"authentication_age_seconds_max":300},"TTL-JWKS-001":{"stage0_registration_required":true,"publish_before_signing_cache_multiplier_min":2,"old_key_retention_formula":"max_token_ttl + jwks_max_age + clock_skew"},"TERM-DELETE-001":{"default_days":15,"days_min":7},"TERM-REBIND-001":{"protection_hours_min":24},"TERM-IDENTIFIER-001":{"phone_quarantine_days_min":90,"enterprise_email_quarantine_days_min":180,"username_reuse":"forbidden"},"TERM-RECOVERY-001":{"wait_hours_min":24,"wait_hours_max":72},"TERM-RECOVERY-002":{"observation_days_min":7},"TERM-TENANT-001":{"ownership_transfer_wait_hours_min":72},"TERM-DORMANT-001":{"default_months":18},"TERM-EXCEPTION-001":{"validity_months_max":6},"TERM-KEY-001":{"rotation_days_max":90},"TERM-EXPORT-001":{"download_hours_max":24}}'::jsonb),
        ('30000000-0000-0000-0000-000000000004'::uuid, 'DATA_CATALOG', 'DEFAULT', '{"classes":["PUBLIC","INTERNAL","PERSONAL","SENSITIVE_PERSONAL","SECRET"],"default":"INTERNAL","deny_unknown":true}'::jsonb),
        ('30000000-0000-0000-0000-000000000006'::uuid, 'DEPENDENCY_FAILURE_POLICY', 'DEFAULT', '{"authorization":"fail_closed","revocation":"fail_closed","risk":"step_up_or_deny","messaging":"queue_and_retry"}'::jsonb)
), applied AS (
INSERT INTO iam.configuration_versions AS current_version (
    id, config_type, config_code, scope_type, scope_id, version, schema_version,
    payload, payload_digest, state, created_by_type, created_by_id, published_at
)
SELECT
    id, config_type, config_code, 'PLATFORM', NULL, 1, 2,
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
