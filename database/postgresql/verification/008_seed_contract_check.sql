\set ON_ERROR_STOP on

DO $seed_contract$
DECLARE
    missing_profiles text;
    invalid_profiles text;
    missing_slos text;
    missing_durations text;
    invalid_baseline boolean;
    invalid_seed_state text;
    permission_count integer;
    template_count integer;
    event_schema_count integer;
    invalid_event_schemas text;
BEGIN
    SELECT string_agg(required.code, ', ' ORDER BY required.code)
      INTO missing_profiles
      FROM (VALUES ('SP1'),('SP1-D'),('SP2'),('SP3'),('SP4'),('SP5')) AS required(code)
     WHERE NOT EXISTS (
        SELECT 1
          FROM iam.configuration_versions c
         WHERE c.config_type = 'SECURITY_PROFILE'
           AND c.config_code = required.code
           AND c.scope_type = 'PLATFORM'
           AND c.scope_id IS NULL
           AND c.version = 1
     );

    SELECT string_agg(c.config_code, ', ' ORDER BY c.config_code)
      INTO invalid_profiles
      FROM iam.configuration_versions c
     WHERE c.config_type = 'SECURITY_PROFILE'
       AND c.version = 1
       AND (
            (c.config_code = 'SP1' AND (
                c.payload #>> '{authentication,flow}' IS DISTINCT FROM 'authorization_code'
                OR c.payload #>> '{authentication,pkce}' IS DISTINCT FROM 'S256'
                OR coalesce((c.payload #>> '{token,access_token_max_seconds}')::integer, 2147483647) > 900
                OR c.payload #>> '{token,refresh_rotation}' IS DISTINCT FROM 'required'
            ))
         OR (c.config_code = 'SP1-D' AND (
                c.payload #>> '{authentication,flow}' IS DISTINCT FROM 'device_authorization_grant'
                OR c.payload #>> '{device_authorization,device_code}' IS DISTINCT FROM 'short_lived'
                OR c.payload #>> '{device_authorization,user_code}' IS DISTINCT FROM 'short_lived'
                OR c.payload #>> '{device_authorization,polling_rate_limit}' IS DISTINCT FROM 'required'
                OR c.payload #>> '{device_authorization,scope_confirmation}' IS DISTINCT FROM 'required'
                OR c.payload #>> '{device_authorization,password_fallback}' IS DISTINCT FROM 'forbidden'
            ))
         OR (c.config_code = 'SP2' AND (
                coalesce((c.payload #>> '{token,access_token_max_seconds}')::integer, 2147483647) > 300
                OR coalesce((c.payload #>> '{authentication,max_authentication_age_seconds}')::integer, 2147483647) > 300
                OR c.payload #>> '{authorization,realtime}' IS DISTINCT FROM 'required'
            ))
         OR (c.config_code = 'SP3' AND (
                c.payload #>> '{authentication,phishing_resistant_mfa}' IS DISTINCT FROM 'required'
                OR coalesce((c.payload #>> '{token,access_token_max_seconds}')::integer, 2147483647) > 300
                OR coalesce((c.payload #>> '{session,absolute_max_seconds}')::integer, 2147483647) > 43200
                OR coalesce((c.payload #>> '{session,idle_max_seconds}')::integer, 2147483647) > 1800
            ))
         OR (c.config_code = 'SP4' AND (
                c.payload #>> '{subject_type}' IS DISTINCT FROM 'machine'
                OR (c.payload #> '{client_authentication,methods}' ? 'private_key_jwt') IS DISTINCT FROM true
                OR (c.payload #> '{client_authentication,methods}' ? 'mtls') IS DISTINCT FROM true
                OR coalesce((c.payload #>> '{token,access_token_max_seconds}')::integer, 2147483647) > 300
                OR c.payload #>> '{token,refresh_token}' IS DISTINCT FROM 'forbidden'
                OR c.payload #>> '{token,explicit_audience}' IS DISTINCT FROM 'required'
                OR c.payload #>> '{token,automatic_key_rotation}' IS DISTINCT FROM 'required'
            ))
         OR (c.config_code = 'SP5' AND (
                c.payload #>> '{protocol,profile}' IS DISTINCT FROM 'FAPI_2_0'
                OR c.payload #>> '{protocol,par}' IS DISTINCT FROM 'required'
                OR c.payload #>> '{client_authentication,strict}' IS DISTINCT FROM 'required'
                OR coalesce((c.payload #>> '{token,access_token_max_seconds}')::integer, 2147483647) > 120
                OR c.payload #>> '{token,sender_constraint,required}' IS DISTINCT FROM 'true'
                OR (c.payload #> '{token,sender_constraint,methods}' ? 'DPoP') IS DISTINCT FROM true
                OR (c.payload #> '{token,sender_constraint,methods}' ? 'mTLS') IS DISTINCT FROM true
            ))
       );

    SELECT string_agg(required.id, ', ' ORDER BY required.id)
      INTO missing_slos
      FROM (VALUES
        ('SLO-AUTH-001'),('SLO-API-001'),('SLO-TOKEN-001'),('SLO-AUTHZ-001'),
        ('SLO-REVOKE-001'),('SLO-REVOKE-002'),('SLO-EVENT-001'),('SLO-PRIV-001'),
        ('SLO-ALERT-001'),('SLO-DR-001'),('SLO-DR-002'),('SLO-HA-001')
      ) AS required(id)
     WHERE NOT EXISTS (
        SELECT 1 FROM iam.configuration_versions c
         WHERE c.config_type = 'SLO_BASELINE'
           AND c.config_code = 'DEFAULT'
           AND c.version = 1
           AND c.payload ? required.id
     );

    SELECT string_agg(required.id, ', ' ORDER BY required.id)
      INTO missing_durations
      FROM (VALUES
        ('TTL-TOKEN-001'),('TTL-TOKEN-002'),('TTL-TOKEN-003'),('TTL-TOKEN-004'),('TTL-CODE-001'),
        ('TTL-SESSION-001'),('TTL-LOGINTX-001'),('TTL-CHALLENGE-001'),('TTL-STEPUP-001'),('TTL-JWKS-001'),
        ('TERM-DELETE-001'),('TERM-REBIND-001'),('TERM-IDENTIFIER-001'),('TERM-RECOVERY-001'),
        ('TERM-RECOVERY-002'),('TERM-TENANT-001'),('TERM-DORMANT-001'),('TERM-EXCEPTION-001'),
        ('TERM-KEY-001'),('TERM-EXPORT-001')
      ) AS required(id)
     WHERE NOT EXISTS (
        SELECT 1 FROM iam.configuration_versions c
         WHERE c.config_type = 'DURATION_BASELINE'
           AND c.config_code = 'DEFAULT'
           AND c.version = 1
           AND c.payload ? required.id
     );

    SELECT EXISTS (
        SELECT 1
          FROM iam.configuration_versions c
         WHERE (c.config_type = 'SLO_BASELINE' AND c.config_code = 'DEFAULT' AND c.version = 1 AND (
                    (c.payload #>> '{SLO-AUTH-001,monthly_availability_min}')::numeric IS DISTINCT FROM 0.9999
                 OR (c.payload #>> '{SLO-API-001,monthly_availability_min}')::numeric IS DISTINCT FROM 0.999
                 OR (c.payload #>> '{SLO-TOKEN-001,p95_ms_max}')::integer IS DISTINCT FROM 150
                 OR (c.payload #>> '{SLO-TOKEN-001,p99_ms_max}')::integer IS DISTINCT FROM 300
                 OR (c.payload #>> '{SLO-AUTHZ-001,p99_ms_max}')::integer IS DISTINCT FROM 50
                 OR (c.payload #>> '{SLO-REVOKE-001,p99_seconds_max}')::integer IS DISTINCT FROM 30
                 OR (c.payload #>> '{SLO-REVOKE-001,hard_seconds_max}')::integer IS DISTINCT FROM 60
                 OR (c.payload #>> '{SLO-REVOKE-002,staleness_seconds_max}')::integer IS DISTINCT FROM 300
                 OR (c.payload #>> '{SLO-EVENT-001,percentile}')::numeric IS DISTINCT FROM 0.999
                 OR (c.payload #>> '{SLO-EVENT-001,visible_seconds_max}')::integer IS DISTINCT FROM 60
                 OR (c.payload #>> '{SLO-PRIV-001,substantive_response_workdays_max}')::integer IS DISTINCT FROM 15
                 OR (c.payload #>> '{SLO-PRIV-001,completion_days_max}')::integer IS DISTINCT FROM 30
                 OR (c.payload #>> '{SLO-ALERT-001,p1_ack_minutes_max}')::integer IS DISTINCT FROM 15
                 OR (c.payload #>> '{SLO-ALERT-001,p1_response_minutes_max}')::integer IS DISTINCT FROM 60
                 OR (c.payload #>> '{SLO-DR-001,regional_rto_minutes_max}')::integer IS DISTINCT FROM 30
                 OR (c.payload #>> '{SLO-DR-001,c2_rpo_minutes_max}')::integer IS DISTINCT FROM 5
                 OR (c.payload #>> '{SLO-DR-002,c0_c1_security_state_rpo_seconds}')::integer IS DISTINCT FROM 0
                 OR (c.payload #>> '{SLO-HA-001,same_az_database_rpo_seconds}')::integer IS DISTINCT FROM 0
             ))
            OR (c.config_type = 'DURATION_BASELINE' AND c.config_code = 'DEFAULT' AND c.version = 1 AND (
                    c.payload ? 'invitation_hours'
                 OR (c.payload #>> '{TTL-TOKEN-001,sp1_access_token_seconds_max}')::integer IS DISTINCT FROM 900
                 OR (c.payload #>> '{TTL-TOKEN-001,sp2_sp3_access_token_seconds_max}')::integer IS DISTINCT FROM 300
                 OR (c.payload #>> '{TTL-TOKEN-001,sp5_access_token_seconds_max}')::integer IS DISTINCT FROM 120
                 OR (c.payload #>> '{TTL-TOKEN-002,machine_access_token_seconds_max}')::integer IS DISTINCT FROM 300
                 OR (c.payload #>> '{TTL-TOKEN-003,sp1_absolute_days_max}')::integer IS DISTINCT FROM 90
                 OR (c.payload #>> '{TTL-TOKEN-003,sp1_idle_days_max}')::integer IS DISTINCT FROM 30
                 OR (c.payload #>> '{TTL-TOKEN-003,sp2_absolute_days_max}')::integer IS DISTINCT FROM 30
                 OR (c.payload #>> '{TTL-TOKEN-003,sp3_absolute_days_max}')::integer IS DISTINCT FROM 1
                 OR c.payload #>> '{TTL-TOKEN-003,sp4_refresh_token}' IS DISTINCT FROM 'forbidden'
                 OR c.payload #>> '{TTL-TOKEN-003,sp5_sender_constraint}' IS DISTINCT FROM 'required'
                 OR (c.payload #>> '{TTL-TOKEN-004,id_token_seconds_max}')::integer IS DISTINCT FROM 300
                 OR (c.payload #>> '{TTL-CODE-001,authorization_code_seconds_max}')::integer IS DISTINCT FROM 60
                 OR c.payload #>> '{TTL-CODE-001,single_use}' IS DISTINCT FROM 'true'
                 OR (c.payload #>> '{TTL-SESSION-001,normal_absolute_days_max}')::integer IS DISTINCT FROM 30
                 OR (c.payload #>> '{TTL-SESSION-001,normal_idle_days_max}')::integer IS DISTINCT FROM 7
                 OR (c.payload #>> '{TTL-SESSION-001,sp3_absolute_hours_max}')::integer IS DISTINCT FROM 12
                 OR (c.payload #>> '{TTL-SESSION-001,sp3_idle_minutes_max}')::integer IS DISTINCT FROM 30
                 OR (c.payload #>> '{TTL-LOGINTX-001,login_transaction_seconds_max}')::integer IS DISTINCT FROM 900
                 OR c.payload #>> '{TTL-LOGINTX-001,single_use}' IS DISTINCT FROM 'true'
                 OR (c.payload #>> '{TTL-CHALLENGE-001,challenge_seconds_max}')::integer IS DISTINCT FROM 300
                 OR (c.payload #>> '{TTL-CHALLENGE-001,attempts_max}')::integer IS DISTINCT FROM 5
                 OR (c.payload #>> '{TTL-CHALLENGE-001,send_interval_seconds_min}')::integer IS DISTINCT FROM 60
                 OR (c.payload #>> '{TTL-STEPUP-001,authentication_age_seconds_max}')::integer IS DISTINCT FROM 300
                 OR c.payload #>> '{TTL-JWKS-001,stage0_registration_required}' IS DISTINCT FROM 'true'
                 OR (c.payload #>> '{TTL-JWKS-001,publish_before_signing_cache_multiplier_min}')::integer IS DISTINCT FROM 2
                 OR (c.payload #>> '{TERM-DELETE-001,default_days}')::integer IS DISTINCT FROM 15
                 OR (c.payload #>> '{TERM-DELETE-001,days_min}')::integer IS DISTINCT FROM 7
                 OR (c.payload #>> '{TERM-REBIND-001,protection_hours_min}')::integer IS DISTINCT FROM 24
                 OR (c.payload #>> '{TERM-IDENTIFIER-001,phone_quarantine_days_min}')::integer IS DISTINCT FROM 90
                 OR (c.payload #>> '{TERM-IDENTIFIER-001,enterprise_email_quarantine_days_min}')::integer IS DISTINCT FROM 180
                 OR c.payload #>> '{TERM-IDENTIFIER-001,username_reuse}' IS DISTINCT FROM 'forbidden'
                 OR (c.payload #>> '{TERM-RECOVERY-001,wait_hours_min}')::integer IS DISTINCT FROM 24
                 OR (c.payload #>> '{TERM-RECOVERY-001,wait_hours_max}')::integer IS DISTINCT FROM 72
                 OR (c.payload #>> '{TERM-RECOVERY-002,observation_days_min}')::integer IS DISTINCT FROM 7
                 OR (c.payload #>> '{TERM-TENANT-001,ownership_transfer_wait_hours_min}')::integer IS DISTINCT FROM 72
                 OR (c.payload #>> '{TERM-DORMANT-001,default_months}')::integer IS DISTINCT FROM 18
                 OR (c.payload #>> '{TERM-EXCEPTION-001,validity_months_max}')::integer IS DISTINCT FROM 6
                 OR (c.payload #>> '{TERM-KEY-001,rotation_days_max}')::integer IS DISTINCT FROM 90
                 OR (c.payload #>> '{TERM-EXPORT-001,download_hours_max}')::integer IS DISTINCT FROM 24
             ))
            OR c.id = '30000000-0000-0000-0000-000000000005'::uuid
    ) INTO invalid_baseline;

    SELECT string_agg(format('%s/%s/%s', object_type, object_code, state), ', ' ORDER BY object_type, object_code)
      INTO invalid_seed_state
      FROM (
        SELECT 'CONFIG' AS object_type, config_type || ':' || config_code AS object_code, state
          FROM iam.configuration_versions
         WHERE (id::text LIKE '10000000-%' OR id::text LIKE '30000000-%')
           AND (state NOT IN ('DRAFT','PUBLISHED') OR (state = 'PUBLISHED' AND approved_by_case_id IS NULL))
        UNION ALL
        SELECT 'TEMPLATE', template_code || ':' || channel || ':' || locale, state
          FROM iam.message_template_versions
         WHERE id::text LIKE '40000000-%'
           AND (state NOT IN ('DRAFT','PUBLISHED') OR (state = 'PUBLISHED' AND approval_case_id IS NULL))
        UNION ALL
        SELECT 'EVENT_SCHEMA', event_type, state
          FROM iam.event_schema_versions
         WHERE id::text LIKE '50000000-%'
           AND (state NOT IN ('DRAFT','PUBLISHED') OR (state = 'PUBLISHED' AND approval_case_id IS NULL))
      ) seeded;

    SELECT count(*) INTO permission_count
      FROM iam.permissions
     WHERE id::text LIKE '21000000-%';

    SELECT count(*) INTO template_count
      FROM iam.message_template_versions
     WHERE id::text LIKE '40000000-%';

    SELECT count(*) INTO event_schema_count
      FROM iam.event_schema_versions
     WHERE id::text LIKE '50000000-%';

    SELECT string_agg(event_type, ', ' ORDER BY event_type)
      INTO invalid_event_schemas
      FROM iam.event_schema_versions e
     WHERE e.id::text LIKE '50000000-%'
       AND (
            jsonb_typeof(e.json_schema) <> 'object'
         OR coalesce(e.json_schema->>'type', '') <> 'object'
         OR jsonb_typeof(coalesce(e.json_schema->'properties', '{}'::jsonb)) <> 'object'
         OR jsonb_typeof(coalesce(e.json_schema->'required', '[]'::jsonb)) <> 'array'
         OR e.json_schema->'additionalProperties' IS DISTINCT FROM 'false'::jsonb
         OR EXISTS (
            SELECT 1
              FROM jsonb_array_elements_text(
                    CASE WHEN jsonb_typeof(e.json_schema->'required') = 'array' THEN e.json_schema->'required' ELSE '[]'::jsonb END
              ) AS required(property_name)
             WHERE NOT coalesce(e.json_schema->'properties', '{}'::jsonb) ? required.property_name
         )
       );

    IF missing_profiles IS NOT NULL OR invalid_profiles IS NOT NULL OR missing_slos IS NOT NULL OR missing_durations IS NOT NULL
       OR invalid_baseline OR invalid_seed_state IS NOT NULL OR permission_count < 48 OR template_count < 13
       OR event_schema_count < 18 OR invalid_event_schemas IS NOT NULL THEN
        RAISE EXCEPTION 'Seed 契约失败：missing_profiles=%, invalid_profiles=%, missing_slos=%, missing_durations=%, invalid_baseline=%, invalid_state=%, permissions=%, templates=%, event_schemas=%, invalid_event_schemas=%',
            coalesce(missing_profiles, '<none>'), coalesce(invalid_profiles, '<none>'), coalesce(missing_slos, '<none>'),
            coalesce(missing_durations, '<none>'), invalid_baseline, coalesce(invalid_seed_state, '<none>'),
            permission_count, template_count, event_schema_count, coalesce(invalid_event_schemas, '<none>');
    END IF;
END
$seed_contract$;

SELECT 'PASS: Security Profile、SLO/时长、权限、模板和核心事件 Seed 契约完整' AS result;
