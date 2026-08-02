\set ON_ERROR_STOP on

DO $sensitive_contract$
DECLARE
    banned_columns text;
    missing_expected text;
    risky_json_payloads text;
    invalid_template_schemas text;
BEGIN
    SELECT string_agg(format('%I.%I', c.relname, a.attname), ', ' ORDER BY c.relname, a.attname)
      INTO banned_columns
      FROM pg_class c
      JOIN pg_namespace n ON n.oid = c.relnamespace
      JOIN pg_attribute a ON a.attrelid = c.oid
     WHERE n.nspname = 'iam'
       AND c.relkind IN ('r','p')
       AND NOT c.relispartition
       AND a.attnum > 0
       AND NOT a.attisdropped
       AND a.attname IN ('password','plain_password','verification_code','access_token','refresh_token','authorization_code','private_key','client_secret','totp_secret');

    SELECT string_agg(format('%I.%I', required.table_name, required.column_name), ', ')
      INTO missing_expected
      FROM (VALUES
        ('identifiers','value_ciphertext'),('identifiers','blind_index'),
        ('credential_materials','secret_hash'),('credential_materials','secret_ciphertext'),
        ('authorization_codes','code_hash'),('refresh_token_instances','token_hash'),
        ('access_token_records','sender_constraint_thumbprint'),
        ('machine_credentials','secret_hash'),('cryptographic_keys','key_ref'),
        ('webhook_subscriptions','endpoint_ciphertext'),('message_requests','target_ciphertext')
      ) AS required(table_name, column_name)
     WHERE NOT EXISTS (
         SELECT 1
           FROM information_schema.columns c
          WHERE c.table_schema = 'iam'
            AND c.table_name = required.table_name
            AND c.column_name = required.column_name
     );

    SELECT string_agg(format('%s/%s/v%s', config_type, config_code, version), ', ' ORDER BY config_type, config_code, version)
      INTO risky_json_payloads
      FROM iam.configuration_versions
     WHERE payload::text ~* '"(plain_password|verification_code|private_key_value|client_secret_value|totp_secret)"\s*:';

    SELECT string_agg(format('%s/%s/%s/v%s', template_code, channel, locale, version), ', ' ORDER BY template_code, channel, locale, version)
      INTO invalid_template_schemas
      FROM iam.message_template_versions t
     WHERE jsonb_typeof(t.variable_schema) <> 'object'
        OR coalesce(t.variable_schema->>'type', '') <> 'object'
        OR jsonb_typeof(coalesce(t.variable_schema->'properties', '{}'::jsonb)) <> 'object'
        OR jsonb_typeof(coalesce(t.variable_schema->'required', '[]'::jsonb)) <> 'array'
        OR t.variable_schema->'additionalProperties' IS DISTINCT FROM 'false'::jsonb
        OR EXISTS (
            SELECT 1
              FROM jsonb_array_elements_text(
                    CASE WHEN jsonb_typeof(t.variable_schema->'required') = 'array' THEN t.variable_schema->'required' ELSE '[]'::jsonb END
              ) AS required(property_name)
             WHERE NOT coalesce(t.variable_schema->'properties', '{}'::jsonb) ? required.property_name
        );

    IF banned_columns IS NOT NULL OR missing_expected IS NOT NULL OR risky_json_payloads IS NOT NULL OR invalid_template_schemas IS NOT NULL THEN
        RAISE EXCEPTION '敏感数据门禁失败：banned=%, missing_secure_shape=%, risky_json=%, invalid_template_schema=%',
            coalesce(banned_columns, '<none>'), coalesce(missing_expected, '<none>'),
            coalesce(risky_json_payloads, '<none>'), coalesce(invalid_template_schemas, '<none>');
    END IF;
END
$sensitive_contract$;

SELECT 'PASS: 未发现敏感原文列名或危险 JSON Key，关键密文/摘要字段及模板 Schema 有效' AS result;
