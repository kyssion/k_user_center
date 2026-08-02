\set ON_ERROR_STOP on

DO $sensitive_contract$
DECLARE
    banned_columns text;
    missing_expected text;
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

    IF banned_columns IS NOT NULL OR missing_expected IS NOT NULL THEN
        RAISE EXCEPTION '敏感数据门禁失败：banned=%, missing_secure_shape=%', coalesce(banned_columns, '<none>'), coalesce(missing_expected, '<none>');
    END IF;
END
$sensitive_contract$;

SELECT 'PASS: 未发现敏感原文列名且关键密文/摘要字段存在' AS result;

