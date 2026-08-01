-- =============================================================================
-- verify.sql
-- PostgreSQL 基线结构、注释、状态机、公开 ID、敏感字段和关键不变量验收
-- psql 建议：psql -v ON_ERROR_STOP=1 -f docs/database/verify.sql
-- =============================================================================

BEGIN;
CREATE TEMP TABLE kuc_verification_violation (
    check_code text NOT NULL,
    object_name text NOT NULL,
    detail text NOT NULL
) ON COMMIT DROP;

INSERT INTO kuc_verification_violation
SELECT 'V001_MISSING_SCHEMA', required_schema, '缺少平台 Schema'
  FROM unnest(ARRAY['core','iam','authn','oauth','org','authz','profile','privacy','federation','risk','workload','assurance','crypto','control','integration','audit','messaging','migration']) required_schema
 WHERE NOT EXISTS (SELECT 1 FROM pg_namespace n WHERE n.nspname = required_schema);

INSERT INTO kuc_verification_violation
SELECT 'V002_MISSING_MIGRATION', required_version, '迁移版本未登记'
  FROM unnest(ARRAY['000','010','020','030','040','050','060','070','075','080','900']) required_version
 WHERE to_regclass('core.schema_migration') IS NULL
    OR NOT EXISTS (SELECT 1 FROM core.schema_migration m WHERE m.version = required_version);

INSERT INTO kuc_verification_violation
SELECT 'V003_MISSING_TABLE', required_table, '能力蓝图要求的核心表不存在'
  FROM unnest(ARRAY[
    'iam.user_account','iam.identifier','authn.authenticator','authn.login_transaction','authn.verification_challenge',
    'oauth.client','oauth.authorization_grant','oauth.user_session','oauth.token_family','oauth.revocation_record',
    'org.tenant','org.membership','org.invitation','authz.authorization_decision','authz.relationship_tuple','authz.access_review','profile.field_definition','profile.notification_preference',
    'privacy.consent_aggregate','privacy.consent','privacy.privacy_request','privacy.cross_border_authorization','privacy.minor_protection','privacy.privacy_impact_assessment','federation.external_identity','federation.directory_object',
    'risk.risk_signal','risk.risk_assessment','workload.machine_principal','workload.machine_credential','workload.trust_bundle','workload.workload_attestation',
    'assurance.delegation','control.approval_case','control.config_release','control.client_certification_run',
    'crypto.key_asset','crypto.certificate_asset','crypto.jwks_release',
    'integration.outbox_event','integration.webhook_delivery','audit.audit_event','messaging.message_send','messaging.content_compliance_rule',
    'migration.migration_batch','migration.change_log'
 ]) required_table
 WHERE to_regclass(required_table) IS NULL;

INSERT INTO kuc_verification_violation
SELECT 'V003_MISSING_VIEW', required_view, '数据库契约要求的视图不存在'
  FROM unnest(ARRAY['authn.device_authorization_status','core.data_dictionary','core.object_dictionary']) required_view
 WHERE to_regclass(required_view) IS NULL;

INSERT INTO kuc_verification_violation
SELECT 'V004_MISSING_TABLE_COMMENT', n.nspname || '.' || c.relname, '基表缺少 COMMENT ON TABLE'
  FROM pg_class c
  JOIN pg_namespace n ON n.oid = c.relnamespace
 WHERE n.nspname = ANY(ARRAY['core','iam','authn','oauth','org','authz','profile','privacy','federation','risk','workload','assurance','crypto','control','integration','audit','messaging','migration'])
   AND c.relkind IN ('r','p')
   AND NULLIF(btrim(obj_description(c.oid, 'pg_class')), '') IS NULL;

INSERT INTO kuc_verification_violation
SELECT 'V004_MISSING_DATABASE_COMMENT', current_database(), '当前数据库缺少 COMMENT ON DATABASE'
  FROM pg_database d
 WHERE d.datname = current_database()
   AND NULLIF(btrim(shobj_description(d.oid, 'pg_database')), '') IS NULL;

INSERT INTO kuc_verification_violation
SELECT 'V004_MISSING_EXTENSION_COMMENT', e.extname, '平台扩展缺少 COMMENT ON EXTENSION'
  FROM pg_extension e
 WHERE e.extname = 'pgcrypto'
   AND NULLIF(btrim(obj_description(e.oid, 'pg_extension')), '') IS NULL;

INSERT INTO kuc_verification_violation
SELECT 'V004_MISSING_SCHEMA_COMMENT', n.nspname, '平台 Schema 缺少 COMMENT ON SCHEMA'
  FROM pg_namespace n
 WHERE n.nspname = ANY(ARRAY['core','iam','authn','oauth','org','authz','profile','privacy','federation','risk','workload','assurance','crypto','control','integration','audit','messaging','migration'])
   AND NULLIF(btrim(obj_description(n.oid, 'pg_namespace')), '') IS NULL;

INSERT INTO kuc_verification_violation
SELECT 'V004_MISSING_VIEW_COMMENT', n.nspname || '.' || c.relname, '视图或物化视图缺少 COMMENT'
  FROM pg_class c
  JOIN pg_namespace n ON n.oid = c.relnamespace
 WHERE n.nspname = ANY(ARRAY['core','iam','authn','oauth','org','authz','profile','privacy','federation','risk','workload','assurance','crypto','control','integration','audit','messaging','migration'])
   AND c.relkind IN ('v','m')
   AND NULLIF(btrim(obj_description(c.oid, 'pg_class')), '') IS NULL;

INSERT INTO kuc_verification_violation
SELECT 'V004_MISSING_SEQUENCE_COMMENT', n.nspname || '.' || c.relname, '序列缺少 COMMENT ON SEQUENCE'
  FROM pg_class c
  JOIN pg_namespace n ON n.oid = c.relnamespace
 WHERE n.nspname = ANY(ARRAY['core','iam','authn','oauth','org','authz','profile','privacy','federation','risk','workload','assurance','crypto','control','integration','audit','messaging','migration'])
   AND c.relkind = 'S'
   AND NULLIF(btrim(obj_description(c.oid, 'pg_class')), '') IS NULL;

INSERT INTO kuc_verification_violation
SELECT 'V004_MISSING_INDEX_COMMENT', n.nspname || '.' || idx.relname, '索引缺少 COMMENT ON INDEX'
  FROM pg_index i
  JOIN pg_class idx ON idx.oid = i.indexrelid
  JOIN pg_namespace n ON n.oid = idx.relnamespace
 WHERE n.nspname = ANY(ARRAY['core','iam','authn','oauth','org','authz','profile','privacy','federation','risk','workload','assurance','crypto','control','integration','audit','messaging','migration'])
   AND NULLIF(btrim(obj_description(idx.oid, 'pg_class')), '') IS NULL;

INSERT INTO kuc_verification_violation
SELECT 'V004_MISSING_CONSTRAINT_COMMENT', n.nspname || '.' || c.relname || '.' || con.conname, '约束缺少 COMMENT ON CONSTRAINT'
  FROM pg_constraint con
  JOIN pg_class c ON c.oid = con.conrelid
  JOIN pg_namespace n ON n.oid = c.relnamespace
 WHERE n.nspname = ANY(ARRAY['core','iam','authn','oauth','org','authz','profile','privacy','federation','risk','workload','assurance','crypto','control','integration','audit','messaging','migration'])
   AND NULLIF(btrim(obj_description(con.oid, 'pg_constraint')), '') IS NULL;

INSERT INTO kuc_verification_violation
SELECT 'V004_MISSING_TRIGGER_COMMENT', n.nspname || '.' || c.relname || '.' || t.tgname, '业务触发器缺少 COMMENT ON TRIGGER'
  FROM pg_trigger t
  JOIN pg_class c ON c.oid = t.tgrelid
  JOIN pg_namespace n ON n.oid = c.relnamespace
 WHERE NOT t.tgisinternal
   AND n.nspname = ANY(ARRAY['core','iam','authn','oauth','org','authz','profile','privacy','federation','risk','workload','assurance','crypto','control','integration','audit','messaging','migration'])
   AND NULLIF(btrim(obj_description(t.oid, 'pg_trigger')), '') IS NULL;

INSERT INTO kuc_verification_violation
SELECT 'V004_MISSING_TYPE_COMMENT', n.nspname || '.' || t.typname, '独立 Type/Domain 缺少 COMMENT'
  FROM pg_type t
  JOIN pg_namespace n ON n.oid = t.typnamespace
  LEFT JOIN pg_class c ON c.oid = t.typrelid
 WHERE n.nspname = ANY(ARRAY['core','iam','authn','oauth','org','authz','profile','privacy','federation','risk','workload','assurance','crypto','control','integration','audit','messaging','migration'])
   AND (t.typtype IN ('d','e','r','m') OR (t.typtype = 'c' AND c.relkind = 'c'))
   AND NULLIF(btrim(obj_description(t.oid, 'pg_type')), '') IS NULL;

INSERT INTO kuc_verification_violation
SELECT 'V004_MISSING_ROUTINE_COMMENT', n.nspname || '.' || p.proname || '(' || pg_get_function_identity_arguments(p.oid) || ')', '函数或过程缺少 COMMENT'
  FROM pg_proc p
  JOIN pg_namespace n ON n.oid = p.pronamespace
 WHERE p.prokind IN ('f','p')
   AND n.nspname = ANY(ARRAY['core','iam','authn','oauth','org','authz','profile','privacy','federation','risk','workload','assurance','crypto','control','integration','audit','messaging','migration'])
   AND NULLIF(btrim(obj_description(p.oid, 'pg_proc')), '') IS NULL;

INSERT INTO kuc_verification_violation
SELECT 'V004_MISSING_ROLE_COMMENT', r.rolname, '平台角色缺少 COMMENT ON ROLE'
  FROM pg_roles r
 WHERE r.rolname = ANY(ARRAY['kuc_owner','kuc_migrator','kuc_app','kuc_authn_writer','kuc_control_writer',
                            'kuc_outbox_dispatcher','kuc_message_dispatcher','kuc_audit_writer','kuc_auditor','kuc_readonly'])
   AND NULLIF(btrim(shobj_description(r.oid, 'pg_authid')), '') IS NULL;

INSERT INTO kuc_verification_violation
SELECT 'V004_MISSING_POLICY_COMMENT', n.nspname || '.' || c.relname || '.' || p.polname, '已启用的 RLS Policy 缺少 COMMENT ON POLICY'
  FROM pg_policy p
  JOIN pg_class c ON c.oid = p.polrelid
  JOIN pg_namespace n ON n.oid = c.relnamespace
 WHERE EXISTS (SELECT 1 FROM core.schema_migration WHERE version = '910')
   AND n.nspname = ANY(ARRAY['core','iam','authn','oauth','org','authz','profile','privacy','federation','risk','workload','assurance','crypto','control','integration','audit','messaging','migration'])
   AND NULLIF(btrim(obj_description(p.oid, 'pg_policy')), '') IS NULL;

INSERT INTO kuc_verification_violation
SELECT 'V004_OBJECT_DICTIONARY_GAP',
       concat_ws('.', schema_name, parent_object, object_name),
       object_dimension || ' 对象在 core.object_dictionary 中缺少非空描述'
  FROM core.object_dictionary
 WHERE NULLIF(btrim(description), '') IS NULL;

INSERT INTO kuc_verification_violation
SELECT 'V005_MISSING_COLUMN_COMMENT', n.nspname || '.' || c.relname || '.' || a.attname, '列缺少非空注释'
  FROM pg_class c
  JOIN pg_namespace n ON n.oid = c.relnamespace
  JOIN pg_attribute a ON a.attrelid = c.oid
 WHERE n.nspname = ANY(ARRAY['core','iam','authn','oauth','org','authz','profile','privacy','federation','risk','workload','assurance','crypto','control','integration','audit','messaging','migration'])
   AND c.relkind IN ('r','p','v','m') AND a.attnum > 0 AND NOT a.attisdropped
   AND NULLIF(btrim(col_description(c.oid, a.attnum)), '') IS NULL;

INSERT INTO kuc_verification_violation
SELECT 'V005_PLACEHOLDER_COLUMN_COMMENT', n.nspname || '.' || c.relname || '.' || a.attname, '列注释仍为旧版占位说明，未形成可用数据字典'
  FROM pg_class c
  JOIN pg_namespace n ON n.oid = c.relnamespace
  JOIN pg_attribute a ON a.attrelid = c.oid
 WHERE n.nspname = ANY(ARRAY['core','iam','authn','oauth','org','authz','profile','privacy','federation','risk','workload','assurance','crypto','control','integration','audit','messaging','migration'])
   AND c.relkind IN ('r','p','v','m') AND a.attnum > 0 AND NOT a.attisdropped
   AND col_description(c.oid, a.attnum) LIKE '%具体业务语义见表注释%';

INSERT INTO kuc_verification_violation
SELECT 'V006_MISSING_PRIMARY_KEY', n.nspname || '.' || c.relname, '基表缺少主键'
  FROM pg_class c
  JOIN pg_namespace n ON n.oid = c.relnamespace
 WHERE n.nspname = ANY(ARRAY['core','iam','authn','oauth','org','authz','profile','privacy','federation','risk','workload','assurance','crypto','control','integration','audit','messaging','migration'])
   AND c.relkind = 'r'
   AND NOT EXISTS (SELECT 1 FROM pg_constraint x WHERE x.conrelid = c.oid AND x.contype = 'p');

INSERT INTO kuc_verification_violation
SELECT 'V007_UNCONSTRAINED_STATE', n.nspname || '.' || c.relname || '.' || a.attname, '状态列未被本表 CHECK 约束引用'
  FROM pg_class c
  JOIN pg_namespace n ON n.oid = c.relnamespace
  JOIN pg_attribute a ON a.attrelid = c.oid
 WHERE n.nspname = ANY(ARRAY['core','iam','authn','oauth','org','authz','profile','privacy','federation','risk','workload','assurance','crypto','control','integration','audit','messaging','migration'])
   AND c.relkind = 'r' AND a.attnum > 0 AND NOT a.attisdropped
   AND a.attname LIKE '%\_state' ESCAPE '\'
   AND a.atttypid = 'text'::regtype
   AND NOT EXISTS (
       SELECT 1 FROM pg_constraint x
        WHERE x.conrelid = c.oid AND x.contype = 'c'
          AND a.attnum = ANY(x.conkey)
   );

INSERT INTO kuc_verification_violation
SELECT 'V008_MISSING_PUBLIC_ID_TRIGGER', n.nspname || '.' || c.relname, '含 public_id 的表未登记 core.fn_register_public_id 触发器'
  FROM pg_class c
  JOIN pg_namespace n ON n.oid = c.relnamespace
 WHERE n.nspname = ANY(ARRAY['core','iam','authn','oauth','org','authz','profile','privacy','federation','risk','workload','assurance','crypto','control','integration','audit','messaging','migration'])
   AND c.relkind = 'r'
   AND NOT (n.nspname = 'core' AND c.relname = 'public_id_ledger')
   AND EXISTS (SELECT 1 FROM pg_attribute a WHERE a.attrelid = c.oid AND a.attname = 'public_id' AND NOT a.attisdropped)
   AND NOT EXISTS (
       SELECT 1 FROM pg_trigger t JOIN pg_proc p ON p.oid = t.tgfoid
        WHERE t.tgrelid = c.oid AND NOT t.tgisinternal AND p.proname = 'fn_register_public_id'
   );

INSERT INTO kuc_verification_violation
SELECT 'V009_ROW_VERSION_WITHOUT_TRIGGER', n.nspname || '.' || c.relname, '含 row_version 的表缺少自动递增触发器'
  FROM pg_class c
  JOIN pg_namespace n ON n.oid = c.relnamespace
 WHERE n.nspname = ANY(ARRAY['core','iam','authn','oauth','org','authz','profile','privacy','federation','risk','workload','assurance','crypto','control','integration','audit','messaging','migration'])
   AND c.relkind = 'r'
   AND EXISTS (SELECT 1 FROM pg_attribute a WHERE a.attrelid = c.oid AND a.attname = 'row_version' AND NOT a.attisdropped)
   AND NOT EXISTS (
       SELECT 1 FROM pg_trigger t JOIN pg_proc p ON p.oid = t.tgfoid
        WHERE t.tgrelid = c.oid AND NOT t.tgisinternal AND p.proname = 'fn_increment_row_version'
   );

INSERT INTO kuc_verification_violation
SELECT 'V010_FORBIDDEN_PLAINTEXT_COLUMN', n.nspname || '.' || c.relname || '.' || a.attname, '疑似保存密码、Secret、完整 Token、私钥、手机号或邮箱明文'
  FROM pg_class c
  JOIN pg_namespace n ON n.oid = c.relnamespace
  JOIN pg_attribute a ON a.attrelid = c.oid
 WHERE n.nspname = ANY(ARRAY['core','iam','authn','oauth','org','authz','profile','privacy','federation','risk','workload','assurance','crypto','control','integration','audit','messaging','migration'])
   AND c.relkind = 'r' AND a.attnum > 0 AND NOT a.attisdropped
   AND lower(a.attname) = ANY(ARRAY['password','password_plaintext','secret','client_secret','token','access_token','refresh_token','id_token','authorization_code','private_key','phone','phone_number','email','email_address','verification_code']);

INSERT INTO kuc_verification_violation
SELECT 'V011_MISSING_CRITICAL_INDEX', required_index, '关键唯一性或撤销/重试索引不存在'
  FROM unnest(ARRAY[
    'ux_identifier_verified_scope','ux_authorization_grant_active','ux_refresh_token_current',
    'ux_membership_effective','ux_consent_effective','ux_config_release_active',
    'ux_authority_lease_active','ux_subject_assignment_active','ux_role_assignment_effective',
    'ux_user_session_login_transaction','ux_authorization_code_login_transaction','ux_token_family_active_grant',
    'ux_consent_pending','ix_outbox_publish','ix_revocation_target'
  ]) required_index
 WHERE NOT EXISTS (SELECT 1 FROM pg_indexes i WHERE i.indexname = required_index);

INSERT INTO kuc_verification_violation
SELECT 'V012_MISSING_CRITICAL_TRIGGER', required_trigger, '关键不变量触发器不存在'
  FROM unnest(ARRAY[
    'trg_user_account_state','trg_user_account_public_id','trg_session_insert','trg_grant_activation',
    'trg_device_loss','trg_membership_scope','trg_consent_epoch','trg_approval_case_guard',
    'trg_approval_case_initial_state','trg_config_release_guard','trg_config_release_approval',
    'trg_config_release_binding_immutable','trg_policy_release_binding_immutable','trg_risk_policy_release_binding_immutable',
    'trg_client_activation_approval',
    'trg_client_configuration_immutable','trg_client_initial_state','trg_identity_provider_state',
    'trg_key_asset_state','trg_key_asset_initial_state','trg_consent_aggregate_context',
    'trg_key_asset_approval_binding','trg_zz_approval_case_evidence',
    'trg_authorization_code_context','trg_authorization_code_state','trg_session_state_guard','trg_token_family_context',
    'trg_token_family_state_guard','trg_refresh_token_guard','trg_refresh_token_successor','trg_reference_token_context',
    'trg_organization_hierarchy','trg_group_member_guard','trg_role_assignment_scope',
    'trg_outbox_immutable','trg_webhook_delivery_immutable','trg_zz_message_send_immutable',
    'trg_identifier_state','trg_operation_state','trg_device_state',
    'trg_authenticator_activation','trg_login_transaction_state','trg_challenge_state',
    'trg_business_line_state','trg_tenant_state','trg_organization_state','trg_membership_state','trg_invitation_state','trg_delegation_guard',
    'trg_machine_state','trg_machine_credential_state','trg_trust_bundle_state','trg_attestation_state',
    'trg_certificate_state','trg_jwks_state','trg_security_exception_state','trg_break_glass_state',
    'trg_privacy_request_state','trg_migration_batch_guard','trg_audit_event_chain','trg_change_log_immutable'
  ]) required_trigger
 WHERE NOT EXISTS (SELECT 1 FROM pg_trigger t WHERE t.tgname = required_trigger AND NOT t.tgisinternal);

INSERT INTO kuc_verification_violation
SELECT 'V013_MODEL_COUNT_DRIFT', 'database', '平台基表数量不是基线定义的 145；迁移可能缺失或文档/验收未同步'
 WHERE (
    SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
     WHERE n.nspname = ANY(ARRAY['core','iam','authn','oauth','org','authz','profile','privacy','federation','risk','workload','assurance','crypto','control','integration','audit','messaging','migration'])
       AND c.relkind = 'r'
 ) <> 145;

INSERT INTO kuc_verification_violation
SELECT 'V014_MISSING_FOREIGN_KEY_INDEX', con.conrelid::regclass::text || '.' || con.conname, '外键列没有可用的非部分前导索引'
  FROM pg_constraint con
  JOIN pg_class c ON c.oid = con.conrelid
  JOIN pg_namespace n ON n.oid = c.relnamespace
 WHERE con.contype = 'f'
   AND n.nspname = ANY(ARRAY['core','iam','authn','oauth','org','authz','profile','privacy','federation','risk','workload','assurance','crypto','control','integration','audit','messaging','migration'])
   AND NOT EXISTS (
       SELECT 1
         FROM pg_index i
        WHERE i.indrelid = con.conrelid
          AND i.indisvalid
          AND i.indpred IS NULL
          AND (
              SELECT array_agg(x.attnum ORDER BY x.ordinality)
                FROM unnest(i.indkey::smallint[]) WITH ORDINALITY AS x(attnum, ordinality)
               WHERE x.ordinality <= cardinality(con.conkey)
          ) = con.conkey
   );

INSERT INTO kuc_verification_violation
SELECT 'V015_BUSINESS_LINE_WITHOUT_FOREIGN_KEY', c.oid::regclass::text, '直接 business_line_id 列未引用 org.business_line(id)'
  FROM pg_class c
  JOIN pg_namespace n ON n.oid = c.relnamespace
  JOIN pg_attribute a ON a.attrelid = c.oid AND a.attname = 'business_line_id' AND NOT a.attisdropped
 WHERE c.relkind = 'r'
   AND n.nspname = ANY(ARRAY['core','iam','authn','oauth','org','authz','profile','privacy','federation','risk','workload','assurance','crypto','control','integration','audit','messaging','migration'])
   AND NOT EXISTS (
       SELECT 1 FROM pg_constraint fk
        WHERE fk.conrelid = c.oid
          AND fk.contype = 'f'
          AND fk.confrelid = 'org.business_line'::regclass
          AND fk.conkey = ARRAY[a.attnum]::smallint[]
   );

INSERT INTO kuc_verification_violation
SELECT 'V015_TENANT_BUSINESS_SCOPE_UNPROVEN', c.oid::regclass::text, '同时含 tenant_id/business_line_id 的表缺少范围一致性复合外键'
  FROM pg_class c
  JOIN pg_namespace n ON n.oid = c.relnamespace
  JOIN pg_attribute tenant_col ON tenant_col.attrelid = c.oid AND tenant_col.attname = 'tenant_id' AND NOT tenant_col.attisdropped
  JOIN pg_attribute business_col ON business_col.attrelid = c.oid AND business_col.attname = 'business_line_id' AND NOT business_col.attisdropped
 WHERE c.relkind = 'r'
   AND n.nspname = ANY(ARRAY['core','iam','authn','oauth','org','authz','profile','privacy','federation','risk','workload','assurance','crypto','control','integration','audit','messaging','migration'])
   AND NOT EXISTS (
       SELECT 1 FROM pg_constraint fk
        WHERE fk.conrelid = c.oid
          AND fk.contype = 'f'
          AND fk.confrelid = 'org.tenant'::regclass
          AND fk.conkey = ARRAY[tenant_col.attnum, business_col.attnum]::smallint[]
   );

INSERT INTO kuc_verification_violation
SELECT 'V015_TENANT_ORGANIZATION_SCOPE_UNPROVEN', c.oid::regclass::text, '同时含 tenant_id/organization_id 的表缺少范围一致性复合外键'
  FROM pg_class c
  JOIN pg_namespace n ON n.oid = c.relnamespace
  JOIN pg_attribute tenant_col ON tenant_col.attrelid = c.oid AND tenant_col.attname = 'tenant_id' AND NOT tenant_col.attisdropped
  JOIN pg_attribute organization_col ON organization_col.attrelid = c.oid AND organization_col.attname = 'organization_id' AND NOT organization_col.attisdropped
 WHERE c.relkind = 'r'
   AND n.nspname = ANY(ARRAY['core','iam','authn','oauth','org','authz','profile','privacy','federation','risk','workload','assurance','crypto','control','integration','audit','messaging','migration'])
   AND NOT EXISTS (
       SELECT 1 FROM pg_constraint fk
        WHERE fk.conrelid = c.oid
          AND fk.contype = 'f'
          AND fk.confrelid = 'org.organization'::regclass
          AND fk.conkey = ARRAY[organization_col.attnum, tenant_col.attnum]::smallint[]
   );

INSERT INTO kuc_verification_violation
SELECT 'V015_TENANT_WITHOUT_FOREIGN_KEY', c.oid::regclass::text, '直接 tenant_id 列未引用 org.tenant(id)'
  FROM pg_class c
  JOIN pg_namespace n ON n.oid = c.relnamespace
  JOIN pg_attribute a ON a.attrelid = c.oid AND a.attname = 'tenant_id' AND NOT a.attisdropped
 WHERE c.relkind = 'r'
   AND n.nspname = ANY(ARRAY['core','iam','authn','oauth','org','authz','profile','privacy','federation','risk','workload','assurance','crypto','control','integration','audit','messaging','migration'])
   AND c.oid <> 'org.tenant'::regclass
   AND NOT EXISTS (
       SELECT 1 FROM pg_constraint fk
        WHERE fk.conrelid = c.oid
          AND fk.contype = 'f'
          AND fk.confrelid = 'org.tenant'::regclass
          AND fk.conkey = ARRAY[a.attnum]::smallint[]
   );

INSERT INTO kuc_verification_violation
SELECT 'V016_WRONG_RELATION_OWNER', c.oid::regclass::text, '平台关系对象 owner 不是 kuc_owner'
  FROM pg_class c
  JOIN pg_namespace n ON n.oid = c.relnamespace
 WHERE n.nspname = ANY(ARRAY['core','iam','authn','oauth','org','authz','profile','privacy','federation','risk','workload','assurance','crypto','control','integration','audit','messaging','migration'])
   AND c.relkind IN ('r','p','v','m','S','f')
   AND pg_get_userbyid(c.relowner) <> 'kuc_owner';

INSERT INTO kuc_verification_violation
SELECT 'V016_WRONG_SCHEMA_OWNER', n.nspname, '平台 Schema owner 不是 kuc_owner'
  FROM pg_namespace n
 WHERE n.nspname = ANY(ARRAY['core','iam','authn','oauth','org','authz','profile','privacy','federation','risk','workload','assurance','crypto','control','integration','audit','messaging','migration'])
   AND pg_get_userbyid(n.nspowner) <> 'kuc_owner';

INSERT INTO kuc_verification_violation
SELECT 'V016_WRONG_FUNCTION_OWNER', n.nspname || '.' || p.proname || '(' || pg_get_function_identity_arguments(p.oid) || ')', '平台函数 owner 不是 kuc_owner'
  FROM pg_proc p
  JOIN pg_namespace n ON n.oid = p.pronamespace
 WHERE n.nspname = ANY(ARRAY['core','iam','authn','oauth','org','authz','profile','privacy','federation','risk','workload','assurance','crypto','control','integration','audit','messaging','migration'])
   AND pg_get_userbyid(p.proowner) <> 'kuc_owner';

INSERT INTO kuc_verification_violation
SELECT 'V017_APPLICATION_CONTROL_PLANE_WRITE', relation_name, 'kuc_app 不得写控制面、策略、联合、风险、Webhook 配置或消息模板'
  FROM unnest(ARRAY[
      'control.config_release','control.approval_case','authz.role','authz.policy_release',
      'federation.identity_provider','risk.risk_policy_release','integration.webhook_subscription',
      'messaging.message_template','messaging.route_policy','crypto.key_asset'
  ]) AS relation_name
 WHERE has_table_privilege('kuc_app', relation_name, 'INSERT')
    OR has_table_privilege('kuc_app', relation_name, 'UPDATE')
    OR has_table_privilege('kuc_app', relation_name, 'DELETE');

INSERT INTO kuc_verification_violation
SELECT 'V017_DISPATCHER_CONTENT_WRITE', object_name, '投递角色不得修改事件、Webhook 或消息正文/身份列'
  FROM (VALUES
      ('integration.outbox_event.payload', has_column_privilege('kuc_outbox_dispatcher', 'integration.outbox_event', 'payload', 'UPDATE')),
      ('integration.outbox_event.tenant_id', has_column_privilege('kuc_outbox_dispatcher', 'integration.outbox_event', 'tenant_id', 'UPDATE')),
      ('integration.webhook_delivery.payload_hash', has_column_privilege('kuc_outbox_dispatcher', 'integration.webhook_delivery', 'payload_hash', 'UPDATE')),
      ('messaging.message_send.target_address_ciphertext', has_column_privilege('kuc_message_dispatcher', 'messaging.message_send', 'target_address_ciphertext', 'UPDATE')),
      ('messaging.message_send.variable_hash', has_column_privilege('kuc_message_dispatcher', 'messaging.message_send', 'variable_hash', 'UPDATE'))
  ) AS x(object_name, leaked)
 WHERE leaked;

INSERT INTO kuc_verification_violation
SELECT 'V017_APPLICATION_SENSITIVE_READ', relation_name, 'kuc_app 不得读取认证恢复、Token、机器凭证、跨租户回放或消息密文'
  FROM unnest(ARRAY[
      'oauth.client_credential','oauth.refresh_token','oauth.authorization_code','oauth.reference_access_token',
      'assurance.recovery_request','workload.machine_credential','integration.event_replay_request','messaging.message_send'
  ]) AS x(relation_name)
 WHERE has_table_privilege('kuc_app', relation_name, 'SELECT');

INSERT INTO kuc_verification_violation
SELECT 'V018_REQUIREMENT_TRACE_INCOMPLETE', 'core.requirement_trace', '能力地图/蓝图的 218 个 REQ/API/EVT/INV 标识未全部种入追踪矩阵'
 WHERE (SELECT count(DISTINCT requirement_id) FROM core.requirement_trace) <> 218;

INSERT INTO kuc_verification_violation
SELECT 'V019_MIGRATION_HASH_INVALID', version, '迁移 SHA-256 不是 64 位小写十六进制'
  FROM core.schema_migration
 WHERE script_sha256 IS NOT NULL AND script_sha256 !~ '^[0-9a-f]{64}$';

INSERT INTO kuc_verification_violation
SELECT 'V020_MISSING_HARDENING_COLUMN', required_column, '安全加固列不存在'
  FROM unnest(ARRAY[
      'iam.identifier.ownership_digest','iam.identifier.ownership_key_version',
      'authn.verification_challenge.hash_key_version','authn.recovery_code.hash_key_version',
      'oauth.client.configuration_hash','federation.identity_provider.configuration_hash',
      'crypto.key_asset.asset_metadata_hash','audit.audit_outbox.tenant_id',
      'oauth.authorization_grant.machine_epoch_at_grant','oauth.reference_access_token.machine_epoch_at_issue',
      'authz.role.organization_id','control.config_release.approval_execution_id',
      'oauth.client.approval_execution_id','oauth.client.last_activation_execution_id',
      'federation.identity_provider.last_activation_execution_id',
      'authz.role_assignment.approval_execution_id','authz.role_assignment.last_activation_execution_id',
      'privacy.consent.consent_version','oauth.user_session.expired_at','oauth.user_session.compromise_reason_code',
      'control.approval_case.submitted_at','control.approval_case.rejected_at',
      'authz.policy_release.revoked_at','risk.risk_policy_release.retired_at','risk.risk_policy_release.revoked_at',
      'authn.authenticator.state_expired_at','authn.login_transaction.identified_at','authn.login_transaction.expired_at','authn.login_transaction.blocked_at',
      'authn.verification_challenge.risk_assessment_id','authn.verification_challenge.risk_context_hash',
      'org.business_line.suspended_at','org.business_line.irreversible_at','org.tenant.suspended_at',
      'org.organization.suspended_at','org.membership.state_expired_at','org.invitation.state_expired_at',
      'org.invitation.creation_authorization_decision_id','org.invitation.acceptance_authorization_decision_id',
      'assurance.delegation.delegation_context_hash','assurance.delegation.revoked_by_ref',
      'workload.machine_principal.last_revalidation_evidence_hash','workload.machine_credential.replaces_credential_id',
      'workload.machine_credential.compromised_at','workload.trust_bundle.bundle_context_hash',
      'workload.workload_attestation.expired_at','crypto.certificate_asset.activated_at',
      'crypto.jwks_release.activated_at','crypto.jwks_release.revoked_at',
      'control.security_exception.exception_context_hash','control.security_exception.tenant_id',
      'control.break_glass_grant.grant_context_hash','control.break_glass_grant.expired_at',
      'iam.identifier.state_reason_code','core.async_operation.blocked_at','core.async_operation.partial_at',
      'oauth.device.trust_evidence_hash','oauth.device.loss_clear_evidence_hash',
      'privacy.privacy_request.blocked_at','privacy.privacy_request.partial_at',
      'migration.migration_batch.paused_from_state','migration.migration_batch.rolled_back_at'
  ]) AS required_column
 WHERE NOT EXISTS (
     SELECT 1
       FROM pg_attribute a
      WHERE a.attrelid = to_regclass(split_part(required_column, '.', 1) || '.' || split_part(required_column, '.', 2))
        AND a.attname = split_part(required_column, '.', 3)
        AND NOT a.attisdropped
 );

INSERT INTO kuc_verification_violation
SELECT 'V021_PLATFORM_TENANT_MISSING', 'org.tenant:00000000-0000-0000-0000-000000000000', '平台范围全零 UUID 租户/业务线种子缺失或未激活'
 WHERE NOT EXISTS (
     SELECT 1
       FROM org.tenant t
       JOIN org.business_line b ON b.id = t.business_line_id
      WHERE t.id = '00000000-0000-0000-0000-000000000000'
        AND b.id = '00000000-0000-0000-0000-000000000000'
        AND t.tenant_state = 'ACTIVE'
        AND b.business_line_state = 'ACTIVE'
 );

INSERT INTO kuc_verification_violation
SELECT 'V022_PUBLIC_FUNCTION_EXECUTE', n.nspname || '.' || p.proname, '平台函数仍向 PUBLIC 开放 EXECUTE'
 FROM pg_proc p
  JOIN pg_namespace n ON n.oid = p.pronamespace
 WHERE n.nspname = ANY(ARRAY['core','iam','authn','oauth','org','authz','profile','privacy','federation','risk','workload','assurance','crypto','control','integration','audit','messaging','migration'])
   AND EXISTS (
       SELECT 1
         FROM aclexplode(COALESCE(p.proacl, acldefault('f', p.proowner))) acl
        WHERE acl.grantee = 0 AND acl.privilege_type = 'EXECUTE'
   );

INSERT INTO kuc_verification_violation
SELECT 'V023_RLS_DIRECT_TENANT_MISSING', c.oid::regclass::text, '已登记 910，但直接 tenant_id 表未启用并 FORCE RLS'
  FROM pg_class c
  JOIN pg_namespace n ON n.oid = c.relnamespace
  JOIN pg_attribute a ON a.attrelid = c.oid AND a.attname = 'tenant_id' AND NOT a.attisdropped
 WHERE EXISTS (SELECT 1 FROM core.schema_migration WHERE version = '910')
   AND c.relkind = 'r'
   AND n.nspname = ANY(ARRAY['core','iam','authn','oauth','org','authz','profile','privacy','federation','risk','workload','assurance','crypto','control','integration','audit','messaging','migration'])
   AND (NOT c.relrowsecurity OR NOT c.relforcerowsecurity);

INSERT INTO kuc_verification_violation
SELECT 'V023_RLS_DERIVED_POLICY_MISSING', relation_name, '已登记 910，但关键派生租户表缺少 derived_tenant_context_policy'
  FROM unnest(ARRAY[
      'core.async_operation_step','authn.login_factor','oauth.application','oauth.api_resource','oauth.scope_definition',
      'oauth.client_uri','oauth.client_credential',
      'oauth.refresh_token','oauth.authorization_code','oauth.logout_request','oauth.logout_target_result',
      'org.group_member','authz.role_permission','authz.role_exclusion','authz.access_review',
      'control.approval_decision','control.client_certification_run',
      'profile.business_profile','profile.profile_change','privacy.consent',
      'privacy.privacy_request','privacy.privacy_request_task','privacy.export_job','privacy.deletion_proof',
      'federation.identity_provider_key','federation.external_identity','federation.attribute_mapping',
      'federation.directory_object','federation.directory_sync_run','federation.assertion_replay',
      'integration.webhook_delivery','messaging.delivery_receipt','messaging.reachability',
      'workload.machine_credential','workload.workload_attestation',
      'migration.migration_batch','migration.authority_lease','migration.legacy_id_mapping',
      'migration.duplicate_candidate','migration.change_log','migration.reconciliation_run','migration.rollback_execution'
  ]) AS x(relation_name)
 WHERE EXISTS (SELECT 1 FROM core.schema_migration WHERE version = '910')
   AND NOT EXISTS (
       SELECT 1 FROM pg_policy p
        WHERE p.polrelid = relation_name::regclass
          AND p.polname = 'derived_tenant_context_policy'
   );

INSERT INTO kuc_verification_violation
SELECT 'V023_RLS_TENANT_ROOT_MISSING', relation_name, '已登记 910，但 Tenant/Business Line 隔离根未启用并 FORCE RLS'
  FROM unnest(ARRAY['org.tenant','org.business_line']) AS x(relation_name)
  JOIN pg_class c ON c.oid = relation_name::regclass
 WHERE EXISTS (SELECT 1 FROM core.schema_migration WHERE version = '910')
   AND (NOT c.relrowsecurity OR NOT c.relforcerowsecurity);

SELECT check_code, object_name, detail
  FROM kuc_verification_violation
 ORDER BY check_code, object_name;

DO $$
DECLARE v_count integer;
BEGIN
    SELECT count(*) INTO v_count FROM kuc_verification_violation;
    IF v_count > 0 THEN
        RAISE EXCEPTION '数据库验收失败：% 个问题；请查看上方明细', v_count;
    END IF;
END;
$$;

COMMIT;
SELECT '数据库结构、注释与关键不变量验证通过' AS verification_result;
