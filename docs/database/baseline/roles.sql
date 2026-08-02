\set ON_ERROR_STOP on

SELECT (NOT EXISTS (SELECT 1 FROM core.schema_migration WHERE version = 'baseline:roles'))::text AS kuc_run_roles \gset
\if :kuc_run_roles
-- =============================================================================
-- baseline/roles.sql
-- 数据库 NOLOGIN 角色、对象所有权和显式最小权限；登录角色由基础设施绑定
-- =============================================================================

BEGIN;
SET LOCAL lock_timeout = '10s';

DO $$
DECLARE v_role text;
BEGIN
    FOREACH v_role IN ARRAY ARRAY[
        'kuc_owner', 'kuc_migrator', 'kuc_app', 'kuc_authn_writer',
        'kuc_control_writer', 'kuc_outbox_dispatcher', 'kuc_message_dispatcher',
        'kuc_audit_writer', 'kuc_auditor', 'kuc_readonly'
    ]
    LOOP
        IF to_regrole(v_role) IS NULL THEN
            EXECUTE format('CREATE ROLE %I NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS', v_role);
        END IF;
    END LOOP;
END;
$$;

COMMENT ON ROLE kuc_owner IS '统一身份与访问平台数据库对象的 NOLOGIN 所有者；仅供受控迁移 SET ROLE。';
COMMENT ON ROLE kuc_migrator IS '统一身份与访问平台迁移执行角色；负责 DDL、注释和结构验收。';
COMMENT ON ROLE kuc_app IS '普通领域应用角色；仅访问获准业务表，不得写控制面或读取凭证密文。';
COMMENT ON ROLE kuc_authn_writer IS '认证数据面写角色；负责认证、会话、Token 与联合运行态。';
COMMENT ON ROLE kuc_control_writer IS '控制面写角色；负责审批、策略、密钥、联合与隐私配置。';
COMMENT ON ROLE kuc_outbox_dispatcher IS '事件与 Webhook 投递角色；仅推进投递状态、尝试记录和消费水位。';
COMMENT ON ROLE kuc_message_dispatcher IS '消息投递角色；仅推进发送状态、回执、可达性和供应商指标。';
COMMENT ON ROLE kuc_audit_writer IS '独立审计写角色；负责 Audit Outbox、审计事件和数据访问审计。';
COMMENT ON ROLE kuc_auditor IS '审计与控制面只读角色；用于合规检查和证据查询。';
COMMENT ON ROLE kuc_readonly IS '受控运维只读角色；生产环境应继续按人员和环境收窄。';

GRANT kuc_owner TO kuc_migrator;

REVOKE CREATE ON SCHEMA public FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA public FROM PUBLIC;
REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA core, iam, authn, oauth, org, authz, profile, privacy, federation, risk, workload, assurance, crypto, control, integration, audit, messaging, migration FROM PUBLIC;

-- 普通领域应用：可读业务投影，只能写用户、组织成员、Profile、隐私请求和本地事务 Outbox。
GRANT USAGE ON SCHEMA core, iam, oauth, org, authz, profile, privacy, assurance, workload, integration, messaging, audit TO kuc_app;
GRANT SELECT ON ALL TABLES IN SCHEMA core, iam, oauth, org, authz, profile, privacy, assurance, workload, integration, messaging TO kuc_app;
REVOKE SELECT ON oauth.client_credential, oauth.refresh_token, oauth.authorization_code,
    oauth.reference_access_token, messaging.message_send,
    assurance.recovery_request, workload.machine_credential,
    integration.event_replay_request
FROM kuc_app;

GRANT SELECT, INSERT, UPDATE ON
    core.async_operation, core.async_operation_step, core.idempotency_request,
    iam.user_account, iam.subject_assignment, iam.identifier,
    iam.account_merge, iam.account_merge_item, iam.account_deletion,
    org.membership, org.invitation, org.user_group, org.group_member, org.usage_meter,
    authz.relationship_tuple,
    profile.user_profile, profile.sensitive_attribute, profile.business_profile,
    profile.profile_change, profile.user_preference, profile.notification_preference,
    privacy.agreement_acceptance, privacy.consent,
    privacy.marketing_subscription, privacy.privacy_request, privacy.privacy_request_task,
    privacy.export_job
TO kuc_app;
GRANT SELECT, INSERT ON privacy.consent_aggregate TO kuc_app;
REVOKE DELETE ON ALL TABLES IN SCHEMA core, iam, oauth, org, authz, profile, privacy, assurance, workload, integration, messaging, audit FROM kuc_app;
REVOKE UPDATE ON iam.subject_assignment, profile.profile_change FROM kuc_app;
GRANT INSERT ON integration.outbox_event, audit.audit_outbox, messaging.message_send TO kuc_app;
GRANT INSERT ON authz.authorization_decision TO kuc_app;

-- 认证写入方：认证秘密、Login/Session/Grant/Token、撤销、风险信号和事务 Outbox。
GRANT USAGE ON SCHEMA core, iam, authn, oauth, org, privacy, risk, assurance, workload, integration, audit TO kuc_authn_writer;
GRANT SELECT ON ALL TABLES IN SCHEMA core, iam, authn, oauth, org, privacy, risk, assurance, workload TO kuc_authn_writer;
GRANT USAGE ON SCHEMA federation TO kuc_authn_writer;
GRANT SELECT ON federation.identity_provider, federation.identity_provider_key,
    federation.external_identity, federation.attribute_mapping, federation.assertion_replay
TO kuc_authn_writer;
GRANT INSERT, UPDATE ON federation.external_identity TO kuc_authn_writer;
GRANT INSERT ON federation.identity_provider_key, federation.assertion_replay TO kuc_authn_writer;
GRANT SELECT, INSERT, UPDATE ON ALL TABLES IN SCHEMA authn TO kuc_authn_writer;
GRANT SELECT, INSERT, UPDATE ON
    oauth.device, oauth.authorization_grant, oauth.user_session, oauth.token_family,
    oauth.refresh_token, oauth.authorization_code, oauth.reference_access_token,
    oauth.revocation_record, oauth.logout_request, oauth.logout_target_result,
    workload.token_exchange
TO kuc_authn_writer;
REVOKE DELETE ON ALL TABLES IN SCHEMA authn, oauth FROM kuc_authn_writer;
GRANT INSERT ON risk.risk_signal, integration.outbox_event, audit.audit_outbox TO kuc_authn_writer;

-- 控制面写入方：版本化配置、审批、策略、联合、密钥、机器身份和合规配置。
GRANT USAGE ON SCHEMA core, oauth, org, authz, profile, privacy, federation, risk, workload, assurance, crypto, control, integration, messaging, audit TO kuc_control_writer;
GRANT SELECT ON ALL TABLES IN SCHEMA core, federation, risk, assurance, crypto, control TO kuc_control_writer;
GRANT SELECT, INSERT, UPDATE ON ALL TABLES IN SCHEMA control, crypto, federation, risk, assurance TO kuc_control_writer;
GRANT SELECT, INSERT, UPDATE ON
    oauth.application, oauth.client, oauth.client_uri, oauth.client_credential,
    oauth.api_resource, oauth.scope_definition,
    org.business_line, org.tenant, org.tenant_domain, org.organization,
    authz.permission, authz.role, authz.role_permission, authz.role_exclusion,
    authz.role_assignment, authz.policy_release, authz.obligation_type,
    authz.pep_capability, authz.access_review, authz.permission_simulation,
    profile.field_definition,

    privacy.purpose, privacy.data_category, privacy.purpose_data_mapping, privacy.agreement,
    privacy.legal_hold, privacy.retention_rule, privacy.cross_border_authorization,
    privacy.minor_protection, privacy.privacy_impact_assessment,
    workload.machine_principal, workload.machine_credential,
    workload.trust_bundle, workload.workload_attestation,
    integration.event_schema, integration.webhook_subscription, integration.event_replay_request,
    messaging.provider, messaging.route_policy, messaging.message_template, messaging.content_compliance_rule
TO kuc_control_writer;
REVOKE DELETE ON ALL TABLES IN SCHEMA oauth, org, authz, profile, privacy, federation, risk, workload, assurance, crypto, control, integration, messaging FROM kuc_control_writer;
GRANT INSERT ON integration.outbox_event, audit.audit_outbox TO kuc_control_writer;

-- Outbox/Webhook 投递方：正文只读，只能更新明确的投递列；每次 Webhook 尝试新增一行。
GRANT USAGE ON SCHEMA integration TO kuc_outbox_dispatcher;
GRANT SELECT ON integration.outbox_event, integration.webhook_subscription,
    integration.webhook_delivery, integration.event_schema, integration.consumer_watermark TO kuc_outbox_dispatcher;
GRANT UPDATE (publish_state, attempt_count, next_attempt_at, published_at, broker_partition, broker_offset, last_error_code)
    ON integration.outbox_event TO kuc_outbox_dispatcher;
GRANT INSERT ON integration.webhook_delivery TO kuc_outbox_dispatcher;
GRANT UPDATE (delivery_state, response_status, response_body_hash, next_attempt_at, first_attempt_at, delivered_at, dead_lettered_at)
    ON integration.webhook_delivery TO kuc_outbox_dispatcher;
GRANT INSERT, UPDATE ON integration.consumer_watermark TO kuc_outbox_dispatcher;

-- 消息投递方：目标和模板只读，只推进发送元数据并追加回执/指标。
GRANT USAGE ON SCHEMA messaging, iam, integration, audit TO kuc_message_dispatcher;
GRANT SELECT ON ALL TABLES IN SCHEMA messaging TO kuc_message_dispatcher;
GRANT SELECT (id, identifier_state, value_cipher, cipher_key_version, value_masked)
    ON iam.identifier TO kuc_message_dispatcher;
GRANT UPDATE (send_state, provider_id, provider_message_ref_hash, attempt_count, next_attempt_at,
              sent_at, delivered_at, failed_at, failure_code, updated_at, row_version)
    ON messaging.message_send TO kuc_message_dispatcher;
GRANT INSERT ON messaging.delivery_receipt, messaging.provider_metric, integration.outbox_event, audit.audit_outbox TO kuc_message_dispatcher;
GRANT INSERT, UPDATE ON messaging.reachability TO kuc_message_dispatcher;

-- 审计写入方：追加审计证据，并只推进本地审计 Outbox 的远端持久化状态。
GRANT USAGE ON SCHEMA audit, core, control, authz, org TO kuc_audit_writer;
GRANT SELECT ON ALL TABLES IN SCHEMA audit TO kuc_audit_writer;
GRANT SELECT ON core.data_classification, control.approval_case, authz.authorization_decision, org.tenant TO kuc_audit_writer;
GRANT INSERT ON audit.audit_outbox, audit.audit_event, audit.audit_seal, audit.data_access_event TO kuc_audit_writer;
GRANT UPDATE (persistence_state, remote_persisted_at) ON audit.audit_outbox TO kuc_audit_writer;

-- 审计员：审计、控制面和数据字典只读。
GRANT USAGE ON SCHEMA audit, core, control TO kuc_auditor;
GRANT SELECT ON ALL TABLES IN SCHEMA audit, control TO kuc_auditor;
GRANT SELECT ON core.data_dictionary, core.requirement_trace, core.security_profile, core.error_registry TO kuc_auditor;

-- 运维只读：默认广泛只读，但明确排除秘密、Token、PII 密文和密钥引用。
GRANT USAGE ON SCHEMA core, iam, authn, oauth, org, authz, profile, privacy, federation, risk, workload, assurance, crypto, control, integration, audit, messaging, migration TO kuc_readonly;
GRANT SELECT ON ALL TABLES IN SCHEMA core, iam, authn, oauth, org, authz, profile, privacy, federation, risk, workload, assurance, crypto, control, integration, audit, messaging, migration TO kuc_readonly;
REVOKE SELECT ON
    iam.identifier, iam.identifier_tombstone,
    authn.password_credential, authn.password_history, authn.recovery_code,
    authn.verification_challenge, authn.device_authorization,
    oauth.client_credential, oauth.refresh_token, oauth.authorization_code, oauth.reference_access_token,
    profile.sensitive_attribute, profile.business_profile,
    workload.machine_credential, crypto.key_asset,
    audit.audit_outbox, messaging.message_send
FROM kuc_readonly;

-- 迁移角色只负责 DDL/验收；生产迁移先 SET ROLE kuc_owner，再执行迁移文件。
GRANT USAGE, CREATE ON SCHEMA core, iam, authn, oauth, org, authz, profile, privacy, federation, risk, workload, assurance, crypto, control, integration, audit, messaging, migration TO kuc_migrator;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA core, iam, authn, oauth, org, authz, profile, privacy, federation, risk, workload, assurance, crypto, control, integration, audit, messaging, migration TO kuc_migrator;
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA core, iam, authn, oauth, org, authz, profile, privacy, federation, risk, workload, assurance, crypto, control, integration, audit, messaging, migration TO kuc_migrator;

GRANT EXECUTE ON FUNCTION core.fn_hash_jsonb(jsonb) TO kuc_audit_writer;
GRANT EXECUTE ON FUNCTION oauth.fn_mark_refresh_token_reuse(uuid, text) TO kuc_authn_writer;
REVOKE ALL ON FUNCTION core.fn_apply_complete_column_comments() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION core.fn_apply_complete_column_comments() TO kuc_migrator;
REVOKE ALL ON FUNCTION core.fn_apply_complete_object_comments() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION core.fn_apply_complete_object_comments() TO kuc_migrator;

-- 将平台对象从构建登录用户转交统一 NOLOGIN owner，RLS 才不会被应用角色以 owner 身份绕过。
DO $$
DECLARE r record;
BEGIN
    FOR r IN
        SELECT nspname FROM pg_namespace
         WHERE nspname = ANY(ARRAY['core','iam','authn','oauth','org','authz','profile','privacy','federation','risk','workload','assurance','crypto','control','integration','audit','messaging','migration'])
    LOOP
        EXECUTE format('ALTER SCHEMA %I OWNER TO kuc_owner', r.nspname);
    END LOOP;

    FOR r IN
        SELECT c.oid::regclass AS object_name, c.relkind
          FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
         WHERE n.nspname = ANY(ARRAY['core','iam','authn','oauth','org','authz','profile','privacy','federation','risk','workload','assurance','crypto','control','integration','audit','messaging','migration'])
           AND c.relkind IN ('r','p','v','m','S','f')
    LOOP
        EXECUTE CASE r.relkind
            WHEN 'v' THEN format('ALTER VIEW %s OWNER TO kuc_owner', r.object_name)
            WHEN 'm' THEN format('ALTER MATERIALIZED VIEW %s OWNER TO kuc_owner', r.object_name)
            WHEN 'S' THEN format('ALTER SEQUENCE %s OWNER TO kuc_owner', r.object_name)
            WHEN 'f' THEN format('ALTER FOREIGN TABLE %s OWNER TO kuc_owner', r.object_name)
            ELSE format('ALTER TABLE %s OWNER TO kuc_owner', r.object_name)
        END;
    END LOOP;

    FOR r IN
        SELECT n.nspname, p.proname, p.prokind, pg_get_function_identity_arguments(p.oid) AS identity_arguments
          FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
         WHERE n.nspname = ANY(ARRAY['core','iam','authn','oauth','org','authz','profile','privacy','federation','risk','workload','assurance','crypto','control','integration','audit','messaging','migration'])

    LOOP
        IF r.prokind = 'p' THEN
            EXECUTE format('ALTER PROCEDURE %I.%I(%s) OWNER TO kuc_owner', r.nspname, r.proname, r.identity_arguments);
        ELSIF r.prokind = 'a' THEN
            EXECUTE format('ALTER AGGREGATE %I.%I(%s) OWNER TO kuc_owner', r.nspname, r.proname, r.identity_arguments);
        ELSE
            EXECUTE format('ALTER FUNCTION %I.%I(%s) OWNER TO kuc_owner', r.nspname, r.proname, r.identity_arguments);
        END IF;
    END LOOP;
END;
$$;

ALTER DEFAULT PRIVILEGES FOR ROLE kuc_owner
    REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
ALTER DEFAULT PRIVILEGES FOR ROLE kuc_owner IN SCHEMA core, iam, authn, oauth, org, authz, profile, privacy, federation, risk, workload, assurance, crypto, control, integration, audit, messaging, migration
    GRANT ALL PRIVILEGES ON TABLES TO kuc_migrator;
ALTER DEFAULT PRIVILEGES FOR ROLE kuc_owner IN SCHEMA core, iam, authn, oauth, org, authz, profile, privacy, federation, risk, workload, assurance, crypto, control, integration, audit, messaging, migration
    GRANT EXECUTE ON FUNCTIONS TO kuc_migrator;

SET ROLE kuc_owner;
SELECT core.fn_register_migration('baseline:roles', '统一对象所有者、显式最小权限与职责分离角色');
RESET ROLE;
COMMIT;
\endif

