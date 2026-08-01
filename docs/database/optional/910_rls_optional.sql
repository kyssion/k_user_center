-- =============================================================================
-- 910_rls_optional.sql
-- 可选 PostgreSQL RLS。启用前必须完成连接池事务级 tenant context 集成测试。
-- =============================================================================

BEGIN;

-- 直接 tenant_id 表：业务角色只能访问当前租户；控制、审计、迁移与 owner 角色受控全局访问。
DO $$
DECLARE r record;
BEGIN
    FOR r IN
        SELECT n.nspname AS schema_name, c.relname AS table_name
          FROM pg_class c
          JOIN pg_namespace n ON n.oid = c.relnamespace
          JOIN pg_attribute a ON a.attrelid = c.oid AND a.attname = 'tenant_id' AND NOT a.attisdropped
         WHERE n.nspname = ANY(ARRAY['core','iam','authn','oauth','org','authz','profile','privacy','federation','risk','workload','assurance','crypto','control','integration','audit','messaging','migration'])
           AND c.relkind = 'r'
    LOOP
        EXECUTE format('ALTER TABLE %I.%I ENABLE ROW LEVEL SECURITY', r.schema_name, r.table_name);
        EXECUTE format('ALTER TABLE %I.%I FORCE ROW LEVEL SECURITY', r.schema_name, r.table_name);
        EXECUTE format('DROP POLICY IF EXISTS tenant_context_policy ON %I.%I', r.schema_name, r.table_name);
        EXECUTE format(
            'CREATE POLICY tenant_context_policy ON %I.%I '
            'TO kuc_app, kuc_authn_writer, kuc_outbox_dispatcher, kuc_message_dispatcher, kuc_readonly '
            'USING (tenant_id = NULLIF(current_setting(''app.tenant_id'', true), '''')::uuid) '
            'WITH CHECK (tenant_id = NULLIF(current_setting(''app.tenant_id'', true), '''')::uuid)',
            r.schema_name, r.table_name
        );
        EXECUTE format('DROP POLICY IF EXISTS platform_control_policy ON %I.%I', r.schema_name, r.table_name);
        EXECUTE format(
            'CREATE POLICY platform_control_policy ON %I.%I '
            'TO kuc_owner, kuc_control_writer, kuc_audit_writer, kuc_auditor, kuc_migrator '
            'USING (true) WITH CHECK (true)',
            r.schema_name, r.table_name
        );
    END LOOP;
END;
$$;

ALTER TABLE org.tenant ENABLE ROW LEVEL SECURITY;
ALTER TABLE org.tenant FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_root_context_policy ON org.tenant;
CREATE POLICY tenant_root_context_policy ON org.tenant
    TO kuc_app, kuc_authn_writer, kuc_outbox_dispatcher, kuc_message_dispatcher, kuc_readonly
    USING (id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
    WITH CHECK (id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
DROP POLICY IF EXISTS tenant_root_platform_policy ON org.tenant;
CREATE POLICY tenant_root_platform_policy ON org.tenant
    TO kuc_owner, kuc_control_writer, kuc_audit_writer, kuc_auditor, kuc_migrator
    USING (true) WITH CHECK (true);

ALTER TABLE org.business_line ENABLE ROW LEVEL SECURITY;
ALTER TABLE org.business_line FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS business_line_context_policy ON org.business_line;
CREATE POLICY business_line_context_policy ON org.business_line
    TO kuc_app, kuc_authn_writer, kuc_outbox_dispatcher, kuc_message_dispatcher, kuc_readonly
    USING (EXISTS (
        SELECT 1 FROM org.tenant t
         WHERE t.id = NULLIF(current_setting('app.tenant_id', true), '')::uuid
           AND t.business_line_id = org.business_line.id
    ))
    WITH CHECK (EXISTS (
        SELECT 1 FROM org.tenant t
         WHERE t.id = NULLIF(current_setting('app.tenant_id', true), '')::uuid
           AND t.business_line_id = org.business_line.id
    ));
DROP POLICY IF EXISTS business_line_platform_policy ON org.business_line;
CREATE POLICY business_line_platform_policy ON org.business_line
    TO kuc_owner, kuc_control_writer, kuc_audit_writer, kuc_auditor, kuc_migrator
    USING (true) WITH CHECK (true);

-- Role/Assignment 的 tenant_id 可为空；业务线作用域只对该业务线下的当前租户可见，平台作用域不下放给普通租户角色。
DROP POLICY IF EXISTS tenant_context_policy ON authz.role;
CREATE POLICY tenant_context_policy ON authz.role
    TO kuc_app, kuc_authn_writer, kuc_outbox_dispatcher, kuc_message_dispatcher, kuc_readonly
    USING (
        authz.role.tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid
        OR (
            authz.role.tenant_id IS NULL
            AND authz.role.business_line_id IS NOT NULL
            AND EXISTS (
                SELECT 1 FROM org.tenant t
                 WHERE t.id = NULLIF(current_setting('app.tenant_id', true), '')::uuid
                   AND t.business_line_id = authz.role.business_line_id
            )
        )
    )
    WITH CHECK (
        authz.role.tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid
        OR (
            authz.role.tenant_id IS NULL
            AND authz.role.business_line_id IS NOT NULL
            AND EXISTS (
                SELECT 1 FROM org.tenant t
                 WHERE t.id = NULLIF(current_setting('app.tenant_id', true), '')::uuid
                   AND t.business_line_id = authz.role.business_line_id
            )
        )
    );

DROP POLICY IF EXISTS tenant_context_policy ON authz.role_assignment;
CREATE POLICY tenant_context_policy ON authz.role_assignment
    TO kuc_app, kuc_authn_writer, kuc_outbox_dispatcher, kuc_message_dispatcher, kuc_readonly
    USING (
        authz.role_assignment.tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid
        OR (
            authz.role_assignment.tenant_id IS NULL
            AND authz.role_assignment.business_line_id IS NOT NULL
            AND EXISTS (
                SELECT 1 FROM org.tenant t
                 WHERE t.id = NULLIF(current_setting('app.tenant_id', true), '')::uuid
                   AND t.business_line_id = authz.role_assignment.business_line_id
            )
        )
    )
    WITH CHECK (
        authz.role_assignment.tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid
        OR (
            authz.role_assignment.tenant_id IS NULL
            AND authz.role_assignment.business_line_id IS NOT NULL
            AND EXISTS (
                SELECT 1 FROM org.tenant t
                 WHERE t.id = NULLIF(current_setting('app.tenant_id', true), '')::uuid
                   AND t.business_line_id = authz.role_assignment.business_line_id
            )
        )
    );

-- 无 tenant_id 但可由一跳/两跳外键确定租户的表，同样启用派生 RLS。
DO $$
DECLARE r record;
BEGIN
    FOR r IN
        SELECT * FROM (VALUES
            ('core.async_operation_step'::regclass, 'EXISTS (SELECT 1 FROM core.async_operation p WHERE p.id = core.async_operation_step.operation_id AND p.tenant_id = NULLIF(current_setting(''app.tenant_id'', true), '''')::uuid)'),
            ('authn.login_factor'::regclass, 'EXISTS (SELECT 1 FROM authn.login_transaction p WHERE p.id = authn.login_factor.login_transaction_id AND p.tenant_id = NULLIF(current_setting(''app.tenant_id'', true), '''')::uuid)'),
            ('oauth.application'::regclass, 'EXISTS (SELECT 1 FROM org.tenant p WHERE p.id = NULLIF(current_setting(''app.tenant_id'', true), '''')::uuid AND p.business_line_id = oauth.application.business_line_id)'),
            ('oauth.api_resource'::regclass, 'EXISTS (SELECT 1 FROM org.tenant p WHERE p.id = NULLIF(current_setting(''app.tenant_id'', true), '''')::uuid AND p.business_line_id = oauth.api_resource.business_line_id)'),
            ('oauth.scope_definition'::regclass, 'EXISTS (SELECT 1 FROM oauth.api_resource r JOIN org.tenant p ON p.business_line_id = r.business_line_id WHERE r.id = oauth.scope_definition.api_resource_id AND p.id = NULLIF(current_setting(''app.tenant_id'', true), '''')::uuid)'),
            ('oauth.client_uri'::regclass, 'EXISTS (SELECT 1 FROM oauth.client p WHERE p.id = oauth.client_uri.client_id AND p.tenant_id = NULLIF(current_setting(''app.tenant_id'', true), '''')::uuid)'),
            ('oauth.client_credential'::regclass, 'EXISTS (SELECT 1 FROM oauth.client p WHERE p.id = oauth.client_credential.client_id AND p.tenant_id = NULLIF(current_setting(''app.tenant_id'', true), '''')::uuid)'),
            ('oauth.refresh_token'::regclass, 'EXISTS (SELECT 1 FROM oauth.token_family p WHERE p.id = oauth.refresh_token.family_id AND p.tenant_id = NULLIF(current_setting(''app.tenant_id'', true), '''')::uuid)'),
            ('oauth.authorization_code'::regclass, 'EXISTS (SELECT 1 FROM oauth.authorization_grant p WHERE p.id = oauth.authorization_code.grant_id AND p.tenant_id = NULLIF(current_setting(''app.tenant_id'', true), '''')::uuid)'),
            ('oauth.logout_request'::regclass, 'EXISTS (SELECT 1 FROM core.async_operation p WHERE p.id = oauth.logout_request.operation_id AND p.tenant_id = NULLIF(current_setting(''app.tenant_id'', true), '''')::uuid)'),
            ('oauth.logout_target_result'::regclass, 'EXISTS (SELECT 1 FROM oauth.logout_request lr JOIN core.async_operation p ON p.id = lr.operation_id WHERE lr.id = oauth.logout_target_result.logout_request_id AND p.tenant_id = NULLIF(current_setting(''app.tenant_id'', true), '''')::uuid)'),
            ('org.group_member'::regclass, 'EXISTS (SELECT 1 FROM org.user_group p WHERE p.id = org.group_member.group_id AND p.tenant_id = NULLIF(current_setting(''app.tenant_id'', true), '''')::uuid)'),
            ('authz.role_permission'::regclass, 'EXISTS (SELECT 1 FROM authz.role p JOIN org.tenant t ON t.id = NULLIF(current_setting(''app.tenant_id'', true), '''')::uuid WHERE p.id = authz.role_permission.role_id AND (p.tenant_id = t.id OR (p.tenant_id IS NULL AND p.business_line_id = t.business_line_id)))'),
            ('authz.role_exclusion'::regclass, 'EXISTS (SELECT 1 FROM authz.role p JOIN org.tenant t ON t.id = NULLIF(current_setting(''app.tenant_id'', true), '''')::uuid WHERE p.id = authz.role_exclusion.role_id AND (p.tenant_id = t.id OR (p.tenant_id IS NULL AND p.business_line_id = t.business_line_id)))'),
            ('authz.access_review'::regclass, 'EXISTS (SELECT 1 FROM core.async_operation p WHERE p.id = authz.access_review.operation_id AND p.tenant_id = NULLIF(current_setting(''app.tenant_id'', true), '''')::uuid)'),
            ('control.approval_decision'::regclass, 'EXISTS (SELECT 1 FROM control.approval_case p WHERE p.id = control.approval_decision.approval_case_id AND p.tenant_id = NULLIF(current_setting(''app.tenant_id'', true), '''')::uuid)'),
            ('control.client_certification_run'::regclass, 'EXISTS (SELECT 1 FROM oauth.client p WHERE p.id = control.client_certification_run.client_id AND p.tenant_id = NULLIF(current_setting(''app.tenant_id'', true), '''')::uuid)'),
            ('profile.business_profile'::regclass, 'EXISTS (SELECT 1 FROM org.membership p WHERE p.id = profile.business_profile.membership_id AND p.tenant_id = NULLIF(current_setting(''app.tenant_id'', true), '''')::uuid)'),
            ('profile.profile_change'::regclass, '(profile.profile_change.membership_id IS NOT NULL AND EXISTS (SELECT 1 FROM org.membership p WHERE p.id = profile.profile_change.membership_id AND p.tenant_id = NULLIF(current_setting(''app.tenant_id'', true), '''')::uuid)) OR (profile.profile_change.user_id IS NOT NULL AND EXISTS (SELECT 1 FROM org.membership p WHERE p.user_id = profile.profile_change.user_id AND p.tenant_id = NULLIF(current_setting(''app.tenant_id'', true), '''')::uuid AND p.membership_state = ''ACTIVE''))'),
            ('privacy.consent'::regclass, 'EXISTS (SELECT 1 FROM privacy.consent_aggregate p WHERE p.id = privacy.consent.aggregate_id AND p.tenant_id = NULLIF(current_setting(''app.tenant_id'', true), '''')::uuid)'),
            ('privacy.privacy_request'::regclass, 'EXISTS (SELECT 1 FROM core.async_operation p WHERE p.id = privacy.privacy_request.operation_id AND p.tenant_id = NULLIF(current_setting(''app.tenant_id'', true), '''')::uuid)'),
            ('privacy.privacy_request_task'::regclass, 'EXISTS (SELECT 1 FROM privacy.privacy_request pr JOIN core.async_operation p ON p.id = pr.operation_id WHERE pr.id = privacy.privacy_request_task.privacy_request_id AND p.tenant_id = NULLIF(current_setting(''app.tenant_id'', true), '''')::uuid)'),
            ('privacy.export_job'::regclass, 'EXISTS (SELECT 1 FROM privacy.privacy_request pr JOIN core.async_operation p ON p.id = pr.operation_id WHERE pr.id = privacy.export_job.privacy_request_id AND p.tenant_id = NULLIF(current_setting(''app.tenant_id'', true), '''')::uuid)'),
            ('privacy.deletion_proof'::regclass, 'EXISTS (SELECT 1 FROM privacy.privacy_request pr JOIN core.async_operation p ON p.id = pr.operation_id WHERE pr.id = privacy.deletion_proof.privacy_request_id AND p.tenant_id = NULLIF(current_setting(''app.tenant_id'', true), '''')::uuid)'),
            ('federation.identity_provider_key'::regclass, 'EXISTS (SELECT 1 FROM federation.identity_provider p WHERE p.id = federation.identity_provider_key.identity_provider_id AND p.tenant_id = NULLIF(current_setting(''app.tenant_id'', true), '''')::uuid)'),
            ('federation.external_identity'::regclass, 'EXISTS (SELECT 1 FROM federation.identity_provider p WHERE p.id = federation.external_identity.identity_provider_id AND p.tenant_id = NULLIF(current_setting(''app.tenant_id'', true), '''')::uuid)'),
            ('federation.attribute_mapping'::regclass, 'EXISTS (SELECT 1 FROM federation.identity_provider p WHERE p.id = federation.attribute_mapping.identity_provider_id AND p.tenant_id = NULLIF(current_setting(''app.tenant_id'', true), '''')::uuid)'),
            ('federation.directory_object'::regclass, 'EXISTS (SELECT 1 FROM federation.directory_connection p WHERE p.id = federation.directory_object.directory_connection_id AND p.tenant_id = NULLIF(current_setting(''app.tenant_id'', true), '''')::uuid)'),
            ('federation.directory_sync_run'::regclass, 'EXISTS (SELECT 1 FROM federation.directory_connection p WHERE p.id = federation.directory_sync_run.directory_connection_id AND p.tenant_id = NULLIF(current_setting(''app.tenant_id'', true), '''')::uuid)'),
            ('federation.assertion_replay'::regclass, 'EXISTS (SELECT 1 FROM federation.identity_provider p WHERE p.id = federation.assertion_replay.identity_provider_id AND p.tenant_id = NULLIF(current_setting(''app.tenant_id'', true), '''')::uuid)'),
            ('integration.webhook_delivery'::regclass, 'EXISTS (SELECT 1 FROM integration.webhook_subscription p WHERE p.id = integration.webhook_delivery.subscription_id AND p.tenant_id = NULLIF(current_setting(''app.tenant_id'', true), '''')::uuid)'),
            ('messaging.delivery_receipt'::regclass, 'EXISTS (SELECT 1 FROM messaging.message_send p WHERE p.id = messaging.delivery_receipt.message_send_id AND p.tenant_id = NULLIF(current_setting(''app.tenant_id'', true), '''')::uuid)'),
            ('messaging.reachability'::regclass, 'EXISTS (SELECT 1 FROM iam.identifier i JOIN org.membership m ON m.user_id = i.user_id WHERE i.id = messaging.reachability.identifier_id AND m.tenant_id = NULLIF(current_setting(''app.tenant_id'', true), '''')::uuid AND m.membership_state = ''ACTIVE'')'),
            ('workload.machine_credential'::regclass, 'EXISTS (SELECT 1 FROM workload.machine_principal p WHERE p.id = workload.machine_credential.machine_principal_id AND p.tenant_id = NULLIF(current_setting(''app.tenant_id'', true), '''')::uuid)'),
            ('workload.workload_attestation'::regclass, 'EXISTS (SELECT 1 FROM workload.machine_principal p WHERE p.id = workload.workload_attestation.machine_principal_id AND p.tenant_id = NULLIF(current_setting(''app.tenant_id'', true), '''')::uuid)'),
            ('migration.migration_batch'::regclass, 'EXISTS (SELECT 1 FROM core.async_operation p WHERE p.id = migration.migration_batch.operation_id AND p.tenant_id = NULLIF(current_setting(''app.tenant_id'', true), '''')::uuid)'),
            ('migration.authority_lease'::regclass, 'EXISTS (SELECT 1 FROM migration.migration_batch b JOIN core.async_operation p ON p.id = b.operation_id WHERE b.id = migration.authority_lease.migration_batch_id AND p.tenant_id = NULLIF(current_setting(''app.tenant_id'', true), '''')::uuid)'),
            ('migration.legacy_id_mapping'::regclass, 'EXISTS (SELECT 1 FROM migration.migration_batch b JOIN core.async_operation p ON p.id = b.operation_id WHERE b.id = migration.legacy_id_mapping.migration_batch_id AND p.tenant_id = NULLIF(current_setting(''app.tenant_id'', true), '''')::uuid)'),
            ('migration.duplicate_candidate'::regclass, 'EXISTS (SELECT 1 FROM migration.migration_batch b JOIN core.async_operation p ON p.id = b.operation_id WHERE b.id = migration.duplicate_candidate.migration_batch_id AND p.tenant_id = NULLIF(current_setting(''app.tenant_id'', true), '''')::uuid)'),
            ('migration.change_log'::regclass, 'EXISTS (SELECT 1 FROM migration.migration_batch b JOIN core.async_operation p ON p.id = b.operation_id WHERE b.id = migration.change_log.migration_batch_id AND p.tenant_id = NULLIF(current_setting(''app.tenant_id'', true), '''')::uuid)'),
            ('migration.reconciliation_run'::regclass, 'EXISTS (SELECT 1 FROM migration.migration_batch b JOIN core.async_operation p ON p.id = b.operation_id WHERE b.id = migration.reconciliation_run.migration_batch_id AND p.tenant_id = NULLIF(current_setting(''app.tenant_id'', true), '''')::uuid)'),
            ('migration.rollback_execution'::regclass, 'EXISTS (SELECT 1 FROM migration.migration_batch b JOIN core.async_operation p ON p.id = b.operation_id WHERE b.id = migration.rollback_execution.migration_batch_id AND p.tenant_id = NULLIF(current_setting(''app.tenant_id'', true), '''')::uuid)')
        ) AS x(table_name, predicate)
    LOOP
        EXECUTE format('ALTER TABLE %s ENABLE ROW LEVEL SECURITY', r.table_name);
        EXECUTE format('ALTER TABLE %s FORCE ROW LEVEL SECURITY', r.table_name);
        EXECUTE format('DROP POLICY IF EXISTS derived_tenant_context_policy ON %s', r.table_name);
        EXECUTE format(
            'CREATE POLICY derived_tenant_context_policy ON %s '
            'TO kuc_app, kuc_authn_writer, kuc_outbox_dispatcher, kuc_message_dispatcher, kuc_readonly '
            'USING (%s) WITH CHECK (%s)',
            r.table_name, r.predicate, r.predicate
        );
        EXECUTE format('DROP POLICY IF EXISTS derived_platform_control_policy ON %s', r.table_name);
        EXECUTE format(
            'CREATE POLICY derived_platform_control_policy ON %s '
            'TO kuc_owner, kuc_control_writer, kuc_audit_writer, kuc_auditor, kuc_migrator '
            'USING (true) WITH CHECK (true)',
            r.table_name
        );
    END LOOP;
END;
$$;

COMMENT ON SCHEMA org IS '业务线、租户、组织、Membership、Invitation、用户组与计量；可选 PostgreSQL RLS 已覆盖直接 tenant_id 与关键派生租户关系。';
SELECT core.fn_register_migration('910', '可选 PostgreSQL RLS：直接与派生租户隔离策略', NULLIF(current_setting('kuc.migration_sha256', true), ''));
COMMIT;
