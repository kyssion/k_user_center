-- =============================================================================
-- 075_integrity_hardening.sql
-- 跨领域安全不变量、租户完整性、不可变发布、上下文绑定与索引加固
-- =============================================================================

BEGIN;
SET LOCAL lock_timeout = '10s';
SET LOCAL statement_timeout = '10min';

-- -----------------------------------------------------------------------------
-- 1. 可轮换检索摘要与低熵秘密摘要元数据
-- -----------------------------------------------------------------------------

ALTER TABLE iam.identifier
    ADD COLUMN ownership_digest bytea NOT NULL,
    ADD COLUMN ownership_key_version integer NOT NULL;
ALTER TABLE iam.identifier
    ADD CONSTRAINT ck_identifier_ownership_digest CHECK (octet_length(ownership_digest) = 32 AND ownership_key_version > 0);

DROP INDEX ux_identifier_verified_scope;
CREATE UNIQUE INDEX ux_identifier_verified_scope
    ON iam.identifier(identifier_type, uniqueness_scope, scope_ref_id, ownership_digest)
    WHERE identifier_state = 'VERIFIED';

ALTER TABLE iam.identifier_tombstone DROP CONSTRAINT uq_identifier_tombstone;
ALTER TABLE iam.identifier_tombstone
    ADD COLUMN ownership_key_version integer NOT NULL DEFAULT 1,
    ADD CONSTRAINT uq_identifier_tombstone UNIQUE (identifier_type, uniqueness_scope, scope_ref_id, ownership_digest),
    ADD CONSTRAINT ck_identifier_tombstone_ownership CHECK (octet_length(ownership_digest) = 32 AND ownership_key_version > 0);

ALTER TABLE authn.recovery_code
    ADD COLUMN hash_algorithm text NOT NULL DEFAULT 'HMAC-SHA-256',
    ADD COLUMN hash_key_version integer NOT NULL DEFAULT 1,
    ADD CONSTRAINT ck_recovery_code_hash_profile CHECK (hash_algorithm IN ('HMAC-SHA-256', 'HMAC-SM3') AND hash_key_version > 0);

ALTER TABLE authn.verification_challenge
    ADD COLUMN hash_algorithm text NOT NULL DEFAULT 'HMAC-SHA-256',
    ADD COLUMN hash_key_version integer NOT NULL DEFAULT 1,
    ADD CONSTRAINT ck_challenge_hash_profile CHECK (hash_algorithm IN ('HMAC-SHA-256', 'HMAC-SM3') AND hash_key_version > 0);

ALTER TABLE authn.device_authorization
    ADD COLUMN device_code_hash_algorithm text NOT NULL DEFAULT 'SHA-256',
    ADD COLUMN user_code_hash_algorithm text NOT NULL DEFAULT 'HMAC-SHA-256',
    ADD COLUMN user_code_hash_key_version integer NOT NULL DEFAULT 1,
    ADD CONSTRAINT ck_device_code_hash_profile CHECK (device_code_hash_algorithm IN ('SHA-256', 'SM3')),
    ADD CONSTRAINT ck_user_code_hash_profile CHECK (user_code_hash_algorithm IN ('HMAC-SHA-256', 'HMAC-SM3') AND user_code_hash_key_version > 0);

ALTER TABLE oauth.client
    ADD COLUMN configuration_hash bytea NOT NULL,
    ADD CONSTRAINT ck_client_configuration_hash CHECK (octet_length(configuration_hash) = 32);

ALTER TABLE federation.identity_provider
    ADD COLUMN configuration_hash bytea NOT NULL,
    ADD CONSTRAINT ck_identity_provider_configuration_hash CHECK (octet_length(configuration_hash) = 32);

ALTER TABLE crypto.key_asset
    ADD COLUMN asset_metadata_hash bytea NOT NULL,
    ADD CONSTRAINT ck_key_asset_metadata_hash CHECK (octet_length(asset_metadata_hash) = 32);
ALTER TABLE crypto.key_asset DROP CONSTRAINT ck_key_asset_state;
ALTER TABLE crypto.key_asset
    ADD COLUMN activated_at timestamptz NULL,
    ADD CONSTRAINT ck_key_asset_state CHECK (key_state IN ('GENERATED', 'PUBLISHED', 'SIGNING_AND_VERIFYING', 'ACTIVE', 'VERIFY_ONLY', 'COMPROMISED', 'REVOKED', 'RETIRED', 'DESTROYED')),
    ADD CONSTRAINT ck_key_asset_state_use CHECK (
        (key_use IN ('TOKEN_SIGNING', 'WEBHOOK_SIGNING', 'AUDIT_SEAL') AND key_state <> 'ACTIVE')
        OR (key_use NOT IN ('TOKEN_SIGNING', 'WEBHOOK_SIGNING', 'AUDIT_SEAL') AND key_state NOT IN ('PUBLISHED', 'SIGNING_AND_VERIFYING', 'VERIFY_ONLY'))
    ),
    ADD CONSTRAINT ck_key_asset_state_time CHECK (
        (key_state NOT IN ('PUBLISHED', 'SIGNING_AND_VERIFYING', 'VERIFY_ONLY') OR published_at IS NOT NULL)
        AND (key_state NOT IN ('SIGNING_AND_VERIFYING', 'VERIFY_ONLY') OR signing_started_at IS NOT NULL)
        AND (key_state <> 'ACTIVE' OR activated_at IS NOT NULL)
        AND (key_state <> 'VERIFY_ONLY' OR verify_only_at IS NOT NULL)
        AND (key_state <> 'COMPROMISED' OR compromised_at IS NOT NULL)
        AND (key_state <> 'REVOKED' OR revoked_at IS NOT NULL)
        AND (key_state <> 'RETIRED' OR retired_at IS NOT NULL)
    );

ALTER TABLE audit.audit_outbox
    ADD COLUMN tenant_id uuid NOT NULL DEFAULT '00000000-0000-0000-0000-000000000000';

ALTER TABLE control.config_release ADD COLUMN approval_execution_id uuid NULL;
ALTER TABLE authz.policy_release ADD COLUMN approval_execution_id uuid NULL;
ALTER TABLE risk.risk_policy_release ADD COLUMN approval_execution_id uuid NULL;
ALTER TABLE oauth.client
    ADD COLUMN approval_execution_id uuid NULL,
    ADD COLUMN last_activation_execution_id uuid NULL;
ALTER TABLE federation.identity_provider
    ADD COLUMN approval_execution_id uuid NULL,
    ADD COLUMN last_activation_execution_id uuid NULL;
ALTER TABLE crypto.key_asset ADD COLUMN approval_execution_id uuid NULL;
ALTER TABLE authz.role_assignment
    ADD COLUMN approval_execution_id uuid NULL,
    ADD COLUMN last_activation_execution_id uuid NULL,
    ADD CONSTRAINT ck_role_assignment_revoke_reason CHECK (
        assignment_state <> 'REVOKED' OR NULLIF(btrim(revoke_reason_code), '') IS NOT NULL
    );

-- Consent 是可重复作出的版本化决定；PENDING 不得提前失效当前 GRANTED 决定。
ALTER TABLE privacy.consent DROP CONSTRAINT uq_consent_context;
ALTER TABLE privacy.consent
    ADD COLUMN consent_version bigint NOT NULL DEFAULT 1,
    ADD CONSTRAINT uq_consent_version UNIQUE (aggregate_id, consent_version),
    ADD CONSTRAINT ck_consent_version CHECK (consent_version >= 1);
DROP INDEX ux_consent_effective;
CREATE UNIQUE INDEX ux_consent_effective ON privacy.consent(aggregate_id)
    WHERE consent_state = 'GRANTED';
CREATE UNIQUE INDEX ux_consent_pending ON privacy.consent(aggregate_id)
    WHERE consent_state = 'PENDING';

ALTER TABLE control.config_release
    ADD CONSTRAINT ck_config_release_state_times CHECK (
        (staged_at IS NULL OR release_state IN ('STAGED', 'ACTIVE', 'DEPRECATED', 'REVOKED'))
        AND (activated_at IS NULL OR release_state IN ('ACTIVE', 'DEPRECATED', 'REVOKED'))
        AND (deprecated_at IS NULL OR release_state = 'DEPRECATED')
        AND ((release_state = 'STAGED') = (staged_at IS NOT NULL AND activated_at IS NULL AND deprecated_at IS NULL AND revoked_at IS NULL))
        AND (release_state <> 'ACTIVE' OR (staged_at IS NOT NULL AND activated_at IS NOT NULL AND deprecated_at IS NULL AND revoked_at IS NULL))
        AND (release_state <> 'DEPRECATED' OR (staged_at IS NOT NULL AND activated_at IS NOT NULL AND deprecated_at IS NOT NULL AND revoked_at IS NULL))
        AND ((release_state = 'REVOKED') = (revoked_at IS NOT NULL))
    );
ALTER TABLE authz.policy_release
    ADD COLUMN revoked_at timestamptz NULL,
    ADD CONSTRAINT ck_policy_release_state_times CHECK (
        (activated_at IS NULL OR policy_state IN ('ACTIVE', 'DEPRECATED', 'REVOKED'))
        AND (retired_at IS NULL OR policy_state IN ('DEPRECATED', 'REVOKED'))
        AND (revoked_at IS NULL OR policy_state = 'REVOKED')
        AND (policy_state <> 'ACTIVE' OR activated_at IS NOT NULL)
        AND (policy_state <> 'DEPRECATED' OR (activated_at IS NOT NULL AND retired_at IS NOT NULL))
        AND ((policy_state = 'REVOKED') = (revoked_at IS NOT NULL))
    );
ALTER TABLE risk.risk_policy_release
    ADD COLUMN retired_at timestamptz NULL,
    ADD COLUMN revoked_at timestamptz NULL,
    ADD CONSTRAINT ck_risk_policy_release_state_times CHECK (
        (activated_at IS NULL OR policy_state IN ('ACTIVE', 'DEPRECATED', 'REVOKED'))
        AND (retired_at IS NULL OR policy_state = 'DEPRECATED')
        AND (revoked_at IS NULL OR policy_state = 'REVOKED')
        AND (policy_state <> 'ACTIVE' OR activated_at IS NOT NULL)
        AND (policy_state <> 'DEPRECATED' OR (activated_at IS NOT NULL AND retired_at IS NOT NULL))
        AND ((policy_state = 'REVOKED') = (revoked_at IS NOT NULL))
    );
ALTER TABLE crypto.jwks_release
    ADD CONSTRAINT ck_jwks_release_state_times CHECK (
        (published_at IS NULL OR release_state IN ('PUBLISHED', 'ACTIVE', 'SUPERSEDED', 'REVOKED'))
        AND (release_state NOT IN ('PUBLISHED', 'ACTIVE', 'SUPERSEDED') OR published_at IS NOT NULL)
        AND (expires_at IS NULL OR (published_at IS NOT NULL AND expires_at > published_at))
    );

-- -----------------------------------------------------------------------------
-- 2. 唯一性、组织作用域与同租户关系
-- -----------------------------------------------------------------------------

CREATE UNIQUE INDEX ux_subject_assignment_active
    ON iam.subject_assignment(user_id, audience_kind, audience_ref_id)
    WHERE retired_at IS NULL;

ALTER TABLE core.requirement_trace DROP CONSTRAINT ck_requirement_trace_req;
ALTER TABLE core.requirement_trace
    ADD CONSTRAINT ck_requirement_trace_req CHECK (requirement_id ~ '^(REQ|API|EVT|INV)-[A-Z0-9-]+$');

ALTER TABLE iam.account_merge_item DROP CONSTRAINT uq_account_merge_item;
ALTER TABLE iam.account_merge_item
    ADD CONSTRAINT uq_account_merge_item UNIQUE NULLS NOT DISTINCT (merge_id, domain_code, source_ref, target_ref);

ALTER TABLE authn.login_factor DROP CONSTRAINT uq_login_factor;
ALTER TABLE authn.login_factor
    ADD CONSTRAINT uq_login_factor UNIQUE NULLS NOT DISTINCT (login_transaction_id, amr_value, authenticator_id);

ALTER TABLE privacy.agreement_acceptance DROP CONSTRAINT uq_agreement_acceptance;
ALTER TABLE privacy.agreement_acceptance
    ADD CONSTRAINT uq_agreement_acceptance UNIQUE NULLS NOT DISTINCT (agreement_id, user_id, client_id, tenant_id);

ALTER TABLE org.tenant
    ADD CONSTRAINT uq_tenant_id_business_line UNIQUE (id, business_line_id);
ALTER TABLE org.organization
    ADD CONSTRAINT uq_organization_id_tenant UNIQUE (id, tenant_id);
ALTER TABLE oauth.client
    ADD CONSTRAINT uq_client_id_tenant UNIQUE (id, tenant_id),
    ADD CONSTRAINT uq_client_id_tenant_business UNIQUE (id, tenant_id, business_line_id),
    ADD CONSTRAINT fk_client_tenant FOREIGN KEY (tenant_id) REFERENCES org.tenant(id),
    ADD CONSTRAINT fk_client_tenant_business FOREIGN KEY (tenant_id, business_line_id) REFERENCES org.tenant(id, business_line_id);

ALTER TABLE authn.login_transaction
    ADD CONSTRAINT fk_login_tx_client_scope FOREIGN KEY (client_id, tenant_id, business_line_id)
        REFERENCES oauth.client(id, tenant_id, business_line_id);
ALTER TABLE oauth.authorization_grant
    ADD CONSTRAINT fk_grant_client_scope FOREIGN KEY (client_id, tenant_id)
        REFERENCES oauth.client(id, tenant_id);
ALTER TABLE oauth.user_session
    ADD CONSTRAINT fk_session_client_scope FOREIGN KEY (origin_client_id, tenant_id)
        REFERENCES oauth.client(id, tenant_id);
ALTER TABLE integration.webhook_subscription
    ADD CONSTRAINT fk_webhook_client_scope FOREIGN KEY (client_id, tenant_id)
        REFERENCES oauth.client(id, tenant_id);
ALTER TABLE messaging.message_send
    ADD CONSTRAINT fk_message_client_scope FOREIGN KEY (client_id, tenant_id)
        REFERENCES oauth.client(id, tenant_id);

ALTER TABLE authz.role
    ADD COLUMN organization_id uuid NULL;
ALTER TABLE authz.role DROP CONSTRAINT uq_role_code_scope;
ALTER TABLE authz.role DROP CONSTRAINT ck_role_scope_value;
ALTER TABLE authz.role
    ADD CONSTRAINT uq_role_code_scope UNIQUE NULLS NOT DISTINCT (role_code, scope_kind, business_line_id, tenant_id, organization_id),
    ADD CONSTRAINT fk_role_organization FOREIGN KEY (organization_id, tenant_id) REFERENCES org.organization(id, tenant_id),
    ADD CONSTRAINT fk_role_tenant_business FOREIGN KEY (tenant_id, business_line_id) REFERENCES org.tenant(id, business_line_id),
    ADD CONSTRAINT ck_role_scope_value CHECK (
        (scope_kind = 'PLATFORM' AND business_line_id IS NULL AND tenant_id IS NULL AND organization_id IS NULL)
        OR (scope_kind = 'BUSINESS_LINE' AND business_line_id IS NOT NULL AND tenant_id IS NULL AND organization_id IS NULL)
        OR (scope_kind = 'TENANT' AND business_line_id IS NOT NULL AND tenant_id IS NOT NULL AND organization_id IS NULL)
        OR (scope_kind = 'ORGANIZATION' AND business_line_id IS NOT NULL AND tenant_id IS NOT NULL AND organization_id IS NOT NULL)
    );

DROP INDEX ux_authorization_grant_active;
CREATE UNIQUE INDEX ux_authorization_grant_active
    ON oauth.authorization_grant(subject_kind, subject_id, client_id, tenant_id)
    WHERE grant_state IN ('PENDING', 'ACTIVE');

CREATE UNIQUE INDEX ux_role_assignment_effective
    ON authz.role_assignment(
        role_id,
        subject_kind,
        subject_id,
        COALESCE(business_line_id, '00000000-0000-0000-0000-000000000000'::uuid),
        COALESCE(tenant_id, '00000000-0000-0000-0000-000000000000'::uuid),
        COALESCE(organization_id, '00000000-0000-0000-0000-000000000000'::uuid)
    )
    WHERE assignment_state IN ('ACTIVE', 'SUSPENDED');

-- 以全零 UUID 表示平台范围，同时仍通过同一 Tenant 外键体系约束。
ALTER TABLE core.async_operation ADD CONSTRAINT fk_async_operation_tenant FOREIGN KEY (tenant_id) REFERENCES org.tenant(id);
ALTER TABLE core.idempotency_request ADD CONSTRAINT fk_idempotency_tenant FOREIGN KEY (tenant_id) REFERENCES org.tenant(id);
ALTER TABLE authn.device_authorization ADD CONSTRAINT fk_device_authorization_tenant FOREIGN KEY (tenant_id) REFERENCES org.tenant(id);
ALTER TABLE oauth.authorization_grant ADD CONSTRAINT fk_authorization_grant_tenant FOREIGN KEY (tenant_id) REFERENCES org.tenant(id);
ALTER TABLE oauth.user_session ADD CONSTRAINT fk_user_session_tenant FOREIGN KEY (tenant_id) REFERENCES org.tenant(id);
ALTER TABLE oauth.token_family ADD CONSTRAINT fk_token_family_tenant FOREIGN KEY (tenant_id) REFERENCES org.tenant(id);
ALTER TABLE oauth.reference_access_token ADD CONSTRAINT fk_reference_token_tenant FOREIGN KEY (tenant_id) REFERENCES org.tenant(id);
ALTER TABLE oauth.revocation_record ADD CONSTRAINT fk_revocation_tenant FOREIGN KEY (tenant_id) REFERENCES org.tenant(id);
ALTER TABLE authz.authorization_decision ADD CONSTRAINT fk_authz_decision_tenant FOREIGN KEY (tenant_id) REFERENCES org.tenant(id);
ALTER TABLE authz.relationship_tuple ADD CONSTRAINT fk_relationship_tenant FOREIGN KEY (tenant_id) REFERENCES org.tenant(id);
ALTER TABLE privacy.agreement_acceptance ADD CONSTRAINT fk_agreement_acceptance_tenant FOREIGN KEY (tenant_id) REFERENCES org.tenant(id);
ALTER TABLE privacy.consent_aggregate ADD CONSTRAINT fk_consent_aggregate_tenant FOREIGN KEY (tenant_id) REFERENCES org.tenant(id);
ALTER TABLE control.approval_case ADD CONSTRAINT fk_approval_case_tenant FOREIGN KEY (tenant_id) REFERENCES org.tenant(id);
ALTER TABLE control.break_glass_grant ADD CONSTRAINT fk_break_glass_tenant FOREIGN KEY (tenant_id) REFERENCES org.tenant(id);
ALTER TABLE risk.risk_signal ADD CONSTRAINT fk_risk_signal_tenant FOREIGN KEY (tenant_id) REFERENCES org.tenant(id);
ALTER TABLE risk.risk_assessment ADD CONSTRAINT fk_risk_assessment_tenant FOREIGN KEY (tenant_id) REFERENCES org.tenant(id);
ALTER TABLE workload.machine_principal ADD CONSTRAINT fk_machine_principal_tenant FOREIGN KEY (tenant_id) REFERENCES org.tenant(id);
ALTER TABLE workload.token_exchange ADD CONSTRAINT fk_token_exchange_tenant FOREIGN KEY (tenant_id) REFERENCES org.tenant(id);
ALTER TABLE integration.outbox_event ADD CONSTRAINT fk_outbox_event_tenant FOREIGN KEY (tenant_id) REFERENCES org.tenant(id);
ALTER TABLE integration.consumer_watermark ADD CONSTRAINT fk_consumer_watermark_tenant FOREIGN KEY (tenant_id) REFERENCES org.tenant(id);
ALTER TABLE audit.audit_event ADD CONSTRAINT fk_audit_event_tenant FOREIGN KEY (tenant_id) REFERENCES org.tenant(id);
ALTER TABLE audit.data_access_event ADD CONSTRAINT fk_data_access_tenant FOREIGN KEY (tenant_id) REFERENCES org.tenant(id);
ALTER TABLE messaging.message_send ADD CONSTRAINT fk_message_send_tenant FOREIGN KEY (tenant_id) REFERENCES org.tenant(id);

-- -----------------------------------------------------------------------------
-- 3. 通用不可变守卫和受控 Release 状态机
-- -----------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION core.fn_immutable_except()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    v_old jsonb := to_jsonb(OLD);
    v_new jsonb := to_jsonb(NEW);
    i integer;
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION '% 是不可变对象，禁止 DELETE', TG_TABLE_SCHEMA || '.' || TG_TABLE_NAME USING ERRCODE = '55000';
    END IF;
    IF TG_NARGS > 0 THEN
        FOR i IN 0..TG_NARGS - 1 LOOP
            v_old := v_old - TG_ARGV[i];
            v_new := v_new - TG_ARGV[i];
        END LOOP;
    END IF;
    IF v_old IS DISTINCT FROM v_new THEN
        RAISE EXCEPTION '% 的版本内容不可原地修改', TG_TABLE_SCHEMA || '.' || TG_TABLE_NAME USING ERRCODE = '55000';
    END IF;
    RETURN NEW;
END;
$$;
COMMENT ON FUNCTION core.fn_immutable_except() IS '除触发器参数列外，阻止版本化目录、发布内容和安全证据被原地修改或删除。';

CREATE OR REPLACE FUNCTION core.fn_immutable_after_draft()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    v_old jsonb := to_jsonb(OLD);
    v_new jsonb := to_jsonb(NEW);
    v_old_state text;
    i integer;
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION '% 禁止 DELETE', TG_TABLE_SCHEMA || '.' || TG_TABLE_NAME USING ERRCODE = '55000';
    END IF;
    v_old_state := v_old ->> TG_ARGV[0];
    IF v_old_state = 'DRAFT' THEN RETURN NEW; END IF;
    IF TG_NARGS > 0 THEN
        FOR i IN 0..TG_NARGS - 1 LOOP
            v_old := v_old - TG_ARGV[i];
            v_new := v_new - TG_ARGV[i];
        END LOOP;
    END IF;
    IF v_old IS DISTINCT FROM v_new THEN
        RAISE EXCEPTION 'CONFIGURATION_CONTENT_IMMUTABLE: % 离开 DRAFT 后配置内容不可修改', TG_TABLE_SCHEMA || '.' || TG_TABLE_NAME USING ERRCODE = '55000';
    END IF;
    RETURN NEW;
END;
$$;
COMMENT ON FUNCTION core.fn_immutable_after_draft() IS '配置资源离开 DRAFT 后，只允许修改触发器参数列；其余配置内容及摘要不可原地改写。';

CREATE OR REPLACE FUNCTION core.fn_initial_state_guard()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF (to_jsonb(NEW) ->> TG_ARGV[0]) <> TG_ARGV[1] THEN
        RAISE EXCEPTION 'INVALID_INITIAL_STATE: %.% 必须从 % 创建', TG_TABLE_SCHEMA || '.' || TG_TABLE_NAME, TG_ARGV[0], TG_ARGV[1] USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;
COMMENT ON FUNCTION core.fn_initial_state_guard() IS '要求配置、发布和密钥资源从明确的初始状态创建，禁止直接插入生效态绕过校验与审批。';

CREATE OR REPLACE FUNCTION control.fn_active_approval_binding_guard()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    v_old jsonb := to_jsonb(OLD);
    v_new jsonb := to_jsonb(NEW);
BEGIN
    IF (v_old ->> TG_ARGV[0]) = TG_ARGV[1]
       AND ((v_old -> TG_ARGV[2]) IS DISTINCT FROM (v_new -> TG_ARGV[2])
            OR (v_old -> TG_ARGV[3]) IS DISTINCT FROM (v_new -> TG_ARGV[3])) THEN
        RAISE EXCEPTION 'ACTIVE_APPROVAL_BINDING_IMMUTABLE' USING ERRCODE = '55000';
    END IF;
    RETURN NEW;
END;
$$;
COMMENT ON FUNCTION control.fn_active_approval_binding_guard() IS '资源处于 ACTIVE 时不得替换 approval_case_id 或 approval_execution_id；暂停后可准备新的再激活审批。';

CREATE OR REPLACE FUNCTION oauth.fn_client_state_guard()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE v_allowed boolean := false;
BEGIN
    IF NEW.client_state = OLD.client_state THEN v_allowed := true;
    ELSIF OLD.client_state = 'DRAFT' AND NEW.client_state = 'VALIDATED' THEN v_allowed := true;
    ELSIF OLD.client_state = 'VALIDATED' AND NEW.client_state = 'APPROVED' THEN v_allowed := true;
    ELSIF OLD.client_state = 'APPROVED' AND NEW.client_state = 'ACTIVE' THEN v_allowed := true;
    ELSIF OLD.client_state = 'ACTIVE' AND NEW.client_state IN ('SUSPENDED', 'COMPROMISED', 'RETIRED') THEN v_allowed := true;
    ELSIF OLD.client_state = 'SUSPENDED' AND NEW.client_state IN ('ACTIVE', 'COMPROMISED', 'RETIRED') THEN v_allowed := true;
    ELSIF OLD.client_state = 'COMPROMISED' AND NEW.client_state = 'RETIRED' THEN v_allowed := true;
    END IF;
    IF NOT v_allowed THEN
        RAISE EXCEPTION 'INVALID_STATE_TRANSITION: Client % -> %', OLD.client_state, NEW.client_state USING ERRCODE = '23514';
    END IF;
    IF NEW.approved_at IS DISTINCT FROM OLD.approved_at AND NOT (NEW.client_state = 'ACTIVE' AND OLD.client_state <> 'ACTIVE') THEN
        RAISE EXCEPTION 'CLIENT_STATE_EVIDENCE_IMMUTABLE: approved_at' USING ERRCODE = '55000';
    END IF;
    IF NEW.suspended_at IS DISTINCT FROM OLD.suspended_at AND NOT (NEW.client_state = 'SUSPENDED' AND OLD.client_state <> 'SUSPENDED') THEN
        RAISE EXCEPTION 'CLIENT_STATE_EVIDENCE_IMMUTABLE: suspended_at' USING ERRCODE = '55000';
    END IF;
    IF NEW.compromised_at IS DISTINCT FROM OLD.compromised_at AND NOT (NEW.client_state = 'COMPROMISED' AND OLD.client_state <> 'COMPROMISED') THEN
        RAISE EXCEPTION 'CLIENT_STATE_EVIDENCE_IMMUTABLE: compromised_at' USING ERRCODE = '55000';
    END IF;
    IF NEW.retired_at IS DISTINCT FROM OLD.retired_at AND NOT (NEW.client_state = 'RETIRED' AND OLD.client_state <> 'RETIRED') THEN
        RAISE EXCEPTION 'CLIENT_STATE_EVIDENCE_IMMUTABLE: retired_at' USING ERRCODE = '55000';
    END IF;
    IF OLD.client_state = 'SUSPENDED' AND NEW.client_state = 'ACTIVE'
       AND NULLIF(btrim(NEW.reactivation_review_ref), '') IS NULL THEN
        RAISE EXCEPTION 'CLIENT_REACTIVATION_REVIEW_REQUIRED' USING ERRCODE = '23514';
    END IF;
    IF NEW.client_state = 'ACTIVE' AND OLD.client_state <> 'ACTIVE' THEN NEW.approved_at := clock_timestamp(); END IF;
    IF NEW.client_state = 'SUSPENDED' AND OLD.client_state <> 'SUSPENDED' THEN
        NEW.suspended_at := clock_timestamp();
        NEW.reactivation_review_ref := NULL;
    END IF;
    IF NEW.client_state = 'COMPROMISED' AND OLD.client_state <> 'COMPROMISED' THEN NEW.compromised_at := clock_timestamp(); END IF;
    IF NEW.client_state = 'RETIRED' AND OLD.client_state <> 'RETIRED' THEN NEW.retired_at := clock_timestamp(); END IF;
    RETURN NEW;
END;
$$;
COMMENT ON FUNCTION oauth.fn_client_state_guard() IS 'Client 使用显式单向生命周期；暂停后再激活必须重新经过绑定审批，COMPROMISED 只能退役。';

CREATE OR REPLACE FUNCTION federation.fn_identity_provider_state_guard()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE v_allowed boolean := false;
BEGIN
    IF NEW.provider_state = OLD.provider_state THEN v_allowed := true;
    ELSIF OLD.provider_state = 'DRAFT' AND NEW.provider_state = 'VALIDATED' THEN v_allowed := true;
    ELSIF OLD.provider_state = 'VALIDATED' AND NEW.provider_state = 'APPROVED' THEN v_allowed := true;
    ELSIF OLD.provider_state = 'APPROVED' AND NEW.provider_state = 'ACTIVE' THEN v_allowed := true;
    ELSIF OLD.provider_state = 'ACTIVE' AND NEW.provider_state IN ('SUSPENDED', 'COMPROMISED', 'RETIRED') THEN v_allowed := true;
    ELSIF OLD.provider_state = 'SUSPENDED' AND NEW.provider_state IN ('ACTIVE', 'COMPROMISED', 'RETIRED') THEN v_allowed := true;
    ELSIF OLD.provider_state = 'COMPROMISED' AND NEW.provider_state = 'RETIRED' THEN v_allowed := true;
    END IF;
    IF NOT v_allowed THEN
        RAISE EXCEPTION 'INVALID_STATE_TRANSITION: Identity Provider % -> %', OLD.provider_state, NEW.provider_state USING ERRCODE = '23514';
    END IF;
    IF NEW.activated_at IS DISTINCT FROM OLD.activated_at AND NOT (NEW.provider_state = 'ACTIVE' AND OLD.provider_state <> 'ACTIVE') THEN
        RAISE EXCEPTION 'IDENTITY_PROVIDER_STATE_EVIDENCE_IMMUTABLE' USING ERRCODE = '55000';
    END IF;
    IF NEW.provider_state = 'ACTIVE' AND OLD.provider_state <> 'ACTIVE' THEN NEW.activated_at := clock_timestamp(); END IF;
    RETURN NEW;
END;
$$;
COMMENT ON FUNCTION federation.fn_identity_provider_state_guard() IS 'Identity Provider 使用显式单向生命周期；暂停后再激活必须重新绑定审批，COMPROMISED 只能退役。';

CREATE OR REPLACE FUNCTION crypto.fn_key_asset_state_guard()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE v_allowed boolean := false;
BEGIN
    IF NEW.key_state = OLD.key_state THEN v_allowed := true;
    ELSIF OLD.key_state = 'GENERATED' AND NEW.key_state IN ('PUBLISHED', 'ACTIVE', 'REVOKED', 'DESTROYED') THEN v_allowed := true;
    ELSIF OLD.key_state = 'PUBLISHED' AND NEW.key_state IN ('SIGNING_AND_VERIFYING', 'COMPROMISED', 'REVOKED') THEN v_allowed := true;
    ELSIF OLD.key_state = 'SIGNING_AND_VERIFYING' AND NEW.key_state IN ('VERIFY_ONLY', 'COMPROMISED', 'REVOKED') THEN v_allowed := true;
    ELSIF OLD.key_state = 'ACTIVE' AND NEW.key_state IN ('RETIRED', 'COMPROMISED', 'REVOKED') THEN v_allowed := true;
    ELSIF OLD.key_state = 'VERIFY_ONLY' AND NEW.key_state IN ('RETIRED', 'COMPROMISED', 'REVOKED') THEN v_allowed := true;
    ELSIF OLD.key_state = 'COMPROMISED' AND NEW.key_state IN ('REVOKED', 'DESTROYED') THEN v_allowed := true;
    ELSIF OLD.key_state IN ('REVOKED', 'RETIRED') AND NEW.key_state = 'DESTROYED' THEN v_allowed := true;
    END IF;
    IF NOT v_allowed THEN
        RAISE EXCEPTION 'INVALID_STATE_TRANSITION: Key Asset % -> %', OLD.key_state, NEW.key_state USING ERRCODE = '23514';
    END IF;
    IF NEW.published_at IS DISTINCT FROM OLD.published_at AND NOT (NEW.key_state = 'PUBLISHED' AND OLD.key_state <> 'PUBLISHED') THEN
        RAISE EXCEPTION 'KEY_STATE_EVIDENCE_IMMUTABLE: published_at' USING ERRCODE = '55000';
    END IF;
    IF NEW.signing_started_at IS DISTINCT FROM OLD.signing_started_at AND NOT (NEW.key_state = 'SIGNING_AND_VERIFYING' AND OLD.key_state <> 'SIGNING_AND_VERIFYING') THEN
        RAISE EXCEPTION 'KEY_STATE_EVIDENCE_IMMUTABLE: signing_started_at' USING ERRCODE = '55000';
    END IF;
    IF NEW.activated_at IS DISTINCT FROM OLD.activated_at AND NOT (NEW.key_state = 'ACTIVE' AND OLD.key_state <> 'ACTIVE') THEN
        RAISE EXCEPTION 'KEY_STATE_EVIDENCE_IMMUTABLE: activated_at' USING ERRCODE = '55000';
    END IF;
    IF NEW.verify_only_at IS DISTINCT FROM OLD.verify_only_at AND NOT (NEW.key_state = 'VERIFY_ONLY' AND OLD.key_state <> 'VERIFY_ONLY') THEN
        RAISE EXCEPTION 'KEY_STATE_EVIDENCE_IMMUTABLE: verify_only_at' USING ERRCODE = '55000';
    END IF;
    IF NEW.compromised_at IS DISTINCT FROM OLD.compromised_at AND NOT (NEW.key_state = 'COMPROMISED' AND OLD.key_state <> 'COMPROMISED') THEN
        RAISE EXCEPTION 'KEY_STATE_EVIDENCE_IMMUTABLE: compromised_at' USING ERRCODE = '55000';
    END IF;
    IF NEW.revoked_at IS DISTINCT FROM OLD.revoked_at AND NOT (NEW.key_state = 'REVOKED' AND OLD.key_state <> 'REVOKED') THEN
        RAISE EXCEPTION 'KEY_STATE_EVIDENCE_IMMUTABLE: revoked_at' USING ERRCODE = '55000';
    END IF;
    IF NEW.retired_at IS DISTINCT FROM OLD.retired_at AND NOT (NEW.key_state = 'RETIRED' AND OLD.key_state <> 'RETIRED') THEN
        RAISE EXCEPTION 'KEY_STATE_EVIDENCE_IMMUTABLE: retired_at' USING ERRCODE = '55000';
    END IF;
    IF NEW.destroyed_at IS DISTINCT FROM OLD.destroyed_at AND NOT (NEW.key_state = 'DESTROYED' AND OLD.key_state <> 'DESTROYED') THEN
        RAISE EXCEPTION 'KEY_STATE_EVIDENCE_IMMUTABLE: destroyed_at' USING ERRCODE = '55000';
    END IF;
    IF NEW.key_state = 'PUBLISHED' AND OLD.key_state <> 'PUBLISHED' THEN NEW.published_at := clock_timestamp(); END IF;
    IF NEW.key_state = 'SIGNING_AND_VERIFYING' AND OLD.key_state <> 'SIGNING_AND_VERIFYING' THEN NEW.signing_started_at := clock_timestamp(); END IF;
    IF NEW.key_state = 'ACTIVE' AND OLD.key_state <> 'ACTIVE' THEN NEW.activated_at := clock_timestamp(); END IF;
    IF NEW.key_state = 'VERIFY_ONLY' AND OLD.key_state <> 'VERIFY_ONLY' THEN NEW.verify_only_at := clock_timestamp(); END IF;
    IF NEW.key_state = 'COMPROMISED' AND OLD.key_state <> 'COMPROMISED' THEN NEW.compromised_at := clock_timestamp(); END IF;
    IF NEW.key_state = 'REVOKED' AND OLD.key_state <> 'REVOKED' THEN NEW.revoked_at := clock_timestamp(); END IF;
    IF NEW.key_state = 'RETIRED' AND OLD.key_state <> 'RETIRED' THEN NEW.retired_at := clock_timestamp(); END IF;
    IF NEW.key_state = 'DESTROYED' AND OLD.key_state <> 'DESTROYED' THEN NEW.destroyed_at := clock_timestamp(); END IF;
    RETURN NEW;
END;
$$;
COMMENT ON FUNCTION crypto.fn_key_asset_state_guard() IS '签名类与加密类 Key Asset 使用用途匹配的单向状态机，并由数据库记录发布、激活、失陷、撤销、退役和销毁时间。';

CREATE OR REPLACE FUNCTION crypto.fn_key_approval_binding_guard()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF OLD.key_state NOT IN ('GENERATED', 'PUBLISHED')
       AND (NEW.approval_case_id IS DISTINCT FROM OLD.approval_case_id
            OR NEW.approval_execution_id IS DISTINCT FROM OLD.approval_execution_id) THEN
        RAISE EXCEPTION 'KEY_APPROVAL_BINDING_IMMUTABLE' USING ERRCODE = '55000';
    END IF;
    RETURN NEW;
END;
$$;
COMMENT ON FUNCTION crypto.fn_key_approval_binding_guard() IS 'Key Asset 仅可在生成或发布阶段准备激活审批；开始签名、加密、验证或进入终态后审批绑定不可替换。';

CREATE OR REPLACE FUNCTION control.fn_release_guard()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    v_state_column text := TG_ARGV[0];
    v_old_state text;
    v_new_state text;
    v_old jsonb := to_jsonb(OLD);
    v_new jsonb := to_jsonb(NEW);
    v_transition_column text;
    v_column text;
    i integer;
    v_allowed boolean := false;
BEGIN
    EXECUTE format('SELECT ($1).%I, ($2).%I', v_state_column, v_state_column)
       INTO v_old_state, v_new_state USING OLD, NEW;

    IF v_new_state = v_old_state THEN
        v_allowed := true;
    ELSIF v_old_state = 'DRAFT' AND v_new_state IN ('VALIDATED', 'PUBLISHED', 'REVOKED') THEN
        v_allowed := true;
    ELSIF v_old_state = 'VALIDATED' AND v_new_state IN ('APPROVED', 'REVOKED') THEN
        v_allowed := true;
    ELSIF v_old_state = 'APPROVED' AND v_new_state IN ('STAGED', 'REVOKED') THEN
        v_allowed := true;
    ELSIF v_old_state = 'STAGED' AND v_new_state IN ('ACTIVE', 'REVOKED') THEN
        v_allowed := true;
    ELSIF v_old_state = 'PUBLISHED' AND v_new_state IN ('ACTIVE', 'REVOKED') THEN
        v_allowed := true;
    ELSIF v_old_state = 'ACTIVE' AND v_new_state IN ('DEPRECATED', 'SUPERSEDED', 'REVOKED') THEN
        v_allowed := true;
    END IF;

    IF NOT v_allowed THEN
        RAISE EXCEPTION 'INVALID_STATE_TRANSITION: %.% % -> %', TG_TABLE_NAME, v_state_column, v_old_state, v_new_state USING ERRCODE = '23514';
    END IF;

    IF v_new_state IS DISTINCT FROM v_old_state THEN
        v_transition_column := CASE v_new_state
            WHEN 'STAGED' THEN 'staged_at'
            WHEN 'ACTIVE' THEN 'activated_at'
            WHEN 'PUBLISHED' THEN 'published_at'
            WHEN 'DEPRECATED' THEN CASE WHEN v_new ? 'deprecated_at' THEN 'deprecated_at' ELSE 'retired_at' END
            WHEN 'REVOKED' THEN CASE WHEN v_new ? 'revoked_at' THEN 'revoked_at' ELSE NULL END
            ELSE NULL
        END;
        IF v_transition_column IS NOT NULL AND v_new ? v_transition_column THEN
            NEW := jsonb_populate_record(NEW, jsonb_build_object(v_transition_column, clock_timestamp()));
            v_new := to_jsonb(NEW);
        END IF;
    END IF;

    FOREACH v_column IN ARRAY ARRAY['staged_at','activated_at','published_at','deprecated_at','retired_at','revoked_at']
    LOOP
        IF v_new ? v_column
           AND (v_old -> v_column) IS DISTINCT FROM (v_new -> v_column)
           AND v_column IS DISTINCT FROM v_transition_column THEN
            RAISE EXCEPTION 'RELEASE_STATE_EVIDENCE_IMMUTABLE: %.%', TG_TABLE_SCHEMA || '.' || TG_TABLE_NAME, v_column USING ERRCODE = '55000';
        END IF;
    END LOOP;

    IF v_old_state <> 'DRAFT' THEN
        FOR i IN 0..TG_NARGS - 1 LOOP
            v_old := v_old - TG_ARGV[i];
            v_new := v_new - TG_ARGV[i];
        END LOOP;
        IF v_old IS DISTINCT FROM v_new THEN
            RAISE EXCEPTION 'RELEASE_CONTENT_IMMUTABLE: %', TG_TABLE_SCHEMA || '.' || TG_TABLE_NAME USING ERRCODE = '55000';
        END IF;
    END IF;
    IF v_old_state IN ('DEPRECATED', 'SUPERSEDED', 'REVOKED')
       AND to_jsonb(NEW) IS DISTINCT FROM to_jsonb(OLD) THEN
        RAISE EXCEPTION 'RELEASE_TERMINAL_EVIDENCE_IMMUTABLE: %', TG_TABLE_SCHEMA || '.' || TG_TABLE_NAME USING ERRCODE = '55000';
    END IF;
    RETURN NEW;
END;
$$;
COMMENT ON FUNCTION control.fn_release_guard() IS '控制不可变 Release 的单向状态转换；关键状态时间由数据库写入且不可改写，离开 DRAFT 后仅允许显式运维列变化。';

CREATE TRIGGER trg_config_release_guard BEFORE UPDATE ON control.config_release FOR EACH ROW
    EXECUTE FUNCTION control.fn_release_guard('release_state', 'staged_at', 'activated_at', 'deprecated_at', 'revoked_at',
        'approval_case_id', 'approval_execution_id');
CREATE TRIGGER trg_policy_release_guard BEFORE UPDATE ON authz.policy_release FOR EACH ROW
    EXECUTE FUNCTION control.fn_release_guard('policy_state', 'activated_at', 'retired_at', 'revoked_at',
        'approval_case_id', 'approval_execution_id');
CREATE TRIGGER trg_risk_policy_release_guard BEFORE UPDATE ON risk.risk_policy_release FOR EACH ROW
    EXECUTE FUNCTION control.fn_release_guard('policy_state', 'rollout_percentage', 'emergency_disabled',
        'activated_at', 'retired_at', 'revoked_at', 'approval_case_id', 'approval_execution_id');
CREATE TRIGGER trg_jwks_release_guard BEFORE UPDATE ON crypto.jwks_release FOR EACH ROW
    EXECUTE FUNCTION control.fn_release_guard('release_state', 'published_at');

CREATE TRIGGER trg_config_release_binding_immutable BEFORE UPDATE ON control.config_release FOR EACH ROW
    EXECUTE FUNCTION control.fn_active_approval_binding_guard('release_state', 'ACTIVE', 'approval_case_id', 'approval_execution_id');
CREATE TRIGGER trg_policy_release_binding_immutable BEFORE UPDATE ON authz.policy_release FOR EACH ROW
    EXECUTE FUNCTION control.fn_active_approval_binding_guard('policy_state', 'ACTIVE', 'approval_case_id', 'approval_execution_id');
CREATE TRIGGER trg_risk_policy_release_binding_immutable BEFORE UPDATE ON risk.risk_policy_release FOR EACH ROW
    EXECUTE FUNCTION control.fn_active_approval_binding_guard('policy_state', 'ACTIVE', 'approval_case_id', 'approval_execution_id');

CREATE TRIGGER trg_security_profile_immutable BEFORE UPDATE OR DELETE ON core.security_profile FOR EACH ROW
    EXECUTE FUNCTION core.fn_immutable_except('is_active', 'retired_at');
CREATE TRIGGER trg_duration_policy_immutable BEFORE UPDATE OR DELETE ON core.duration_policy FOR EACH ROW
    EXECUTE FUNCTION core.fn_immutable_except('retired_at');
CREATE TRIGGER trg_data_classification_immutable BEFORE UPDATE OR DELETE ON core.data_classification FOR EACH ROW
    EXECUTE FUNCTION core.fn_immutable_except();
CREATE TRIGGER trg_purpose_immutable BEFORE UPDATE OR DELETE ON privacy.purpose FOR EACH ROW
    EXECUTE FUNCTION core.fn_immutable_except('retired_at');
CREATE TRIGGER trg_agreement_immutable BEFORE UPDATE OR DELETE ON privacy.agreement FOR EACH ROW
    EXECUTE FUNCTION core.fn_immutable_except('retired_at');
CREATE TRIGGER trg_event_schema_immutable BEFORE UPDATE OR DELETE ON integration.event_schema FOR EACH ROW
    EXECUTE FUNCTION core.fn_immutable_except('is_active');
CREATE TRIGGER trg_route_policy_immutable BEFORE UPDATE OR DELETE ON messaging.route_policy FOR EACH ROW
    EXECUTE FUNCTION core.fn_immutable_except('is_active');
CREATE TRIGGER trg_message_template_immutable BEFORE UPDATE OR DELETE ON messaging.message_template FOR EACH ROW
    EXECUTE FUNCTION core.fn_immutable_except('is_active');
CREATE TRIGGER trg_content_rule_immutable BEFORE UPDATE OR DELETE ON messaging.content_compliance_rule FOR EACH ROW
    EXECUTE FUNCTION core.fn_immutable_except('is_active', 'retired_at');

CREATE TRIGGER trg_client_binding_immutable BEFORE UPDATE ON oauth.client FOR EACH ROW
    EXECUTE FUNCTION control.fn_active_approval_binding_guard('client_state', 'ACTIVE', 'approval_case_id', 'approval_execution_id');
CREATE TRIGGER trg_client_configuration_immutable BEFORE UPDATE OR DELETE ON oauth.client FOR EACH ROW
    EXECUTE FUNCTION core.fn_immutable_after_draft('client_state', 'approval_case_id', 'approval_execution_id',
        'approved_at', 'suspended_at', 'compromised_at', 'retired_at', 'last_used_at',
        'client_security_epoch', 'reactivation_review_ref', 'last_activation_execution_id', 'updated_at', 'row_version');
CREATE TRIGGER trg_client_initial_state BEFORE INSERT ON oauth.client FOR EACH ROW
    EXECUTE FUNCTION core.fn_initial_state_guard('client_state', 'DRAFT');
CREATE TRIGGER trg_identity_provider_binding_immutable BEFORE UPDATE ON federation.identity_provider FOR EACH ROW
    EXECUTE FUNCTION control.fn_active_approval_binding_guard('provider_state', 'ACTIVE', 'approval_case_id', 'approval_execution_id');
CREATE TRIGGER trg_identity_provider_configuration_immutable BEFORE UPDATE OR DELETE ON federation.identity_provider FOR EACH ROW
    EXECUTE FUNCTION core.fn_immutable_after_draft('provider_state', 'approval_case_id', 'approval_execution_id',
        'activated_at', 'last_activation_execution_id', 'updated_at', 'row_version');
CREATE TRIGGER trg_identity_provider_initial_state BEFORE INSERT ON federation.identity_provider FOR EACH ROW
    EXECUTE FUNCTION core.fn_initial_state_guard('provider_state', 'DRAFT');
CREATE TRIGGER trg_identity_provider_state BEFORE UPDATE ON federation.identity_provider FOR EACH ROW
    EXECUTE FUNCTION federation.fn_identity_provider_state_guard();

DROP TRIGGER trg_key_asset_terminal ON crypto.key_asset;
CREATE TRIGGER trg_key_asset_approval_binding BEFORE UPDATE ON crypto.key_asset FOR EACH ROW
    EXECUTE FUNCTION crypto.fn_key_approval_binding_guard();
CREATE TRIGGER trg_key_asset_identity_immutable BEFORE UPDATE OR DELETE ON crypto.key_asset FOR EACH ROW
    EXECUTE FUNCTION core.fn_immutable_except('key_state', 'published_at', 'signing_started_at', 'activated_at',
        'verify_only_at', 'compromised_at', 'revoked_at', 'retired_at', 'destroyed_at',
        'approval_case_id', 'approval_execution_id', 'updated_at', 'row_version');
CREATE TRIGGER trg_key_asset_initial_state BEFORE INSERT ON crypto.key_asset FOR EACH ROW
    EXECUTE FUNCTION core.fn_initial_state_guard('key_state', 'GENERATED');
CREATE TRIGGER trg_key_asset_state BEFORE UPDATE ON crypto.key_asset FOR EACH ROW
    EXECUTE FUNCTION crypto.fn_key_asset_state_guard();

DROP INDEX ix_key_asset_rotation;
CREATE INDEX ix_key_asset_rotation ON crypto.key_asset(not_after)
    WHERE key_state IN ('PUBLISHED', 'SIGNING_AND_VERIFYING', 'ACTIVE', 'VERIFY_ONLY');

CREATE TRIGGER trg_config_release_initial_state BEFORE INSERT ON control.config_release FOR EACH ROW
    EXECUTE FUNCTION core.fn_initial_state_guard('release_state', 'DRAFT');
CREATE TRIGGER trg_policy_release_initial_state BEFORE INSERT ON authz.policy_release FOR EACH ROW
    EXECUTE FUNCTION core.fn_initial_state_guard('policy_state', 'DRAFT');
CREATE TRIGGER trg_risk_policy_release_initial_state BEFORE INSERT ON risk.risk_policy_release FOR EACH ROW
    EXECUTE FUNCTION core.fn_initial_state_guard('policy_state', 'DRAFT');
CREATE TRIGGER trg_jwks_release_initial_state BEFORE INSERT ON crypto.jwks_release FOR EACH ROW
    EXECUTE FUNCTION core.fn_initial_state_guard('release_state', 'DRAFT');

-- -----------------------------------------------------------------------------
-- 4. 审批单状态机与被审批资源的单次执行绑定
-- -----------------------------------------------------------------------------

ALTER TABLE control.approval_case
    DROP CONSTRAINT ck_approval_case_approved,
    DROP CONSTRAINT ck_approval_case_executed;
ALTER TABLE control.approval_case
    ADD COLUMN submitted_at timestamptz NULL,
    ADD COLUMN rejected_at timestamptz NULL,
    ADD CONSTRAINT ck_approval_case_submitted CHECK (
        (approval_state IN ('PENDING_REVIEW', 'APPROVED', 'EXECUTED', 'REJECTED', 'EXPIRED')) = (submitted_at IS NOT NULL)
        OR (approval_state = 'CANCELLED')
    ),
    ADD CONSTRAINT ck_approval_case_approved CHECK (
        (approved_at IS NULL OR approval_state IN ('APPROVED', 'EXECUTED', 'CANCELLED', 'EXPIRED'))
        AND (approval_state NOT IN ('APPROVED', 'EXECUTED') OR approved_at IS NOT NULL)
    ),
    ADD CONSTRAINT ck_approval_case_executed CHECK (
        (approval_state = 'EXECUTED' AND executed_at IS NOT NULL AND execution_id IS NOT NULL)
        OR (approval_state <> 'EXECUTED' AND executed_at IS NULL AND execution_id IS NULL)
    ),
    ADD CONSTRAINT ck_approval_case_rejected CHECK ((approval_state = 'REJECTED') = (rejected_at IS NOT NULL));

CREATE OR REPLACE FUNCTION control.fn_approval_decision_guard()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    v_case control.approval_case%ROWTYPE;
BEGIN
    SELECT * INTO v_case
      FROM control.approval_case
     WHERE id = NEW.approval_case_id
     FOR UPDATE;
    IF NOT FOUND THEN RAISE EXCEPTION 'APPROVAL_CASE_NOT_FOUND' USING ERRCODE = '23503'; END IF;
    IF v_case.approval_state <> 'PENDING_REVIEW' OR v_case.valid_until <= clock_timestamp() THEN
        RAISE EXCEPTION 'APPROVAL_NOT_REVIEWABLE' USING ERRCODE = '23514';
    END IF;
    IF NEW.approver_ref = v_case.requested_by_ref THEN
        RAISE EXCEPTION 'APPROVAL_FORBIDDEN: 发起人不得审批自己的请求' USING ERRCODE = '23514';
    END IF;
    IF NEW.risk_snapshot_hash <> v_case.risk_snapshot_hash THEN
        RAISE EXCEPTION 'APPROVAL_RISK_SNAPSHOT_MISMATCH' USING ERRCODE = '23514';
    END IF;
    IF btrim(NEW.decision_reason) = '' THEN
        RAISE EXCEPTION 'APPROVAL_DECISION_REASON_REQUIRED' USING ERRCODE = '23514';
    END IF;
    NEW.decided_at := clock_timestamp();
    RETURN NEW;
END;
$$;
COMMENT ON FUNCTION control.fn_approval_decision_guard() IS '只允许在有效审核窗口内决定，阻止发起人自审，并要求决定绑定审批单同一风险快照和非空理由。';

CREATE OR REPLACE FUNCTION control.fn_approval_case_guard()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    v_approvals integer;
    v_rejections integer;
    v_transition_allowed boolean := false;
BEGIN
    IF OLD.approval_state <> 'DRAFT' AND (
        NEW.approval_type IS DISTINCT FROM OLD.approval_type
        OR NEW.requested_by_ref IS DISTINCT FROM OLD.requested_by_ref
        OR NEW.requested_by_kind IS DISTINCT FROM OLD.requested_by_kind
        OR NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
        OR NEW.resource_kind IS DISTINCT FROM OLD.resource_kind
        OR NEW.resource_ref IS DISTINCT FROM OLD.resource_ref
        OR NEW.immutable_request_hash IS DISTINCT FROM OLD.immutable_request_hash
        OR NEW.before_value_hash IS DISTINCT FROM OLD.before_value_hash
        OR NEW.after_value_hash IS DISTINCT FROM OLD.after_value_hash
        OR NEW.justification IS DISTINCT FROM OLD.justification
        OR NEW.required_approvals IS DISTINCT FROM OLD.required_approvals
        OR NEW.policy_version IS DISTINCT FROM OLD.policy_version
        OR NEW.resource_version IS DISTINCT FROM OLD.resource_version
        OR NEW.risk_snapshot_hash IS DISTINCT FROM OLD.risk_snapshot_hash
        OR NEW.valid_until IS DISTINCT FROM OLD.valid_until
    ) THEN
        RAISE EXCEPTION 'APPROVAL_REQUEST_IMMUTABLE: 审批进入审核后，请求范围、摘要、策略与有效期不得修改' USING ERRCODE = '55000';
    END IF;

    IF NEW.approval_state = OLD.approval_state THEN
        v_transition_allowed := true;
    ELSIF OLD.approval_state = 'DRAFT' AND NEW.approval_state IN ('PENDING_REVIEW', 'CANCELLED') THEN
        v_transition_allowed := true;
    ELSIF OLD.approval_state = 'PENDING_REVIEW' AND NEW.approval_state IN ('APPROVED', 'REJECTED', 'CANCELLED', 'EXPIRED') THEN
        v_transition_allowed := true;
    ELSIF OLD.approval_state = 'APPROVED' AND NEW.approval_state IN ('EXECUTED', 'CANCELLED', 'EXPIRED') THEN
        v_transition_allowed := true;
    END IF;

    IF NOT v_transition_allowed THEN
        RAISE EXCEPTION 'INVALID_STATE_TRANSITION: Approval Case % -> %', OLD.approval_state, NEW.approval_state USING ERRCODE = '23514';
    END IF;

    IF NEW.approval_state = 'PENDING_REVIEW' AND OLD.approval_state <> 'PENDING_REVIEW'
    THEN
        IF NEW.valid_until <= clock_timestamp() THEN
            RAISE EXCEPTION 'APPROVAL_EXPIRED: 已过有效期的请求不得提交审核' USING ERRCODE = '23514';
        END IF;
        NEW.submitted_at := clock_timestamp();
    END IF;

    IF NEW.approval_state IN ('APPROVED', 'REJECTED') AND OLD.approval_state = 'PENDING_REVIEW' THEN
        SELECT count(*) FILTER (WHERE decision = 'APPROVE'), count(*) FILTER (WHERE decision = 'REJECT')
          INTO v_approvals, v_rejections
          FROM control.approval_decision
         WHERE approval_case_id = NEW.id;

        IF NEW.approval_state = 'APPROVED' THEN
            IF v_rejections > 0 OR v_approvals < NEW.required_approvals THEN
                RAISE EXCEPTION 'APPROVAL_INCOMPLETE' USING ERRCODE = '23514';
            END IF;
            IF NEW.valid_until <= clock_timestamp() THEN
                RAISE EXCEPTION 'APPROVAL_EXPIRED' USING ERRCODE = '23514';
            END IF;
            NEW.approved_at := clock_timestamp();
        ELSIF v_rejections = 0 THEN
            RAISE EXCEPTION 'APPROVAL_REJECTION_MISSING' USING ERRCODE = '23514';
        ELSE
            NEW.rejected_at := clock_timestamp();
        END IF;
    END IF;

    IF NEW.approval_state = 'EXECUTED' AND OLD.approval_state <> 'EXECUTED' THEN
        IF OLD.approval_state <> 'APPROVED' OR NEW.valid_until <= clock_timestamp() THEN
            RAISE EXCEPTION 'APPROVAL_NOT_EXECUTABLE' USING ERRCODE = '23514';
        END IF;
        NEW.execution_id := gen_random_uuid();
        NEW.executed_at := clock_timestamp();
    END IF;

    IF NEW.approval_state = 'CANCELLED' AND OLD.approval_state <> 'CANCELLED' THEN
        NEW.submitted_at := OLD.submitted_at;
        NEW.approved_at := OLD.approved_at;
        NEW.rejected_at := OLD.rejected_at;
        NEW.cancelled_at := clock_timestamp();
    ELSIF NEW.approval_state = 'EXPIRED' AND OLD.approval_state <> 'EXPIRED' THEN
        NEW.submitted_at := OLD.submitted_at;
        NEW.approved_at := OLD.approved_at;
        NEW.rejected_at := OLD.rejected_at;
        NEW.expired_at := clock_timestamp();
    END IF;
    RETURN NEW;
END;
$$;
COMMENT ON FUNCTION control.fn_approval_case_guard() IS '审批请求进入审核后完整不可变；只允许单向状态转换，批准人数、拒绝决定、有效期和单次 execution_id 均在库内校验。';

CREATE OR REPLACE FUNCTION control.fn_approval_case_evidence_guard()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF OLD.submitted_at IS NOT NULL AND NEW.submitted_at IS DISTINCT FROM OLD.submitted_at THEN
        RAISE EXCEPTION 'APPROVAL_SUBMITTED_EVIDENCE_IMMUTABLE' USING ERRCODE = '55000';
    END IF;
    IF OLD.approved_at IS NOT NULL AND NEW.approved_at IS DISTINCT FROM OLD.approved_at THEN
        RAISE EXCEPTION 'APPROVAL_APPROVED_EVIDENCE_IMMUTABLE' USING ERRCODE = '55000';
    END IF;
    IF OLD.rejected_at IS NOT NULL AND NEW.rejected_at IS DISTINCT FROM OLD.rejected_at THEN
        RAISE EXCEPTION 'APPROVAL_REJECTED_EVIDENCE_IMMUTABLE' USING ERRCODE = '55000';
    END IF;
    IF OLD.executed_at IS NOT NULL
       AND (NEW.executed_at IS DISTINCT FROM OLD.executed_at OR NEW.execution_id IS DISTINCT FROM OLD.execution_id) THEN
        RAISE EXCEPTION 'APPROVAL_EXECUTION_EVIDENCE_IMMUTABLE' USING ERRCODE = '55000';
    END IF;
    IF OLD.cancelled_at IS NOT NULL AND NEW.cancelled_at IS DISTINCT FROM OLD.cancelled_at THEN
        RAISE EXCEPTION 'APPROVAL_CANCELLATION_EVIDENCE_IMMUTABLE' USING ERRCODE = '55000';
    END IF;
    IF OLD.expired_at IS NOT NULL AND NEW.expired_at IS DISTINCT FROM OLD.expired_at THEN
        RAISE EXCEPTION 'APPROVAL_EXPIRY_EVIDENCE_IMMUTABLE' USING ERRCODE = '55000';
    END IF;
    IF OLD.approval_state IN ('EXECUTED', 'REJECTED', 'CANCELLED', 'EXPIRED')
       AND to_jsonb(NEW) IS DISTINCT FROM to_jsonb(OLD) THEN
        RAISE EXCEPTION 'APPROVAL_TERMINAL_EVIDENCE_IMMUTABLE' USING ERRCODE = '55000';
    END IF;
    RETURN NEW;
END;
$$;
COMMENT ON FUNCTION control.fn_approval_case_evidence_guard() IS '审批提交、批准、拒绝、执行、取消、过期时间及数据库生成的 execution_id 一经写入不可改写；终态记录拒绝任何更新。';

CREATE TRIGGER trg_approval_case_initial_state BEFORE INSERT ON control.approval_case FOR EACH ROW
    EXECUTE FUNCTION core.fn_initial_state_guard('approval_state', 'DRAFT');
CREATE TRIGGER trg_zz_approval_case_evidence BEFORE UPDATE ON control.approval_case FOR EACH ROW
    EXECUTE FUNCTION control.fn_approval_case_evidence_guard();

CREATE OR REPLACE FUNCTION control.fn_bound_approval_activation_guard()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    v_old_state text;
    v_new_state text;
    v_resource_ref text;
    v_approval_case_id uuid;
    v_approval_execution_id uuid;
    v_last_activation_execution_id uuid;
    v_supplied_last_activation_execution_id uuid;
    v_content_hash bytea;
    v_tenant_id uuid;
BEGIN
    IF TG_OP = 'INSERT' THEN
        EXECUTE format(
            'SELECT NULL::text, ($1).%1$I::text, ($1).%2$I::text, ($1).%3$I::uuid, ($1).%4$I::bytea, ($1).%5$I::uuid',
            TG_ARGV[0], TG_ARGV[4], TG_ARGV[6], TG_ARGV[5], TG_ARGV[7]
        ) INTO v_old_state, v_new_state, v_resource_ref, v_approval_case_id, v_content_hash, v_approval_execution_id USING NEW;
    ELSE
        EXECUTE format(
            'SELECT ($1).%1$I::text, ($2).%1$I::text, ($2).%2$I::text, ($2).%3$I::uuid, ($2).%4$I::bytea, ($2).%5$I::uuid',
            TG_ARGV[0], TG_ARGV[4], TG_ARGV[6], TG_ARGV[5], TG_ARGV[7]
        ) INTO v_old_state, v_new_state, v_resource_ref, v_approval_case_id, v_content_hash, v_approval_execution_id USING OLD, NEW;
    END IF;

    v_tenant_id := COALESCE(
        NULLIF(to_jsonb(NEW) ->> 'tenant_id', '')::uuid,
        '00000000-0000-0000-0000-000000000000'::uuid
    );

    IF TG_NARGS > 8 THEN
        IF TG_OP = 'UPDATE' THEN
            v_last_activation_execution_id := NULLIF(to_jsonb(OLD) ->> TG_ARGV[8], '')::uuid;
            v_supplied_last_activation_execution_id := NULLIF(to_jsonb(NEW) ->> TG_ARGV[8], '')::uuid;
            IF v_supplied_last_activation_execution_id IS DISTINCT FROM v_last_activation_execution_id
               AND NOT (v_new_state = TG_ARGV[1] AND v_old_state IS DISTINCT FROM v_new_state) THEN
                RAISE EXCEPTION 'LAST_ACTIVATION_EXECUTION_ID_IMMUTABLE' USING ERRCODE = '55000';
            END IF;
        END IF;
    END IF;

    IF v_new_state = TG_ARGV[1] AND (TG_OP = 'INSERT' OR v_old_state IS DISTINCT FROM v_new_state) THEN
        IF v_approval_case_id IS NULL OR NOT EXISTS (
            SELECT 1
              FROM control.approval_case a
             WHERE a.id = v_approval_case_id
               AND a.approval_state = 'EXECUTED'
               AND a.approval_type = TG_ARGV[2]
               AND a.resource_kind = TG_ARGV[3]
                AND a.resource_ref = v_resource_ref
                AND a.after_value_hash = v_content_hash
                AND a.execution_id = v_approval_execution_id
                AND a.tenant_id = v_tenant_id
                AND a.valid_until > a.executed_at
                AND a.valid_until > clock_timestamp()
        ) THEN
            RAISE EXCEPTION 'BOUND_APPROVAL_REQUIRED: %.% 激活必须绑定范围、摘要和 execution_id 完全一致的已执行审批', TG_TABLE_SCHEMA, TG_TABLE_NAME USING ERRCODE = '23514';
        END IF;
        IF TG_NARGS > 8 THEN
            IF v_last_activation_execution_id = v_approval_execution_id THEN
                RAISE EXCEPTION 'APPROVAL_EXECUTION_ALREADY_APPLIED' USING ERRCODE = '23514';
            END IF;
            NEW := jsonb_populate_record(NEW, jsonb_build_object(TG_ARGV[8], v_approval_execution_id));
        END IF;
    END IF;
    RETURN NEW;
END;
$$;
COMMENT ON FUNCTION control.fn_bound_approval_activation_guard() IS '资源进入生效态时，要求 Tenant、审批类型、资源种类、资源引用、内容摘要和单次执行 ID 精确绑定；无 tenant_id 的全局资源使用平台租户。';

CREATE TRIGGER trg_config_release_approval BEFORE INSERT OR UPDATE ON control.config_release FOR EACH ROW
    EXECUTE FUNCTION control.fn_bound_approval_activation_guard('release_state', 'ACTIVE', 'CONFIG_RELEASE', 'CONFIG_RELEASE', 'public_id', 'content_hash', 'approval_case_id', 'approval_execution_id');
CREATE TRIGGER trg_policy_release_approval BEFORE INSERT OR UPDATE ON authz.policy_release FOR EACH ROW
    EXECUTE FUNCTION control.fn_bound_approval_activation_guard('policy_state', 'ACTIVE', 'CONFIG_RELEASE', 'AUTHZ_POLICY', 'public_id', 'content_hash', 'approval_case_id', 'approval_execution_id');
CREATE TRIGGER trg_risk_policy_release_approval BEFORE INSERT OR UPDATE ON risk.risk_policy_release FOR EACH ROW
    EXECUTE FUNCTION control.fn_bound_approval_activation_guard('policy_state', 'ACTIVE', 'CONFIG_RELEASE', 'RISK_POLICY', 'public_id', 'content_hash', 'approval_case_id', 'approval_execution_id');
CREATE TRIGGER trg_client_activation_approval BEFORE INSERT OR UPDATE ON oauth.client FOR EACH ROW
    EXECUTE FUNCTION control.fn_bound_approval_activation_guard('client_state', 'ACTIVE', 'CONFIG_RELEASE', 'CLIENT', 'public_id', 'configuration_hash', 'approval_case_id', 'approval_execution_id', 'last_activation_execution_id');
CREATE TRIGGER trg_identity_provider_activation_approval BEFORE INSERT OR UPDATE ON federation.identity_provider FOR EACH ROW
    EXECUTE FUNCTION control.fn_bound_approval_activation_guard('provider_state', 'ACTIVE', 'CONFIG_RELEASE', 'IDENTITY_PROVIDER', 'public_id', 'configuration_hash', 'approval_case_id', 'approval_execution_id', 'last_activation_execution_id');
CREATE TRIGGER trg_key_asset_signing_approval BEFORE INSERT OR UPDATE ON crypto.key_asset FOR EACH ROW
    WHEN (NEW.key_use IN ('TOKEN_SIGNING', 'WEBHOOK_SIGNING', 'AUDIT_SEAL'))
    EXECUTE FUNCTION control.fn_bound_approval_activation_guard('key_state', 'SIGNING_AND_VERIFYING', 'KEY_OPERATION', 'KEY_ASSET', 'public_id', 'asset_metadata_hash', 'approval_case_id', 'approval_execution_id');
CREATE TRIGGER trg_key_asset_active_approval BEFORE INSERT OR UPDATE ON crypto.key_asset FOR EACH ROW
    WHEN (NEW.key_use NOT IN ('TOKEN_SIGNING', 'WEBHOOK_SIGNING', 'AUDIT_SEAL'))
    EXECUTE FUNCTION control.fn_bound_approval_activation_guard('key_state', 'ACTIVE', 'KEY_OPERATION', 'KEY_ASSET', 'public_id', 'asset_metadata_hash', 'approval_case_id', 'approval_execution_id');

-- -----------------------------------------------------------------------------
-- 5. Consent、Grant、Session、Code 与 Token 的完整上下文绑定
-- -----------------------------------------------------------------------------

ALTER TABLE oauth.authorization_grant
    ADD COLUMN machine_epoch_at_grant bigint NULL,
    ADD CONSTRAINT ck_grant_subject_epoch CHECK (
        (subject_kind = 'USER' AND user_epoch_at_grant IS NOT NULL AND machine_epoch_at_grant IS NULL)
        OR (subject_kind = 'MACHINE' AND user_epoch_at_grant IS NULL AND machine_epoch_at_grant IS NOT NULL)
    ),
    ADD CONSTRAINT ck_grant_subject_context CHECK (
        (subject_kind = 'USER' AND login_transaction_id IS NOT NULL)
        OR (subject_kind = 'MACHINE' AND login_transaction_id IS NULL AND NOT consent_required)
    ),
    ADD CONSTRAINT ck_grant_state_evidence CHECK (
        (granted_at IS NULL OR grant_state IN ('ACTIVE', 'REVOKED', 'EXPIRED'))
        AND ((grant_state = 'DENIED') = (denied_at IS NOT NULL))
        AND (grant_state <> 'ACTIVE' OR (granted_at IS NOT NULL AND expires_at IS NOT NULL))
        AND (grant_state <> 'REVOKED' OR (revoked_at IS NOT NULL AND NULLIF(btrim(revoke_reason_code), '') IS NOT NULL AND NULLIF(btrim(revoked_by_ref), '') IS NOT NULL))
    );
ALTER TABLE oauth.reference_access_token
    ADD COLUMN machine_epoch_at_issue bigint NULL,
    ADD CONSTRAINT ck_reference_token_subject_epoch CHECK (
        (subject_kind = 'USER' AND user_epoch_at_issue IS NOT NULL AND machine_epoch_at_issue IS NULL)
        OR (subject_kind = 'MACHINE' AND user_epoch_at_issue IS NULL AND machine_epoch_at_issue IS NOT NULL)
    );

ALTER TABLE oauth.user_session
    DROP CONSTRAINT ck_user_session_revoked,
    DROP CONSTRAINT ck_user_session_compromised;
ALTER TABLE oauth.user_session
    ADD COLUMN expired_at timestamptz NULL,
    ADD COLUMN compromise_reason_code text NULL,
    ADD CONSTRAINT ck_user_session_expired CHECK ((session_state = 'EXPIRED') = (expired_at IS NOT NULL)),
    ADD CONSTRAINT ck_user_session_compromised CHECK (
        (compromised_at IS NULL) = (compromise_reason_code IS NULL)
        AND (session_state = 'COMPROMISED') = (compromised_at IS NOT NULL)
    ),
    ADD CONSTRAINT ck_user_session_revoked CHECK (
        (revoked_at IS NULL) = (revoke_reason_code IS NULL)
        AND (session_state = 'REVOKED') = (revoked_at IS NOT NULL)
    );

ALTER TABLE oauth.refresh_token DROP CONSTRAINT fk_refresh_token_successor;
ALTER TABLE oauth.refresh_token DROP CONSTRAINT ck_refresh_token_used;
ALTER TABLE oauth.refresh_token
    ADD CONSTRAINT fk_refresh_token_successor FOREIGN KEY (successor_id) REFERENCES oauth.refresh_token(id)
        DEFERRABLE INITIALLY DEFERRED,
    ADD CONSTRAINT ck_refresh_token_used CHECK (
        (refresh_token_instance_state = 'USED' AND used_at IS NOT NULL AND successor_id IS NOT NULL AND retry_window_until IS NOT NULL)
        OR (refresh_token_instance_state <> 'USED' AND used_at IS NULL AND successor_id IS NULL AND retry_window_until IS NULL)
    ),
    ADD CONSTRAINT ck_refresh_token_revoked CHECK (
        (refresh_token_instance_state = 'REVOKED' AND revoked_at IS NOT NULL AND NULLIF(btrim(revoke_reason_code), '') IS NOT NULL)
        OR (refresh_token_instance_state <> 'REVOKED' AND revoked_at IS NULL AND revoke_reason_code IS NULL)
    ),
    ADD CONSTRAINT ck_refresh_token_retry_window CHECK (
        retry_window_until IS NULL OR (used_at IS NOT NULL AND retry_window_until >= used_at AND retry_window_until <= used_at + interval '60 seconds')
    );

ALTER TABLE oauth.authorization_code
    ADD CONSTRAINT ck_authorization_code_revoked CHECK ((authorization_code_state = 'REVOKED') = (revoked_at IS NOT NULL)),
    ADD CONSTRAINT ck_authorization_code_replay CHECK (replay_detected_at IS NULL OR authorization_code_state = 'CONSUMED');

CREATE OR REPLACE FUNCTION privacy.fn_consent_aggregate_context_guard()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    v_expected_key bytea;
BEGIN
    v_expected_key := core.fn_hash_jsonb(jsonb_build_object(
        'user_id', NEW.user_id::text,
        'purpose_code', NEW.purpose_code,
        'data_categories_hash', encode(NEW.data_categories_hash, 'hex'),
        'recipient_code', NEW.recipient_code,
        'tenant_id', NEW.tenant_id::text
    ));
    IF NEW.aggregate_key_hash <> v_expected_key THEN
        RAISE EXCEPTION 'CONSENT_AGGREGATE_KEY_HASH_MISMATCH' USING ERRCODE = '23514';
    END IF;
    IF TG_OP = 'UPDATE' AND (
        NEW.user_id IS DISTINCT FROM OLD.user_id
        OR NEW.purpose_code IS DISTINCT FROM OLD.purpose_code
        OR NEW.data_categories_hash IS DISTINCT FROM OLD.data_categories_hash
        OR NEW.recipient_code IS DISTINCT FROM OLD.recipient_code
        OR NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
        OR NEW.aggregate_key_hash IS DISTINCT FROM OLD.aggregate_key_hash
    ) THEN
        RAISE EXCEPTION 'CONSENT_AGGREGATE_CONTEXT_IMMUTABLE' USING ERRCODE = '55000';
    END IF;
    IF TG_OP = 'UPDATE' AND NEW.current_epoch IS DISTINCT FROM OLD.current_epoch
       AND (current_user <> 'kuc_owner' OR NEW.current_epoch <> OLD.current_epoch + 1) THEN
        RAISE EXCEPTION 'CONSENT_EPOCH_UPDATE_FORBIDDEN' USING ERRCODE = '42501';
    END IF;
    RETURN NEW;
END;
$$;
COMMENT ON FUNCTION privacy.fn_consent_aggregate_context_guard() IS 'Consent 聚合键由 User、用途、规范化类别摘要、接收方和 Tenant 确定；上下文不可修改且 epoch 不得回退。';

CREATE OR REPLACE FUNCTION privacy.fn_consent_epoch_guard()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
    v_epoch bigint;
    v_version bigint;
    v_aggregate privacy.consent_aggregate%ROWTYPE;
    v_categories_hash bytea;
    v_expected_context_hash bytea;
    v_allowed boolean := false;
BEGIN
    IF cardinality(NEW.data_category_codes) <> (
        SELECT count(DISTINCT d.category_code)
          FROM unnest(NEW.data_category_codes) AS d(category_code)
    ) THEN
        RAISE EXCEPTION 'CONSENT_DATA_CATEGORY_DUPLICATED' USING ERRCODE = '23514';
    END IF;

    SELECT * INTO v_aggregate
      FROM privacy.consent_aggregate
     WHERE id = NEW.aggregate_id
     FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'CONSENT_AGGREGATE_NOT_FOUND' USING ERRCODE = '23503';
    END IF;

    v_categories_hash := core.fn_hash_jsonb(
        to_jsonb(ARRAY(
            SELECT d.category_code
              FROM unnest(NEW.data_category_codes) AS d(category_code)
             ORDER BY d.category_code
        ))
    );
    IF v_aggregate.purpose_code <> NEW.purpose_code
       OR v_aggregate.recipient_code <> NEW.recipient_code
       OR v_aggregate.data_categories_hash <> v_categories_hash THEN
        RAISE EXCEPTION 'CONSENT_AGGREGATE_CONTEXT_MISMATCH' USING ERRCODE = '23514';
    END IF;

    v_expected_context_hash := core.fn_hash_jsonb(jsonb_build_object(
        'aggregate_id', NEW.aggregate_id::text,
        'purpose_code', NEW.purpose_code,
        'purpose_version', NEW.purpose_version,
        'data_category_codes', ARRAY(SELECT d.category_code FROM unnest(NEW.data_category_codes) AS d(category_code) ORDER BY d.category_code),
        'recipient_code', NEW.recipient_code,
        'requested_scope_codes', ARRAY(SELECT s.scope_code FROM unnest(NEW.requested_scope_codes) AS s(scope_code) ORDER BY s.scope_code),
        'source_client_id', NEW.source_client_id::text
    ));
    IF NEW.consent_context_hash <> v_expected_context_hash THEN
        RAISE EXCEPTION 'CONSENT_CONTEXT_HASH_MISMATCH' USING ERRCODE = '23514';
    END IF;

    IF NEW.source_client_id IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM oauth.client c
         WHERE c.id = NEW.source_client_id AND c.tenant_id = v_aggregate.tenant_id
    ) THEN
        RAISE EXCEPTION 'CONSENT_SOURCE_CLIENT_TENANT_MISMATCH' USING ERRCODE = '23514';
    END IF;
    IF NEW.source_login_transaction_id IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM authn.login_transaction tx
         WHERE tx.id = NEW.source_login_transaction_id
           AND tx.user_id = v_aggregate.user_id
           AND tx.tenant_id = v_aggregate.tenant_id
           AND tx.client_id = NEW.source_client_id
    ) THEN
        RAISE EXCEPTION 'CONSENT_SOURCE_TRANSACTION_CONTEXT_MISMATCH' USING ERRCODE = '23514';
    END IF;

    IF EXISTS (
        SELECT 1
          FROM unnest(NEW.data_category_codes) AS d(category_code)
         WHERE NOT EXISTS (
             SELECT 1
               FROM privacy.purpose_data_mapping m
              WHERE m.purpose_code = NEW.purpose_code
                AND m.purpose_version = NEW.purpose_version
                AND m.category_code = d.category_code
                AND m.recipient_code = NEW.recipient_code
         )
    ) THEN
        RAISE EXCEPTION 'CONSENT_PURPOSE_DATA_MAPPING_MISSING' USING ERRCODE = '23514';
    END IF;

    IF TG_OP = 'INSERT' THEN
        IF NEW.consent_state <> 'PENDING' THEN
            RAISE EXCEPTION 'INVALID_STATE_TRANSITION: Consent 必须从 PENDING 创建' USING ERRCODE = '23514';
        END IF;
        SELECT COALESCE(max(c.consent_version), 0) + 1
          INTO v_version
          FROM privacy.consent c
         WHERE c.aggregate_id = NEW.aggregate_id;
        NEW.consent_version := v_version;
        NEW.consent_epoch := v_aggregate.current_epoch;
        RETURN NEW;
    ELSE
        IF NEW.aggregate_id IS DISTINCT FROM OLD.aggregate_id
           OR NEW.consent_version IS DISTINCT FROM OLD.consent_version
           OR NEW.consent_context_hash IS DISTINCT FROM OLD.consent_context_hash
           OR NEW.purpose_code IS DISTINCT FROM OLD.purpose_code
           OR NEW.purpose_version IS DISTINCT FROM OLD.purpose_version
           OR NEW.data_category_codes IS DISTINCT FROM OLD.data_category_codes
           OR NEW.recipient_code IS DISTINCT FROM OLD.recipient_code
           OR NEW.requested_scope_codes IS DISTINCT FROM OLD.requested_scope_codes
           OR NEW.source_client_id IS DISTINCT FROM OLD.source_client_id
           OR NEW.source_login_transaction_id IS DISTINCT FROM OLD.source_login_transaction_id
           OR NEW.expires_at IS DISTINCT FROM OLD.expires_at THEN
            RAISE EXCEPTION 'CONSENT_CONTEXT_IMMUTABLE' USING ERRCODE = '55000';
        END IF;

        IF OLD.consent_state <> 'PENDING' AND (
            NEW.affirmative_action IS DISTINCT FROM OLD.affirmative_action
            OR NEW.action_kind IS DISTINCT FROM OLD.action_kind
            OR NEW.action_evidence_hash IS DISTINCT FROM OLD.action_evidence_hash
        ) THEN
            RAISE EXCEPTION 'CONSENT_ACTION_EVIDENCE_IMMUTABLE' USING ERRCODE = '55000';
        END IF;

        IF NEW.consent_state = OLD.consent_state THEN
            IF NEW.granted_at IS DISTINCT FROM OLD.granted_at
               OR NEW.denied_at IS DISTINCT FROM OLD.denied_at
               OR NEW.withdrawn_at IS DISTINCT FROM OLD.withdrawn_at
               OR NEW.expired_at IS DISTINCT FROM OLD.expired_at
               OR NEW.superseded_at IS DISTINCT FROM OLD.superseded_at THEN
                RAISE EXCEPTION 'CONSENT_STATE_EVIDENCE_IMMUTABLE' USING ERRCODE = '55000';
            END IF;
            NEW.consent_epoch := OLD.consent_epoch;
            RETURN NEW;
        ELSIF OLD.consent_state = 'PENDING' AND NEW.consent_state IN ('GRANTED', 'DENIED', 'EXPIRED') THEN
            v_allowed := true;
        ELSIF OLD.consent_state = 'GRANTED' AND NEW.consent_state IN ('WITHDRAWN', 'EXPIRED', 'SUPERSEDED') THEN
            v_allowed := true;
        END IF;
        IF NOT v_allowed THEN
            RAISE EXCEPTION 'INVALID_STATE_TRANSITION: Consent % -> %', OLD.consent_state, NEW.consent_state USING ERRCODE = '23514';
        END IF;
    END IF;

    IF NEW.consent_state = 'GRANTED' THEN
        NEW.granted_at := clock_timestamp();
    ELSIF NEW.consent_state = 'DENIED' THEN
        NEW.denied_at := clock_timestamp();
    ELSIF NEW.consent_state = 'WITHDRAWN' THEN
        NEW.withdrawn_at := clock_timestamp();
    ELSIF NEW.consent_state = 'EXPIRED' THEN
        NEW.expired_at := clock_timestamp();
    ELSIF NEW.consent_state = 'SUPERSEDED' THEN
        NEW.superseded_at := clock_timestamp();
    END IF;

    IF OLD.consent_state = 'PENDING' AND NEW.consent_state = 'EXPIRED' THEN
        NEW.consent_epoch := v_aggregate.current_epoch;
        RETURN NEW;
    END IF;

    -- 新决定生效时，下方 UPDATE 会递归进入本触发器以终结旧 GRANTED。
    -- 自动 SUPERSEDED 只记录旧版本终态，不得再次推进聚合 epoch；外层新决定统一推进一次。
    IF pg_trigger_depth() > 1
       AND OLD.consent_state = 'GRANTED'
       AND NEW.consent_state = 'SUPERSEDED' THEN
        NEW.consent_epoch := OLD.consent_epoch;
        RETURN NEW;
    END IF;

    IF OLD.consent_state = 'PENDING' AND NEW.consent_state IN ('GRANTED', 'DENIED') THEN
        UPDATE privacy.consent c
           SET consent_state = 'SUPERSEDED'
         WHERE c.aggregate_id = NEW.aggregate_id
           AND c.id <> NEW.id
           AND c.consent_state = 'GRANTED'
           AND c.consent_epoch = (SELECT a.current_epoch FROM privacy.consent_aggregate a WHERE a.id = NEW.aggregate_id);
    END IF;

    UPDATE privacy.consent_aggregate
       SET current_epoch = current_epoch + 1
     WHERE id = NEW.aggregate_id
     RETURNING current_epoch INTO v_epoch;
    NEW.consent_epoch := v_epoch;
    RETURN NEW;
END;
$$;
COMMENT ON FUNCTION privacy.fn_consent_epoch_guard() IS 'Consent 必须匹配聚合用途、接收方和规范化类别摘要；PENDING 按聚合串行分配版本且不推进 epoch，生效决定原子替代旧 GRANTED 并推进 epoch。';

CREATE TRIGGER trg_consent_aggregate_context BEFORE INSERT OR UPDATE ON privacy.consent_aggregate FOR EACH ROW
    EXECUTE FUNCTION privacy.fn_consent_aggregate_context_guard();

CREATE OR REPLACE FUNCTION privacy.fn_subscription_guard()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.subscription_state = 'SUBSCRIBED' AND NOT EXISTS (
        SELECT 1
          FROM privacy.consent c
          JOIN privacy.consent_aggregate a ON a.id = c.aggregate_id
         WHERE c.id = NEW.consent_id
           AND c.consent_state = 'GRANTED'
           AND c.consent_epoch = NEW.consent_epoch
           AND a.current_epoch = c.consent_epoch
           AND a.user_id = NEW.user_id
           AND a.recipient_code = NEW.recipient_code
           AND (c.expires_at IS NULL OR c.expires_at > clock_timestamp())
    ) THEN
        RAISE EXCEPTION 'CONSENT_NOT_EFFECTIVE' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;
COMMENT ON FUNCTION privacy.fn_subscription_guard() IS '订阅启用必须绑定同一用户、接收方、当前聚合 epoch 且未过期的 GRANTED Consent。';

CREATE OR REPLACE FUNCTION privacy.fn_notification_preference_guard()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.notification_category = 'SECURITY' AND NEW.preference_state <> 'ENABLED' THEN
        RAISE EXCEPTION 'SECURITY_NOTIFICATION_MANDATORY' USING ERRCODE = '23514';
    END IF;
    IF NEW.notification_category = 'MARKETING' AND NEW.preference_state = 'ENABLED' AND NOT EXISTS (
        SELECT 1
          FROM privacy.consent c
          JOIN privacy.consent_aggregate a ON a.id = c.aggregate_id
         WHERE c.id = NEW.consent_id
           AND c.consent_state = 'GRANTED'
           AND c.consent_epoch = NEW.consent_epoch
           AND a.current_epoch = c.consent_epoch
           AND a.user_id = NEW.user_id
           AND (c.expires_at IS NULL OR c.expires_at > clock_timestamp())
    ) THEN
        RAISE EXCEPTION 'MARKETING_CONSENT_NOT_EFFECTIVE' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;
COMMENT ON FUNCTION privacy.fn_notification_preference_guard() IS '安全通知不可关闭；营销通知启用必须绑定同一用户当前且未过期的 GRANTED Consent。';

CREATE OR REPLACE FUNCTION oauth.fn_session_insert_guard()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    PERFORM authn.fn_assert_user_can_authenticate(NEW.user_id);
    IF NOT EXISTS (
        SELECT 1
          FROM authn.login_transaction tx
          JOIN iam.user_account u ON u.id = tx.user_id
          JOIN oauth.client c ON c.id = tx.client_id
          JOIN org.tenant t ON t.id = tx.tenant_id
         WHERE tx.id = NEW.login_transaction_id
           AND tx.login_transaction_state = 'COMPLETED'
           AND tx.expires_at > clock_timestamp()
           AND tx.user_id = NEW.user_id
           AND tx.client_id = NEW.origin_client_id
           AND tx.tenant_id = NEW.tenant_id
           AND tx.profile_code = NEW.profile_code
           AND tx.achieved_aal = NEW.achieved_aal
           AND tx.authenticated_at = NEW.auth_time
           AND tx.achieved_amr @> NEW.amr_values
           AND NEW.amr_values @> tx.achieved_amr
           AND u.lifecycle_state = 'ACTIVE'
           AND u.authentication_lock_state = 'ENABLED'
           AND u.security_freeze_state = 'CLEAR'
           AND u.user_security_epoch = NEW.user_epoch_at_issue
           AND c.client_state = 'ACTIVE'
           AND c.client_security_epoch = NEW.client_epoch_at_issue
           AND t.tenant_state = 'ACTIVE'
           AND t.tenant_security_epoch = NEW.tenant_epoch_at_issue
           AND (NEW.device_id IS NULL OR EXISTS (
               SELECT 1 FROM oauth.device d
                WHERE d.id = NEW.device_id
                  AND d.user_id = NEW.user_id
                  AND d.device_lifecycle_state = 'REGISTERED'
                  AND d.device_loss_state = 'CLEAR'
           ))
           AND (NEW.parent_session_id IS NULL OR EXISTS (
               SELECT 1 FROM oauth.user_session parent
                WHERE parent.id = NEW.parent_session_id
                  AND parent.session_state = 'ACTIVE'
                  AND parent.user_id = NEW.user_id
                  AND parent.origin_client_id = NEW.origin_client_id
                  AND parent.tenant_id = NEW.tenant_id
           ))
    ) THEN
        RAISE EXCEPTION 'SESSION_CONTEXT_MISMATCH: Login Transaction、主体、Client、Tenant、Profile、AAL 或 epoch 不一致' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;
COMMENT ON FUNCTION oauth.fn_session_insert_guard() IS 'Session 只能由未过期的 COMPLETED Login Transaction 创建，并精确绑定主体、Client、Tenant、Profile、AAL 及当前安全 epoch。';

CREATE OR REPLACE FUNCTION oauth.fn_grant_activation_guard()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    v_allowed boolean := false;
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.grant_state <> 'PENDING' OR NEW.granted_at IS NOT NULL OR NEW.denied_at IS NOT NULL OR NEW.revoked_at IS NOT NULL THEN
            RAISE EXCEPTION 'GRANT_INITIAL_STATE_INVALID' USING ERRCODE = '23514';
        END IF;
        RETURN NEW;
    END IF;

    IF NEW.grant_state = OLD.grant_state THEN
        v_allowed := true;
    ELSIF OLD.grant_state = 'PENDING' AND NEW.grant_state IN ('ACTIVE', 'DENIED', 'EXPIRED') THEN
        v_allowed := true;
    ELSIF OLD.grant_state = 'ACTIVE' AND NEW.grant_state IN ('REVOKED', 'EXPIRED') THEN
        v_allowed := true;
    END IF;
    IF NOT v_allowed THEN
        RAISE EXCEPTION 'INVALID_STATE_TRANSITION: Authorization Grant % -> %', OLD.grant_state, NEW.grant_state USING ERRCODE = '23514';
    END IF;

    IF TG_OP = 'UPDATE' AND OLD.grant_state = 'ACTIVE' AND (
        NEW.subject_kind IS DISTINCT FROM OLD.subject_kind
        OR NEW.subject_id IS DISTINCT FROM OLD.subject_id
        OR NEW.client_id IS DISTINCT FROM OLD.client_id
        OR NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
        OR NEW.login_transaction_id IS DISTINCT FROM OLD.login_transaction_id
        OR NEW.requested_scopes IS DISTINCT FROM OLD.requested_scopes
        OR NEW.granted_scopes IS DISTINCT FROM OLD.granted_scopes
        OR NEW.granted_resources IS DISTINCT FROM OLD.granted_resources
        OR NEW.authorization_details IS DISTINCT FROM OLD.authorization_details
        OR NEW.consent_required IS DISTINCT FROM OLD.consent_required
        OR NEW.consent_id IS DISTINCT FROM OLD.consent_id
        OR NEW.consent_context_hash IS DISTINCT FROM OLD.consent_context_hash
        OR NEW.consent_epoch_at_grant IS DISTINCT FROM OLD.consent_epoch_at_grant
        OR NEW.user_epoch_at_grant IS DISTINCT FROM OLD.user_epoch_at_grant
        OR NEW.machine_epoch_at_grant IS DISTINCT FROM OLD.machine_epoch_at_grant
        OR NEW.client_epoch_at_grant IS DISTINCT FROM OLD.client_epoch_at_grant
        OR NEW.tenant_epoch_at_grant IS DISTINCT FROM OLD.tenant_epoch_at_grant
        OR NEW.policy_version IS DISTINCT FROM OLD.policy_version
        OR NEW.expires_at IS DISTINCT FROM OLD.expires_at
        OR NEW.granted_at IS DISTINCT FROM OLD.granted_at
    ) THEN
        RAISE EXCEPTION 'GRANT_CONTEXT_IMMUTABLE' USING ERRCODE = '55000';
    END IF;

    IF NEW.grant_state = 'ACTIVE' AND OLD.grant_state <> 'ACTIVE' THEN
        IF NEW.expires_at IS NULL OR NEW.expires_at <= clock_timestamp() THEN
            RAISE EXCEPTION 'GRANT_EXPIRY_REQUIRED' USING ERRCODE = '23514';
        END IF;
        NEW.granted_at := clock_timestamp();
        IF NOT EXISTS (
            SELECT 1
              FROM oauth.client c
              JOIN org.tenant t ON t.id = c.tenant_id
             WHERE c.id = NEW.client_id
               AND c.tenant_id = NEW.tenant_id
               AND c.client_state = 'ACTIVE'
               AND c.client_security_epoch = NEW.client_epoch_at_grant
               AND NEW.granted_scopes <@ c.allowed_scopes
               AND NEW.granted_resources <@ c.allowed_resources
               AND (NOT c.consent_required OR NEW.consent_required)
               AND t.tenant_state = 'ACTIVE'
               AND t.tenant_security_epoch = NEW.tenant_epoch_at_grant
        ) THEN
            RAISE EXCEPTION 'GRANT_CLIENT_OR_TENANT_CONTEXT_MISMATCH' USING ERRCODE = '23514';
        END IF;

        IF NEW.subject_kind = 'USER' THEN
            IF NOT EXISTS (
                SELECT 1
                  FROM authn.login_transaction tx
                  JOIN iam.user_account u ON u.id = tx.user_id
                 WHERE tx.id = NEW.login_transaction_id
                   AND tx.login_transaction_state = 'COMPLETED'
                   AND tx.expires_at > clock_timestamp()
                   AND tx.user_id = NEW.subject_id
                   AND tx.client_id = NEW.client_id
                   AND tx.tenant_id = NEW.tenant_id
                   AND NEW.granted_scopes <@ tx.requested_scopes
                   AND NEW.granted_resources <@ tx.requested_resources
                   AND u.lifecycle_state = 'ACTIVE'
                   AND u.authentication_lock_state = 'ENABLED'
                   AND u.security_freeze_state = 'CLEAR'
                   AND u.user_security_epoch = NEW.user_epoch_at_grant
            ) THEN
                RAISE EXCEPTION 'GRANT_USER_TRANSACTION_CONTEXT_MISMATCH' USING ERRCODE = '23514';
            END IF;
        ELSIF NOT EXISTS (
            SELECT 1
              FROM workload.machine_principal m
             WHERE m.id = NEW.subject_id
               AND m.tenant_id = NEW.tenant_id
               AND m.principal_state = 'ACTIVE'
               AND m.principal_security_epoch = NEW.machine_epoch_at_grant
               AND m.expires_at > clock_timestamp()
        ) THEN
            RAISE EXCEPTION 'GRANT_MACHINE_CONTEXT_MISMATCH' USING ERRCODE = '23514';
        END IF;

        IF NEW.consent_required AND NOT EXISTS (
            SELECT 1
              FROM privacy.consent c
              JOIN privacy.consent_aggregate a ON a.id = c.aggregate_id
             WHERE c.id = NEW.consent_id
               AND c.consent_state = 'GRANTED'
               AND c.consent_context_hash = NEW.consent_context_hash
               AND c.consent_epoch = NEW.consent_epoch_at_grant
               AND a.current_epoch = c.consent_epoch
               AND a.user_id = NEW.subject_id
               AND a.tenant_id = NEW.tenant_id
               AND (c.expires_at IS NULL OR c.expires_at > clock_timestamp())
        ) THEN
            RAISE EXCEPTION 'GRANT_CONSENT_CONTEXT_MISMATCH' USING ERRCODE = '23514';
        END IF;
    ELSIF NEW.grant_state = 'DENIED' AND OLD.grant_state <> 'DENIED' THEN
        NEW.denied_at := clock_timestamp();
    ELSIF NEW.grant_state = 'REVOKED' AND OLD.grant_state <> 'REVOKED' THEN
        NEW.revoked_at := clock_timestamp();
    ELSIF NEW.grant_state = 'EXPIRED' AND OLD.grant_state <> 'EXPIRED'
       AND (NEW.expires_at IS NULL OR NEW.expires_at > clock_timestamp()) THEN
        RAISE EXCEPTION 'GRANT_NOT_EXPIRED' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;
COMMENT ON FUNCTION oauth.fn_grant_activation_guard() IS 'Grant 激活精确绑定当前 Client/Tenant/主体 epoch、Login Transaction、scope/resource 子集和当前有效 Consent；激活后上下文不可变。';

CREATE OR REPLACE FUNCTION oauth.fn_authorization_code_context_guard()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.authorization_code_state <> 'ISSUED'
       OR NEW.consumed_at IS NOT NULL
       OR NEW.replay_detected_at IS NOT NULL
       OR NEW.revoked_at IS NOT NULL THEN
        RAISE EXCEPTION 'AUTHORIZATION_CODE_INITIAL_STATE_INVALID' USING ERRCODE = '23514';
    END IF;
    IF NOT EXISTS (
        SELECT 1
          FROM oauth.authorization_grant g
          JOIN authn.login_transaction tx ON tx.id = NEW.login_transaction_id
         WHERE g.id = NEW.grant_id
           AND g.grant_state = 'ACTIVE'
           AND g.subject_kind = 'USER'
           AND g.subject_id = NEW.user_id
           AND g.client_id = NEW.client_id
           AND tx.login_transaction_state = 'COMPLETED'
           AND tx.expires_at > clock_timestamp()
           AND tx.user_id = NEW.user_id
           AND tx.client_id = NEW.client_id
           AND tx.id = g.login_transaction_id
           AND tx.redirect_uri = NEW.redirect_uri
           AND tx.code_challenge = NEW.code_challenge
           AND tx.code_challenge_method = NEW.code_challenge_method
           AND NEW.scopes <@ g.granted_scopes
           AND NEW.resources <@ g.granted_resources
           AND (g.expires_at IS NULL OR NEW.expires_at <= g.expires_at)
           AND (NEW.session_id IS NULL OR EXISTS (
               SELECT 1 FROM oauth.user_session s
                WHERE s.id = NEW.session_id
                  AND s.session_state = 'ACTIVE'
                  AND s.user_id = NEW.user_id
                  AND s.origin_client_id = NEW.client_id
                  AND s.login_transaction_id = NEW.login_transaction_id
           ))
    ) THEN
        RAISE EXCEPTION 'AUTHORIZATION_CODE_CONTEXT_MISMATCH' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;
COMMENT ON FUNCTION oauth.fn_authorization_code_context_guard() IS '授权码签发必须与 ACTIVE Grant、COMPLETED Login Transaction、Session、redirect URI、PKCE、scope 和 resource 精确一致。';

CREATE OR REPLACE FUNCTION oauth.fn_token_family_context_guard()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.revoked_at IS NOT NULL OR NOT EXISTS (
        SELECT 1
          FROM oauth.authorization_grant g
          JOIN oauth.client c ON c.id = g.client_id
          JOIN org.tenant t ON t.id = g.tenant_id
         WHERE g.id = NEW.grant_id
           AND g.grant_state = 'ACTIVE'
           AND g.subject_kind = NEW.subject_kind
           AND g.subject_id = NEW.subject_id
           AND g.client_id = NEW.client_id
           AND g.tenant_id = NEW.tenant_id
           AND c.client_state = 'ACTIVE'
           AND c.client_security_epoch = g.client_epoch_at_grant
           AND t.tenant_state = 'ACTIVE'
           AND t.tenant_security_epoch = g.tenant_epoch_at_grant
           AND (g.expires_at IS NULL OR NEW.absolute_expires_at <= g.expires_at)
           AND (NEW.session_id IS NOT NULL OR NEW.profile_code = c.profile_code)
           AND (NOT g.consent_required OR EXISTS (
               SELECT 1
                 FROM privacy.consent cn
                 JOIN privacy.consent_aggregate a ON a.id = cn.aggregate_id
                WHERE cn.id = g.consent_id
                  AND cn.consent_state = 'GRANTED'
                  AND cn.consent_context_hash = g.consent_context_hash
                  AND cn.consent_epoch = g.consent_epoch_at_grant
                  AND a.current_epoch = cn.consent_epoch
                  AND (cn.expires_at IS NULL OR cn.expires_at > clock_timestamp())
           ))
           AND (NEW.subject_kind <> 'USER' OR EXISTS (
               SELECT 1 FROM iam.user_account u
                WHERE u.id = NEW.subject_id
                  AND u.lifecycle_state = 'ACTIVE'
                  AND u.authentication_lock_state = 'ENABLED'
                  AND u.security_freeze_state = 'CLEAR'
                  AND u.user_security_epoch = g.user_epoch_at_grant
           ))
           AND (NEW.subject_kind <> 'MACHINE' OR EXISTS (
               SELECT 1 FROM workload.machine_principal m
                WHERE m.id = NEW.subject_id
                  AND m.tenant_id = NEW.tenant_id
                  AND m.principal_state = 'ACTIVE'
                  AND m.principal_security_epoch = g.machine_epoch_at_grant
                  AND m.expires_at > clock_timestamp()
           ))
           AND (NEW.session_id IS NULL OR EXISTS (
               SELECT 1 FROM oauth.user_session s
                WHERE s.id = NEW.session_id
                  AND s.session_state = 'ACTIVE'
                  AND s.user_id = NEW.subject_id
                  AND s.origin_client_id = NEW.client_id
                  AND s.tenant_id = NEW.tenant_id
                  AND s.profile_code = NEW.profile_code
           ))
    ) THEN
        RAISE EXCEPTION 'TOKEN_FAMILY_CONTEXT_MISMATCH' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;
COMMENT ON FUNCTION oauth.fn_token_family_context_guard() IS 'Refresh Token Family 必须绑定同一主体、Client、Tenant、ACTIVE Grant 和可选 ACTIVE Session。';

CREATE OR REPLACE FUNCTION oauth.fn_reference_token_context_guard()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.revoked_at IS NOT NULL OR NOT EXISTS (
        SELECT 1
          FROM oauth.authorization_grant g
          JOIN oauth.client c ON c.id = g.client_id
          JOIN org.tenant t ON t.id = g.tenant_id
         WHERE g.id = NEW.grant_id
           AND g.grant_state = 'ACTIVE'
           AND g.subject_kind = NEW.subject_kind
           AND g.subject_id = NEW.subject_id
           AND g.client_id = NEW.client_id
           AND g.tenant_id = NEW.tenant_id
           AND NEW.scopes <@ g.granted_scopes
           AND NEW.audiences <@ g.granted_resources
           AND c.client_state = 'ACTIVE'
           AND c.client_security_epoch = NEW.client_epoch_at_issue
           AND t.tenant_state = 'ACTIVE'
           AND t.tenant_security_epoch = NEW.tenant_epoch_at_issue
           AND g.client_epoch_at_grant = NEW.client_epoch_at_issue
           AND g.tenant_epoch_at_grant = NEW.tenant_epoch_at_issue
           AND (g.expires_at IS NULL OR NEW.expires_at <= g.expires_at)
           AND (NEW.session_id IS NOT NULL OR NEW.profile_code = c.profile_code)
           AND (NOT g.consent_required OR (
               NEW.consent_id = g.consent_id
               AND NEW.consent_context_hash = g.consent_context_hash
               AND NEW.consent_epoch_at_issue = g.consent_epoch_at_grant
           ))
           AND (NEW.subject_kind <> 'USER' OR EXISTS (
               SELECT 1 FROM iam.user_account u
                WHERE u.id = NEW.subject_id
                  AND u.lifecycle_state = 'ACTIVE'
                  AND u.authentication_lock_state = 'ENABLED'
                  AND u.security_freeze_state = 'CLEAR'
                  AND u.user_security_epoch = NEW.user_epoch_at_issue
                  AND g.user_epoch_at_grant = NEW.user_epoch_at_issue
           ))
           AND (NEW.subject_kind <> 'MACHINE' OR EXISTS (
               SELECT 1 FROM workload.machine_principal m
                WHERE m.id = NEW.subject_id
                  AND m.tenant_id = NEW.tenant_id
                  AND m.principal_state = 'ACTIVE'
                  AND m.principal_security_epoch = NEW.machine_epoch_at_issue
                  AND g.machine_epoch_at_grant = NEW.machine_epoch_at_issue
                  AND m.expires_at > clock_timestamp()
           ))
           AND (NEW.session_id IS NULL OR EXISTS (
               SELECT 1 FROM oauth.user_session s
                WHERE s.id = NEW.session_id
                  AND s.session_state = 'ACTIVE'
                  AND s.user_id = NEW.subject_id
                  AND s.origin_client_id = NEW.client_id
                  AND s.tenant_id = NEW.tenant_id
                  AND s.profile_code = NEW.profile_code
                  AND NEW.expires_at <= s.absolute_expires_at
           ))
           AND (NEW.token_family_id IS NULL OR EXISTS (
               SELECT 1 FROM oauth.token_family f
                WHERE f.id = NEW.token_family_id
                  AND f.token_family_state = 'ACTIVE'
                  AND f.grant_id = NEW.grant_id
                  AND f.subject_kind = NEW.subject_kind
                  AND f.subject_id = NEW.subject_id
                  AND f.client_id = NEW.client_id
                  AND f.tenant_id = NEW.tenant_id
                  AND f.profile_code = NEW.profile_code
                  AND NEW.expires_at <= f.absolute_expires_at
           ))
           AND (NEW.consent_id IS NULL OR EXISTS (
               SELECT 1
                 FROM privacy.consent cn
                 JOIN privacy.consent_aggregate a ON a.id = cn.aggregate_id
                WHERE cn.id = NEW.consent_id
                  AND cn.consent_state = 'GRANTED'
                  AND cn.consent_context_hash = NEW.consent_context_hash
                  AND cn.consent_epoch = NEW.consent_epoch_at_issue
                  AND a.current_epoch = cn.consent_epoch
                  AND a.user_id = NEW.subject_id
                  AND a.tenant_id = NEW.tenant_id
                  AND (cn.expires_at IS NULL OR cn.expires_at > clock_timestamp())
           ))
    ) THEN
        RAISE EXCEPTION 'REFERENCE_TOKEN_CONTEXT_MISMATCH' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;
COMMENT ON FUNCTION oauth.fn_reference_token_context_guard() IS 'Reference Access Token 签发时重验 Grant、主体、Client、Tenant、Session、Token Family、Consent 和全部适用 epoch。';

CREATE OR REPLACE FUNCTION oauth.fn_token_family_state_guard()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    v_allowed boolean := false;
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.token_family_state <> 'ACTIVE'
           OR NEW.generation_count <> 0
           OR NEW.compromised_at IS NOT NULL
           OR NEW.revoked_at IS NOT NULL
           OR NEW.idle_expires_at <= clock_timestamp()
           OR NEW.absolute_expires_at <= clock_timestamp() THEN
            RAISE EXCEPTION 'TOKEN_FAMILY_INITIAL_STATE_INVALID' USING ERRCODE = '23514';
        END IF;
        RETURN NEW;
    END IF;

    IF NEW.token_family_state = OLD.token_family_state THEN
        v_allowed := true;
    ELSIF OLD.token_family_state = 'ACTIVE' AND NEW.token_family_state IN ('COMPROMISED', 'REVOKED', 'EXPIRED') THEN
        v_allowed := true;
    END IF;
    IF NOT v_allowed THEN
        RAISE EXCEPTION 'INVALID_STATE_TRANSITION: Token Family % -> %', OLD.token_family_state, NEW.token_family_state USING ERRCODE = '23514';
    END IF;

    IF NEW.generation_count IS DISTINCT FROM OLD.generation_count
       AND (OLD.token_family_state <> 'ACTIVE' OR NEW.token_family_state <> 'ACTIVE' OR NEW.generation_count <> OLD.generation_count + 1) THEN
        RAISE EXCEPTION 'TOKEN_FAMILY_GENERATION_NOT_MONOTONIC' USING ERRCODE = '23514';
    END IF;
    IF NEW.idle_expires_at IS DISTINCT FROM OLD.idle_expires_at
       AND (OLD.token_family_state <> 'ACTIVE' OR NEW.token_family_state <> 'ACTIVE'
            OR NEW.idle_expires_at <= clock_timestamp() OR NEW.idle_expires_at > NEW.absolute_expires_at) THEN
        RAISE EXCEPTION 'TOKEN_FAMILY_IDLE_EXPIRY_INVALID' USING ERRCODE = '23514';
    END IF;
    IF NEW.compromised_at IS DISTINCT FROM OLD.compromised_at
       AND NOT (OLD.token_family_state = 'ACTIVE' AND NEW.token_family_state = 'COMPROMISED') THEN
        RAISE EXCEPTION 'TOKEN_FAMILY_COMPROMISE_EVIDENCE_IMMUTABLE' USING ERRCODE = '55000';
    END IF;
    IF NEW.compromise_reason_code IS DISTINCT FROM OLD.compromise_reason_code
       AND NOT (OLD.token_family_state = 'ACTIVE' AND NEW.token_family_state = 'COMPROMISED') THEN
        RAISE EXCEPTION 'TOKEN_FAMILY_COMPROMISE_REASON_IMMUTABLE' USING ERRCODE = '55000';
    END IF;
    IF NEW.revoked_at IS DISTINCT FROM OLD.revoked_at
       AND NOT (OLD.token_family_state = 'ACTIVE' AND NEW.token_family_state = 'REVOKED') THEN
        RAISE EXCEPTION 'TOKEN_FAMILY_REVOCATION_EVIDENCE_IMMUTABLE' USING ERRCODE = '55000';
    END IF;
    IF NEW.revoke_reason_code IS DISTINCT FROM OLD.revoke_reason_code
       AND NOT (OLD.token_family_state = 'ACTIVE' AND NEW.token_family_state = 'REVOKED') THEN
        RAISE EXCEPTION 'TOKEN_FAMILY_REVOKE_REASON_IMMUTABLE' USING ERRCODE = '55000';
    END IF;
    IF NEW.token_family_state = 'COMPROMISED' AND OLD.token_family_state <> 'COMPROMISED' THEN
        IF NULLIF(btrim(NEW.compromise_reason_code), '') IS NULL THEN
            RAISE EXCEPTION 'TOKEN_FAMILY_COMPROMISE_REASON_REQUIRED' USING ERRCODE = '23514';
        END IF;
        NEW.compromised_at := clock_timestamp();
    ELSIF NEW.token_family_state = 'REVOKED' AND OLD.token_family_state <> 'REVOKED' THEN
        IF NULLIF(btrim(NEW.revoke_reason_code), '') IS NULL THEN
            RAISE EXCEPTION 'TOKEN_FAMILY_REVOKE_REASON_REQUIRED' USING ERRCODE = '23514';
        END IF;
        NEW.revoked_at := clock_timestamp();
    ELSIF NEW.token_family_state = 'EXPIRED' AND OLD.token_family_state <> 'EXPIRED'
       AND LEAST(NEW.idle_expires_at, NEW.absolute_expires_at) > clock_timestamp() THEN
        RAISE EXCEPTION 'TOKEN_FAMILY_NOT_EXPIRED' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;
COMMENT ON FUNCTION oauth.fn_token_family_state_guard() IS 'Token Family 从 ACTIVE 单向进入失陷、撤销或过期；代际只允许逐次递增，关键时间由数据库写入。';

CREATE OR REPLACE FUNCTION oauth.fn_session_state_guard()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    v_allowed boolean := false;
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.session_state <> 'ACTIVE'
           OR NEW.expired_at IS NOT NULL
           OR NEW.compromised_at IS NOT NULL
           OR NEW.compromise_reason_code IS NOT NULL
           OR NEW.revoked_at IS NOT NULL
           OR NEW.revoke_reason_code IS NOT NULL
           OR NEW.idle_expires_at <= clock_timestamp()
           OR NEW.absolute_expires_at <= clock_timestamp() THEN
            RAISE EXCEPTION 'SESSION_INITIAL_STATE_INVALID' USING ERRCODE = '23514';
        END IF;
        RETURN NEW;
    END IF;

    IF NEW.session_state = OLD.session_state THEN
        v_allowed := true;
    ELSIF OLD.session_state = 'ACTIVE' AND NEW.session_state IN ('EXPIRED', 'COMPROMISED', 'REVOKED') THEN
        v_allowed := true;
    END IF;
    IF NOT v_allowed THEN
        RAISE EXCEPTION 'INVALID_STATE_TRANSITION: Session % -> %', OLD.session_state, NEW.session_state USING ERRCODE = '23514';
    END IF;

    IF NEW.idle_expires_at IS DISTINCT FROM OLD.idle_expires_at
       AND (OLD.session_state <> 'ACTIVE' OR NEW.session_state <> 'ACTIVE'
            OR NEW.idle_expires_at <= clock_timestamp() OR NEW.idle_expires_at > NEW.absolute_expires_at) THEN
        RAISE EXCEPTION 'SESSION_IDLE_EXPIRY_INVALID' USING ERRCODE = '23514';
    END IF;

    IF NEW.expired_at IS DISTINCT FROM OLD.expired_at
       AND NOT (OLD.session_state = 'ACTIVE' AND NEW.session_state = 'EXPIRED') THEN
        RAISE EXCEPTION 'SESSION_EXPIRY_EVIDENCE_IMMUTABLE' USING ERRCODE = '55000';
    END IF;
    IF (NEW.compromised_at, NEW.compromise_reason_code)
       IS DISTINCT FROM (OLD.compromised_at, OLD.compromise_reason_code)
       AND NOT (OLD.session_state = 'ACTIVE' AND NEW.session_state = 'COMPROMISED') THEN
        RAISE EXCEPTION 'SESSION_COMPROMISE_EVIDENCE_IMMUTABLE' USING ERRCODE = '55000';
    END IF;
    IF (NEW.revoked_at, NEW.revoke_reason_code)
       IS DISTINCT FROM (OLD.revoked_at, OLD.revoke_reason_code)
       AND NOT (OLD.session_state = 'ACTIVE' AND NEW.session_state = 'REVOKED') THEN
        RAISE EXCEPTION 'SESSION_REVOCATION_EVIDENCE_IMMUTABLE' USING ERRCODE = '55000';
    END IF;

    IF OLD.session_state = 'ACTIVE' AND NEW.session_state = 'EXPIRED' THEN
        IF LEAST(OLD.idle_expires_at, OLD.absolute_expires_at) > clock_timestamp() THEN
            RAISE EXCEPTION 'SESSION_NOT_EXPIRED' USING ERRCODE = '23514';
        END IF;
        NEW.expired_at := clock_timestamp();
    ELSIF OLD.session_state = 'ACTIVE' AND NEW.session_state = 'COMPROMISED' THEN
        IF NULLIF(btrim(NEW.compromise_reason_code), '') IS NULL THEN
            RAISE EXCEPTION 'SESSION_COMPROMISE_REASON_REQUIRED' USING ERRCODE = '23514';
        END IF;
        NEW.compromised_at := clock_timestamp();
    ELSIF OLD.session_state = 'ACTIVE' AND NEW.session_state = 'REVOKED' THEN
        IF NULLIF(btrim(NEW.revoke_reason_code), '') IS NULL THEN
            RAISE EXCEPTION 'SESSION_REVOKE_REASON_REQUIRED' USING ERRCODE = '23514';
        END IF;
        NEW.revoked_at := clock_timestamp();
    END IF;
    RETURN NEW;
END;
$$;
COMMENT ON FUNCTION oauth.fn_session_state_guard() IS 'Session 必须从 ACTIVE 创建，只能单向进入过期、失陷或撤销；原因和关键时间由数据库维护且不可改写。';

CREATE OR REPLACE FUNCTION oauth.fn_refresh_token_guard()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    v_family oauth.token_family%ROWTYPE;
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'REFRESH_TOKEN_DELETE_FORBIDDEN' USING ERRCODE = '55000';
    END IF;
    IF TG_OP = 'INSERT' THEN
        SELECT * INTO v_family FROM oauth.token_family WHERE id = NEW.family_id FOR UPDATE;
        IF NOT FOUND OR v_family.token_family_state <> 'ACTIVE'
           OR NEW.expires_at <= clock_timestamp()
           OR NEW.expires_at > v_family.absolute_expires_at
           OR NEW.refresh_token_instance_state <> 'CURRENT'
           OR NEW.used_at IS NOT NULL OR NEW.successor_id IS NOT NULL
           OR NEW.retry_window_until IS NOT NULL OR NEW.revoked_at IS NOT NULL THEN
            RAISE EXCEPTION 'REFRESH_TOKEN_INITIAL_CONTEXT_INVALID' USING ERRCODE = '23514';
        END IF;
        NEW.generation := v_family.generation_count + 1;
        NEW.issued_at := clock_timestamp();
        UPDATE oauth.token_family
           SET generation_count = NEW.generation
         WHERE id = NEW.family_id;
        RETURN NEW;
    END IF;

    IF NEW.family_id IS DISTINCT FROM OLD.family_id
       OR NEW.generation IS DISTINCT FROM OLD.generation
       OR NEW.token_hash IS DISTINCT FROM OLD.token_hash
       OR NEW.issued_at IS DISTINCT FROM OLD.issued_at
       OR NEW.expires_at IS DISTINCT FROM OLD.expires_at
       OR NEW.binding_context_hash IS DISTINCT FROM OLD.binding_context_hash THEN
        RAISE EXCEPTION 'REFRESH_TOKEN_IDENTITY_IMMUTABLE' USING ERRCODE = '55000';
    END IF;

    IF OLD.refresh_token_instance_state = 'CURRENT' AND NEW.refresh_token_instance_state = 'USED' THEN
        IF NEW.successor_id IS NULL THEN
            RAISE EXCEPTION 'REFRESH_TOKEN_SUCCESSOR_REQUIRED' USING ERRCODE = '23514';
        END IF;
        NEW.used_at := clock_timestamp();
        NEW.retry_window_until := NEW.used_at + interval '10 seconds';
    ELSIF OLD.refresh_token_instance_state = 'CURRENT' AND NEW.refresh_token_instance_state = 'REVOKED' THEN
        IF NULLIF(btrim(NEW.revoke_reason_code), '') IS NULL THEN
            RAISE EXCEPTION 'REFRESH_TOKEN_REVOKE_REASON_REQUIRED' USING ERRCODE = '23514';
        END IF;
        NEW.revoked_at := clock_timestamp();
    ELSIF OLD.refresh_token_instance_state = 'CURRENT' AND NEW.refresh_token_instance_state = 'EXPIRED' THEN
        IF OLD.expires_at > clock_timestamp() THEN
            RAISE EXCEPTION 'REFRESH_TOKEN_NOT_EXPIRED' USING ERRCODE = '23514';
        END IF;
    ELSIF NEW.refresh_token_instance_state = OLD.refresh_token_instance_state
       AND to_jsonb(NEW) IS NOT DISTINCT FROM to_jsonb(OLD) THEN
        RETURN NEW;
    ELSE
        RAISE EXCEPTION 'INVALID_STATE_TRANSITION: Refresh Token % -> %', OLD.refresh_token_instance_state, NEW.refresh_token_instance_state USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;
COMMENT ON FUNCTION oauth.fn_refresh_token_guard() IS 'Refresh Token 由数据库串行分配 Family generation；CURRENT 只能原子转为 USED、REVOKED 或到期，哈希、Family、代际和绑定上下文不可改写。';

CREATE OR REPLACE FUNCTION oauth.fn_refresh_token_successor_guard()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.refresh_token_instance_state = 'USED' AND NOT EXISTS (
        SELECT 1 FROM oauth.refresh_token s
         WHERE s.id = NEW.successor_id
           AND s.family_id = NEW.family_id
           AND s.generation = NEW.generation + 1
           AND s.refresh_token_instance_state = 'CURRENT'
    ) THEN
        RAISE EXCEPTION 'REFRESH_TOKEN_SUCCESSOR_CONTEXT_MISMATCH' USING ERRCODE = '23514';
    END IF;
    RETURN NULL;
END;
$$;
COMMENT ON FUNCTION oauth.fn_refresh_token_successor_guard() IS '事务提交前验证 USED Refresh Token 的 successor 属于同一 Family、恰好下一代且仍为 CURRENT。';

CREATE OR REPLACE FUNCTION oauth.fn_mark_refresh_token_reuse(p_refresh_token_id uuid, p_reason_code text DEFAULT 'REFRESH_TOKEN_REUSE')
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
    v_family oauth.token_family%ROWTYPE;
BEGIN
    SELECT f.* INTO v_family
      FROM oauth.refresh_token rt
      JOIN oauth.token_family f ON f.id = rt.family_id
     WHERE rt.id = p_refresh_token_id
       AND rt.refresh_token_instance_state = 'USED'
     FOR UPDATE OF f;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'REFRESH_TOKEN_REUSE_TARGET_INVALID' USING ERRCODE = '23514';
    END IF;
    IF v_family.token_family_state = 'ACTIVE' THEN
        UPDATE oauth.token_family
           SET token_family_state = 'COMPROMISED', compromise_reason_code = p_reason_code
         WHERE id = v_family.id;
        INSERT INTO oauth.revocation_record(
            revocation_kind, target_ref, user_id, client_id, tenant_id,
            reason_code, source_kind, source_ref, prunable_after
        ) VALUES (
            'TOKEN_FAMILY', v_family.id::text,
            CASE WHEN v_family.subject_kind = 'USER' THEN v_family.subject_id ELSE NULL END,
            v_family.client_id, v_family.tenant_id,
            p_reason_code, 'SYSTEM', p_refresh_token_id::text,
            clock_timestamp() + interval '400 days'
        );
    END IF;
END;
$$;
COMMENT ON FUNCTION oauth.fn_mark_refresh_token_reuse(uuid, text) IS '确认已使用 Refresh Token 被重放时，原子将整个 Family 标记为 COMPROMISED 并追加撤销记录。';

CREATE OR REPLACE FUNCTION oauth.fn_authorization_code_state_guard()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    v_grant oauth.authorization_grant%ROWTYPE;
BEGIN
    IF OLD.authorization_code_state = 'ISSUED' AND NEW.authorization_code_state = 'CONSUMED' THEN
        IF NEW.replay_detected_at IS NOT NULL OR NEW.revoked_at IS NOT NULL THEN
            RAISE EXCEPTION 'AUTHORIZATION_CODE_CONSUMPTION_EVIDENCE_INVALID' USING ERRCODE = '23514';
        END IF;
        NEW.consumed_at := clock_timestamp();
    ELSIF OLD.authorization_code_state = 'ISSUED' AND NEW.authorization_code_state = 'EXPIRED' THEN
        IF OLD.expires_at > clock_timestamp() THEN
            RAISE EXCEPTION 'AUTHORIZATION_CODE_NOT_EXPIRED' USING ERRCODE = '23514';
        END IF;
    ELSIF OLD.authorization_code_state = 'ISSUED' AND NEW.authorization_code_state = 'REVOKED' THEN
        NEW.revoked_at := clock_timestamp();
    ELSIF OLD.authorization_code_state = 'CONSUMED'
       AND NEW.authorization_code_state = 'CONSUMED'
       AND OLD.replay_detected_at IS NULL
       AND NEW.replay_detected_at IS NOT NULL THEN
        NEW.replay_detected_at := clock_timestamp();
        SELECT * INTO v_grant FROM oauth.authorization_grant WHERE id = NEW.grant_id FOR UPDATE;
        UPDATE oauth.token_family
           SET token_family_state = 'COMPROMISED', compromise_reason_code = 'AUTHORIZATION_CODE_REPLAY'
         WHERE grant_id = NEW.grant_id AND token_family_state = 'ACTIVE';
        UPDATE oauth.authorization_grant
           SET grant_state = 'REVOKED', revoke_reason_code = 'AUTHORIZATION_CODE_REPLAY', revoked_by_ref = 'database'
         WHERE id = NEW.grant_id AND grant_state = 'ACTIVE';
        IF FOUND THEN
            INSERT INTO oauth.revocation_record(
                revocation_kind, target_ref, user_id, client_id, tenant_id,
                reason_code, source_kind, source_ref, prunable_after
            ) VALUES (
                'GRANT', v_grant.id::text,
                CASE WHEN v_grant.subject_kind = 'USER' THEN v_grant.subject_id ELSE NULL END,
                v_grant.client_id, v_grant.tenant_id,
                'AUTHORIZATION_CODE_REPLAY', 'SYSTEM', NEW.id::text,
                clock_timestamp() + interval '400 days'
            );
        END IF;
    ELSIF NEW.authorization_code_state = OLD.authorization_code_state
       AND to_jsonb(NEW) IS NOT DISTINCT FROM to_jsonb(OLD) THEN
        RETURN NEW;
    ELSE
        RAISE EXCEPTION 'INVALID_STATE_TRANSITION: Authorization Code % -> %', OLD.authorization_code_state, NEW.authorization_code_state USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;
COMMENT ON FUNCTION oauth.fn_authorization_code_state_guard() IS 'Authorization Code 只能单次消费、到期或撤销；消费后重放会原子失陷 Token Family、撤销 Grant 并写撤销记录。';

CREATE OR REPLACE FUNCTION oauth.fn_reference_token_revoke_guard()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF OLD.revoked_at IS NOT NULL AND NEW.revoked_at IS DISTINCT FROM OLD.revoked_at THEN
        RAISE EXCEPTION 'REFERENCE_TOKEN_REVOCATION_IMMUTABLE' USING ERRCODE = '55000';
    ELSIF OLD.revoked_at IS NULL AND NEW.revoked_at IS NOT NULL THEN
        NEW.revoked_at := clock_timestamp();
    END IF;
    RETURN NEW;
END;
$$;
COMMENT ON FUNCTION oauth.fn_reference_token_revoke_guard() IS 'Reference Token 的 revoked_at 只能从 NULL 设置一次，设置后不可清除或改写。';

CREATE TRIGGER trg_authorization_code_context BEFORE INSERT ON oauth.authorization_code FOR EACH ROW
    EXECUTE FUNCTION oauth.fn_authorization_code_context_guard();
CREATE TRIGGER trg_token_family_context BEFORE INSERT ON oauth.token_family FOR EACH ROW
    EXECUTE FUNCTION oauth.fn_token_family_context_guard();
CREATE TRIGGER trg_session_state_guard BEFORE INSERT OR UPDATE ON oauth.user_session FOR EACH ROW
    EXECUTE FUNCTION oauth.fn_session_state_guard();
CREATE TRIGGER trg_token_family_state_guard BEFORE INSERT OR UPDATE ON oauth.token_family FOR EACH ROW
    EXECUTE FUNCTION oauth.fn_token_family_state_guard();
CREATE TRIGGER trg_refresh_token_guard BEFORE INSERT OR UPDATE OR DELETE ON oauth.refresh_token FOR EACH ROW
    EXECUTE FUNCTION oauth.fn_refresh_token_guard();
CREATE CONSTRAINT TRIGGER trg_refresh_token_successor
    AFTER INSERT OR UPDATE ON oauth.refresh_token
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION oauth.fn_refresh_token_successor_guard();
CREATE TRIGGER trg_reference_token_context BEFORE INSERT ON oauth.reference_access_token FOR EACH ROW
    EXECUTE FUNCTION oauth.fn_reference_token_context_guard();
CREATE TRIGGER trg_authorization_code_state BEFORE UPDATE ON oauth.authorization_code FOR EACH ROW
    EXECUTE FUNCTION oauth.fn_authorization_code_state_guard();

CREATE UNIQUE INDEX ux_user_session_login_transaction ON oauth.user_session(login_transaction_id);
CREATE UNIQUE INDEX ux_authorization_code_login_transaction ON oauth.authorization_code(login_transaction_id);
CREATE UNIQUE INDEX ux_token_family_active_grant ON oauth.token_family(grant_id)
    WHERE token_family_state = 'ACTIVE';

CREATE TRIGGER trg_session_identity_immutable BEFORE UPDATE OR DELETE ON oauth.user_session FOR EACH ROW
    EXECUTE FUNCTION core.fn_immutable_except('session_state', 'idle_expires_at', 'last_reauth_at', 'risk_level',
        'expired_at', 'compromised_at', 'compromise_reason_code', 'revoked_at', 'revoke_reason_code', 'updated_at', 'row_version');
CREATE TRIGGER trg_token_family_identity_immutable BEFORE UPDATE OR DELETE ON oauth.token_family FOR EACH ROW
    EXECUTE FUNCTION core.fn_immutable_except('token_family_state', 'generation_count', 'idle_expires_at', 'compromised_at', 'compromise_reason_code', 'revoked_at', 'revoke_reason_code', 'updated_at', 'row_version');
CREATE TRIGGER trg_authorization_code_identity_immutable BEFORE UPDATE OR DELETE ON oauth.authorization_code FOR EACH ROW
    EXECUTE FUNCTION core.fn_immutable_except('authorization_code_state', 'consumed_at', 'replay_detected_at', 'revoked_at');
CREATE TRIGGER trg_reference_token_identity_immutable BEFORE UPDATE OR DELETE ON oauth.reference_access_token FOR EACH ROW
    EXECUTE FUNCTION core.fn_immutable_except('revoked_at');
CREATE TRIGGER trg_reference_token_revoke BEFORE UPDATE ON oauth.reference_access_token FOR EACH ROW
    EXECUTE FUNCTION oauth.fn_reference_token_revoke_guard();
CREATE TRIGGER trg_session_terminal BEFORE UPDATE ON oauth.user_session FOR EACH ROW
    EXECUTE FUNCTION core.fn_terminal_state_guard('session_state', 'EXPIRED', 'COMPROMISED', 'REVOKED');
CREATE TRIGGER trg_token_family_terminal BEFORE UPDATE ON oauth.token_family FOR EACH ROW
    EXECUTE FUNCTION core.fn_terminal_state_guard('token_family_state', 'EXPIRED', 'COMPROMISED', 'REVOKED');
CREATE TRIGGER trg_authorization_code_terminal BEFORE UPDATE ON oauth.authorization_code FOR EACH ROW
    EXECUTE FUNCTION core.fn_terminal_state_guard('authorization_code_state', 'CONSUMED', 'EXPIRED', 'REVOKED');

-- -----------------------------------------------------------------------------
-- 6. 组织树、用户组与角色授予的范围一致性
-- -----------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION org.fn_organization_hierarchy_guard()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    v_parent org.organization%ROWTYPE;
BEGIN
    IF NEW.parent_id IS NULL THEN
        IF NEW.hierarchy_path <> NEW.organization_code THEN
            RAISE EXCEPTION 'ORGANIZATION_ROOT_PATH_INVALID' USING ERRCODE = '23514';
        END IF;
    ELSE
        SELECT * INTO v_parent FROM org.organization WHERE id = NEW.parent_id FOR SHARE;
        IF NOT FOUND OR v_parent.tenant_id <> NEW.tenant_id THEN
            RAISE EXCEPTION 'ORGANIZATION_PARENT_TENANT_MISMATCH' USING ERRCODE = '23514';
        END IF;
        IF NEW.hierarchy_path <> v_parent.hierarchy_path || '/' || NEW.organization_code THEN
            RAISE EXCEPTION 'ORGANIZATION_PATH_INVALID' USING ERRCODE = '23514';
        END IF;
        IF EXISTS (
            WITH RECURSIVE ancestors AS (
                SELECT o.id, o.parent_id FROM org.organization o WHERE o.id = NEW.parent_id
                UNION ALL
                SELECT o.id, o.parent_id FROM org.organization o JOIN ancestors a ON o.id = a.parent_id
            )
            SELECT 1 FROM ancestors WHERE id = NEW.id
        ) THEN
            RAISE EXCEPTION 'ORGANIZATION_CYCLE_DETECTED' USING ERRCODE = '23514';
        END IF;
    END IF;

    IF TG_OP = 'UPDATE'
       AND (NEW.tenant_id, NEW.parent_id, NEW.organization_code, NEW.hierarchy_path)
           IS DISTINCT FROM (OLD.tenant_id, OLD.parent_id, OLD.organization_code, OLD.hierarchy_path)
       AND EXISTS (SELECT 1 FROM org.organization c WHERE c.parent_id = OLD.id) THEN
        RAISE EXCEPTION 'ORGANIZATION_WITH_CHILDREN_REPARENT_FORBIDDEN' USING ERRCODE = '55000';
    END IF;
    RETURN NEW;
END;
$$;
COMMENT ON FUNCTION org.fn_organization_hierarchy_guard() IS '组织父子必须同租户，路径必须由父路径和本级代码确定，禁止循环及带子节点原地改父/改名。';

CREATE OR REPLACE FUNCTION org.fn_group_member_guard()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    v_group_tenant uuid;
    v_nested_tenant uuid;
BEGIN
    SELECT tenant_id INTO v_group_tenant FROM org.user_group WHERE id = NEW.group_id FOR SHARE;
    IF NOT FOUND THEN RAISE EXCEPTION 'GROUP_NOT_FOUND' USING ERRCODE = '23503'; END IF;
    IF NEW.nested_group_id IS NOT NULL THEN
        SELECT tenant_id INTO v_nested_tenant FROM org.user_group WHERE id = NEW.nested_group_id FOR SHARE;
        IF v_nested_tenant IS DISTINCT FROM v_group_tenant THEN
            RAISE EXCEPTION 'NESTED_GROUP_TENANT_MISMATCH' USING ERRCODE = '23514';
        END IF;
        IF EXISTS (
            WITH RECURSIVE descendants AS (
                SELECT gm.nested_group_id AS id
                  FROM org.group_member gm
                 WHERE gm.group_id = NEW.nested_group_id
                   AND gm.nested_group_id IS NOT NULL
                   AND gm.membership_state IN ('ACTIVE', 'SUSPENDED')
                UNION
                SELECT gm.nested_group_id
                  FROM org.group_member gm
                  JOIN descendants d ON gm.group_id = d.id
                 WHERE gm.nested_group_id IS NOT NULL
                   AND gm.membership_state IN ('ACTIVE', 'SUSPENDED')
            )
            SELECT 1 FROM descendants WHERE id = NEW.group_id
        ) THEN
            RAISE EXCEPTION 'GROUP_CYCLE_DETECTED' USING ERRCODE = '23514';
        END IF;
    END IF;
    RETURN NEW;
END;
$$;
COMMENT ON FUNCTION org.fn_group_member_guard() IS '用户组嵌套必须同租户，并在数据库内递归阻断直接或间接循环。';

CREATE OR REPLACE FUNCTION authz.fn_role_assignment_scope_guard()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    v_role authz.role%ROWTYPE;
    v_subject_valid boolean := false;
    v_is_activation boolean := TG_OP = 'INSERT';
BEGIN
    IF TG_OP = 'UPDATE' AND (
        NEW.role_id IS DISTINCT FROM OLD.role_id
        OR NEW.subject_kind IS DISTINCT FROM OLD.subject_kind
        OR NEW.subject_id IS DISTINCT FROM OLD.subject_id
        OR NEW.business_line_id IS DISTINCT FROM OLD.business_line_id
        OR NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
        OR NEW.organization_id IS DISTINCT FROM OLD.organization_id
        OR ((NEW.approval_case_id IS DISTINCT FROM OLD.approval_case_id
             OR NEW.approval_execution_id IS DISTINCT FROM OLD.approval_execution_id)
            AND NOT (OLD.assignment_state = 'SUSPENDED' AND NEW.assignment_state = 'SUSPENDED'))
        OR NEW.last_activation_execution_id IS DISTINCT FROM OLD.last_activation_execution_id
        OR NEW.granted_by_ref IS DISTINCT FROM OLD.granted_by_ref
        OR NEW.valid_from IS DISTINCT FROM OLD.valid_from
        OR NEW.valid_until IS DISTINCT FROM OLD.valid_until
    ) THEN
        RAISE EXCEPTION 'ROLE_ASSIGNMENT_IDENTITY_IMMUTABLE' USING ERRCODE = '55000';
    END IF;

    IF TG_OP = 'UPDATE' THEN
        v_is_activation := OLD.assignment_state <> 'ACTIVE' AND NEW.assignment_state = 'ACTIVE';
        IF NOT (
            NEW.assignment_state = OLD.assignment_state
            OR (OLD.assignment_state = 'ACTIVE' AND NEW.assignment_state IN ('SUSPENDED', 'REVOKED', 'EXPIRED'))
            OR (OLD.assignment_state = 'SUSPENDED' AND NEW.assignment_state IN ('ACTIVE', 'REVOKED', 'EXPIRED'))
        ) THEN
            RAISE EXCEPTION 'INVALID_STATE_TRANSITION: Role Assignment % -> %', OLD.assignment_state, NEW.assignment_state USING ERRCODE = '23514';
        END IF;
        IF NEW.assignment_state = 'REVOKED' AND OLD.assignment_state <> 'REVOKED' THEN
            IF NULLIF(btrim(NEW.revoke_reason_code), '') IS NULL THEN
                RAISE EXCEPTION 'ROLE_ASSIGNMENT_REVOKE_REASON_REQUIRED' USING ERRCODE = '23514';
            END IF;
            NEW.revoked_at := clock_timestamp();
        ELSIF NEW.assignment_state = 'EXPIRED' AND OLD.assignment_state <> 'EXPIRED'
           AND (NEW.valid_until IS NULL OR NEW.valid_until > clock_timestamp()) THEN
            RAISE EXCEPTION 'ROLE_ASSIGNMENT_NOT_EXPIRED' USING ERRCODE = '23514';
        ELSIF NEW.revoked_at IS DISTINCT FROM OLD.revoked_at THEN
            RAISE EXCEPTION 'ROLE_ASSIGNMENT_REVOCATION_EVIDENCE_IMMUTABLE' USING ERRCODE = '55000';
        END IF;
        IF NEW.revoke_reason_code IS DISTINCT FROM OLD.revoke_reason_code
           AND NOT (NEW.assignment_state = 'REVOKED' AND OLD.assignment_state <> 'REVOKED') THEN
            RAISE EXCEPTION 'ROLE_ASSIGNMENT_REVOKE_REASON_IMMUTABLE' USING ERRCODE = '55000';
        END IF;
    END IF;
    IF TG_OP = 'UPDATE' AND NEW.assignment_state <> 'ACTIVE' THEN
        RETURN NEW;
    END IF;

    IF NEW.assignment_state <> 'ACTIVE'
       OR NEW.valid_from > clock_timestamp()
       OR (NEW.valid_until IS NOT NULL AND NEW.valid_until <= clock_timestamp()) THEN
        RAISE EXCEPTION 'ROLE_ASSIGNMENT_ACTIVE_WINDOW_INVALID' USING ERRCODE = '23514';
    END IF;

    SELECT * INTO v_role FROM authz.role WHERE id = NEW.role_id FOR SHARE;
    IF NOT FOUND OR v_role.role_state <> 'ACTIVE' THEN
        RAISE EXCEPTION 'ROLE_NOT_ACTIVE' USING ERRCODE = '23514';
    END IF;
    IF (NEW.business_line_id, NEW.tenant_id, NEW.organization_id)
       IS DISTINCT FROM (v_role.business_line_id, v_role.tenant_id, v_role.organization_id) THEN
        RAISE EXCEPTION 'ROLE_ASSIGNMENT_SCOPE_MISMATCH' USING ERRCODE = '23514';
    END IF;

    IF NEW.subject_kind = 'USER' THEN
        IF v_role.scope_kind = 'PLATFORM' THEN
            SELECT EXISTS (SELECT 1 FROM iam.user_account u WHERE u.id = NEW.subject_id AND u.lifecycle_state = 'ACTIVE') INTO v_subject_valid;
        ELSE
            SELECT EXISTS (
                SELECT 1 FROM org.membership m
                 WHERE m.user_id = NEW.subject_id
                   AND m.membership_state = 'ACTIVE'
                   AND (NEW.business_line_id IS NULL OR m.business_line_id = NEW.business_line_id)
                   AND (NEW.tenant_id IS NULL OR m.tenant_id = NEW.tenant_id)
                   AND (NEW.organization_id IS NULL OR m.organization_id = NEW.organization_id)
            ) INTO v_subject_valid;
        END IF;
    ELSIF NEW.subject_kind = 'MEMBERSHIP' THEN
        SELECT EXISTS (
            SELECT 1 FROM org.membership m
             WHERE m.id = NEW.subject_id AND m.membership_state = 'ACTIVE'
               AND (NEW.business_line_id IS NULL OR m.business_line_id = NEW.business_line_id)
               AND (NEW.tenant_id IS NULL OR m.tenant_id = NEW.tenant_id)
               AND (NEW.organization_id IS NULL OR m.organization_id = NEW.organization_id)
        ) INTO v_subject_valid;
    ELSIF NEW.subject_kind = 'GROUP' THEN
        SELECT EXISTS (
            SELECT 1
              FROM org.user_group g
              JOIN org.tenant t ON t.id = g.tenant_id
             WHERE g.id = NEW.subject_id AND g.group_state = 'ACTIVE'
               AND (NEW.tenant_id IS NULL OR g.tenant_id = NEW.tenant_id)
               AND (NEW.business_line_id IS NULL OR t.business_line_id = NEW.business_line_id)
               AND (NEW.organization_id IS NULL OR g.organization_id = NEW.organization_id)
        ) INTO v_subject_valid;
    ELSIF NEW.subject_kind = 'CLIENT' THEN
        SELECT EXISTS (
            SELECT 1 FROM oauth.client c
             WHERE c.id = NEW.subject_id AND c.client_state = 'ACTIVE'
               AND (NEW.tenant_id IS NULL OR c.tenant_id = NEW.tenant_id)
               AND (NEW.business_line_id IS NULL OR c.business_line_id = NEW.business_line_id)
        ) INTO v_subject_valid;
    ELSIF NEW.subject_kind = 'MACHINE' THEN
        SELECT EXISTS (
            SELECT 1 FROM workload.machine_principal m
             WHERE m.id = NEW.subject_id AND m.principal_state = 'ACTIVE'
               AND m.expires_at > clock_timestamp()
               AND (NEW.tenant_id IS NULL OR m.tenant_id = NEW.tenant_id)
               AND (NEW.business_line_id IS NULL OR m.business_line_id = NEW.business_line_id)
        ) INTO v_subject_valid;
    END IF;
    IF NOT v_subject_valid THEN
        RAISE EXCEPTION 'ROLE_ASSIGNMENT_SUBJECT_SCOPE_MISMATCH' USING ERRCODE = '23514';
    END IF;

    IF v_role.privilege_tier = 'STANDARD' AND v_is_activation
       AND (NEW.approval_case_id IS NOT NULL OR NEW.approval_execution_id IS NOT NULL) THEN
        RAISE EXCEPTION 'STANDARD_ROLE_ASSIGNMENT_APPROVAL_NOT_EXPECTED' USING ERRCODE = '23514';
    END IF;

    IF v_role.privilege_tier <> 'STANDARD' AND v_is_activation AND NOT EXISTS (
        SELECT 1 FROM control.approval_case a
         WHERE a.id = NEW.approval_case_id
           AND a.approval_state = 'EXECUTED'
           AND a.approval_type = 'PRIVILEGED_ACCESS'
           AND a.resource_kind = 'ROLE_ASSIGNMENT'
           AND a.resource_ref = NEW.id::text
           AND a.execution_id = NEW.approval_execution_id
           AND a.valid_until > a.executed_at
           AND a.valid_until > clock_timestamp()
           AND a.tenant_id = COALESCE(NEW.tenant_id, '00000000-0000-0000-0000-000000000000'::uuid)
           AND a.after_value_hash = core.fn_hash_jsonb(jsonb_build_object(
               'role_id', NEW.role_id::text,
               'subject_kind', NEW.subject_kind,
               'subject_id', NEW.subject_id::text,
               'business_line_id', NEW.business_line_id::text,
               'tenant_id', NEW.tenant_id::text,
               'organization_id', NEW.organization_id::text,
               'granted_by_ref', NEW.granted_by_ref,
               'valid_from', NEW.valid_from,
               'valid_until', NEW.valid_until
           ))
    ) THEN
        RAISE EXCEPTION 'PRIVILEGED_ROLE_ASSIGNMENT_APPROVAL_REQUIRED' USING ERRCODE = '23514';
    END IF;

    IF v_role.privilege_tier <> 'STANDARD' AND v_is_activation THEN
        IF TG_OP = 'UPDATE' AND OLD.last_activation_execution_id = NEW.approval_execution_id THEN
            RAISE EXCEPTION 'APPROVAL_EXECUTION_ALREADY_APPLIED' USING ERRCODE = '23514';
        END IF;
        NEW.last_activation_execution_id := NEW.approval_execution_id;
    ELSIF v_role.privilege_tier = 'STANDARD' THEN
        NEW.last_activation_execution_id := NULL;
    END IF;

    RETURN NEW;
END;
$$;
COMMENT ON FUNCTION authz.fn_role_assignment_scope_guard() IS '角色作用域与授予范围必须完全一致，主体必须属于该范围，高权限角色必须绑定单次已执行审批，授予身份字段不可改写。';

CREATE TRIGGER trg_organization_hierarchy BEFORE INSERT OR UPDATE ON org.organization FOR EACH ROW
    EXECUTE FUNCTION org.fn_organization_hierarchy_guard();
CREATE TRIGGER trg_group_member_guard BEFORE INSERT OR UPDATE ON org.group_member FOR EACH ROW
    EXECUTE FUNCTION org.fn_group_member_guard();
CREATE TRIGGER trg_role_assignment_scope BEFORE INSERT OR UPDATE ON authz.role_assignment FOR EACH ROW
    EXECUTE FUNCTION authz.fn_role_assignment_scope_guard();
CREATE TRIGGER trg_role_assignment_terminal BEFORE UPDATE ON authz.role_assignment FOR EACH ROW
    EXECUTE FUNCTION core.fn_terminal_state_guard('assignment_state', 'REVOKED', 'EXPIRED');

-- 为所有直接 tenant_id 列补齐租户外键，避免后续新增表遗漏。
DO $$
DECLARE
    r record;
    v_name text;
BEGIN
    FOR r IN
        SELECT c.oid AS table_oid, c.oid::regclass AS table_name, a.attnum
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
           )
    LOOP
        v_name := 'fk_' || substr(replace(r.table_name::text, '.', '_'), 1, 43) || '_' || substr(md5(r.table_oid::text), 1, 8);
        EXECUTE format('ALTER TABLE %s ADD CONSTRAINT %I FOREIGN KEY (tenant_id) REFERENCES org.tenant(id)', r.table_name, v_name);
    END LOOP;
END;
$$;

-- 所有直接 business_line_id 统一引用业务线目录。
DO $$
DECLARE
    r record;
    v_name text;
BEGIN
    FOR r IN
        SELECT c.oid AS table_oid, c.oid::regclass AS table_name, a.attnum
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
           )
    LOOP
        v_name := 'fk_' || substr(replace(r.table_name::text, '.', '_'), 1, 39) || '_business_' || substr(md5(r.table_oid::text), 1, 8);
        EXECUTE format('ALTER TABLE %s ADD CONSTRAINT %I FOREIGN KEY (business_line_id) REFERENCES org.business_line(id)', r.table_name, v_name);
    END LOOP;
END;
$$;

-- 同时含 Tenant/Business Line 或 Tenant/Organization 的表必须使用复合外键证明范围一致。
DO $$
DECLARE
    r record;
    v_name text;
BEGIN
    FOR r IN
        SELECT c.oid AS table_oid, c.oid::regclass AS table_name,
               tenant_col.attnum AS tenant_attnum, business_col.attnum AS scope_attnum
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
           )
    LOOP
        v_name := 'fk_' || substr(replace(r.table_name::text, '.', '_'), 1, 37) || '_tenant_business_' || substr(md5(r.table_oid::text), 1, 8);
        EXECUTE format('ALTER TABLE %s ADD CONSTRAINT %I FOREIGN KEY (tenant_id, business_line_id) REFERENCES org.tenant(id, business_line_id)', r.table_name, v_name);
    END LOOP;

    FOR r IN
        SELECT c.oid AS table_oid, c.oid::regclass AS table_name,
               tenant_col.attnum AS tenant_attnum, organization_col.attnum AS scope_attnum
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
           )
    LOOP
        v_name := 'fk_' || substr(replace(r.table_name::text, '.', '_'), 1, 40) || '_org_scope_' || substr(md5(r.table_oid::text), 1, 8);
        EXECUTE format('ALTER TABLE %s ADD CONSTRAINT %I FOREIGN KEY (organization_id, tenant_id) REFERENCES org.organization(id, tenant_id)', r.table_name, v_name);
    END LOOP;
END;
$$;

-- -----------------------------------------------------------------------------
-- 7. 事件、投递与审计证据不可变性
-- -----------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION integration.fn_outbox_immutable_guard()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'OUTBOX_DELETE_FORBIDDEN' USING ERRCODE = '55000';
    END IF;
    IF NOT (
        NEW.publish_state = OLD.publish_state
        OR (OLD.publish_state = 'PENDING' AND NEW.publish_state IN ('PUBLISHING', 'DEAD_LETTER'))
        OR (OLD.publish_state = 'PUBLISHING' AND NEW.publish_state IN ('PUBLISHED', 'FAILED', 'DEAD_LETTER'))
        OR (OLD.publish_state = 'FAILED' AND NEW.publish_state IN ('PUBLISHING', 'DEAD_LETTER'))
    ) THEN
        RAISE EXCEPTION 'INVALID_STATE_TRANSITION: Outbox % -> %', OLD.publish_state, NEW.publish_state USING ERRCODE = '23514';
    END IF;
    IF OLD.publish_state = 'PUBLISHING' AND NEW.publish_state = 'PUBLISHED' THEN
        NEW.published_at := clock_timestamp();
    END IF;
    IF OLD.publish_state IN ('PUBLISHED', 'DEAD_LETTER') AND to_jsonb(NEW) IS DISTINCT FROM to_jsonb(OLD) THEN
        RAISE EXCEPTION 'OUTBOX_TERMINAL_EVIDENCE_IMMUTABLE' USING ERRCODE = '55000';
    END IF;
    IF (to_jsonb(NEW) - ARRAY['publish_state','attempt_count','next_attempt_at','published_at','broker_partition','broker_offset','last_error_code'])
       IS DISTINCT FROM
       (to_jsonb(OLD) - ARRAY['publish_state','attempt_count','next_attempt_at','published_at','broker_partition','broker_offset','last_error_code']) THEN
        RAISE EXCEPTION 'OUTBOX_EVENT_IMMUTABLE' USING ERRCODE = '55000';
    END IF;
    RETURN NEW;
END;
$$;
COMMENT ON FUNCTION integration.fn_outbox_immutable_guard() IS 'Outbox 只允许推进发布状态、重试和 Broker 回执；租户、Subject、Actor、追踪、正文、摘要和事件身份均不可改删。';

CREATE OR REPLACE FUNCTION integration.fn_webhook_delivery_immutable_guard()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN RAISE EXCEPTION 'WEBHOOK_DELIVERY_DELETE_FORBIDDEN' USING ERRCODE = '55000'; END IF;
    IF NOT (
        NEW.delivery_state = OLD.delivery_state
        OR (OLD.delivery_state = 'PENDING' AND NEW.delivery_state IN ('SENDING', 'CANCELLED', 'DEAD_LETTER'))
        OR (OLD.delivery_state = 'SENDING' AND NEW.delivery_state IN ('DELIVERED', 'FAILED', 'DEAD_LETTER'))
    ) THEN
        RAISE EXCEPTION 'INVALID_STATE_TRANSITION: Webhook Delivery % -> %', OLD.delivery_state, NEW.delivery_state USING ERRCODE = '23514';
    END IF;
    IF OLD.delivery_state = 'PENDING' AND NEW.delivery_state = 'SENDING' THEN
        NEW.first_attempt_at := clock_timestamp();
    ELSIF OLD.delivery_state = 'SENDING' AND NEW.delivery_state = 'DELIVERED' THEN
        NEW.delivered_at := clock_timestamp();
    ELSIF NEW.delivery_state = 'DEAD_LETTER' AND OLD.delivery_state <> 'DEAD_LETTER' THEN
        NEW.dead_lettered_at := clock_timestamp();
    END IF;
    IF OLD.delivery_state IN ('DELIVERED', 'FAILED', 'DEAD_LETTER', 'CANCELLED')
       AND to_jsonb(NEW) IS DISTINCT FROM to_jsonb(OLD) THEN
        RAISE EXCEPTION 'WEBHOOK_DELIVERY_TERMINAL_EVIDENCE_IMMUTABLE' USING ERRCODE = '55000';
    END IF;
    IF (to_jsonb(NEW) - ARRAY['delivery_state','response_status','response_body_hash','next_attempt_at','first_attempt_at','delivered_at','dead_lettered_at'])
       IS DISTINCT FROM
       (to_jsonb(OLD) - ARRAY['delivery_state','response_status','response_body_hash','next_attempt_at','first_attempt_at','delivered_at','dead_lettered_at']) THEN
        RAISE EXCEPTION 'WEBHOOK_DELIVERY_EVIDENCE_IMMUTABLE' USING ERRCODE = '55000';
    END IF;
    RETURN NEW;
END;
$$;
COMMENT ON FUNCTION integration.fn_webhook_delivery_immutable_guard() IS 'Webhook Delivery 只允许推进尝试、响应和终态元数据；订阅、事件、接收者、Payload 与签名证据不可修改或删除。';

CREATE OR REPLACE FUNCTION audit.fn_audit_outbox_immutable_guard()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN RAISE EXCEPTION 'AUDIT_OUTBOX_DELETE_FORBIDDEN' USING ERRCODE = '55000'; END IF;
    IF NOT (
        NEW.persistence_state = OLD.persistence_state
        OR (OLD.persistence_state = 'PERSISTED' AND NEW.persistence_state IN ('DELIVERING', 'FAILED'))
        OR (OLD.persistence_state = 'DELIVERING' AND NEW.persistence_state IN ('REMOTE_PERSISTED', 'FAILED'))
        OR (OLD.persistence_state = 'FAILED' AND NEW.persistence_state = 'DELIVERING')
    ) THEN
        RAISE EXCEPTION 'INVALID_STATE_TRANSITION: Audit Outbox % -> %', OLD.persistence_state, NEW.persistence_state USING ERRCODE = '23514';
    END IF;
    IF OLD.persistence_state = 'DELIVERING' AND NEW.persistence_state = 'REMOTE_PERSISTED' THEN
        NEW.remote_persisted_at := clock_timestamp();
    END IF;
    IF OLD.persistence_state = 'REMOTE_PERSISTED' AND to_jsonb(NEW) IS DISTINCT FROM to_jsonb(OLD) THEN
        RAISE EXCEPTION 'AUDIT_OUTBOX_TERMINAL_EVIDENCE_IMMUTABLE' USING ERRCODE = '55000';
    END IF;
    IF (to_jsonb(NEW) - ARRAY['persistence_state','remote_persisted_at'])
       IS DISTINCT FROM
       (to_jsonb(OLD) - ARRAY['persistence_state','remote_persisted_at']) THEN
        RAISE EXCEPTION 'AUDIT_OUTBOX_PAYLOAD_IMMUTABLE' USING ERRCODE = '55000';
    END IF;
    RETURN NEW;
END;
$$;
COMMENT ON FUNCTION audit.fn_audit_outbox_immutable_guard() IS '本地审计 Outbox 只允许单向推进远端持久化状态；事件身份、证据密文、摘要、密钥引用和创建时间不可改删。';

CREATE OR REPLACE FUNCTION messaging.fn_message_send_immutable_guard()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN RAISE EXCEPTION 'MESSAGE_SEND_DELETE_FORBIDDEN' USING ERRCODE = '55000'; END IF;
    IF NOT (
        NEW.send_state = OLD.send_state
        OR (OLD.send_state = 'PENDING' AND NEW.send_state IN ('SENDING', 'CANCELLED', 'EXPIRED'))
        OR (OLD.send_state = 'SENDING' AND NEW.send_state IN ('SENT', 'DELIVERED', 'FAILED', 'EXPIRED'))
        OR (OLD.send_state = 'SENT' AND NEW.send_state IN ('DELIVERED', 'FAILED'))
        OR (OLD.send_state = 'FAILED' AND NEW.send_state IN ('SENDING', 'CANCELLED', 'EXPIRED'))
    ) THEN
        RAISE EXCEPTION 'INVALID_STATE_TRANSITION: Message Send % -> %', OLD.send_state, NEW.send_state USING ERRCODE = '23514';
    END IF;
    IF OLD.send_state = 'FAILED' AND NEW.send_state = 'SENDING' THEN
        NEW.failed_at := NULL;
        NEW.failure_code := NULL;
    ELSIF NEW.send_state = 'SENT' AND OLD.send_state <> 'SENT' THEN
        NEW.sent_at := clock_timestamp();
    ELSIF NEW.send_state = 'DELIVERED' AND OLD.send_state <> 'DELIVERED' THEN
        NEW.sent_at := COALESCE(OLD.sent_at, clock_timestamp());
        NEW.delivered_at := clock_timestamp();
    ELSIF NEW.send_state = 'FAILED' AND OLD.send_state <> 'FAILED' THEN
        IF NULLIF(btrim(NEW.failure_code), '') IS NULL THEN
            RAISE EXCEPTION 'MESSAGE_FAILURE_CODE_REQUIRED' USING ERRCODE = '23514';
        END IF;
        NEW.failed_at := clock_timestamp();
    END IF;
    IF OLD.send_state IN ('DELIVERED', 'EXPIRED', 'CANCELLED')
       AND to_jsonb(NEW) IS DISTINCT FROM to_jsonb(OLD) THEN
        RAISE EXCEPTION 'MESSAGE_SEND_TERMINAL_EVIDENCE_IMMUTABLE' USING ERRCODE = '55000';
    END IF;
    IF (to_jsonb(NEW) - ARRAY['send_state','provider_id','provider_message_ref_hash','attempt_count','next_attempt_at','sent_at','delivered_at','failed_at','failure_code','updated_at','row_version'])
       IS DISTINCT FROM
       (to_jsonb(OLD) - ARRAY['send_state','provider_id','provider_message_ref_hash','attempt_count','next_attempt_at','sent_at','delivered_at','failed_at','failure_code','updated_at','row_version']) THEN
        RAISE EXCEPTION 'MESSAGE_SEND_CONTENT_IMMUTABLE' USING ERRCODE = '55000';
    END IF;
    RETURN NEW;
END;
$$;
COMMENT ON FUNCTION messaging.fn_message_send_immutable_guard() IS 'Message Send 只允许推进供应商、重试和发送结果；目标、模板、路由、变量摘要、租户和幂等身份不可修改或删除。';

CREATE OR REPLACE FUNCTION audit.fn_audit_chain_guard()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    v_previous bytea;
    v_sequence bigint;
BEGIN
    PERFORM pg_advisory_xact_lock(hashtextextended(NEW.chain_partition, 0));
    SELECT event_hash, chain_sequence
      INTO v_previous, v_sequence
      FROM audit.audit_event
     WHERE chain_partition = NEW.chain_partition
     ORDER BY chain_sequence DESC
     LIMIT 1;

    IF NOT FOUND THEN
        NEW.chain_sequence := 1;
        NEW.previous_event_hash := NULL;
    ELSE
        NEW.chain_sequence := v_sequence + 1;
        NEW.previous_event_hash := v_previous;
    END IF;
    NEW.event_hash := core.fn_hash_jsonb(to_jsonb(NEW) - 'event_hash');
    RETURN NEW;
END;
$$;
COMMENT ON FUNCTION audit.fn_audit_chain_guard() IS '按 chain_partition 使用事务级 advisory lock 串行分配序号和 previous hash，并由数据库重新计算完整事件摘要。';

CREATE TRIGGER trg_webhook_delivery_immutable BEFORE UPDATE OR DELETE ON integration.webhook_delivery FOR EACH ROW
    EXECUTE FUNCTION integration.fn_webhook_delivery_immutable_guard();
CREATE TRIGGER trg_zz_message_send_immutable BEFORE UPDATE OR DELETE ON messaging.message_send FOR EACH ROW
    EXECUTE FUNCTION messaging.fn_message_send_immutable_guard();

-- -----------------------------------------------------------------------------
-- 8. 为所有外键自动补齐前导列索引
-- -----------------------------------------------------------------------------

DO $$
DECLARE
    r record;
    v_index_name text;
BEGIN
    FOR r IN
        SELECT con.oid,
               con.conrelid::regclass AS table_name,
               n.nspname,
               c.relname,
               string_agg(quote_ident(a.attname), ', ' ORDER BY k.ordinality) AS column_list
          FROM pg_constraint con
          JOIN pg_class c ON c.oid = con.conrelid
          JOIN pg_namespace n ON n.oid = c.relnamespace
          JOIN unnest(con.conkey) WITH ORDINALITY AS k(attnum, ordinality) ON true
          JOIN pg_attribute a ON a.attrelid = con.conrelid AND a.attnum = k.attnum
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
           )
         GROUP BY con.oid, con.conrelid, n.nspname, c.relname
    LOOP
        v_index_name := 'ix_fk_' || substr(r.nspname || '_' || r.relname, 1, 42) || '_' || substr(md5(r.oid::text), 1, 8);
        EXECUTE format('CREATE INDEX %I ON %s (%s)', v_index_name, r.table_name, r.column_list);
    END LOOP;
END;
$$;

SELECT core.fn_apply_complete_column_comments();

SELECT core.fn_register_migration(
    '075',
    '跨领域审批、租户、上下文、不可变证据与外键索引加固',
    NULLIF(current_setting('kuc.migration_sha256', true), '')
);

COMMIT;
