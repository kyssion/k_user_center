\set ON_ERROR_STOP on

SET ROLE iam_owner;

-- 防御性撤销历史基线或人工授权遗留的整表 UPDATE，再按持久化可变字段重新授权。
-- 主键、公开稳定 ID、唯一业务键、创建/签发时间、请求/内容摘要、不可变载荷、updated_at 和 row_version 不得由运行角色直接改写。
-- updated_at 与 row_version 由 790_technical_time.sql 的纯技术 Trigger 统一维护。
REVOKE UPDATE ON ALL TABLES IN SCHEMA iam FROM
    iam_app_rw,
    iam_id_rw, iam_auth_rw, iam_plt_rw, iam_tenant_rw, iam_oap_rw,
    iam_session_rw, iam_profile_rw, iam_priv_rw, iam_authz_rw, iam_fed_rw,
    iam_risk_rw, iam_machine_rw, iam_ctrl_rw, iam_key_rw, iam_event_rw,
    iam_msg_rw, iam_mig_rw, iam_ops;

-- 公共技术持久化：请求身份与输入快照不可变，只推进处理结果、检查点和重试元数据。
GRANT UPDATE (operation_id, state, response_status, response_body, expires_at)
    ON iam.idempotency_records TO iam_app_rw;
GRANT UPDATE (state, current_step, irreversible_at, result_payload, error_code, expires_at, completed_at)
    ON iam.operations TO iam_app_rw;
GRANT UPDATE (state, attempt_count, checkpoint, output_digest, error_code, next_attempt_at, started_at, completed_at)
    ON iam.operation_steps TO iam_app_rw;
GRANT UPDATE (state, result_digest, error_code, processed_at)
    ON iam.inbox_messages TO iam_app_rw;

-- ID。
GRANT UPDATE (user_type, lifecycle_state, lifecycle_reason, authentication_lock_state, authentication_locked_until, security_freeze_state, security_frozen_at, guest_expires_at, user_security_epoch, state_changed_at)
    ON iam.global_users TO iam_id_rw;
GRANT UPDATE (retired_at, current_subject_slot)
    ON iam.user_subjects TO iam_id_rw;
GRANT UPDATE (value_ciphertext, value_fingerprint, encryption_algorithm, encryption_version, key_id, verification_state, verified_at)
    ON iam.identifiers TO iam_id_rw;
GRANT UPDATE (identifier_id, owner_user_id, claim_state, claimed_at, released_at, isolation_until)
    ON iam.identifier_claims TO iam_id_rw;
GRANT UPDATE (binding_state, reason_code, unbound_at)
    ON iam.identifier_bindings TO iam_id_rw;
GRANT UPDATE (state, assurance_level, unlinked_at, metadata)
    ON iam.user_identities TO iam_id_rw;
GRANT UPDATE (state, expires_at)
    ON iam.user_aliases TO iam_id_rw;

-- AUTH：认证结果证据只追加；凭证材料只允许 CAS 更新计数器和退役元数据。
GRANT UPDATE (state, display_name, last_used_at, replaced_by_id, state_reason, metadata)
    ON iam.authenticators TO iam_auth_rw;
GRANT UPDATE (usage_counter, retired_at)
    ON iam.credential_materials TO iam_auth_rw;
GRANT UPDATE (state, invalidated_at)
    ON iam.recovery_code_batches TO iam_auth_rw;
GRANT UPDATE (state, used_at)
    ON iam.recovery_codes TO iam_auth_rw;
GRANT UPDATE (state, attempt_count, consumed_at)
    ON iam.auth_challenges TO iam_auth_rw;
GRANT UPDATE (state, risk_snapshot, context, completed_at)
    ON iam.login_transactions TO iam_auth_rw;
GRANT UPDATE (state, evidence_digest, evidence, completed_at)
    ON iam.login_transaction_steps TO iam_auth_rw;

-- PLT / TENANT。
GRANT UPDATE (name, owner_type, owner_id, state, metadata)
    ON iam.applications TO iam_plt_rw;
GRANT UPDATE (limit_value, period_code, configuration_version_id, state, effective_at, expires_at)
    ON iam.resource_quotas TO iam_plt_rw;
GRANT UPDATE (name, owner_type, owner_id, state, active_configuration_id, state_changed_at)
    ON iam.business_lines TO iam_tenant_rw;
GRANT UPDATE (name, owner_type, owner_id, state, tenant_security_epoch, active_configuration_id)
    ON iam.tenants TO iam_tenant_rw;
GRANT UPDATE (purpose, verification_state, verification_token_hash, verified_at, state)
    ON iam.tenant_domains TO iam_tenant_rw;
GRANT UPDATE (parent_organization_id, name, external_mapping_digest, state, path_hint)
    ON iam.organizations TO iam_tenant_rw;
GRANT UPDATE (state, left_at, current_occupancy_slot, attributes)
    ON iam.memberships TO iam_tenant_rw;
GRANT UPDATE (role_upper_bound, state, expires_at, accepted_by_user_id, accepted_at)
    ON iam.invitations TO iam_tenant_rw;
GRANT UPDATE (organization_id, name, state, source_connector_id)
    ON iam.groups TO iam_tenant_rw;
GRANT UPDATE (removed_at)
    ON iam.group_members TO iam_tenant_rw;

-- OAP / Token。
GRANT UPDATE (owner_type, owner_id, state, client_security_epoch, active_configuration_id)
    ON iam.oauth_clients TO iam_oap_rw;
GRANT UPDATE (name, owner_type, owner_id, state, token_profile, active_configuration_id)
    ON iam.api_resources TO iam_oap_rw;
GRANT UPDATE (display_name, description, sensitivity, consent_required, state)
    ON iam.oauth_scopes TO iam_oap_rw;
GRANT UPDATE (scope_snapshot, consent_id, state, granted_at, expires_at, revoked_at, grant_version)
    ON iam.authorization_grants TO iam_oap_rw;
GRANT UPDATE (current_instance_id, state, family_version, reuse_detected_at, expires_at)
    ON iam.token_families TO iam_oap_rw;
GRANT UPDATE (state, consumed_at)
    ON iam.authorization_codes TO iam_oap_rw;
GRANT UPDATE (state, used_at, replaced_by_id)
    ON iam.refresh_token_instances TO iam_oap_rw;
GRANT UPDATE (revoked_at)
    ON iam.access_token_records TO iam_oap_rw;

-- SESSION。
GRANT UPDATE (lifecycle_state, trust_state, loss_state, display_name, last_seen_at, metadata)
    ON iam.devices TO iam_session_rw;
GRANT UPDATE (state, consent_id, consent_epoch, revocation_watermark, user_security_epoch, client_security_epoch, tenant_security_epoch, idle_expires_at, last_seen_at, revoked_at)
    ON iam.sessions TO iam_session_rw;
GRANT UPDATE (logout_state, last_logout_result, last_notified_at)
    ON iam.session_participants TO iam_session_rw;

-- PROFILE / PRIV。
GRANT UPDATE (display_name, avatar_uri, locale, timezone, primary_contact_identifier_id, profile_version)
    ON iam.user_profiles TO iam_profile_rw;
GRANT UPDATE (schema_version, document_version, payload, payload_digest)
    ON iam.profile_documents TO iam_profile_rw;
GRANT UPDATE (state, expires_at, revoked_at)
    ON iam.identity_assurance_assertions TO iam_profile_rw;
GRANT UPDATE (state, published_at, effective_at, retired_at)
    ON iam.agreement_versions TO iam_priv_rw;
GRANT UPDATE (consent_epoch, current_consent_id)
    ON iam.consent_aggregates TO iam_priv_rw;
GRANT UPDATE (state, identity_verification_id, deadline_at, result_summary, rejection_reason, completed_at)
    ON iam.privacy_requests TO iam_priv_rw;
GRANT UPDATE (state, expires_at, released_at)
    ON iam.legal_holds TO iam_priv_rw;
GRANT UPDATE (state, expires_at, downloaded_at)
    ON iam.data_export_artifacts TO iam_priv_rw;

-- AUTHZ：目录键与授权事实身份不可变，代码只维护展示、有效期和生命周期元数据。
GRANT UPDATE (sensitivity, description, state)
    ON iam.permissions TO iam_authz_rw;
GRANT UPDATE (display_name, description, state, role_version)
    ON iam.roles TO iam_authz_rw;
GRANT UPDATE (removed_at)
    ON iam.role_permissions TO iam_authz_rw;
GRANT UPDATE (reason_code, valid_until, state)
    ON iam.user_role_assignments TO iam_authz_rw;
GRANT UPDATE (valid_until, state)
    ON iam.group_role_assignments TO iam_authz_rw;
GRANT UPDATE (valid_until, state)
    ON iam.machine_role_assignments TO iam_authz_rw;
GRANT UPDATE (schema_version, definition, definition_digest, state)
    ON iam.data_scope_definitions TO iam_authz_rw;
GRANT UPDATE (priority, state, effective_at, expires_at)
    ON iam.policy_bindings TO iam_authz_rw;
GRANT UPDATE (valid_until, state)
    ON iam.relationship_tuples TO iam_authz_rw;
GRANT UPDATE (state, published_at)
    ON iam.policy_versions TO iam_authz_rw;

-- FED。
GRANT UPDATE (owner_type, owner_id, state, active_configuration_id, metadata_digest)
    ON iam.identity_providers TO iam_fed_rw;
GRANT UPDATE (owner_type, owner_id, state, active_configuration_id, last_success_at)
    ON iam.directory_connectors TO iam_fed_rw;
GRANT UPDATE (cursor_value_ciphertext, cursor_digest, source_version, tombstone_watermark, last_success_at)
    ON iam.directory_sync_cursors TO iam_fed_rw;
GRANT UPDATE (state, end_cursor_digest, read_count, created_count, updated_count, deleted_count, conflict_count, result_summary, started_at, completed_at)
    ON iam.directory_sync_batches TO iam_fed_rw;
GRANT UPDATE (platform_object_type, platform_object_id, source_version, mapping_state, last_seen_at, tombstoned_at)
    ON iam.directory_object_mappings TO iam_fed_rw;

-- RISK。
GRANT UPDATE (owner_type, owner_id, priority, state, result_code, summary, due_at, closed_at)
    ON iam.risk_cases TO iam_risk_rw;
GRANT UPDATE (state, expires_at)
    ON iam.security_signals TO iam_risk_rw;
GRANT UPDATE (state, expires_at)
    ON iam.restriction_entries TO iam_risk_rw;
GRANT UPDATE (state, expires_at)
    ON iam.risk_entity_links TO iam_risk_rw;

-- MACHINE / CTRL / KEY。
GRANT UPDATE (owner_type, owner_id, purpose, state, security_epoch, expires_at)
    ON iam.machine_principals TO iam_machine_rw;
GRANT UPDATE (state, last_used_at)
    ON iam.machine_credentials TO iam_machine_rw;
GRANT UPDATE (state, valid_until, reason_code)
    ON iam.delegations TO iam_machine_rw;
GRANT UPDATE (state, published_at)
    ON iam.workload_trust_bundle_versions TO iam_machine_rw;
GRANT UPDATE (state, expires_at, execution_id, executed_at)
    ON iam.approval_cases TO iam_ctrl_rw;
GRANT UPDATE (state, activated_at, rolled_back_at)
    ON iam.configuration_releases TO iam_ctrl_rw;
GRANT UPDATE (state, approved_by_case_id, published_at)
    ON iam.configuration_versions TO iam_ctrl_rw;
GRANT UPDATE (state, expires_at, closed_at)
    ON iam.security_exceptions TO iam_ctrl_rw;
GRANT UPDATE (state)
    ON iam.cryptographic_keys TO iam_key_rw;
GRANT UPDATE (state, revoked_at)
    ON iam.certificates TO iam_key_rw;
GRANT UPDATE (state, published_at, active_from, retired_at)
    ON iam.jwks_releases TO iam_key_rw;

-- EVENT / MSG。
GRANT UPDATE (approval_case_id, state, published_at)
    ON iam.event_schema_versions TO iam_event_rw;
GRANT UPDATE (endpoint_ciphertext, endpoint_host_hash, event_filter, state, active_configuration_id)
    ON iam.webhook_subscriptions TO iam_event_rw;
GRANT UPDATE (state, valid_until)
    ON iam.webhook_signing_keys TO iam_event_rw;
GRANT UPDATE (state, attempt_count, next_attempt_at, final_result, completed_at)
    ON iam.webhook_deliveries TO iam_event_rw;
GRANT UPDATE (state)
    ON iam.event_replay_requests TO iam_event_rw;
GRANT UPDATE (last_event_id, aggregate_version, security_watermark, checkpoint)
    ON iam.consumer_checkpoints TO iam_event_rw;
GRANT UPDATE (owner_type, owner_id, state, active_configuration_id, priority_hint)
    ON iam.message_providers TO iam_msg_rw;
GRANT UPDATE (approval_case_id, state, published_at)
    ON iam.message_template_versions TO iam_msg_rw;
GRANT UPDATE (state, priority, scheduled_at, expires_at, completed_at)
    ON iam.message_requests TO iam_msg_rw;
GRANT UPDATE (reachability_state, failure_type, consecutive_failure_count, last_success_at, last_failure_at, verified_at)
    ON iam.contact_reachability TO iam_msg_rw;
GRANT UPDATE (state, expires_at)
    ON iam.message_suppressions TO iam_msg_rw;

-- MIG。
GRANT UPDATE (name, owner_type, owner_id, authority_scope, state, retirement_at, active_configuration_id)
    ON iam.legacy_systems TO iam_mig_rw;
GRANT UPDATE (external_id_ciphertext, platform_type, platform_id, mapping_version, state, last_verified_at)
    ON iam.legacy_id_mappings TO iam_mig_rw;
GRANT UPDATE (state, source_checkpoint, total_count, success_count, conflict_count, failure_count, result_summary, started_at, completed_at)
    ON iam.migration_batches TO iam_mig_rw;
GRANT UPDATE (platform_object_type, platform_object_id, source_version, state, difference_summary, result_code, attempt_count, next_attempt_at)
    ON iam.migration_items TO iam_mig_rw;

-- OPS 只获得运行队列的最小列级推进能力，不可改写请求、事件或配置内容。
GRANT UPDATE (state, current_step, irreversible_at, result_payload, error_code, expires_at, completed_at)
    ON iam.operations TO iam_ops;
GRANT UPDATE (state, attempt_count, checkpoint, output_digest, error_code, next_attempt_at, started_at, completed_at)
    ON iam.operation_steps TO iam_ops;
GRANT UPDATE (publish_state, attempt_count, next_attempt_at, published_at)
    ON iam.outbox_events TO iam_ops;
GRANT UPDATE (state, result_digest, error_code, processed_at)
    ON iam.inbox_messages TO iam_ops;
GRANT UPDATE (cursor_value_ciphertext, cursor_digest, source_version, tombstone_watermark, last_success_at)
    ON iam.directory_sync_cursors TO iam_ops;
GRANT UPDATE (state, end_cursor_digest, read_count, created_count, updated_count, deleted_count, conflict_count, result_summary, started_at, completed_at)
    ON iam.directory_sync_batches TO iam_ops;
GRANT UPDATE (state, source_checkpoint, total_count, success_count, conflict_count, failure_count, result_summary, started_at, completed_at)
    ON iam.migration_batches TO iam_ops;
GRANT UPDATE (platform_object_type, platform_object_id, source_version, state, difference_summary, result_code, attempt_count, next_attempt_at)
    ON iam.migration_items TO iam_ops;
GRANT UPDATE (state, attempt_count, next_attempt_at, final_result, completed_at)
    ON iam.webhook_deliveries TO iam_ops;
GRANT UPDATE (state)
    ON iam.event_replay_requests TO iam_ops;
GRANT UPDATE (last_event_id, aggregate_version, security_watermark, checkpoint)
    ON iam.consumer_checkpoints TO iam_ops;
GRANT UPDATE (state, priority, scheduled_at, expires_at, completed_at)
    ON iam.message_requests TO iam_ops;
