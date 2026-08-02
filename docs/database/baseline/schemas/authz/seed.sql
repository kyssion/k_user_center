-- =============================================================================
-- baseline/schemas/authz/seed.sql
-- authz Schema 的幂等基线种子
-- PostgreSQL 16+；应用技术栈：.NET 10 + SqlSugar
-- =============================================================================

\set ON_ERROR_STOP on

SELECT (NOT EXISTS (SELECT 1 FROM core.schema_migration WHERE version = 'baseline:authz:seed'))::text AS kuc_run_seed \gset
\if :kuc_run_seed
BEGIN;
SET LOCAL lock_timeout = '10s';
SET LOCAL statement_timeout = '10min';

INSERT INTO authz.obligation_type(obligation_code, schema_version, display_name, parameter_schema, execution_point, is_mandatory) VALUES
('STEP_UP', 1, '提升认证保证等级', '{"type":"object","required":["required_aal","max_auth_age_seconds"]}', 'BEFORE_COMMIT', true),
('MASK_FIELDS', 1, '字段脱敏', '{"type":"object","required":["field_codes","masking_profile"]}', 'RESPONSE_TRANSFORM', true),
('ROW_FILTER', 1, '行级过滤', '{"type":"object","required":["filter_expression"]}', 'QUERY_FILTER', true),
('WATERMARK', 1, '导出水印', '{"type":"object","required":["watermark_text"]}', 'RESPONSE_TRANSFORM', true),
('ADDITIONAL_AUDIT', 1, '附加审计', '{"type":"object","required":["audit_type"]}', 'AFTER_COMMIT', true)
ON CONFLICT (obligation_code, schema_version) DO UPDATE SET display_name = EXCLUDED.display_name, parameter_schema = EXCLUDED.parameter_schema, execution_point = EXCLUDED.execution_point, is_mandatory = EXCLUDED.is_mandatory;

INSERT INTO authz.permission(permission_code, resource_type, action_code, risk_tier, required_profile_code, description) VALUES
('identity.user.read', 'USER', 'READ', 'NORMAL', 'SP1', '读取最小用户主档'),
('identity.user.freeze', 'USER', 'FREEZE', 'CRITICAL', 'SP3', '全局冻结用户'),
('identity.user.merge', 'USER', 'MERGE', 'CRITICAL', 'SP3', '执行账号合并'),
('identity.user.delete', 'USER', 'DELETE', 'CRITICAL', 'SP2', '发起或执行账号删除'),
('tenant.membership.manage', 'MEMBERSHIP', 'MANAGE', 'HIGH', 'SP2', '管理租户 Membership'),
('tenant.invitation.create', 'INVITATION', 'CREATE', 'HIGH', 'SP2', '创建租户邀请'),
('tenant.invitation.accept', 'INVITATION', 'ACCEPT', 'HIGH', 'SP2', '接受租户邀请并创建或激活成员关系'),
('authz.policy.publish', 'POLICY', 'PUBLISH', 'CRITICAL', 'SP3', '发布授权策略'),
('control.approval.decide', 'APPROVAL_CASE', 'DECIDE', 'CRITICAL', 'SP3', '审批高风险变更'),
('crypto.key.rotate', 'KEY', 'ROTATE', 'CRITICAL', 'SP3', '轮换密钥'),
('audit.event.query', 'AUDIT', 'QUERY', 'HIGH', 'SP3', '查询审计事件'),
('privacy.request.process', 'PRIVACY_REQUEST', 'PROCESS', 'HIGH', 'SP2', '处理个人权利请求'),
('integration.event.replay', 'EVENT', 'REPLAY', 'CRITICAL', 'SP3', '审批并执行事件回放')
ON CONFLICT (permission_code) DO UPDATE SET resource_type = EXCLUDED.resource_type, action_code = EXCLUDED.action_code, risk_tier = EXCLUDED.risk_tier, required_profile_code = EXCLUDED.required_profile_code, description = EXCLUDED.description;

SELECT core.fn_register_migration('baseline:authz:seed', 'authz Schema 基线种子');
COMMIT;
\endif

