-- =============================================================================
-- baseline/schemas/risk/links.sql
-- risk 源表拥有的最终跨 Schema 外键、绑定触发器、支撑索引及 COMMENT
-- PostgreSQL 16+；应用技术栈：.NET 10 + SqlSugar
-- =============================================================================

\set ON_ERROR_STOP on

SELECT (NOT EXISTS (SELECT 1 FROM core.schema_migration WHERE version = 'baseline:risk:links'))::text AS kuc_run_links \gset
\if :kuc_run_links
BEGIN;
SET LOCAL lock_timeout = '10s';
SET LOCAL statement_timeout = '5min';

ALTER TABLE risk.risk_signal
    ADD CONSTRAINT fk_risk_signal_tenant FOREIGN KEY (tenant_id) REFERENCES org.tenant(id);

ALTER TABLE risk.risk_assessment
    ADD CONSTRAINT fk_risk_assessment_tenant FOREIGN KEY (tenant_id) REFERENCES org.tenant(id);

ALTER TABLE risk.risk_policy_release
    ADD CONSTRAINT fk_risk_policy_release_approval FOREIGN KEY (approval_case_id) REFERENCES control.approval_case(id);

ALTER TABLE risk.security_case
    ADD CONSTRAINT fk_security_case_hold FOREIGN KEY (evidence_hold_id) REFERENCES privacy.legal_hold(id);

CREATE TRIGGER trg_risk_policy_release_guard BEFORE UPDATE ON risk.risk_policy_release FOR EACH ROW
    EXECUTE FUNCTION control.fn_release_guard('policy_state', 'rollout_percentage', 'emergency_disabled',
        'activated_at', 'retired_at', 'revoked_at', 'approval_case_id', 'approval_execution_id');

CREATE TRIGGER trg_risk_policy_release_binding_immutable BEFORE UPDATE ON risk.risk_policy_release FOR EACH ROW
    EXECUTE FUNCTION control.fn_active_approval_binding_guard('policy_state', 'ACTIVE', 'approval_case_id', 'approval_execution_id');

CREATE INDEX ix_fk_risk_signal_tenant_id ON risk.risk_signal (tenant_id);

CREATE INDEX ix_fk_risk_assessment_tenant_id ON risk.risk_assessment (tenant_id);

CREATE INDEX ix_fk_risk_policy_release_approval_case_id ON risk.risk_policy_release (approval_case_id);

CREATE INDEX ix_fk_security_case_evidence_hold_id ON risk.security_case (evidence_hold_id);

COMMENT ON CONSTRAINT fk_risk_signal_tenant ON risk.risk_signal IS '外键约束：risk.risk_signal 的 tenant_id 必须引用 org.tenant；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT fk_risk_assessment_tenant ON risk.risk_assessment IS '外键约束：risk.risk_assessment 的 tenant_id 必须引用 org.tenant；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT fk_risk_policy_release_approval ON risk.risk_policy_release IS '外键约束：risk.risk_policy_release 的 approval_case_id 必须引用 control.approval_case；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT fk_security_case_hold ON risk.security_case IS '外键约束：risk.security_case 的 evidence_hold_id 必须引用 privacy.legal_hold；级联行为以约束定义为准。';

COMMENT ON INDEX risk.ix_fk_risk_signal_tenant_id IS '跨 Schema 外键前导索引：优化 risk.risk_signal 按 tenant_id 的关联与删除校验。';
COMMENT ON INDEX risk.ix_fk_risk_assessment_tenant_id IS '跨 Schema 外键前导索引：优化 risk.risk_assessment 按 tenant_id 的关联与删除校验。';
COMMENT ON INDEX risk.ix_fk_risk_policy_release_approval_case_id IS '跨 Schema 外键前导索引：优化 risk.risk_policy_release 按 approval_case_id 的关联与删除校验。';
COMMENT ON INDEX risk.ix_fk_security_case_evidence_hold_id IS '跨 Schema 外键前导索引：优化 risk.security_case 按 evidence_hold_id 的关联与删除校验。';

COMMENT ON TRIGGER trg_risk_policy_release_guard ON risk.risk_policy_release IS '跨 Schema 触发器：调用 control.fn_release_guard 保护发布、审批或安全绑定底线。';

COMMENT ON TRIGGER trg_risk_policy_release_binding_immutable ON risk.risk_policy_release IS '跨 Schema 触发器：调用 control.fn_active_approval_binding_guard 保护发布、审批或安全绑定底线。';

SELECT core.fn_register_migration('baseline:risk:links', 'risk Schema 跨域约束与绑定');
COMMIT;
\endif

