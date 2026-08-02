-- =============================================================================
-- baseline/schemas/workload/links.sql
-- workload 源表拥有的最终跨 Schema 外键、绑定触发器、支撑索引及 COMMENT
-- PostgreSQL 16+；应用技术栈：.NET 10 + SqlSugar
-- =============================================================================

\set ON_ERROR_STOP on

SELECT (NOT EXISTS (SELECT 1 FROM core.schema_migration WHERE version = 'baseline:workload:links'))::text AS kuc_run_links \gset
\if :kuc_run_links
BEGIN;
SET LOCAL lock_timeout = '10s';
SET LOCAL statement_timeout = '5min';

ALTER TABLE workload.machine_principal
    ADD CONSTRAINT fk_machine_principal_tenant FOREIGN KEY (tenant_id) REFERENCES org.tenant(id),
    ADD CONSTRAINT fk_machine_principal_business_line FOREIGN KEY (business_line_id) REFERENCES org.business_line(id);

ALTER TABLE workload.token_exchange
    ADD CONSTRAINT fk_token_exchange_tenant FOREIGN KEY (tenant_id) REFERENCES org.tenant(id),
    ADD CONSTRAINT fk_token_exchange_delegation FOREIGN KEY (delegation_id) REFERENCES assurance.delegation(id);

ALTER TABLE workload.trust_bundle
    ADD CONSTRAINT fk_trust_bundle_approval FOREIGN KEY (approval_case_id) REFERENCES control.approval_case(id);

ALTER TABLE workload.machine_credential
    ADD CONSTRAINT fk_machine_credential_key FOREIGN KEY (key_asset_id) REFERENCES crypto.key_asset(id);

CREATE INDEX ix_fk_machine_principal_tenant_id ON workload.machine_principal (tenant_id);

CREATE INDEX ix_fk_token_exchange_tenant_id ON workload.token_exchange (tenant_id);

CREATE INDEX ix_fk_trust_bundle_approval_case_id ON workload.trust_bundle (approval_case_id);

CREATE INDEX ix_fk_token_exchange_delegation_id ON workload.token_exchange (delegation_id);

CREATE INDEX ix_fk_machine_credential_key_asset_id ON workload.machine_credential (key_asset_id);

COMMENT ON CONSTRAINT fk_machine_principal_tenant ON workload.machine_principal IS '外键约束：workload.machine_principal 的 tenant_id 必须引用 org.tenant；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT fk_token_exchange_tenant ON workload.token_exchange IS '外键约束：workload.token_exchange 的 tenant_id 必须引用 org.tenant；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT fk_machine_principal_business_line ON workload.machine_principal IS '外键约束：workload.machine_principal 的 business_line_id 必须引用 org.business_line；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT fk_trust_bundle_approval ON workload.trust_bundle IS '外键约束：workload.trust_bundle 的 approval_case_id 必须引用 control.approval_case；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT fk_token_exchange_delegation ON workload.token_exchange IS '外键约束：workload.token_exchange 的 delegation_id 必须引用 assurance.delegation；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT fk_machine_credential_key ON workload.machine_credential IS '外键约束：workload.machine_credential 的 key_asset_id 必须引用 crypto.key_asset；级联行为以约束定义为准。';

COMMENT ON INDEX workload.ix_fk_machine_principal_tenant_id IS '跨 Schema 外键前导索引：优化 workload.machine_principal 按 tenant_id 的关联与删除校验。';
COMMENT ON INDEX workload.ix_fk_token_exchange_tenant_id IS '跨 Schema 外键前导索引：优化 workload.token_exchange 按 tenant_id 的关联与删除校验。';
COMMENT ON INDEX workload.ix_fk_trust_bundle_approval_case_id IS '跨 Schema 外键前导索引：优化 workload.trust_bundle 按 approval_case_id 的关联与删除校验。';
COMMENT ON INDEX workload.ix_fk_token_exchange_delegation_id IS '跨 Schema 外键前导索引：优化 workload.token_exchange 按 delegation_id 的关联与删除校验。';
COMMENT ON INDEX workload.ix_fk_machine_credential_key_asset_id IS '跨 Schema 外键前导索引：优化 workload.machine_credential 按 key_asset_id 的关联与删除校验。';

SELECT core.fn_register_migration('baseline:workload:links', 'workload Schema 跨域约束与绑定');
COMMIT;
\endif

