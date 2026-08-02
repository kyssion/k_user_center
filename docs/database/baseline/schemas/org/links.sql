-- =============================================================================
-- baseline/schemas/org/links.sql
-- org 源表拥有的最终跨 Schema 外键、绑定触发器、支撑索引及 COMMENT
-- PostgreSQL 16+；应用技术栈：.NET 10 + SqlSugar
-- =============================================================================

\set ON_ERROR_STOP on

SELECT (NOT EXISTS (SELECT 1 FROM core.schema_migration WHERE version = 'baseline:org:links'))::text AS kuc_run_links \gset
\if :kuc_run_links
BEGIN;
SET LOCAL lock_timeout = '10s';
SET LOCAL statement_timeout = '5min';

ALTER TABLE org.invitation
    ADD CONSTRAINT fk_invitation_creation_decision FOREIGN KEY (creation_authorization_decision_id) REFERENCES authz.authorization_decision(id),
    ADD CONSTRAINT fk_invitation_acceptance_decision FOREIGN KEY (acceptance_authorization_decision_id) REFERENCES authz.authorization_decision(id),
    ADD CONSTRAINT fk_invitation_user FOREIGN KEY (accepted_by_user_id) REFERENCES iam.user_account(id);

ALTER TABLE org.tenant
    ADD CONSTRAINT fk_tenant_close_operation FOREIGN KEY (close_operation_id) REFERENCES core.async_operation(id);

ALTER TABLE org.membership
    ADD CONSTRAINT fk_membership_user FOREIGN KEY (user_id) REFERENCES iam.user_account(id);

ALTER TABLE org.group_member
    ADD CONSTRAINT fk_group_member_user FOREIGN KEY (user_id) REFERENCES iam.user_account(id);

CREATE INDEX ix_fk_invitation_creation_authorization_decision_id ON org.invitation (creation_authorization_decision_id);

CREATE INDEX ix_fk_invitation_acceptance_authorization_decision_id ON org.invitation (acceptance_authorization_decision_id);

CREATE INDEX ix_fk_tenant_close_operation_id ON org.tenant (close_operation_id);

CREATE INDEX ix_fk_membership_user_id ON org.membership (user_id);

CREATE INDEX ix_fk_invitation_accepted_by_user_id ON org.invitation (accepted_by_user_id);

CREATE INDEX ix_fk_group_member_user_id ON org.group_member (user_id);

COMMENT ON CONSTRAINT fk_invitation_creation_decision ON org.invitation IS '外键约束：org.invitation 的 creation_authorization_decision_id 必须引用 authz.authorization_decision；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT fk_invitation_acceptance_decision ON org.invitation IS '外键约束：org.invitation 的 acceptance_authorization_decision_id 必须引用 authz.authorization_decision；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT fk_tenant_close_operation ON org.tenant IS '外键约束：org.tenant 的 close_operation_id 必须引用 core.async_operation；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT fk_membership_user ON org.membership IS '外键约束：org.membership 的 user_id 必须引用 iam.user_account；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT fk_invitation_user ON org.invitation IS '外键约束：org.invitation 的 accepted_by_user_id 必须引用 iam.user_account；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT fk_group_member_user ON org.group_member IS '外键约束：org.group_member 的 user_id 必须引用 iam.user_account；级联行为以约束定义为准。';

COMMENT ON INDEX org.ix_fk_invitation_creation_authorization_decision_id IS '跨 Schema 外键前导索引：优化 org.invitation 按 creation_authorization_decision_id 的关联与删除校验。';
COMMENT ON INDEX org.ix_fk_invitation_acceptance_authorization_decision_id IS '跨 Schema 外键前导索引：优化 org.invitation 按 acceptance_authorization_decision_id 的关联与删除校验。';
COMMENT ON INDEX org.ix_fk_tenant_close_operation_id IS '跨 Schema 外键前导索引：优化 org.tenant 按 close_operation_id 的关联与删除校验。';
COMMENT ON INDEX org.ix_fk_membership_user_id IS '跨 Schema 外键前导索引：优化 org.membership 按 user_id 的关联与删除校验。';
COMMENT ON INDEX org.ix_fk_invitation_accepted_by_user_id IS '跨 Schema 外键前导索引：优化 org.invitation 按 accepted_by_user_id 的关联与删除校验。';
COMMENT ON INDEX org.ix_fk_group_member_user_id IS '跨 Schema 外键前导索引：优化 org.group_member 按 user_id 的关联与删除校验。';

SELECT core.fn_register_migration('baseline:org:links', 'org Schema 跨域约束与绑定');
COMMIT;
\endif

