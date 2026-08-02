-- =============================================================================
-- baseline/schemas/messaging/links.sql
-- messaging 源表拥有的最终跨 Schema 外键、绑定触发器、支撑索引及 COMMENT
-- PostgreSQL 16+；应用技术栈：.NET 10 + SqlSugar
-- =============================================================================

\set ON_ERROR_STOP on

SELECT (NOT EXISTS (SELECT 1 FROM core.schema_migration WHERE version = 'baseline:messaging:links'))::text AS kuc_run_links \gset
\if :kuc_run_links
BEGIN;
SET LOCAL lock_timeout = '10s';
SET LOCAL statement_timeout = '5min';

ALTER TABLE messaging.message_send
    ADD CONSTRAINT fk_message_client_scope FOREIGN KEY (client_id, tenant_id)
        REFERENCES oauth.client(id, tenant_id),
    ADD CONSTRAINT fk_message_send_tenant FOREIGN KEY (tenant_id) REFERENCES org.tenant(id),
    ADD CONSTRAINT fk_message_send_identifier FOREIGN KEY (target_identifier_id) REFERENCES iam.identifier(id),
    ADD CONSTRAINT fk_message_send_user FOREIGN KEY (user_id) REFERENCES iam.user_account(id),
    ADD CONSTRAINT fk_message_send_client FOREIGN KEY (client_id) REFERENCES oauth.client(id),
    ADD CONSTRAINT fk_message_send_challenge FOREIGN KEY (challenge_id) REFERENCES authn.verification_challenge(id);

ALTER TABLE messaging.message_template
    ADD CONSTRAINT fk_message_template_release FOREIGN KEY (release_id) REFERENCES control.config_release(id);

ALTER TABLE messaging.reachability
    ADD CONSTRAINT fk_reachability_identifier FOREIGN KEY (identifier_id) REFERENCES iam.identifier(id);

ALTER TABLE messaging.content_compliance_rule
    ADD CONSTRAINT fk_content_compliance_rule_release FOREIGN KEY (release_id) REFERENCES control.config_release(id);

CREATE INDEX ix_fk_message_send_client_id_tenant_id ON messaging.message_send (client_id, tenant_id);

CREATE INDEX ix_fk_message_send_tenant_id ON messaging.message_send (tenant_id);

CREATE INDEX ix_fk_message_template_release_id ON messaging.message_template (release_id);

CREATE INDEX ix_fk_message_send_target_identifier_id ON messaging.message_send (target_identifier_id);

CREATE INDEX ix_fk_message_send_user_id ON messaging.message_send (user_id);

CREATE INDEX ix_fk_message_send_challenge_id ON messaging.message_send (challenge_id);

CREATE INDEX ix_fk_content_compliance_rule_release_id ON messaging.content_compliance_rule (release_id);

COMMENT ON CONSTRAINT fk_message_client_scope ON messaging.message_send IS '外键约束：messaging.message_send 的 client_id、tenant_id 必须引用 oauth.client；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT fk_message_send_tenant ON messaging.message_send IS '外键约束：messaging.message_send 的 tenant_id 必须引用 org.tenant；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT fk_message_template_release ON messaging.message_template IS '外键约束：messaging.message_template 的 release_id 必须引用 control.config_release；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT fk_message_send_identifier ON messaging.message_send IS '外键约束：messaging.message_send 的 target_identifier_id 必须引用 iam.identifier；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT fk_message_send_user ON messaging.message_send IS '外键约束：messaging.message_send 的 user_id 必须引用 iam.user_account；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT fk_message_send_client ON messaging.message_send IS '外键约束：messaging.message_send 的 client_id 必须引用 oauth.client；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT fk_message_send_challenge ON messaging.message_send IS '外键约束：messaging.message_send 的 challenge_id 必须引用 authn.verification_challenge；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT fk_reachability_identifier ON messaging.reachability IS '外键约束：messaging.reachability 的 identifier_id 必须引用 iam.identifier；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT fk_content_compliance_rule_release ON messaging.content_compliance_rule IS '外键约束：messaging.content_compliance_rule 的 release_id 必须引用 control.config_release；级联行为以约束定义为准。';

COMMENT ON INDEX messaging.ix_fk_message_send_client_id_tenant_id IS '跨 Schema 外键前导索引：优化 messaging.message_send 按 client_id、tenant_id 的关联与删除校验。';
COMMENT ON INDEX messaging.ix_fk_message_send_tenant_id IS '跨 Schema 外键前导索引：优化 messaging.message_send 按 tenant_id 的关联与删除校验。';
COMMENT ON INDEX messaging.ix_fk_message_template_release_id IS '跨 Schema 外键前导索引：优化 messaging.message_template 按 release_id 的关联与删除校验。';
COMMENT ON INDEX messaging.ix_fk_message_send_target_identifier_id IS '跨 Schema 外键前导索引：优化 messaging.message_send 按 target_identifier_id 的关联与删除校验。';
COMMENT ON INDEX messaging.ix_fk_message_send_user_id IS '跨 Schema 外键前导索引：优化 messaging.message_send 按 user_id 的关联与删除校验。';
COMMENT ON INDEX messaging.ix_fk_message_send_challenge_id IS '跨 Schema 外键前导索引：优化 messaging.message_send 按 challenge_id 的关联与删除校验。';
COMMENT ON INDEX messaging.ix_fk_content_compliance_rule_release_id IS '跨 Schema 外键前导索引：优化 messaging.content_compliance_rule 按 release_id 的关联与删除校验。';

SELECT core.fn_register_migration('baseline:messaging:links', 'messaging Schema 跨域约束与绑定');
COMMIT;
\endif

