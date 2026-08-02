-- =============================================================================
-- baseline/schemas/integration/links.sql
-- integration 源表拥有的最终跨 Schema 外键、绑定触发器、支撑索引及 COMMENT
-- PostgreSQL 16+；应用技术栈：.NET 10 + SqlSugar
-- =============================================================================

\set ON_ERROR_STOP on

SELECT (NOT EXISTS (SELECT 1 FROM core.schema_migration WHERE version = 'baseline:integration:links'))::text AS kuc_run_links \gset
\if :kuc_run_links
BEGIN;
SET LOCAL lock_timeout = '10s';
SET LOCAL statement_timeout = '5min';

ALTER TABLE integration.webhook_subscription
    ADD CONSTRAINT fk_webhook_client_scope FOREIGN KEY (client_id, tenant_id)
        REFERENCES oauth.client(id, tenant_id),
    ADD CONSTRAINT fk_webhook_subscription_client FOREIGN KEY (client_id) REFERENCES oauth.client(id),
    ADD CONSTRAINT fk_webhook_subscription_class FOREIGN KEY (maximum_classification) REFERENCES core.data_classification(classification_code),
    ADD CONSTRAINT fk_webhook_subscription_consent FOREIGN KEY (consent_aggregate_id) REFERENCES privacy.consent_aggregate(id);

ALTER TABLE integration.outbox_event
    ADD CONSTRAINT fk_outbox_event_tenant FOREIGN KEY (tenant_id) REFERENCES org.tenant(id);

ALTER TABLE integration.consumer_watermark
    ADD CONSTRAINT fk_consumer_watermark_tenant FOREIGN KEY (tenant_id) REFERENCES org.tenant(id);

ALTER TABLE integration.event_schema
    ADD CONSTRAINT fk_event_schema_class FOREIGN KEY (maximum_classification) REFERENCES core.data_classification(classification_code),
    ADD CONSTRAINT fk_event_schema_release FOREIGN KEY (release_id) REFERENCES control.config_release(id);

ALTER TABLE integration.event_replay_request
    ADD CONSTRAINT fk_event_replay_operation FOREIGN KEY (operation_id) REFERENCES core.async_operation(id),
    ADD CONSTRAINT fk_event_replay_approval FOREIGN KEY (approval_case_id) REFERENCES control.approval_case(id);

CREATE INDEX ix_fk_webhook_subscription_client_id_tenant_id ON integration.webhook_subscription (client_id, tenant_id);

CREATE INDEX ix_fk_outbox_event_tenant_id ON integration.outbox_event (tenant_id);

CREATE INDEX ix_fk_consumer_watermark_tenant_id ON integration.consumer_watermark (tenant_id);

CREATE INDEX ix_fk_event_schema_maximum_classification ON integration.event_schema (maximum_classification);

CREATE INDEX ix_fk_event_schema_release_id ON integration.event_schema (release_id);

CREATE INDEX ix_fk_webhook_subscription_maximum_classification ON integration.webhook_subscription (maximum_classification);

CREATE INDEX ix_fk_webhook_subscription_consent_aggregate_id ON integration.webhook_subscription (consent_aggregate_id);

CREATE INDEX ix_fk_event_replay_request_approval_case_id ON integration.event_replay_request (approval_case_id);

COMMENT ON CONSTRAINT fk_webhook_client_scope ON integration.webhook_subscription IS '外键约束：integration.webhook_subscription 的 client_id、tenant_id 必须引用 oauth.client；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT fk_outbox_event_tenant ON integration.outbox_event IS '外键约束：integration.outbox_event 的 tenant_id 必须引用 org.tenant；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT fk_consumer_watermark_tenant ON integration.consumer_watermark IS '外键约束：integration.consumer_watermark 的 tenant_id 必须引用 org.tenant；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT fk_event_schema_class ON integration.event_schema IS '外键约束：integration.event_schema 的 maximum_classification 必须引用 core.data_classification；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT fk_event_schema_release ON integration.event_schema IS '外键约束：integration.event_schema 的 release_id 必须引用 control.config_release；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT fk_webhook_subscription_client ON integration.webhook_subscription IS '外键约束：integration.webhook_subscription 的 client_id 必须引用 oauth.client；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT fk_webhook_subscription_class ON integration.webhook_subscription IS '外键约束：integration.webhook_subscription 的 maximum_classification 必须引用 core.data_classification；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT fk_webhook_subscription_consent ON integration.webhook_subscription IS '外键约束：integration.webhook_subscription 的 consent_aggregate_id 必须引用 privacy.consent_aggregate；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT fk_event_replay_operation ON integration.event_replay_request IS '外键约束：integration.event_replay_request 的 operation_id 必须引用 core.async_operation；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT fk_event_replay_approval ON integration.event_replay_request IS '外键约束：integration.event_replay_request 的 approval_case_id 必须引用 control.approval_case；级联行为以约束定义为准。';

COMMENT ON INDEX integration.ix_fk_webhook_subscription_client_id_tenant_id IS '跨 Schema 外键前导索引：优化 integration.webhook_subscription 按 client_id、tenant_id 的关联与删除校验。';
COMMENT ON INDEX integration.ix_fk_outbox_event_tenant_id IS '跨 Schema 外键前导索引：优化 integration.outbox_event 按 tenant_id 的关联与删除校验。';
COMMENT ON INDEX integration.ix_fk_consumer_watermark_tenant_id IS '跨 Schema 外键前导索引：优化 integration.consumer_watermark 按 tenant_id 的关联与删除校验。';
COMMENT ON INDEX integration.ix_fk_event_schema_maximum_classification IS '跨 Schema 外键前导索引：优化 integration.event_schema 按 maximum_classification 的关联与删除校验。';
COMMENT ON INDEX integration.ix_fk_event_schema_release_id IS '跨 Schema 外键前导索引：优化 integration.event_schema 按 release_id 的关联与删除校验。';
COMMENT ON INDEX integration.ix_fk_webhook_subscription_maximum_classification IS '跨 Schema 外键前导索引：优化 integration.webhook_subscription 按 maximum_classification 的关联与删除校验。';
COMMENT ON INDEX integration.ix_fk_webhook_subscription_consent_aggregate_id IS '跨 Schema 外键前导索引：优化 integration.webhook_subscription 按 consent_aggregate_id 的关联与删除校验。';
COMMENT ON INDEX integration.ix_fk_event_replay_request_approval_case_id IS '跨 Schema 外键前导索引：优化 integration.event_replay_request 按 approval_case_id 的关联与删除校验。';

SELECT core.fn_register_migration('baseline:integration:links', 'integration Schema 跨域约束与绑定');
COMMIT;
\endif

