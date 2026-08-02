-- =============================================================================
-- baseline/schemas/profile/links.sql
-- profile 源表拥有的最终跨 Schema 外键、绑定触发器、支撑索引及 COMMENT
-- PostgreSQL 16+；应用技术栈：.NET 10 + SqlSugar
-- =============================================================================

\set ON_ERROR_STOP on

SELECT (NOT EXISTS (SELECT 1 FROM core.schema_migration WHERE version = 'baseline:profile:links'))::text AS kuc_run_links \gset
\if :kuc_run_links
BEGIN;
SET LOCAL lock_timeout = '10s';
SET LOCAL statement_timeout = '5min';

ALTER TABLE profile.field_definition
    ADD CONSTRAINT fk_field_definition_class FOREIGN KEY (classification_code) REFERENCES core.data_classification(classification_code);

ALTER TABLE profile.user_profile
    ADD CONSTRAINT fk_user_profile_user FOREIGN KEY (user_id) REFERENCES iam.user_account(id);

ALTER TABLE profile.sensitive_attribute
    ADD CONSTRAINT fk_sensitive_attribute_user FOREIGN KEY (user_id) REFERENCES iam.user_account(id);

ALTER TABLE profile.business_profile
    ADD CONSTRAINT fk_business_profile_membership FOREIGN KEY (membership_id) REFERENCES org.membership(id);

ALTER TABLE profile.profile_change
    ADD CONSTRAINT fk_profile_change_user FOREIGN KEY (user_id) REFERENCES iam.user_account(id),
    ADD CONSTRAINT fk_profile_change_membership FOREIGN KEY (membership_id) REFERENCES org.membership(id);

ALTER TABLE profile.user_preference
    ADD CONSTRAINT fk_user_preference_user FOREIGN KEY (user_id) REFERENCES iam.user_account(id);

ALTER TABLE profile.notification_preference
    ADD CONSTRAINT fk_notification_preference_user FOREIGN KEY (user_id) REFERENCES iam.user_account(id),
    ADD CONSTRAINT fk_notification_preference_consent FOREIGN KEY (consent_id) REFERENCES privacy.consent(id);

CREATE INDEX ix_fk_field_definition_classification_code ON profile.field_definition (classification_code);

CREATE INDEX ix_fk_profile_change_user_id ON profile.profile_change (user_id);

CREATE INDEX ix_fk_profile_change_membership_id ON profile.profile_change (membership_id);

CREATE INDEX ix_fk_notification_preference_consent_id ON profile.notification_preference (consent_id);

COMMENT ON CONSTRAINT fk_field_definition_class ON profile.field_definition IS '外键约束：profile.field_definition 的 classification_code 必须引用 core.data_classification；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT fk_user_profile_user ON profile.user_profile IS '外键约束：profile.user_profile 的 user_id 必须引用 iam.user_account；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT fk_sensitive_attribute_user ON profile.sensitive_attribute IS '外键约束：profile.sensitive_attribute 的 user_id 必须引用 iam.user_account；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT fk_business_profile_membership ON profile.business_profile IS '外键约束：profile.business_profile 的 membership_id 必须引用 org.membership；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT fk_profile_change_user ON profile.profile_change IS '外键约束：profile.profile_change 的 user_id 必须引用 iam.user_account；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT fk_profile_change_membership ON profile.profile_change IS '外键约束：profile.profile_change 的 membership_id 必须引用 org.membership；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT fk_user_preference_user ON profile.user_preference IS '外键约束：profile.user_preference 的 user_id 必须引用 iam.user_account；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT fk_notification_preference_user ON profile.notification_preference IS '外键约束：profile.notification_preference 的 user_id 必须引用 iam.user_account；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT fk_notification_preference_consent ON profile.notification_preference IS '外键约束：profile.notification_preference 的 consent_id 必须引用 privacy.consent；级联行为以约束定义为准。';

COMMENT ON INDEX profile.ix_fk_field_definition_classification_code IS '跨 Schema 外键前导索引：优化 profile.field_definition 按 classification_code 的关联与删除校验。';
COMMENT ON INDEX profile.ix_fk_profile_change_user_id IS '跨 Schema 外键前导索引：优化 profile.profile_change 按 user_id 的关联与删除校验。';
COMMENT ON INDEX profile.ix_fk_profile_change_membership_id IS '跨 Schema 外键前导索引：优化 profile.profile_change 按 membership_id 的关联与删除校验。';
COMMENT ON INDEX profile.ix_fk_notification_preference_consent_id IS '跨 Schema 外键前导索引：优化 profile.notification_preference 按 consent_id 的关联与删除校验。';

SELECT core.fn_register_migration('baseline:profile:links', 'profile Schema 跨域约束与绑定');
COMMIT;
\endif

