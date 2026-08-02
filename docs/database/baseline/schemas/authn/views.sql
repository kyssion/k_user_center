-- =============================================================================
-- baseline/schemas/authn/views.sql
-- authn Schema 的视图及内联 COMMENT
-- PostgreSQL 16+；应用技术栈：.NET 10 + SqlSugar
-- =============================================================================

CREATE VIEW authn.device_authorization_status AS
SELECT d.*,
       CASE
           WHEN d.consumed_at IS NOT NULL THEN 'CONSUMED'
           WHEN d.denied_at IS NOT NULL THEN 'ACCESS_DENIED'
           WHEN d.expires_at <= clock_timestamp() THEN 'EXPIRED_TOKEN'
           WHEN d.approved_at IS NOT NULL THEN 'AUTHORIZED'
           ELSE 'AUTHORIZATION_PENDING'
       END AS derived_status
  FROM authn.device_authorization d;

COMMENT ON VIEW authn.device_authorization_status IS 'RFC 8628 派生状态视图；源表用不可互斥时间证据避免额外未登记状态机。';

COMMENT ON COLUMN authn.device_authorization_status.id IS 'authn.device_authorization_status.id 的只读投影列；语义继承来源对象及本视图定义。';

COMMENT ON COLUMN authn.device_authorization_status.client_id IS 'authn.device_authorization_status.client_id 的只读投影列；语义继承来源对象及本视图定义。';

COMMENT ON COLUMN authn.device_authorization_status.tenant_id IS 'authn.device_authorization_status.tenant_id 的只读投影列；语义继承来源对象及本视图定义。';

COMMENT ON COLUMN authn.device_authorization_status.device_code_hash IS 'authn.device_authorization_status.device_code_hash 的只读投影列；语义继承来源对象及本视图定义。';

COMMENT ON COLUMN authn.device_authorization_status.user_code_hash IS 'authn.device_authorization_status.user_code_hash 的只读投影列；语义继承来源对象及本视图定义。';

COMMENT ON COLUMN authn.device_authorization_status.requested_scopes IS 'authn.device_authorization_status.requested_scopes 的只读投影列；语义继承来源对象及本视图定义。';

COMMENT ON COLUMN authn.device_authorization_status.requested_resources IS 'authn.device_authorization_status.requested_resources 的只读投影列；语义继承来源对象及本视图定义。';

COMMENT ON COLUMN authn.device_authorization_status.authorization_details IS 'authn.device_authorization_status.authorization_details 的只读投影列；语义继承来源对象及本视图定义。';

COMMENT ON COLUMN authn.device_authorization_status.polling_interval_seconds IS 'authn.device_authorization_status.polling_interval_seconds 的只读投影列；语义继承来源对象及本视图定义。';

COMMENT ON COLUMN authn.device_authorization_status.poll_count IS 'authn.device_authorization_status.poll_count 的只读投影列；语义继承来源对象及本视图定义。';

COMMENT ON COLUMN authn.device_authorization_status.slow_down_count IS 'authn.device_authorization_status.slow_down_count 的只读投影列；语义继承来源对象及本视图定义。';

COMMENT ON COLUMN authn.device_authorization_status.last_polled_at IS 'authn.device_authorization_status.last_polled_at 的只读投影列；语义继承来源对象及本视图定义。';

COMMENT ON COLUMN authn.device_authorization_status.authorized_user_id IS 'authn.device_authorization_status.authorized_user_id 的只读投影列；语义继承来源对象及本视图定义。';

COMMENT ON COLUMN authn.device_authorization_status.login_transaction_id IS 'authn.device_authorization_status.login_transaction_id 的只读投影列；语义继承来源对象及本视图定义。';

COMMENT ON COLUMN authn.device_authorization_status.grant_id IS 'authn.device_authorization_status.grant_id 的只读投影列；语义继承来源对象及本视图定义。';

COMMENT ON COLUMN authn.device_authorization_status.approved_at IS 'authn.device_authorization_status.approved_at 的只读投影列；语义继承来源对象及本视图定义。';

COMMENT ON COLUMN authn.device_authorization_status.denied_at IS 'authn.device_authorization_status.denied_at 的只读投影列；语义继承来源对象及本视图定义。';

COMMENT ON COLUMN authn.device_authorization_status.consumed_at IS 'authn.device_authorization_status.consumed_at 的只读投影列；语义继承来源对象及本视图定义。';

COMMENT ON COLUMN authn.device_authorization_status.expires_at IS 'authn.device_authorization_status.expires_at 的只读投影列；语义继承来源对象及本视图定义。';

COMMENT ON COLUMN authn.device_authorization_status.created_at IS 'authn.device_authorization_status.created_at 的只读投影列；语义继承来源对象及本视图定义。';

COMMENT ON COLUMN authn.device_authorization_status.updated_at IS 'authn.device_authorization_status.updated_at 的只读投影列；语义继承来源对象及本视图定义。';

COMMENT ON COLUMN authn.device_authorization_status.row_version IS 'authn.device_authorization_status.row_version 的只读投影列；语义继承来源对象及本视图定义。';

COMMENT ON COLUMN authn.device_authorization_status.derived_status IS '依据消费、拒绝、过期与批准时间证据计算的 RFC 8628 派生状态。';

