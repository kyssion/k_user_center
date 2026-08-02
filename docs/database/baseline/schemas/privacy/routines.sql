-- =============================================================================
-- baseline/schemas/privacy/routines.sql
-- privacy Schema 的最终函数、过程、局部触发器及内联 COMMENT
-- PostgreSQL 16+；应用技术栈：.NET 10 + SqlSugar
-- =============================================================================

CREATE TRIGGER trg_consent_aggregate_public_id BEFORE INSERT ON privacy.consent_aggregate FOR EACH ROW EXECUTE FUNCTION core.fn_register_public_id('CONSENT_AGGREGATE');

CREATE TRIGGER trg_consent_aggregate_touch BEFORE UPDATE ON privacy.consent_aggregate FOR EACH ROW EXECUTE FUNCTION core.fn_touch_updated_at();

CREATE TRIGGER trg_consent_aggregate_version BEFORE UPDATE ON privacy.consent_aggregate FOR EACH ROW EXECUTE FUNCTION core.fn_increment_row_version();

CREATE TRIGGER trg_consent_public_id BEFORE INSERT ON privacy.consent FOR EACH ROW EXECUTE FUNCTION core.fn_register_public_id('CONSENT');

CREATE TRIGGER trg_consent_touch BEFORE UPDATE ON privacy.consent FOR EACH ROW EXECUTE FUNCTION core.fn_touch_updated_at();

CREATE TRIGGER trg_consent_version BEFORE UPDATE ON privacy.consent FOR EACH ROW EXECUTE FUNCTION core.fn_increment_row_version();

CREATE TRIGGER trg_subscription_touch BEFORE UPDATE ON privacy.marketing_subscription FOR EACH ROW EXECUTE FUNCTION core.fn_touch_updated_at();

CREATE TRIGGER trg_subscription_version BEFORE UPDATE ON privacy.marketing_subscription FOR EACH ROW EXECUTE FUNCTION core.fn_increment_row_version();

CREATE TRIGGER trg_privacy_request_public_id BEFORE INSERT ON privacy.privacy_request FOR EACH ROW EXECUTE FUNCTION core.fn_register_public_id('PRIVACY_REQUEST');

CREATE TRIGGER trg_privacy_request_touch BEFORE UPDATE ON privacy.privacy_request FOR EACH ROW EXECUTE FUNCTION core.fn_touch_updated_at();

CREATE TRIGGER trg_privacy_request_version BEFORE UPDATE ON privacy.privacy_request FOR EACH ROW EXECUTE FUNCTION core.fn_increment_row_version();

CREATE TRIGGER trg_privacy_request_terminal BEFORE UPDATE ON privacy.privacy_request FOR EACH ROW EXECUTE FUNCTION core.fn_terminal_state_guard('request_state', 'COMPLETED', 'REJECTED');

CREATE TRIGGER trg_privacy_task_touch BEFORE UPDATE ON privacy.privacy_request_task FOR EACH ROW EXECUTE FUNCTION core.fn_touch_updated_at();

CREATE TRIGGER trg_legal_hold_public_id BEFORE INSERT ON privacy.legal_hold FOR EACH ROW EXECUTE FUNCTION core.fn_register_public_id('LEGAL_HOLD');

CREATE TRIGGER trg_legal_hold_terminal BEFORE UPDATE ON privacy.legal_hold FOR EACH ROW EXECUTE FUNCTION core.fn_terminal_state_guard('hold_state', 'RELEASED', 'EXPIRED');

CREATE TRIGGER trg_export_job_touch BEFORE UPDATE ON privacy.export_job FOR EACH ROW EXECUTE FUNCTION core.fn_touch_updated_at();

CREATE TRIGGER trg_deletion_proof_append_only BEFORE UPDATE OR DELETE ON privacy.deletion_proof FOR EACH STATEMENT EXECUTE FUNCTION core.fn_append_only();

CREATE TRIGGER trg_cross_border_public_id BEFORE INSERT ON privacy.cross_border_authorization FOR EACH ROW EXECUTE FUNCTION core.fn_register_public_id('CROSS_BORDER_AUTHORIZATION');

CREATE TRIGGER trg_cross_border_touch BEFORE UPDATE ON privacy.cross_border_authorization FOR EACH ROW EXECUTE FUNCTION core.fn_touch_updated_at();

CREATE TRIGGER trg_cross_border_version BEFORE UPDATE ON privacy.cross_border_authorization FOR EACH ROW EXECUTE FUNCTION core.fn_increment_row_version();

CREATE TRIGGER trg_minor_protection_touch BEFORE UPDATE ON privacy.minor_protection FOR EACH ROW EXECUTE FUNCTION core.fn_touch_updated_at();

CREATE TRIGGER trg_minor_protection_version BEFORE UPDATE ON privacy.minor_protection FOR EACH ROW EXECUTE FUNCTION core.fn_increment_row_version();

CREATE TRIGGER trg_pia_public_id BEFORE INSERT ON privacy.privacy_impact_assessment FOR EACH ROW EXECUTE FUNCTION core.fn_register_public_id('PRIVACY_IMPACT_ASSESSMENT');

CREATE TRIGGER trg_purpose_immutable BEFORE UPDATE OR DELETE ON privacy.purpose FOR EACH ROW
    EXECUTE FUNCTION core.fn_immutable_except('retired_at');

CREATE TRIGGER trg_agreement_immutable BEFORE UPDATE OR DELETE ON privacy.agreement FOR EACH ROW
    EXECUTE FUNCTION core.fn_immutable_except('retired_at');

CREATE TRIGGER trg_consent_terminal BEFORE UPDATE ON privacy.consent FOR EACH ROW
    EXECUTE FUNCTION core.fn_terminal_state_guard('consent_state', 'DENIED', 'WITHDRAWN', 'EXPIRED', 'SUPERSEDED');

CREATE TRIGGER trg_consent_aggregate_epoch BEFORE UPDATE ON privacy.consent_aggregate FOR EACH ROW
    EXECUTE FUNCTION core.fn_forbid_epoch_decrease('current_epoch');

COMMENT ON TRIGGER trg_consent_aggregate_public_id ON privacy.consent_aggregate IS '触发器：调用 core.fn_register_public_id 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_consent_aggregate_touch ON privacy.consent_aggregate IS '触发器：调用 core.fn_touch_updated_at 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_consent_aggregate_version ON privacy.consent_aggregate IS '触发器：调用 core.fn_increment_row_version 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_consent_public_id ON privacy.consent IS '触发器：调用 core.fn_register_public_id 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_consent_touch ON privacy.consent IS '触发器：调用 core.fn_touch_updated_at 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_consent_version ON privacy.consent IS '触发器：调用 core.fn_increment_row_version 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_subscription_touch ON privacy.marketing_subscription IS '触发器：调用 core.fn_touch_updated_at 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_subscription_version ON privacy.marketing_subscription IS '触发器：调用 core.fn_increment_row_version 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_privacy_request_public_id ON privacy.privacy_request IS '触发器：调用 core.fn_register_public_id 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_privacy_request_touch ON privacy.privacy_request IS '触发器：调用 core.fn_touch_updated_at 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_privacy_request_version ON privacy.privacy_request IS '触发器：调用 core.fn_increment_row_version 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_privacy_request_terminal ON privacy.privacy_request IS '触发器：调用 core.fn_terminal_state_guard 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_privacy_task_touch ON privacy.privacy_request_task IS '触发器：调用 core.fn_touch_updated_at 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_legal_hold_public_id ON privacy.legal_hold IS '触发器：调用 core.fn_register_public_id 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_legal_hold_terminal ON privacy.legal_hold IS '触发器：调用 core.fn_terminal_state_guard 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_export_job_touch ON privacy.export_job IS '触发器：调用 core.fn_touch_updated_at 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_deletion_proof_append_only ON privacy.deletion_proof IS '触发器：调用 core.fn_append_only 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_cross_border_public_id ON privacy.cross_border_authorization IS '触发器：调用 core.fn_register_public_id 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_cross_border_touch ON privacy.cross_border_authorization IS '触发器：调用 core.fn_touch_updated_at 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_cross_border_version ON privacy.cross_border_authorization IS '触发器：调用 core.fn_increment_row_version 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_minor_protection_touch ON privacy.minor_protection IS '触发器：调用 core.fn_touch_updated_at 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_minor_protection_version ON privacy.minor_protection IS '触发器：调用 core.fn_increment_row_version 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_pia_public_id ON privacy.privacy_impact_assessment IS '触发器：调用 core.fn_register_public_id 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_purpose_immutable ON privacy.purpose IS '触发器：调用 core.fn_immutable_except 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_agreement_immutable ON privacy.agreement IS '触发器：调用 core.fn_immutable_except 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_consent_terminal ON privacy.consent IS '触发器：调用 core.fn_terminal_state_guard 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_consent_aggregate_epoch ON privacy.consent_aggregate IS '触发器：调用 core.fn_forbid_epoch_decrease 维护数据库结构完整性、不可变证据或关键原子安全底线。';

