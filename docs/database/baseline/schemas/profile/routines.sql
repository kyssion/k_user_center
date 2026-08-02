-- =============================================================================
-- baseline/schemas/profile/routines.sql
-- profile Schema 的最终函数、过程、局部触发器及内联 COMMENT
-- PostgreSQL 16+；应用技术栈：.NET 10 + SqlSugar
-- =============================================================================

CREATE TRIGGER trg_profile_user_touch BEFORE UPDATE ON profile.user_profile FOR EACH ROW EXECUTE FUNCTION core.fn_touch_updated_at();

CREATE TRIGGER trg_profile_user_version BEFORE UPDATE ON profile.user_profile FOR EACH ROW EXECUTE FUNCTION core.fn_increment_row_version();

CREATE TRIGGER trg_sensitive_attribute_touch BEFORE UPDATE ON profile.sensitive_attribute FOR EACH ROW EXECUTE FUNCTION core.fn_touch_updated_at();

CREATE TRIGGER trg_sensitive_attribute_version BEFORE UPDATE ON profile.sensitive_attribute FOR EACH ROW EXECUTE FUNCTION core.fn_increment_row_version();

CREATE TRIGGER trg_business_profile_touch BEFORE UPDATE ON profile.business_profile FOR EACH ROW EXECUTE FUNCTION core.fn_touch_updated_at();

CREATE TRIGGER trg_business_profile_version BEFORE UPDATE ON profile.business_profile FOR EACH ROW EXECUTE FUNCTION core.fn_increment_row_version();

CREATE TRIGGER trg_profile_change_append_only BEFORE UPDATE OR DELETE ON profile.profile_change FOR EACH STATEMENT EXECUTE FUNCTION core.fn_append_only();

CREATE TRIGGER trg_user_preference_touch BEFORE UPDATE ON profile.user_preference FOR EACH ROW EXECUTE FUNCTION core.fn_touch_updated_at();

CREATE TRIGGER trg_user_preference_version BEFORE UPDATE ON profile.user_preference FOR EACH ROW EXECUTE FUNCTION core.fn_increment_row_version();

CREATE TRIGGER trg_notification_preference_touch BEFORE UPDATE ON profile.notification_preference FOR EACH ROW EXECUTE FUNCTION core.fn_touch_updated_at();

CREATE TRIGGER trg_notification_preference_version BEFORE UPDATE ON profile.notification_preference FOR EACH ROW EXECUTE FUNCTION core.fn_increment_row_version();

COMMENT ON TRIGGER trg_profile_user_touch ON profile.user_profile IS '触发器：调用 core.fn_touch_updated_at 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_profile_user_version ON profile.user_profile IS '触发器：调用 core.fn_increment_row_version 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_sensitive_attribute_touch ON profile.sensitive_attribute IS '触发器：调用 core.fn_touch_updated_at 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_sensitive_attribute_version ON profile.sensitive_attribute IS '触发器：调用 core.fn_increment_row_version 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_business_profile_touch ON profile.business_profile IS '触发器：调用 core.fn_touch_updated_at 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_business_profile_version ON profile.business_profile IS '触发器：调用 core.fn_increment_row_version 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_profile_change_append_only ON profile.profile_change IS '触发器：调用 core.fn_append_only 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_user_preference_touch ON profile.user_preference IS '触发器：调用 core.fn_touch_updated_at 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_user_preference_version ON profile.user_preference IS '触发器：调用 core.fn_increment_row_version 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_notification_preference_touch ON profile.notification_preference IS '触发器：调用 core.fn_touch_updated_at 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_notification_preference_version ON profile.notification_preference IS '触发器：调用 core.fn_increment_row_version 维护数据库结构完整性、不可变证据或关键原子安全底线。';

