-- =============================================================================
-- baseline/schemas/oauth/routines.sql
-- oauth Schema 的最终函数、过程、局部触发器及内联 COMMENT
-- PostgreSQL 16+；应用技术栈：.NET 10 + SqlSugar
-- =============================================================================

CREATE OR REPLACE FUNCTION oauth.fn_client_state_guard()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF OLD.client_state = 'RETIRED' AND NEW.client_state <> 'RETIRED' THEN
        RAISE EXCEPTION 'INVALID_STATE_TRANSITION: RETIRED Client 不得恢复' USING ERRCODE = '23514';
    END IF;
    IF OLD.client_state = 'COMPROMISED' AND NEW.client_state NOT IN ('COMPROMISED', 'RETIRED') THEN
        RAISE EXCEPTION 'INVALID_STATE_TRANSITION: COMPROMISED Client 只能转为 RETIRED' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION oauth.fn_device_loss_guard()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.device_loss_state = 'LOST' AND OLD.device_loss_state <> 'LOST' THEN
        NEW.device_trust_state := 'UNTRUSTED';
        NEW.lost_at := clock_timestamp();
        NEW.loss_cleared_at := NULL;
        UPDATE oauth.user_session
           SET session_state = 'REVOKED', revoked_at = clock_timestamp(), revoke_reason_code = 'DEVICE_LOST'
         WHERE device_id = NEW.id AND session_state IN ('ACTIVE', 'COMPROMISED');
        UPDATE oauth.token_family
           SET token_family_state = 'REVOKED', revoked_at = clock_timestamp(), revoke_reason_code = 'DEVICE_LOST'
         WHERE device_id = NEW.id AND token_family_state = 'ACTIVE';
        INSERT INTO oauth.revocation_record(
            revocation_kind, target_ref, user_id, reason_code, source_kind, source_ref, prunable_after
        ) VALUES (
            'DEVICE', NEW.public_id, NEW.user_id, 'DEVICE_LOST', 'SYSTEM', NEW.public_id,
            clock_timestamp() + interval '400 days'
        );
    END IF;
    IF OLD.device_loss_state = 'LOST' AND NEW.device_loss_state = 'CLEAR' THEN
        NEW.device_trust_state := 'UNTRUSTED';
        NEW.loss_cleared_at := clock_timestamp();
    ELSIF OLD.device_loss_state = NEW.device_loss_state
       AND (NEW.lost_at IS DISTINCT FROM OLD.lost_at
            OR NEW.loss_cleared_at IS DISTINCT FROM OLD.loss_cleared_at) THEN
        RAISE EXCEPTION 'DEVICE_LOSS_EVIDENCE_IMMUTABLE' USING ERRCODE = '55000';
    END IF;

    RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION oauth.fn_refresh_token_guard()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    v_family oauth.token_family%ROWTYPE;
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'REFRESH_TOKEN_DELETE_FORBIDDEN' USING ERRCODE = '55000';
    END IF;
    IF TG_OP = 'INSERT' THEN
        SELECT * INTO v_family FROM oauth.token_family WHERE id = NEW.family_id FOR UPDATE;
        IF NOT FOUND OR v_family.token_family_state <> 'ACTIVE'
           OR NEW.expires_at <= clock_timestamp()
           OR NEW.expires_at > v_family.absolute_expires_at
           OR NEW.refresh_token_instance_state <> 'CURRENT'
           OR NEW.used_at IS NOT NULL OR NEW.successor_id IS NOT NULL
           OR NEW.retry_window_until IS NOT NULL OR NEW.revoked_at IS NOT NULL THEN
            RAISE EXCEPTION 'REFRESH_TOKEN_INITIAL_CONTEXT_INVALID' USING ERRCODE = '23514';
        END IF;
        NEW.generation := v_family.generation_count + 1;
        NEW.issued_at := clock_timestamp();
        UPDATE oauth.token_family
           SET generation_count = NEW.generation
         WHERE id = NEW.family_id;
        RETURN NEW;
    END IF;

    IF NEW.family_id IS DISTINCT FROM OLD.family_id
       OR NEW.generation IS DISTINCT FROM OLD.generation
       OR NEW.token_hash IS DISTINCT FROM OLD.token_hash
       OR NEW.issued_at IS DISTINCT FROM OLD.issued_at
       OR NEW.expires_at IS DISTINCT FROM OLD.expires_at
       OR NEW.binding_context_hash IS DISTINCT FROM OLD.binding_context_hash THEN
        RAISE EXCEPTION 'REFRESH_TOKEN_IDENTITY_IMMUTABLE' USING ERRCODE = '55000';
    END IF;

    IF OLD.refresh_token_instance_state = 'CURRENT' AND NEW.refresh_token_instance_state = 'USED' THEN
        IF NEW.successor_id IS NULL THEN
            RAISE EXCEPTION 'REFRESH_TOKEN_SUCCESSOR_REQUIRED' USING ERRCODE = '23514';
        END IF;
        NEW.used_at := clock_timestamp();
        NEW.retry_window_until := NEW.used_at + interval '10 seconds';
    ELSIF OLD.refresh_token_instance_state = 'CURRENT' AND NEW.refresh_token_instance_state = 'REVOKED' THEN
        IF NULLIF(btrim(NEW.revoke_reason_code), '') IS NULL THEN
            RAISE EXCEPTION 'REFRESH_TOKEN_REVOKE_REASON_REQUIRED' USING ERRCODE = '23514';
        END IF;
        NEW.revoked_at := clock_timestamp();
    ELSIF OLD.refresh_token_instance_state = 'CURRENT' AND NEW.refresh_token_instance_state = 'EXPIRED' THEN
        IF OLD.expires_at > clock_timestamp() THEN
            RAISE EXCEPTION 'REFRESH_TOKEN_NOT_EXPIRED' USING ERRCODE = '23514';
        END IF;
    ELSIF NEW.refresh_token_instance_state = OLD.refresh_token_instance_state
       AND to_jsonb(NEW) IS NOT DISTINCT FROM to_jsonb(OLD) THEN
        RETURN NEW;
    ELSE
        RAISE EXCEPTION 'INVALID_STATE_TRANSITION: Refresh Token % -> %', OLD.refresh_token_instance_state, NEW.refresh_token_instance_state USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION oauth.fn_refresh_token_successor_guard()
RETURNS trigger
LANGUAGE plpgsql
AS $$

BEGIN
    IF NEW.refresh_token_instance_state = 'USED' AND NOT EXISTS (
        SELECT 1 FROM oauth.refresh_token s
         WHERE s.id = NEW.successor_id
           AND s.family_id = NEW.family_id
           AND s.generation = NEW.generation + 1
           AND s.refresh_token_instance_state = 'CURRENT'
    ) THEN
        RAISE EXCEPTION 'REFRESH_TOKEN_SUCCESSOR_CONTEXT_MISMATCH' USING ERRCODE = '23514';
    END IF;
    RETURN NULL;
END;
$$;

CREATE OR REPLACE FUNCTION oauth.fn_mark_refresh_token_reuse(p_refresh_token_id uuid, p_reason_code text DEFAULT 'REFRESH_TOKEN_REUSE')
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
    v_family oauth.token_family%ROWTYPE;
BEGIN
    SELECT f.* INTO v_family
      FROM oauth.refresh_token rt
      JOIN oauth.token_family f ON f.id = rt.family_id
     WHERE rt.id = p_refresh_token_id
       AND rt.refresh_token_instance_state = 'USED'
     FOR UPDATE OF f;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'REFRESH_TOKEN_REUSE_TARGET_INVALID' USING ERRCODE = '23514';
    END IF;
    IF v_family.token_family_state = 'ACTIVE' THEN
        UPDATE oauth.token_family
           SET token_family_state = 'COMPROMISED', compromised_at = clock_timestamp(), compromise_reason_code = p_reason_code
         WHERE id = v_family.id;
        INSERT INTO oauth.revocation_record(
            revocation_kind, target_ref, user_id, client_id, tenant_id,
            reason_code, source_kind, source_ref, prunable_after
        ) VALUES (
            'TOKEN_FAMILY', v_family.id::text,
            CASE WHEN v_family.subject_kind = 'USER' THEN v_family.subject_id ELSE NULL END,
            v_family.client_id, v_family.tenant_id,
            p_reason_code, 'SYSTEM', p_refresh_token_id::text,
            clock_timestamp() + interval '400 days'
        );
    END IF;
END;
$$;

CREATE OR REPLACE FUNCTION oauth.fn_authorization_code_state_guard()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    v_grant oauth.authorization_grant%ROWTYPE;
BEGIN
    IF OLD.authorization_code_state = 'ISSUED' AND NEW.authorization_code_state = 'CONSUMED' THEN
        IF NEW.replay_detected_at IS NOT NULL OR NEW.revoked_at IS NOT NULL THEN
            RAISE EXCEPTION 'AUTHORIZATION_CODE_CONSUMPTION_EVIDENCE_INVALID' USING ERRCODE = '23514';
        END IF;
        NEW.consumed_at := clock_timestamp();
    ELSIF OLD.authorization_code_state = 'ISSUED' AND NEW.authorization_code_state = 'EXPIRED' THEN
        IF OLD.expires_at > clock_timestamp() THEN
            RAISE EXCEPTION 'AUTHORIZATION_CODE_NOT_EXPIRED' USING ERRCODE = '23514';
        END IF;
    ELSIF OLD.authorization_code_state = 'ISSUED' AND NEW.authorization_code_state = 'REVOKED' THEN
        NEW.revoked_at := clock_timestamp();
    ELSIF OLD.authorization_code_state = 'CONSUMED'
       AND NEW.authorization_code_state = 'CONSUMED'
       AND OLD.replay_detected_at IS NULL
       AND NEW.replay_detected_at IS NOT NULL THEN
        NEW.replay_detected_at := clock_timestamp();
        SELECT * INTO v_grant FROM oauth.authorization_grant WHERE id = NEW.grant_id FOR UPDATE;
        UPDATE oauth.token_family
           SET token_family_state = 'COMPROMISED', compromised_at = clock_timestamp(), compromise_reason_code = 'AUTHORIZATION_CODE_REPLAY'
         WHERE grant_id = NEW.grant_id AND token_family_state = 'ACTIVE';
        UPDATE oauth.authorization_grant
           SET grant_state = 'REVOKED', revoked_at = clock_timestamp(), revoke_reason_code = 'AUTHORIZATION_CODE_REPLAY', revoked_by_ref = 'database'
         WHERE id = NEW.grant_id AND grant_state = 'ACTIVE';
        IF FOUND THEN
            INSERT INTO oauth.revocation_record(
                revocation_kind, target_ref, user_id, client_id, tenant_id,
                reason_code, source_kind, source_ref, prunable_after
            ) VALUES (
                'GRANT', v_grant.id::text,
                CASE WHEN v_grant.subject_kind = 'USER' THEN v_grant.subject_id ELSE NULL END,
                v_grant.client_id, v_grant.tenant_id,
                'AUTHORIZATION_CODE_REPLAY', 'SYSTEM', NEW.id::text,
                clock_timestamp() + interval '400 days'
            );
        END IF;
    ELSIF NEW.authorization_code_state = OLD.authorization_code_state
       AND to_jsonb(NEW) IS NOT DISTINCT FROM to_jsonb(OLD) THEN
        RETURN NEW;
    ELSE

        RAISE EXCEPTION 'INVALID_STATE_TRANSITION: Authorization Code % -> %', OLD.authorization_code_state, NEW.authorization_code_state USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION oauth.fn_reference_token_revoke_guard()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF OLD.revoked_at IS NOT NULL AND NEW.revoked_at IS DISTINCT FROM OLD.revoked_at THEN
        RAISE EXCEPTION 'REFERENCE_TOKEN_REVOCATION_IMMUTABLE' USING ERRCODE = '55000';
    ELSIF OLD.revoked_at IS NULL AND NEW.revoked_at IS NOT NULL THEN
        NEW.revoked_at := clock_timestamp();
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_application_touch BEFORE UPDATE ON oauth.application FOR EACH ROW EXECUTE FUNCTION core.fn_touch_updated_at();

CREATE TRIGGER trg_application_version BEFORE UPDATE ON oauth.application FOR EACH ROW EXECUTE FUNCTION core.fn_increment_row_version();

CREATE TRIGGER trg_application_public_id BEFORE INSERT ON oauth.application FOR EACH ROW EXECUTE FUNCTION core.fn_register_public_id('APPLICATION');

CREATE TRIGGER trg_client_touch BEFORE UPDATE ON oauth.client FOR EACH ROW EXECUTE FUNCTION core.fn_touch_updated_at();

CREATE TRIGGER trg_client_version BEFORE UPDATE ON oauth.client FOR EACH ROW EXECUTE FUNCTION core.fn_increment_row_version();

CREATE TRIGGER trg_client_epoch BEFORE UPDATE ON oauth.client FOR EACH ROW EXECUTE FUNCTION core.fn_forbid_epoch_decrease('client_security_epoch');

CREATE TRIGGER trg_client_public_id BEFORE INSERT ON oauth.client FOR EACH ROW EXECUTE FUNCTION core.fn_register_public_id('CLIENT');

CREATE TRIGGER trg_client_terminal BEFORE UPDATE ON oauth.client FOR EACH ROW EXECUTE FUNCTION oauth.fn_client_state_guard();

CREATE TRIGGER trg_client_credential_touch BEFORE UPDATE ON oauth.client_credential FOR EACH ROW EXECUTE FUNCTION core.fn_touch_updated_at();

CREATE TRIGGER trg_client_credential_version BEFORE UPDATE ON oauth.client_credential FOR EACH ROW EXECUTE FUNCTION core.fn_increment_row_version();

CREATE TRIGGER trg_api_resource_touch BEFORE UPDATE ON oauth.api_resource FOR EACH ROW EXECUTE FUNCTION core.fn_touch_updated_at();

CREATE TRIGGER trg_api_resource_version BEFORE UPDATE ON oauth.api_resource FOR EACH ROW EXECUTE FUNCTION core.fn_increment_row_version();

CREATE TRIGGER trg_api_resource_public_id BEFORE INSERT ON oauth.api_resource FOR EACH ROW EXECUTE FUNCTION core.fn_register_public_id('API_RESOURCE');

CREATE TRIGGER trg_device_touch BEFORE UPDATE ON oauth.device FOR EACH ROW EXECUTE FUNCTION core.fn_touch_updated_at();

CREATE TRIGGER trg_device_version BEFORE UPDATE ON oauth.device FOR EACH ROW EXECUTE FUNCTION core.fn_increment_row_version();

CREATE TRIGGER trg_device_loss BEFORE UPDATE ON oauth.device FOR EACH ROW EXECUTE FUNCTION oauth.fn_device_loss_guard();

CREATE TRIGGER trg_device_public_id BEFORE INSERT ON oauth.device FOR EACH ROW EXECUTE FUNCTION core.fn_register_public_id('DEVICE');

CREATE TRIGGER trg_grant_touch BEFORE UPDATE ON oauth.authorization_grant FOR EACH ROW EXECUTE FUNCTION core.fn_touch_updated_at();

CREATE TRIGGER trg_grant_version BEFORE UPDATE ON oauth.authorization_grant FOR EACH ROW EXECUTE FUNCTION core.fn_increment_row_version();

CREATE TRIGGER trg_grant_terminal BEFORE UPDATE ON oauth.authorization_grant FOR EACH ROW EXECUTE FUNCTION core.fn_terminal_state_guard('grant_state', 'DENIED', 'REVOKED', 'EXPIRED');

CREATE TRIGGER trg_grant_public_id BEFORE INSERT ON oauth.authorization_grant FOR EACH ROW EXECUTE FUNCTION core.fn_register_public_id('GRANT');

CREATE TRIGGER trg_session_touch BEFORE UPDATE ON oauth.user_session FOR EACH ROW EXECUTE FUNCTION core.fn_touch_updated_at();

CREATE TRIGGER trg_session_version BEFORE UPDATE ON oauth.user_session FOR EACH ROW EXECUTE FUNCTION core.fn_increment_row_version();

CREATE TRIGGER trg_session_public_id BEFORE INSERT ON oauth.user_session FOR EACH ROW EXECUTE FUNCTION core.fn_register_public_id('SESSION');

CREATE TRIGGER trg_token_family_touch BEFORE UPDATE ON oauth.token_family FOR EACH ROW EXECUTE FUNCTION core.fn_touch_updated_at();

CREATE TRIGGER trg_token_family_version BEFORE UPDATE ON oauth.token_family FOR EACH ROW EXECUTE FUNCTION core.fn_increment_row_version();

CREATE TRIGGER trg_revocation_append_only BEFORE UPDATE OR DELETE ON oauth.revocation_record FOR EACH STATEMENT EXECUTE FUNCTION core.fn_append_only();

CREATE TRIGGER trg_logout_touch BEFORE UPDATE ON oauth.logout_request FOR EACH ROW EXECUTE FUNCTION core.fn_touch_updated_at();

CREATE TRIGGER trg_logout_version BEFORE UPDATE ON oauth.logout_request FOR EACH ROW EXECUTE FUNCTION core.fn_increment_row_version();

CREATE TRIGGER trg_logout_target_touch BEFORE UPDATE ON oauth.logout_target_result FOR EACH ROW EXECUTE FUNCTION core.fn_touch_updated_at();

CREATE TRIGGER trg_client_configuration_immutable BEFORE UPDATE OR DELETE ON oauth.client FOR EACH ROW
    EXECUTE FUNCTION core.fn_immutable_after_draft('client_state', 'approval_case_id', 'approval_execution_id',
        'approved_at', 'suspended_at', 'compromised_at', 'retired_at', 'last_used_at',
        'client_security_epoch', 'reactivation_review_ref', 'last_activation_execution_id', 'updated_at', 'row_version');

CREATE TRIGGER trg_refresh_token_guard BEFORE INSERT OR UPDATE OR DELETE ON oauth.refresh_token FOR EACH ROW
    EXECUTE FUNCTION oauth.fn_refresh_token_guard();

CREATE CONSTRAINT TRIGGER trg_refresh_token_successor
    AFTER INSERT OR UPDATE ON oauth.refresh_token
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION oauth.fn_refresh_token_successor_guard();

CREATE TRIGGER trg_authorization_code_state BEFORE UPDATE ON oauth.authorization_code FOR EACH ROW
    EXECUTE FUNCTION oauth.fn_authorization_code_state_guard();

CREATE TRIGGER trg_session_identity_immutable BEFORE UPDATE OR DELETE ON oauth.user_session FOR EACH ROW
    EXECUTE FUNCTION core.fn_immutable_except('session_state', 'idle_expires_at', 'last_reauth_at', 'risk_level',
        'expired_at', 'compromised_at', 'compromise_reason_code', 'revoked_at', 'revoke_reason_code', 'updated_at', 'row_version');

CREATE TRIGGER trg_token_family_identity_immutable BEFORE UPDATE OR DELETE ON oauth.token_family FOR EACH ROW
    EXECUTE FUNCTION core.fn_immutable_except('token_family_state', 'generation_count', 'idle_expires_at', 'compromised_at', 'compromise_reason_code', 'revoked_at', 'revoke_reason_code', 'updated_at', 'row_version');

CREATE TRIGGER trg_authorization_code_identity_immutable BEFORE UPDATE OR DELETE ON oauth.authorization_code FOR EACH ROW
    EXECUTE FUNCTION core.fn_immutable_except('authorization_code_state', 'consumed_at', 'replay_detected_at', 'revoked_at');

CREATE TRIGGER trg_reference_token_identity_immutable BEFORE UPDATE OR DELETE ON oauth.reference_access_token FOR EACH ROW
    EXECUTE FUNCTION core.fn_immutable_except('revoked_at');

CREATE TRIGGER trg_reference_token_revoke BEFORE UPDATE ON oauth.reference_access_token FOR EACH ROW
    EXECUTE FUNCTION oauth.fn_reference_token_revoke_guard();

CREATE TRIGGER trg_session_terminal BEFORE UPDATE ON oauth.user_session FOR EACH ROW
    EXECUTE FUNCTION core.fn_terminal_state_guard('session_state', 'EXPIRED', 'REVOKED');

CREATE TRIGGER trg_token_family_terminal BEFORE UPDATE ON oauth.token_family FOR EACH ROW
    EXECUTE FUNCTION core.fn_terminal_state_guard('token_family_state', 'EXPIRED', 'COMPROMISED', 'REVOKED');

CREATE TRIGGER trg_authorization_code_terminal BEFORE UPDATE ON oauth.authorization_code FOR EACH ROW
    EXECUTE FUNCTION core.fn_terminal_state_guard('authorization_code_state', 'CONSUMED', 'EXPIRED', 'REVOKED');

CREATE TRIGGER trg_device_lifecycle_terminal BEFORE UPDATE ON oauth.device FOR EACH ROW
    EXECUTE FUNCTION core.fn_terminal_state_guard('device_lifecycle_state', 'RETIRED', 'REVOKED');

COMMENT ON FUNCTION oauth.fn_client_state_guard() IS 'Client 状态守卫：受损后只能维持受损或退役，退役不可恢复。';

COMMENT ON FUNCTION oauth.fn_device_loss_guard() IS 'REQ-SESSION-017：挂失原子撤销关联会话和 Token Family；解除挂失不恢复可信关系。';

COMMENT ON FUNCTION oauth.fn_refresh_token_guard() IS 'Refresh Token 由数据库串行分配 Family generation；CURRENT 只能原子转为 USED、REVOKED 或到期，哈希、Family、代际和绑定上下文不可改写。';

COMMENT ON FUNCTION oauth.fn_refresh_token_successor_guard() IS '事务提交前验证 USED Refresh Token 的 successor 属于同一 Family、恰好下一代且仍为 CURRENT。';

COMMENT ON FUNCTION oauth.fn_mark_refresh_token_reuse(uuid, text) IS '确认已使用 Refresh Token 被重放时，原子将整个 Family 标记为 COMPROMISED 并追加撤销记录。';

COMMENT ON FUNCTION oauth.fn_authorization_code_state_guard() IS 'Authorization Code 只能单次消费、到期或撤销；消费后重放会原子失陷 Token Family、撤销 Grant 并写撤销记录。';

COMMENT ON FUNCTION oauth.fn_reference_token_revoke_guard() IS 'Reference Token 的 revoked_at 只能从 NULL 设置一次，设置后不可清除或改写。';

COMMENT ON TRIGGER trg_application_touch ON oauth.application IS '触发器：调用 core.fn_touch_updated_at 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_application_version ON oauth.application IS '触发器：调用 core.fn_increment_row_version 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_application_public_id ON oauth.application IS '触发器：调用 core.fn_register_public_id 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_client_touch ON oauth.client IS '触发器：调用 core.fn_touch_updated_at 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_client_version ON oauth.client IS '触发器：调用 core.fn_increment_row_version 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_client_epoch ON oauth.client IS '触发器：调用 core.fn_forbid_epoch_decrease 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_client_public_id ON oauth.client IS '触发器：调用 core.fn_register_public_id 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_client_terminal ON oauth.client IS '触发器：调用 oauth.fn_client_state_guard 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_client_credential_touch ON oauth.client_credential IS '触发器：调用 core.fn_touch_updated_at 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_client_credential_version ON oauth.client_credential IS '触发器：调用 core.fn_increment_row_version 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_api_resource_touch ON oauth.api_resource IS '触发器：调用 core.fn_touch_updated_at 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_api_resource_version ON oauth.api_resource IS '触发器：调用 core.fn_increment_row_version 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_api_resource_public_id ON oauth.api_resource IS '触发器：调用 core.fn_register_public_id 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_device_touch ON oauth.device IS '触发器：调用 core.fn_touch_updated_at 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_device_version ON oauth.device IS '触发器：调用 core.fn_increment_row_version 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_device_loss ON oauth.device IS '触发器：调用 oauth.fn_device_loss_guard 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_device_public_id ON oauth.device IS '触发器：调用 core.fn_register_public_id 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_grant_touch ON oauth.authorization_grant IS '触发器：调用 core.fn_touch_updated_at 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_grant_version ON oauth.authorization_grant IS '触发器：调用 core.fn_increment_row_version 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_grant_terminal ON oauth.authorization_grant IS '触发器：调用 core.fn_terminal_state_guard 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_grant_public_id ON oauth.authorization_grant IS '触发器：调用 core.fn_register_public_id 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_session_touch ON oauth.user_session IS '触发器：调用 core.fn_touch_updated_at 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_session_version ON oauth.user_session IS '触发器：调用 core.fn_increment_row_version 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_session_public_id ON oauth.user_session IS '触发器：调用 core.fn_register_public_id 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_token_family_touch ON oauth.token_family IS '触发器：调用 core.fn_touch_updated_at 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_token_family_version ON oauth.token_family IS '触发器：调用 core.fn_increment_row_version 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_revocation_append_only ON oauth.revocation_record IS '触发器：调用 core.fn_append_only 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_logout_touch ON oauth.logout_request IS '触发器：调用 core.fn_touch_updated_at 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_logout_version ON oauth.logout_request IS '触发器：调用 core.fn_increment_row_version 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_logout_target_touch ON oauth.logout_target_result IS '触发器：调用 core.fn_touch_updated_at 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_client_configuration_immutable ON oauth.client IS '触发器：调用 core.fn_immutable_after_draft 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_refresh_token_guard ON oauth.refresh_token IS '触发器：调用 oauth.fn_refresh_token_guard 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_refresh_token_successor ON oauth.refresh_token IS '触发器：调用 oauth.fn_refresh_token_successor_guard 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_authorization_code_state ON oauth.authorization_code IS '触发器：调用 oauth.fn_authorization_code_state_guard 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_session_identity_immutable ON oauth.user_session IS '触发器：调用 core.fn_immutable_except 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_token_family_identity_immutable ON oauth.token_family IS '触发器：调用 core.fn_immutable_except 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_authorization_code_identity_immutable ON oauth.authorization_code IS '触发器：调用 core.fn_immutable_except 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_reference_token_identity_immutable ON oauth.reference_access_token IS '触发器：调用 core.fn_immutable_except 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_reference_token_revoke ON oauth.reference_access_token IS '触发器：调用 oauth.fn_reference_token_revoke_guard 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_session_terminal ON oauth.user_session IS '触发器：调用 core.fn_terminal_state_guard 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_token_family_terminal ON oauth.token_family IS '触发器：调用 core.fn_terminal_state_guard 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_authorization_code_terminal ON oauth.authorization_code IS '触发器：调用 core.fn_terminal_state_guard 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_device_lifecycle_terminal ON oauth.device IS '触发器：调用 core.fn_terminal_state_guard 维护数据库结构完整性、不可变证据或关键原子安全底线。';

