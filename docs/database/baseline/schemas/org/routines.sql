-- =============================================================================
-- baseline/schemas/org/routines.sql
-- org Schema 的最终函数、过程、局部触发器及内联 COMMENT
-- PostgreSQL 16+；应用技术栈：.NET 10 + SqlSugar
-- =============================================================================

CREATE OR REPLACE FUNCTION org.fn_organization_hierarchy_guard()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    v_parent org.organization%ROWTYPE;
BEGIN
    IF NEW.parent_id IS NULL THEN
        IF NEW.hierarchy_path <> NEW.organization_code THEN
            RAISE EXCEPTION 'ORGANIZATION_ROOT_PATH_INVALID' USING ERRCODE = '23514';
        END IF;
    ELSE
        SELECT * INTO v_parent FROM org.organization WHERE id = NEW.parent_id FOR SHARE;
        IF NOT FOUND OR v_parent.tenant_id <> NEW.tenant_id THEN
            RAISE EXCEPTION 'ORGANIZATION_PARENT_TENANT_MISMATCH' USING ERRCODE = '23514';
        END IF;
        IF NEW.hierarchy_path <> v_parent.hierarchy_path || '/' || NEW.organization_code THEN
            RAISE EXCEPTION 'ORGANIZATION_PATH_INVALID' USING ERRCODE = '23514';
        END IF;
        IF EXISTS (
            WITH RECURSIVE ancestors AS (
                SELECT o.id, o.parent_id FROM org.organization o WHERE o.id = NEW.parent_id
                UNION ALL
                SELECT o.id, o.parent_id FROM org.organization o JOIN ancestors a ON o.id = a.parent_id
            )
            SELECT 1 FROM ancestors WHERE id = NEW.id
        ) THEN
            RAISE EXCEPTION 'ORGANIZATION_CYCLE_DETECTED' USING ERRCODE = '23514';
        END IF;
    END IF;

    IF TG_OP = 'UPDATE'
       AND (NEW.tenant_id, NEW.parent_id, NEW.organization_code, NEW.hierarchy_path)
           IS DISTINCT FROM (OLD.tenant_id, OLD.parent_id, OLD.organization_code, OLD.hierarchy_path)
       AND EXISTS (SELECT 1 FROM org.organization c WHERE c.parent_id = OLD.id) THEN
        RAISE EXCEPTION 'ORGANIZATION_WITH_CHILDREN_REPARENT_FORBIDDEN' USING ERRCODE = '55000';
    END IF;
    RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION org.fn_group_member_guard()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    v_group_tenant uuid;
    v_nested_tenant uuid;
BEGIN
    SELECT tenant_id INTO v_group_tenant FROM org.user_group WHERE id = NEW.group_id FOR SHARE;
    IF NOT FOUND THEN RAISE EXCEPTION 'GROUP_NOT_FOUND' USING ERRCODE = '23503'; END IF;
    IF NEW.nested_group_id IS NOT NULL THEN
        SELECT tenant_id INTO v_nested_tenant FROM org.user_group WHERE id = NEW.nested_group_id FOR SHARE;
        IF v_nested_tenant IS DISTINCT FROM v_group_tenant THEN
            RAISE EXCEPTION 'NESTED_GROUP_TENANT_MISMATCH' USING ERRCODE = '23514';
        END IF;
        IF EXISTS (
            WITH RECURSIVE descendants AS (
                SELECT gm.nested_group_id AS id
                  FROM org.group_member gm
                 WHERE gm.group_id = NEW.nested_group_id
                   AND gm.nested_group_id IS NOT NULL
                   AND gm.membership_state IN ('ACTIVE', 'SUSPENDED')
                UNION
                SELECT gm.nested_group_id
                  FROM org.group_member gm
                  JOIN descendants d ON gm.group_id = d.id
                 WHERE gm.nested_group_id IS NOT NULL
                   AND gm.membership_state IN ('ACTIVE', 'SUSPENDED')
            )
            SELECT 1 FROM descendants WHERE id = NEW.group_id
        ) THEN
            RAISE EXCEPTION 'GROUP_CYCLE_DETECTED' USING ERRCODE = '23514';
        END IF;

    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_business_line_public_id BEFORE INSERT ON org.business_line FOR EACH ROW EXECUTE FUNCTION core.fn_register_public_id('BUSINESS_LINE');

CREATE TRIGGER trg_business_line_touch BEFORE UPDATE ON org.business_line FOR EACH ROW EXECUTE FUNCTION core.fn_touch_updated_at();

CREATE TRIGGER trg_business_line_version BEFORE UPDATE ON org.business_line FOR EACH ROW EXECUTE FUNCTION core.fn_increment_row_version();

CREATE TRIGGER trg_business_line_terminal BEFORE UPDATE ON org.business_line FOR EACH ROW EXECUTE FUNCTION core.fn_terminal_state_guard('business_line_state', 'CLOSED');

CREATE TRIGGER trg_tenant_public_id BEFORE INSERT ON org.tenant FOR EACH ROW EXECUTE FUNCTION core.fn_register_public_id('TENANT');

CREATE TRIGGER trg_tenant_touch BEFORE UPDATE ON org.tenant FOR EACH ROW EXECUTE FUNCTION core.fn_touch_updated_at();

CREATE TRIGGER trg_tenant_version BEFORE UPDATE ON org.tenant FOR EACH ROW EXECUTE FUNCTION core.fn_increment_row_version();

CREATE TRIGGER trg_tenant_epoch BEFORE UPDATE ON org.tenant FOR EACH ROW EXECUTE FUNCTION core.fn_forbid_epoch_decrease('tenant_security_epoch');

CREATE TRIGGER trg_tenant_terminal BEFORE UPDATE ON org.tenant FOR EACH ROW EXECUTE FUNCTION core.fn_terminal_state_guard('tenant_state', 'CLOSED');

CREATE TRIGGER trg_tenant_domain_touch BEFORE UPDATE ON org.tenant_domain FOR EACH ROW EXECUTE FUNCTION core.fn_touch_updated_at();

CREATE TRIGGER trg_tenant_domain_version BEFORE UPDATE ON org.tenant_domain FOR EACH ROW EXECUTE FUNCTION core.fn_increment_row_version();

CREATE TRIGGER trg_organization_public_id BEFORE INSERT ON org.organization FOR EACH ROW EXECUTE FUNCTION core.fn_register_public_id('ORGANIZATION');

CREATE TRIGGER trg_organization_touch BEFORE UPDATE ON org.organization FOR EACH ROW EXECUTE FUNCTION core.fn_touch_updated_at();

CREATE TRIGGER trg_organization_version BEFORE UPDATE ON org.organization FOR EACH ROW EXECUTE FUNCTION core.fn_increment_row_version();

CREATE TRIGGER trg_organization_terminal BEFORE UPDATE ON org.organization FOR EACH ROW EXECUTE FUNCTION core.fn_terminal_state_guard('organization_state', 'CLOSED');

CREATE TRIGGER trg_membership_public_id BEFORE INSERT ON org.membership FOR EACH ROW EXECUTE FUNCTION core.fn_register_public_id('MEMBERSHIP');

CREATE TRIGGER trg_membership_touch BEFORE UPDATE ON org.membership FOR EACH ROW EXECUTE FUNCTION core.fn_touch_updated_at();

CREATE TRIGGER trg_membership_version BEFORE UPDATE ON org.membership FOR EACH ROW EXECUTE FUNCTION core.fn_increment_row_version();

CREATE TRIGGER trg_membership_terminal BEFORE UPDATE ON org.membership FOR EACH ROW EXECUTE FUNCTION core.fn_terminal_state_guard('membership_state', 'LEFT', 'REJECTED', 'EXPIRED');

CREATE TRIGGER trg_invitation_public_id BEFORE INSERT ON org.invitation FOR EACH ROW EXECUTE FUNCTION core.fn_register_public_id('INVITATION');

CREATE TRIGGER trg_invitation_touch BEFORE UPDATE ON org.invitation FOR EACH ROW EXECUTE FUNCTION core.fn_touch_updated_at();

CREATE TRIGGER trg_invitation_version BEFORE UPDATE ON org.invitation FOR EACH ROW EXECUTE FUNCTION core.fn_increment_row_version();

CREATE TRIGGER trg_invitation_terminal BEFORE UPDATE ON org.invitation FOR EACH ROW EXECUTE FUNCTION core.fn_terminal_state_guard('invitation_state', 'ACCEPTED', 'REJECTED', 'EXPIRED', 'REVOKED');

CREATE TRIGGER trg_group_public_id BEFORE INSERT ON org.user_group FOR EACH ROW EXECUTE FUNCTION core.fn_register_public_id('GROUP');

CREATE TRIGGER trg_group_touch BEFORE UPDATE ON org.user_group FOR EACH ROW EXECUTE FUNCTION core.fn_touch_updated_at();

CREATE TRIGGER trg_group_version BEFORE UPDATE ON org.user_group FOR EACH ROW EXECUTE FUNCTION core.fn_increment_row_version();

CREATE TRIGGER trg_organization_hierarchy BEFORE INSERT OR UPDATE ON org.organization FOR EACH ROW
    EXECUTE FUNCTION org.fn_organization_hierarchy_guard();

CREATE TRIGGER trg_group_member_guard BEFORE INSERT OR UPDATE ON org.group_member FOR EACH ROW
    EXECUTE FUNCTION org.fn_group_member_guard();

COMMENT ON FUNCTION org.fn_organization_hierarchy_guard() IS '组织父子必须同租户，路径必须由父路径和本级代码确定，禁止循环及带子节点原地改父/改名。';

COMMENT ON FUNCTION org.fn_group_member_guard() IS '用户组嵌套必须同租户，并在数据库内递归阻断直接或间接循环。';

COMMENT ON TRIGGER trg_business_line_public_id ON org.business_line IS '触发器：调用 core.fn_register_public_id 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_business_line_touch ON org.business_line IS '触发器：调用 core.fn_touch_updated_at 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_business_line_version ON org.business_line IS '触发器：调用 core.fn_increment_row_version 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_business_line_terminal ON org.business_line IS '触发器：调用 core.fn_terminal_state_guard 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_tenant_public_id ON org.tenant IS '触发器：调用 core.fn_register_public_id 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_tenant_touch ON org.tenant IS '触发器：调用 core.fn_touch_updated_at 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_tenant_version ON org.tenant IS '触发器：调用 core.fn_increment_row_version 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_tenant_epoch ON org.tenant IS '触发器：调用 core.fn_forbid_epoch_decrease 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_tenant_terminal ON org.tenant IS '触发器：调用 core.fn_terminal_state_guard 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_tenant_domain_touch ON org.tenant_domain IS '触发器：调用 core.fn_touch_updated_at 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_tenant_domain_version ON org.tenant_domain IS '触发器：调用 core.fn_increment_row_version 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_organization_public_id ON org.organization IS '触发器：调用 core.fn_register_public_id 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_organization_touch ON org.organization IS '触发器：调用 core.fn_touch_updated_at 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_organization_version ON org.organization IS '触发器：调用 core.fn_increment_row_version 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_organization_terminal ON org.organization IS '触发器：调用 core.fn_terminal_state_guard 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_membership_public_id ON org.membership IS '触发器：调用 core.fn_register_public_id 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_membership_touch ON org.membership IS '触发器：调用 core.fn_touch_updated_at 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_membership_version ON org.membership IS '触发器：调用 core.fn_increment_row_version 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_membership_terminal ON org.membership IS '触发器：调用 core.fn_terminal_state_guard 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_invitation_public_id ON org.invitation IS '触发器：调用 core.fn_register_public_id 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_invitation_touch ON org.invitation IS '触发器：调用 core.fn_touch_updated_at 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_invitation_version ON org.invitation IS '触发器：调用 core.fn_increment_row_version 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_invitation_terminal ON org.invitation IS '触发器：调用 core.fn_terminal_state_guard 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_group_public_id ON org.user_group IS '触发器：调用 core.fn_register_public_id 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_group_touch ON org.user_group IS '触发器：调用 core.fn_touch_updated_at 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_group_version ON org.user_group IS '触发器：调用 core.fn_increment_row_version 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_organization_hierarchy ON org.organization IS '触发器：调用 org.fn_organization_hierarchy_guard 维护数据库结构完整性、不可变证据或关键原子安全底线。';

COMMENT ON TRIGGER trg_group_member_guard ON org.group_member IS '触发器：调用 org.fn_group_member_guard 维护数据库结构完整性、不可变证据或关键原子安全底线。';

