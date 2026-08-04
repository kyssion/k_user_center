\set ON_ERROR_STOP on

SET ROLE iam_owner;

-- 唯一允许的持久化 Trigger：只维护技术更新时间，不读取其他表，不判断状态，不推进流程。
CREATE OR REPLACE FUNCTION iam.set_updated_at_technical()
RETURNS trigger
LANGUAGE plpgsql
AS $set_updated_at_technical$
BEGIN
    NEW.updated_at := statement_timestamp();
    RETURN NEW;
END
$set_updated_at_technical$;

REVOKE ALL ON FUNCTION iam.set_updated_at_technical() FROM PUBLIC;

COMMENT ON FUNCTION iam.set_updated_at_technical() IS '纯技术更新时间函数；只在 UPDATE 时覆盖 NEW.updated_at，不承载业务状态、授权、风险、审批或流程逻辑。';

DO $updated_at_trigger_setup$
DECLARE
    target record;
BEGIN
    FOR target IN
        SELECT namespace.nspname AS schema_name, relation.relname AS table_name
        FROM pg_class relation
        JOIN pg_namespace namespace ON namespace.oid = relation.relnamespace
        JOIN pg_attribute attribute
          ON attribute.attrelid = relation.oid
         AND attribute.attname = 'updated_at'
         AND attribute.attnum > 0
         AND NOT attribute.attisdropped
        WHERE namespace.nspname = 'iam'
          AND relation.relkind IN ('r', 'p')
          AND NOT relation.relispartition
        ORDER BY relation.relname
    LOOP
        EXECUTE format(
            'DROP TRIGGER IF EXISTS trg_set_updated_at ON %I.%I',
            target.schema_name, target.table_name
        );
        EXECUTE format(
            'CREATE TRIGGER trg_set_updated_at BEFORE UPDATE ON %I.%I '
            'FOR EACH ROW EXECUTE FUNCTION iam.set_updated_at_technical()',
            target.schema_name, target.table_name
        );
    END LOOP;
END
$updated_at_trigger_setup$;
