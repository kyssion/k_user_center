\set ON_ERROR_STOP on

SET ROLE iam_owner;

-- 仅维护数据库技术元数据：不读取其他表，不判断状态，不推进流程。
CREATE OR REPLACE FUNCTION iam.set_updated_at_row_version_technical()
RETURNS trigger
LANGUAGE plpgsql
AS $set_updated_at_row_version_technical$
BEGIN
    NEW.updated_at := statement_timestamp();
    NEW.row_version := OLD.row_version + 1;
    RETURN NEW;
END
$set_updated_at_row_version_technical$;

CREATE OR REPLACE FUNCTION iam.set_row_version_technical()
RETURNS trigger
LANGUAGE plpgsql
AS $set_row_version_technical$
BEGIN
    NEW.row_version := OLD.row_version + 1;
    RETURN NEW;
END
$set_row_version_technical$;

REVOKE ALL ON FUNCTION iam.set_updated_at_row_version_technical() FROM PUBLIC;
REVOKE ALL ON FUNCTION iam.set_row_version_technical() FROM PUBLIC;

COMMENT ON FUNCTION iam.set_updated_at_row_version_technical() IS '纯技术元数据函数；在 UPDATE 时刷新 updated_at 并将 row_version 单调递增 1，不承载业务状态、授权、风险、审批或流程逻辑。';
COMMENT ON FUNCTION iam.set_row_version_technical() IS '纯技术版本函数；对无 updated_at 的可变事实在 UPDATE 时将 row_version 单调递增 1，不承载业务逻辑。';

DO $technical_metadata_trigger_setup$
DECLARE
    target record;
BEGIN
    FOR target IN
        SELECT namespace.nspname AS schema_name,
               relation.relname AS table_name,
               EXISTS (
                   SELECT 1
                   FROM pg_attribute updated_attribute
                   WHERE updated_attribute.attrelid = relation.oid
                     AND updated_attribute.attname = 'updated_at'
                     AND updated_attribute.attnum > 0
                     AND NOT updated_attribute.attisdropped
               ) AS has_updated_at
        FROM pg_class relation
        JOIN pg_namespace namespace ON namespace.oid = relation.relnamespace
        JOIN pg_attribute version_attribute
          ON version_attribute.attrelid = relation.oid
         AND version_attribute.attname = 'row_version'
         AND version_attribute.attnum > 0
         AND NOT version_attribute.attisdropped
        WHERE namespace.nspname = 'iam'
          AND relation.relkind IN ('r', 'p')
          AND NOT relation.relispartition
        ORDER BY relation.relname
    LOOP
        EXECUTE format(
            'DROP TRIGGER IF EXISTS trg_set_updated_at_row_version ON %I.%I',
            target.schema_name, target.table_name
        );
        EXECUTE format(
            'DROP TRIGGER IF EXISTS trg_set_row_version ON %I.%I',
            target.schema_name, target.table_name
        );

        IF target.has_updated_at THEN
            EXECUTE format(
                'CREATE TRIGGER trg_set_updated_at_row_version BEFORE UPDATE ON %I.%I '
                'FOR EACH ROW EXECUTE FUNCTION iam.set_updated_at_row_version_technical()',
                target.schema_name, target.table_name
            );
        ELSE
            EXECUTE format(
                'CREATE TRIGGER trg_set_row_version BEFORE UPDATE ON %I.%I '
                'FOR EACH ROW EXECUTE FUNCTION iam.set_row_version_technical()',
                target.schema_name, target.table_name
            );
        END IF;
    END LOOP;
END
$technical_metadata_trigger_setup$;
