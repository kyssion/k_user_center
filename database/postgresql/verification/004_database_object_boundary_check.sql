\set ON_ERROR_STOP on

DO $database_object_boundary$
DECLARE
    invalid_triggers text;
    missing_technical_triggers text;
    invalid_routines text;
    public_routine_execute text;
    enums text;
    views text;
BEGIN
    SELECT string_agg(format('%s.%s', relation.relname, trigger_object.tgname), ', ' ORDER BY relation.relname, trigger_object.tgname)
      INTO invalid_triggers
      FROM pg_trigger trigger_object
      JOIN pg_class relation ON relation.oid = trigger_object.tgrelid
      JOIN pg_namespace relation_namespace ON relation_namespace.oid = relation.relnamespace
      JOIN pg_proc routine ON routine.oid = trigger_object.tgfoid
      JOIN pg_namespace routine_namespace ON routine_namespace.oid = routine.pronamespace
     WHERE relation_namespace.nspname = 'iam'
       AND NOT trigger_object.tgisinternal
       AND NOT (
           trigger_object.tgtype = 19
           AND trigger_object.tgenabled = 'O'
           AND trigger_object.tgnargs = 0
           AND routine_namespace.nspname = 'iam'
           AND (
               (trigger_object.tgname = 'trg_set_updated_at_row_version' AND routine.proname = 'set_updated_at_row_version_technical')
               OR (trigger_object.tgname = 'trg_set_row_version' AND routine.proname = 'set_row_version_technical')
           )
       );

    WITH target AS (
        SELECT relation.oid,
               relation.relname,
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
    )
    SELECT string_agg(target.relname, ', ' ORDER BY target.relname)
      INTO missing_technical_triggers
      FROM target
     WHERE NOT EXISTS (
        SELECT 1
        FROM pg_trigger trigger_object
        JOIN pg_proc routine ON routine.oid = trigger_object.tgfoid
        JOIN pg_namespace routine_namespace ON routine_namespace.oid = routine.pronamespace
        WHERE trigger_object.tgrelid = target.oid
          AND NOT trigger_object.tgisinternal
          AND trigger_object.tgtype = 19
          AND trigger_object.tgenabled = 'O'
          AND trigger_object.tgnargs = 0
          AND routine_namespace.nspname = 'iam'
          AND (
              (target.has_updated_at
               AND trigger_object.tgname = 'trg_set_updated_at_row_version'
               AND routine.proname = 'set_updated_at_row_version_technical')
              OR
              (NOT target.has_updated_at
               AND trigger_object.tgname = 'trg_set_row_version'
               AND routine.proname = 'set_row_version_technical')
          )
     );

    SELECT string_agg(routine.proname, ', ' ORDER BY routine.proname)
      INTO invalid_routines
      FROM pg_proc routine
      JOIN pg_namespace namespace ON namespace.oid = routine.pronamespace
      JOIN pg_language language ON language.oid = routine.prolang
     WHERE namespace.nspname = 'iam'
       AND NOT (
           pg_get_function_identity_arguments(routine.oid) = ''
           AND routine.prorettype = 'trigger'::regtype
           AND language.lanname = 'plpgsql'
           AND NOT routine.prosecdef
           AND (
               (
                   routine.proname = 'set_updated_at_row_version_technical'
                   AND regexp_replace(btrim(routine.prosrc), '\s+', ' ', 'g') =
                       'BEGIN NEW.updated_at := statement_timestamp(); NEW.row_version := OLD.row_version + 1; RETURN NEW; END'
               )
               OR
               (
                   routine.proname = 'set_row_version_technical'
                   AND regexp_replace(btrim(routine.prosrc), '\s+', ' ', 'g') =
                       'BEGIN NEW.row_version := OLD.row_version + 1; RETURN NEW; END'
               )
           )
       );

    SELECT string_agg(routine.proname, ', ' ORDER BY routine.proname)
      INTO public_routine_execute
      FROM pg_proc routine
      JOIN pg_namespace namespace ON namespace.oid = routine.pronamespace
     WHERE namespace.nspname = 'iam'
       AND EXISTS (
           SELECT 1
           FROM aclexplode(coalesce(routine.proacl, acldefault('f', routine.proowner))) acl
           WHERE acl.grantee = 0
             AND acl.privilege_type = 'EXECUTE'
       );

    SELECT string_agg(type_object.typname, ', ' ORDER BY type_object.typname)
      INTO enums
      FROM pg_type type_object
      JOIN pg_namespace namespace ON namespace.oid = type_object.typnamespace
     WHERE namespace.nspname = 'iam' AND type_object.typtype = 'e';

    SELECT string_agg(relation.relname, ', ' ORDER BY relation.relname)
      INTO views
      FROM pg_class relation
      JOIN pg_namespace namespace ON namespace.oid = relation.relnamespace
     WHERE namespace.nspname = 'iam' AND relation.relkind IN ('v','m');

    IF invalid_triggers IS NOT NULL OR missing_technical_triggers IS NOT NULL OR invalid_routines IS NOT NULL
       OR public_routine_execute IS NOT NULL OR enums IS NOT NULL OR views IS NOT NULL THEN
        RAISE EXCEPTION '数据库对象边界门禁失败：invalid_trigger=%, missing_technical_trigger=%, invalid_routine=%, public_execute=%, enum=%, view=%',
            coalesce(invalid_triggers, '<none>'), coalesce(missing_technical_triggers, '<none>'), coalesce(invalid_routines, '<none>'),
            coalesce(public_routine_execute, '<none>'), coalesce(enums, '<none>'), coalesce(views, '<none>');
    END IF;
END
$database_object_boundary$;

SELECT 'PASS: 仅存在白名单技术时间与 row_version Trigger；函数体精确匹配且不存在业务 Routine、Enum、View 或 Materialized View' AS result;
