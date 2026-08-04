\set ON_ERROR_STOP on

DO $database_object_boundary$
DECLARE
    invalid_triggers text;
    missing_updated_at_triggers text;
    invalid_routines text;
    public_routine_execute text;
    enums text;
    views text;
BEGIN
    SELECT string_agg(format('%s.%s', c.relname, t.tgname), ', ' ORDER BY c.relname, t.tgname)
      INTO invalid_triggers
      FROM pg_trigger t
       JOIN pg_class c ON c.oid = t.tgrelid
       JOIN pg_namespace n ON n.oid = c.relnamespace
       JOIN pg_proc p ON p.oid = t.tgfoid
       JOIN pg_namespace function_namespace ON function_namespace.oid = p.pronamespace
      WHERE n.nspname = 'iam'
        AND NOT t.tgisinternal
        AND (
            t.tgname <> 'trg_set_updated_at'
            OR function_namespace.nspname <> 'iam'
            OR p.proname <> 'set_updated_at_technical'
            OR t.tgtype <> 19
            OR t.tgenabled <> 'O'
            OR t.tgnargs <> 0
        );

    SELECT string_agg(c.relname, ', ' ORDER BY c.relname)
      INTO missing_updated_at_triggers
      FROM pg_class c
      JOIN pg_namespace n ON n.oid = c.relnamespace
      JOIN pg_attribute a
        ON a.attrelid = c.oid
       AND a.attname = 'updated_at'
       AND a.attnum > 0
       AND NOT a.attisdropped
     WHERE n.nspname = 'iam'
       AND c.relkind IN ('r', 'p')
       AND NOT c.relispartition
       AND NOT EXISTS (
            SELECT 1
            FROM pg_trigger t
            JOIN pg_proc p ON p.oid = t.tgfoid
            JOIN pg_namespace function_namespace ON function_namespace.oid = p.pronamespace
            WHERE t.tgrelid = c.oid
              AND NOT t.tgisinternal
              AND t.tgname = 'trg_set_updated_at'
              AND function_namespace.nspname = 'iam'
              AND p.proname = 'set_updated_at_technical'
              AND t.tgtype = 19
              AND t.tgenabled = 'O'
              AND t.tgnargs = 0
       );

    SELECT string_agg(p.proname, ', ' ORDER BY p.proname)
      INTO invalid_routines
      FROM pg_proc p
      JOIN pg_namespace n ON n.oid = p.pronamespace
      JOIN pg_language language ON language.oid = p.prolang
     WHERE n.nspname = 'iam'
       AND NOT (
           p.proname = 'set_updated_at_technical'
           AND pg_get_function_identity_arguments(p.oid) = ''
           AND p.prorettype = 'trigger'::regtype
           AND language.lanname = 'plpgsql'
           AND NOT p.prosecdef
       );

    SELECT string_agg(p.proname, ', ' ORDER BY p.proname)
      INTO public_routine_execute
      FROM pg_proc p
      JOIN pg_namespace n ON n.oid = p.pronamespace
     WHERE n.nspname = 'iam'
       AND EXISTS (
           SELECT 1
           FROM aclexplode(coalesce(p.proacl, acldefault('f', p.proowner))) acl
           WHERE acl.grantee = 0
             AND acl.privilege_type = 'EXECUTE'
       );

    SELECT string_agg(t.typname, ', ' ORDER BY t.typname)
      INTO enums
      FROM pg_type t
      JOIN pg_namespace n ON n.oid = t.typnamespace
     WHERE n.nspname = 'iam' AND t.typtype = 'e';

    SELECT string_agg(c.relname, ', ' ORDER BY c.relname)
      INTO views
      FROM pg_class c
      JOIN pg_namespace n ON n.oid = c.relnamespace
     WHERE n.nspname = 'iam' AND c.relkind IN ('v','m');

    IF invalid_triggers IS NOT NULL OR missing_updated_at_triggers IS NOT NULL OR invalid_routines IS NOT NULL
       OR public_routine_execute IS NOT NULL OR enums IS NOT NULL OR views IS NOT NULL THEN
        RAISE EXCEPTION '数据库对象边界门禁失败：invalid_trigger=%, missing_updated_at_trigger=%, invalid_routine=%, public_execute=%, enum=%, view=%',
            coalesce(invalid_triggers, '<none>'), coalesce(missing_updated_at_triggers, '<none>'), coalesce(invalid_routines, '<none>'),
            coalesce(public_routine_execute, '<none>'), coalesce(enums, '<none>'), coalesce(views, '<none>');
    END IF;
END
$database_object_boundary$;

SELECT 'PASS: 仅存在白名单 updated_at 技术 Trigger；不存在业务 Routine、Enum、View 或 Materialized View' AS result;
