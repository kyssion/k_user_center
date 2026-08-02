\set ON_ERROR_STOP on

DO $forbidden_objects$
DECLARE
    foreign_keys text;
    triggers text;
    routines text;
    enums text;
BEGIN
    SELECT string_agg(con.conname, ', ' ORDER BY con.conname)
      INTO foreign_keys
      FROM pg_constraint con
      JOIN pg_class c ON c.oid = con.conrelid
      JOIN pg_namespace n ON n.oid = c.relnamespace
     WHERE n.nspname = 'iam' AND con.contype = 'f';

    SELECT string_agg(t.tgname, ', ' ORDER BY t.tgname)
      INTO triggers
      FROM pg_trigger t
      JOIN pg_class c ON c.oid = t.tgrelid
      JOIN pg_namespace n ON n.oid = c.relnamespace
     WHERE n.nspname = 'iam' AND NOT t.tgisinternal;

    SELECT string_agg(p.proname, ', ' ORDER BY p.proname)
      INTO routines
      FROM pg_proc p
      JOIN pg_namespace n ON n.oid = p.pronamespace
     WHERE n.nspname = 'iam';

    SELECT string_agg(t.typname, ', ' ORDER BY t.typname)
      INTO enums
      FROM pg_type t
      JOIN pg_namespace n ON n.oid = t.typnamespace
     WHERE n.nspname = 'iam' AND t.typtype = 'e';

    IF foreign_keys IS NOT NULL OR triggers IS NOT NULL OR routines IS NOT NULL OR enums IS NOT NULL THEN
        RAISE EXCEPTION '禁止对象门禁失败：fk=%, trigger=%, routine=%, enum=%',
            coalesce(foreign_keys, '<none>'), coalesce(triggers, '<none>'), coalesce(routines, '<none>'), coalesce(enums, '<none>');
    END IF;
END
$forbidden_objects$;

SELECT 'PASS: 不存在 FK、业务 Trigger、持久化 Routine 或 Enum' AS result;

