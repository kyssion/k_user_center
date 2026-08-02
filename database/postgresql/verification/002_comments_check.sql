\set ON_ERROR_STOP on

DO $comments_check$
DECLARE
    missing_table_comments text;
    missing_column_comments text;
BEGIN
    SELECT string_agg(c.relname, ', ' ORDER BY c.relname)
      INTO missing_table_comments
      FROM pg_class c
      JOIN pg_namespace n ON n.oid = c.relnamespace
     WHERE n.nspname = 'iam'
       AND c.relkind IN ('r','p')
       AND obj_description(c.oid, 'pg_class') IS NULL;

    SELECT string_agg(format('%I.%I', c.relname, a.attname), ', ' ORDER BY c.relname, a.attnum)
      INTO missing_column_comments
      FROM pg_class c
      JOIN pg_namespace n ON n.oid = c.relnamespace
      JOIN pg_attribute a ON a.attrelid = c.oid
     WHERE n.nspname = 'iam'
       AND c.relkind IN ('r','p')
       AND NOT c.relispartition
       AND a.attnum > 0
       AND NOT a.attisdropped
       AND col_description(c.oid, a.attnum) IS NULL;

    IF missing_table_comments IS NOT NULL OR missing_column_comments IS NOT NULL THEN
        RAISE EXCEPTION 'Comment 门禁失败：tables=%, columns=%', coalesce(missing_table_comments, '<none>'), coalesce(missing_column_comments, '<none>');
    END IF;
END
$comments_check$;

SELECT 'PASS: 所有父表、分区表和父表字段均有 Comment' AS result;
