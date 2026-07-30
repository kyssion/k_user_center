-- PostgreSQL 16+ preflight. This migration validates the target and changes
-- only the current psql session; instance/database settings remain DBA-owned.

SET TIME ZONE 'UTC';

BEGIN;

SET LOCAL search_path = pg_catalog, public;

DO $preflight$
DECLARE
    database_timezone text;
BEGIN
    IF current_setting('server_version_num')::integer < 160000 THEN
        RAISE EXCEPTION
            USING
                ERRCODE = '0A000',
                MESSAGE = format(
                    'PostgreSQL 16 or later is required; connected server reports %s',
                    current_setting('server_version')
                );
    END IF;

    IF pg_catalog.getdatabaseencoding() <> 'UTF8' THEN
        RAISE EXCEPTION
            USING
                ERRCODE = '22023',
                MESSAGE = format(
                    'database %I must use UTF8 encoding; current encoding is %s',
                    current_database(),
                    pg_catalog.getdatabaseencoding()
                );
    END IF;

    IF current_setting('TimeZone') <> 'UTC' THEN
        RAISE EXCEPTION
            USING
                ERRCODE = '22023',
                MESSAGE = format(
                    'migration session must use UTC; current setting is %s',
                    current_setting('TimeZone')
                );
    END IF;

    SELECT pg_catalog.split_part(setting, '=', 2)
      INTO database_timezone
      FROM pg_catalog.pg_db_role_setting AS settings
      CROSS JOIN LATERAL pg_catalog.unnest(settings.setconfig) AS config(setting)
     WHERE settings.setdatabase = (
               SELECT db.oid
                 FROM pg_catalog.pg_database AS db
                WHERE db.datname = current_database()
           )
       AND settings.setrole = 0
       AND pg_catalog.lower(pg_catalog.split_part(setting, '=', 1)) = 'timezone'
     LIMIT 1;

    IF database_timezone IS NULL OR pg_catalog.upper(database_timezone) <> 'UTC' THEN
        RAISE NOTICE '%',
            format(
                'database-level UTC is not configured (current database setting: %s). DBA may run: ALTER DATABASE %I SET timezone TO %L;',
                coalesce(database_timezone, '<inherit server/role default>'),
                current_database(),
                'UTC'
            );
    END IF;
END
$preflight$;

COMMIT;
