\set ON_ERROR_STOP on

SET ROLE iam_owner;

-- 作为全局去重键或逻辑关系目标的高容量标识采用 Hash 分区，数据库直接保证唯一性。
-- 该 DO 块只创建物理分区，不承载状态、授权或流程逻辑。
DO $hash_partition_setup$
DECLARE
    item record;
    remainder_no integer;
    partition_name text;
BEGIN
    FOR item IN
        SELECT * FROM (VALUES
            ('outbox_events', 'event_id'),
            ('inbox_messages', 'consumer_id + event_id'),
            ('access_token_records', 'jti'),
            ('audit_events', 'event_id'),
            ('authorization_decisions', 'decision_id'),
            ('risk_signals', 'signal_id'),
            ('webhook_deliveries', 'delivery_id'),
            ('message_requests', 'request_id')
        ) AS partitioned_table(table_name, key_label)
    LOOP
        FOR remainder_no IN 0..7 LOOP
            partition_name := item.table_name || '_h' || lpad(remainder_no::text, 2, '0');
            EXECUTE format(
                'CREATE TABLE IF NOT EXISTS %I.%I PARTITION OF %I.%I FOR VALUES WITH (MODULUS 8, REMAINDER %s)',
                'iam', partition_name, 'iam', item.table_name, remainder_no
            );
            EXECUTE format(
                'COMMENT ON TABLE %I.%I IS %L',
                'iam', partition_name,
                item.table_name || ' 按 ' || item.key_label || ' 的 Hash 分区 ' || remainder_no || '/8。'
            );
        END LOOP;
    END LOOP;
END
$hash_partition_setup$;

-- 首次部署创建上月、当前月及未来 24 个月，并创建兜底分区。
-- 该 DO 块只在 Migration 会话执行，不创建持久化 Routine，也不承载业务逻辑。
DO $partition_setup$
DECLARE
    item record;
    month_start date;
    month_end date;
    partition_name text;
    offset_no integer;
BEGIN
    FOR item IN
        SELECT * FROM (VALUES
            ('authentication_attempts', 'occurred_at'),
            ('workload_attestations', 'received_at'),
            ('webhook_delivery_attempts', 'created_at'),
            ('message_delivery_attempts', 'created_at'),
            ('migration_change_logs', 'recorded_at')
        ) AS partitioned_table(table_name, partition_column)
    LOOP
        FOR offset_no IN -1..24 LOOP
            month_start := (date_trunc('month', CURRENT_DATE) + make_interval(months => offset_no))::date;
            month_end := (month_start + interval '1 month')::date;
            partition_name := item.table_name || '_' || to_char(month_start, 'YYYYMM');
            EXECUTE format(
                'CREATE TABLE IF NOT EXISTS %I.%I PARTITION OF %I.%I FOR VALUES FROM (%L) TO (%L)',
                'iam', partition_name, 'iam', item.table_name, month_start, month_end
            );
            EXECUTE format(
                'COMMENT ON TABLE %I.%I IS %L',
                'iam', partition_name,
                item.table_name || ' 的 ' || to_char(month_start, 'YYYY-MM') || ' 月度 Range 分区。'
            );
        END LOOP;

        partition_name := item.table_name || '_default';
        EXECUTE format(
            'CREATE TABLE IF NOT EXISTS %I.%I PARTITION OF %I.%I DEFAULT',
            'iam', partition_name, 'iam', item.table_name
        );
        EXECUTE format(
            'COMMENT ON TABLE %I.%I IS %L',
            'iam', partition_name,
            item.table_name || ' 的兜底分区；运维必须监控并迁移其中数据。'
        );
    END LOOP;
END
$partition_setup$;
