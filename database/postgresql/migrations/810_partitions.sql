\set ON_ERROR_STOP on

SET ROLE iam_owner;

-- Outbox/Inbox 采用 Hash 分区以维持全局去重唯一键；其他高容量表采用月度 Range 分区。
CREATE TABLE IF NOT EXISTS iam.outbox_events_h00 PARTITION OF iam.outbox_events FOR VALUES WITH (MODULUS 8, REMAINDER 0);
CREATE TABLE IF NOT EXISTS iam.outbox_events_h01 PARTITION OF iam.outbox_events FOR VALUES WITH (MODULUS 8, REMAINDER 1);
CREATE TABLE IF NOT EXISTS iam.outbox_events_h02 PARTITION OF iam.outbox_events FOR VALUES WITH (MODULUS 8, REMAINDER 2);
CREATE TABLE IF NOT EXISTS iam.outbox_events_h03 PARTITION OF iam.outbox_events FOR VALUES WITH (MODULUS 8, REMAINDER 3);
CREATE TABLE IF NOT EXISTS iam.outbox_events_h04 PARTITION OF iam.outbox_events FOR VALUES WITH (MODULUS 8, REMAINDER 4);
CREATE TABLE IF NOT EXISTS iam.outbox_events_h05 PARTITION OF iam.outbox_events FOR VALUES WITH (MODULUS 8, REMAINDER 5);
CREATE TABLE IF NOT EXISTS iam.outbox_events_h06 PARTITION OF iam.outbox_events FOR VALUES WITH (MODULUS 8, REMAINDER 6);
CREATE TABLE IF NOT EXISTS iam.outbox_events_h07 PARTITION OF iam.outbox_events FOR VALUES WITH (MODULUS 8, REMAINDER 7);

CREATE TABLE IF NOT EXISTS iam.inbox_messages_h00 PARTITION OF iam.inbox_messages FOR VALUES WITH (MODULUS 8, REMAINDER 0);
CREATE TABLE IF NOT EXISTS iam.inbox_messages_h01 PARTITION OF iam.inbox_messages FOR VALUES WITH (MODULUS 8, REMAINDER 1);
CREATE TABLE IF NOT EXISTS iam.inbox_messages_h02 PARTITION OF iam.inbox_messages FOR VALUES WITH (MODULUS 8, REMAINDER 2);
CREATE TABLE IF NOT EXISTS iam.inbox_messages_h03 PARTITION OF iam.inbox_messages FOR VALUES WITH (MODULUS 8, REMAINDER 3);
CREATE TABLE IF NOT EXISTS iam.inbox_messages_h04 PARTITION OF iam.inbox_messages FOR VALUES WITH (MODULUS 8, REMAINDER 4);
CREATE TABLE IF NOT EXISTS iam.inbox_messages_h05 PARTITION OF iam.inbox_messages FOR VALUES WITH (MODULUS 8, REMAINDER 5);
CREATE TABLE IF NOT EXISTS iam.inbox_messages_h06 PARTITION OF iam.inbox_messages FOR VALUES WITH (MODULUS 8, REMAINDER 6);
CREATE TABLE IF NOT EXISTS iam.inbox_messages_h07 PARTITION OF iam.inbox_messages FOR VALUES WITH (MODULUS 8, REMAINDER 7);

COMMENT ON TABLE iam.outbox_events_h00 IS 'Outbox event_id Hash 分区 0/8。';
COMMENT ON TABLE iam.outbox_events_h01 IS 'Outbox event_id Hash 分区 1/8。';
COMMENT ON TABLE iam.outbox_events_h02 IS 'Outbox event_id Hash 分区 2/8。';
COMMENT ON TABLE iam.outbox_events_h03 IS 'Outbox event_id Hash 分区 3/8。';
COMMENT ON TABLE iam.outbox_events_h04 IS 'Outbox event_id Hash 分区 4/8。';
COMMENT ON TABLE iam.outbox_events_h05 IS 'Outbox event_id Hash 分区 5/8。';
COMMENT ON TABLE iam.outbox_events_h06 IS 'Outbox event_id Hash 分区 6/8。';
COMMENT ON TABLE iam.outbox_events_h07 IS 'Outbox event_id Hash 分区 7/8。';
COMMENT ON TABLE iam.inbox_messages_h00 IS 'Inbox consumer_id 与 event_id Hash 分区 0/8。';
COMMENT ON TABLE iam.inbox_messages_h01 IS 'Inbox consumer_id 与 event_id Hash 分区 1/8。';
COMMENT ON TABLE iam.inbox_messages_h02 IS 'Inbox consumer_id 与 event_id Hash 分区 2/8。';
COMMENT ON TABLE iam.inbox_messages_h03 IS 'Inbox consumer_id 与 event_id Hash 分区 3/8。';
COMMENT ON TABLE iam.inbox_messages_h04 IS 'Inbox consumer_id 与 event_id Hash 分区 4/8。';
COMMENT ON TABLE iam.inbox_messages_h05 IS 'Inbox consumer_id 与 event_id Hash 分区 5/8。';
COMMENT ON TABLE iam.inbox_messages_h06 IS 'Inbox consumer_id 与 event_id Hash 分区 6/8。';
COMMENT ON TABLE iam.inbox_messages_h07 IS 'Inbox consumer_id 与 event_id Hash 分区 7/8。';

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
            ('audit_events', 'recorded_at'),
            ('authentication_attempts', 'occurred_at'),
            ('access_token_records', 'issued_at'),
            ('authorization_decisions', 'decided_at'),
            ('risk_signals', 'occurred_at'),
            ('workload_attestations', 'received_at'),
            ('webhook_deliveries', 'created_at'),
            ('webhook_delivery_attempts', 'created_at'),
            ('message_requests', 'created_at'),
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

