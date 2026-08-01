-- =============================================================================
-- 070_migration_catalog_comments.sql
-- 旧系统迁移、双轨权威、反向 CDC、对账，以及全库列注释与数据字典
-- =============================================================================

BEGIN;
SET LOCAL lock_timeout = '10s';
SET LOCAL statement_timeout = '5min';

CREATE TABLE migration.migration_batch (
    id                    uuid        NOT NULL DEFAULT gen_random_uuid(),
    public_id             text        NOT NULL,
    batch_code            text        NOT NULL,
    source_system_code    text        NOT NULL,
    object_kind           text        NOT NULL,
    migration_batch_state text        NOT NULL DEFAULT 'DISCOVERED',
    operation_id          uuid        NOT NULL,
    source_snapshot_ref   text        NOT NULL,
    source_snapshot_hash  bytea       NOT NULL,
    authority_side        text        NOT NULL DEFAULT 'LEGACY',
    rollback_deadline_at  timestamptz NOT NULL,
    irreversible_at       timestamptz NULL,
    cutover_at            timestamptz NULL,
    observing_until       timestamptz NULL,
    completed_at          timestamptz NULL,
    paused_reason_code    text        NULL,
    created_at            timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at            timestamptz NOT NULL DEFAULT clock_timestamp(),
    row_version           bigint      NOT NULL DEFAULT 1,
    CONSTRAINT pk_migration_batch PRIMARY KEY (id),
    CONSTRAINT uq_migration_batch_public_id UNIQUE (public_id),
    CONSTRAINT uq_migration_batch_code UNIQUE (batch_code),
    CONSTRAINT uq_migration_batch_operation UNIQUE (operation_id),
    CONSTRAINT fk_migration_batch_operation FOREIGN KEY (operation_id) REFERENCES core.async_operation(id),
    CONSTRAINT ck_migration_batch_state CHECK (migration_batch_state IN ('DISCOVERED', 'CLEANSED', 'MAPPED', 'SHADOW', 'CANARY', 'CUTOVER', 'OBSERVING', 'COMPLETE', 'PAUSED', 'ROLLED_BACK')),
    CONSTRAINT ck_migration_batch_authority CHECK (authority_side IN ('LEGACY', 'PLATFORM')),
    CONSTRAINT ck_migration_batch_hash CHECK (octet_length(source_snapshot_hash) = 32),
    CONSTRAINT ck_migration_batch_deadline CHECK (rollback_deadline_at > created_at),
    CONSTRAINT ck_migration_batch_cutover CHECK (migration_batch_state NOT IN ('CUTOVER', 'OBSERVING', 'COMPLETE') OR cutover_at IS NOT NULL),
    CONSTRAINT ck_migration_batch_complete CHECK ((migration_batch_state = 'COMPLETE') = (completed_at IS NOT NULL)),
    CONSTRAINT ck_migration_batch_pause CHECK (migration_batch_state <> 'PAUSED' OR paused_reason_code IS NOT NULL)
);
COMMENT ON TABLE migration.migration_batch IS 'REQ-MIG-001 至 010：发现、清洗、映射、影子、灰度、切换、观察、完成与回滚边界明确的迁移批次。';

CREATE TABLE migration.authority_lease (
    id                    uuid        NOT NULL DEFAULT gen_random_uuid(),
    migration_batch_id    uuid        NOT NULL,
    object_kind           text        NOT NULL,
    scope_hash            bytea       NOT NULL,
    authority_side        text        NOT NULL,
    lease_token_hash      bytea       NOT NULL,
    fencing_token         bigint      NOT NULL,
    acquired_at           timestamptz NOT NULL DEFAULT clock_timestamp(),
    expires_at            timestamptz NOT NULL,
    released_at           timestamptz NULL,
    CONSTRAINT pk_authority_lease PRIMARY KEY (id),
    CONSTRAINT uq_authority_lease_fence UNIQUE (object_kind, scope_hash, fencing_token),
    CONSTRAINT fk_authority_lease_batch FOREIGN KEY (migration_batch_id) REFERENCES migration.migration_batch(id),
    CONSTRAINT ck_authority_lease_side CHECK (authority_side IN ('LEGACY', 'PLATFORM')),
    CONSTRAINT ck_authority_lease_hash CHECK (octet_length(scope_hash) = 32 AND octet_length(lease_token_hash) = 32),
    CONSTRAINT ck_authority_lease_fence CHECK (fencing_token >= 1),
    CONSTRAINT ck_authority_lease_window CHECK (expires_at > acquired_at)
);
COMMENT ON TABLE migration.authority_lease IS 'REQ-MIG-002：每类/范围数据唯一权威写入方的租约与 fencing token，阻断双主写入。';

CREATE TABLE migration.legacy_id_mapping (
    id                    uuid        NOT NULL DEFAULT gen_random_uuid(),
    migration_batch_id    uuid        NOT NULL,
    source_system_code    text        NOT NULL,
    object_kind           text        NOT NULL,
    legacy_id_hash        bytea       NOT NULL,
    legacy_id_ciphertext  bytea       NOT NULL,
    platform_id           uuid        NOT NULL,
    platform_public_id    text        NULL,
    mapping_confidence    numeric(5,4) NOT NULL DEFAULT 1,
    mapping_method        text        NOT NULL,
    mapped_at             timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT pk_legacy_id_mapping PRIMARY KEY (id),
    CONSTRAINT uq_legacy_id_mapping_source UNIQUE (source_system_code, object_kind, legacy_id_hash),
    CONSTRAINT uq_legacy_id_mapping_target UNIQUE (migration_batch_id, object_kind, platform_id),
    CONSTRAINT fk_legacy_id_mapping_batch FOREIGN KEY (migration_batch_id) REFERENCES migration.migration_batch(id),
    CONSTRAINT ck_legacy_id_mapping_hash CHECK (octet_length(legacy_id_hash) = 32),
    CONSTRAINT ck_legacy_id_mapping_confidence CHECK (mapping_confidence BETWEEN 0 AND 1),
    CONSTRAINT ck_legacy_id_mapping_method CHECK (mapping_method IN ('CREATED', 'VERIFIED_LINK', 'MANUAL_APPROVAL', 'RULE_BASED', 'IMPORT_REFERENCE'))
);
COMMENT ON TABLE migration.legacy_id_mapping IS 'REQ-MIG-001：加密保存的旧 ID 到新内部 ID/公开 ID 的永久可追溯映射；旧 ID 不进入新主键语义。';

CREATE TABLE migration.duplicate_candidate (
    id                    uuid        NOT NULL DEFAULT gen_random_uuid(),
    migration_batch_id    uuid        NOT NULL,
    candidate_state       text        NOT NULL DEFAULT 'OPEN',
    left_object_ref       text        NOT NULL,
    right_object_ref      text        NOT NULL,
    match_signal_hashes   bytea[]     NOT NULL,
    confidence            numeric(5,4) NOT NULL,
    resolution_kind       text        NULL,
    resolved_by_ref       text        NULL,
    approval_case_id      uuid        NULL,
    resolved_at           timestamptz NULL,
    created_at            timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT pk_duplicate_candidate PRIMARY KEY (id),
    CONSTRAINT uq_duplicate_candidate UNIQUE (migration_batch_id, left_object_ref, right_object_ref),
    CONSTRAINT fk_duplicate_candidate_batch FOREIGN KEY (migration_batch_id) REFERENCES migration.migration_batch(id),
    CONSTRAINT fk_duplicate_candidate_approval FOREIGN KEY (approval_case_id) REFERENCES control.approval_case(id),
    CONSTRAINT ck_duplicate_candidate_distinct CHECK (left_object_ref <> right_object_ref),
    CONSTRAINT ck_duplicate_candidate_state CHECK (candidate_state IN ('OPEN', 'REVIEWING', 'RESOLVED', 'DISMISSED')),
    CONSTRAINT ck_duplicate_candidate_confidence CHECK (confidence BETWEEN 0 AND 1),
    CONSTRAINT ck_duplicate_candidate_resolution CHECK (resolution_kind IS NULL OR resolution_kind IN ('KEEP_SEPARATE', 'LINK_EXTERNAL', 'MERGE_APPROVED', 'FALSE_POSITIVE')),
    CONSTRAINT ck_duplicate_candidate_resolved CHECK (candidate_state NOT IN ('RESOLVED', 'DISMISSED') OR (resolved_at IS NOT NULL AND resolved_by_ref IS NOT NULL AND resolution_kind IS NOT NULL))
);
COMMENT ON TABLE migration.duplicate_candidate IS 'REQ-MIG-004：迁移判重只生成候选与证据；禁止仅按手机号、邮箱或姓名静默合并。';

CREATE TABLE migration.change_log (
    id                    uuid        NOT NULL DEFAULT gen_random_uuid(),
    migration_batch_id    uuid        NOT NULL,
    change_sequence       bigint      NOT NULL,
    authority_side        text        NOT NULL,
    object_kind           text        NOT NULL,
    object_ref            text        NOT NULL,
    object_version        bigint      NOT NULL,
    change_kind           text        NOT NULL,
    idempotency_key       text        NOT NULL,
    change_payload_ciphertext bytea   NOT NULL,
    change_hash           bytea       NOT NULL,
    previous_change_hash  bytea       NULL,
    occurred_at           timestamptz NOT NULL,
    applied_to_other_side_at timestamptz NULL,
    apply_state           text        NOT NULL DEFAULT 'PENDING',
    conflict_reason_code  text        NULL,
    created_at            timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT pk_change_log PRIMARY KEY (id),
    CONSTRAINT uq_change_log_sequence UNIQUE (migration_batch_id, change_sequence),
    CONSTRAINT uq_change_log_key UNIQUE (migration_batch_id, idempotency_key),
    CONSTRAINT fk_change_log_batch FOREIGN KEY (migration_batch_id) REFERENCES migration.migration_batch(id),
    CONSTRAINT ck_change_log_side CHECK (authority_side IN ('LEGACY', 'PLATFORM')),
    CONSTRAINT ck_change_log_version CHECK (object_version >= 1 AND change_sequence >= 1),
    CONSTRAINT ck_change_log_kind CHECK (change_kind IN ('CREATE', 'UPDATE', 'STATE_CHANGE', 'DELETE', 'ANONYMIZE', 'TOMBSTONE')),
    CONSTRAINT ck_change_log_hash CHECK (octet_length(change_hash) = 32 AND (previous_change_hash IS NULL OR octet_length(previous_change_hash) = 32)),
    CONSTRAINT ck_change_log_state CHECK (apply_state IN ('PENDING', 'APPLIED', 'CONFLICT', 'SKIPPED', 'FAILED')),
    CONSTRAINT ck_change_log_conflict CHECK (apply_state <> 'CONFLICT' OR conflict_reason_code IS NOT NULL)
);
COMMENT ON TABLE migration.change_log IS 'REQ-MIG-008/009：切换后不可变、有序、版本化、幂等、带权威来源与哈希链的反向 CDC/受控重放日志。';

CREATE TABLE migration.reconciliation_run (
    id                    uuid        NOT NULL DEFAULT gen_random_uuid(),
    public_id             text        NOT NULL,
    migration_batch_id    uuid        NOT NULL,
    operation_id          uuid        NOT NULL,
    reconciliation_state  text        NOT NULL DEFAULT 'PENDING',
    expected_count        bigint      NOT NULL,
    actual_count          bigint      NOT NULL DEFAULT 0,
    missing_count         bigint      NOT NULL DEFAULT 0,
    duplicate_count       bigint      NOT NULL DEFAULT 0,
    mismatch_count        bigint      NOT NULL DEFAULT 0,
    exception_count       bigint      NOT NULL DEFAULT 0,
    details_uri           text        NULL,
    details_hash          bytea       NULL,
    started_at            timestamptz NULL,
    completed_at          timestamptz NULL,
    created_at            timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT pk_reconciliation_run PRIMARY KEY (id),
    CONSTRAINT uq_reconciliation_run_public_id UNIQUE (public_id),
    CONSTRAINT uq_reconciliation_run_operation UNIQUE (operation_id),
    CONSTRAINT fk_reconciliation_run_batch FOREIGN KEY (migration_batch_id) REFERENCES migration.migration_batch(id),
    CONSTRAINT fk_reconciliation_run_operation FOREIGN KEY (operation_id) REFERENCES core.async_operation(id),
    CONSTRAINT ck_reconciliation_run_state CHECK (reconciliation_state IN ('PENDING', 'RUNNING', 'COMPLETED', 'FAILED', 'BLOCKED')),
    CONSTRAINT ck_reconciliation_run_counts CHECK (expected_count >= 0 AND actual_count >= 0 AND missing_count >= 0 AND duplicate_count >= 0 AND mismatch_count >= 0 AND exception_count >= 0),
    CONSTRAINT ck_reconciliation_run_hash CHECK (details_hash IS NULL OR octet_length(details_hash) = 32),
    CONSTRAINT ck_reconciliation_run_complete CHECK (reconciliation_state <> 'COMPLETED' OR completed_at IS NOT NULL)
);
COMMENT ON TABLE migration.reconciliation_run IS 'REQ-MIG-005：每批数量、唯一性、状态、身份、凭证、Membership 和审批例外的对账证据。';

CREATE TABLE migration.rollback_execution (
    id                    uuid        NOT NULL DEFAULT gen_random_uuid(),
    public_id             text        NOT NULL,
    migration_batch_id    uuid        NOT NULL,
    operation_id          uuid        NOT NULL,
    approval_case_id      uuid        NOT NULL,
    rollback_state        text        NOT NULL DEFAULT 'PENDING',
    stopped_writes_at     timestamptz NULL,
    drained_changes_at    timestamptz NULL,
    reverse_sync_at       timestamptz NULL,
    reconciled_at         timestamptz NULL,
    traffic_switched_at   timestamptz NULL,
    completed_at          timestamptz NULL,
    failure_code          text        NULL,
    created_at            timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT pk_rollback_execution PRIMARY KEY (id),
    CONSTRAINT uq_rollback_execution_public_id UNIQUE (public_id),
    CONSTRAINT uq_rollback_execution_operation UNIQUE (operation_id),
    CONSTRAINT fk_rollback_execution_batch FOREIGN KEY (migration_batch_id) REFERENCES migration.migration_batch(id),
    CONSTRAINT fk_rollback_execution_operation FOREIGN KEY (operation_id) REFERENCES core.async_operation(id),
    CONSTRAINT fk_rollback_execution_approval FOREIGN KEY (approval_case_id) REFERENCES control.approval_case(id),
    CONSTRAINT ck_rollback_execution_state CHECK (rollback_state IN ('PENDING', 'STOPPING_WRITES', 'DRAINING', 'REVERSE_SYNCING', 'RECONCILING', 'SWITCHING', 'COMPLETED', 'PAUSED', 'FAILED', 'FORWARD_FIX_REQUIRED')),
    CONSTRAINT ck_rollback_execution_complete CHECK ((rollback_state = 'COMPLETED') = (completed_at IS NOT NULL)),
    CONSTRAINT ck_rollback_execution_failure CHECK (rollback_state NOT IN ('FAILED', 'FORWARD_FIX_REQUIRED') OR failure_code IS NOT NULL)
);
COMMENT ON TABLE migration.rollback_execution IS 'REQ-MIG-010：停止写入、排空、反向同步、对账、切换和恢复流量的有序回滚执行证据。';

CREATE UNIQUE INDEX ux_authority_lease_active ON migration.authority_lease(object_kind, scope_hash) WHERE released_at IS NULL;
CREATE INDEX ix_change_log_apply ON migration.change_log(migration_batch_id, change_sequence) WHERE apply_state IN ('PENDING', 'FAILED');
CREATE INDEX ix_reconciliation_batch ON migration.reconciliation_run(migration_batch_id, created_at DESC);

CREATE OR REPLACE FUNCTION migration.fn_batch_state_guard()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF OLD.migration_batch_state = 'COMPLETE' AND NEW.migration_batch_state <> 'COMPLETE' THEN
        RAISE EXCEPTION 'INVALID_STATE_TRANSITION: COMPLETE migration batch 不得恢复' USING ERRCODE = '23514';
    END IF;
    IF OLD.irreversible_at IS NOT NULL AND NEW.migration_batch_state = 'ROLLED_BACK' THEN
        RAISE EXCEPTION 'FORWARD_FIX_REQUIRED: 已越过不可逆边界' USING ERRCODE = '23514';
    END IF;
    IF NEW.migration_batch_state IN ('CUTOVER', 'OBSERVING', 'COMPLETE') AND NEW.authority_side <> 'PLATFORM' THEN
        RAISE EXCEPTION 'MIGRATION_AUTHORITY_NOT_PLATFORM' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;
COMMENT ON FUNCTION migration.fn_batch_state_guard() IS '迁移完成不可恢复、不可逆边界后禁止伪回滚，切换后平台必须成为权威写入方。';

CREATE OR REPLACE FUNCTION migration.fn_change_log_immutable_guard()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN RAISE EXCEPTION 'MIGRATION_CHANGE_DELETE_FORBIDDEN' USING ERRCODE = '55000'; END IF;
    IF NEW.migration_batch_id <> OLD.migration_batch_id OR NEW.change_sequence <> OLD.change_sequence
       OR NEW.authority_side <> OLD.authority_side OR NEW.object_kind <> OLD.object_kind OR NEW.object_ref <> OLD.object_ref
       OR NEW.object_version <> OLD.object_version OR NEW.change_kind <> OLD.change_kind
       OR NEW.idempotency_key <> OLD.idempotency_key OR NEW.change_payload_ciphertext <> OLD.change_payload_ciphertext
       OR NEW.change_hash <> OLD.change_hash OR NEW.previous_change_hash IS DISTINCT FROM OLD.previous_change_hash THEN
        RAISE EXCEPTION 'MIGRATION_CHANGE_IMMUTABLE' USING ERRCODE = '55000';
    END IF;
    RETURN NEW;
END;
$$;
COMMENT ON FUNCTION migration.fn_change_log_immutable_guard() IS '迁移变更内容、顺序、版本、幂等键和哈希链不可修改；仅允许推进应用结果。';

CREATE OR REPLACE FUNCTION core.fn_apply_complete_column_comments()
RETURNS integer
LANGUAGE plpgsql
AS $$
DECLARE r record; v_description text; v_count integer := 0;
BEGIN
    FOR r IN
        SELECT n.nspname AS schema_name, c.relname AS table_name, a.attname AS column_name,
               format_type(a.atttypid, a.atttypmod) AS data_type,
               obj_description(c.oid, 'pg_class') AS table_description
          FROM pg_class c
          JOIN pg_namespace n ON n.oid = c.relnamespace
          JOIN pg_attribute a ON a.attrelid = c.oid
         WHERE n.nspname = ANY(ARRAY['core','iam','authn','oauth','org','authz','profile','privacy','federation','risk','workload','assurance','crypto','control','integration','audit','messaging','migration'])
           AND c.relkind IN ('r','p') AND a.attnum > 0 AND NOT a.attisdropped
           AND col_description(c.oid, a.attnum) IS NULL
         ORDER BY n.nspname, c.relname, a.attnum
    LOOP
        v_description := CASE
            WHEN r.column_name = 'id' THEN '内部主键 UUID；仅用于数据库关系，不作为跨域公开标识。'
            WHEN r.column_name = 'public_id' THEN '不可复用的公开稳定标识；插入时登记到 core.public_id_ledger。'
            WHEN r.column_name = 'tenant_id' THEN '租户隔离键；全零 UUID 表示平台范围，应用查询必须显式携带可信租户上下文。'
            WHEN r.column_name = 'business_line_id' THEN '业务线隔离键；引用 org.business_line。'
            WHEN r.column_name = 'row_version' THEN '乐观并发版本；更新必须使用原值 compare-and-set，成功后单调递增。'
            WHEN r.column_name LIKE '%\_epoch' ESCAPE '\' OR r.column_name LIKE '%\_epoch\_at\_%' ESCAPE '\' THEN '安全或同意水位版本；只能单调递增，用于 Token、缓存和撤销新鲜度校验。'
            WHEN r.column_name LIKE '%\_state' ESCAPE '\' THEN '显式状态机当前值；合法取值与转换见本表 CHECK、触发器及蓝图。'
            WHEN r.column_name LIKE '%\_hash' ESCAPE '\' OR r.column_name LIKE '%\_hashes' ESCAPE '\'
              OR r.column_name LIKE '%\_digest' ESCAPE '\' THEN '不可逆摘要；用于等值匹配、幂等、完整性或最小化证据，不保存原始敏感值。'
            WHEN r.column_name LIKE '%\_ciphertext' ESCAPE '\' OR r.column_name LIKE '%\_cipher' ESCAPE '\'
              OR r.column_name LIKE 'encrypted\_%' ESCAPE '\' THEN '随机化加密密文；解密密钥由独立 KMS/HSM 引用管理。'
            WHEN r.column_name LIKE '%\_blind\_index' ESCAPE '\' THEN '带版本的密钥化盲索引；只用于受控等值检索，不可作为所有权唯一性摘要。'
            WHEN r.column_name LIKE '%\_key\_ref' ESCAPE '\' OR r.column_name LIKE '%\_key\_id' ESCAPE '\' THEN '外部 KMS/HSM 或受控密钥资产引用；不是私钥或 Secret 明文。'
            WHEN r.column_name LIKE '%\_key\_version' ESCAPE '\' THEN '生成密文、HMAC 或盲索引所用密钥版本；轮换时必须保留可验证窗口。'
            WHEN r.column_name LIKE '%\_algorithm' ESCAPE '\' THEN '显式算法标识；必须来自环境算法 allowlist，禁止 none、弱算法和静默降级。'
            WHEN r.column_name LIKE '%\_id' ESCAPE '\' THEN '关联对象内部 UUID；具体目标由外键或字段语义限定。'
            WHEN r.column_name LIKE '%\_at' ESCAPE '\' OR r.column_name LIKE '%\_until' ESCAPE '\' THEN '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。'
            WHEN r.column_name LIKE '%\_count' ESCAPE '\' OR r.column_name LIKE '%\_attempt' ESCAPE '\' THEN '非负计数器；并发更新需使用原子 SQL 或乐观锁。'
            WHEN r.column_name LIKE '%\_seconds' ESCAPE '\' THEN '以秒为单位的显式时长；上限由 Security Profile、时长策略和表约束共同限制。'
            WHEN r.column_name LIKE '%\_version' ESCAPE '\' THEN '对象、Schema、策略或源数据的显式版本；不得以不可信客户端时间戳替代。'
            WHEN r.column_name LIKE '%\_code' ESCAPE '\' THEN '稳定机器可读代码；展示文本应通过资源或目录解析。'
            WHEN r.column_name LIKE '%\_kind' ESCAPE '\' OR r.column_name LIKE '%\_type' ESCAPE '\' THEN '对象类别判别字段；允许值由 CHECK 或对应注册表约束。'
            WHEN r.column_name LIKE '%\_ref' ESCAPE '\' THEN '不透明对象引用；不得假定其可解析为手机号、邮箱或其他业务事实。'
            WHEN r.column_name LIKE '%\_uri' ESCAPE '\' THEN '受控 URI；写入前必须执行协议、主机、重定向和 SSRF 安全校验。'
            WHEN r.column_name LIKE 'is\_%' ESCAPE '\' OR r.column_name LIKE 'has\_%' ESCAPE '\'
              OR r.column_name LIKE '%\_enabled' ESCAPE '\' THEN '显式布尔开关；默认值、启用前置条件和失效行为由本表约束及版本化策略控制。'
            WHEN r.data_type LIKE '%[]' THEN '有序或集合型代码列表；写入前必须去重、校验 allowlist，并遵守表约束定义的包含关系。'
            WHEN r.data_type = 'jsonb' THEN '版本化结构化扩展数据；必须通过对应 JSON Schema 校验，不得替代核心状态、租户键、外键或安全 epoch。'
            ELSE format('%s；列 %s（%s）承载该记录的领域属性，写入方必须满足本表约束、数据分类、保留与审计规则。',
                        COALESCE(r.table_description, r.schema_name || '.' || r.table_name), r.column_name, r.data_type)
        END;
        EXECUTE format('COMMENT ON COLUMN %I.%I.%I IS %L', r.schema_name, r.table_name, r.column_name, v_description);
        v_count := v_count + 1;
    END LOOP;
    RETURN v_count;
END;
$$;
COMMENT ON FUNCTION core.fn_apply_complete_column_comments() IS '为平台所有基表中尚未显式注释的列补充非空数据字典注释；迁移末尾和 CI 均可重复执行。';

CREATE VIEW core.data_dictionary AS
SELECT n.nspname AS schema_name,
       c.relname AS table_name,
       obj_description(c.oid, 'pg_class') AS table_description,
       a.attnum AS ordinal_position,
       a.attname AS column_name,
       format_type(a.atttypid, a.atttypmod) AS data_type,
       a.attnotnull AS is_not_null,
       pg_get_expr(ad.adbin, ad.adrelid) AS default_expression,
       col_description(c.oid, a.attnum) AS column_description
  FROM pg_class c
  JOIN pg_namespace n ON n.oid = c.relnamespace
  JOIN pg_attribute a ON a.attrelid = c.oid
  LEFT JOIN pg_attrdef ad ON ad.adrelid = c.oid AND ad.adnum = a.attnum
 WHERE n.nspname = ANY(ARRAY['core','iam','authn','oauth','org','authz','profile','privacy','federation','risk','workload','assurance','crypto','control','integration','audit','messaging','migration'])
   AND c.relkind IN ('r','p') AND a.attnum > 0 AND NOT a.attisdropped;
COMMENT ON VIEW core.data_dictionary IS '全库 Schema、表、表描述、列序、类型、空值、默认值和列描述的可查询数据字典。';

CREATE TRIGGER trg_migration_batch_public_id BEFORE INSERT ON migration.migration_batch FOR EACH ROW EXECUTE FUNCTION core.fn_register_public_id('MIGRATION_BATCH');
CREATE TRIGGER trg_migration_batch_guard BEFORE UPDATE ON migration.migration_batch FOR EACH ROW EXECUTE FUNCTION migration.fn_batch_state_guard();
CREATE TRIGGER trg_migration_batch_touch BEFORE UPDATE ON migration.migration_batch FOR EACH ROW EXECUTE FUNCTION core.fn_touch_updated_at();
CREATE TRIGGER trg_migration_batch_version BEFORE UPDATE ON migration.migration_batch FOR EACH ROW EXECUTE FUNCTION core.fn_increment_row_version();
CREATE TRIGGER trg_legacy_mapping_append_only BEFORE UPDATE OR DELETE ON migration.legacy_id_mapping FOR EACH STATEMENT EXECUTE FUNCTION core.fn_append_only();
CREATE TRIGGER trg_change_log_immutable BEFORE UPDATE OR DELETE ON migration.change_log FOR EACH ROW EXECUTE FUNCTION migration.fn_change_log_immutable_guard();
CREATE TRIGGER trg_reconciliation_public_id BEFORE INSERT ON migration.reconciliation_run FOR EACH ROW EXECUTE FUNCTION core.fn_register_public_id('RECONCILIATION_RUN');
CREATE TRIGGER trg_rollback_public_id BEFORE INSERT ON migration.rollback_execution FOR EACH ROW EXECUTE FUNCTION core.fn_register_public_id('ROLLBACK_EXECUTION');

SELECT core.fn_apply_complete_column_comments();
SELECT core.fn_register_migration('070', '迁移双轨、映射、反向 CDC、对账、回滚与全库数据字典', NULLIF(current_setting('kuc.migration_sha256', true), ''));
COMMIT;
