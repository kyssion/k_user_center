-- =============================================================================
-- baseline/schemas/migration/tables.sql
-- migration Schema 的最终基表、同 Schema 约束、索引及内联 COMMENT
-- PostgreSQL 16+；应用技术栈：.NET 10 + SqlSugar
-- =============================================================================

CREATE TABLE migration.migration_batch (
    id uuid        NOT NULL DEFAULT gen_random_uuid(),
    public_id text        NOT NULL,
    batch_code text        NOT NULL,
    source_system_code text        NOT NULL,
    object_kind text        NOT NULL,
    migration_batch_state text        NOT NULL DEFAULT 'DISCOVERED',
    operation_id uuid        NOT NULL,
    source_snapshot_ref text        NOT NULL,
    source_snapshot_hash bytea       NOT NULL,
    authority_side text        NOT NULL DEFAULT 'LEGACY',
    rollback_deadline_at timestamptz NOT NULL,
    irreversible_at timestamptz NULL,
    cutover_at timestamptz NULL,
    observing_until timestamptz NULL,
    completed_at timestamptz NULL,
    paused_reason_code text        NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    row_version bigint      NOT NULL DEFAULT 1,
    paused_from_state text NULL,
    paused_at timestamptz NULL,
    rolled_back_at timestamptz NULL,
    CONSTRAINT pk_migration_batch PRIMARY KEY (id),
    CONSTRAINT uq_migration_batch_public_id UNIQUE (public_id),
    CONSTRAINT uq_migration_batch_code UNIQUE (batch_code),
    CONSTRAINT uq_migration_batch_operation UNIQUE (operation_id),
    CONSTRAINT ck_migration_batch_state CHECK (migration_batch_state IN ('DISCOVERED', 'CLEANSED', 'MAPPED', 'SHADOW', 'CANARY', 'CUTOVER', 'OBSERVING', 'COMPLETE', 'PAUSED', 'ROLLED_BACK')),
    CONSTRAINT ck_migration_batch_authority CHECK (authority_side IN ('LEGACY', 'PLATFORM')),
    CONSTRAINT ck_migration_batch_hash CHECK (octet_length(source_snapshot_hash) = 32),
    CONSTRAINT ck_migration_batch_deadline CHECK (rollback_deadline_at > created_at),
    CONSTRAINT ck_migration_batch_cutover CHECK (migration_batch_state NOT IN ('CUTOVER', 'OBSERVING', 'COMPLETE') OR cutover_at IS NOT NULL),
    CONSTRAINT ck_migration_batch_complete CHECK ((migration_batch_state = 'COMPLETE') = (completed_at IS NOT NULL)),
    CONSTRAINT ck_migration_batch_pause CHECK (migration_batch_state <> 'PAUSED' OR paused_reason_code IS NOT NULL),
    CONSTRAINT ck_migration_batch_paused_from CHECK (
    paused_from_state IS NULL OR paused_from_state IN ('DISCOVERED', 'CLEANSED', 'MAPPED', 'SHADOW', 'CANARY', 'CUTOVER', 'OBSERVING')
    ),
    CONSTRAINT ck_migration_batch_paused_state CHECK (
    migration_batch_state <> 'PAUSED' OR (paused_from_state IS NOT NULL AND paused_at IS NOT NULL)
    ),
    CONSTRAINT ck_migration_batch_rolled_back CHECK ((migration_batch_state = 'ROLLED_BACK') = (rolled_back_at IS NOT NULL))
);

COMMENT ON TABLE migration.migration_batch IS 'REQ-MIG-001 至 010：发现、清洗、映射、影子、灰度、切换、观察、完成与回滚边界明确的迁移批次。';

CREATE TABLE migration.authority_lease (
    id uuid        NOT NULL DEFAULT gen_random_uuid(),
    migration_batch_id uuid        NOT NULL,
    object_kind text        NOT NULL,
    scope_hash bytea       NOT NULL,
    authority_side text        NOT NULL,
    lease_token_hash bytea       NOT NULL,
    fencing_token bigint      NOT NULL,
    acquired_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    expires_at timestamptz NOT NULL,
    released_at timestamptz NULL,
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
    id uuid        NOT NULL DEFAULT gen_random_uuid(),
    migration_batch_id uuid        NOT NULL,
    source_system_code text        NOT NULL,
    object_kind text        NOT NULL,
    legacy_id_hash bytea       NOT NULL,
    legacy_id_ciphertext bytea       NOT NULL,
    platform_id uuid        NOT NULL,
    platform_public_id text        NULL,
    mapping_confidence numeric(5,4) NOT NULL DEFAULT 1,
    mapping_method text        NOT NULL,
    mapped_at timestamptz NOT NULL DEFAULT clock_timestamp(),
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
    id uuid        NOT NULL DEFAULT gen_random_uuid(),
    migration_batch_id uuid        NOT NULL,
    candidate_state text        NOT NULL DEFAULT 'OPEN',
    left_object_ref text        NOT NULL,
    right_object_ref text        NOT NULL,
    match_signal_hashes bytea[]     NOT NULL,
    confidence numeric(5,4) NOT NULL,
    resolution_kind text        NULL,
    resolved_by_ref text        NULL,
    approval_case_id uuid        NULL,
    resolved_at timestamptz NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT pk_duplicate_candidate PRIMARY KEY (id),
    CONSTRAINT uq_duplicate_candidate UNIQUE (migration_batch_id, left_object_ref, right_object_ref),
    CONSTRAINT fk_duplicate_candidate_batch FOREIGN KEY (migration_batch_id) REFERENCES migration.migration_batch(id),
    CONSTRAINT ck_duplicate_candidate_distinct CHECK (left_object_ref <> right_object_ref),
    CONSTRAINT ck_duplicate_candidate_state CHECK (candidate_state IN ('OPEN', 'REVIEWING', 'RESOLVED', 'DISMISSED')),
    CONSTRAINT ck_duplicate_candidate_confidence CHECK (confidence BETWEEN 0 AND 1),
    CONSTRAINT ck_duplicate_candidate_resolution CHECK (resolution_kind IS NULL OR resolution_kind IN ('KEEP_SEPARATE', 'LINK_EXTERNAL', 'MERGE_APPROVED', 'FALSE_POSITIVE')),
    CONSTRAINT ck_duplicate_candidate_resolved CHECK (candidate_state NOT IN ('RESOLVED', 'DISMISSED') OR (resolved_at IS NOT NULL AND resolved_by_ref IS NOT NULL AND resolution_kind IS NOT NULL))
);

COMMENT ON TABLE migration.duplicate_candidate IS 'REQ-MIG-004：迁移判重只生成候选与证据；禁止仅按手机号、邮箱或姓名静默合并。';

CREATE TABLE migration.change_log (
    id uuid        NOT NULL DEFAULT gen_random_uuid(),
    migration_batch_id uuid        NOT NULL,
    change_sequence bigint      NOT NULL,
    authority_side text        NOT NULL,
    object_kind text        NOT NULL,
    object_ref text        NOT NULL,
    object_version bigint      NOT NULL,
    change_kind text        NOT NULL,
    idempotency_key text        NOT NULL,
    change_payload_ciphertext bytea   NOT NULL,
    change_hash bytea       NOT NULL,
    previous_change_hash bytea       NULL,
    occurred_at timestamptz NOT NULL,
    applied_to_other_side_at timestamptz NULL,
    apply_state text        NOT NULL DEFAULT 'PENDING',
    conflict_reason_code text        NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
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
    id uuid        NOT NULL DEFAULT gen_random_uuid(),
    public_id text        NOT NULL,
    migration_batch_id uuid        NOT NULL,
    operation_id uuid        NOT NULL,
    reconciliation_state text        NOT NULL DEFAULT 'PENDING',
    expected_count bigint      NOT NULL,
    actual_count bigint      NOT NULL DEFAULT 0,
    missing_count bigint      NOT NULL DEFAULT 0,
    duplicate_count bigint      NOT NULL DEFAULT 0,
    mismatch_count bigint      NOT NULL DEFAULT 0,
    exception_count bigint      NOT NULL DEFAULT 0,
    details_uri text        NULL,
    details_hash bytea       NULL,
    started_at timestamptz NULL,
    completed_at timestamptz NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT pk_reconciliation_run PRIMARY KEY (id),
    CONSTRAINT uq_reconciliation_run_public_id UNIQUE (public_id),
    CONSTRAINT uq_reconciliation_run_operation UNIQUE (operation_id),
    CONSTRAINT fk_reconciliation_run_batch FOREIGN KEY (migration_batch_id) REFERENCES migration.migration_batch(id),
    CONSTRAINT ck_reconciliation_run_state CHECK (reconciliation_state IN ('PENDING', 'RUNNING', 'COMPLETED', 'FAILED', 'BLOCKED')),
    CONSTRAINT ck_reconciliation_run_counts CHECK (expected_count >= 0 AND actual_count >= 0 AND missing_count >= 0 AND duplicate_count >= 0 AND mismatch_count >= 0 AND exception_count >= 0),
    CONSTRAINT ck_reconciliation_run_hash CHECK (details_hash IS NULL OR octet_length(details_hash) = 32),
    CONSTRAINT ck_reconciliation_run_complete CHECK (reconciliation_state <> 'COMPLETED' OR completed_at IS NOT NULL)
);

COMMENT ON TABLE migration.reconciliation_run IS 'REQ-MIG-005：每批数量、唯一性、状态、身份、凭证、Membership 和审批例外的对账证据。';

CREATE TABLE migration.rollback_execution (
    id uuid        NOT NULL DEFAULT gen_random_uuid(),
    public_id text        NOT NULL,
    migration_batch_id uuid        NOT NULL,
    operation_id uuid        NOT NULL,
    approval_case_id uuid        NOT NULL,
    rollback_state text        NOT NULL DEFAULT 'PENDING',
    stopped_writes_at timestamptz NULL,
    drained_changes_at timestamptz NULL,
    reverse_sync_at timestamptz NULL,
    reconciled_at timestamptz NULL,
    traffic_switched_at timestamptz NULL,
    completed_at timestamptz NULL,
    failure_code text        NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT pk_rollback_execution PRIMARY KEY (id),
    CONSTRAINT uq_rollback_execution_public_id UNIQUE (public_id),
    CONSTRAINT uq_rollback_execution_operation UNIQUE (operation_id),
    CONSTRAINT fk_rollback_execution_batch FOREIGN KEY (migration_batch_id) REFERENCES migration.migration_batch(id),
    CONSTRAINT ck_rollback_execution_state CHECK (rollback_state IN ('PENDING', 'STOPPING_WRITES', 'DRAINING', 'REVERSE_SYNCING', 'RECONCILING', 'SWITCHING', 'COMPLETED', 'PAUSED', 'FAILED', 'FORWARD_FIX_REQUIRED')),
    CONSTRAINT ck_rollback_execution_complete CHECK ((rollback_state = 'COMPLETED') = (completed_at IS NOT NULL)),
    CONSTRAINT ck_rollback_execution_failure CHECK (rollback_state NOT IN ('FAILED', 'FORWARD_FIX_REQUIRED') OR failure_code IS NOT NULL)
);

COMMENT ON TABLE migration.rollback_execution IS 'REQ-MIG-010：停止写入、排空、反向同步、对账、切换和恢复流量的有序回滚执行证据。';

CREATE UNIQUE INDEX ux_authority_lease_active ON migration.authority_lease(object_kind, scope_hash) WHERE released_at IS NULL;

CREATE INDEX ix_change_log_apply ON migration.change_log(migration_batch_id, change_sequence) WHERE apply_state IN ('PENDING', 'FAILED');

CREATE INDEX ix_reconciliation_batch ON migration.reconciliation_run(migration_batch_id, created_at DESC);

CREATE INDEX ix_fk_authority_lease_migration_batch_id ON migration.authority_lease (migration_batch_id);

CREATE INDEX ix_fk_rollback_execution_migration_batch_id ON migration.rollback_execution (migration_batch_id);

COMMENT ON COLUMN migration.migration_batch.id IS '内部 UUID 主键；仅用于数据库关系，不作为跨域公开标识。';
COMMENT ON COLUMN migration.migration_batch.public_id IS '不可复用的公开稳定标识；插入时登记到 core.public_id_ledger。';
COMMENT ON COLUMN migration.migration_batch.batch_code IS '稳定机器可读代码；展示文本由资源或目录解析。';
COMMENT ON COLUMN migration.migration_batch.source_system_code IS '稳定机器可读代码；展示文本由资源或目录解析。';
COMMENT ON COLUMN migration.migration_batch.object_kind IS '对象类别判别字段；允许值由 CHECK 或对应注册表限定。';
COMMENT ON COLUMN migration.migration_batch.migration_batch_state IS '显式状态当前值；合法取值见 CHECK，完整状态转换由 .NET 领域策略执行。';
COMMENT ON COLUMN migration.migration_batch.operation_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN migration.migration_batch.source_snapshot_ref IS '不透明对象引用；不得从格式推断手机号、邮箱或其他业务事实。';
COMMENT ON COLUMN migration.migration_batch.source_snapshot_hash IS '不可逆摘要；用于等值匹配、幂等、完整性或最小化证据，不保存原始敏感值。';
COMMENT ON COLUMN migration.migration_batch.authority_side IS 'migration.migration_batch.authority_side 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN migration.migration_batch.rollback_deadline_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN migration.migration_batch.irreversible_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN migration.migration_batch.cutover_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN migration.migration_batch.observing_until IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN migration.migration_batch.completed_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN migration.migration_batch.paused_reason_code IS '稳定机器可读代码；展示文本由资源或目录解析。';
COMMENT ON COLUMN migration.migration_batch.created_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN migration.migration_batch.updated_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN migration.migration_batch.row_version IS '乐观并发版本；更新必须使用原值 compare-and-set，成功后由数据库单调递增。';
COMMENT ON COLUMN migration.migration_batch.paused_from_state IS '显式状态当前值；合法取值见 CHECK，完整状态转换由 .NET 领域策略执行。';
COMMENT ON COLUMN migration.migration_batch.paused_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN migration.migration_batch.rolled_back_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN migration.authority_lease.id IS '内部 UUID 主键；仅用于数据库关系，不作为跨域公开标识。';
COMMENT ON COLUMN migration.authority_lease.migration_batch_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN migration.authority_lease.object_kind IS '对象类别判别字段；允许值由 CHECK 或对应注册表限定。';
COMMENT ON COLUMN migration.authority_lease.scope_hash IS '不可逆摘要；用于等值匹配、幂等、完整性或最小化证据，不保存原始敏感值。';
COMMENT ON COLUMN migration.authority_lease.authority_side IS 'migration.authority_lease.authority_side 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN migration.authority_lease.lease_token_hash IS '不可逆摘要；用于等值匹配、幂等、完整性或最小化证据，不保存原始敏感值。';
COMMENT ON COLUMN migration.authority_lease.fencing_token IS 'migration.authority_lease.fencing_token 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN migration.authority_lease.acquired_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN migration.authority_lease.expires_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN migration.authority_lease.released_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN migration.legacy_id_mapping.id IS '内部 UUID 主键；仅用于数据库关系，不作为跨域公开标识。';
COMMENT ON COLUMN migration.legacy_id_mapping.migration_batch_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN migration.legacy_id_mapping.source_system_code IS '稳定机器可读代码；展示文本由资源或目录解析。';
COMMENT ON COLUMN migration.legacy_id_mapping.object_kind IS '对象类别判别字段；允许值由 CHECK 或对应注册表限定。';
COMMENT ON COLUMN migration.legacy_id_mapping.legacy_id_hash IS '不可逆摘要；用于等值匹配、幂等、完整性或最小化证据，不保存原始敏感值。';
COMMENT ON COLUMN migration.legacy_id_mapping.legacy_id_ciphertext IS '随机化加密密文；解密密钥由独立 KMS/HSM 引用管理。';
COMMENT ON COLUMN migration.legacy_id_mapping.platform_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN migration.legacy_id_mapping.platform_public_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN migration.legacy_id_mapping.mapping_confidence IS 'migration.legacy_id_mapping.mapping_confidence 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN migration.legacy_id_mapping.mapping_method IS 'migration.legacy_id_mapping.mapping_method 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN migration.legacy_id_mapping.mapped_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN migration.duplicate_candidate.id IS '内部 UUID 主键；仅用于数据库关系，不作为跨域公开标识。';
COMMENT ON COLUMN migration.duplicate_candidate.migration_batch_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN migration.duplicate_candidate.candidate_state IS '显式状态当前值；合法取值见 CHECK，完整状态转换由 .NET 领域策略执行。';
COMMENT ON COLUMN migration.duplicate_candidate.left_object_ref IS '不透明对象引用；不得从格式推断手机号、邮箱或其他业务事实。';
COMMENT ON COLUMN migration.duplicate_candidate.right_object_ref IS '不透明对象引用；不得从格式推断手机号、邮箱或其他业务事实。';
COMMENT ON COLUMN migration.duplicate_candidate.match_signal_hashes IS '不可逆摘要；用于等值匹配、幂等、完整性或最小化证据，不保存原始敏感值。';
COMMENT ON COLUMN migration.duplicate_candidate.confidence IS 'migration.duplicate_candidate.confidence 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN migration.duplicate_candidate.resolution_kind IS '对象类别判别字段；允许值由 CHECK 或对应注册表限定。';
COMMENT ON COLUMN migration.duplicate_candidate.resolved_by_ref IS '不透明对象引用；不得从格式推断手机号、邮箱或其他业务事实。';
COMMENT ON COLUMN migration.duplicate_candidate.approval_case_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN migration.duplicate_candidate.resolved_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN migration.duplicate_candidate.created_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN migration.change_log.id IS '内部 UUID 主键；仅用于数据库关系，不作为跨域公开标识。';
COMMENT ON COLUMN migration.change_log.migration_batch_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN migration.change_log.change_sequence IS 'migration.change_log.change_sequence 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN migration.change_log.authority_side IS 'migration.change_log.authority_side 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN migration.change_log.object_kind IS '对象类别判别字段；允许值由 CHECK 或对应注册表限定。';
COMMENT ON COLUMN migration.change_log.object_ref IS '不透明对象引用；不得从格式推断手机号、邮箱或其他业务事实。';
COMMENT ON COLUMN migration.change_log.object_version IS '对象、策略或源数据的显式版本；不得以不可信客户端时间戳替代。';
COMMENT ON COLUMN migration.change_log.change_kind IS '对象类别判别字段；允许值由 CHECK 或对应注册表限定。';
COMMENT ON COLUMN migration.change_log.idempotency_key IS 'migration.change_log.idempotency_key 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN migration.change_log.change_payload_ciphertext IS '随机化加密密文；解密密钥由独立 KMS/HSM 引用管理。';
COMMENT ON COLUMN migration.change_log.change_hash IS '不可逆摘要；用于等值匹配、幂等、完整性或最小化证据，不保存原始敏感值。';
COMMENT ON COLUMN migration.change_log.previous_change_hash IS '不可逆摘要；用于等值匹配、幂等、完整性或最小化证据，不保存原始敏感值。';
COMMENT ON COLUMN migration.change_log.occurred_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN migration.change_log.applied_to_other_side_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN migration.change_log.apply_state IS '显式状态当前值；合法取值见 CHECK，完整状态转换由 .NET 领域策略执行。';
COMMENT ON COLUMN migration.change_log.conflict_reason_code IS '稳定机器可读代码；展示文本由资源或目录解析。';
COMMENT ON COLUMN migration.change_log.created_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN migration.reconciliation_run.id IS '内部 UUID 主键；仅用于数据库关系，不作为跨域公开标识。';
COMMENT ON COLUMN migration.reconciliation_run.public_id IS '不可复用的公开稳定标识；插入时登记到 core.public_id_ledger。';
COMMENT ON COLUMN migration.reconciliation_run.migration_batch_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN migration.reconciliation_run.operation_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN migration.reconciliation_run.reconciliation_state IS '显式状态当前值；合法取值见 CHECK，完整状态转换由 .NET 领域策略执行。';
COMMENT ON COLUMN migration.reconciliation_run.expected_count IS '非负计数器；并发更新使用原子 SQL 或乐观并发控制。';
COMMENT ON COLUMN migration.reconciliation_run.actual_count IS '非负计数器；并发更新使用原子 SQL 或乐观并发控制。';
COMMENT ON COLUMN migration.reconciliation_run.missing_count IS '非负计数器；并发更新使用原子 SQL 或乐观并发控制。';
COMMENT ON COLUMN migration.reconciliation_run.duplicate_count IS '非负计数器；并发更新使用原子 SQL 或乐观并发控制。';
COMMENT ON COLUMN migration.reconciliation_run.mismatch_count IS '非负计数器；并发更新使用原子 SQL 或乐观并发控制。';
COMMENT ON COLUMN migration.reconciliation_run.exception_count IS '非负计数器；并发更新使用原子 SQL 或乐观并发控制。';
COMMENT ON COLUMN migration.reconciliation_run.details_uri IS '受控 URI；写入前必须执行协议、主机、重定向与 SSRF 安全校验。';
COMMENT ON COLUMN migration.reconciliation_run.details_hash IS '不可逆摘要；用于等值匹配、幂等、完整性或最小化证据，不保存原始敏感值。';
COMMENT ON COLUMN migration.reconciliation_run.started_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN migration.reconciliation_run.completed_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN migration.reconciliation_run.created_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN migration.rollback_execution.id IS '内部 UUID 主键；仅用于数据库关系，不作为跨域公开标识。';
COMMENT ON COLUMN migration.rollback_execution.public_id IS '不可复用的公开稳定标识；插入时登记到 core.public_id_ledger。';
COMMENT ON COLUMN migration.rollback_execution.migration_batch_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN migration.rollback_execution.operation_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN migration.rollback_execution.approval_case_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN migration.rollback_execution.rollback_state IS '显式状态当前值；合法取值见 CHECK，完整状态转换由 .NET 领域策略执行。';
COMMENT ON COLUMN migration.rollback_execution.stopped_writes_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN migration.rollback_execution.drained_changes_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN migration.rollback_execution.reverse_sync_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN migration.rollback_execution.reconciled_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN migration.rollback_execution.traffic_switched_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN migration.rollback_execution.completed_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN migration.rollback_execution.failure_code IS '稳定机器可读代码；展示文本由资源或目录解析。';
COMMENT ON COLUMN migration.rollback_execution.created_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';

COMMENT ON CONSTRAINT pk_migration_batch ON migration.migration_batch IS '主键约束：唯一标识 migration.migration_batch 记录。';
COMMENT ON CONSTRAINT uq_migration_batch_public_id ON migration.migration_batch IS '唯一约束：保证 public_id 在 migration.migration_batch 范围内不重复。';
COMMENT ON CONSTRAINT uq_migration_batch_code ON migration.migration_batch IS '唯一约束：保证 batch_code 在 migration.migration_batch 范围内不重复。';
COMMENT ON CONSTRAINT uq_migration_batch_operation ON migration.migration_batch IS '唯一约束：保证 operation_id 在 migration.migration_batch 范围内不重复。';
COMMENT ON CONSTRAINT ck_migration_batch_state ON migration.migration_batch IS '检查约束：限制 migration.migration_batch 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_migration_batch_authority ON migration.migration_batch IS '检查约束：限制 migration.migration_batch 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_migration_batch_hash ON migration.migration_batch IS '检查约束：限制 migration.migration_batch 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_migration_batch_deadline ON migration.migration_batch IS '检查约束：限制 migration.migration_batch 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_migration_batch_cutover ON migration.migration_batch IS '检查约束：限制 migration.migration_batch 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_migration_batch_complete ON migration.migration_batch IS '检查约束：限制 migration.migration_batch 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_migration_batch_pause ON migration.migration_batch IS '检查约束：限制 migration.migration_batch 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_migration_batch_paused_from ON migration.migration_batch IS '检查约束：限制 migration.migration_batch 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_migration_batch_paused_state ON migration.migration_batch IS '检查约束：限制 migration.migration_batch 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_migration_batch_rolled_back ON migration.migration_batch IS '检查约束：限制 migration.migration_batch 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT pk_authority_lease ON migration.authority_lease IS '主键约束：唯一标识 migration.authority_lease 记录。';
COMMENT ON CONSTRAINT uq_authority_lease_fence ON migration.authority_lease IS '唯一约束：保证 object_kind、scope_hash、fencing_token 在 migration.authority_lease 范围内不重复。';
COMMENT ON CONSTRAINT fk_authority_lease_batch ON migration.authority_lease IS '外键约束：migration.authority_lease 的 migration_batch_id 必须引用 migration.migration_batch；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT ck_authority_lease_side ON migration.authority_lease IS '检查约束：限制 migration.authority_lease 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_authority_lease_hash ON migration.authority_lease IS '检查约束：限制 migration.authority_lease 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_authority_lease_fence ON migration.authority_lease IS '检查约束：限制 migration.authority_lease 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_authority_lease_window ON migration.authority_lease IS '检查约束：限制 migration.authority_lease 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT pk_legacy_id_mapping ON migration.legacy_id_mapping IS '主键约束：唯一标识 migration.legacy_id_mapping 记录。';
COMMENT ON CONSTRAINT uq_legacy_id_mapping_source ON migration.legacy_id_mapping IS '唯一约束：保证 source_system_code、object_kind、legacy_id_hash 在 migration.legacy_id_mapping 范围内不重复。';
COMMENT ON CONSTRAINT uq_legacy_id_mapping_target ON migration.legacy_id_mapping IS '唯一约束：保证 migration_batch_id、object_kind、platform_id 在 migration.legacy_id_mapping 范围内不重复。';
COMMENT ON CONSTRAINT fk_legacy_id_mapping_batch ON migration.legacy_id_mapping IS '外键约束：migration.legacy_id_mapping 的 migration_batch_id 必须引用 migration.migration_batch；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT ck_legacy_id_mapping_hash ON migration.legacy_id_mapping IS '检查约束：限制 migration.legacy_id_mapping 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_legacy_id_mapping_confidence ON migration.legacy_id_mapping IS '检查约束：限制 migration.legacy_id_mapping 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_legacy_id_mapping_method ON migration.legacy_id_mapping IS '检查约束：限制 migration.legacy_id_mapping 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT pk_duplicate_candidate ON migration.duplicate_candidate IS '主键约束：唯一标识 migration.duplicate_candidate 记录。';
COMMENT ON CONSTRAINT uq_duplicate_candidate ON migration.duplicate_candidate IS '唯一约束：保证 migration_batch_id、left_object_ref、right_object_ref 在 migration.duplicate_candidate 范围内不重复。';
COMMENT ON CONSTRAINT fk_duplicate_candidate_batch ON migration.duplicate_candidate IS '外键约束：migration.duplicate_candidate 的 migration_batch_id 必须引用 migration.migration_batch；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT ck_duplicate_candidate_distinct ON migration.duplicate_candidate IS '检查约束：限制 migration.duplicate_candidate 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_duplicate_candidate_state ON migration.duplicate_candidate IS '检查约束：限制 migration.duplicate_candidate 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_duplicate_candidate_confidence ON migration.duplicate_candidate IS '检查约束：限制 migration.duplicate_candidate 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_duplicate_candidate_resolution ON migration.duplicate_candidate IS '检查约束：限制 migration.duplicate_candidate 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_duplicate_candidate_resolved ON migration.duplicate_candidate IS '检查约束：限制 migration.duplicate_candidate 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT pk_change_log ON migration.change_log IS '主键约束：唯一标识 migration.change_log 记录。';
COMMENT ON CONSTRAINT uq_change_log_sequence ON migration.change_log IS '唯一约束：保证 migration_batch_id、change_sequence 在 migration.change_log 范围内不重复。';
COMMENT ON CONSTRAINT uq_change_log_key ON migration.change_log IS '唯一约束：保证 migration_batch_id、idempotency_key 在 migration.change_log 范围内不重复。';
COMMENT ON CONSTRAINT fk_change_log_batch ON migration.change_log IS '外键约束：migration.change_log 的 migration_batch_id 必须引用 migration.migration_batch；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT ck_change_log_side ON migration.change_log IS '检查约束：限制 migration.change_log 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_change_log_version ON migration.change_log IS '检查约束：限制 migration.change_log 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_change_log_kind ON migration.change_log IS '检查约束：限制 migration.change_log 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_change_log_hash ON migration.change_log IS '检查约束：限制 migration.change_log 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_change_log_state ON migration.change_log IS '检查约束：限制 migration.change_log 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_change_log_conflict ON migration.change_log IS '检查约束：限制 migration.change_log 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT pk_reconciliation_run ON migration.reconciliation_run IS '主键约束：唯一标识 migration.reconciliation_run 记录。';
COMMENT ON CONSTRAINT uq_reconciliation_run_public_id ON migration.reconciliation_run IS '唯一约束：保证 public_id 在 migration.reconciliation_run 范围内不重复。';
COMMENT ON CONSTRAINT uq_reconciliation_run_operation ON migration.reconciliation_run IS '唯一约束：保证 operation_id 在 migration.reconciliation_run 范围内不重复。';
COMMENT ON CONSTRAINT fk_reconciliation_run_batch ON migration.reconciliation_run IS '外键约束：migration.reconciliation_run 的 migration_batch_id 必须引用 migration.migration_batch；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT ck_reconciliation_run_state ON migration.reconciliation_run IS '检查约束：限制 migration.reconciliation_run 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_reconciliation_run_counts ON migration.reconciliation_run IS '检查约束：限制 migration.reconciliation_run 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_reconciliation_run_hash ON migration.reconciliation_run IS '检查约束：限制 migration.reconciliation_run 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_reconciliation_run_complete ON migration.reconciliation_run IS '检查约束：限制 migration.reconciliation_run 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT pk_rollback_execution ON migration.rollback_execution IS '主键约束：唯一标识 migration.rollback_execution 记录。';
COMMENT ON CONSTRAINT uq_rollback_execution_public_id ON migration.rollback_execution IS '唯一约束：保证 public_id 在 migration.rollback_execution 范围内不重复。';
COMMENT ON CONSTRAINT uq_rollback_execution_operation ON migration.rollback_execution IS '唯一约束：保证 operation_id 在 migration.rollback_execution 范围内不重复。';
COMMENT ON CONSTRAINT fk_rollback_execution_batch ON migration.rollback_execution IS '外键约束：migration.rollback_execution 的 migration_batch_id 必须引用 migration.migration_batch；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT ck_rollback_execution_state ON migration.rollback_execution IS '检查约束：限制 migration.rollback_execution 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_rollback_execution_complete ON migration.rollback_execution IS '检查约束：限制 migration.rollback_execution 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_rollback_execution_failure ON migration.rollback_execution IS '检查约束：限制 migration.rollback_execution 的字段取值或组合满足结构与安全底线。';

COMMENT ON INDEX migration.ux_authority_lease_active IS '查询索引：优化 migration.authority_lease 按 object_kind、scope_hash 的访问，仅覆盖 WHERE 条件命中的记录。';
COMMENT ON INDEX migration.ix_change_log_apply IS '查询索引：优化 migration.change_log 按 migration_batch_id、change_sequence 的访问，仅覆盖 WHERE 条件命中的记录。';
COMMENT ON INDEX migration.ix_reconciliation_batch IS '查询索引：优化 migration.reconciliation_run 按 migration_batch_id、created_at 的访问。';
COMMENT ON INDEX migration.pk_migration_batch IS '约束 pk_migration_batch 的支撑唯一索引。';
COMMENT ON INDEX migration.uq_migration_batch_public_id IS '约束 uq_migration_batch_public_id 的支撑唯一索引。';
COMMENT ON INDEX migration.uq_migration_batch_code IS '约束 uq_migration_batch_code 的支撑唯一索引。';
COMMENT ON INDEX migration.uq_migration_batch_operation IS '约束 uq_migration_batch_operation 的支撑唯一索引。';
COMMENT ON INDEX migration.pk_authority_lease IS '约束 pk_authority_lease 的支撑唯一索引。';
COMMENT ON INDEX migration.uq_authority_lease_fence IS '约束 uq_authority_lease_fence 的支撑唯一索引。';
COMMENT ON INDEX migration.pk_legacy_id_mapping IS '约束 pk_legacy_id_mapping 的支撑唯一索引。';
COMMENT ON INDEX migration.uq_legacy_id_mapping_source IS '约束 uq_legacy_id_mapping_source 的支撑唯一索引。';
COMMENT ON INDEX migration.uq_legacy_id_mapping_target IS '约束 uq_legacy_id_mapping_target 的支撑唯一索引。';
COMMENT ON INDEX migration.pk_duplicate_candidate IS '约束 pk_duplicate_candidate 的支撑唯一索引。';
COMMENT ON INDEX migration.uq_duplicate_candidate IS '约束 uq_duplicate_candidate 的支撑唯一索引。';
COMMENT ON INDEX migration.pk_change_log IS '约束 pk_change_log 的支撑唯一索引。';
COMMENT ON INDEX migration.uq_change_log_sequence IS '约束 uq_change_log_sequence 的支撑唯一索引。';
COMMENT ON INDEX migration.uq_change_log_key IS '约束 uq_change_log_key 的支撑唯一索引。';
COMMENT ON INDEX migration.pk_reconciliation_run IS '约束 pk_reconciliation_run 的支撑唯一索引。';
COMMENT ON INDEX migration.uq_reconciliation_run_public_id IS '约束 uq_reconciliation_run_public_id 的支撑唯一索引。';
COMMENT ON INDEX migration.uq_reconciliation_run_operation IS '约束 uq_reconciliation_run_operation 的支撑唯一索引。';
COMMENT ON INDEX migration.pk_rollback_execution IS '约束 pk_rollback_execution 的支撑唯一索引。';
COMMENT ON INDEX migration.uq_rollback_execution_public_id IS '约束 uq_rollback_execution_public_id 的支撑唯一索引。';
COMMENT ON INDEX migration.uq_rollback_execution_operation IS '约束 uq_rollback_execution_operation 的支撑唯一索引。';
COMMENT ON INDEX migration.ix_fk_authority_lease_migration_batch_id IS '查询索引：优化 migration.authority_lease 按 migration_batch_id 的访问。';
COMMENT ON INDEX migration.ix_fk_rollback_execution_migration_batch_id IS '查询索引：优化 migration.rollback_execution 按 migration_batch_id 的访问。';

