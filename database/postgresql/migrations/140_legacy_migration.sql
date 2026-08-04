\set ON_ERROR_STOP on

SET ROLE iam_owner;

-- 旧系统迁移、ID 映射、批次和双写期变更日志。

CREATE TABLE iam.legacy_systems (
    id uuid PRIMARY KEY,
    system_code varchar(128) NOT NULL,
    name varchar(200) NOT NULL,
    owner_type varchar(40) NOT NULL,
    owner_id uuid NOT NULL,
    authority_scope jsonb NOT NULL,
    state varchar(40) NOT NULL,
    retirement_at timestamptz,
    active_configuration_id uuid,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    row_version bigint NOT NULL DEFAULT 0,
    CONSTRAINT uq_legacy_system_code UNIQUE (system_code),
    CONSTRAINT ck_legacy_system_version CHECK (row_version >= 0)
);
COMMENT ON TABLE iam.legacy_systems IS '旧身份或业务系统登记；权威范围、迁移阶段、切换和退役由 MIG/PLT 代码控制。';
COMMENT ON COLUMN iam.legacy_systems.id IS '应用生成的旧系统 UUIDv7。';
COMMENT ON COLUMN iam.legacy_systems.system_code IS '稳定旧系统代码。';
COMMENT ON COLUMN iam.legacy_systems.name IS '旧系统展示名称。';
COMMENT ON COLUMN iam.legacy_systems.owner_type IS '旧系统责任所有者类型。';
COMMENT ON COLUMN iam.legacy_systems.owner_id IS '旧系统责任所有者逻辑 ID。';
COMMENT ON COLUMN iam.legacy_systems.authority_scope IS '迁移阶段各数据域权威范围快照。';
COMMENT ON COLUMN iam.legacy_systems.state IS '旧系统迁移和退役状态。';
COMMENT ON COLUMN iam.legacy_systems.retirement_at IS '可空；计划或实际退役时间。';
COMMENT ON COLUMN iam.legacy_systems.active_configuration_id IS '可空；逻辑引用 iam.configuration_versions.id。';
COMMENT ON COLUMN iam.legacy_systems.created_at IS '数据库插入时间。';
COMMENT ON COLUMN iam.legacy_systems.updated_at IS '数据库更新时间；由技术 Trigger 自动刷新。';
COMMENT ON COLUMN iam.legacy_systems.row_version IS '乐观锁版本。';

CREATE TABLE iam.legacy_id_mappings (
    id uuid PRIMARY KEY,
    system_id uuid NOT NULL,
    external_type varchar(80) NOT NULL,
    external_id_digest varchar(256) NOT NULL,
    external_id_ciphertext text,
    platform_type varchar(80) NOT NULL,
    platform_id uuid NOT NULL,
    mapping_version integer NOT NULL,
    state varchar(40) NOT NULL,
    first_mapped_at timestamptz NOT NULL,
    last_verified_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    row_version bigint NOT NULL DEFAULT 0,
    CONSTRAINT uq_legacy_external_mapping UNIQUE (system_id, external_type, external_id_digest),
    CONSTRAINT ck_legacy_mapping_version CHECK (mapping_version > 0 AND row_version >= 0)
);
COMMENT ON TABLE iam.legacy_id_mappings IS '旧对象 ID 到平台对象 ID 的稳定映射；冲突、合并和权威判断由 MIG 代码处理。';
COMMENT ON COLUMN iam.legacy_id_mappings.id IS '应用生成的映射 UUIDv7。';
COMMENT ON COLUMN iam.legacy_id_mappings.system_id IS '逻辑引用 iam.legacy_systems.id。';
COMMENT ON COLUMN iam.legacy_id_mappings.external_type IS '旧对象类型。';
COMMENT ON COLUMN iam.legacy_id_mappings.external_id_digest IS '旧系统外部 ID 的安全摘要。';
COMMENT ON COLUMN iam.legacy_id_mappings.external_id_ciphertext IS '可空；确需回查时保存的外部 ID 应用密文。';
COMMENT ON COLUMN iam.legacy_id_mappings.platform_type IS '平台对象类型。';
COMMENT ON COLUMN iam.legacy_id_mappings.platform_id IS '按 platform_type 逻辑引用平台对象。';
COMMENT ON COLUMN iam.legacy_id_mappings.mapping_version IS '映射规则正整数版本。';
COMMENT ON COLUMN iam.legacy_id_mappings.state IS '映射状态。';
COMMENT ON COLUMN iam.legacy_id_mappings.first_mapped_at IS '首次建立映射时间。';
COMMENT ON COLUMN iam.legacy_id_mappings.last_verified_at IS '可空；最近对账确认时间。';
COMMENT ON COLUMN iam.legacy_id_mappings.created_at IS '数据库插入时间。';
COMMENT ON COLUMN iam.legacy_id_mappings.updated_at IS '数据库更新时间；由技术 Trigger 自动刷新。';
COMMENT ON COLUMN iam.legacy_id_mappings.row_version IS '乐观锁版本。';

CREATE TABLE iam.migration_batches (
    id uuid PRIMARY KEY,
    system_id uuid NOT NULL,
    batch_code varchar(160) NOT NULL,
    operation_id uuid NOT NULL,
    state varchar(40) NOT NULL,
    source_checkpoint jsonb NOT NULL DEFAULT '{}'::jsonb,
    total_count bigint NOT NULL DEFAULT 0,
    success_count bigint NOT NULL DEFAULT 0,
    conflict_count bigint NOT NULL DEFAULT 0,
    failure_count bigint NOT NULL DEFAULT 0,
    result_summary jsonb,
    started_at timestamptz,
    completed_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    row_version bigint NOT NULL DEFAULT 0,
    CONSTRAINT uq_migration_batch_code UNIQUE (system_id, batch_code),
    CONSTRAINT uq_migration_batch_operation UNIQUE (operation_id),
    CONSTRAINT ck_migration_batch_counts CHECK (
        total_count >= 0 AND success_count >= 0 AND conflict_count >= 0 AND failure_count >= 0
        AND success_count + conflict_count + failure_count <= total_count
    ),
    CONSTRAINT ck_migration_batch_version CHECK (row_version >= 0)
);
COMMENT ON TABLE iam.migration_batches IS '旧系统迁移批次、检查点和统计；读取、转换、冲突处置和提交由 MIG 代码编排。';
COMMENT ON COLUMN iam.migration_batches.id IS '应用生成的迁移批次 UUIDv7。';
COMMENT ON COLUMN iam.migration_batches.system_id IS '逻辑引用 iam.legacy_systems.id。';
COMMENT ON COLUMN iam.migration_batches.batch_code IS '旧系统内稳定批次代码。';
COMMENT ON COLUMN iam.migration_batches.operation_id IS '逻辑引用 iam.operations.id。';
COMMENT ON COLUMN iam.migration_batches.state IS '批次状态。';
COMMENT ON COLUMN iam.migration_batches.source_checkpoint IS '源读取检查点；代码解释和推进。';
COMMENT ON COLUMN iam.migration_batches.total_count IS '发现或计划对象总数。';
COMMENT ON COLUMN iam.migration_batches.success_count IS '成功迁移数量。';
COMMENT ON COLUMN iam.migration_batches.conflict_count IS '需人工或规则处置冲突数量。';
COMMENT ON COLUMN iam.migration_batches.failure_count IS '失败数量。';
COMMENT ON COLUMN iam.migration_batches.result_summary IS '可空；脱敏结果摘要。';
COMMENT ON COLUMN iam.migration_batches.started_at IS '可空；批次开始时间。';
COMMENT ON COLUMN iam.migration_batches.completed_at IS '可空；批次完成时间。';
COMMENT ON COLUMN iam.migration_batches.created_at IS '数据库插入时间。';
COMMENT ON COLUMN iam.migration_batches.updated_at IS '数据库更新时间；由技术 Trigger 自动刷新。';
COMMENT ON COLUMN iam.migration_batches.row_version IS '乐观锁版本。';

CREATE TABLE iam.migration_items (
    id uuid PRIMARY KEY,
    batch_id uuid NOT NULL,
    external_object_type varchar(80) NOT NULL,
    external_object_id_digest varchar(256) NOT NULL,
    platform_object_type varchar(80),
    platform_object_id uuid,
    source_version varchar(256),
    state varchar(40) NOT NULL,
    difference_summary jsonb NOT NULL DEFAULT '{}'::jsonb,
    result_code varchar(100),
    attempt_count integer NOT NULL DEFAULT 0,
    next_attempt_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    row_version bigint NOT NULL DEFAULT 0,
    CONSTRAINT uq_migration_item_external UNIQUE (batch_id, external_object_type, external_object_id_digest),
    CONSTRAINT ck_migration_item_attempt CHECK (attempt_count >= 0),
    CONSTRAINT ck_migration_item_version CHECK (row_version >= 0)
);
COMMENT ON TABLE iam.migration_items IS '迁移批次内逐对象状态和差异摘要；转换和冲突决策由 MIG 代码执行。';
COMMENT ON COLUMN iam.migration_items.id IS '应用生成的迁移项 UUIDv7。';
COMMENT ON COLUMN iam.migration_items.batch_id IS '逻辑引用 iam.migration_batches.id。';
COMMENT ON COLUMN iam.migration_items.external_object_type IS '旧对象类型。';
COMMENT ON COLUMN iam.migration_items.external_object_id_digest IS '旧对象 ID 安全摘要。';
COMMENT ON COLUMN iam.migration_items.platform_object_type IS '可空；平台对象类型。';
COMMENT ON COLUMN iam.migration_items.platform_object_id IS '可空；平台对象逻辑 ID。';
COMMENT ON COLUMN iam.migration_items.source_version IS '可空；源对象版本。';
COMMENT ON COLUMN iam.migration_items.state IS '迁移项状态。';
COMMENT ON COLUMN iam.migration_items.difference_summary IS '脱敏差异摘要。';
COMMENT ON COLUMN iam.migration_items.result_code IS '可空；稳定处理结果码。';
COMMENT ON COLUMN iam.migration_items.attempt_count IS '处理尝试次数。';
COMMENT ON COLUMN iam.migration_items.next_attempt_at IS '可空；代码计算的下次重试时间。';
COMMENT ON COLUMN iam.migration_items.created_at IS '数据库插入时间。';
COMMENT ON COLUMN iam.migration_items.updated_at IS '数据库更新时间；由技术 Trigger 自动刷新。';
COMMENT ON COLUMN iam.migration_items.row_version IS '乐观锁版本。';

CREATE TABLE iam.migration_change_logs (
    id uuid NOT NULL,
    system_id uuid NOT NULL,
    external_object_type varchar(80) NOT NULL,
    external_object_id_digest varchar(256) NOT NULL,
    sequence_no bigint NOT NULL,
    source_version varchar(256) NOT NULL,
    idempotency_key varchar(200) NOT NULL,
    change_type varchar(80) NOT NULL,
    payload_ciphertext text,
    payload_digest char(64) NOT NULL,
    state varchar(40) NOT NULL,
    occurred_at timestamptz NOT NULL,
    recorded_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT pk_migration_change_logs PRIMARY KEY (id, recorded_at),
    CONSTRAINT ck_migration_change_sequence CHECK (sequence_no > 0)
) PARTITION BY RANGE (recorded_at);
COMMENT ON TABLE iam.migration_change_logs IS '切换期不可变增量变更日志；按 recorded_at 月度分区，顺序、幂等和冲突由 MIG 代码处理。';
COMMENT ON COLUMN iam.migration_change_logs.id IS '应用生成的日志 UUIDv7。';
COMMENT ON COLUMN iam.migration_change_logs.system_id IS '逻辑引用 iam.legacy_systems.id。';
COMMENT ON COLUMN iam.migration_change_logs.external_object_type IS '旧对象类型。';
COMMENT ON COLUMN iam.migration_change_logs.external_object_id_digest IS '旧对象 ID 安全摘要。';
COMMENT ON COLUMN iam.migration_change_logs.sequence_no IS '同外部对象的正整数变更序号。';
COMMENT ON COLUMN iam.migration_change_logs.source_version IS '源对象版本。';
COMMENT ON COLUMN iam.migration_change_logs.idempotency_key IS '源变更幂等键；跨分区唯一性由 iam.idempotency_records 保证。';
COMMENT ON COLUMN iam.migration_change_logs.change_type IS '变更类型。';
COMMENT ON COLUMN iam.migration_change_logs.payload_ciphertext IS '可空；确需保存时的源变更应用密文。';
COMMENT ON COLUMN iam.migration_change_logs.payload_digest IS '规范化变更载荷 SHA-256 摘要。';
COMMENT ON COLUMN iam.migration_change_logs.state IS '变更消费状态。';
COMMENT ON COLUMN iam.migration_change_logs.occurred_at IS '源变更实际发生时间。';
COMMENT ON COLUMN iam.migration_change_logs.recorded_at IS '数据库落库时间和月度分区键。';

CREATE INDEX ix_legacy_mappings_platform ON iam.legacy_id_mappings (platform_type, platform_id, state);
CREATE INDEX ix_migration_batches_queue ON iam.migration_batches (state, updated_at);
CREATE INDEX ix_migration_items_queue ON iam.migration_items (state, next_attempt_at, updated_at);
CREATE INDEX ix_migration_change_object ON iam.migration_change_logs (system_id, external_object_type, external_object_id_digest, sequence_no, recorded_at);
CREATE INDEX ix_migration_change_queue ON iam.migration_change_logs (state, recorded_at);
COMMENT ON INDEX iam.ix_migration_change_object IS '按旧对象和序号读取双写期增量变更。';
