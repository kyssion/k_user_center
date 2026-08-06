\set ON_ERROR_STOP on

SET ROLE iam_owner;

-- 联合身份和企业目录连接。协议验证、路由、映射和同步冲突由 FED 代码处理。

CREATE TABLE iam.identity_providers (
    id uuid PRIMARY KEY,
    tenant_id uuid,
    provider_code varchar(128) NOT NULL,
    protocol varchar(40) NOT NULL,
    issuer_or_entity_id varchar(512) NOT NULL,
    owner_type varchar(40) NOT NULL,
    owner_id uuid NOT NULL,
    state varchar(40) NOT NULL,
    active_configuration_id uuid NOT NULL,
    metadata_digest char(64),
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    row_version bigint NOT NULL DEFAULT 0,
    CONSTRAINT uq_identity_provider_code UNIQUE NULLS NOT DISTINCT (tenant_id, provider_code),
    CONSTRAINT uq_identity_provider_issuer UNIQUE NULLS NOT DISTINCT (tenant_id, protocol, issuer_or_entity_id),
    CONSTRAINT ck_identity_provider_version CHECK (row_version >= 0)
);
COMMENT ON TABLE iam.identity_providers IS 'OIDC、SAML、社交等身份源登记；Key、属性映射和路由通过版本化配置承载。';
COMMENT ON COLUMN iam.identity_providers.id IS '应用生成的身份源 UUIDv7。';
COMMENT ON COLUMN iam.identity_providers.tenant_id IS '可空；逻辑引用 iam.tenants.id，平台共享身份源为空。';
COMMENT ON COLUMN iam.identity_providers.provider_code IS '作用域内稳定身份源代码。';
COMMENT ON COLUMN iam.identity_providers.protocol IS '联合协议类型。';
COMMENT ON COLUMN iam.identity_providers.issuer_or_entity_id IS 'OIDC Issuer 或 SAML Entity ID。';
COMMENT ON COLUMN iam.identity_providers.owner_type IS '身份源所有者类型。';
COMMENT ON COLUMN iam.identity_providers.owner_id IS '身份源所有者逻辑 ID。';
COMMENT ON COLUMN iam.identity_providers.state IS '身份源状态。';
COMMENT ON COLUMN iam.identity_providers.active_configuration_id IS '逻辑引用 iam.configuration_versions.id。';
COMMENT ON COLUMN iam.identity_providers.metadata_digest IS '可空；当前元数据规范化摘要。';
COMMENT ON COLUMN iam.identity_providers.created_at IS '数据库插入时间。';
COMMENT ON COLUMN iam.identity_providers.updated_at IS '数据库更新时间；应用显式刷新。';
COMMENT ON COLUMN iam.identity_providers.row_version IS '乐观锁版本。';

CREATE TABLE iam.directory_connectors (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    provider_id uuid,
    connector_code varchar(128) NOT NULL,
    connector_type varchar(40) NOT NULL,
    owner_type varchar(40) NOT NULL,
    owner_id uuid NOT NULL,
    state varchar(40) NOT NULL,
    active_configuration_id uuid NOT NULL,
    last_success_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    row_version bigint NOT NULL DEFAULT 0,
    CONSTRAINT uq_directory_connector_code UNIQUE (tenant_id, connector_code),
    CONSTRAINT ck_directory_connector_version CHECK (row_version >= 0)
);
COMMENT ON TABLE iam.directory_connectors IS 'SCIM、API 或批量目录连接器；连接秘密仅保存于密钥系统，数据库保存配置引用。';
COMMENT ON COLUMN iam.directory_connectors.id IS '应用生成的连接器 UUIDv7。';
COMMENT ON COLUMN iam.directory_connectors.tenant_id IS '逻辑引用 iam.tenants.id。';
COMMENT ON COLUMN iam.directory_connectors.provider_id IS '可空；逻辑引用 iam.identity_providers.id。';
COMMENT ON COLUMN iam.directory_connectors.connector_code IS '租户内稳定连接器代码。';
COMMENT ON COLUMN iam.directory_connectors.connector_type IS '连接器类型。';
COMMENT ON COLUMN iam.directory_connectors.owner_type IS '连接器所有者类型。';
COMMENT ON COLUMN iam.directory_connectors.owner_id IS '连接器所有者逻辑 ID。';
COMMENT ON COLUMN iam.directory_connectors.state IS '连接器状态。';
COMMENT ON COLUMN iam.directory_connectors.active_configuration_id IS '逻辑引用 iam.configuration_versions.id。';
COMMENT ON COLUMN iam.directory_connectors.last_success_at IS '可空；最近同步成功时间。';
COMMENT ON COLUMN iam.directory_connectors.created_at IS '数据库插入时间。';
COMMENT ON COLUMN iam.directory_connectors.updated_at IS '数据库更新时间；应用显式刷新。';
COMMENT ON COLUMN iam.directory_connectors.row_version IS '乐观锁版本。';

CREATE TABLE iam.directory_sync_cursors (
    id uuid PRIMARY KEY,
    connector_id uuid NOT NULL,
    stream_code varchar(80) NOT NULL,
    cursor_value_ciphertext text,
    cursor_digest char(64),
    source_version varchar(256),
    tombstone_watermark varchar(256),
    last_success_at timestamptz,
    updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    row_version bigint NOT NULL DEFAULT 0,
    CONSTRAINT uq_directory_sync_cursor UNIQUE (connector_id, stream_code),
    CONSTRAINT ck_directory_sync_cursor_version CHECK (row_version >= 0)
);
COMMENT ON TABLE iam.directory_sync_cursors IS '目录增量同步位置；游标解释和原子推进由 FED 同步器负责。';
COMMENT ON COLUMN iam.directory_sync_cursors.id IS '应用生成的游标记录 UUIDv7。';
COMMENT ON COLUMN iam.directory_sync_cursors.connector_id IS '逻辑引用 iam.directory_connectors.id。';
COMMENT ON COLUMN iam.directory_sync_cursors.stream_code IS '连接器内同步流代码。';
COMMENT ON COLUMN iam.directory_sync_cursors.cursor_value_ciphertext IS '可空；敏感外部游标的应用密文。';
COMMENT ON COLUMN iam.directory_sync_cursors.cursor_digest IS '可空；游标规范化摘要。';
COMMENT ON COLUMN iam.directory_sync_cursors.source_version IS '可空；外部源版本或 ETag。';
COMMENT ON COLUMN iam.directory_sync_cursors.tombstone_watermark IS '可空；删除墓碑消费水位。';
COMMENT ON COLUMN iam.directory_sync_cursors.last_success_at IS '可空；成功提交该游标的时间。';
COMMENT ON COLUMN iam.directory_sync_cursors.updated_at IS '数据库更新时间；应用显式刷新。';
COMMENT ON COLUMN iam.directory_sync_cursors.row_version IS '乐观锁版本。';

CREATE TABLE iam.directory_sync_batches (
    id uuid PRIMARY KEY,
    connector_id uuid NOT NULL,
    operation_id uuid NOT NULL,
    state varchar(40) NOT NULL,
    start_cursor_digest char(64),
    end_cursor_digest char(64),
    read_count bigint NOT NULL DEFAULT 0,
    created_count bigint NOT NULL DEFAULT 0,
    updated_count bigint NOT NULL DEFAULT 0,
    deleted_count bigint NOT NULL DEFAULT 0,
    conflict_count bigint NOT NULL DEFAULT 0,
    result_summary jsonb,
    started_at timestamptz NOT NULL,
    completed_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    row_version bigint NOT NULL DEFAULT 0,
    CONSTRAINT uq_directory_sync_operation UNIQUE (operation_id),
    CONSTRAINT ck_directory_sync_counts CHECK (read_count >= 0 AND created_count >= 0 AND updated_count >= 0 AND deleted_count >= 0 AND conflict_count >= 0),
    CONSTRAINT ck_directory_sync_batch_version CHECK (row_version >= 0)
);
COMMENT ON TABLE iam.directory_sync_batches IS '目录同步批次统计和结果；对象处理、冲突和游标提交由 FED 代码编排。';
COMMENT ON COLUMN iam.directory_sync_batches.id IS '应用生成的批次 UUIDv7。';
COMMENT ON COLUMN iam.directory_sync_batches.connector_id IS '逻辑引用 iam.directory_connectors.id。';
COMMENT ON COLUMN iam.directory_sync_batches.operation_id IS '逻辑引用 iam.operations.id。';
COMMENT ON COLUMN iam.directory_sync_batches.state IS '同步批次状态。';
COMMENT ON COLUMN iam.directory_sync_batches.start_cursor_digest IS '可空；开始游标摘要。';
COMMENT ON COLUMN iam.directory_sync_batches.end_cursor_digest IS '可空；结束游标摘要。';
COMMENT ON COLUMN iam.directory_sync_batches.read_count IS '读取对象数量。';
COMMENT ON COLUMN iam.directory_sync_batches.created_count IS '平台创建对象数量。';
COMMENT ON COLUMN iam.directory_sync_batches.updated_count IS '平台更新对象数量。';
COMMENT ON COLUMN iam.directory_sync_batches.deleted_count IS '平台终止或墓碑对象数量。';
COMMENT ON COLUMN iam.directory_sync_batches.conflict_count IS '需处置冲突数量。';
COMMENT ON COLUMN iam.directory_sync_batches.result_summary IS '可空；脱敏结果摘要。';
COMMENT ON COLUMN iam.directory_sync_batches.started_at IS '批次开始时间。';
COMMENT ON COLUMN iam.directory_sync_batches.completed_at IS '可空；批次完成时间。';
COMMENT ON COLUMN iam.directory_sync_batches.created_at IS '数据库插入时间。';
COMMENT ON COLUMN iam.directory_sync_batches.updated_at IS '数据库更新时间；应用显式刷新。';
COMMENT ON COLUMN iam.directory_sync_batches.row_version IS '乐观锁版本。';

CREATE TABLE iam.directory_object_mappings (
    id uuid PRIMARY KEY,
    connector_id uuid NOT NULL,
    external_object_type varchar(40) NOT NULL,
    external_object_id_digest varchar(256) NOT NULL,
    platform_object_type varchar(40) NOT NULL,
    platform_object_id uuid NOT NULL,
    source_version varchar(256),
    mapping_state varchar(40) NOT NULL,
    last_seen_at timestamptz NOT NULL,
    tombstoned_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    row_version bigint NOT NULL DEFAULT 0,
    CONSTRAINT uq_directory_external_mapping UNIQUE (connector_id, external_object_type, external_object_id_digest),
    CONSTRAINT uq_directory_platform_mapping UNIQUE (connector_id, platform_object_type, platform_object_id),
    CONSTRAINT ck_directory_mapping_version CHECK (row_version >= 0)
);
COMMENT ON TABLE iam.directory_object_mappings IS '外部目录对象到平台对象的稳定映射；权威性和冲突处理由 FED 代码决定。';
COMMENT ON COLUMN iam.directory_object_mappings.id IS '应用生成的映射 UUIDv7。';
COMMENT ON COLUMN iam.directory_object_mappings.connector_id IS '逻辑引用 iam.directory_connectors.id。';
COMMENT ON COLUMN iam.directory_object_mappings.external_object_type IS '外部对象类型。';
COMMENT ON COLUMN iam.directory_object_mappings.external_object_id_digest IS '外部稳定 ID 的安全摘要。';
COMMENT ON COLUMN iam.directory_object_mappings.platform_object_type IS '平台对象类型。';
COMMENT ON COLUMN iam.directory_object_mappings.platform_object_id IS '按类型逻辑引用平台对象。';
COMMENT ON COLUMN iam.directory_object_mappings.source_version IS '可空；外部对象版本或 ETag。';
COMMENT ON COLUMN iam.directory_object_mappings.mapping_state IS '映射状态。';
COMMENT ON COLUMN iam.directory_object_mappings.last_seen_at IS '外部对象最近观察时间。';
COMMENT ON COLUMN iam.directory_object_mappings.tombstoned_at IS '可空；外部对象删除墓碑时间。';
COMMENT ON COLUMN iam.directory_object_mappings.created_at IS '数据库插入时间。';
COMMENT ON COLUMN iam.directory_object_mappings.updated_at IS '数据库更新时间；应用显式刷新。';
COMMENT ON COLUMN iam.directory_object_mappings.row_version IS '乐观锁版本。';

CREATE INDEX ix_identity_providers_tenant ON iam.identity_providers (tenant_id, state, protocol);
CREATE INDEX ix_directory_connectors_tenant ON iam.directory_connectors (tenant_id, state);
CREATE INDEX ix_directory_sync_batches_queue ON iam.directory_sync_batches (state, updated_at);
CREATE INDEX ix_directory_mappings_platform ON iam.directory_object_mappings (platform_object_type, platform_object_id, mapping_state);
COMMENT ON INDEX iam.ix_directory_sync_batches_queue IS '目录同步编排器按状态和更新时间查询批次。';
