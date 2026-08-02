-- =============================================================================
-- baseline/schemas/audit/tables.sql
-- audit Schema 的最终基表、同 Schema 约束、索引及内联 COMMENT
-- PostgreSQL 16+；应用技术栈：.NET 10 + SqlSugar
-- =============================================================================

CREATE TABLE audit.audit_outbox (
    id uuid        NOT NULL DEFAULT gen_random_uuid(),
    audit_event_id uuid        NOT NULL,
    audit_type text        NOT NULL,
    event_payload_ciphertext bytea    NOT NULL,
    payload_hash bytea       NOT NULL,
    encryption_key_ref text        NOT NULL,
    persistence_state text        NOT NULL DEFAULT 'PERSISTED',
    remote_persisted_at timestamptz NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    tenant_id uuid NOT NULL DEFAULT '00000000-0000-0000-0000-000000000000',
    CONSTRAINT pk_audit_outbox PRIMARY KEY (id),
    CONSTRAINT uq_audit_outbox_event UNIQUE (audit_event_id),
    CONSTRAINT ck_audit_outbox_hash CHECK (octet_length(payload_hash) = 32),
    CONSTRAINT ck_audit_outbox_state CHECK (persistence_state IN ('PERSISTED', 'DELIVERING', 'REMOTE_PERSISTED', 'FAILED')),
    CONSTRAINT ck_audit_outbox_remote CHECK ((persistence_state = 'REMOTE_PERSISTED') = (remote_persisted_at IS NOT NULL))
);

COMMENT ON TABLE audit.audit_outbox IS 'INV-G-008：高风险业务事务本地原子写入的加密审计证据；落盘失败时业务写入失败关闭。';

CREATE TABLE audit.audit_event (
    id uuid        NOT NULL DEFAULT gen_random_uuid(),
    audit_event_id uuid        NOT NULL,
    audit_type text        NOT NULL,
    actor_kind text        NOT NULL,
    actor_ref text        NOT NULL,
    subject_kind text        NULL,
    subject_ref text        NULL,
    tenant_id uuid        NOT NULL DEFAULT '00000000-0000-0000-0000-000000000000',
    source_kind text        NOT NULL,
    source_ref_hash bytea       NULL,
    action_code text        NOT NULL,
    object_kind text        NOT NULL,
    object_ref text        NOT NULL,
    before_version text        NULL,
    after_version text        NULL,
    before_value_hash bytea       NULL,
    after_value_hash bytea       NULL,
    reason_code text        NULL,
    approval_case_id uuid        NULL,
    decision_id uuid        NULL,
    result_code text        NOT NULL,
    policy_version bigint      NULL,
    trace_id text        NOT NULL,
    correlation_id text        NULL,
    classification_code text        NOT NULL,
    retention_rule_code text        NOT NULL,
    legal_basis text        NOT NULL,
    previous_event_hash bytea       NULL,
    event_hash bytea       NOT NULL,
    chain_partition text        NOT NULL,
    chain_sequence bigint      NOT NULL,
    occurred_at timestamptz NOT NULL,
    ingested_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT pk_audit_event PRIMARY KEY (id),
    CONSTRAINT uq_audit_event_id UNIQUE (audit_event_id),
    CONSTRAINT uq_audit_event_chain UNIQUE (chain_partition, chain_sequence),
    CONSTRAINT ck_audit_event_subject CHECK ((subject_kind IS NULL) = (subject_ref IS NULL)),
    CONSTRAINT ck_audit_event_actor CHECK (actor_kind IN ('USER', 'ADMIN', 'CLIENT', 'MACHINE', 'SYSTEM', 'IDENTITY_PROVIDER')),
    CONSTRAINT ck_audit_event_result CHECK (result_code IN ('SUCCEEDED', 'DENIED', 'FAILED', 'PARTIAL', 'CANCELLED')),
    CONSTRAINT ck_audit_event_hash CHECK (octet_length(event_hash) = 32 AND (previous_event_hash IS NULL OR octet_length(previous_event_hash) = 32)),
    CONSTRAINT ck_audit_event_sequence CHECK (chain_sequence >= 1)
);

COMMENT ON TABLE audit.audit_event IS 'REQ-CTRL 审计契约：操作者、Actor、Subject、范围、前后版本/摘要、原因、审批、结果、trace、策略和哈希链。';

CREATE TABLE audit.audit_seal (
    id uuid        NOT NULL DEFAULT gen_random_uuid(),
    chain_partition text        NOT NULL,
    sequence_from bigint      NOT NULL,
    sequence_until bigint      NOT NULL,
    root_hash bytea       NOT NULL,
    signing_key_ref text        NOT NULL,
    signature bytea       NOT NULL,
    external_timestamp_ref text       NULL,
    sealed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT pk_audit_seal PRIMARY KEY (id),
    CONSTRAINT uq_audit_seal_range UNIQUE (chain_partition, sequence_from, sequence_until),
    CONSTRAINT ck_audit_seal_range CHECK (sequence_from >= 1 AND sequence_until >= sequence_from),
    CONSTRAINT ck_audit_seal_hash CHECK (octet_length(root_hash) = 32)
);

COMMENT ON TABLE audit.audit_seal IS '审计哈希链批次的根摘要、签名密钥与可选外部可信时间戳封存证明。';

CREATE TABLE audit.data_access_event (
    id uuid        NOT NULL DEFAULT gen_random_uuid(),
    actor_kind text        NOT NULL,
    actor_ref text        NOT NULL,
    tenant_id uuid        NOT NULL DEFAULT '00000000-0000-0000-0000-000000000000',
    purpose_code text        NOT NULL,
    category_codes text[]      NOT NULL,
    operation_kind text        NOT NULL,
    query_shape_hash bytea       NOT NULL,
    row_count bigint      NOT NULL,
    decision_id uuid        NOT NULL,
    result_code text        NOT NULL,
    trace_id text        NOT NULL,
    accessed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT pk_data_access_event PRIMARY KEY (id),
    CONSTRAINT ck_data_access_categories CHECK (cardinality(category_codes) > 0),
    CONSTRAINT ck_data_access_operation CHECK (operation_kind IN ('READ', 'SEARCH', 'EXPORT', 'BULK_READ', 'BLIND_INDEX_LOOKUP', 'AUDIT_QUERY')),
    CONSTRAINT ck_data_access_hash CHECK (octet_length(query_shape_hash) = 32),
    CONSTRAINT ck_data_access_count CHECK (row_count >= 0),
    CONSTRAINT ck_data_access_result CHECK (result_code IN ('SUCCEEDED', 'DENIED', 'FAILED'))
);

COMMENT ON TABLE audit.data_access_event IS 'REQ-KEY-009 / 隐私审计：敏感读取、搜索、导出、盲索引与审计查询本身的用途、类别、决策和查询形状。';

CREATE INDEX ix_audit_trace ON audit.audit_event(trace_id, occurred_at);

CREATE INDEX ix_audit_object ON audit.audit_event(object_kind, object_ref, occurred_at DESC);

CREATE INDEX ix_audit_occurred_brin ON audit.audit_event USING brin(occurred_at);

CREATE INDEX ix_data_access_occurred_brin ON audit.data_access_event USING brin(accessed_at);

COMMENT ON COLUMN audit.audit_outbox.id IS '内部 UUID 主键；仅用于数据库关系，不作为跨域公开标识。';
COMMENT ON COLUMN audit.audit_outbox.audit_event_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN audit.audit_outbox.audit_type IS '对象类别判别字段；允许值由 CHECK 或对应注册表限定。';
COMMENT ON COLUMN audit.audit_outbox.event_payload_ciphertext IS '随机化加密密文；解密密钥由独立 KMS/HSM 引用管理。';
COMMENT ON COLUMN audit.audit_outbox.payload_hash IS '不可逆摘要；用于等值匹配、幂等、完整性或最小化证据，不保存原始敏感值。';
COMMENT ON COLUMN audit.audit_outbox.encryption_key_ref IS '外部 KMS/HSM 或受控密钥资产引用；不得保存私钥或 Secret 明文。';
COMMENT ON COLUMN audit.audit_outbox.persistence_state IS '显式状态当前值；合法取值见 CHECK，完整状态转换由 .NET 领域策略执行。';
COMMENT ON COLUMN audit.audit_outbox.remote_persisted_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN audit.audit_outbox.created_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN audit.audit_outbox.tenant_id IS '租户隔离键；全零 UUID 表示平台范围，应用查询必须显式携带可信租户上下文。';
COMMENT ON COLUMN audit.audit_event.id IS '内部 UUID 主键；仅用于数据库关系，不作为跨域公开标识。';
COMMENT ON COLUMN audit.audit_event.audit_event_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN audit.audit_event.audit_type IS '对象类别判别字段；允许值由 CHECK 或对应注册表限定。';
COMMENT ON COLUMN audit.audit_event.actor_kind IS '对象类别判别字段；允许值由 CHECK 或对应注册表限定。';
COMMENT ON COLUMN audit.audit_event.actor_ref IS '不透明对象引用；不得从格式推断手机号、邮箱或其他业务事实。';
COMMENT ON COLUMN audit.audit_event.subject_kind IS '对象类别判别字段；允许值由 CHECK 或对应注册表限定。';
COMMENT ON COLUMN audit.audit_event.subject_ref IS '不透明对象引用；不得从格式推断手机号、邮箱或其他业务事实。';
COMMENT ON COLUMN audit.audit_event.tenant_id IS '租户隔离键；全零 UUID 表示平台范围，应用查询必须显式携带可信租户上下文。';
COMMENT ON COLUMN audit.audit_event.source_kind IS '对象类别判别字段；允许值由 CHECK 或对应注册表限定。';
COMMENT ON COLUMN audit.audit_event.source_ref_hash IS '不可逆摘要；用于等值匹配、幂等、完整性或最小化证据，不保存原始敏感值。';
COMMENT ON COLUMN audit.audit_event.action_code IS '稳定机器可读代码；展示文本由资源或目录解析。';
COMMENT ON COLUMN audit.audit_event.object_kind IS '对象类别判别字段；允许值由 CHECK 或对应注册表限定。';
COMMENT ON COLUMN audit.audit_event.object_ref IS '不透明对象引用；不得从格式推断手机号、邮箱或其他业务事实。';
COMMENT ON COLUMN audit.audit_event.before_version IS '对象、策略或源数据的显式版本；不得以不可信客户端时间戳替代。';
COMMENT ON COLUMN audit.audit_event.after_version IS '对象、策略或源数据的显式版本；不得以不可信客户端时间戳替代。';
COMMENT ON COLUMN audit.audit_event.before_value_hash IS '不可逆摘要；用于等值匹配、幂等、完整性或最小化证据，不保存原始敏感值。';
COMMENT ON COLUMN audit.audit_event.after_value_hash IS '不可逆摘要；用于等值匹配、幂等、完整性或最小化证据，不保存原始敏感值。';
COMMENT ON COLUMN audit.audit_event.reason_code IS '稳定机器可读代码；展示文本由资源或目录解析。';
COMMENT ON COLUMN audit.audit_event.approval_case_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN audit.audit_event.decision_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN audit.audit_event.result_code IS '稳定机器可读代码；展示文本由资源或目录解析。';
COMMENT ON COLUMN audit.audit_event.policy_version IS '对象、策略或源数据的显式版本；不得以不可信客户端时间戳替代。';
COMMENT ON COLUMN audit.audit_event.trace_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN audit.audit_event.correlation_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN audit.audit_event.classification_code IS '稳定机器可读代码；展示文本由资源或目录解析。';
COMMENT ON COLUMN audit.audit_event.retention_rule_code IS '稳定机器可读代码；展示文本由资源或目录解析。';
COMMENT ON COLUMN audit.audit_event.legal_basis IS 'audit.audit_event.legal_basis 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN audit.audit_event.previous_event_hash IS '不可逆摘要；用于等值匹配、幂等、完整性或最小化证据，不保存原始敏感值。';
COMMENT ON COLUMN audit.audit_event.event_hash IS '不可逆摘要；用于等值匹配、幂等、完整性或最小化证据，不保存原始敏感值。';
COMMENT ON COLUMN audit.audit_event.chain_partition IS 'audit.audit_event.chain_partition 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN audit.audit_event.chain_sequence IS 'audit.audit_event.chain_sequence 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN audit.audit_event.occurred_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN audit.audit_event.ingested_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN audit.audit_seal.id IS '内部 UUID 主键；仅用于数据库关系，不作为跨域公开标识。';
COMMENT ON COLUMN audit.audit_seal.chain_partition IS 'audit.audit_seal.chain_partition 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN audit.audit_seal.sequence_from IS 'audit.audit_seal.sequence_from 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN audit.audit_seal.sequence_until IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN audit.audit_seal.root_hash IS '不可逆摘要；用于等值匹配、幂等、完整性或最小化证据，不保存原始敏感值。';
COMMENT ON COLUMN audit.audit_seal.signing_key_ref IS '外部 KMS/HSM 或受控密钥资产引用；不得保存私钥或 Secret 明文。';
COMMENT ON COLUMN audit.audit_seal.signature IS 'audit.audit_seal.signature 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN audit.audit_seal.external_timestamp_ref IS '不透明对象引用；不得从格式推断手机号、邮箱或其他业务事实。';
COMMENT ON COLUMN audit.audit_seal.sealed_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN audit.data_access_event.id IS '内部 UUID 主键；仅用于数据库关系，不作为跨域公开标识。';
COMMENT ON COLUMN audit.data_access_event.actor_kind IS '对象类别判别字段；允许值由 CHECK 或对应注册表限定。';
COMMENT ON COLUMN audit.data_access_event.actor_ref IS '不透明对象引用；不得从格式推断手机号、邮箱或其他业务事实。';
COMMENT ON COLUMN audit.data_access_event.tenant_id IS '租户隔离键；全零 UUID 表示平台范围，应用查询必须显式携带可信租户上下文。';
COMMENT ON COLUMN audit.data_access_event.purpose_code IS '稳定机器可读代码；展示文本由资源或目录解析。';
COMMENT ON COLUMN audit.data_access_event.category_codes IS '代码或引用集合；写入前去重、校验 allowlist，并满足表约束。';
COMMENT ON COLUMN audit.data_access_event.operation_kind IS '对象类别判别字段；允许值由 CHECK 或对应注册表限定。';
COMMENT ON COLUMN audit.data_access_event.query_shape_hash IS '不可逆摘要；用于等值匹配、幂等、完整性或最小化证据，不保存原始敏感值。';
COMMENT ON COLUMN audit.data_access_event.row_count IS '非负计数器；并发更新使用原子 SQL 或乐观并发控制。';
COMMENT ON COLUMN audit.data_access_event.decision_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN audit.data_access_event.result_code IS '稳定机器可读代码；展示文本由资源或目录解析。';
COMMENT ON COLUMN audit.data_access_event.trace_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN audit.data_access_event.accessed_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';

COMMENT ON CONSTRAINT pk_audit_outbox ON audit.audit_outbox IS '主键约束：唯一标识 audit.audit_outbox 记录。';
COMMENT ON CONSTRAINT uq_audit_outbox_event ON audit.audit_outbox IS '唯一约束：保证 audit_event_id 在 audit.audit_outbox 范围内不重复。';
COMMENT ON CONSTRAINT ck_audit_outbox_hash ON audit.audit_outbox IS '检查约束：限制 audit.audit_outbox 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_audit_outbox_state ON audit.audit_outbox IS '检查约束：限制 audit.audit_outbox 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_audit_outbox_remote ON audit.audit_outbox IS '检查约束：限制 audit.audit_outbox 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT pk_audit_event ON audit.audit_event IS '主键约束：唯一标识 audit.audit_event 记录。';
COMMENT ON CONSTRAINT uq_audit_event_id ON audit.audit_event IS '唯一约束：保证 audit_event_id 在 audit.audit_event 范围内不重复。';
COMMENT ON CONSTRAINT uq_audit_event_chain ON audit.audit_event IS '唯一约束：保证 chain_partition、chain_sequence 在 audit.audit_event 范围内不重复。';
COMMENT ON CONSTRAINT ck_audit_event_subject ON audit.audit_event IS '检查约束：限制 audit.audit_event 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_audit_event_actor ON audit.audit_event IS '检查约束：限制 audit.audit_event 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_audit_event_result ON audit.audit_event IS '检查约束：限制 audit.audit_event 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_audit_event_hash ON audit.audit_event IS '检查约束：限制 audit.audit_event 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_audit_event_sequence ON audit.audit_event IS '检查约束：限制 audit.audit_event 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT pk_audit_seal ON audit.audit_seal IS '主键约束：唯一标识 audit.audit_seal 记录。';
COMMENT ON CONSTRAINT uq_audit_seal_range ON audit.audit_seal IS '唯一约束：保证 chain_partition、sequence_from、sequence_until 在 audit.audit_seal 范围内不重复。';
COMMENT ON CONSTRAINT ck_audit_seal_range ON audit.audit_seal IS '检查约束：限制 audit.audit_seal 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_audit_seal_hash ON audit.audit_seal IS '检查约束：限制 audit.audit_seal 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT pk_data_access_event ON audit.data_access_event IS '主键约束：唯一标识 audit.data_access_event 记录。';
COMMENT ON CONSTRAINT ck_data_access_categories ON audit.data_access_event IS '检查约束：限制 audit.data_access_event 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_data_access_operation ON audit.data_access_event IS '检查约束：限制 audit.data_access_event 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_data_access_hash ON audit.data_access_event IS '检查约束：限制 audit.data_access_event 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_data_access_count ON audit.data_access_event IS '检查约束：限制 audit.data_access_event 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_data_access_result ON audit.data_access_event IS '检查约束：限制 audit.data_access_event 的字段取值或组合满足结构与安全底线。';

COMMENT ON INDEX audit.ix_audit_trace IS '查询索引：优化 audit.audit_event 按 trace_id、occurred_at 的访问。';
COMMENT ON INDEX audit.ix_audit_object IS '查询索引：优化 audit.audit_event 按 object_kind、object_ref、occurred_at 的访问。';
COMMENT ON INDEX audit.ix_audit_occurred_brin IS '查询索引：优化 audit.audit_event 按 occurred_at 的访问。';
COMMENT ON INDEX audit.ix_data_access_occurred_brin IS '查询索引：优化 audit.data_access_event 按 accessed_at 的访问。';
COMMENT ON INDEX audit.pk_audit_outbox IS '约束 pk_audit_outbox 的支撑唯一索引。';
COMMENT ON INDEX audit.uq_audit_outbox_event IS '约束 uq_audit_outbox_event 的支撑唯一索引。';
COMMENT ON INDEX audit.pk_audit_event IS '约束 pk_audit_event 的支撑唯一索引。';
COMMENT ON INDEX audit.uq_audit_event_id IS '约束 uq_audit_event_id 的支撑唯一索引。';
COMMENT ON INDEX audit.uq_audit_event_chain IS '约束 uq_audit_event_chain 的支撑唯一索引。';
COMMENT ON INDEX audit.pk_audit_seal IS '约束 pk_audit_seal 的支撑唯一索引。';
COMMENT ON INDEX audit.uq_audit_seal_range IS '约束 uq_audit_seal_range 的支撑唯一索引。';
COMMENT ON INDEX audit.pk_data_access_event IS '约束 pk_data_access_event 的支撑唯一索引。';

