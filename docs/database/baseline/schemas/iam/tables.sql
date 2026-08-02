-- =============================================================================
-- baseline/schemas/iam/tables.sql
-- iam Schema 的最终基表、同 Schema 约束、索引及内联 COMMENT
-- PostgreSQL 16+；应用技术栈：.NET 10 + SqlSugar
-- =============================================================================

CREATE TABLE iam.user_account (
    id uuid        NOT NULL DEFAULT gen_random_uuid(),
    public_id text        NOT NULL,
    subject_kind text        NOT NULL DEFAULT 'HUMAN',
    lifecycle_state text        NOT NULL DEFAULT 'PROVISIONAL',
    authentication_lock_state text    NOT NULL DEFAULT 'ENABLED',
    security_freeze_state text        NOT NULL DEFAULT 'CLEAR',
    user_security_epoch bigint      NOT NULL DEFAULT 1,
    aggregate_version bigint      NOT NULL DEFAULT 1,
    creation_source text        NOT NULL,
    creation_client_id uuid        NULL,
    activated_at timestamptz NULL,
    dormant_at timestamptz NULL,
    last_authenticated_at timestamptz NULL,
    lock_reason_code text        NULL,
    lock_until timestamptz NULL,
    freeze_reason_code text        NULL,
    frozen_at timestamptz NULL,
    frozen_by_ref text        NULL,
    deletion_requested_at timestamptz NULL,
    anonymized_at timestamptz NULL,
    erased_at timestamptz NULL,
    merged_into_user_id uuid        NULL,
    terminal_reason_code text        NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    row_version bigint      NOT NULL DEFAULT 1,
    CONSTRAINT pk_user_account PRIMARY KEY (id),
    CONSTRAINT uq_user_account_public_id UNIQUE (public_id),
    CONSTRAINT fk_user_account_merged_into FOREIGN KEY (merged_into_user_id) REFERENCES iam.user_account(id),
    CONSTRAINT ck_user_account_kind CHECK (subject_kind IN ('HUMAN', 'GUEST')),
    CONSTRAINT ck_user_account_lifecycle CHECK (lifecycle_state IN ('PROVISIONAL', 'ACTIVE', 'DORMANT', 'DELETION_PENDING', 'DELETION_BLOCKED', 'ANONYMIZED', 'ERASED', 'MERGED')),
    CONSTRAINT ck_user_account_lock CHECK (authentication_lock_state IN ('ENABLED', 'LOCKED')),
    CONSTRAINT ck_user_account_freeze CHECK (security_freeze_state IN ('CLEAR', 'FROZEN')),
    CONSTRAINT ck_user_account_epoch CHECK (user_security_epoch >= 1),
    CONSTRAINT ck_user_account_frozen CHECK (security_freeze_state <> 'FROZEN' OR (freeze_reason_code IS NOT NULL AND frozen_at IS NOT NULL)),
    CONSTRAINT ck_user_account_merged CHECK ((lifecycle_state = 'MERGED') = (merged_into_user_id IS NOT NULL)),
    CONSTRAINT ck_user_account_anonymized CHECK ((lifecycle_state = 'ANONYMIZED') = (anonymized_at IS NOT NULL)),
    CONSTRAINT ck_user_account_erased CHECK ((lifecycle_state = 'ERASED') = (erased_at IS NOT NULL))
);

COMMENT ON TABLE iam.user_account IS 'CAP-ID-001/013：Global User 主档；生命周期、认证锁定和安全冻结正交，UID 不可变不可复用，终态不可恢复。';

CREATE TABLE iam.subject_assignment (
    id uuid        NOT NULL DEFAULT gen_random_uuid(),
    public_id text        NOT NULL,
    user_id uuid        NOT NULL,
    audience_kind text        NOT NULL,
    audience_ref_id uuid        NOT NULL,
    subject_version integer     NOT NULL DEFAULT 1,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    retired_at timestamptz NULL,
    CONSTRAINT pk_subject_assignment PRIMARY KEY (id),
    CONSTRAINT uq_subject_assignment_public_id UNIQUE (public_id),
    CONSTRAINT uq_subject_assignment_audience UNIQUE (user_id, audience_kind, audience_ref_id, subject_version),
    CONSTRAINT fk_subject_assignment_user FOREIGN KEY (user_id) REFERENCES iam.user_account(id),
    CONSTRAINT ck_subject_assignment_audience CHECK (audience_kind IN ('CLIENT', 'BUSINESS_LINE', 'TENANT', 'WEBHOOK_RECIPIENT')),
    CONSTRAINT ck_subject_assignment_version CHECK (subject_version >= 1)
);

COMMENT ON TABLE iam.subject_assignment IS 'CAP-ID-001 / REQ-PRIV-010 / EVT-G-012：按 Client、业务、租户或 Webhook 接收方发布无可计算关系的 pairwise Subject。';

CREATE TABLE iam.identifier (
    id uuid        NOT NULL DEFAULT gen_random_uuid(),
    user_id uuid        NOT NULL,
    identifier_type text        NOT NULL,
    identifier_state text        NOT NULL DEFAULT 'PENDING',
    uniqueness_scope text        NOT NULL,
    scope_ref_id uuid        NOT NULL DEFAULT '00000000-0000-0000-0000-000000000000',
    value_cipher bytea       NOT NULL,
    value_blind_index bytea       NOT NULL,
    value_masked text        NOT NULL,
    cipher_key_version integer     NOT NULL,
    blind_index_key_version integer     NOT NULL,
    normalization_version integer     NOT NULL,
    normalization_profile_code text        NOT NULL,
    verified_at timestamptz NULL,
    verification_method text        NULL,
    unbound_at timestamptz NULL,
    quarantine_until timestamptz NULL,
    released_at timestamptz NULL,
    is_primary boolean     NOT NULL DEFAULT false,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    row_version bigint      NOT NULL DEFAULT 1,
    ownership_digest bytea NOT NULL,
    ownership_key_version integer NOT NULL,
    state_reason_code text NULL,
    CONSTRAINT pk_identifier PRIMARY KEY (id),
    CONSTRAINT fk_identifier_user FOREIGN KEY (user_id) REFERENCES iam.user_account(id),
    CONSTRAINT ck_identifier_type CHECK (identifier_type IN ('PHONE', 'EMAIL', 'USERNAME')),
    CONSTRAINT ck_identifier_state CHECK (identifier_state IN ('PENDING', 'VERIFIED', 'UNBOUND', 'QUARANTINED', 'RELEASED')),
    CONSTRAINT ck_identifier_scope CHECK (uniqueness_scope IN ('GLOBAL', 'BUSINESS_LINE', 'TENANT', 'CLIENT')),
    CONSTRAINT ck_identifier_blind_index CHECK (octet_length(value_blind_index) = 32),
    CONSTRAINT ck_identifier_versions CHECK (cipher_key_version > 0 AND blind_index_key_version > 0 AND normalization_version > 0),
    CONSTRAINT ck_identifier_verified CHECK (identifier_state <> 'VERIFIED' OR (verified_at IS NOT NULL AND verification_method IS NOT NULL)),
    CONSTRAINT ck_identifier_quarantine CHECK (identifier_state <> 'QUARANTINED' OR quarantine_until IS NOT NULL),
    CONSTRAINT ck_identifier_ownership_digest CHECK (octet_length(ownership_digest) = 32 AND ownership_key_version > 0),
    CONSTRAINT ck_identifier_verified_history CHECK (
    identifier_state = 'PENDING' OR verified_at IS NOT NULL
    ),
    CONSTRAINT ck_identifier_unbound_history CHECK (
    identifier_state NOT IN ('UNBOUND', 'QUARANTINED', 'RELEASED') OR unbound_at IS NOT NULL
    ),
    CONSTRAINT ck_identifier_released CHECK ((identifier_state = 'RELEASED') = (released_at IS NOT NULL))
);

COMMENT ON TABLE iam.identifier IS 'CAP-ID-002 至 009：手机号、邮箱、用户名的加密值、盲索引、版本化规范化、验证、解绑、隔离与释放。';

CREATE TABLE iam.identifier_tombstone (
    id uuid        NOT NULL DEFAULT gen_random_uuid(),
    identifier_type text        NOT NULL,
    uniqueness_scope text        NOT NULL,
    scope_ref_id uuid        NOT NULL,
    value_blind_index bytea       NOT NULL,
    blind_index_key_version integer     NOT NULL,
    former_user_id uuid        NOT NULL,
    ownership_digest bytea       NOT NULL,
    quarantine_until timestamptz NOT NULL,
    released_at timestamptz NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    ownership_key_version integer NOT NULL DEFAULT 1,
    CONSTRAINT pk_identifier_tombstone PRIMARY KEY (id),
    CONSTRAINT fk_identifier_tombstone_user FOREIGN KEY (former_user_id) REFERENCES iam.user_account(id),
    CONSTRAINT ck_identifier_tombstone_hash CHECK (octet_length(value_blind_index) = 32 AND octet_length(ownership_digest) = 32),
    CONSTRAINT uq_identifier_tombstone UNIQUE (identifier_type, uniqueness_scope, scope_ref_id, ownership_digest),
    CONSTRAINT ck_identifier_tombstone_ownership CHECK (octet_length(ownership_digest) = 32 AND ownership_key_version > 0)
);

COMMENT ON TABLE iam.identifier_tombstone IS 'CAP-ID-008/009/012：解绑历史、号码回收隔离和不可逆归属墓碑；释放唯一键也不删除历史。';

CREATE TABLE iam.account_merge (
    id uuid        NOT NULL DEFAULT gen_random_uuid(),
    public_id text        NOT NULL,
    source_user_id uuid        NOT NULL,
    target_user_id uuid        NOT NULL,
    merge_state text        NOT NULL DEFAULT 'CANDIDATE',
    source_verified_at timestamptz NULL,
    target_verified_at timestamptz NULL,
    conflict_summary jsonb       NULL,
    approval_case_id uuid        NULL,
    operation_id uuid        NOT NULL,
    irreversible_at timestamptz NULL,
    completed_at timestamptz NULL,
    failed_reason_code text        NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    row_version bigint      NOT NULL DEFAULT 1,
    CONSTRAINT pk_account_merge PRIMARY KEY (id),
    CONSTRAINT uq_account_merge_public_id UNIQUE (public_id),
    CONSTRAINT fk_account_merge_source FOREIGN KEY (source_user_id) REFERENCES iam.user_account(id),
    CONSTRAINT fk_account_merge_target FOREIGN KEY (target_user_id) REFERENCES iam.user_account(id),
    CONSTRAINT ck_account_merge_distinct CHECK (source_user_id <> target_user_id),
    CONSTRAINT ck_account_merge_state CHECK (merge_state IN ('CANDIDATE', 'VERIFYING', 'CONFLICT', 'APPROVED', 'EXECUTING', 'COMPLETED', 'FAILED', 'CANCELLED')),
    CONSTRAINT ck_account_merge_completed CHECK (merge_state <> 'COMPLETED' OR completed_at IS NOT NULL)
);

COMMENT ON TABLE iam.account_merge IS 'CAP-ID-015 至 018：重复候选、双账号验证、冲突处理、审批、不可逆边界与合并 Operation。';

CREATE TABLE iam.account_merge_item (
    id uuid        NOT NULL DEFAULT gen_random_uuid(),
    merge_id uuid        NOT NULL,
    domain_code text        NOT NULL,
    source_ref text        NULL,
    target_ref text        NULL,
    resolution_action text        NOT NULL,
    resolution_state text        NOT NULL DEFAULT 'PENDING',
    evidence jsonb       NULL,
    completed_at timestamptz NULL,
    CONSTRAINT pk_account_merge_item PRIMARY KEY (id),
    CONSTRAINT fk_account_merge_item_merge FOREIGN KEY (merge_id) REFERENCES iam.account_merge(id) ON DELETE CASCADE,
    CONSTRAINT ck_account_merge_item_action CHECK (resolution_action IN ('MOVE', 'KEEP_TARGET', 'KEEP_BOTH', 'REVOKE', 'MANUAL', 'REJECT')),
    CONSTRAINT ck_account_merge_item_state CHECK (resolution_state IN ('PENDING', 'RESOLVED', 'BLOCKED', 'FAILED')),
    CONSTRAINT uq_account_merge_item UNIQUE NULLS NOT DISTINCT (merge_id, domain_code, source_ref, target_ref)
);

COMMENT ON TABLE iam.account_merge_item IS 'CAP-ID-016/017：按权威域记录合并冲突、处置动作、证据与执行结果。';

CREATE TABLE iam.account_deletion (
    id uuid        NOT NULL DEFAULT gen_random_uuid(),
    user_id uuid        NOT NULL,
    operation_id uuid        NOT NULL,
    requested_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    cooling_off_until timestamptz NOT NULL,
    blocked_reason_code text        NULL,
    blocked_owner text        NULL,
    blocked_at timestamptz NULL,
    resumed_at timestamptz NULL,
    withdrawn_at timestamptz NULL,
    withdrawal_auth_time timestamptz NULL,
    irreversible_at timestamptz NULL,
    completion_kind text        NULL,
    completion_proof_ref text        NULL,
    completed_at timestamptz NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    row_version bigint      NOT NULL DEFAULT 1,
    CONSTRAINT pk_account_deletion PRIMARY KEY (id),
    CONSTRAINT uq_account_deletion_operation UNIQUE (operation_id),
    CONSTRAINT fk_account_deletion_user FOREIGN KEY (user_id) REFERENCES iam.user_account(id),
    CONSTRAINT ck_account_deletion_cooling CHECK (cooling_off_until >= requested_at),
    CONSTRAINT ck_account_deletion_block CHECK (
    (blocked_at IS NULL AND blocked_reason_code IS NULL AND blocked_owner IS NULL)
    OR (blocked_at IS NOT NULL AND blocked_reason_code IS NOT NULL AND blocked_owner IS NOT NULL)
    ),
    CONSTRAINT ck_account_deletion_completion CHECK (completion_kind IS NULL OR completion_kind IN ('ANONYMIZED', 'ERASED'))
);

COMMENT ON TABLE iam.account_deletion IS 'CAP-ID-020 至 023 / REQ-ID-014 至 016：注销冷静期、阻断、恢复原检查点、撤回强认证和完成证明。';

CREATE UNIQUE INDEX ux_identifier_primary
    ON iam.identifier(user_id, identifier_type)
    WHERE is_primary AND identifier_state = 'VERIFIED';

CREATE UNIQUE INDEX ux_account_merge_active_source
    ON iam.account_merge(source_user_id)
    WHERE merge_state IN ('CANDIDATE', 'VERIFYING', 'CONFLICT', 'APPROVED', 'EXECUTING');

CREATE UNIQUE INDEX ux_account_deletion_active_user
    ON iam.account_deletion(user_id)
    WHERE completed_at IS NULL AND withdrawn_at IS NULL;

CREATE INDEX ix_user_account_lifecycle ON iam.user_account(lifecycle_state, updated_at DESC);

CREATE INDEX ix_user_account_frozen ON iam.user_account(frozen_at DESC) WHERE security_freeze_state = 'FROZEN';

CREATE INDEX ix_identifier_user ON iam.identifier(user_id, identifier_type, identifier_state);

CREATE INDEX ix_identifier_lookup ON iam.identifier(identifier_type, value_blind_index, blind_index_key_version);

CREATE INDEX ix_identifier_tombstone_quarantine ON iam.identifier_tombstone(quarantine_until);

CREATE UNIQUE INDEX ux_identifier_verified_scope
    ON iam.identifier(identifier_type, uniqueness_scope, scope_ref_id, ownership_digest)
    WHERE identifier_state = 'VERIFIED';

CREATE UNIQUE INDEX ux_subject_assignment_active
    ON iam.subject_assignment(user_id, audience_kind, audience_ref_id)
    WHERE retired_at IS NULL;

CREATE INDEX ix_fk_user_account_merged_into_user_id ON iam.user_account (merged_into_user_id);

CREATE INDEX ix_fk_identifier_tombstone_former_user_id ON iam.identifier_tombstone (former_user_id);

CREATE INDEX ix_fk_account_merge_source_user_id ON iam.account_merge (source_user_id);

CREATE INDEX ix_fk_account_merge_target_user_id ON iam.account_merge (target_user_id);

CREATE INDEX ix_fk_account_deletion_user_id ON iam.account_deletion (user_id);

COMMENT ON COLUMN iam.user_account.id IS '内部 UUID 主键；仅用于数据库关系，不作为跨域公开标识。';
COMMENT ON COLUMN iam.user_account.public_id IS '不可复用的公开稳定标识；插入时登记到 core.public_id_ledger。';
COMMENT ON COLUMN iam.user_account.subject_kind IS '对象类别判别字段；允许值由 CHECK 或对应注册表限定。';
COMMENT ON COLUMN iam.user_account.lifecycle_state IS '显式状态当前值；合法取值见 CHECK，完整状态转换由 .NET 领域策略执行。';
COMMENT ON COLUMN iam.user_account.authentication_lock_state IS '显式状态当前值；合法取值见 CHECK，完整状态转换由 .NET 领域策略执行。';
COMMENT ON COLUMN iam.user_account.security_freeze_state IS '显式状态当前值；合法取值见 CHECK，完整状态转换由 .NET 领域策略执行。';
COMMENT ON COLUMN iam.user_account.user_security_epoch IS '安全或同意水位版本；只能单调递增，用于令牌、缓存与撤销新鲜度校验。';
COMMENT ON COLUMN iam.user_account.aggregate_version IS '对象、策略或源数据的显式版本；不得以不可信客户端时间戳替代。';
COMMENT ON COLUMN iam.user_account.creation_source IS 'iam.user_account.creation_source 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN iam.user_account.creation_client_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN iam.user_account.activated_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN iam.user_account.dormant_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN iam.user_account.last_authenticated_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN iam.user_account.lock_reason_code IS '稳定机器可读代码；展示文本由资源或目录解析。';
COMMENT ON COLUMN iam.user_account.lock_until IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN iam.user_account.freeze_reason_code IS '稳定机器可读代码；展示文本由资源或目录解析。';
COMMENT ON COLUMN iam.user_account.frozen_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN iam.user_account.frozen_by_ref IS '不透明对象引用；不得从格式推断手机号、邮箱或其他业务事实。';
COMMENT ON COLUMN iam.user_account.deletion_requested_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN iam.user_account.anonymized_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN iam.user_account.erased_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN iam.user_account.merged_into_user_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN iam.user_account.terminal_reason_code IS '稳定机器可读代码；展示文本由资源或目录解析。';
COMMENT ON COLUMN iam.user_account.created_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN iam.user_account.updated_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN iam.user_account.row_version IS '乐观并发版本；更新必须使用原值 compare-and-set，成功后由数据库单调递增。';
COMMENT ON COLUMN iam.subject_assignment.id IS '内部 UUID 主键；仅用于数据库关系，不作为跨域公开标识。';
COMMENT ON COLUMN iam.subject_assignment.public_id IS '不可复用的公开稳定标识；插入时登记到 core.public_id_ledger。';
COMMENT ON COLUMN iam.subject_assignment.user_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN iam.subject_assignment.audience_kind IS '对象类别判别字段；允许值由 CHECK 或对应注册表限定。';
COMMENT ON COLUMN iam.subject_assignment.audience_ref_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN iam.subject_assignment.subject_version IS '对象、策略或源数据的显式版本；不得以不可信客户端时间戳替代。';
COMMENT ON COLUMN iam.subject_assignment.created_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN iam.subject_assignment.retired_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN iam.identifier.id IS '内部 UUID 主键；仅用于数据库关系，不作为跨域公开标识。';
COMMENT ON COLUMN iam.identifier.user_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN iam.identifier.identifier_type IS '对象类别判别字段；允许值由 CHECK 或对应注册表限定。';
COMMENT ON COLUMN iam.identifier.identifier_state IS '显式状态当前值；合法取值见 CHECK，完整状态转换由 .NET 领域策略执行。';
COMMENT ON COLUMN iam.identifier.uniqueness_scope IS 'iam.identifier.uniqueness_scope 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN iam.identifier.scope_ref_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN iam.identifier.value_cipher IS '随机化加密密文；解密密钥由独立 KMS/HSM 引用管理。';
COMMENT ON COLUMN iam.identifier.value_blind_index IS '带版本的密钥化盲索引；只用于受控等值检索。';
COMMENT ON COLUMN iam.identifier.value_masked IS 'iam.identifier.value_masked 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN iam.identifier.cipher_key_version IS '生成密文、HMAC 或盲索引所用密钥版本；轮换时保留可验证窗口。';
COMMENT ON COLUMN iam.identifier.blind_index_key_version IS '生成密文、HMAC 或盲索引所用密钥版本；轮换时保留可验证窗口。';
COMMENT ON COLUMN iam.identifier.normalization_version IS '对象、策略或源数据的显式版本；不得以不可信客户端时间戳替代。';
COMMENT ON COLUMN iam.identifier.normalization_profile_code IS '稳定机器可读代码；展示文本由资源或目录解析。';
COMMENT ON COLUMN iam.identifier.verified_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN iam.identifier.verification_method IS 'iam.identifier.verification_method 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN iam.identifier.unbound_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN iam.identifier.quarantine_until IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN iam.identifier.released_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN iam.identifier.is_primary IS '显式布尔开关；启用前置条件与失效行为由约束和版本化策略控制。';
COMMENT ON COLUMN iam.identifier.created_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN iam.identifier.updated_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN iam.identifier.row_version IS '乐观并发版本；更新必须使用原值 compare-and-set，成功后由数据库单调递增。';
COMMENT ON COLUMN iam.identifier.ownership_digest IS '不可逆摘要；用于等值匹配、幂等、完整性或最小化证据，不保存原始敏感值。';
COMMENT ON COLUMN iam.identifier.ownership_key_version IS '生成密文、HMAC 或盲索引所用密钥版本；轮换时保留可验证窗口。';
COMMENT ON COLUMN iam.identifier.state_reason_code IS '稳定机器可读代码；展示文本由资源或目录解析。';
COMMENT ON COLUMN iam.identifier_tombstone.id IS '内部 UUID 主键；仅用于数据库关系，不作为跨域公开标识。';
COMMENT ON COLUMN iam.identifier_tombstone.identifier_type IS '对象类别判别字段；允许值由 CHECK 或对应注册表限定。';
COMMENT ON COLUMN iam.identifier_tombstone.uniqueness_scope IS 'iam.identifier_tombstone.uniqueness_scope 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN iam.identifier_tombstone.scope_ref_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN iam.identifier_tombstone.value_blind_index IS '带版本的密钥化盲索引；只用于受控等值检索。';
COMMENT ON COLUMN iam.identifier_tombstone.blind_index_key_version IS '生成密文、HMAC 或盲索引所用密钥版本；轮换时保留可验证窗口。';
COMMENT ON COLUMN iam.identifier_tombstone.former_user_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN iam.identifier_tombstone.ownership_digest IS '不可逆摘要；用于等值匹配、幂等、完整性或最小化证据，不保存原始敏感值。';
COMMENT ON COLUMN iam.identifier_tombstone.quarantine_until IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN iam.identifier_tombstone.released_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN iam.identifier_tombstone.created_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN iam.identifier_tombstone.ownership_key_version IS '生成密文、HMAC 或盲索引所用密钥版本；轮换时保留可验证窗口。';
COMMENT ON COLUMN iam.account_merge.id IS '内部 UUID 主键；仅用于数据库关系，不作为跨域公开标识。';
COMMENT ON COLUMN iam.account_merge.public_id IS '不可复用的公开稳定标识；插入时登记到 core.public_id_ledger。';
COMMENT ON COLUMN iam.account_merge.source_user_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN iam.account_merge.target_user_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN iam.account_merge.merge_state IS '显式状态当前值；合法取值见 CHECK，完整状态转换由 .NET 领域策略执行。';
COMMENT ON COLUMN iam.account_merge.source_verified_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN iam.account_merge.target_verified_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN iam.account_merge.conflict_summary IS '版本化结构化扩展数据；必须由 .NET 按对应 JSON Schema 校验，不得替代核心状态或外键。';
COMMENT ON COLUMN iam.account_merge.approval_case_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN iam.account_merge.operation_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN iam.account_merge.irreversible_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN iam.account_merge.completed_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN iam.account_merge.failed_reason_code IS '稳定机器可读代码；展示文本由资源或目录解析。';
COMMENT ON COLUMN iam.account_merge.created_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN iam.account_merge.updated_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN iam.account_merge.row_version IS '乐观并发版本；更新必须使用原值 compare-and-set，成功后由数据库单调递增。';
COMMENT ON COLUMN iam.account_merge_item.id IS '内部 UUID 主键；仅用于数据库关系，不作为跨域公开标识。';
COMMENT ON COLUMN iam.account_merge_item.merge_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN iam.account_merge_item.domain_code IS '稳定机器可读代码；展示文本由资源或目录解析。';
COMMENT ON COLUMN iam.account_merge_item.source_ref IS '不透明对象引用；不得从格式推断手机号、邮箱或其他业务事实。';
COMMENT ON COLUMN iam.account_merge_item.target_ref IS '不透明对象引用；不得从格式推断手机号、邮箱或其他业务事实。';
COMMENT ON COLUMN iam.account_merge_item.resolution_action IS 'iam.account_merge_item.resolution_action 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN iam.account_merge_item.resolution_state IS '显式状态当前值；合法取值见 CHECK，完整状态转换由 .NET 领域策略执行。';
COMMENT ON COLUMN iam.account_merge_item.evidence IS '版本化结构化扩展数据；必须由 .NET 按对应 JSON Schema 校验，不得替代核心状态或外键。';
COMMENT ON COLUMN iam.account_merge_item.completed_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN iam.account_deletion.id IS '内部 UUID 主键；仅用于数据库关系，不作为跨域公开标识。';
COMMENT ON COLUMN iam.account_deletion.user_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN iam.account_deletion.operation_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN iam.account_deletion.requested_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN iam.account_deletion.cooling_off_until IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN iam.account_deletion.blocked_reason_code IS '稳定机器可读代码；展示文本由资源或目录解析。';
COMMENT ON COLUMN iam.account_deletion.blocked_owner IS 'iam.account_deletion.blocked_owner 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN iam.account_deletion.blocked_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN iam.account_deletion.resumed_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN iam.account_deletion.withdrawn_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN iam.account_deletion.withdrawal_auth_time IS 'iam.account_deletion.withdrawal_auth_time 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN iam.account_deletion.irreversible_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN iam.account_deletion.completion_kind IS '对象类别判别字段；允许值由 CHECK 或对应注册表限定。';
COMMENT ON COLUMN iam.account_deletion.completion_proof_ref IS '不透明对象引用；不得从格式推断手机号、邮箱或其他业务事实。';
COMMENT ON COLUMN iam.account_deletion.completed_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN iam.account_deletion.created_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN iam.account_deletion.updated_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN iam.account_deletion.row_version IS '乐观并发版本；更新必须使用原值 compare-and-set，成功后由数据库单调递增。';

COMMENT ON CONSTRAINT pk_user_account ON iam.user_account IS '主键约束：唯一标识 iam.user_account 记录。';
COMMENT ON CONSTRAINT uq_user_account_public_id ON iam.user_account IS '唯一约束：保证 public_id 在 iam.user_account 范围内不重复。';
COMMENT ON CONSTRAINT fk_user_account_merged_into ON iam.user_account IS '外键约束：iam.user_account 的 merged_into_user_id 必须引用 iam.user_account；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT ck_user_account_kind ON iam.user_account IS '检查约束：限制 iam.user_account 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_user_account_lifecycle ON iam.user_account IS '检查约束：限制 iam.user_account 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_user_account_lock ON iam.user_account IS '检查约束：限制 iam.user_account 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_user_account_freeze ON iam.user_account IS '检查约束：限制 iam.user_account 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_user_account_epoch ON iam.user_account IS '检查约束：限制 iam.user_account 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_user_account_frozen ON iam.user_account IS '检查约束：限制 iam.user_account 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_user_account_merged ON iam.user_account IS '检查约束：限制 iam.user_account 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_user_account_anonymized ON iam.user_account IS '检查约束：限制 iam.user_account 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_user_account_erased ON iam.user_account IS '检查约束：限制 iam.user_account 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT pk_subject_assignment ON iam.subject_assignment IS '主键约束：唯一标识 iam.subject_assignment 记录。';
COMMENT ON CONSTRAINT uq_subject_assignment_public_id ON iam.subject_assignment IS '唯一约束：保证 public_id 在 iam.subject_assignment 范围内不重复。';
COMMENT ON CONSTRAINT uq_subject_assignment_audience ON iam.subject_assignment IS '唯一约束：保证 user_id、audience_kind、audience_ref_id、subject_version 在 iam.subject_assignment 范围内不重复。';
COMMENT ON CONSTRAINT fk_subject_assignment_user ON iam.subject_assignment IS '外键约束：iam.subject_assignment 的 user_id 必须引用 iam.user_account；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT ck_subject_assignment_audience ON iam.subject_assignment IS '检查约束：限制 iam.subject_assignment 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_subject_assignment_version ON iam.subject_assignment IS '检查约束：限制 iam.subject_assignment 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT pk_identifier ON iam.identifier IS '主键约束：唯一标识 iam.identifier 记录。';
COMMENT ON CONSTRAINT fk_identifier_user ON iam.identifier IS '外键约束：iam.identifier 的 user_id 必须引用 iam.user_account；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT ck_identifier_type ON iam.identifier IS '检查约束：限制 iam.identifier 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_identifier_state ON iam.identifier IS '检查约束：限制 iam.identifier 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_identifier_scope ON iam.identifier IS '检查约束：限制 iam.identifier 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_identifier_blind_index ON iam.identifier IS '检查约束：限制 iam.identifier 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_identifier_versions ON iam.identifier IS '检查约束：限制 iam.identifier 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_identifier_verified ON iam.identifier IS '检查约束：限制 iam.identifier 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_identifier_quarantine ON iam.identifier IS '检查约束：限制 iam.identifier 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_identifier_ownership_digest ON iam.identifier IS '检查约束：限制 iam.identifier 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_identifier_verified_history ON iam.identifier IS '检查约束：限制 iam.identifier 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_identifier_unbound_history ON iam.identifier IS '检查约束：限制 iam.identifier 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_identifier_released ON iam.identifier IS '检查约束：限制 iam.identifier 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT pk_identifier_tombstone ON iam.identifier_tombstone IS '主键约束：唯一标识 iam.identifier_tombstone 记录。';
COMMENT ON CONSTRAINT fk_identifier_tombstone_user ON iam.identifier_tombstone IS '外键约束：iam.identifier_tombstone 的 former_user_id 必须引用 iam.user_account；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT ck_identifier_tombstone_hash ON iam.identifier_tombstone IS '检查约束：限制 iam.identifier_tombstone 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT uq_identifier_tombstone ON iam.identifier_tombstone IS '唯一约束：保证 identifier_type、uniqueness_scope、scope_ref_id、ownership_digest 在 iam.identifier_tombstone 范围内不重复。';
COMMENT ON CONSTRAINT ck_identifier_tombstone_ownership ON iam.identifier_tombstone IS '检查约束：限制 iam.identifier_tombstone 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT pk_account_merge ON iam.account_merge IS '主键约束：唯一标识 iam.account_merge 记录。';
COMMENT ON CONSTRAINT uq_account_merge_public_id ON iam.account_merge IS '唯一约束：保证 public_id 在 iam.account_merge 范围内不重复。';
COMMENT ON CONSTRAINT fk_account_merge_source ON iam.account_merge IS '外键约束：iam.account_merge 的 source_user_id 必须引用 iam.user_account；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT fk_account_merge_target ON iam.account_merge IS '外键约束：iam.account_merge 的 target_user_id 必须引用 iam.user_account；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT ck_account_merge_distinct ON iam.account_merge IS '检查约束：限制 iam.account_merge 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_account_merge_state ON iam.account_merge IS '检查约束：限制 iam.account_merge 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_account_merge_completed ON iam.account_merge IS '检查约束：限制 iam.account_merge 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT pk_account_merge_item ON iam.account_merge_item IS '主键约束：唯一标识 iam.account_merge_item 记录。';
COMMENT ON CONSTRAINT fk_account_merge_item_merge ON iam.account_merge_item IS '外键约束：iam.account_merge_item 的 merge_id 必须引用 iam.account_merge；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT ck_account_merge_item_action ON iam.account_merge_item IS '检查约束：限制 iam.account_merge_item 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_account_merge_item_state ON iam.account_merge_item IS '检查约束：限制 iam.account_merge_item 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT uq_account_merge_item ON iam.account_merge_item IS '唯一约束：保证 merge_id、domain_code、source_ref、target_ref 在 iam.account_merge_item 范围内不重复。';
COMMENT ON CONSTRAINT pk_account_deletion ON iam.account_deletion IS '主键约束：唯一标识 iam.account_deletion 记录。';
COMMENT ON CONSTRAINT uq_account_deletion_operation ON iam.account_deletion IS '唯一约束：保证 operation_id 在 iam.account_deletion 范围内不重复。';
COMMENT ON CONSTRAINT fk_account_deletion_user ON iam.account_deletion IS '外键约束：iam.account_deletion 的 user_id 必须引用 iam.user_account；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT ck_account_deletion_cooling ON iam.account_deletion IS '检查约束：限制 iam.account_deletion 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_account_deletion_block ON iam.account_deletion IS '检查约束：限制 iam.account_deletion 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_account_deletion_completion ON iam.account_deletion IS '检查约束：限制 iam.account_deletion 的字段取值或组合满足结构与安全底线。';

COMMENT ON INDEX iam.ux_identifier_primary IS '查询索引：优化 iam.identifier 按 user_id、identifier_type 的访问，仅覆盖 WHERE 条件命中的记录。';
COMMENT ON INDEX iam.ux_account_merge_active_source IS '查询索引：优化 iam.account_merge 按 source_user_id 的访问，仅覆盖 WHERE 条件命中的记录。';
COMMENT ON INDEX iam.ux_account_deletion_active_user IS '查询索引：优化 iam.account_deletion 按 user_id 的访问，仅覆盖 WHERE 条件命中的记录。';
COMMENT ON INDEX iam.ix_user_account_lifecycle IS '查询索引：优化 iam.user_account 按 lifecycle_state、updated_at 的访问。';
COMMENT ON INDEX iam.ix_user_account_frozen IS '查询索引：优化 iam.user_account 按 frozen_at 的访问，仅覆盖 WHERE 条件命中的记录。';
COMMENT ON INDEX iam.ix_identifier_user IS '查询索引：优化 iam.identifier 按 user_id、identifier_type、identifier_state 的访问。';
COMMENT ON INDEX iam.ix_identifier_lookup IS '查询索引：优化 iam.identifier 按 identifier_type、value_blind_index、blind_index_key_version 的访问。';
COMMENT ON INDEX iam.ix_identifier_tombstone_quarantine IS '查询索引：优化 iam.identifier_tombstone 按 quarantine_until 的访问。';
COMMENT ON INDEX iam.ux_identifier_verified_scope IS '查询索引：优化 iam.identifier 按 identifier_type、uniqueness_scope、scope_ref_id、ownership_digest 的访问，仅覆盖 WHERE 条件命中的记录。';
COMMENT ON INDEX iam.ux_subject_assignment_active IS '查询索引：优化 iam.subject_assignment 按 user_id、audience_kind、audience_ref_id 的访问，仅覆盖 WHERE 条件命中的记录。';
COMMENT ON INDEX iam.pk_user_account IS '约束 pk_user_account 的支撑唯一索引。';
COMMENT ON INDEX iam.uq_user_account_public_id IS '约束 uq_user_account_public_id 的支撑唯一索引。';
COMMENT ON INDEX iam.pk_subject_assignment IS '约束 pk_subject_assignment 的支撑唯一索引。';
COMMENT ON INDEX iam.uq_subject_assignment_public_id IS '约束 uq_subject_assignment_public_id 的支撑唯一索引。';
COMMENT ON INDEX iam.uq_subject_assignment_audience IS '约束 uq_subject_assignment_audience 的支撑唯一索引。';
COMMENT ON INDEX iam.pk_identifier IS '约束 pk_identifier 的支撑唯一索引。';
COMMENT ON INDEX iam.pk_identifier_tombstone IS '约束 pk_identifier_tombstone 的支撑唯一索引。';
COMMENT ON INDEX iam.uq_identifier_tombstone IS '约束 uq_identifier_tombstone 的支撑唯一索引。';
COMMENT ON INDEX iam.pk_account_merge IS '约束 pk_account_merge 的支撑唯一索引。';
COMMENT ON INDEX iam.uq_account_merge_public_id IS '约束 uq_account_merge_public_id 的支撑唯一索引。';
COMMENT ON INDEX iam.pk_account_merge_item IS '约束 pk_account_merge_item 的支撑唯一索引。';
COMMENT ON INDEX iam.uq_account_merge_item IS '约束 uq_account_merge_item 的支撑唯一索引。';
COMMENT ON INDEX iam.pk_account_deletion IS '约束 pk_account_deletion 的支撑唯一索引。';
COMMENT ON INDEX iam.uq_account_deletion_operation IS '约束 uq_account_deletion_operation 的支撑唯一索引。';
COMMENT ON INDEX iam.ix_fk_user_account_merged_into_user_id IS '查询索引：优化 iam.user_account 按 merged_into_user_id 的访问。';
COMMENT ON INDEX iam.ix_fk_identifier_tombstone_former_user_id IS '查询索引：优化 iam.identifier_tombstone 按 former_user_id 的访问。';
COMMENT ON INDEX iam.ix_fk_account_merge_source_user_id IS '查询索引：优化 iam.account_merge 按 source_user_id 的访问。';
COMMENT ON INDEX iam.ix_fk_account_merge_target_user_id IS '查询索引：优化 iam.account_merge 按 target_user_id 的访问。';
COMMENT ON INDEX iam.ix_fk_account_deletion_user_id IS '查询索引：优化 iam.account_deletion 按 user_id 的访问。';

