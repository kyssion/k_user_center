-- =============================================================================
-- baseline/schemas/control/tables.sql
-- control Schema 的最终基表、同 Schema 约束、索引及内联 COMMENT
-- PostgreSQL 16+；应用技术栈：.NET 10 + SqlSugar
-- =============================================================================

CREATE TABLE control.approval_case (
    id uuid        NOT NULL DEFAULT gen_random_uuid(),
    public_id text        NOT NULL,
    approval_type text        NOT NULL,
    approval_state text        NOT NULL DEFAULT 'DRAFT',
    requested_by_ref text        NOT NULL,
    requested_by_kind text        NOT NULL,
    tenant_id uuid        NOT NULL DEFAULT '00000000-0000-0000-0000-000000000000',
    resource_kind text        NOT NULL,
    resource_ref text        NOT NULL,
    immutable_request_hash bytea      NOT NULL,
    before_value_hash bytea       NULL,
    after_value_hash bytea       NOT NULL,
    justification text        NOT NULL,
    required_approvals smallint    NOT NULL DEFAULT 1,
    policy_version bigint      NOT NULL,
    resource_version text        NULL,
    risk_snapshot_hash bytea       NOT NULL,
    valid_until timestamptz NOT NULL,
    approved_at timestamptz NULL,
    executed_at timestamptz NULL,
    execution_id uuid        NULL,
    cancelled_at timestamptz NULL,
    expired_at timestamptz NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    row_version bigint      NOT NULL DEFAULT 1,
    submitted_at timestamptz NULL,
    rejected_at timestamptz NULL,
    CONSTRAINT pk_approval_case PRIMARY KEY (id),
    CONSTRAINT uq_approval_case_public_id UNIQUE (public_id),
    CONSTRAINT uq_approval_case_execution UNIQUE (execution_id),
    CONSTRAINT ck_approval_case_type CHECK (approval_type IN ('CONFIG_RELEASE', 'PRIVILEGED_ACCESS', 'TENANT_TRANSFER', 'ACCOUNT_MERGE', 'SECURITY_EXCEPTION', 'BREAK_GLASS', 'DELEGATION', 'KEY_OPERATION', 'DATA_EXPORT', 'EVENT_REPLAY', 'RECOVERY')),
    CONSTRAINT ck_approval_case_state CHECK (approval_state IN ('DRAFT', 'PENDING_REVIEW', 'APPROVED', 'EXECUTED', 'REJECTED', 'CANCELLED', 'EXPIRED')),
    CONSTRAINT ck_approval_case_requester CHECK (requested_by_kind IN ('USER', 'ADMIN', 'CLIENT', 'MACHINE', 'SYSTEM')),
    CONSTRAINT ck_approval_case_hashes CHECK (octet_length(immutable_request_hash) = 32 AND octet_length(after_value_hash) = 32 AND octet_length(risk_snapshot_hash) = 32),
    CONSTRAINT ck_approval_case_required CHECK (required_approvals BETWEEN 1 AND 5),
    CONSTRAINT ck_approval_case_expiry CHECK (valid_until > created_at),
    CONSTRAINT ck_approval_case_cancelled CHECK ((approval_state = 'CANCELLED') = (cancelled_at IS NOT NULL)),
    CONSTRAINT ck_approval_case_expired CHECK ((approval_state = 'EXPIRED') = (expired_at IS NOT NULL)),
    CONSTRAINT ck_approval_case_submitted CHECK (
    (approval_state IN ('PENDING_REVIEW', 'APPROVED', 'EXECUTED', 'REJECTED', 'EXPIRED')) = (submitted_at IS NOT NULL)
    OR (approval_state = 'CANCELLED')
    ),
    CONSTRAINT ck_approval_case_approved CHECK (
    (approved_at IS NULL OR approval_state IN ('APPROVED', 'EXECUTED', 'CANCELLED', 'EXPIRED'))
    AND (approval_state NOT IN ('APPROVED', 'EXECUTED') OR approved_at IS NOT NULL)
    ),
    CONSTRAINT ck_approval_case_executed CHECK (
    (approval_state = 'EXECUTED' AND executed_at IS NOT NULL AND execution_id IS NOT NULL)
    OR (approval_state <> 'EXECUTED' AND executed_at IS NULL AND execution_id IS NULL)
    ),
    CONSTRAINT ck_approval_case_rejected CHECK ((approval_state = 'REJECTED') = (rejected_at IS NOT NULL))
);

COMMENT ON TABLE control.approval_case IS 'INV-G-017 / REQ-ASR-004/005：职责分离、不可变请求摘要、有效期、版本绑定和单次执行的高风险审批单。';

CREATE TABLE control.approval_decision (
    id uuid        NOT NULL DEFAULT gen_random_uuid(),
    approval_case_id uuid        NOT NULL,
    approver_kind text        NOT NULL,
    approver_ref text        NOT NULL,
    decision text        NOT NULL,
    decision_reason text        NOT NULL,
    assurance_context_hash bytea      NOT NULL,
    risk_snapshot_hash bytea       NOT NULL,
    decided_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT pk_approval_decision PRIMARY KEY (id),
    CONSTRAINT uq_approval_decision_approver UNIQUE (approval_case_id, approver_kind, approver_ref),
    CONSTRAINT fk_approval_decision_case FOREIGN KEY (approval_case_id) REFERENCES control.approval_case(id) ON DELETE CASCADE,
    CONSTRAINT ck_approval_decision_approver CHECK (approver_kind IN ('USER', 'ADMIN')),
    CONSTRAINT ck_approval_decision_value CHECK (decision IN ('APPROVE', 'REJECT')),
    CONSTRAINT ck_approval_decision_hash CHECK (octet_length(assurance_context_hash) = 32 AND octet_length(risk_snapshot_hash) = 32)
);

COMMENT ON TABLE control.approval_decision IS '审批人的不可抵赖决定、认证保证和风险快照；同一审批人只能决定一次。';

CREATE TABLE control.config_release (
    id uuid        NOT NULL DEFAULT gen_random_uuid(),
    public_id text        NOT NULL,
    config_kind text        NOT NULL,
    config_code text        NOT NULL,
    release_version bigint      NOT NULL,
    release_state text        NOT NULL DEFAULT 'DRAFT',
    environment text        NOT NULL,
    content_hash bytea       NOT NULL,
    content_uri text        NOT NULL,
    dependency_versions jsonb       NOT NULL DEFAULT '{}',
    owner_ref text        NOT NULL,
    approval_case_id uuid        NULL,
    rollback_of_id uuid        NULL,
    validation_evidence jsonb       NULL,
    staged_at timestamptz NULL,
    activated_at timestamptz NULL,
    deprecated_at timestamptz NULL,
    revoked_at timestamptz NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    approval_execution_id uuid NULL,
    CONSTRAINT pk_config_release PRIMARY KEY (id),
    CONSTRAINT uq_config_release_public_id UNIQUE (public_id),
    CONSTRAINT uq_config_release_version UNIQUE (config_kind, config_code, environment, release_version),
    CONSTRAINT fk_config_release_approval FOREIGN KEY (approval_case_id) REFERENCES control.approval_case(id),
    CONSTRAINT fk_config_release_rollback FOREIGN KEY (rollback_of_id) REFERENCES control.config_release(id),
    CONSTRAINT ck_config_release_kind CHECK (config_kind IN ('CLIENT', 'CALLBACK', 'IDENTITY_PROVIDER', 'AUTHZ_POLICY', 'RISK_POLICY', 'RETENTION_RULE', 'TRUST_BUNDLE', 'KEY_POLICY', 'MESSAGE_TEMPLATE', 'EVENT_SCHEMA')),
    CONSTRAINT ck_config_release_state CHECK (release_state IN ('DRAFT', 'VALIDATED', 'APPROVED', 'STAGED', 'ACTIVE', 'DEPRECATED', 'REVOKED')),
    CONSTRAINT ck_config_release_hash CHECK (octet_length(content_hash) = 32),
    CONSTRAINT ck_config_release_active CHECK (release_state <> 'ACTIVE' OR (approval_case_id IS NOT NULL AND activated_at IS NOT NULL AND validation_evidence IS NOT NULL)),
    CONSTRAINT ck_config_release_state_times CHECK (
    (staged_at IS NULL OR release_state IN ('STAGED', 'ACTIVE', 'DEPRECATED', 'REVOKED'))
    AND (activated_at IS NULL OR release_state IN ('ACTIVE', 'DEPRECATED', 'REVOKED'))
    AND (deprecated_at IS NULL OR release_state = 'DEPRECATED')
    AND ((release_state = 'STAGED') = (staged_at IS NOT NULL AND activated_at IS NULL AND deprecated_at IS NULL AND revoked_at IS NULL))
    AND (release_state <> 'ACTIVE' OR (staged_at IS NOT NULL AND activated_at IS NOT NULL AND deprecated_at IS NULL AND revoked_at IS NULL))
    AND (release_state <> 'DEPRECATED' OR (staged_at IS NOT NULL AND activated_at IS NOT NULL AND deprecated_at IS NOT NULL AND revoked_at IS NULL))
    AND ((release_state = 'REVOKED') = (revoked_at IS NOT NULL))
    )
);

COMMENT ON TABLE control.config_release IS 'INV-G-011 / REQ-CTRL-001 至 004：控制面不可变配置、校验、审批、灰度、激活和新 Release 回滚。';

CREATE TABLE control.security_exception (
    id uuid        NOT NULL DEFAULT gen_random_uuid(),
    public_id text        NOT NULL,
    exception_code text        NOT NULL,
    exception_state text        NOT NULL DEFAULT 'DRAFT',
    requirement_ids text[]      NOT NULL,
    scope_definition jsonb       NOT NULL,
    risk_statement text        NOT NULL,
    compensating_controls jsonb       NOT NULL,
    risk_acceptor_ref text        NOT NULL,
    owner_ref text        NOT NULL,
    approval_case_id uuid,
    starts_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    tightened_at timestamptz NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    row_version bigint      NOT NULL DEFAULT 1,
    tenant_id uuid NOT NULL DEFAULT '00000000-0000-0000-0000-000000000000',
    exception_context_hash bytea NOT NULL,
    approved_at timestamptz NULL,
    activated_at timestamptz NULL,
    expired_at timestamptz NULL,
    revoked_at timestamptz NULL,
    state_reason_code text NULL,
    CONSTRAINT pk_security_exception PRIMARY KEY (id),
    CONSTRAINT uq_security_exception_public_id UNIQUE (public_id),
    CONSTRAINT uq_security_exception_code UNIQUE (exception_code),
    CONSTRAINT fk_security_exception_approval FOREIGN KEY (approval_case_id) REFERENCES control.approval_case(id),
    CONSTRAINT ck_security_exception_state CHECK (exception_state IN ('DRAFT', 'APPROVED', 'ACTIVE', 'EXPIRED', 'REVOKED', 'TIGHTENED')),
    CONSTRAINT ck_security_exception_requirements CHECK (cardinality(requirement_ids) > 0),
    CONSTRAINT ck_security_exception_window CHECK (expires_at > starts_at AND expires_at <= starts_at + interval '6 months'),
    CONSTRAINT ck_security_exception_tightened CHECK ((exception_state = 'TIGHTENED') = (tightened_at IS NOT NULL)),
    CONSTRAINT ck_security_exception_context_hash CHECK (octet_length(exception_context_hash) = 32),
    CONSTRAINT ck_security_exception_approved CHECK (
    exception_state NOT IN ('APPROVED', 'ACTIVE', 'TIGHTENED') OR (approved_at IS NOT NULL AND approval_case_id IS NOT NULL)
    ),
    CONSTRAINT ck_security_exception_active CHECK (exception_state <> 'ACTIVE' OR activated_at IS NOT NULL),
    CONSTRAINT ck_security_exception_expired_state CHECK ((exception_state = 'EXPIRED') = (expired_at IS NOT NULL)),
    CONSTRAINT ck_security_exception_revoked_state CHECK ((exception_state = 'REVOKED') = (revoked_at IS NOT NULL))
);

COMMENT ON TABLE control.security_exception IS 'CAP-CTRL-006/007：偏离要求的范围、风险接受、补偿控制、审批和最长六个月到期收紧。';

CREATE TABLE control.break_glass_grant (
    id uuid        NOT NULL DEFAULT gen_random_uuid(),
    public_id text        NOT NULL,
    user_id uuid        NOT NULL,
    tenant_id uuid        NOT NULL DEFAULT '00000000-0000-0000-0000-000000000000',
    permission_codes text[]      NOT NULL,
    grant_state text        NOT NULL DEFAULT 'PENDING',
    justification text        NOT NULL,
    approval_case_id uuid,
    activated_at timestamptz NULL,
    expires_at timestamptz NOT NULL,
    revoked_at timestamptz NULL,
    post_review_due_at timestamptz NOT NULL,
    post_reviewed_at timestamptz NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    grant_context_hash bytea NOT NULL,
    expired_at timestamptz NULL,
    revoke_reason_code text NULL,
    CONSTRAINT pk_break_glass_grant PRIMARY KEY (id),
    CONSTRAINT uq_break_glass_grant_public_id UNIQUE (public_id),
    CONSTRAINT fk_break_glass_approval FOREIGN KEY (approval_case_id) REFERENCES control.approval_case(id),
    CONSTRAINT ck_break_glass_state CHECK (grant_state IN ('PENDING', 'ACTIVE', 'EXPIRED', 'REVOKED')),
    CONSTRAINT ck_break_glass_permissions CHECK (cardinality(permission_codes) > 0),
    CONSTRAINT ck_break_glass_window CHECK (expires_at > created_at AND expires_at <= created_at + interval '4 hours'),
    CONSTRAINT ck_break_glass_review CHECK (post_review_due_at > expires_at),
    CONSTRAINT ck_break_glass_active CHECK (grant_state <> 'ACTIVE' OR activated_at IS NOT NULL),
    CONSTRAINT ck_break_glass_context_hash CHECK (octet_length(grant_context_hash) = 32),
    CONSTRAINT ck_break_glass_approval CHECK (grant_state <> 'ACTIVE' OR approval_case_id IS NOT NULL),
    CONSTRAINT ck_break_glass_expired CHECK ((grant_state = 'EXPIRED') = (expired_at IS NOT NULL)),
    CONSTRAINT ck_break_glass_revoked CHECK (
    (grant_state = 'REVOKED') = (revoked_at IS NOT NULL)
    AND (grant_state <> 'REVOKED' OR revoke_reason_code IS NOT NULL)
    )
);

COMMENT ON TABLE control.break_glass_grant IS 'REQ-CTRL-006：限时、最小权限、审批、使用即告警、自动失效与事后复核的 Break-glass。';

CREATE TABLE control.owner_review (
    id uuid        NOT NULL DEFAULT gen_random_uuid(),
    resource_kind text        NOT NULL,
    resource_ref text        NOT NULL,
    owner_ref text        NOT NULL,
    review_state text        NOT NULL DEFAULT 'DUE',
    due_at timestamptz NOT NULL,
    completed_at timestamptz NULL,
    outcome text        NULL,
    evidence_hash bytea       NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT pk_owner_review PRIMARY KEY (id),
    CONSTRAINT uq_owner_review UNIQUE (resource_kind, resource_ref, due_at),
    CONSTRAINT ck_owner_review_state CHECK (review_state IN ('DUE', 'IN_PROGRESS', 'COMPLETED', 'OVERDUE', 'WAIVED')),
    CONSTRAINT ck_owner_review_outcome CHECK (outcome IS NULL OR outcome IN ('RETAIN', 'SUSPEND', 'ROTATE', 'REASSIGN', 'RETIRE')),
    CONSTRAINT ck_owner_review_complete CHECK (review_state <> 'COMPLETED' OR (completed_at IS NOT NULL AND outcome IS NOT NULL AND evidence_hash IS NOT NULL))
);

COMMENT ON TABLE control.owner_review IS 'Client、机器主体、特权授权等 Owner 有效性、用途、到期、基线和轮换的周期复核。';

CREATE TABLE control.client_certification_run (
    id uuid        NOT NULL DEFAULT gen_random_uuid(),
    public_id text        NOT NULL,
    client_id uuid        NOT NULL,
    operation_id uuid        NOT NULL,
    certification_state text        NOT NULL DEFAULT 'PENDING',
    profile_code text        NOT NULL,
    profile_version integer     NOT NULL,
    environment text        NOT NULL,
    client_config_hash bytea       NOT NULL,
    protocol_test_report jsonb       NOT NULL DEFAULT '{}',
    security_test_report jsonb       NOT NULL DEFAULT '{}',
    tenant_isolation_report jsonb     NOT NULL DEFAULT '{}',
    passed_control_codes text[]      NOT NULL DEFAULT '{}',
    failed_control_codes text[]      NOT NULL DEFAULT '{}',
    evidence_uri text        NULL,
    started_at timestamptz NULL,
    completed_at timestamptz NULL,
    expires_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT pk_client_certification_run PRIMARY KEY (id),
    CONSTRAINT uq_client_certification_public_id UNIQUE (public_id),
    CONSTRAINT uq_client_certification_operation UNIQUE (operation_id),
    CONSTRAINT ck_client_certification_state CHECK (certification_state IN ('PENDING', 'RUNNING', 'PASSED', 'FAILED', 'EXPIRED', 'CANCELLED')),
    CONSTRAINT ck_client_certification_hash CHECK (octet_length(client_config_hash) = 32),
    CONSTRAINT ck_client_certification_result CHECK (certification_state NOT IN ('PASSED', 'FAILED') OR completed_at IS NOT NULL),
    CONSTRAINT ck_client_certification_pass CHECK (certification_state <> 'PASSED' OR cardinality(failed_control_codes) = 0),
    CONSTRAINT ck_client_certification_expiry CHECK (expires_at > created_at)
);

COMMENT ON TABLE control.client_certification_run IS 'CAP-PLT-019：Client 上线前按适用安全 Profile 执行协议、安全、隔离和负向测试的认证报告。';

CREATE UNIQUE INDEX ux_config_release_active ON control.config_release(config_kind, config_code, environment) WHERE release_state = 'ACTIVE';

CREATE INDEX ix_approval_case_queue ON control.approval_case(approval_state, valid_until) WHERE approval_state IN ('PENDING_REVIEW', 'APPROVED');

CREATE INDEX ix_security_exception_expiry ON control.security_exception(expires_at) WHERE exception_state = 'ACTIVE';

CREATE INDEX ix_client_certification_expiry ON control.client_certification_run(client_id, expires_at DESC) WHERE certification_state = 'PASSED';

CREATE INDEX ix_fk_config_release_approval_case_id ON control.config_release (approval_case_id);

CREATE INDEX ix_fk_config_release_rollback_of_id ON control.config_release (rollback_of_id);

CREATE INDEX ix_fk_security_exception_approval_case_id ON control.security_exception (approval_case_id);

CREATE INDEX ix_fk_break_glass_grant_approval_case_id ON control.break_glass_grant (approval_case_id);

COMMENT ON COLUMN control.approval_case.id IS '内部 UUID 主键；仅用于数据库关系，不作为跨域公开标识。';
COMMENT ON COLUMN control.approval_case.public_id IS '不可复用的公开稳定标识；插入时登记到 core.public_id_ledger。';
COMMENT ON COLUMN control.approval_case.approval_type IS '对象类别判别字段；允许值由 CHECK 或对应注册表限定。';
COMMENT ON COLUMN control.approval_case.approval_state IS '显式状态当前值；合法取值见 CHECK，完整状态转换由 .NET 领域策略执行。';
COMMENT ON COLUMN control.approval_case.requested_by_ref IS '不透明对象引用；不得从格式推断手机号、邮箱或其他业务事实。';
COMMENT ON COLUMN control.approval_case.requested_by_kind IS '对象类别判别字段；允许值由 CHECK 或对应注册表限定。';
COMMENT ON COLUMN control.approval_case.tenant_id IS '租户隔离键；全零 UUID 表示平台范围，应用查询必须显式携带可信租户上下文。';
COMMENT ON COLUMN control.approval_case.resource_kind IS '对象类别判别字段；允许值由 CHECK 或对应注册表限定。';
COMMENT ON COLUMN control.approval_case.resource_ref IS '不透明对象引用；不得从格式推断手机号、邮箱或其他业务事实。';
COMMENT ON COLUMN control.approval_case.immutable_request_hash IS '不可逆摘要；用于等值匹配、幂等、完整性或最小化证据，不保存原始敏感值。';
COMMENT ON COLUMN control.approval_case.before_value_hash IS '不可逆摘要；用于等值匹配、幂等、完整性或最小化证据，不保存原始敏感值。';
COMMENT ON COLUMN control.approval_case.after_value_hash IS '不可逆摘要；用于等值匹配、幂等、完整性或最小化证据，不保存原始敏感值。';
COMMENT ON COLUMN control.approval_case.justification IS 'control.approval_case.justification 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN control.approval_case.required_approvals IS 'control.approval_case.required_approvals 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN control.approval_case.policy_version IS '对象、策略或源数据的显式版本；不得以不可信客户端时间戳替代。';
COMMENT ON COLUMN control.approval_case.resource_version IS '对象、策略或源数据的显式版本；不得以不可信客户端时间戳替代。';
COMMENT ON COLUMN control.approval_case.risk_snapshot_hash IS '不可逆摘要；用于等值匹配、幂等、完整性或最小化证据，不保存原始敏感值。';
COMMENT ON COLUMN control.approval_case.valid_until IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN control.approval_case.approved_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN control.approval_case.executed_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN control.approval_case.execution_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN control.approval_case.cancelled_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN control.approval_case.expired_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN control.approval_case.created_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN control.approval_case.updated_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN control.approval_case.row_version IS '乐观并发版本；更新必须使用原值 compare-and-set，成功后由数据库单调递增。';
COMMENT ON COLUMN control.approval_case.submitted_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN control.approval_case.rejected_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN control.approval_decision.id IS '内部 UUID 主键；仅用于数据库关系，不作为跨域公开标识。';
COMMENT ON COLUMN control.approval_decision.approval_case_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN control.approval_decision.approver_kind IS '对象类别判别字段；允许值由 CHECK 或对应注册表限定。';
COMMENT ON COLUMN control.approval_decision.approver_ref IS '不透明对象引用；不得从格式推断手机号、邮箱或其他业务事实。';
COMMENT ON COLUMN control.approval_decision.decision IS 'control.approval_decision.decision 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN control.approval_decision.decision_reason IS 'control.approval_decision.decision_reason 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN control.approval_decision.assurance_context_hash IS '不可逆摘要；用于等值匹配、幂等、完整性或最小化证据，不保存原始敏感值。';
COMMENT ON COLUMN control.approval_decision.risk_snapshot_hash IS '不可逆摘要；用于等值匹配、幂等、完整性或最小化证据，不保存原始敏感值。';
COMMENT ON COLUMN control.approval_decision.decided_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN control.config_release.id IS '内部 UUID 主键；仅用于数据库关系，不作为跨域公开标识。';
COMMENT ON COLUMN control.config_release.public_id IS '不可复用的公开稳定标识；插入时登记到 core.public_id_ledger。';
COMMENT ON COLUMN control.config_release.config_kind IS '对象类别判别字段；允许值由 CHECK 或对应注册表限定。';
COMMENT ON COLUMN control.config_release.config_code IS '稳定机器可读代码；展示文本由资源或目录解析。';
COMMENT ON COLUMN control.config_release.release_version IS '对象、策略或源数据的显式版本；不得以不可信客户端时间戳替代。';
COMMENT ON COLUMN control.config_release.release_state IS '显式状态当前值；合法取值见 CHECK，完整状态转换由 .NET 领域策略执行。';
COMMENT ON COLUMN control.config_release.environment IS 'control.config_release.environment 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN control.config_release.content_hash IS '不可逆摘要；用于等值匹配、幂等、完整性或最小化证据，不保存原始敏感值。';
COMMENT ON COLUMN control.config_release.content_uri IS '受控 URI；写入前必须执行协议、主机、重定向与 SSRF 安全校验。';
COMMENT ON COLUMN control.config_release.dependency_versions IS '版本化结构化扩展数据；必须由 .NET 按对应 JSON Schema 校验，不得替代核心状态或外键。';
COMMENT ON COLUMN control.config_release.owner_ref IS '不透明对象引用；不得从格式推断手机号、邮箱或其他业务事实。';
COMMENT ON COLUMN control.config_release.approval_case_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN control.config_release.rollback_of_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN control.config_release.validation_evidence IS '版本化结构化扩展数据；必须由 .NET 按对应 JSON Schema 校验，不得替代核心状态或外键。';
COMMENT ON COLUMN control.config_release.staged_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN control.config_release.activated_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN control.config_release.deprecated_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN control.config_release.revoked_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN control.config_release.created_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN control.config_release.approval_execution_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN control.security_exception.id IS '内部 UUID 主键；仅用于数据库关系，不作为跨域公开标识。';
COMMENT ON COLUMN control.security_exception.public_id IS '不可复用的公开稳定标识；插入时登记到 core.public_id_ledger。';
COMMENT ON COLUMN control.security_exception.exception_code IS '稳定机器可读代码；展示文本由资源或目录解析。';
COMMENT ON COLUMN control.security_exception.exception_state IS '显式状态当前值；合法取值见 CHECK，完整状态转换由 .NET 领域策略执行。';
COMMENT ON COLUMN control.security_exception.requirement_ids IS '代码或引用集合；写入前去重、校验 allowlist，并满足表约束。';
COMMENT ON COLUMN control.security_exception.scope_definition IS '版本化结构化扩展数据；必须由 .NET 按对应 JSON Schema 校验，不得替代核心状态或外键。';
COMMENT ON COLUMN control.security_exception.risk_statement IS 'control.security_exception.risk_statement 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN control.security_exception.compensating_controls IS '版本化结构化扩展数据；必须由 .NET 按对应 JSON Schema 校验，不得替代核心状态或外键。';
COMMENT ON COLUMN control.security_exception.risk_acceptor_ref IS '不透明对象引用；不得从格式推断手机号、邮箱或其他业务事实。';
COMMENT ON COLUMN control.security_exception.owner_ref IS '不透明对象引用；不得从格式推断手机号、邮箱或其他业务事实。';
COMMENT ON COLUMN control.security_exception.approval_case_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN control.security_exception.starts_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN control.security_exception.expires_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN control.security_exception.tightened_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN control.security_exception.created_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN control.security_exception.updated_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN control.security_exception.row_version IS '乐观并发版本；更新必须使用原值 compare-and-set，成功后由数据库单调递增。';
COMMENT ON COLUMN control.security_exception.tenant_id IS '租户隔离键；全零 UUID 表示平台范围，应用查询必须显式携带可信租户上下文。';
COMMENT ON COLUMN control.security_exception.exception_context_hash IS '不可逆摘要；用于等值匹配、幂等、完整性或最小化证据，不保存原始敏感值。';
COMMENT ON COLUMN control.security_exception.approved_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN control.security_exception.activated_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN control.security_exception.expired_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN control.security_exception.revoked_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN control.security_exception.state_reason_code IS '稳定机器可读代码；展示文本由资源或目录解析。';
COMMENT ON COLUMN control.break_glass_grant.id IS '内部 UUID 主键；仅用于数据库关系，不作为跨域公开标识。';
COMMENT ON COLUMN control.break_glass_grant.public_id IS '不可复用的公开稳定标识；插入时登记到 core.public_id_ledger。';
COMMENT ON COLUMN control.break_glass_grant.user_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN control.break_glass_grant.tenant_id IS '租户隔离键；全零 UUID 表示平台范围，应用查询必须显式携带可信租户上下文。';
COMMENT ON COLUMN control.break_glass_grant.permission_codes IS '代码或引用集合；写入前去重、校验 allowlist，并满足表约束。';
COMMENT ON COLUMN control.break_glass_grant.grant_state IS '显式状态当前值；合法取值见 CHECK，完整状态转换由 .NET 领域策略执行。';
COMMENT ON COLUMN control.break_glass_grant.justification IS 'control.break_glass_grant.justification 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN control.break_glass_grant.approval_case_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN control.break_glass_grant.activated_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN control.break_glass_grant.expires_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN control.break_glass_grant.revoked_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN control.break_glass_grant.post_review_due_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN control.break_glass_grant.post_reviewed_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN control.break_glass_grant.created_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN control.break_glass_grant.grant_context_hash IS '不可逆摘要；用于等值匹配、幂等、完整性或最小化证据，不保存原始敏感值。';
COMMENT ON COLUMN control.break_glass_grant.expired_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN control.break_glass_grant.revoke_reason_code IS '稳定机器可读代码；展示文本由资源或目录解析。';
COMMENT ON COLUMN control.owner_review.id IS '内部 UUID 主键；仅用于数据库关系，不作为跨域公开标识。';
COMMENT ON COLUMN control.owner_review.resource_kind IS '对象类别判别字段；允许值由 CHECK 或对应注册表限定。';
COMMENT ON COLUMN control.owner_review.resource_ref IS '不透明对象引用；不得从格式推断手机号、邮箱或其他业务事实。';
COMMENT ON COLUMN control.owner_review.owner_ref IS '不透明对象引用；不得从格式推断手机号、邮箱或其他业务事实。';
COMMENT ON COLUMN control.owner_review.review_state IS '显式状态当前值；合法取值见 CHECK，完整状态转换由 .NET 领域策略执行。';
COMMENT ON COLUMN control.owner_review.due_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN control.owner_review.completed_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN control.owner_review.outcome IS 'control.owner_review.outcome 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN control.owner_review.evidence_hash IS '不可逆摘要；用于等值匹配、幂等、完整性或最小化证据，不保存原始敏感值。';
COMMENT ON COLUMN control.owner_review.created_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN control.client_certification_run.id IS '内部 UUID 主键；仅用于数据库关系，不作为跨域公开标识。';
COMMENT ON COLUMN control.client_certification_run.public_id IS '不可复用的公开稳定标识；插入时登记到 core.public_id_ledger。';
COMMENT ON COLUMN control.client_certification_run.client_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN control.client_certification_run.operation_id IS '关联对象内部 UUID；具体目标由外键或字段语义限定。';
COMMENT ON COLUMN control.client_certification_run.certification_state IS '显式状态当前值；合法取值见 CHECK，完整状态转换由 .NET 领域策略执行。';
COMMENT ON COLUMN control.client_certification_run.profile_code IS '稳定机器可读代码；展示文本由资源或目录解析。';
COMMENT ON COLUMN control.client_certification_run.profile_version IS '对象、策略或源数据的显式版本；不得以不可信客户端时间戳替代。';
COMMENT ON COLUMN control.client_certification_run.environment IS 'control.client_certification_run.environment 的领域属性；写入方必须满足本表约束、数据分类、保留与审计规则。';
COMMENT ON COLUMN control.client_certification_run.client_config_hash IS '不可逆摘要；用于等值匹配、幂等、完整性或最小化证据，不保存原始敏感值。';
COMMENT ON COLUMN control.client_certification_run.protocol_test_report IS '版本化结构化扩展数据；必须由 .NET 按对应 JSON Schema 校验，不得替代核心状态或外键。';
COMMENT ON COLUMN control.client_certification_run.security_test_report IS '版本化结构化扩展数据；必须由 .NET 按对应 JSON Schema 校验，不得替代核心状态或外键。';
COMMENT ON COLUMN control.client_certification_run.tenant_isolation_report IS '版本化结构化扩展数据；必须由 .NET 按对应 JSON Schema 校验，不得替代核心状态或外键。';
COMMENT ON COLUMN control.client_certification_run.passed_control_codes IS '代码或引用集合；写入前去重、校验 allowlist，并满足表约束。';
COMMENT ON COLUMN control.client_certification_run.failed_control_codes IS '代码或引用集合；写入前去重、校验 allowlist，并满足表约束。';
COMMENT ON COLUMN control.client_certification_run.evidence_uri IS '受控 URI；写入前必须执行协议、主机、重定向与 SSRF 安全校验。';
COMMENT ON COLUMN control.client_certification_run.started_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN control.client_certification_run.completed_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN control.client_certification_run.expires_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';
COMMENT ON COLUMN control.client_certification_run.created_at IS '数据库 timestamptz 时间证据；安全判断使用数据库可信时钟。';

COMMENT ON CONSTRAINT pk_approval_case ON control.approval_case IS '主键约束：唯一标识 control.approval_case 记录。';
COMMENT ON CONSTRAINT uq_approval_case_public_id ON control.approval_case IS '唯一约束：保证 public_id 在 control.approval_case 范围内不重复。';
COMMENT ON CONSTRAINT uq_approval_case_execution ON control.approval_case IS '唯一约束：保证 execution_id 在 control.approval_case 范围内不重复。';
COMMENT ON CONSTRAINT ck_approval_case_type ON control.approval_case IS '检查约束：限制 control.approval_case 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_approval_case_state ON control.approval_case IS '检查约束：限制 control.approval_case 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_approval_case_requester ON control.approval_case IS '检查约束：限制 control.approval_case 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_approval_case_hashes ON control.approval_case IS '检查约束：限制 control.approval_case 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_approval_case_required ON control.approval_case IS '检查约束：限制 control.approval_case 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_approval_case_expiry ON control.approval_case IS '检查约束：限制 control.approval_case 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_approval_case_cancelled ON control.approval_case IS '检查约束：限制 control.approval_case 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_approval_case_expired ON control.approval_case IS '检查约束：限制 control.approval_case 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_approval_case_submitted ON control.approval_case IS '检查约束：限制 control.approval_case 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_approval_case_approved ON control.approval_case IS '检查约束：限制 control.approval_case 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_approval_case_executed ON control.approval_case IS '检查约束：限制 control.approval_case 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_approval_case_rejected ON control.approval_case IS '检查约束：限制 control.approval_case 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT pk_approval_decision ON control.approval_decision IS '主键约束：唯一标识 control.approval_decision 记录。';
COMMENT ON CONSTRAINT uq_approval_decision_approver ON control.approval_decision IS '唯一约束：保证 approval_case_id、approver_kind、approver_ref 在 control.approval_decision 范围内不重复。';
COMMENT ON CONSTRAINT fk_approval_decision_case ON control.approval_decision IS '外键约束：control.approval_decision 的 approval_case_id 必须引用 control.approval_case；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT ck_approval_decision_approver ON control.approval_decision IS '检查约束：限制 control.approval_decision 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_approval_decision_value ON control.approval_decision IS '检查约束：限制 control.approval_decision 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_approval_decision_hash ON control.approval_decision IS '检查约束：限制 control.approval_decision 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT pk_config_release ON control.config_release IS '主键约束：唯一标识 control.config_release 记录。';
COMMENT ON CONSTRAINT uq_config_release_public_id ON control.config_release IS '唯一约束：保证 public_id 在 control.config_release 范围内不重复。';
COMMENT ON CONSTRAINT uq_config_release_version ON control.config_release IS '唯一约束：保证 config_kind、config_code、environment、release_version 在 control.config_release 范围内不重复。';
COMMENT ON CONSTRAINT fk_config_release_approval ON control.config_release IS '外键约束：control.config_release 的 approval_case_id 必须引用 control.approval_case；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT fk_config_release_rollback ON control.config_release IS '外键约束：control.config_release 的 rollback_of_id 必须引用 control.config_release；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT ck_config_release_kind ON control.config_release IS '检查约束：限制 control.config_release 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_config_release_state ON control.config_release IS '检查约束：限制 control.config_release 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_config_release_hash ON control.config_release IS '检查约束：限制 control.config_release 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_config_release_active ON control.config_release IS '检查约束：限制 control.config_release 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_config_release_state_times ON control.config_release IS '检查约束：限制 control.config_release 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT pk_security_exception ON control.security_exception IS '主键约束：唯一标识 control.security_exception 记录。';
COMMENT ON CONSTRAINT uq_security_exception_public_id ON control.security_exception IS '唯一约束：保证 public_id 在 control.security_exception 范围内不重复。';
COMMENT ON CONSTRAINT uq_security_exception_code ON control.security_exception IS '唯一约束：保证 exception_code 在 control.security_exception 范围内不重复。';
COMMENT ON CONSTRAINT fk_security_exception_approval ON control.security_exception IS '外键约束：control.security_exception 的 approval_case_id 必须引用 control.approval_case；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT ck_security_exception_state ON control.security_exception IS '检查约束：限制 control.security_exception 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_security_exception_requirements ON control.security_exception IS '检查约束：限制 control.security_exception 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_security_exception_window ON control.security_exception IS '检查约束：限制 control.security_exception 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_security_exception_tightened ON control.security_exception IS '检查约束：限制 control.security_exception 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_security_exception_context_hash ON control.security_exception IS '检查约束：限制 control.security_exception 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_security_exception_approved ON control.security_exception IS '检查约束：限制 control.security_exception 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_security_exception_active ON control.security_exception IS '检查约束：限制 control.security_exception 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_security_exception_expired_state ON control.security_exception IS '检查约束：限制 control.security_exception 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_security_exception_revoked_state ON control.security_exception IS '检查约束：限制 control.security_exception 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT pk_break_glass_grant ON control.break_glass_grant IS '主键约束：唯一标识 control.break_glass_grant 记录。';
COMMENT ON CONSTRAINT uq_break_glass_grant_public_id ON control.break_glass_grant IS '唯一约束：保证 public_id 在 control.break_glass_grant 范围内不重复。';
COMMENT ON CONSTRAINT fk_break_glass_approval ON control.break_glass_grant IS '外键约束：control.break_glass_grant 的 approval_case_id 必须引用 control.approval_case；级联行为以约束定义为准。';
COMMENT ON CONSTRAINT ck_break_glass_state ON control.break_glass_grant IS '检查约束：限制 control.break_glass_grant 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_break_glass_permissions ON control.break_glass_grant IS '检查约束：限制 control.break_glass_grant 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_break_glass_window ON control.break_glass_grant IS '检查约束：限制 control.break_glass_grant 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_break_glass_review ON control.break_glass_grant IS '检查约束：限制 control.break_glass_grant 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_break_glass_active ON control.break_glass_grant IS '检查约束：限制 control.break_glass_grant 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_break_glass_context_hash ON control.break_glass_grant IS '检查约束：限制 control.break_glass_grant 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_break_glass_approval ON control.break_glass_grant IS '检查约束：限制 control.break_glass_grant 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_break_glass_expired ON control.break_glass_grant IS '检查约束：限制 control.break_glass_grant 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_break_glass_revoked ON control.break_glass_grant IS '检查约束：限制 control.break_glass_grant 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT pk_owner_review ON control.owner_review IS '主键约束：唯一标识 control.owner_review 记录。';
COMMENT ON CONSTRAINT uq_owner_review ON control.owner_review IS '唯一约束：保证 resource_kind、resource_ref、due_at 在 control.owner_review 范围内不重复。';
COMMENT ON CONSTRAINT ck_owner_review_state ON control.owner_review IS '检查约束：限制 control.owner_review 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_owner_review_outcome ON control.owner_review IS '检查约束：限制 control.owner_review 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_owner_review_complete ON control.owner_review IS '检查约束：限制 control.owner_review 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT pk_client_certification_run ON control.client_certification_run IS '主键约束：唯一标识 control.client_certification_run 记录。';
COMMENT ON CONSTRAINT uq_client_certification_public_id ON control.client_certification_run IS '唯一约束：保证 public_id 在 control.client_certification_run 范围内不重复。';
COMMENT ON CONSTRAINT uq_client_certification_operation ON control.client_certification_run IS '唯一约束：保证 operation_id 在 control.client_certification_run 范围内不重复。';
COMMENT ON CONSTRAINT ck_client_certification_state ON control.client_certification_run IS '检查约束：限制 control.client_certification_run 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_client_certification_hash ON control.client_certification_run IS '检查约束：限制 control.client_certification_run 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_client_certification_result ON control.client_certification_run IS '检查约束：限制 control.client_certification_run 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_client_certification_pass ON control.client_certification_run IS '检查约束：限制 control.client_certification_run 的字段取值或组合满足结构与安全底线。';
COMMENT ON CONSTRAINT ck_client_certification_expiry ON control.client_certification_run IS '检查约束：限制 control.client_certification_run 的字段取值或组合满足结构与安全底线。';

COMMENT ON INDEX control.ux_config_release_active IS '查询索引：优化 control.config_release 按 config_kind、config_code、environment 的访问，仅覆盖 WHERE 条件命中的记录。';
COMMENT ON INDEX control.ix_approval_case_queue IS '查询索引：优化 control.approval_case 按 approval_state、valid_until 的访问，仅覆盖 WHERE 条件命中的记录。';
COMMENT ON INDEX control.ix_security_exception_expiry IS '查询索引：优化 control.security_exception 按 expires_at 的访问，仅覆盖 WHERE 条件命中的记录。';
COMMENT ON INDEX control.ix_client_certification_expiry IS '查询索引：优化 control.client_certification_run 按 client_id、expires_at 的访问，仅覆盖 WHERE 条件命中的记录。';
COMMENT ON INDEX control.pk_approval_case IS '约束 pk_approval_case 的支撑唯一索引。';
COMMENT ON INDEX control.uq_approval_case_public_id IS '约束 uq_approval_case_public_id 的支撑唯一索引。';
COMMENT ON INDEX control.uq_approval_case_execution IS '约束 uq_approval_case_execution 的支撑唯一索引。';
COMMENT ON INDEX control.pk_approval_decision IS '约束 pk_approval_decision 的支撑唯一索引。';
COMMENT ON INDEX control.uq_approval_decision_approver IS '约束 uq_approval_decision_approver 的支撑唯一索引。';
COMMENT ON INDEX control.pk_config_release IS '约束 pk_config_release 的支撑唯一索引。';
COMMENT ON INDEX control.uq_config_release_public_id IS '约束 uq_config_release_public_id 的支撑唯一索引。';
COMMENT ON INDEX control.uq_config_release_version IS '约束 uq_config_release_version 的支撑唯一索引。';
COMMENT ON INDEX control.pk_security_exception IS '约束 pk_security_exception 的支撑唯一索引。';
COMMENT ON INDEX control.uq_security_exception_public_id IS '约束 uq_security_exception_public_id 的支撑唯一索引。';
COMMENT ON INDEX control.uq_security_exception_code IS '约束 uq_security_exception_code 的支撑唯一索引。';
COMMENT ON INDEX control.pk_break_glass_grant IS '约束 pk_break_glass_grant 的支撑唯一索引。';
COMMENT ON INDEX control.uq_break_glass_grant_public_id IS '约束 uq_break_glass_grant_public_id 的支撑唯一索引。';
COMMENT ON INDEX control.pk_owner_review IS '约束 pk_owner_review 的支撑唯一索引。';
COMMENT ON INDEX control.uq_owner_review IS '约束 uq_owner_review 的支撑唯一索引。';
COMMENT ON INDEX control.pk_client_certification_run IS '约束 pk_client_certification_run 的支撑唯一索引。';
COMMENT ON INDEX control.uq_client_certification_public_id IS '约束 uq_client_certification_public_id 的支撑唯一索引。';
COMMENT ON INDEX control.uq_client_certification_operation IS '约束 uq_client_certification_operation 的支撑唯一索引。';
COMMENT ON INDEX control.ix_fk_config_release_approval_case_id IS '查询索引：优化 control.config_release 按 approval_case_id 的访问。';
COMMENT ON INDEX control.ix_fk_config_release_rollback_of_id IS '查询索引：优化 control.config_release 按 rollback_of_id 的访问。';
COMMENT ON INDEX control.ix_fk_security_exception_approval_case_id IS '查询索引：优化 control.security_exception 按 approval_case_id 的访问。';
COMMENT ON INDEX control.ix_fk_break_glass_grant_approval_case_id IS '查询索引：优化 control.break_glass_grant 按 approval_case_id 的访问。';

