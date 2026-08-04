\set ON_ERROR_STOP on

SET ROLE iam_owner;

-- 风险信号、评估、安全状态和限制事实。评分、策略和处置由 RISK 代码执行。

CREATE TABLE iam.risk_signals (
    id uuid NOT NULL,
    signal_id uuid NOT NULL,
    signal_type varchar(100) NOT NULL,
    subject_type varchar(40),
    subject_id uuid,
    object_type varchar(40),
    object_id varchar(256),
    tenant_id uuid,
    source_code varchar(100) NOT NULL,
    confidence numeric(5,4),
    evidence jsonb NOT NULL DEFAULT '{}'::jsonb,
    evidence_digest char(64) NOT NULL,
    retention_until timestamptz,
    occurred_at timestamptz NOT NULL,
    recorded_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT pk_risk_signals PRIMARY KEY (id, signal_id),
    CONSTRAINT uq_risk_signals_signal_id UNIQUE (signal_id),
    CONSTRAINT ck_risk_signal_confidence CHECK (confidence IS NULL OR (confidence >= 0 AND confidence <= 1)),
    CONSTRAINT ck_risk_signal_subject_pair CHECK ((subject_type IS NULL) = (subject_id IS NULL)),
    CONSTRAINT ck_risk_signal_object_pair CHECK ((object_type IS NULL) = (object_id IS NULL)),
    CONSTRAINT ck_risk_signal_retention CHECK (retention_until IS NULL OR retention_until >= occurred_at)
) PARTITION BY HASH (signal_id);
COMMENT ON TABLE iam.risk_signals IS '高容量不可变风险原始信号；按 signal_id Hash 分区并由数据库保证信号 ID 全局唯一，风险模型在代码中运行。';
COMMENT ON COLUMN iam.risk_signals.id IS '应用生成的记录 UUIDv7。';
COMMENT ON COLUMN iam.risk_signals.signal_id IS '全局风险信号 UUID；数据库全局唯一。';
COMMENT ON COLUMN iam.risk_signals.signal_type IS '稳定信号类型代码。';
COMMENT ON COLUMN iam.risk_signals.subject_type IS '可空；风险主体类型。';
COMMENT ON COLUMN iam.risk_signals.subject_id IS '可空；风险主体逻辑 ID。';
COMMENT ON COLUMN iam.risk_signals.object_type IS '可空；被观察对象类型。';
COMMENT ON COLUMN iam.risk_signals.object_id IS '可空；对象稳定 ID 或安全摘要。';
COMMENT ON COLUMN iam.risk_signals.tenant_id IS '可空；逻辑引用 iam.tenants.id。';
COMMENT ON COLUMN iam.risk_signals.source_code IS '信号生产者稳定代码。';
COMMENT ON COLUMN iam.risk_signals.confidence IS '可空；0 到 1 的置信度。';
COMMENT ON COLUMN iam.risk_signals.evidence IS '脱敏证据元数据；不得包含凭证或完整 Token。';
COMMENT ON COLUMN iam.risk_signals.evidence_digest IS '规范化证据 SHA-256 摘要。';
COMMENT ON COLUMN iam.risk_signals.retention_until IS '可空；信号最晚保留时间，删除前还需校验 Legal Hold。';
COMMENT ON COLUMN iam.risk_signals.occurred_at IS '信号实际发生时间；用于时间窗口计算、调查和归档查询。';
COMMENT ON COLUMN iam.risk_signals.recorded_at IS '数据库落库时间。';
COMMENT ON CONSTRAINT uq_risk_signals_signal_id ON iam.risk_signals IS '保证风险信号 ID 在数据库内全局唯一并可被评估关系稳定引用；因此按 signal_id Hash 分区。';

CREATE TABLE iam.risk_assessments (
    id uuid PRIMARY KEY,
    assessment_id uuid NOT NULL,
    context_type varchar(80) NOT NULL,
    context_id uuid,
    subject_type varchar(40),
    subject_id uuid,
    tenant_id uuid,
    risk_level varchar(40) NOT NULL,
    score numeric(12,6),
    disposition varchar(80) NOT NULL,
    risk_policy_version_id uuid,
    model_version_id uuid,
    input_digest char(64) NOT NULL,
    result jsonb NOT NULL DEFAULT '{}'::jsonb,
    assessed_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT uq_risk_assessment_public UNIQUE (assessment_id),
    CONSTRAINT ck_risk_assessment_subject_pair CHECK ((subject_type IS NULL) = (subject_id IS NULL))
);
COMMENT ON TABLE iam.risk_assessments IS '不可变风险评估结果；数据库保存输入摘要、版本和结论，不执行评分。';
COMMENT ON COLUMN iam.risk_assessments.id IS '应用生成的内部 UUIDv7。';
COMMENT ON COLUMN iam.risk_assessments.assessment_id IS '对外追踪的全局评估 UUID。';
COMMENT ON COLUMN iam.risk_assessments.context_type IS '评估上下文类型。';
COMMENT ON COLUMN iam.risk_assessments.context_id IS '可空；上下文逻辑 ID。';
COMMENT ON COLUMN iam.risk_assessments.subject_type IS '可空；主体类型。';
COMMENT ON COLUMN iam.risk_assessments.subject_id IS '可空；主体逻辑 ID。';
COMMENT ON COLUMN iam.risk_assessments.tenant_id IS '可空；逻辑引用 iam.tenants.id。';
COMMENT ON COLUMN iam.risk_assessments.risk_level IS '风险等级结论。';
COMMENT ON COLUMN iam.risk_assessments.score IS '可空；模型原始或校准分数。';
COMMENT ON COLUMN iam.risk_assessments.disposition IS '放行、升级认证、拒绝或人工复核等处置代码。';
COMMENT ON COLUMN iam.risk_assessments.risk_policy_version_id IS '可空；逻辑引用 RISK_POLICY 类型 iam.configuration_versions.id；数据库校验版本存在，类型、状态和适用范围由 RISK 代码校验。';
COMMENT ON COLUMN iam.risk_assessments.model_version_id IS '可空；逻辑引用 RISK_MODEL 类型 iam.configuration_versions.id。';
COMMENT ON COLUMN iam.risk_assessments.input_digest IS '规范化模型输入摘要。';
COMMENT ON COLUMN iam.risk_assessments.result IS '脱敏评估结果和解释码。';
COMMENT ON COLUMN iam.risk_assessments.assessed_at IS '评估完成业务时间。';
COMMENT ON COLUMN iam.risk_assessments.created_at IS '数据库插入时间。';

CREATE TABLE iam.risk_assessment_signals (
    id uuid PRIMARY KEY,
    assessment_id uuid NOT NULL,
    signal_id uuid NOT NULL,
    signal_occurred_at timestamptz NOT NULL,
    signal_role varchar(40) NOT NULL,
    weight numeric(12,6),
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT uq_risk_assessment_signal UNIQUE (assessment_id, signal_id)
);
COMMENT ON TABLE iam.risk_assessment_signals IS '风险评估使用的信号关系；保存信号分区时间以便定位，权重解释由模型代码负责。';
COMMENT ON COLUMN iam.risk_assessment_signals.id IS '应用生成的关系 UUIDv7。';
COMMENT ON COLUMN iam.risk_assessment_signals.assessment_id IS '逻辑引用 iam.risk_assessments.id。';
COMMENT ON COLUMN iam.risk_assessment_signals.signal_id IS '逻辑引用 iam.risk_signals.signal_id。';
COMMENT ON COLUMN iam.risk_assessment_signals.signal_occurred_at IS '风险信号分区定位时间。';
COMMENT ON COLUMN iam.risk_assessment_signals.signal_role IS '信号在评估中的角色代码。';
COMMENT ON COLUMN iam.risk_assessment_signals.weight IS '可空；模型使用的权重快照。';
COMMENT ON COLUMN iam.risk_assessment_signals.created_at IS '数据库插入时间。';

CREATE TABLE iam.risk_cases (
    id uuid PRIMARY KEY,
    case_type varchar(80) NOT NULL,
    subject_type varchar(40),
    subject_id uuid,
    tenant_id uuid,
    owner_type varchar(40),
    owner_id uuid,
    priority varchar(40) NOT NULL,
    state varchar(40) NOT NULL,
    result_code varchar(100),
    summary jsonb NOT NULL DEFAULT '{}'::jsonb,
    opened_at timestamptz NOT NULL,
    due_at timestamptz,
    closed_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    row_version bigint NOT NULL DEFAULT 0,
    CONSTRAINT ck_risk_case_version CHECK (row_version >= 0),
    CONSTRAINT ck_risk_case_subject_pair CHECK ((subject_type IS NULL) = (subject_id IS NULL)),
    CONSTRAINT ck_risk_case_owner_pair CHECK ((owner_type IS NULL) = (owner_id IS NULL)),
    CONSTRAINT ck_risk_case_time CHECK (
        (due_at IS NULL OR due_at >= opened_at)
        AND (closed_at IS NULL OR closed_at >= opened_at)
    )
);
COMMENT ON TABLE iam.risk_cases IS '风险、安全和欺诈人工或自动案件；分派、SLA、证据访问和处置由 RISK 代码编排。';
COMMENT ON COLUMN iam.risk_cases.id IS '应用生成的案件 UUIDv7。';
COMMENT ON COLUMN iam.risk_cases.case_type IS '案件类型代码。';
COMMENT ON COLUMN iam.risk_cases.subject_type IS '可空；案件主体类型。';
COMMENT ON COLUMN iam.risk_cases.subject_id IS '可空；案件主体逻辑 ID。';
COMMENT ON COLUMN iam.risk_cases.tenant_id IS '可空；逻辑引用 iam.tenants.id。';
COMMENT ON COLUMN iam.risk_cases.owner_type IS '可空；当前责任人类型。';
COMMENT ON COLUMN iam.risk_cases.owner_id IS '可空；当前责任人逻辑 ID。';
COMMENT ON COLUMN iam.risk_cases.priority IS '案件优先级。';
COMMENT ON COLUMN iam.risk_cases.state IS '案件状态。';
COMMENT ON COLUMN iam.risk_cases.result_code IS '可空；结案结果码。';
COMMENT ON COLUMN iam.risk_cases.summary IS '脱敏案件摘要；原始证据保存在受控证据系统。';
COMMENT ON COLUMN iam.risk_cases.opened_at IS '案件开启时间。';
COMMENT ON COLUMN iam.risk_cases.due_at IS '可空；处理截止时间。';
COMMENT ON COLUMN iam.risk_cases.closed_at IS '可空；结案时间。';
COMMENT ON COLUMN iam.risk_cases.created_at IS '数据库插入时间。';
COMMENT ON COLUMN iam.risk_cases.updated_at IS '数据库更新时间；由技术 Trigger 自动刷新。';
COMMENT ON COLUMN iam.risk_cases.row_version IS '乐观锁版本。';

CREATE TABLE iam.security_signals (
    id uuid PRIMARY KEY,
    signal_type varchar(100) NOT NULL,
    subject_type varchar(40) NOT NULL,
    subject_id uuid NOT NULL,
    client_id uuid,
    session_id uuid,
    source_code varchar(100) NOT NULL,
    state varchar(40) NOT NULL,
    effective_at timestamptz NOT NULL,
    expires_at timestamptz,
    evidence_digest char(64),
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    row_version bigint NOT NULL DEFAULT 0,
    CONSTRAINT ck_security_signal_expiry CHECK (expires_at IS NULL OR expires_at > effective_at),
    CONSTRAINT ck_security_signal_version CHECK (row_version >= 0)
);
COMMENT ON TABLE iam.security_signals IS '持续安全状态信号，例如账号受损、会话异常或设备丢失；有效性由 RISK/SESSION 代码判断。';
COMMENT ON COLUMN iam.security_signals.id IS '应用生成的安全信号 UUIDv7。';
COMMENT ON COLUMN iam.security_signals.signal_type IS '安全信号类型。';
COMMENT ON COLUMN iam.security_signals.subject_type IS '主体类型。';
COMMENT ON COLUMN iam.security_signals.subject_id IS '主体逻辑 ID。';
COMMENT ON COLUMN iam.security_signals.client_id IS '可空；逻辑引用 iam.oauth_clients.id。';
COMMENT ON COLUMN iam.security_signals.session_id IS '可空；逻辑引用 iam.sessions.id。';
COMMENT ON COLUMN iam.security_signals.source_code IS '信号来源代码。';
COMMENT ON COLUMN iam.security_signals.state IS '信号状态。';
COMMENT ON COLUMN iam.security_signals.effective_at IS '信号生效时间。';
COMMENT ON COLUMN iam.security_signals.expires_at IS '可空；信号过期时间。';
COMMENT ON COLUMN iam.security_signals.evidence_digest IS '可空；证据包摘要。';
COMMENT ON COLUMN iam.security_signals.created_at IS '数据库插入时间。';
COMMENT ON COLUMN iam.security_signals.updated_at IS '数据库更新时间；由技术 Trigger 自动刷新。';
COMMENT ON COLUMN iam.security_signals.row_version IS '乐观锁版本。';

CREATE TABLE iam.restriction_entries (
    id uuid PRIMARY KEY,
    target_type varchar(40) NOT NULL,
    target_id uuid,
    target_hash varchar(256),
    restriction_type varchar(80) NOT NULL,
    scope_type varchar(40) NOT NULL,
    scope_id uuid,
    reason_code varchar(100) NOT NULL,
    state varchar(40) NOT NULL,
    effective_at timestamptz NOT NULL,
    expires_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    row_version bigint NOT NULL DEFAULT 0,
    CONSTRAINT ck_restriction_target CHECK (target_id IS NOT NULL OR target_hash IS NOT NULL),
    CONSTRAINT ck_restriction_expiry CHECK (expires_at IS NULL OR expires_at > effective_at),
    CONSTRAINT ck_restriction_version CHECK (row_version >= 0)
);
COMMENT ON TABLE iam.restriction_entries IS '黑名单、灰名单、地域、标识和主体限制事实；命中、优先级和处置由 RISK 代码执行。';
COMMENT ON COLUMN iam.restriction_entries.id IS '应用生成的限制 UUIDv7。';
COMMENT ON COLUMN iam.restriction_entries.target_type IS '限制目标类型。';
COMMENT ON COLUMN iam.restriction_entries.target_id IS '可空；目标逻辑 ID。';
COMMENT ON COLUMN iam.restriction_entries.target_hash IS '可空；敏感目标不可逆摘要。';
COMMENT ON COLUMN iam.restriction_entries.restriction_type IS '限制类型。';
COMMENT ON COLUMN iam.restriction_entries.scope_type IS '限制作用域类型。';
COMMENT ON COLUMN iam.restriction_entries.scope_id IS '可空；作用域逻辑 ID。';
COMMENT ON COLUMN iam.restriction_entries.reason_code IS '稳定限制原因码。';
COMMENT ON COLUMN iam.restriction_entries.state IS '限制状态。';
COMMENT ON COLUMN iam.restriction_entries.effective_at IS '限制生效时间。';
COMMENT ON COLUMN iam.restriction_entries.expires_at IS '可空；限制失效时间。';
COMMENT ON COLUMN iam.restriction_entries.created_at IS '数据库插入时间。';
COMMENT ON COLUMN iam.restriction_entries.updated_at IS '数据库更新时间；由技术 Trigger 自动刷新。';
COMMENT ON COLUMN iam.restriction_entries.row_version IS '乐观锁版本。';

CREATE TABLE iam.risk_entity_links (
    id uuid PRIMARY KEY,
    left_entity_type varchar(40) NOT NULL,
    left_entity_id varchar(256) NOT NULL,
    right_entity_type varchar(40) NOT NULL,
    right_entity_id varchar(256) NOT NULL,
    link_type varchar(80) NOT NULL,
    confidence numeric(5,4) NOT NULL,
    evidence_digest char(64) NOT NULL,
    source_code varchar(100) NOT NULL,
    state varchar(40) NOT NULL,
    observed_at timestamptz NOT NULL,
    expires_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT uq_risk_entity_link UNIQUE (left_entity_type, left_entity_id, right_entity_type, right_entity_id, link_type, observed_at),
    CONSTRAINT ck_risk_link_confidence CHECK (confidence >= 0 AND confidence <= 1),
    CONSTRAINT ck_risk_link_expiry CHECK (expires_at IS NULL OR expires_at > observed_at)
);
COMMENT ON TABLE iam.risk_entity_links IS '受控风险关联图事实；遍历深度、方向、误关联处置和访问权限由 RISK 代码控制。';
COMMENT ON COLUMN iam.risk_entity_links.id IS '应用生成的关联 UUIDv7。';
COMMENT ON COLUMN iam.risk_entity_links.left_entity_type IS '左实体类型。';
COMMENT ON COLUMN iam.risk_entity_links.left_entity_id IS '左实体逻辑 ID 或安全摘要。';
COMMENT ON COLUMN iam.risk_entity_links.right_entity_type IS '右实体类型。';
COMMENT ON COLUMN iam.risk_entity_links.right_entity_id IS '右实体逻辑 ID 或安全摘要。';
COMMENT ON COLUMN iam.risk_entity_links.link_type IS '关联类型。';
COMMENT ON COLUMN iam.risk_entity_links.confidence IS '0 到 1 的关联置信度。';
COMMENT ON COLUMN iam.risk_entity_links.evidence_digest IS '关联证据摘要。';
COMMENT ON COLUMN iam.risk_entity_links.source_code IS '关联生产者代码。';
COMMENT ON COLUMN iam.risk_entity_links.state IS '关联状态。';
COMMENT ON COLUMN iam.risk_entity_links.observed_at IS '关联观察时间。';
COMMENT ON COLUMN iam.risk_entity_links.expires_at IS '可空；关联失效时间。';
COMMENT ON COLUMN iam.risk_entity_links.created_at IS '数据库插入时间。';

CREATE INDEX ix_risk_signals_subject ON iam.risk_signals (subject_type, subject_id, occurred_at DESC);
CREATE INDEX ix_risk_signals_object ON iam.risk_signals (object_type, object_id, occurred_at DESC);
CREATE INDEX ix_risk_assessments_subject ON iam.risk_assessments (subject_type, subject_id, assessed_at DESC);
CREATE INDEX ix_risk_assessments_policy ON iam.risk_assessments (risk_policy_version_id, assessed_at DESC) WHERE risk_policy_version_id IS NOT NULL;
CREATE INDEX ix_risk_assessments_model ON iam.risk_assessments (model_version_id, assessed_at DESC) WHERE model_version_id IS NOT NULL;
CREATE INDEX ix_risk_cases_queue ON iam.risk_cases (state, priority, due_at);
CREATE INDEX ix_security_signals_subject ON iam.security_signals (subject_type, subject_id, state, expires_at);
CREATE INDEX ix_restriction_lookup_id ON iam.restriction_entries (target_type, target_id, state, expires_at);
CREATE INDEX ix_restriction_lookup_hash ON iam.restriction_entries (target_type, target_hash, state, expires_at);
CREATE INDEX ix_risk_entity_links_left ON iam.risk_entity_links (left_entity_type, left_entity_id, state);
CREATE INDEX ix_risk_entity_links_right ON iam.risk_entity_links (right_entity_type, right_entity_id, state);
COMMENT ON INDEX iam.ix_risk_cases_queue IS '风险运营按状态、优先级和截止时间查询案件。';
