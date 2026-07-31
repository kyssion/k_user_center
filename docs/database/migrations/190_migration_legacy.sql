-- =============================================================================
-- 190_migration_legacy.sql
-- MIG 域：旧 ID 映射、迁移批次、切换后变更日志、对账结果
-- 依据：能力地图 §10；蓝图 §17（REQ-MIG-001 至 010）
-- 关键：旧 ID 100% 可追溯且不进入新主键语义；越过不可逆边界后只允许前向修复
-- =============================================================================

SET client_min_messages = warning;

-- -----------------------------------------------------------------------------
-- 1. 迁移批次（蓝图 §17 状态机）
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS mig.migration_batch (
    id                       uuid        NOT NULL DEFAULT core.uuid_generate_v7(),
    public_id                text        NOT NULL,
    source_system_code       text        NOT NULL,
    batch_no                 integer     NOT NULL,
    batch_state              text        NOT NULL DEFAULT 'DISCOVERED',
    scope_description        text        NOT NULL,
    business_line_id         uuid        NULL,
    tenant_id                uuid        NOT NULL DEFAULT '00000000-0000-0000-0000-000000000000',
    record_count             bigint      NOT NULL DEFAULT 0,
    mapped_count             bigint      NOT NULL DEFAULT 0,
    discrepancy_count        bigint      NOT NULL DEFAULT 0,
    authority_side           text        NOT NULL DEFAULT 'LEGACY',
    canary_percentage        smallint    NULL,
    cutover_at               timestamptz NULL,
    rollback_deadline        timestamptz NULL,
    irreversible_boundary_passed boolean NOT NULL DEFAULT false,
    irreversible_reason_code text        NULL,
    observing_until          timestamptz NULL,
    paused_at                timestamptz NULL,
    paused_reason_code       text        NULL,
    rolled_back_at           timestamptz NULL,
    completed_at             timestamptz NULL,
    security_exception_ref   text        NULL,
    owner_ref                text        NOT NULL,
    created_at               timestamptz NOT NULL DEFAULT now(),
    updated_at               timestamptz NOT NULL DEFAULT now(),
    row_version              bigint      NOT NULL DEFAULT 1,
    CONSTRAINT pk_migration_batch PRIMARY KEY (id),
    CONSTRAINT uq_migration_batch_public_id UNIQUE (public_id),
    CONSTRAINT uq_migration_batch_no UNIQUE (source_system_code, batch_no),
    CONSTRAINT ck_migration_batch_state CHECK (batch_state IN (
        'DISCOVERED', 'CLEANSED', 'MAPPED', 'SHADOW', 'CANARY', 'CUTOVER', 'OBSERVING', 'COMPLETE',
        'PAUSED', 'ROLLED_BACK'
    )),
    -- REQ-MIG-002：双轨期间每类数据只能有一个权威写入方
    CONSTRAINT ck_migration_batch_authority CHECK (authority_side IN ('LEGACY', 'PLATFORM')),
    CONSTRAINT ck_migration_batch_canary CHECK (canary_percentage IS NULL OR canary_percentage BETWEEN 1 AND 100),
    CONSTRAINT ck_migration_batch_cutover CHECK (batch_state NOT IN ('CUTOVER', 'OBSERVING', 'COMPLETE') OR cutover_at IS NOT NULL),
    -- REQ-MIG-008：越过不可逆边界必须登记原因
    CONSTRAINT ck_migration_batch_irreversible CHECK (
        NOT irreversible_boundary_passed OR irreversible_reason_code IS NOT NULL
    ),
    -- REQ-MIG-006：暂停必须有原因
    CONSTRAINT ck_migration_batch_paused CHECK (
        (batch_state = 'PAUSED') = (paused_at IS NOT NULL AND paused_reason_code IS NOT NULL)
    ),
    -- REQ-MIG-008 / AT-MIG-007：越过不可逆边界后不得再回滚
    CONSTRAINT ck_migration_batch_rollback CHECK (
        rolled_back_at IS NULL OR NOT irreversible_boundary_passed
    ),
    CONSTRAINT ck_migration_batch_complete CHECK ((batch_state = 'COMPLETE') = (completed_at IS NOT NULL))
);
COMMENT ON TABLE mig.migration_batch IS '蓝图 §17 迁移批次状态机；irreversible_boundary_passed 为 true 后回滚请求必须被拒并转为前向修复（AT-MIG-007）';
COMMENT ON COLUMN mig.migration_batch.authority_side IS 'REQ-MIG-002：双轨期同一类数据只能有一侧拥有写权威，切换本身是一次受控变更';

CREATE OR REPLACE TRIGGER trg_migration_batch_touch
    BEFORE UPDATE ON mig.migration_batch
    FOR EACH ROW EXECUTE FUNCTION core.fn_touch_updated_at();
CREATE OR REPLACE TRIGGER trg_migration_batch_public_id
    BEFORE INSERT ON mig.migration_batch
    FOR EACH ROW EXECUTE FUNCTION core.fn_register_public_id('MIGRATION_BATCH');

CREATE INDEX IF NOT EXISTS ix_migration_batch_state ON mig.migration_batch (batch_state, created_at DESC);

-- -----------------------------------------------------------------------------
-- 2. 旧 ID 映射（REQ-MIG-001：100% 可追溯，旧 ID 不进入新主键语义）
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS mig.legacy_id_map (
    id                 uuid        NOT NULL DEFAULT core.uuid_generate_v7(),
    source_system_code text        NOT NULL,
    legacy_entity_kind text        NOT NULL,
    legacy_id          text        NOT NULL,
    platform_entity_kind text      NOT NULL,
    platform_id        uuid        NOT NULL,
    platform_public_id text        NULL,
    batch_id           uuid        NULL,
    match_confidence   text        NOT NULL DEFAULT 'EXACT',
    mapped_at          timestamptz NOT NULL DEFAULT now(),
    mapped_by_ref      text        NOT NULL,
    CONSTRAINT pk_legacy_id_map PRIMARY KEY (id),
    CONSTRAINT uq_legacy_id_map UNIQUE (source_system_code, legacy_entity_kind, legacy_id),
    CONSTRAINT fk_legacy_id_map_batch FOREIGN KEY (batch_id) REFERENCES mig.migration_batch (id),
    CONSTRAINT ck_legacy_id_map_entity CHECK (legacy_entity_kind IN ('USER', 'ACCOUNT', 'MEMBER', 'ORGANIZATION', 'TENANT', 'CLIENT')),
    CONSTRAINT ck_legacy_id_map_platform_entity CHECK (platform_entity_kind IN ('GLOBAL_USER', 'MEMBERSHIP', 'ORGANIZATION', 'TENANT', 'CLIENT')),
    CONSTRAINT ck_legacy_id_map_confidence CHECK (match_confidence IN ('EXACT', 'HIGH', 'MANUAL_CONFIRMED'))
);
COMMENT ON TABLE mig.legacy_id_map IS 'REQ-MIG-001：旧 ID 到平台 ID 的映射；REQ-ID-010 业务系统不得继续以旧 ID 作为跨系统主键（AT-MIG-001）';
COMMENT ON COLUMN mig.legacy_id_map.match_confidence IS 'REQ-MIG-004：重复账号只生成候选，只有 MANUAL_CONFIRMED 才允许作为合并依据（AT-MIG-004）';

CREATE INDEX IF NOT EXISTS ix_legacy_id_map_platform ON mig.legacy_id_map (platform_entity_kind, platform_id);
CREATE INDEX IF NOT EXISTS ix_legacy_id_map_batch ON mig.legacy_id_map (batch_id);

-- 重复账号候选（REQ-MIG-004：只生成候选，不静默合并）
CREATE TABLE IF NOT EXISTS mig.duplicate_candidate (
    id                 uuid        NOT NULL DEFAULT core.uuid_generate_v7(),
    batch_id           uuid        NULL,
    left_user_id       uuid        NOT NULL,
    right_user_id      uuid        NOT NULL,
    similarity_reason  text[]      NOT NULL,
    candidate_state    text        NOT NULL DEFAULT 'PENDING',
    reviewed_by_ref    text        NULL,
    reviewed_at        timestamptz NULL,
    approval_case_id   uuid        NULL,
    created_at         timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT pk_duplicate_candidate PRIMARY KEY (id),
    CONSTRAINT uq_duplicate_candidate UNIQUE (left_user_id, right_user_id),
    CONSTRAINT fk_duplicate_candidate_left FOREIGN KEY (left_user_id) REFERENCES id.global_user (id),
    CONSTRAINT fk_duplicate_candidate_right FOREIGN KEY (right_user_id) REFERENCES id.global_user (id),
    CONSTRAINT fk_duplicate_candidate_batch FOREIGN KEY (batch_id) REFERENCES mig.migration_batch (id),
    CONSTRAINT fk_duplicate_candidate_approval FOREIGN KEY (approval_case_id) REFERENCES ctrl.approval_case (id),
    CONSTRAINT ck_duplicate_candidate_distinct CHECK (left_user_id <> right_user_id),
    CONSTRAINT ck_duplicate_candidate_state CHECK (candidate_state IN ('PENDING', 'CONFIRMED_SAME', 'CONFIRMED_DIFFERENT', 'MERGED', 'DISMISSED')),
    -- 合并必须有审批（CAP-ID-016、能力地图 §5.2 第 1 步：用户明确发起，系统不静默合并）
    CONSTRAINT ck_duplicate_candidate_merge_approval CHECK (
        candidate_state <> 'MERGED' OR approval_case_id IS NOT NULL
    )
);
COMMENT ON TABLE mig.duplicate_candidate IS 'REQ-MIG-004 / CAP-ID-015：重复检测只生成候选；合并必须走审批与强验证，禁止静默合并';

CREATE INDEX IF NOT EXISTS ix_duplicate_candidate_state ON mig.duplicate_candidate (candidate_state, created_at DESC);

-- -----------------------------------------------------------------------------
-- 3. 切换后变更日志（REQ-MIG-009/010：反向同步的唯一依据，追加型）
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS mig.change_log (
    id                 uuid        NOT NULL DEFAULT core.uuid_generate_v7(),
    batch_id           uuid        NOT NULL,
    occurred_at        timestamptz NOT NULL DEFAULT now(),
    change_seq         bigint      NOT NULL,
    entity_kind        text        NOT NULL,
    entity_ref         text        NOT NULL,
    change_kind        text        NOT NULL,
    authority_side     text        NOT NULL,
    idempotency_key    text        NOT NULL,
    entity_version     bigint      NOT NULL,
    payload            jsonb       NOT NULL,
    reverse_synced_at  timestamptz NULL,
    reverse_sync_state text        NOT NULL DEFAULT 'PENDING',
    conflict_reason    text        NULL,
    CONSTRAINT pk_change_log PRIMARY KEY (id),
    CONSTRAINT uq_change_log_seq UNIQUE (batch_id, entity_kind, entity_ref, change_seq),
    CONSTRAINT uq_change_log_idempotency UNIQUE (batch_id, idempotency_key),
    CONSTRAINT fk_change_log_batch FOREIGN KEY (batch_id) REFERENCES mig.migration_batch (id),
    CONSTRAINT ck_change_log_change_kind CHECK (change_kind IN ('CREATE', 'UPDATE', 'DELETE', 'STATE_CHANGE')),
    CONSTRAINT ck_change_log_authority CHECK (authority_side IN ('LEGACY', 'PLATFORM')),
    CONSTRAINT ck_change_log_reverse_state CHECK (reverse_sync_state IN ('PENDING', 'SYNCED', 'CONFLICT', 'SKIPPED')),
    CONSTRAINT ck_change_log_synced CHECK ((reverse_sync_state = 'SYNCED') = (reverse_synced_at IS NOT NULL)),
    CONSTRAINT ck_change_log_conflict CHECK (reverse_sync_state <> 'CONFLICT' OR conflict_reason IS NOT NULL),
    CONSTRAINT ck_change_log_seq_positive CHECK (change_seq >= 1)
);
COMMENT ON TABLE mig.change_log IS 'REQ-MIG-009/010：切换后新写入进入不可变变更日志，按版本反向同步并隔离冲突；日志不完整即视为越过不可逆边界（REQ-MIG-008）';

CREATE OR REPLACE TRIGGER trg_change_log_no_delete
    BEFORE DELETE ON mig.change_log
    FOR EACH STATEMENT EXECUTE FUNCTION core.fn_append_only();

CREATE INDEX IF NOT EXISTS ix_change_log_pending ON mig.change_log (batch_id, change_seq) WHERE reverse_sync_state = 'PENDING';
CREATE INDEX IF NOT EXISTS ix_change_log_entity ON mig.change_log (entity_kind, entity_ref, change_seq DESC);

-- -----------------------------------------------------------------------------
-- 4. 对账结果（REQ-MIG-005：总量、唯一性、状态、身份、凭证与 Membership）
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS mig.reconciliation_result (
    id                    uuid        NOT NULL DEFAULT core.uuid_generate_v7(),
    batch_id              uuid        NOT NULL,
    check_code            text        NOT NULL,
    checked_at            timestamptz NOT NULL DEFAULT now(),
    expected_value        text        NULL,
    actual_value          text        NULL,
    diff_count            bigint      NOT NULL DEFAULT 0,
    result_state          text        NOT NULL,
    sample_ref            text        NULL,
    approved_exception_ref text       NULL,
    CONSTRAINT pk_reconciliation_result PRIMARY KEY (id),
    CONSTRAINT uq_reconciliation_result UNIQUE (batch_id, check_code, checked_at),
    CONSTRAINT fk_reconciliation_result_batch FOREIGN KEY (batch_id) REFERENCES mig.migration_batch (id),
    CONSTRAINT ck_reconciliation_result_check CHECK (check_code IN (
        'TOTAL_COUNT', 'IDENTIFIER_UNIQUENESS', 'LIFECYCLE_STATE', 'IDENTITY_BINDING',
        'CREDENTIAL_PRESENCE', 'MEMBERSHIP_COUNT', 'KEY_FIELD_DIFF'
    )),
    CONSTRAINT ck_reconciliation_result_state CHECK (result_state IN ('PASS', 'FAIL', 'APPROVED_EXCEPTION')),
    -- AT-MIG-001：差异必须为零，或有逐项审批的例外
    CONSTRAINT ck_reconciliation_result_zero_or_exception CHECK (
        (result_state = 'PASS' AND diff_count = 0)
        OR (result_state = 'APPROVED_EXCEPTION' AND approved_exception_ref IS NOT NULL)
        OR result_state = 'FAIL'
    )
);
COMMENT ON TABLE mig.reconciliation_result IS 'REQ-MIG-005 / AT-MIG-001：每批对账总量、唯一性、状态、身份、凭证与 Membership；差异为零或有逐项审批例外';

CREATE INDEX IF NOT EXISTS ix_reconciliation_result_batch ON mig.reconciliation_result (batch_id, checked_at DESC);

SELECT core.fn_apply_standard_grants('mig');

SELECT core.fn_migration_apply('190', 'migration_legacy：迁移批次、旧 ID 映射、重复候选、切换后变更日志、对账结果');
