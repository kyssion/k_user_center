-- =============================================================================
-- verify.sql
-- 数据库契约自动化校验（CI 门禁）
-- 依据：数据库构建文档 §5 不变量映射、§7.4；蓝图 §18.1「数据库契约测试」、§18.2 发布阻断条件
-- 用法：psql "$PGURL" -v ON_ERROR_STOP=1 -f verify.sql
--       有任何违规即打印明细并以非零码退出
-- =============================================================================

\set ON_ERROR_STOP on

DROP TABLE IF EXISTS verify_violation;
CREATE TEMP TABLE verify_violation (
    check_id  text NOT NULL,
    severity  text NOT NULL,
    detail    text NOT NULL
);

DO $verify$
DECLARE
    v_schemas text[] := ARRAY[
        'core','id','cred','auth','oap','session','tenant','authz','profile','priv',
        'fed','risk','machine','kms','ctrl','event','obs','msg','asr','mig'
    ];
    -- 必须带 tenant_id NOT NULL 的租户内表（INV-G-015）
    v_tenant_scoped text[][] := ARRAY[
        ['tenant','membership'],['tenant','invitation'],['tenant','organization'],
        ['tenant','user_group'],['tenant','user_group_member'],['tenant','usage_metering'],
        ['oap','client'],['auth','login_transaction'],['session','user_session'],
        ['session','authorization_grant'],['session','token_family'],['session','access_token_reference'],
        ['session','revocation_record'],['authz','role'],['authz','role_assignment'],['authz','decision_log'],
        ['profile','business_profile'],['risk','risk_signal'],['risk','risk_assessment'],['risk','risk_case'],
        ['machine','machine_principal'],['ctrl','approval_case'],['event','outbox'],['event','webhook_endpoint'],
        ['obs','audit_event'],['obs','data_access_audit'],['msg','message_send'],['asr','delegation'],
        ['mig','migration_batch'],['fed','directory_sync_state']
    ];
    -- 追加型表：uc_app 不得拥有 UPDATE/DELETE（INV-G-008）
    v_append_only text[][] := ARRAY[
        ['core','public_id_ledger'],['id','identifier_tombstone'],['id','user_alias'],
        ['profile','profile_change_log'],['priv','agreement_acceptance'],['session','revocation_record'],
        ['machine','token_exchange_record'],['authz','decision_log'],['risk','risk_signal'],
        ['obs','audit_event'],['obs','data_access_audit'],['obs','audit_seal'],['msg','delivery_receipt']
    ];
    -- 必须存在的对象（索引 / 触发器 / 约束），映射构建文档 §5
    v_required_index text[][] := ARRAY[
        ['V-002','id','ux_identifier_active_scope'],
        ['V-004','fed','ux_external_identity_key'],
        ['V-006','authz','ux_policy_release_active'],
        ['V-011','ctrl','ux_config_release_active'],
        ['V-014','session','ux_refresh_token_current'],
        ['V-017','ctrl','ux_approval_case_execution'],
        ['V-009','id','ix_global_user_lifecycle'],
        ['V-016','obs','ux_audit_event_chain']
    ];
    v_required_trigger text[][] := ARRAY[
        ['V-001','id','global_user','trg_global_user_public_id'],
        ['V-001','tenant','membership','trg_membership_public_id'],
        ['V-001','id','subject_assignment','trg_subject_assignment_public_id'],
        ['V-009','id','global_user','trg_global_user_terminal_guard'],
        ['V-013','session','user_session','trg_user_session_insert_guard'],
        ['V-023','id','global_user','trg_global_user_epoch'],
        ['V-023','oap','client','trg_client_epoch'],
        ['V-023','tenant','tenant','trg_tenant_epoch'],
        ['V-023','machine','machine_principal','trg_machine_principal_epoch'],
        ['V-008','obs','audit_seal','trg_audit_seal_append_only']
    ];
    v_required_constraint text[] := ARRAY[
        'ck_external_identity_persistent',   -- V-004 / INV-G-004
        'ck_config_release_separation',      -- V-011 / INV-G-011
        'ck_approval_case_separation',       -- V-017 / INV-G-017
        'ck_policy_release_separation',      -- V-006
        'ck_delegation_visible',             -- V-018 / CAP-ASR-011
        'ck_delegation_scope_not_empty',     -- V-018 / INV-G-018
        'uq_idempotency_record_key',         -- V-012 / INV-G-012
        'ck_client_grant_types',             -- REQ-AUTH-001 禁止 ROPC/Implicit
        'ck_client_public_no_secret',        -- REQ-MACHINE-002
        'ck_login_transaction_completed',    -- INV-G-016
        'ck_notification_preference_security_always_on', -- CAP-SSC-011
        'ck_token_exchange_record_no_escalation'         -- REQ-MACHINE-008
    ];
    v_rec        record;
    v_item       text[];
    v_cnt        bigint;
BEGIN
    -- ---------------------------------------------------------------------
    -- V-020：每张表必须有主键
    -- ---------------------------------------------------------------------
    INSERT INTO verify_violation
    SELECT 'V-020', 'ERROR', format('%s.%s 缺少主键', n.nspname, c.relname)
    FROM pg_class c
    JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = ANY (v_schemas)
      AND c.relkind IN ('r', 'p')
      AND NOT c.relispartition
      AND NOT EXISTS (SELECT 1 FROM pg_constraint k WHERE k.conrelid = c.oid AND k.contype = 'p');

    -- ---------------------------------------------------------------------
    -- V-021：每张表必须有 COMMENT，且注释中含能力或规范编号（蓝图 §18.4 追踪矩阵）
    -- ---------------------------------------------------------------------
    INSERT INTO verify_violation
    SELECT 'V-021', 'ERROR', format('%s.%s 的 COMMENT 缺少 CAP-/REQ-/INV-/AT-/API-/EVT- 追溯编号', n.nspname, c.relname)
    FROM pg_class c
    JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = ANY (v_schemas)
      AND c.relkind IN ('r', 'p')
      AND NOT c.relispartition
      AND COALESCE(obj_description(c.oid, 'pg_class'), '') !~ '(CAP|REQ|INV|AT|SLO|TTL|TERM|API|EVT)-[A-Z]+-[0-9]{3}';

    -- ---------------------------------------------------------------------
    -- V-005：禁止出现名为 status 的列（INV-G-005：状态必须正交拆列）
    -- ---------------------------------------------------------------------
    INSERT INTO verify_violation
    SELECT 'V-005', 'ERROR', format('%s.%s 存在被禁止的列名 %s，状态必须语义化拆列', table_schema, table_name, column_name)
    FROM information_schema.columns
    WHERE table_schema = ANY (v_schemas)
      AND column_name IN ('status', 'state', 'account_status');

    -- ---------------------------------------------------------------------
    -- V-003：禁止疑似明文标识列（INV-G-003 / INV-G-007 / REQ-KEY-008）
    -- 允许的形态只有 _cipher、_hash、_blind_index、_masked、_digest、_thumbprint
    -- ---------------------------------------------------------------------
    INSERT INTO verify_violation
    SELECT 'V-003', 'ERROR', format('%s.%s.%s 疑似明文敏感列，必须改为密文、盲索引或掩码形态', table_schema, table_name, column_name)
    FROM information_schema.columns
    WHERE table_schema = ANY (v_schemas)
      AND (
            column_name ~ '(phone|mobile|msisdn|email|id_card|idcard|passport|birth|real_name|secret|password|token)'
        )
      AND column_name !~ '(_cipher|_hash|_blind_index|_masked|_digest|_thumbprint|_version|_ref|_at|_state|_kind|_code|_id|_uri|_count|_format|_method|_algorithm)$'
      AND NOT (table_schema = 'core' AND table_name = 'error_code');

    -- ---------------------------------------------------------------------
    -- V-015：租户内表必须有 tenant_id NOT NULL
    -- ---------------------------------------------------------------------
    FOREACH v_item SLICE 1 IN ARRAY v_tenant_scoped LOOP
        SELECT count(*) INTO v_cnt
        FROM information_schema.columns
        WHERE table_schema = v_item[1] AND table_name = v_item[2]
          AND column_name = 'tenant_id' AND is_nullable = 'NO';
        IF v_cnt = 0 THEN
            INSERT INTO verify_violation VALUES ('V-015', 'ERROR',
                format('%s.%s 缺少 tenant_id NOT NULL（INV-G-015 租户隔离）', v_item[1], v_item[2]));
        END IF;
    END LOOP;

    -- ---------------------------------------------------------------------
    -- V-008：追加型表的 uc_app 不得拥有 UPDATE / DELETE
    -- ---------------------------------------------------------------------
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'uc_app') THEN
        FOREACH v_item SLICE 1 IN ARRAY v_append_only LOOP
            IF EXISTS (
                SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
                WHERE n.nspname = v_item[1] AND c.relname = v_item[2]
            ) THEN
                IF has_table_privilege('uc_app', format('%I.%I', v_item[1], v_item[2]), 'UPDATE')
                   OR has_table_privilege('uc_app', format('%I.%I', v_item[1], v_item[2]), 'DELETE') THEN
                    INSERT INTO verify_violation VALUES ('V-008', 'ERROR',
                        format('追加型表 %s.%s 仍对 uc_app 授予 UPDATE/DELETE（INV-G-008）', v_item[1], v_item[2]));
                END IF;
            ELSE
                INSERT INTO verify_violation VALUES ('V-008', 'ERROR',
                    format('追加型表 %s.%s 不存在', v_item[1], v_item[2]));
            END IF;
        END LOOP;
    ELSE
        INSERT INTO verify_violation VALUES ('V-008', 'ERROR', '角色 uc_app 不存在，无法校验追加型表权限');
    END IF;

    -- ---------------------------------------------------------------------
    -- 必须存在的索引 / 触发器 / 约束
    -- ---------------------------------------------------------------------
    FOREACH v_item SLICE 1 IN ARRAY v_required_index LOOP
        IF NOT EXISTS (
            SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
            WHERE n.nspname = v_item[2] AND c.relname = v_item[3] AND c.relkind IN ('i', 'I')
        ) THEN
            INSERT INTO verify_violation VALUES (v_item[1], 'ERROR',
                format('缺少必需索引 %s.%s', v_item[2], v_item[3]));
        END IF;
    END LOOP;

    FOREACH v_item SLICE 1 IN ARRAY v_required_trigger LOOP
        IF NOT EXISTS (
            SELECT 1 FROM pg_trigger t
            JOIN pg_class c ON c.oid = t.tgrelid
            JOIN pg_namespace n ON n.oid = c.relnamespace
            WHERE n.nspname = v_item[2] AND c.relname = v_item[3] AND t.tgname = v_item[4] AND NOT t.tgisinternal
        ) THEN
            INSERT INTO verify_violation VALUES (v_item[1], 'ERROR',
                format('缺少必需触发器 %s.%s.%s', v_item[2], v_item[3], v_item[4]));
        END IF;
    END LOOP;

    FOR v_rec IN SELECT unnest(v_required_constraint) AS conname LOOP
        IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = v_rec.conname) THEN
            INSERT INTO verify_violation VALUES ('V-CONSTRAINT', 'ERROR',
                format('缺少必需约束 %s（见构建文档 §5 不变量映射）', v_rec.conname));
        END IF;
    END LOOP;

    -- ---------------------------------------------------------------------
    -- V-022：所有 *_state 列必须有引用该列的 CHECK 约束
    -- ---------------------------------------------------------------------
    INSERT INTO verify_violation
    SELECT 'V-022', 'ERROR', format('%s.%s.%s 是状态列但没有 CHECK 约束', n.nspname, c.relname, a.attname)
    FROM pg_attribute a
    JOIN pg_class c ON c.oid = a.attrelid
    JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = ANY (v_schemas)
      AND c.relkind IN ('r', 'p')
      AND NOT c.relispartition
      AND a.attnum > 0 AND NOT a.attisdropped
      AND a.attname LIKE '%\_state'
      AND NOT EXISTS (
          SELECT 1 FROM pg_constraint k
          WHERE k.conrelid = c.oid AND k.contype = 'c'
            AND pg_get_constraintdef(k.oid) LIKE '%' || a.attname || '%'
      );

    -- ---------------------------------------------------------------------
    -- V-023：所有含 security_epoch 的表必须有单调递增触发器
    -- ---------------------------------------------------------------------
    INSERT INTO verify_violation
    SELECT 'V-023', 'ERROR', format('%s.%s 含 security_epoch 但缺少单调递增触发器（蓝图 §4.3）', n.nspname, c.relname)
    FROM pg_class c
    JOIN pg_namespace n ON n.oid = c.relnamespace
    JOIN pg_attribute a ON a.attrelid = c.oid AND a.attname = 'security_epoch' AND a.attnum > 0
    WHERE n.nspname = ANY (v_schemas)
      AND c.relkind IN ('r', 'p')
      AND NOT c.relispartition
      AND NOT EXISTS (
          SELECT 1 FROM pg_trigger t
          WHERE t.tgrelid = c.oid AND NOT t.tgisinternal
            AND pg_get_triggerdef(t.oid) LIKE '%fn_forbid_epoch_decrease%'
      );

    -- ---------------------------------------------------------------------
    -- V-024：分区父表必须有当月分区与默认分区
    -- ---------------------------------------------------------------------
    FOR v_rec IN
        SELECT n.nspname AS sch, c.relname AS tbl
        FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = ANY (v_schemas) AND c.relkind = 'p'
    LOOP
        IF NOT EXISTS (
            SELECT 1 FROM pg_class p JOIN pg_namespace pn ON pn.oid = p.relnamespace
            WHERE pn.nspname = v_rec.sch AND p.relname = format('%s_p%s', v_rec.tbl, to_char(now(), 'YYYYMM'))
        ) THEN
            INSERT INTO verify_violation VALUES ('V-024', 'ERROR',
                format('%s.%s 缺少当月分区，写入将落入默认分区（构建文档 §8）', v_rec.sch, v_rec.tbl));
        END IF;
        IF NOT EXISTS (
            SELECT 1 FROM pg_class p JOIN pg_namespace pn ON pn.oid = p.relnamespace
            WHERE pn.nspname = v_rec.sch AND p.relname = format('%s_pdefault', v_rec.tbl)
        ) THEN
            INSERT INTO verify_violation VALUES ('V-024', 'WARN',
                format('%s.%s 缺少默认分区兜底', v_rec.sch, v_rec.tbl));
        END IF;
    END LOOP;

    -- ---------------------------------------------------------------------
    -- V-025：跨安全域外键必须在允许清单内（构建文档 §2.2 SPLIT-POINT）
    -- 允许：cred.* -> id.global_user；除此之外 cred/obs 与其他域之间不得有外键
    -- ---------------------------------------------------------------------
    INSERT INTO verify_violation
    SELECT 'V-025', 'ERROR',
           format('未登记的跨安全域外键：%s.%s -> %s.%s（约束 %s）',
                  sn.nspname, sc.relname, tn.nspname, tc.relname, k.conname)
    FROM pg_constraint k
    JOIN pg_class sc ON sc.oid = k.conrelid
    JOIN pg_namespace sn ON sn.oid = sc.relnamespace
    JOIN pg_class tc ON tc.oid = k.confrelid
    JOIN pg_namespace tn ON tn.oid = tc.relnamespace
    WHERE k.contype = 'f'
      AND sn.nspname <> tn.nspname
      AND (sn.nspname IN ('cred', 'obs') OR tn.nspname IN ('cred', 'obs'))
      AND NOT (sn.nspname = 'cred' AND tn.nspname = 'id' AND tc.relname = 'global_user')
      AND NOT (sn.nspname = 'auth' AND tn.nspname = 'cred' AND tc.relname = 'authenticator');

    -- ---------------------------------------------------------------------
    -- V-026：参考数据必须已播种（900_seed_baseline.sql）
    -- ---------------------------------------------------------------------
    SELECT count(*) INTO v_cnt FROM core.security_profile WHERE is_active;
    IF v_cnt < 5 THEN
        INSERT INTO verify_violation VALUES ('V-026', 'ERROR', format('core.security_profile 只有 %s 条有效记录，应为 SP1-SP5', v_cnt));
    END IF;

    SELECT count(*) INTO v_cnt FROM core.duration_baseline;
    IF v_cnt < 25 THEN
        INSERT INTO verify_violation VALUES ('V-026', 'ERROR', format('core.duration_baseline 只有 %s 条，蓝图 §15.3.1 时长基线未完整播种', v_cnt));
    END IF;

    SELECT count(*) INTO v_cnt FROM core.error_code WHERE deprecated_at IS NULL;
    IF v_cnt < 13 THEN
        INSERT INTO verify_violation VALUES ('V-026', 'ERROR', format('core.error_code 只有 %s 条，蓝图 §5.2 失败语义未完整播种', v_cnt));
    END IF;

    SELECT count(*) INTO v_cnt FROM core.data_classification;
    IF v_cnt <> 4 THEN
        INSERT INTO verify_violation VALUES ('V-026', 'ERROR', format('core.data_classification 应为 4 级，实际 %s', v_cnt));
    END IF;

    -- ---------------------------------------------------------------------
    -- V-027：迁移台账必须包含全部预期版本
    -- ---------------------------------------------------------------------
    FOR v_rec IN
        SELECT v AS version FROM unnest(ARRAY[
            '000','010','020','030','040','050','060','070','080','090',
            '100','110','120','130','140','150','160','170','180','190','900'
        ]) AS v
    LOOP
        IF NOT EXISTS (SELECT 1 FROM core.schema_migration WHERE version = v_rec.version) THEN
            INSERT INTO verify_violation VALUES ('V-027', 'ERROR',
                format('迁移版本 %s 未登记，Schema 不完整', v_rec.version));
        END IF;
    END LOOP;
END;
$verify$;

-- 输出违规明细
\echo '=== verify.sql 违规明细（空表示通过）==='
SELECT check_id, severity, detail FROM verify_violation ORDER BY severity DESC, check_id, detail;

-- 汇总并在存在 ERROR 时以非零码退出
DO $gate$
DECLARE
    v_errors bigint;
    v_warns  bigint;
BEGIN
    SELECT count(*) FILTER (WHERE severity = 'ERROR'), count(*) FILTER (WHERE severity = 'WARN')
      INTO v_errors, v_warns
      FROM verify_violation;

    RAISE NOTICE 'verify.sql 结果：ERROR=% WARN=%', v_errors, v_warns;

    IF v_errors > 0 THEN
        RAISE EXCEPTION 'VERIFY_FAILED: % 项数据库契约违规，按蓝图 §18.2 阻断发布', v_errors;
    END IF;
END;
$gate$;

DROP TABLE IF EXISTS verify_violation;
