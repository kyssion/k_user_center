\set ON_ERROR_STOP on

DO $permissions_check$
DECLARE
    errors text[] := ARRAY[]::text[];
    missing_roles text;
    unsafe_roles text;
    unexpected_memberships text;
    runtime_role text;
    privilege_name text;
    split_privilege_table text;
    append_table text;
    partition_item record;
BEGIN
    SELECT string_agg(required.role_name, ', ' ORDER BY required.role_name)
      INTO missing_roles
      FROM (VALUES
        ('iam_owner'),('iam_migrator'),('iam_app_rw'),('iam_app_ro'),
        ('iam_sensitive_rw'),('iam_audit_writer'),('iam_audit_reader'),('iam_ops')
      ) AS required(role_name)
     WHERE NOT EXISTS (SELECT 1 FROM pg_roles r WHERE r.rolname = required.role_name);

    IF missing_roles IS NOT NULL THEN
        errors := array_append(errors, format('缺少技术角色：%s', missing_roles));
    ELSE
        SELECT string_agg(r.rolname, ', ' ORDER BY r.rolname)
          INTO unsafe_roles
          FROM pg_roles r
         WHERE r.rolname IN (
            'iam_owner','iam_migrator','iam_app_rw','iam_app_ro',
            'iam_sensitive_rw','iam_audit_writer','iam_audit_reader','iam_ops'
         )
           AND (r.rolcanlogin OR r.rolsuper OR r.rolcreatedb OR r.rolcreaterole OR r.rolreplication OR r.rolbypassrls);

        IF unsafe_roles IS NOT NULL THEN
            errors := array_append(errors, format('技术角色具有登录或高权限属性：%s', unsafe_roles));
        END IF;

        IF NOT pg_has_role('iam_migrator', 'iam_owner', 'MEMBER') THEN
            errors := array_append(errors, 'iam_migrator 未继承 iam_owner');
        END IF;

        SELECT string_agg(format('%s -> %s', member_role.rolname, granted_role.rolname), ', '
                          ORDER BY member_role.rolname, granted_role.rolname)
          INTO unexpected_memberships
          FROM pg_auth_members membership
          JOIN pg_roles granted_role ON granted_role.oid = membership.roleid
          JOIN pg_roles member_role ON member_role.oid = membership.member
         WHERE member_role.rolname IN (
            'iam_owner','iam_migrator','iam_app_rw','iam_app_ro',
            'iam_sensitive_rw','iam_audit_writer','iam_audit_reader','iam_ops'
         )
           AND NOT (member_role.rolname = 'iam_migrator' AND granted_role.rolname = 'iam_owner');

        IF unexpected_memberships IS NOT NULL THEN
            errors := array_append(errors, format('技术角色存在未声明的上级角色继承：%s', unexpected_memberships));
        END IF;

        FOREACH runtime_role IN ARRAY ARRAY[
            'iam_app_rw','iam_app_ro','iam_sensitive_rw','iam_audit_writer','iam_audit_reader','iam_ops'
        ]
        LOOP
            IF pg_has_role(runtime_role, 'iam_owner', 'MEMBER') OR pg_has_role(runtime_role, 'iam_migrator', 'MEMBER') THEN
                errors := array_append(errors, format('%s 越权继承对象所有者或迁移角色', runtime_role));
            END IF;
        END LOOP;

        -- 审计父表只允许专用 Writer 追加和 Reader 读取。
        FOREACH runtime_role IN ARRAY ARRAY['iam_app_rw','iam_app_ro','iam_sensitive_rw','iam_ops']
        LOOP
            FOREACH privilege_name IN ARRAY ARRAY['SELECT','INSERT','UPDATE','DELETE']
            LOOP
                IF has_table_privilege(runtime_role, 'iam.audit_events', privilege_name) THEN
                    errors := array_append(errors, format('%s 具有 audit_events %s', runtime_role, privilege_name));
                END IF;
            END LOOP;
        END LOOP;
        IF NOT has_table_privilege('iam_audit_writer', 'iam.audit_events', 'INSERT')
           OR has_table_privilege('iam_audit_writer', 'iam.audit_events', 'SELECT')
           OR has_table_privilege('iam_audit_writer', 'iam.audit_events', 'UPDATE')
           OR has_table_privilege('iam_audit_writer', 'iam.audit_events', 'DELETE') THEN
            errors := array_append(errors, 'iam_audit_writer 不满足 audit_events 仅追加权限');
        END IF;
        IF NOT has_table_privilege('iam_audit_reader', 'iam.audit_events', 'SELECT')
           OR has_table_privilege('iam_audit_reader', 'iam.audit_events', 'INSERT')
           OR has_table_privilege('iam_audit_reader', 'iam.audit_events', 'UPDATE')
           OR has_table_privilege('iam_audit_reader', 'iam.audit_events', 'DELETE') THEN
            errors := array_append(errors, 'iam_audit_reader 不满足 audit_events 只读权限');
        END IF;

        IF has_column_privilege('iam_app_ro', 'iam.identifiers', 'value_ciphertext', 'SELECT') THEN
            errors := array_append(errors, 'iam_app_ro 可读 identifier 密文');
        END IF;
        IF has_column_privilege('iam_app_ro', 'iam.webhook_subscriptions', 'endpoint_ciphertext', 'SELECT') THEN
            errors := array_append(errors, 'iam_app_ro 可读 Webhook Endpoint 密文');
        END IF;
        IF has_column_privilege('iam_app_ro', 'iam.message_requests', 'target_ciphertext', 'SELECT') THEN
            errors := array_append(errors, 'iam_app_ro 可读消息目标密文');
        END IF;
        IF has_table_privilege('iam_app_rw', 'iam.credential_materials', 'SELECT') THEN
            errors := array_append(errors, 'iam_app_rw 可读凭证材料');
        END IF;
        IF NOT has_table_privilege('iam_sensitive_rw', 'iam.credential_materials', 'SELECT')
           OR NOT has_table_privilege('iam_sensitive_rw', 'iam.credential_materials', 'INSERT')
           OR NOT has_table_privilege('iam_sensitive_rw', 'iam.credential_materials', 'UPDATE') THEN
            errors := array_append(errors, 'iam_sensitive_rw 缺少 credential_materials 受控读写权限');
        END IF;

        FOREACH split_privilege_table IN ARRAY ARRAY[
            'recovery_codes', 'auth_challenges', 'authorization_codes',
            'refresh_token_instances', 'access_token_records'
        ]
        LOOP
            IF has_table_privilege('iam_app_rw', format('iam.%I', split_privilege_table), 'SELECT') THEN
                errors := array_append(errors, format('iam_app_rw 可读取 %s 敏感摘要', split_privilege_table));
            END IF;
            IF NOT has_table_privilege('iam_app_rw', format('iam.%I', split_privilege_table), 'INSERT')
               OR NOT has_table_privilege('iam_app_rw', format('iam.%I', split_privilege_table), 'UPDATE') THEN
                errors := array_append(errors, format('iam_app_rw 缺少 %s INSERT/UPDATE', split_privilege_table));
            END IF;
            IF NOT has_table_privilege('iam_sensitive_rw', format('iam.%I', split_privilege_table), 'SELECT') THEN
                errors := array_append(errors, format('iam_sensitive_rw 缺少 %s SELECT', split_privilege_table));
            END IF;
            IF has_table_privilege('iam_sensitive_rw', format('iam.%I', split_privilege_table), 'INSERT')
               OR has_table_privilege('iam_sensitive_rw', format('iam.%I', split_privilege_table), 'UPDATE')
               OR has_table_privilege('iam_sensitive_rw', format('iam.%I', split_privilege_table), 'DELETE') THEN
                errors := array_append(errors, format('iam_sensitive_rw 可单独改写 %s，破坏组合角色边界', split_privilege_table));
            END IF;
        END LOOP;

        IF has_table_privilege('iam_ops', 'iam.global_users', 'INSERT')
           OR has_table_privilege('iam_ops', 'iam.global_users', 'UPDATE')
           OR has_table_privilege('iam_ops', 'iam.global_users', 'DELETE')
           OR has_table_privilege('iam_ops', 'iam.roles', 'UPDATE')
           OR has_table_privilege('iam_ops', 'iam.policy_versions', 'UPDATE')
           OR has_table_privilege('iam_ops', 'iam.configuration_versions', 'UPDATE')
           OR has_table_privilege('iam_ops', 'iam.approval_cases', 'UPDATE') THEN
            errors := array_append(errors, 'iam_ops 可修改非运维权威业务表');
        END IF;

        -- 数据库只对选定高价值证据做粗粒度防御：普通和运维角色不得 UPDATE/DELETE。
        FOREACH append_table IN ARRAY ARRAY[
            'authentication_attempts','authorization_decisions','risk_signals','workload_attestations',
            'webhook_delivery_attempts','message_delivery_attempts','agreement_acceptances',
            'approval_actions','deletion_proofs','migration_change_logs'
        ]
        LOOP
            FOREACH runtime_role IN ARRAY ARRAY['iam_app_rw','iam_ops']
            LOOP
                IF has_table_privilege(runtime_role, format('iam.%I', append_table), 'UPDATE')
                   OR has_table_privilege(runtime_role, format('iam.%I', append_table), 'DELETE') THEN
                    errors := array_append(errors, format('%s 可改写追加证据表 %s', runtime_role, append_table));
                END IF;
            END LOOP;
        END LOOP;

        -- ALL TABLES 会直接授权现有分区，子表必须维持与父表相同的粗粒度边界。
        FOR partition_item IN
            SELECT child_ns.nspname AS schema_name, child.relname AS table_name, parent.relname AS parent_name
              FROM pg_inherits
              JOIN pg_class parent ON parent.oid = pg_inherits.inhparent
              JOIN pg_class child ON child.oid = pg_inherits.inhrelid
              JOIN pg_namespace parent_ns ON parent_ns.oid = parent.relnamespace
              JOIN pg_namespace child_ns ON child_ns.oid = child.relnamespace
             WHERE parent_ns.nspname = 'iam'
        LOOP
            IF partition_item.parent_name = 'audit_events' THEN
                FOREACH runtime_role IN ARRAY ARRAY['iam_app_rw','iam_app_ro','iam_sensitive_rw','iam_ops']
                LOOP
                    FOREACH privilege_name IN ARRAY ARRAY['SELECT','INSERT','UPDATE','DELETE']
                    LOOP
                        IF has_table_privilege(runtime_role, format('%I.%I', partition_item.schema_name, partition_item.table_name), privilege_name) THEN
                            errors := array_append(errors, format('%s 具有审计分区 %s.%s %s', runtime_role, partition_item.schema_name, partition_item.table_name, privilege_name));
                        END IF;
                    END LOOP;
                END LOOP;
                IF NOT has_table_privilege('iam_audit_reader', format('%I.%I', partition_item.schema_name, partition_item.table_name), 'SELECT') THEN
                    errors := array_append(errors, format('iam_audit_reader 无审计分区 %s.%s SELECT', partition_item.schema_name, partition_item.table_name));
                END IF;
            END IF;

            IF partition_item.parent_name IN ('access_token_records','message_requests','migration_change_logs') THEN
                FOREACH runtime_role IN ARRAY ARRAY['iam_app_rw','iam_app_ro','iam_ops']
                LOOP
                    IF has_table_privilege(runtime_role, format('%I.%I', partition_item.schema_name, partition_item.table_name), 'SELECT') THEN
                        errors := array_append(errors, format('%s 可直接读取敏感分区 %s.%s', runtime_role, partition_item.schema_name, partition_item.table_name));
                    END IF;
                END LOOP;
            END IF;

            IF partition_item.parent_name IN (
                'authentication_attempts','authorization_decisions','risk_signals','workload_attestations',
                'webhook_delivery_attempts','message_delivery_attempts','migration_change_logs'
            ) THEN
                FOREACH runtime_role IN ARRAY ARRAY['iam_app_rw','iam_ops']
                LOOP
                    IF has_table_privilege(runtime_role, format('%I.%I', partition_item.schema_name, partition_item.table_name), 'UPDATE')
                       OR has_table_privilege(runtime_role, format('%I.%I', partition_item.schema_name, partition_item.table_name), 'DELETE') THEN
                        errors := array_append(errors, format('%s 可改写追加证据分区 %s.%s', runtime_role, partition_item.schema_name, partition_item.table_name));
                    END IF;
                END LOOP;
            END IF;
        END LOOP;
    END IF;

    IF array_length(errors, 1) IS NOT NULL THEN
        RAISE EXCEPTION '权限门禁失败：%', array_to_string(errors, '; ');
    END IF;
END
$permissions_check$;

SELECT 'PASS: 技术角色属性、成员关系、敏感数据、运维范围和追加证据权限完整' AS result;
