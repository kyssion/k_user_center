\set ON_ERROR_STOP on

SET ROLE iam_owner;

-- 运行时身份不执行物理删除。业务删除、匿名化、状态终止和引用检查由代码编排；
-- 物理清理、分区退役和依法保留后的删除由单独审批的版本化迁移或维护流程执行。
REVOKE DELETE ON ALL TABLES IN SCHEMA iam FROM
    iam_app_rw,
    iam_app_ro,
    iam_sensitive_rw,
    iam_audit_writer,
    iam_audit_reader,
    iam_ops;

-- 不设置未来表的宽泛默认权限；新增表或分区必须在后续 Migration 中显式授予所需的非 DELETE 权限。
