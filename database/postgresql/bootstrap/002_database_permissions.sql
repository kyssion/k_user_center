\set ON_ERROR_STOP on

-- 在目标数据库内执行。数据库 CONNECT 权限由环境变量和平台账号策略控制。
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
REVOKE ALL ON DATABASE :"DBNAME" FROM PUBLIC;

-- iam Schema 在首个 Migration 中创建；本文件只声明数据库级最小权限。
GRANT CREATE ON DATABASE :"DBNAME" TO iam_owner;
GRANT CONNECT ON DATABASE :"DBNAME" TO iam_migrator, iam_app_rw, iam_app_ro, iam_sensitive_rw, iam_audit_writer, iam_audit_reader, iam_ops;
