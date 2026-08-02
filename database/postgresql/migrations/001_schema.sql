\set ON_ERROR_STOP on

SET ROLE iam_owner;

CREATE SCHEMA IF NOT EXISTS iam AUTHORIZATION iam_owner;
COMMENT ON SCHEMA iam IS '统一身份与访问平台业务数据。数据库负责存储和基础约束，业务规则由 .NET 代码执行。';

REVOKE ALL ON SCHEMA iam FROM PUBLIC;
GRANT USAGE, CREATE ON SCHEMA iam TO iam_migrator;
GRANT USAGE ON SCHEMA iam TO iam_app_rw, iam_app_ro, iam_sensitive_rw, iam_audit_writer, iam_audit_reader, iam_ops;

ALTER DEFAULT PRIVILEGES FOR ROLE iam_owner IN SCHEMA iam REVOKE ALL ON TABLES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES FOR ROLE iam_owner IN SCHEMA iam REVOKE ALL ON SEQUENCES FROM PUBLIC;
