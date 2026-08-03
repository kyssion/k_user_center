\set ON_ERROR_STOP on

SET ROLE iam_owner;

CREATE SCHEMA IF NOT EXISTS iam AUTHORIZATION iam_owner;
COMMENT ON SCHEMA iam IS '统一身份与访问平台业务数据。数据库负责持久化事实和必要硬边界，业务状态机、关联有效性、权限、风险、审批与流程编排属于非数据库职责。';

REVOKE ALL ON SCHEMA iam FROM PUBLIC;
GRANT USAGE, CREATE ON SCHEMA iam TO iam_migrator;
GRANT USAGE ON SCHEMA iam TO iam_app_rw, iam_app_ro, iam_sensitive_rw, iam_audit_writer, iam_audit_reader, iam_ops;

ALTER DEFAULT PRIVILEGES FOR ROLE iam_owner IN SCHEMA iam REVOKE ALL ON TABLES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES FOR ROLE iam_owner IN SCHEMA iam REVOKE ALL ON SEQUENCES FROM PUBLIC;
