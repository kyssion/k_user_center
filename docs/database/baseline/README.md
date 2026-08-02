# PostgreSQL 空库基线

技术基线：PostgreSQL 16+、.NET 10、SqlSugar。

## 目录约定

- `bootstrap.sql`：扩展、Database/Schema COMMENT，以及最小迁移台账；不承载业务表或共享业务例程。
- `schemas/<schema>/`：18 个业务 Schema；默认包含 `README.md`、`tables.sql`、`routines.sql`、`security.sql`、`build.sql`，按需增加 `views.sql`、`links.sql`、`seed.sql`。
- `finalize.sql`：COMMENT 完整性安全网；若补全函数发现任何显式 COMMENT 遗漏，事务立即失败并回滚，不生成业务结构或外键索引。
- `roles.sql`：平台级角色、对象所有权与全局默认权限；具体对象权限归入各 Schema 的 `security.sql`。
- `rls_optional.sql`：可选 RLS；必须先完成连接池事务级上下文集成测试。
- `verify.sql`：结构、注释、索引、Schema 权限、安全不变量和职责边界验收。
- `build.sql`：默认空库一键构建入口。

## 分步执行

1. 执行 `bootstrap.sql`。
2. 先执行 `schemas/core/build.sql`，创建 `core.public_id_ledger` 和所有 Schema 共用的数据库辅助函数。
3. 再逐个执行其余 17 个 `schemas/<schema>/build.sql`；它们只依赖 `bootstrap` 与 `core`，不依赖其他业务 Schema 的表。
4. 全部局部对象完成后，逐个执行 `schemas/<schema>/links.sql`。
5. 执行 `finalize.sql`，再执行存在的 `seed.sql`。
6. 执行 `roles.sql`，随后逐个执行 18 个 `schemas/<schema>/security.sql`。
7. 以 `kuc_owner` 执行 `verify.sql`。
8. 如确需数据库 RLS，使用可 `SET ROLE kuc_owner` 的迁移账号单独评审并执行 `rls_optional.sql`；脚本在事务内切换到对象所有者。

COMMENT 与对象定义保存在同一个 SQL 文件内；运行时补全函数只用于发现迁移遗漏，返回非零即使构建失败，不是注释的主要实现。
