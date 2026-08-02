# PostgreSQL 数据库实施说明

本目录是 `docs/数据库设计总纲.md` 的可执行实现。数据库只承担持久化、基础结构约束、唯一性、原子并发、技术时间、索引、分区和访问控制；状态机、逻辑引用校验、租户隔离、权限、风险、审批、加密及流程编排由 .NET 代码承担。

## 执行顺序

1. 由平台管理员执行 `bootstrap/001_roles.sql`。
2. 使用 `iam_migrator` 依文件名顺序执行 `migrations/*.sql`。
3. 按环境批准情况执行 `seeds/*.sql`。
4. 由高权限只读检查账号执行 `verification/*.sql`。
5. 生产上线前将验证脚本的零异常结果保存为发布证据。

## 迁移约束

- 已在环境执行的迁移文件不可修改，只能追加新文件。
- 全部业务对象位于 `iam` Schema。
- 不创建 Foreign Key、业务 Trigger、持久化业务 Routine、PostgreSQL Enum 或业务 View。
- `*_id` 为逻辑引用，目标、作用域、状态和删除行为由代码校验。
- `created_at`、`recorded_at` 使用数据库默认时间；更新时应用必须显式设置 `updated_at = CURRENT_TIMESTAMP`。
- UUID 由应用生成，推荐 UUIDv7；数据库不替应用推导业务标识。

## 本地执行示例

```powershell
$env:PGPASSWORD = '<password>'
Get-ChildItem database/postgresql/migrations/*.sql | Sort-Object Name | ForEach-Object {
  psql -v ON_ERROR_STOP=1 -U iam_migrator -d '<database>' -f $_.FullName
}
```

脚本使用 `\set ON_ERROR_STOP on`，任一语句失败即停止。角色脚本需要具备创建角色和授权的管理员权限。

