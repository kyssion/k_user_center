# PostgreSQL 数据库实施说明

本目录是 `docs/数据库设计总纲.md` 的可执行实现。数据库只承担持久化、基础结构约束、确定内部引用的存在性、唯一性、原子并发、技术时间、索引、分区和数据库对象访问控制；状态机、多态/外部引用解析、租户与状态有效性、业务授权判定、风险、审批、加密及流程编排属于非数据库职责，具体实现以 `docs/implementation/` 为准。

## 执行顺序

1. 由平台管理员执行 `bootstrap/001_roles.sql`。
2. 使用 `iam_migrator` 依文件名顺序执行 `migrations/*.sql`。
3. 执行 `seeds/*.sql` 写入稳定目录和 DRAFT 控制面候选版本；由应用审批发布流程决定是否激活。
4. 由高权限只读检查账号执行 `verification/*.sql`。
5. 生产上线前将验证脚本的零异常结果保存为发布证据。

## 迁移约束

- 已在环境执行的迁移文件不可修改，只能追加新文件。
- 全部业务对象位于 `iam` Schema。
- 同库、单一目标且目标键唯一的直接 `*_id` 使用 `ON DELETE RESTRICT` Foreign Key；多态、数组和外部引用保留逻辑关系。
- Foreign Key 只校验存在性；作用域、状态、授权、生命周期和业务删除行为由代码校验。
- 每张逻辑表必须映射到一个主要业务模型和权威域；多领域复用遵守 `docs/database/业务模型与持久化边界清单.md` 的共享写入边界，不得形成影子状态或未声明双写。
- `created_at`、`recorded_at` 使用数据库默认时间；`updated_at` 由唯一白名单技术 Trigger 使用 `statement_timestamp()` 自动维护。
- UUID 由应用生成，推荐 UUIDv7；数据库不替应用推导业务标识。
- Seed 使用稳定业务键和内容摘要保证幂等；同键内容不一致时执行失败，禁止静默覆盖或忽略漂移。
- `configuration_versions`、事件 Schema 和消息模板 Seed 默认 `DRAFT`，不得作为已发布配置直接读取。
- 运行时登录身份必须使用对应领域角色（例如 `iam_id_rw`、`iam_auth_rw`、`iam_oap_rw`）并按需叠加 `iam_audit_writer`；`iam_app_rw` 只承载领域角色继承的公共技术表能力，禁止直接授予登录身份。读取标识、认证、Token、机器凭证、投递目标或迁移原文时，分别叠加对应 `*_reader`；`iam_ops` 只处理已登记运行队列。所有运行时角色均无 `DELETE`，且禁止继承 `iam_owner` 或 `iam_migrator`。

## 本地执行示例

```powershell
$env:PGPASSWORD = '<password>'
Get-ChildItem database/postgresql/migrations/*.sql | Sort-Object Name | ForEach-Object {
  psql -v ON_ERROR_STOP=1 -U iam_migrator -d '<database>' -f $_.FullName
}
```

脚本使用 `\set ON_ERROR_STOP on`，任一语句失败即停止。角色脚本需要具备创建角色和授权的管理员权限。

执行完全部 SQL 后运行 `verification/Generate-DatabaseDocs.ps1`，生成数据库需求覆盖索引、逻辑关系清单、孤儿检查 SQL 和数据字典，并校验 113/113 逻辑表业务模型映射、113/113 领域持久化范围映射及全部多领域复用表权威映射。数据库需求覆盖索引只证明持久化边界覆盖，不代替蓝图 §18.4 的正式代码实施与验收矩阵。
