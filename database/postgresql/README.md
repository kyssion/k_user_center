# PostgreSQL 数据库实施说明

本目录是 `docs/数据库设计总纲.md` 的可执行实现。数据库只承担持久化、基础结构约束、唯一性、原子并发、技术时间、索引、分区，以及 Migration、普通运行时、敏感数据、审计和 Worker 等部署身份的粗粒度技术访问控制；状态机、逻辑引用校验、最终用户/管理员授权、租户与数据范围隔离、领域 Owner、风险、审批、加密及流程编排属于用户中心代码职责，具体契约见 `docs/implementation`。

## 执行顺序

1. 由平台管理员执行 `bootstrap/001_roles.sql`。
2. 由平台管理员在目标数据库执行 `bootstrap/002_database_permissions.sql`。
3. 使用继承 `iam_migrator` 的部署登录身份运行 `run-migrations.sh`；Runner 按文件名执行 `migrations/*.sql`，并校验迁移账本中的脚本名和 SHA-256。
4. 使用同一部署登录身份依文件名执行 `seeds/*.sql`，写入稳定目录和 DRAFT 控制面候选版本；由应用审批发布流程决定是否激活。
5. 由高权限只读检查账号执行 `verification/*.sql`。
6. 生产上线前将迁移账本、验证脚本的零异常结果保存为发布证据。

## 迁移约束

- 已在环境执行的迁移文件不可修改，只能追加新文件。
- 权限以完整迁移链执行后的最终状态为准：`820_runtime_permissions.sql` 保留历史基线，`830_runtime_delete_hardening.sql` 追加收回全部运行时 `DELETE`；不得回改 `820` 规避校验和。
- 全部业务对象位于 `iam` Schema；`iam_meta` 只保存 Migration 技术账本，不属于 113 张业务表。
- Migration 文件名必须为唯一的 `NNN_name.sql`，且脚本内不得自行 `BEGIN/COMMIT/ROLLBACK`；Runner 将单个脚本及其账本登记放在同一事务中，已登记版本的脚本被修改、改名或从仓库移除时立即失败。
- 已有环境若已经执行 Migration 但没有 `iam_meta.schema_migrations` 账本，必须通过单独评审的基线登记变更接管，禁止 Runner 自动推断或静默认领历史。
- 不创建 Foreign Key、业务 Trigger、持久化业务 Routine、PostgreSQL Enum 或业务 View。
- `*_id` 为逻辑引用，目标、作用域、状态和删除行为由代码校验。
- 每张逻辑表必须映射到一个主要业务模型和权威域；多领域复用遵守 `docs/database/业务模型与持久化边界清单.md` 的共享写入边界，不得形成影子状态或未声明双写。
- 数据库角色只做部署身份和敏感存储的粗粒度隔离，不映射最终用户、管理员角色、租户、数据范围、领域 Owner 或业务状态。
- 业务授权和追加/不可变写入契约由用户中心的 PEP、应用服务、命令与仓储边界执行；数据库 Grant 只对审计、敏感存储和选定的高价值追加证据表做粗粒度防御纵深，不判断业务主体、作用域、Owner 或状态。
- 所有运行时技术角色均无 `DELETE`；业务删除、匿名化和状态终止由代码实现，物理清理与分区退役由单独审批的版本化迁移或维护流程执行。
- 基线不依赖 RLS、数据库 Policy、`SECURITY DEFINER`、按租户建账号/Schema 或存储过程承载业务授权；若额外用于防御纵深，必须保留代码契约、可迁移实现和独立测试。
- `created_at`、`recorded_at` 使用数据库默认时间；更新时应用必须显式设置 `updated_at = CURRENT_TIMESTAMP`。
- UUID 由应用生成，推荐 UUIDv7；数据库不替应用推导业务标识。
- Seed 使用稳定业务键和内容摘要保证幂等；同键内容不一致时执行失败，禁止静默覆盖或忽略漂移。
- `configuration_versions`、事件 Schema 和消息模板 Seed 默认 `DRAFT`，不得作为已发布配置直接读取。
- 运行时登录身份按最小技术职责组合组角色：普通持久化读写使用 `iam_app_rw + iam_audit_writer`；AUTH/OAP 对 Challenge、恢复码、授权码和 Token 元数据执行读改写时使用 `iam_app_rw + iam_sensitive_rw + iam_audit_writer`；队列和投递 Worker 使用 `iam_ops`，只有确需读取密文时才叠加 `iam_sensitive_rw`。部署清单必须显式登记组合，运行时禁止继承 `iam_owner` 或 `iam_migrator`；这些组合不代替代码中的业务授权、租户校验和状态转换。
- 验证码和 Magic Link Token 不写入 `message_requests.parameters`；消息请求只保存外部短期秘密存储的非承载型 `delivery_secret_handle`，消息 Worker 使用 `iam_ops + iam_sensitive_rw` 和独立秘密存储身份在内存中完成模板渲染。
- 关键读取路径必须符合 `docs/database/查询与索引契约.md`；索引不允许替代 Tenant、Owner、状态、过期时间或权限条件。

## 本地执行示例

```bash
psql -U '<platform-admin-login>' -d '<database>' -f database/postgresql/bootstrap/001_roles.sql
psql -U '<platform-admin-login>' -d '<database>' -f database/postgresql/bootstrap/002_database_permissions.sql

database/postgresql/run-migrations.sh -U '<deployment-login>' -d '<database>'

for seed in database/postgresql/seeds/*.sql; do
  psql -X -v ON_ERROR_STOP=1 -U '<deployment-login>' -d '<database>' -f "$seed"
done
```

`<deployment-login>` 必须继承 `iam_migrator`，不能直接使用 `NOLOGIN` 的组角色名连接。SQL 使用 `\set ON_ERROR_STOP on`，任一语句失败即停止；角色与数据库级权限脚本需要具备创建角色、授权和修改目标数据库权限的管理员身份。

执行完全部 SQL 后运行 `verification/Generate-DatabaseDocs.ps1`，生成数据库需求覆盖索引、逻辑关系清单、孤儿检查 SQL 和数据字典，并校验 113/113 逻辑表业务模型映射、113/113 领域持久化范围映射及全部多领域复用表权威映射。数据库需求覆盖索引只证明持久化边界覆盖，不代替蓝图 §18.4 的正式代码实施与验收矩阵。
