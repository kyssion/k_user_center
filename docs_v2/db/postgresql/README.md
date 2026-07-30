# PostgreSQL 数据库迁移

本目录是统一身份与访问平台的唯一数据库 DDL 入口。基线为 PostgreSQL 16+、单数据库、仅使用 `public` schema；DDL 使用原生 SQL，不依赖 ORM、ORM migration history 或非必要扩展。

## 执行

在仓库根目录连接到目标空数据库，并使用不加载本机 `psqlrc` 的方式执行：

```sh
psql -X "$DATABASE_URL" -v ON_ERROR_STOP=1 -f db/postgresql/apply.sql
```

也可以使用显式连接参数：

```sh
psql -X -h <host> -p 5432 -U <migrator> -d <database> \
  -v ON_ERROR_STOP=1 -f db/postgresql/apply.sql
```

`apply.sql` 通过 `\ir` 按编号固定顺序加载 `migrations/000` 至 `130`。必须从 `apply.sql` 执行，不要单独挑选文件；各迁移自行声明事务边界，入口脚本不包裹全局事务，以便后续明确承载不能位于事务块内的在线迁移步骤。

预检会拒绝 PostgreSQL 16 以下版本和非 UTF-8 数据库，并把本次 `psql` 会话设置为 UTC。如果目标数据库尚未配置数据库级 UTC，预检只给出 `ALTER DATABASE ... SET timezone TO 'UTC'` 提示，不会静默修改数据库或实例配置。

## DBA 与迁移脚本边界

DBA/基础设施脚本负责：

- 创建数据库、登录角色和迁移角色，并安全交付连接凭据；
- 配置备份、复制、高可用、TLS、连接限制、监控和实例参数；
- 按变更流程设置数据库默认时区为 UTC；
- 执行需要超级用户、云控制面或实例重启的操作。

本目录中的迁移只负责当前数据库 `public` schema 内的平台对象、约束、索引、函数、权限和参考数据。迁移不会创建/删除数据库，不修改实例级参数，不授予超级用户或 `BYPASSRLS`，也不安装非必要扩展。生产环境应使用专用 migrator 角色；业务应用和管理后台不得直接执行迁移或写底层表。

## 迁移语义

编号迁移是一次性、仅前向的部署制品，不设计为可重复执行，也不使用 `IF NOT EXISTS` 掩盖漂移。部署系统应记录文件名、SHA-256、执行者、目标数据库和执行时间。

若某个文件失败，其事务会回滚；此前已经提交的编号不会自动撤销。修正问题后应通过新的前向迁移处理，禁止修改已在环境中执行过的迁移、盲目重跑整套脚本，或把“回滚”伪装成历史 DDL 改写。需要 `CREATE INDEX CONCURRENTLY` 等非事务操作时，必须在对应迁移中显式标明边界和恢复步骤。

## 验证

全部迁移成功后运行：

```sh
psql -X "$DATABASE_URL" -v ON_ERROR_STOP=1 -f db/postgresql/verify.sql
```

`verify.sql` 是独立验收入口：只执行只读检查，或把写入型探针包在最终 `ROLLBACK` 的测试事务中。应使用与生产相同的非 Owner 运行时角色补充验证权限、RLS、状态守卫、并发唯一性和事务原子性。迁移执行成功不等于验收通过；备份恢复、版本升级和生产发布后都应再次运行验证。
