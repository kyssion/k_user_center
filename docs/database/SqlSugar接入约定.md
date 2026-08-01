# .NET 10 + SqlSugar + PostgreSQL 接入约定

> 本文只约束应用如何安全使用本数据库。数据库 Schema 由 SQL 迁移唯一管理，禁止 SqlSugar Code First 自动建表或自动改表。

## 1. 包与版本

- 目标框架：`net10.0`。
- ORM 候选基线：`SqlSugarCore 5.1.4.216`，使用 PostgreSQL Provider；该包可由 `net10.0` 消费。
- 使用中央包管理和 `packages.lock.json` 固定完整依赖图，不使用浮动版本或预览版：

```xml
<Project>
  <PropertyGroup>
    <ManagePackageVersionsCentrally>true</ManagePackageVersionsCentrally>
    <RestorePackagesWithLockFile>true</RestorePackagesWithLockFile>
  </PropertyGroup>
  <ItemGroup>
    <PackageVersion Include="SqlSugarCore" Version="5.1.4.216" />
  </ItemGroup>
</Project>
```

- `SqlSugarCore 5.1.4.216` 当前包元数据声明的 PostgreSQL 依赖为 `Npgsql 5.0.18`。不得未经兼容性测试直接覆盖为 Npgsql 10，也不得把旧传递依赖直接视为生产安全结论；正式实现时必须完成依赖漏洞扫描、SqlSugar/Npgsql 兼容矩阵和真实 PostgreSQL 回归后锁定最终图。
- 升级 SqlSugar、Npgsql 或 .NET SDK 时必须重跑 SQL 快照、事务、JSONB、数组、`timestamptz`、Schema 限定、乐观锁和 RLS 测试。

## 2. 连接注册

```csharp
using SqlSugar;

services.AddSingleton<ISqlSugarClient>(_ =>
{
    var db = new SqlSugarScope(new ConnectionConfig
    {
        ConfigId = "identity-primary",
        ConnectionString = configuration.GetConnectionString("IdentityDb"),
        DbType = DbType.PostgreSQL,
        IsAutoCloseConnection = true,
        InitKeyType = InitKeyType.Attribute,
        MoreSettings = new ConnMoreSettings
        {
            IsAutoRemoveDataCache = true
        }
    });

    db.Aop.OnLogExecuting = (sql, parameters) =>
    {
        // 仅记录模板化 SQL、trace 和耗时；参数必须按分类脱敏。
        // 密码、验证码、Token、授权码、密文、盲索引和密钥引用禁止输出。
    };

    return db;
});
```

要求：

- 密码、证书和连接串来自 Secret Manager，不进入源码、配置仓库或日志。
- 生产启用 TLS、证书校验、合理连接池、命令超时和取消令牌。
- API 请求使用短生命周期工作单元；不要把带事务或租户上下文的连接跨请求缓存。
- 不依赖 `search_path` 推断表名。实体或查询必须使用 `schema.table` 全限定名，并在锁定的 SqlSugar 版本上通过 SQL 快照确认被生成为 `"schema"."table"`。

## 3. 实体映射

```csharp
using SqlSugar;

[SugarTable("user_account")]
public sealed class UserAccountRow
{
    [SugarColumn(ColumnName = "id", IsPrimaryKey = true)]
    public Guid Id { get; init; }

    [SugarColumn(ColumnName = "public_id")]
    public required string PublicId { get; init; }

    [SugarColumn(ColumnName = "lifecycle_state")]
    public required string LifecycleState { get; init; }

    [SugarColumn(ColumnName = "user_security_epoch")]
    public long UserSecurityEpoch { get; init; }

    [SugarColumn(ColumnName = "created_at")]
    public DateTimeOffset CreatedAt { get; init; }

    [SugarColumn(ColumnName = "updated_at")]
    public DateTimeOffset UpdatedAt { get; init; }

    [SugarColumn(ColumnName = "row_version")]
    public long RowVersion { get; init; }
}
```

Repository 必须对 Queryable/Insertable/Updateable/Deleteable 使用已验证的 `.AS("iam.user_account")` 运行时映射，并用 SQL 快照断言结果为 `"iam"."user_account"`。只有确认锁定版本能正确拆分 Schema 时，才允许在 `[SugarTable]` 中使用带点名称；禁止生成单一标识 `"iam.user_account"`，也禁止退化为全局 `search_path`。

命名与类型：

| PostgreSQL | .NET 10 | 约定 |
|---|---|---|
| `uuid` | `Guid` | 服务端新 ID 优先 `Guid.CreateVersion7()`；数据库默认 `gen_random_uuid()` 作为兜底 |
| `timestamptz` | `DateTimeOffset` | 持久化 UTC；禁止 `DateTimeKind.Unspecified` |
| `bigint` | `long` | security epoch、聚合版本、row version |
| `integer/smallint` | `int/short` | 有界计数、Schema/Profile 版本 |
| `numeric(p,s)` | `decimal` | 比例、计量；禁止 `double` 替代精确值 |
| `bytea` | `byte[]` | hash、密文、签名和摘要 |
| `jsonb` | JSON DTO/`JsonDocument` | 先做 Schema 校验；不得将领域核心状态藏入任意 JSON |
| `text[]/uuid[]` | `string[]/Guid[]` | scope、audience、引用集合；大量多对多关系仍使用关联表 |
| `interval` | `TimeSpan` | 保留周期；绝对过期时间仍使用 `DateTimeOffset` |

状态字段建议映射为领域枚举，但落库值必须显式指定稳定字符串；禁止使用枚举整数序号。

## 4. 迁移唯一权威

禁止：

```csharp
db.CodeFirst.InitTables(...);
db.DbMaintenance.CreateDatabase();
db.DbMaintenance.AddColumn(...);
```

允许：

- 应用启动只读取 `core.schema_migration` 检查最低兼容版本。
- CI/部署任务使用 `psql` 按文件顺序执行 `docs/database/migrations`。
- Schema 变更采用 expand → migrate/backfill → contract；破坏性变更必须新主版本和迁移窗口。
- SqlSugar 实体不是数据库结构权威，不能依据实体自动删除列、索引、约束、注释或触发器。

## 5. 事务、Operation 与 Outbox

单域权威写入、Audit Outbox 和领域 Outbox 必须在同一数据库事务内完成：

```csharp
var result = await db.Ado.UseTranAsync(async () =>
{
    // 1. 使用带 row_version 的条件 UPDATE 修改聚合。
    // 2. 插入 audit.audit_outbox，并显式写入 tenant_id；高风险操作写入失败必须回滚。
    // 3. 插入 integration.outbox_event，event_id/idempotency_key 由调用方稳定生成。
    // 4. 不在事务内调用消息总线、Webhook、短信、邮件或其他数据库。
});

if (!result.IsSuccess)
{
    throw result.ErrorException;
}
```

跨事务边界流程必须先创建 `core.async_operation` 和步骤记录，使用 Saga、幂等消费者、检查点、补偿和对账。越过 `irreversible_at` 后只允许前向修复。

## 6. 乐观锁与安全版本

高风险更新不要依赖“先查再改”。使用单条 compare-and-set SQL：

```csharp
var affected = await db.Ado.ExecuteCommandAsync(
    """
    UPDATE iam.user_account
       SET security_freeze_state = @freeze_state,
           freeze_reason_code = @reason,
           frozen_at = clock_timestamp(),
           frozen_by_ref = @actor,
           user_security_epoch = user_security_epoch + 1
     WHERE id = @id
       AND row_version = @expected_version
       AND lifecycle_state NOT IN ('ANONYMIZED', 'ERASED', 'MERGED')
    """,
    new SugarParameter("@freeze_state", "FROZEN"),
    new SugarParameter("@reason", reasonCode),
    new SugarParameter("@actor", actorRef),
    new SugarParameter("@id", userId),
    new SugarParameter("@expected_version", expectedVersion));

if (affected != 1)
    throw new OptimisticConcurrencyException();
```

要求：

- `row_version` 冲突返回稳定的 `OPTIMISTIC_LOCK_CONFLICT`。
- 冻结、改密、认证器失陷、Grant/Client/Consent 撤销等安全变更必须同时推进适用 epoch。
- 签发 Token 前重新读取并锁定/校验 Grant、Client、User、Tenant、Consent 水位；不能使用无期限缓存。
- 资源服务器缓存键必须包含所有适用 security epoch、策略版本和以 Consent 为依据时的 consent epoch。
- Refresh Token 轮换在同一事务内预生成 successor UUID，先把旧 CURRENT 更新为 USED 并写 successor，再插入新 CURRENT；generation 由数据库按 Family 行锁分配。确认 USED Token 重放时调用 `oauth.fn_mark_refresh_token_reuse`，不得只在应用内标记。
- Session 只能以 ACTIVE 初态创建；过期、失陷和撤销使用状态更新并由数据库填写时间，失陷/撤销必须传非空原因代码，应用不得直接写终态时间。
- 创建 PENDING Consent 不推进聚合 epoch；只有 GRANTED、DENIED、WITHDRAWN、有效同意到期或 SUPERSEDED 才改变生效水位。同一聚合的新版本由数据库分配 `consent_version`。
- Approval 必须从 DRAFT 创建；`submitted_at`、`approved_at`、`rejected_at`、`execution_id` 和其余关键状态时间由数据库生成，应用必须用 `UPDATE ... RETURNING` 取得真实值，不能预填或用应用服务器时间覆盖。
- Config/授权策略/风险策略 Release 应在进入 ACTIVE 的同一事务前或同一更新中写入已执行审批的 case/execution ID；审批必须与资源 Tenant（全局资源使用平台租户）、类型、引用和内容摘要完全一致，激活后不得替换绑定。

## 7. 幂等

- API 写请求先写 `core.idempotency_request`，唯一键为 scope + actor + tenant + idempotency key。
- 同键同 `request_hash` 返回第一次结果；同键不同摘要返回 `IDEMPOTENCY_CONFLICT`。
- Event、Webhook、供应商回执、SCIM、迁移 CDC 和 Token assertion 都有独立唯一键，不能只依赖“数据库没报错”。
- `Guid.CreateVersion7()` 可用于有时间局部性的内部 UUID；公开 ID 仍由领域前缀 + 加密安全随机值生成，并受 `public_id_ledger` 保护。

## 8. 租户隔离

租户上下文只能由可信入口解析，不能直接信任请求体或 Header 中的任意 UUID。

未启用 RLS 时：

- Repository 方法必须显式接收 `TenantContext`。
- 所有租户表查询在表达式中加入 `tenant_id == trustedTenantId`。
- 详情查询和批量查询同样过滤；禁止先查全局 ID 再在内存判断租户。
- 跨租户资源统一返回 `403 ACCESS_DENIED`，不泄漏存在性。

启用 RLS 时，每个事务第一条数据库命令设置：

```csharp
await db.Ado.ExecuteCommandAsync(
    "SELECT set_config('app.tenant_id', @tenant_id, true)",
    new SugarParameter("@tenant_id", trustedTenantId.ToString()));
```

第三个参数 `true` 表示事务本地设置，必须在显式事务内且是该事务第一条业务 SQL；事务结束后自动恢复，避免连接池租户串线。普通应用角色不得拥有 `BYPASSRLS`、表所有权或平台控制角色成员资格。

## 9. JSONB、数组和动态 Profile

- JSONB 只用于版本化扩展：策略输入、证据、Schema、义务、检查点和发布内容。
- 状态、唯一性、租户键、外键、epoch、过期时间、幂等键等必须是结构化列。
- 写入 `profile.business_profile`、`sensitive_attribute` 前根据 `profile.field_definition.validation_schema` 校验类型、用途、权威域和权限。
- JSON 序列化必须确定性处理，用于 hash 的对象需要固定字段规则；不要依赖属性枚举顺序。
- 数组包含查询、JSONB 运算符、`FOR UPDATE SKIP LOCKED`、部分索引和 `RETURNING` 等 PostgreSQL 特性可通过参数化原生 SQL 使用。

## 10. 队列领取模式

Outbox、Webhook、Privacy Task、消息和迁移 CDC 消费者使用短事务批量领取：

```sql
WITH picked AS (
    SELECT id
      FROM integration.outbox_event
     WHERE publish_state IN ('PENDING', 'FAILED')
       AND available_at <= clock_timestamp()
       AND (next_attempt_at IS NULL OR next_attempt_at <= clock_timestamp())
     ORDER BY available_at, id
     FOR UPDATE SKIP LOCKED
     LIMIT @batch_size
)
UPDATE integration.outbox_event e
   SET publish_state = 'PUBLISHING',
       attempt_count = attempt_count + 1
  FROM picked
 WHERE e.id = picked.id
RETURNING e.*;
```

远端调用不占用数据库事务。调用完成后以新事务推进 `PUBLISHED/FAILED/DEAD_LETTER`；事件正文和摘要不可修改。Outbox 仅由 `kuc_outbox_dispatcher` 更新列白名单；Message Send 仅由 `kuc_message_dispatcher` 推进发送列。

Webhook 每次投递尝试都插入新的 `integration.webhook_delivery` 行并递增 `delivery_attempt`，单行只允许 `PENDING → SENDING → DELIVERED/FAILED/DEAD_LETTER`，不得改写旧尝试来伪造重试历史。

## 11. 敏感数据与日志

任何 AOP、异常、OpenTelemetry、慢查询和审计日志都必须过滤：

- 密码及密码哈希参数。
- 验证码、Challenge、Device/User Code。
- Access/Refresh/ID Token、授权码、Client Assertion、Session Cookie。
- Client Secret、私钥、KMS/HSM 凭证。
- Identifier 密文、盲索引和完整手机号/邮箱。
- Webhook 签名密钥和消息目标密文。

允许记录：SQL 模板、参数分类、参数长度、稳定错误码、trace/correlation ID、受控 public ID、耗时和影响行数。

## 12. 禁止事项

- 禁止使用 SqlSugar Code First 管理生产 Schema。
- 禁止应用账户直连 `public` Schema 或依赖可变 `search_path`。
- 禁止 `Deleteable<T>()` 删除审计、撤销、公开 ID、Risk Assessment、变更日志等证据表。
- 禁止把手机号、邮箱、外部 ID 当作跨域外键。
- 禁止读取后在应用内判断唯一性；必须依靠数据库唯一约束并处理冲突。
- 禁止用本地时间、客户端时间戳或 SCIM ETag 大小决定状态新旧。
- 禁止在数据库事务内同步调用消息、邮件、短信、Webhook、IdP 或 KMS 网络接口。
- 禁止捕获 PostgreSQL 异常文本直接返回用户；映射为 `core.error_registry` 中的稳定错误码。

## 13. 必须覆盖的集成测试

1. 所有实体/查询输出的 SQL 使用正确的 `"schema"."table"`。
2. `uuid`、`timestamptz`、`bytea`、`jsonb`、`text[]`、`uuid[]`、`interval` 往返一致。
3. 100 并发 Identifier 绑定、Invitation 接受、Refresh Token 轮换最多一个成功；successor 必须同 Family 且恰好下一代，USED Token 重放会失陷整个 Family。
4. `row_version` 冲突、状态终态恢复、epoch 回退被拒绝；Session 非 ACTIVE 插入、提前过期、缺少原因的失陷/撤销或改写终态时间均失败。
5. 冻结用户不能创建 Session、刷新 Token 或登记 ACTIVE Authenticator。
6. Login Transaction 未完成，或 User/Machine、Client、Tenant、scope/resource、Session、epoch 任一不一致时，Grant/Code/Token 签发失败。
7. Consent 用途、类别、接收方、聚合 epoch 或过期时间任一不一致时，Grant、Token、营销订阅和偏好启用失败；创建 PENDING 不失效当前 GRANTED，决定生效后旧版本被原子替代。
8. 审批非 DRAFT 插入、从 DRAFT 直接 EXECUTED、审核后篡改请求、换 Tenant/资源/摘要、改写数据库生成的状态时间或 `execution_id`，以及用同一执行再次激活资源均失败；Release 激活前可绑定执行结果，激活后不可替换。
9. Outbox/Audit Outbox 与领域写入原子提交，故障后可重试且不重复副作用；正文/租户/Subject/Actor 不可改写。
10. RLS 开启时直接表、派生表、跨租户、连接池复用、后台任务和平台角色行为正确。
11. 日志扫描不出现密码、验证码、完整 Token、私钥和 Identifier 明文。
12. 锁定的 SqlSugar/Npgsql 依赖图通过漏洞扫描和全部类型/SQL 快照回归。
13. 在真实 PostgreSQL 16+ 上按顺序执行全部迁移并通过 `verify.sql`。
