# SqlSugar 接入约定（PostgreSQL）

> 配套文档：[数据库构建文档](./数据库构建文档.md)
> 适用：SqlSugar + Npgsql + .NET LTS（当前仓库 `net10.0`）
> 定位：本文件只规定**如何把已建好的库正确映射与使用**。表结构、索引、约束、触发器、分区、权限一律以 `migrations/*.sql` 为唯一权威。

## 1. 铁律

| 规则 | 原因 |
|---|---|
| **禁止 `CodeFirst.InitTables`** 在任何环境执行 | CodeFirst 无法表达部分唯一索引、触发器、CHECK、分区与列级权限，会静默建出不满足不变量的库（构建文档 §11.1） |
| 禁止在代码里拼接跨 schema 的写操作 | schema 即模块边界，跨域一律走应用服务或事件（能力地图 §11.0） |
| 禁止手写不带 `tenant_id` 条件的租户内表查询 | `INV-G-015`；必须依赖全局过滤器，见 §5 |
| 禁止把明文手机号、邮箱、验证码、Token 传给数据库层 | `REQ-KEY-008`、`INV-G-007`；加解密与 HMAC 在应用层完成，见 §4 |
| 状态机转换必须走领域服务方法，禁止 `Update` 直接改状态列 | 数据库只对终态与唯一性兜底，合法转换判定在应用层 |
| 写业务状态与写 `event.outbox` 必须在同一事务 | `INV-G-010`，见 §6 |

## 2. 连接与全局配置

### 2.1 三套连接串（对应三个安全域）

| 用途 | 角色 | 说明 |
|---|---|---|
| 业务与控制面 | `uc_app` | 主连接，`Search Path` 覆盖业务域与控制面 schema |
| 认证服务 | `uc_cred_app` | 只用于 `cred` schema，独立连接池 |
| 审计写入 | `uc_app`（仅 INSERT）或 `uc_audit_writer` | 审计表对 `uc_app` 只授 INSERT，无 SELECT |

Npgsql 连接串示例（业务连接）：

```
Host=...;Port=5432;Database=user_center;Username=uc_app;Password=...;
Search Path=core,id,auth,oap,session,tenant,authz,profile,priv,fed,risk,machine,kms,ctrl,event,msg,asr,mig,public;
Maximum Pool Size=50;Timeout=5;Command Timeout=10;Application Name=uc-api
```

依赖 `Search Path` 而不是在实体上写 schema 前缀，这是本设计要求**表名全局唯一**（不同 schema 也不重名）的原因：检索无歧义，映射最简单。

### 2.2 SqlSugar 配置

```csharp
var config = new ConnectionConfig
{
    DbType = DbType.PostgreSQL,
    ConnectionString = businessConnectionString,
    IsAutoCloseConnection = true,
    // PostgreSQL 标识符大小写敏感；库中一律 snake_case 小写，必须关闭自动大写
    MoreSettings = new ConnMoreSettings
    {
        IsAutoToUpper = false,
        IsCorrectErrorSqlParameterName = true
    },
    ConfigureExternalServices = new ConfigureExternalServices
    {
        // 实体 PascalCase → 列 snake_case
        EntityService = (property, column) =>
        {
            column.DbColumnName = UtilMethods.ToUnderLine(column.DbColumnName);
        },
        EntityNameService = (type, entity) =>
        {
            entity.DbTableName = UtilMethods.ToUnderLine(entity.DbTableName);
        }
    }
};
```

### 2.3 时间与时区

- 所有时间列为 `timestamptz`，实体一律用 `DateTimeOffset`，禁止 `DateTime`（避免本地时区污染）。
- 安全判定（Token 过期、Challenge 过期、认证新鲜度）**不得使用应用时钟**，用 `now()` 或数据库返回值；`API-G-009` 与能力地图 §11.0 的可信时钟要求同源。

## 3. 类型映射

| 数据库类型 | 实体类型 | SqlSugar 标注 |
|---|---|---|
| `uuid` | `Guid` | 无需特殊标注 |
| `text` | `string` | 无 |
| `text[]` | `string[]` | `[SugarColumn(ColumnDataType = "text[]", IsArray = true)]` |
| `bytea` | `byte[]` | 无 |
| `jsonb` | `string` 或强类型 | `[SugarColumn(ColumnDataType = "jsonb", IsJson = true)]` |
| `timestamptz` | `DateTimeOffset` / `DateTimeOffset?` | 无 |
| `interval` | `TimeSpan` | 仅参考数据表用到 |
| `bigint` | `long` | 无 |
| `smallint` | `short` | 无 |
| 状态列（`text` + CHECK） | `string` 常量类，**不要用 C# enum 直接映射** | 见 §3.1 |

### 3.1 状态列不用 enum 映射

数据库用 `text` + `CHECK` 表达状态，取值集合由迁移脚本控制。C# 侧用**静态常量类 + 校验**而不是 `enum`：

```csharp
public static class UserLifecycleState
{
    public const string Provisional     = "PROVISIONAL";
    public const string Active          = "ACTIVE";
    public const string Dormant         = "DORMANT";
    public const string DeletionPending = "DELETION_PENDING";
    public const string DeletionBlocked = "DELETION_BLOCKED";
    public const string Anonymized      = "ANONYMIZED";
    public const string Erased          = "ERASED";
    public const string Merged          = "MERGED";

    // 终态：任何路径不得回到其他状态（INV-G-009）
    public static readonly ImmutableHashSet<string> Terminal =
        ImmutableHashSet.Create(Anonymized, Erased, Merged);
}
```

理由：新增状态时数据库 CHECK 与 C# 常量是两次独立评审，`enum` 的隐式数值映射会让"库里出现未知状态"变成静默的 `(MyEnum)0`。

## 4. 加密标识的读写模式

`id.identifier`、`fed.external_identity`、`msg.message_send` 等表的标识列有固定三件套，**必须走统一的仓储方法，禁止各处自行拼装**：

```csharp
public sealed record ProtectedIdentifier(
    byte[] BlindIndex,      // HMAC-SHA256(盲索引密钥, 规范化明文)
    byte[] Cipher,          // AES-256-GCM 随机化密文
    string Masked,          // 展示掩码
    short CipherKeyVersion,
    short BlindIndexKeyVersion,
    short NormalizationVersion);

public interface IIdentifierProtector
{
    // 规范化 + 盲索引 + 加密 + 掩码，一次完成，保证四者同源
    ProtectedIdentifier Protect(string rawValue, IdentifierType type, string? regionHint);

    // 只用于必须回显原值的场景（如客服工单、导出），调用点必须写 obs.data_access_audit
    string Reveal(byte[] cipher, short cipherKeyVersion);
}
```

查询规则：

```csharp
// 正确：等值查找只用盲索引
var idf = await db.Queryable<Identifier>()
    .Where(x => x.IdentifierType == IdentifierType.Phone
             && x.ValueBlindIndex == protected.BlindIndex
             && x.IdentifierState == IdentifierState.Verified)
    .FirstAsync();

// 错误：密文是随机化的，等值比较永远不命中
// .Where(x => x.ValueCipher == protected.Cipher)
```

每次盲索引查找都要写一条 `obs.data_access_audit`（`access_kind = 'BLIND_INDEX_LOOKUP'`，`lookup_kind` 记录检索域），这是 `CAP-KEY-005` 与 `AT-KEY-006` 的证据来源；限速在缓存层实现，不在数据库。

## 5. 租户隔离

租户内表统一继承一个基类并注册全局过滤器：

```csharp
public interface ITenantScoped { Guid TenantId { get; set; } }

public static readonly Guid PlatformTenant = Guid.Empty; // 全零 UUID 表示平台级

db.QueryFilter.AddTableFilter<ITenantScoped>(it =>
    it.TenantId == currentContext.TenantId || it.TenantId == PlatformTenant);
```

约束：

1. 过滤器**不允许**在业务代码中 `ClearFilter`；确有跨租户需要（对账、平台管理）时走独立的 `IPlatformAdminRepository`，其每个方法都必须写数据访问审计。
2. 插入时必须显式设置 `TenantId`，不得依赖数据库默认值兜底（默认值是平台级，误用会造成越权可见）。
3. 分页游标必须包含 `tenant_id`（`API-G-005`），不得用裸 `id` 作游标。

## 6. 事务与 Outbox

任何改变权威状态的写入都必须与事件在同一事务提交（`INV-G-010`）：

```csharp
await db.Ado.UseTranAsync(async () =>
{
    // 1. 权威状态写入（含乐观锁）
    var affected = await db.Updateable<GlobalUser>()
        .SetColumns(u => new GlobalUser
        {
            FreezeState   = FreezeState.Frozen,
            FrozenAt      = DateTimeOffset.UtcNow,
            SecurityEpoch = user.SecurityEpoch + 1,   // 单调递增，数据库触发器兜底
            RowVersion    = user.RowVersion + 1
        })
        .Where(u => u.Id == user.Id && u.RowVersion == user.RowVersion)
        .ExecuteCommandAsync();

    if (affected == 0) throw new VersionMismatchException(); // → 412 VERSION_MISMATCH

    // 2. 同事务写 Outbox
    await db.Insertable(OutboxMessage.From(
        eventType: "user.security_state.changed",
        aggregate: user,
        orderingKey: user.PublicId)).ExecuteCommandAsync();

    // 3. 同事务写审计（审计不可写时必须失败关闭，INV-G-008）
    await db.Insertable(auditEntry).ExecuteCommandAsync();
});
```

要点：

- `ExecuteCommandAsync` 返回 0 即乐观锁冲突，必须抛出并映射为 `412 VERSION_MISMATCH`，不得静默重试覆盖。
- 审计写入失败必须让整个事务失败，禁止 `try/catch` 吞掉（蓝图 §15.2：审计不可用时高风险操作失败关闭）。
- Outbox 投递由独立后台服务读取，业务事务内**不做**任何网络调用。

## 7. 必须用原生 SQL 的几处

以下操作依赖数据库的原子语义，用 ORM 表达会引入竞态，**必须写原生 SQL**：

### 7.1 Refresh Token 原子轮换（`REQ-SESSION-002`、`AT-SESSION-007`）

```csharp
const string RotateSql = @"
WITH used AS (
    UPDATE session.refresh_token_instance
       SET instance_state = 'USED', used_at = now(), successor_id = @newId
     WHERE id = @currentId AND instance_state = 'CURRENT'
    RETURNING family_id, generation
)
INSERT INTO session.refresh_token_instance
    (id, family_id, generation, token_hash, instance_state, issued_at, expires_at, binding_context_hash)
SELECT @newId, family_id, generation + 1, @newHash, 'CURRENT', now(), @expiresAt, @bindingHash
FROM used
RETURNING id;";

var newInstanceId = await db.Ado.SqlQuerySingleAsync<Guid?>(RotateSql, parameters);
if (newInstanceId is null)
{
    // 旧实例已非 CURRENT：按 REQ-SESSION-014 区分丢包重试与重放
    await HandleReuseAsync(currentId);   // 重放则整个 family 标 COMPROMISED
    throw new InvalidGrantException();
}
```

### 7.2 授权码与 Challenge 的单次消费

```sql
UPDATE session.authorization_code
   SET code_state = 'CONSUMED', consumed_at = now()
 WHERE code_hash = @hash AND code_state = 'ISSUED' AND expires_at > now();
-- 影响 0 行 = 重放或过期 → 撤销关联授权（REQ-AUTH-004）
```

```sql
UPDATE auth.verification_challenge
   SET challenge_state = 'CONSUMED', consumed_at = now(), attempt_count = attempt_count + 1
 WHERE id = @id AND challenge_state = 'VERIFIED' AND expires_at > now();
-- 并发消费最多一个成功（REQ-AUTH-015、AT-AUTH-010）
```

### 7.3 幂等键抢占（`INV-G-012`）

```sql
INSERT INTO core.idempotency_record (scope, idempotency_key, principal_ref, endpoint, request_hash, expires_at)
VALUES (@scope, @key, @principal, @endpoint, @hash, @expiresAt)
ON CONFLICT (scope, idempotency_key) DO NOTHING
RETURNING id;
-- 无返回 = 键已存在：比对 request_hash，相同则重放结果，不同则 409 IDEMPOTENCY_KEY_REUSED
```

### 7.4 审计哈希链串行化（`INV-G-008`）

```sql
SELECT pg_advisory_xact_lock(@chainShard);   -- 同分片内串行，事务结束自动释放
-- 读取该分片最后一条 entry_hash，计算新 entry_hash 后插入
```

## 8. 漂移检测（代替 CodeFirst 同步）

CI 中用 SqlSugar 的差异比对能力做**只读**校验，发现实体与库不一致即失败：

```csharp
// 仅在 CI 中执行；生产进程不得包含此代码路径
var diff = db.CodeFirst.GetDifferenceTables(typeof(GlobalUser), typeof(Identifier) /* ... */);
if (diff.Any())
{
    throw new SchemaDriftException(
        "实体与数据库不一致。请修改 migrations/*.sql 并新增版本，禁止用 CodeFirst 同步。");
}
```

配套的门禁顺序（对应蓝图 §18.2）：

1. 执行 `migrations/*.sql`
2. 执行 `verify.sql` —— 有 ERROR 即阻断
3. 执行实体漂移检测 —— 有差异即阻断
4. 执行数据库契约测试（唯一约束、并发、Outbox、状态机负向用例）

## 9. 实体示例

```csharp
[SugarTable("global_user")]
public class GlobalUser
{
    [SugarColumn(IsPrimaryKey = true)]
    public Guid Id { get; set; }

    /// <summary>对外 UID（usr_xxx），永不复用（INV-G-001）</summary>
    public string PublicId { get; set; } = default!;

    public string SubjectKind { get; set; } = "HUMAN";

    /// <summary>生命周期状态，取值见 UserLifecycleState</summary>
    public string LifecycleState { get; set; } = default!;

    /// <summary>认证锁定状态，与生命周期、冻结状态正交（INV-G-005）</summary>
    public string LockState { get; set; } = default!;

    /// <summary>安全冻结状态，与锁定状态正交</summary>
    public string FreezeState { get; set; } = default!;

    /// <summary>安全水位，只增不减（蓝图 §4.3）</summary>
    public long SecurityEpoch { get; set; }

    public long AggregateVersion { get; set; }

    public DateTimeOffset? FrozenAt { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset UpdatedAt { get; set; }

    [SugarColumn(IsEnableUpdateVersionValidation = true)]
    public long RowVersion { get; set; }
}

[SugarTable("business_profile")]
public class BusinessProfile : ITenantScoped
{
    [SugarColumn(IsPrimaryKey = true)]
    public Guid Id { get; set; }
    public Guid UserId { get; set; }
    public Guid BusinessLineId { get; set; }
    public Guid TenantId { get; set; }
    public string Namespace { get; set; } = default!;

    [SugarColumn(ColumnDataType = "jsonb", IsJson = true)]
    public Dictionary<string, object?> Attributes { get; set; } = new();

    public long RowVersion { get; set; }
}
```

注意 `GlobalUser` 中**没有** `updated_at` 的赋值逻辑：该列由数据库触发器 `trg_global_user_touch` 维护，实体只读取。

## 10. 常见错误对照

| 症状 | 根因 | 处理 |
|---|---|---|
| `23505 unique_violation` on `ux_identifier_active_scope` | 并发绑定同一标识 | 返回 `409 IDENTITY_ALREADY_BOUND`，不重试（`AT-ID-002`） |
| `23505` on `ux_refresh_token_current` | 并发轮换 | 返回 `invalid_grant`，按 §7.1 判定重放 |
| `23514 check_violation` 且消息含 `INVALID_STATE_TRANSITION` | 试图离开终态 | 返回 `422 INVALID_STATE_TRANSITION`，说明主体已终结 |
| `23514` 且消息含 `SUBJECT_FROZEN` | 冻结主体执行了受限操作 | 返回 `423 SUBJECT_FROZEN` |
| `23514` 且消息含 `EPOCH_MONOTONICITY_VIOLATION` | 代码试图回退 `security_epoch` | 属于严重 Bug，必须告警而非重试 |
| `42501` 且消息含 `APPEND_ONLY_VIOLATION` | 试图改删追加型表 | 属于严重 Bug，检查是否用错角色或写了修正逻辑 |
| 查询突然返回空集 | 启用了 RLS 但未设置 `app.current_tenant_id` | 见 `optional/910_rls_optional.sql` 的风险提示 |
| 写入报"no partition of relation found" | 分区维护任务未执行 | 立即执行 `core.fn_ensure_monthly_partitions`，并检查告警为何未触发 |
