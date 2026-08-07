namespace KUserCenter.Common.Idempotency;

/// <summary>
/// 幂等端口值对象（全局持久化与事务规范 §1 第 4 步）：
/// 幂等键作用域内登记幂等记录；同键不同规范化请求摘要返回冲突。
/// Common 层只定义端口与值对象，禁止依赖 SqlSugar/Npgsql/ASP.NET。
/// </summary>
public readonly record struct IdempotencyRequestId(Guid Id);

/// <summary>
/// 幂等键定位：调用方稳定作用域 + 幂等键，对应
/// iam.idempotency_records(caller_scope, idempotency_key) 唯一契约。
/// </summary>
public sealed record IdempotencyKey(string CallerScope, string Key);

/// <summary>
/// 幂等登记输入：规范化请求 SHA-256 十六进制摘要（char(64)）与技术过期时间。
/// 摘要由命令代码在规范化后计算，禁止携带敏感原文。
/// </summary>
public sealed record IdempotencyReservation(string RequestHash, DateTimeOffset ExpiresAt)
{
    public const int RequestHashLength = 64;
}

/// <summary>
/// 幂等结果快照：仅包含可安全复用的响应状态与响应体快照；
/// 脱敏与容量限制由命令代码负责。
/// </summary>
public sealed record IdempotentResult(int? ResponseStatus, string? ResponseBody);

/// <summary>首次登记成功后用于完成幂等记录的最终结果。</summary>
public sealed record IdempotencyCompletion(int ResponseStatus, string? ResponseBody);

/// <summary>幂等登记结论：首次接受（继续执行命令）或重放（返回既有结果）。</summary>
public enum IdempotencyOutcome
{
    Accepted,
    Replayed
}

/// <summary>
/// 幂等登记记录：Accepted 时 Result 为空；Replayed 时携带既有结果快照。
/// </summary>
public sealed record IdempotencyRecord(IdempotencyRequestId Id, IdempotencyOutcome Outcome, IdempotentResult? Result);
