namespace KUserCenter.Common.Idempotency;

/// <summary>
/// 幂等存储端口（全局持久化与事务规范 §1 第 4 步）：
/// 命令处理器在事务内登记幂等记录；同键同摘要重放返回既有结果，
/// 同键不同摘要抛出 IDEMPOTENCY_KEY_REUSED（409，见错误码注册表）。
/// 适配器必须与权威事实同事务提交，禁止独立事务。
/// </summary>
public interface IIdempotencyStore
{
    /// <summary>
    /// 事务内登记或重放幂等记录。
    /// 首次登记返回 Accepted；同键同 request_hash 重放返回 Replayed 与既有结果；
    /// 同键不同 request_hash 抛出 <see cref="IdempotencyKeyReusedException"/>。
    /// </summary>
    Task<IdempotencyRecord> ReserveAsync(
        IdempotencyKey key,
        IdempotencyReservation reservation,
        CancellationToken cancellationToken = default);

    /// <summary>命令成功完成后在同一事务内写入最终结果快照。</summary>
    Task CompleteAsync(
        IdempotencyRequestId id,
        IdempotencyCompletion completion,
        CancellationToken cancellationToken = default);
}
