namespace KUserCenter.Common.Transactions;

/// <summary>
/// 事务执行端口：Application 命令处理器是事务入口，通过该端口在同一事务内
/// 提交权威事实、领域 Outbox、本地审计、审计投递 Outbox 与幂等结果。
/// Repository 不自行提交；禁止 TransactionScope 跨库/跨系统。
/// </summary>
public interface ITransactionExecutor
{
    Task<TResult> ExecuteAsync<TResult>(Func<Task<TResult>> work, CancellationToken cancellationToken = default);

    Task ExecuteAsync(Func<Task> work, CancellationToken cancellationToken = default);
}
