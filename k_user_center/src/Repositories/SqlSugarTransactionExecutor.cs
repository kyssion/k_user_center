using KUserCenter.Common.Transactions;
using SqlSugar;

namespace KUserCenter.Repositories;

/// <summary>
/// SqlSugar 事务执行器：Application 命令处理器经此端口开启事务，
/// 权威事实、领域 Outbox、本地审计、审计投递 Outbox 与幂等结果同事务提交；
/// Repository 不自行提交。
/// </summary>
public sealed class SqlSugarTransactionExecutor : ITransactionExecutor
{
    private readonly ISqlSugarClient _client;

    public SqlSugarTransactionExecutor(ISqlSugarClient client)
    {
        _client = client;
    }

    public async Task<TResult> ExecuteAsync<TResult>(Func<Task<TResult>> work, CancellationToken cancellationToken = default)
    {
        try
        {
            _client.Ado.BeginTran();
            var result = await work().ConfigureAwait(false);
            _client.Ado.CommitTran();
            return result;
        }
        catch
        {
            _client.Ado.RollbackTran();
            throw;
        }
    }

    public async Task ExecuteAsync(Func<Task> work, CancellationToken cancellationToken = default)
    {
        await ExecuteAsync(async () =>
        {
            await work().ConfigureAwait(false);
            return true;
        }, cancellationToken).ConfigureAwait(false);
    }
}
