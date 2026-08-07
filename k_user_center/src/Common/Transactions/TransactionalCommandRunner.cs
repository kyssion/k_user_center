using KUserCenter.Common.Audit;
using KUserCenter.Common.Idempotency;
using KUserCenter.Common.Outbox;

namespace KUserCenter.Common.Transactions;

/// <summary>
/// 事务命令输入：幂等键定位 + 规范化请求摘要 + 幂等技术过期时间。
/// 参数校验、作用域解析、授权、风险与审批必须在进入执行器之前完成（规范 §1 第 1~3 步）。
/// </summary>
public sealed record TransactionalCommandRequest(
    IdempotencyKey IdempotencyKey,
    string RequestHash,
    DateTimeOffset IdempotencyExpiresAt);

/// <summary>命令工作体返回值：业务结果与用于幂等结果快照的可复用响应。</summary>
public sealed record CommandOutcome<TResult>(TResult Result, int ResponseStatus, string? ResponseBody);

/// <summary>命令执行结论：重放时返回既有幂等结果快照，不执行业务工作体。</summary>
public sealed record TransactionalCommandResult<TResult>(
    bool Replayed,
    IdempotentResult? ReplayedResult,
    TResult? Result);

/// <summary>
/// 事务内命令上下文：经端口写入领域 Outbox、本地审计与审计投递 Outbox；
/// 所有写入共享调用方当前事务，禁止端口内部另开事务。
/// </summary>
public sealed class TransactionalCommandContext
{
    private readonly IOutboxWriter _outbox;
    private readonly IAuditWriter _audit;

    internal TransactionalCommandContext(IOutboxWriter outbox, IAuditWriter audit)
    {
        _outbox = outbox;
        _audit = audit;
    }

    /// <summary>追加领域 Outbox 事件（与权威事实同事务）。</summary>
    public Task EmitAsync(OutboxMessage message, CancellationToken cancellationToken = default) =>
        _outbox.AppendAsync(message, cancellationToken);

    /// <summary>
    /// 追加本地审计事实，并立即追加引用 audit_event_id 的审计投递 Outbox 信封；
    /// 两者必须同事务提交。审计失败向上抛出并导致整个命令事务回滚（失败关闭）。
    /// </summary>
    public async Task<Guid> RecordAuditAsync(
        AuditEntry entry,
        Func<Guid, OutboxMessage> auditDeliveryFactory,
        CancellationToken cancellationToken = default)
    {
        var auditEventId = await _audit.AppendAsync(entry, cancellationToken).ConfigureAwait(false);
        await _outbox.AppendAsync(auditDeliveryFactory(auditEventId), cancellationToken).ConfigureAwait(false);
        return auditEventId;
    }
}

/// <summary>
/// 事务命令执行器（全局持久化与事务规范 §1 第 4~9 步的可复用骨架）：
/// 事务内依次完成幂等登记 → 权威事实/Outbox/审计（由工作体经上下文写入）
/// → 幂等结果完成 → 提交；任一步失败整体回滚。
/// 重放命中时直接返回既有结果，不执行业务工作体。
/// 阶段 0 技术探针：不暴露为生产 API，不登记为业务交付证据。
/// </summary>
public sealed class TransactionalCommandRunner
{
    private readonly ITransactionExecutor _transaction;
    private readonly IIdempotencyStore _idempotency;
    private readonly IOutboxWriter _outbox;
    private readonly IAuditWriter _audit;

    public TransactionalCommandRunner(
        ITransactionExecutor transaction,
        IIdempotencyStore idempotency,
        IOutboxWriter outbox,
        IAuditWriter audit)
    {
        _transaction = transaction;
        _idempotency = idempotency;
        _outbox = outbox;
        _audit = audit;
    }

    public Task<TransactionalCommandResult<TResult>> ExecuteAsync<TResult>(
        TransactionalCommandRequest request,
        Func<TransactionalCommandContext, Task<CommandOutcome<TResult>>> work,
        CancellationToken cancellationToken = default)
    {
        return _transaction.ExecuteAsync(async () =>
        {
            var reservation = new IdempotencyReservation(request.RequestHash, request.IdempotencyExpiresAt);
            var record = await _idempotency.ReserveAsync(request.IdempotencyKey, reservation, cancellationToken)
                .ConfigureAwait(false);

            if (record.Outcome == IdempotencyOutcome.Replayed)
            {
                return new TransactionalCommandResult<TResult>(true, record.Result, default);
            }

            var context = new TransactionalCommandContext(_outbox, _audit);
            var outcome = await work(context).ConfigureAwait(false);

            await _idempotency.CompleteAsync(
                record.Id,
                new IdempotencyCompletion(outcome.ResponseStatus, outcome.ResponseBody),
                cancellationToken).ConfigureAwait(false);

            return new TransactionalCommandResult<TResult>(false, null, outcome.Result);
        }, cancellationToken);
    }
}
