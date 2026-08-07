using KUserCenter.Common.Concurrency;
using KUserCenter.Common.Errors;
using KUserCenter.Common.Idempotency;
using KUserCenter.Common.Ids;
using SqlSugar;

namespace KUserCenter.Repositories;

/// <summary>
/// iam.idempotency_records 适配器（阶段 0 技术探针）：显式列映射与参数化 SQL，
/// 在调用方当前事务内登记/重放/完成幂等记录。同键竞争由数据库唯一约束裁决：
/// 捕获冲突后重读，同摘要重放、不同摘要抛 IDEMPOTENCY_KEY_REUSED。
/// 真实 PostgreSQL 实跑验证按跳过规则顺延前，不认定为生产仓储冻结。
/// </summary>
public sealed class SqlSugarIdempotencyStore : IIdempotencyStore
{
    private const string StartedState = "STARTED";
    private const string CompletedState = "COMPLETED";
    private const string CallerKeyConstraint = "uq_idempotency_caller_key";

    private readonly ISqlSugarClient _client;
    private readonly PersistenceErrorTranslator _translator;

    public SqlSugarIdempotencyStore(ISqlSugarClient client, PersistenceErrorTranslator translator)
    {
        _client = client;
        _translator = translator;
    }

    public async Task<IdempotencyRecord> ReserveAsync(
        IdempotencyKey key,
        IdempotencyReservation reservation,
        CancellationToken cancellationToken = default)
    {
        var existing = await FindAsync(key).ConfigureAwait(false);
        if (existing is not null)
        {
            return ResolveExisting(existing, reservation.RequestHash);
        }

        var id = Uuid7.New();
        try
        {
            // SqlSugar Ado 不支持 CancellationToken，取消语义由外层事务作用域保障。
            await _client.Ado.ExecuteCommandAsync(
                """
                INSERT INTO iam.idempotency_records
                    (id, caller_scope, idempotency_key, request_hash, state, expires_at)
                VALUES
                    (@id, @callerScope, @key, @requestHash, @state, @expiresAt)
                """,
                new SugarParameter("@id", id),
                new SugarParameter("@callerScope", key.CallerScope),
                new SugarParameter("@key", key.Key),
                new SugarParameter("@requestHash", reservation.RequestHash),
                new SugarParameter("@state", StartedState),
                new SugarParameter("@expiresAt", reservation.ExpiresAt.UtcDateTime)).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            var fault = NpgsqlFaultClassifier.Classify(ex);
            if (fault.Kind == PersistenceFaultKind.UniqueViolation && fault.ConstraintName == CallerKeyConstraint)
            {
                // 并发同键竞争由数据库裁决：重读后按摘要判定重放或冲突。
                var winner = await FindAsync(key).ConfigureAwait(false);
                if (winner is not null)
                {
                    return ResolveExisting(winner, reservation.RequestHash);
                }
            }

            throw _translator.Translate(fault);
        }

        return new IdempotencyRecord(new IdempotencyRequestId(id), IdempotencyOutcome.Accepted, null);
    }

    public async Task CompleteAsync(
        IdempotencyRequestId id,
        IdempotencyCompletion completion,
        CancellationToken cancellationToken = default)
    {
        var affected = await _client.Ado.ExecuteCommandAsync(
            """
            UPDATE iam.idempotency_records
            SET state = @state,
                response_status = @responseStatus,
                response_body = @responseBody,
                updated_at = CURRENT_TIMESTAMP,
                row_version = row_version + 1
            WHERE id = @id
            """,
            new SugarParameter("@state", CompletedState),
            new SugarParameter("@responseStatus", completion.ResponseStatus),
            new SugarParameter("@responseBody", (object?)completion.ResponseBody),
            new SugarParameter("@id", id.Id)).ConfigureAwait(false);

        CasGuard.EnsureApplied(affected);
    }

    private static IdempotencyRecord ResolveExisting(IdempotencyRow row, string requestHash)
    {
        if (!string.Equals(row.RequestHash, requestHash, StringComparison.Ordinal))
        {
            throw new IdempotencyKeyReusedException();
        }

        return new IdempotencyRecord(
            new IdempotencyRequestId(row.Id),
            IdempotencyOutcome.Replayed,
            new IdempotentResult(row.ResponseStatus, row.ResponseBody));
    }

    private async Task<IdempotencyRow?> FindAsync(IdempotencyKey key)
    {
        try
        {
            return await _client.Ado.SqlQuerySingleAsync<IdempotencyRow>(
                """
                SELECT id AS Id,
                       request_hash AS RequestHash,
                       state AS State,
                       response_status AS ResponseStatus,
                       response_body AS ResponseBody
                FROM iam.idempotency_records
                WHERE caller_scope = @callerScope
                  AND idempotency_key = @key
                  AND expires_at > CURRENT_TIMESTAMP
                """,
                new SugarParameter("@callerScope", key.CallerScope),
                new SugarParameter("@key", key.Key)).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            throw _translator.Translate(NpgsqlFaultClassifier.Classify(ex));
        }
    }

    private sealed class IdempotencyRow
    {
        public Guid Id { get; set; }
        public string RequestHash { get; set; } = string.Empty;
        public string State { get; set; } = string.Empty;
        public int? ResponseStatus { get; set; }
        public string? ResponseBody { get; set; }
    }
}
