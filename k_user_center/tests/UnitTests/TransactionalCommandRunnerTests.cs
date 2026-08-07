using KUserCenter.Common.Audit;
using KUserCenter.Common.Idempotency;
using KUserCenter.Common.Ids;
using KUserCenter.Common.Outbox;
using KUserCenter.Common.Transactions;
using Xunit;

namespace KUserCenter.UnitTests;

/// <summary>
/// 事务命令执行器技术探针（阶段 0）：使用内存夹具验证幂等登记/重放/冲突、
/// 权威事实+Outbox+审计+审计投递 Outbox+幂等结果同事务提交、失败整体回滚与审计失败关闭。
/// 探针不作为业务能力交付，不登记进实施追踪矩阵。
/// </summary>
public class TransactionalCommandRunnerTests
{
    private static TransactionalCommandRequest NewRequest(string requestHash) => new(
        new IdempotencyKey("api:tenants:clients", "key-1"),
        requestHash,
        DateTimeOffset.UtcNow.AddMinutes(10));

    private static CommandOutcome<string> Outcome(string result) => new(result, 200, $"{{\"id\":\"{result}\"}}");

    [Fact]
    public async Task FirstRun_CommitsFactsOutboxAuditAndIdempotencyResult()
    {
        var fixture = new InMemoryPersistenceFixture();
        var request = NewRequest(RequestDigest.ComputeSha256Hex("{\"name\":\"a\"}"));

        var result = await fixture.Runner.ExecuteAsync<string>(request, async ctx =>
        {
            await ctx.EmitAsync(NewOutboxMessage("user.created"), CancellationToken.None);
            await ctx.RecordAuditAsync(
                NewAuditEntry("USER_CREATE"),
                auditEventId => NewOutboxMessage("audit.recorded", auditEventId.ToString()),
                CancellationToken.None);
            return Outcome("user-1");
        });

        Assert.False(result.Replayed);
        Assert.Equal("user-1", result.Result);
        fixture.AssertCommitted(1);
        Assert.Single(fixture.CommittedOutbox, m => m.EventType == "user.created");
        Assert.Single(fixture.CommittedAudit);
        Assert.Single(fixture.CommittedOutbox, m => m.EventType == "audit.recorded");
        Assert.Equal(200, fixture.CommittedIdempotencyResult()?.ResponseStatus);
    }

    [Fact]
    public async Task Replay_SameKeySameHash_ReturnsStoredResultWithoutExecutingWork()
    {
        var fixture = new InMemoryPersistenceFixture();
        var request = NewRequest(RequestDigest.ComputeSha256Hex("{\"name\":\"a\"}"));
        var executions = 0;

        await fixture.Runner.ExecuteAsync<string>(request, _ =>
        {
            executions++;
            return Task.FromResult(Outcome("user-1"));
        });

        var replay = await fixture.Runner.ExecuteAsync<string>(request, _ =>
        {
            executions++;
            return Task.FromResult(Outcome("user-2"));
        });

        Assert.Equal(1, executions);
        Assert.True(replay.Replayed);
        Assert.Equal(200, replay.ReplayedResult?.ResponseStatus);
        Assert.Null(replay.Result);
    }

    [Fact]
    public async Task SameKeyDifferentHash_ThrowsIdempotencyKeyReused()
    {
        var fixture = new InMemoryPersistenceFixture();
        await fixture.Runner.ExecuteAsync<string>(
            NewRequest(RequestDigest.ComputeSha256Hex("{\"name\":\"a\"}")),
            _ => Task.FromResult(Outcome("user-1")));

        var ex = await Assert.ThrowsAsync<IdempotencyKeyReusedException>(() =>
            fixture.Runner.ExecuteAsync<string>(
                NewRequest(RequestDigest.ComputeSha256Hex("{\"name\":\"b\"}")),
                _ => Task.FromResult(Outcome("user-2"))));

        Assert.Equal("IDEMPOTENCY_KEY_REUSED", ex.ErrorCode);
        Assert.Equal(409, ex.HttpStatus);
        fixture.AssertCommitted(1);
    }

    [Fact]
    public async Task WorkFailure_RollsBackAllFacts()
    {
        var fixture = new InMemoryPersistenceFixture();

        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            fixture.Runner.ExecuteAsync<string>(NewRequest("hash-a"), async ctx =>
            {
                await ctx.EmitAsync(NewOutboxMessage("user.created"), CancellationToken.None);
                throw new InvalidOperationException("boom");
            }));

        fixture.AssertCommitted(0);
    }

    [Fact]
    public async Task AuditFailure_FailsClosedAndRollsBackAllFacts()
    {
        var fixture = new InMemoryPersistenceFixture();
        fixture.Audit.FailOnAppend = true;

        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            fixture.Runner.ExecuteAsync<string>(NewRequest("hash-a"), async ctx =>
            {
                await ctx.EmitAsync(NewOutboxMessage("user.created"), CancellationToken.None);
                await ctx.RecordAuditAsync(
                    NewAuditEntry("USER_CREATE"),
                    auditEventId => NewOutboxMessage("audit.recorded", auditEventId.ToString()),
                    CancellationToken.None);
                return Outcome("user-1");
            }));

        fixture.AssertCommitted(0);
    }

    private static OutboxMessage NewOutboxMessage(string eventType, string? causationId = null) => new()
    {
        EventId = Uuid7.New(),
        EventType = eventType,
        SchemaVersion = 1,
        AggregateType = "GlobalUser",
        AggregateId = Uuid7.New(),
        ProducerType = "SERVICE",
        ProducerId = Uuid7.New(),
        SubjectRefType = "GLOBAL_USER_ID",
        SubjectRefId = "usr_probe",
        OccurredAt = DateTimeOffset.UtcNow,
        TraceId = "trace-probe",
        CausationId = causationId,
        DataClassification = "INTERNAL",
        PayloadJson = "{}"
    };

    private static AuditEntry NewAuditEntry(string action) => new()
    {
        Action = action,
        ObjectType = "GlobalUser",
        Outcome = "SUCCESS",
        OccurredAt = DateTimeOffset.UtcNow
    };
}

/// <summary>内存持久化夹具：pending/committed 双层结构模拟事务提交与回滚。</summary>
internal sealed class InMemoryPersistenceFixture
{
    private readonly Dictionary<(string Scope, string Key), (string Hash, IdempotentResult? Result)> _committed = [];
    private readonly Dictionary<(string Scope, string Key), (string Hash, IdempotentResult? Result)> _pending = [];
    private readonly List<OutboxMessage> _committedOutbox = [];
    private readonly List<OutboxMessage> _pendingOutbox = [];
    private readonly List<AuditEntry> _committedAudit = [];
    private readonly List<AuditEntry> _pendingAudit = [];

    public InMemoryIdempotencyStore Store { get; }
    public InMemoryOutboxWriter Outbox { get; }
    public InMemoryAuditWriter Audit { get; }
    public TransactionalCommandRunner Runner { get; }

    public IReadOnlyList<OutboxMessage> CommittedOutbox => _committedOutbox;
    public IReadOnlyList<AuditEntry> CommittedAudit => _committedAudit;

    public InMemoryPersistenceFixture()
    {
        Store = new InMemoryIdempotencyStore(this);
        Outbox = new InMemoryOutboxWriter(this);
        Audit = new InMemoryAuditWriter(this);
        Runner = new TransactionalCommandRunner(new InMemoryTransactionExecutor(this), Store, Outbox, Audit);
    }

    public IdempotentResult? CommittedIdempotencyResult() =>
        _committed.Values.Count == 1 ? _committed.Values.Single().Result : null;

    public void AssertCommitted(int expectedKeys)
    {
        Assert.Equal(expectedKeys, _committed.Count);
        Assert.Empty(_pending);
        Assert.Empty(_pendingOutbox);
        Assert.Empty(_pendingAudit);
    }

    internal void Begin()
    {
        _pending.Clear();
        _pendingOutbox.Clear();
        _pendingAudit.Clear();
    }

    internal void Commit()
    {
        foreach (var (key, value) in _pending)
        {
            _committed[key] = value;
        }

        _committedOutbox.AddRange(_pendingOutbox);
        _committedAudit.AddRange(_pendingAudit);
        _pending.Clear();
        _pendingOutbox.Clear();
        _pendingAudit.Clear();
    }

    internal void Rollback()
    {
        _pending.Clear();
        _pendingOutbox.Clear();
        _pendingAudit.Clear();
    }

    internal bool TryFind(string scope, string key, out string hash, out IdempotentResult? result)
    {
        if (_pending.TryGetValue((scope, key), out var pendingEntry))
        {
            (hash, result) = pendingEntry;
            return true;
        }

        if (_committed.TryGetValue((scope, key), out var committedEntry))
        {
            (hash, result) = committedEntry;
            return true;
        }

        hash = string.Empty;
        result = null;
        return false;
    }

    internal void AddPending(string scope, string key, string hash) => _pending[(scope, key)] = (hash, null);

    internal void CompletePending(string scope, string key, IdempotencyCompletion completion)
    {
        var entry = _pending[(scope, key)];
        _pending[(scope, key)] = (entry.Hash, new IdempotentResult(completion.ResponseStatus, completion.ResponseBody));
    }

    internal void AddPendingOutbox(OutboxMessage message) => _pendingOutbox.Add(message);

    internal void AddPendingAudit(AuditEntry entry)
    {
        if (Audit.FailOnAppend)
        {
            throw new InvalidOperationException("audit writer fault injection");
        }

        _pendingAudit.Add(entry);
    }

    private sealed class InMemoryTransactionExecutor(InMemoryPersistenceFixture fixture) : ITransactionExecutor
    {
        public async Task<TResult> ExecuteAsync<TResult>(Func<Task<TResult>> work, CancellationToken cancellationToken = default)
        {
            fixture.Begin();
            try
            {
                var result = await work().ConfigureAwait(false);
                fixture.Commit();
                return result;
            }
            catch
            {
                fixture.Rollback();
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

    internal sealed class InMemoryIdempotencyStore(InMemoryPersistenceFixture fixture) : IIdempotencyStore
    {
        public Task<IdempotencyRecord> ReserveAsync(
            IdempotencyKey key,
            IdempotencyReservation reservation,
            CancellationToken cancellationToken = default)
        {
            if (fixture.TryFind(key.CallerScope, key.Key, out var hash, out var result))
            {
                if (!string.Equals(hash, reservation.RequestHash, StringComparison.Ordinal))
                {
                    throw new IdempotencyKeyReusedException();
                }

                return Task.FromResult(new IdempotencyRecord(
                    new IdempotencyRequestId(Uuid7.New()), IdempotencyOutcome.Replayed, result));
            }

            fixture.AddPending(key.CallerScope, key.Key, reservation.RequestHash);
            return Task.FromResult(new IdempotencyRecord(
                new IdempotencyRequestId(Uuid7.New()), IdempotencyOutcome.Accepted, null));
        }

        public Task CompleteAsync(
            IdempotencyRequestId id,
            IdempotencyCompletion completion,
            CancellationToken cancellationToken = default)
        {
            var entry = fixture._pending.Single();
            fixture.CompletePending(entry.Key.Scope, entry.Key.Key, completion);
            return Task.CompletedTask;
        }
    }

    internal sealed class InMemoryOutboxWriter(InMemoryPersistenceFixture fixture) : IOutboxWriter
    {
        public Task AppendAsync(OutboxMessage message, CancellationToken cancellationToken = default)
        {
            fixture.AddPendingOutbox(message);
            return Task.CompletedTask;
        }
    }

    internal sealed class InMemoryAuditWriter(InMemoryPersistenceFixture fixture) : IAuditWriter
    {
        public bool FailOnAppend { get; set; }

        public Task<Guid> AppendAsync(AuditEntry entry, CancellationToken cancellationToken = default)
        {
            fixture.AddPendingAudit(entry);
            return Task.FromResult(Uuid7.New());
        }
    }
}
