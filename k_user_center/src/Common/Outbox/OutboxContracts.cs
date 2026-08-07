using KUserCenter.Common.Ids;

namespace KUserCenter.Common.Outbox;

/// <summary>
/// 领域 Outbox 事件信封（对应 iam.outbox_events 核心独立列）：
/// 核心信封字段不得使用 headers 隐藏或覆盖；payload 由命令代码按事件 Schema
/// 生成并禁止敏感明文；对外 Subject 改写在投递前由 EVENT 代码执行。
/// </summary>
public sealed record OutboxMessage
{
    public required Guid EventId { get; init; } = Uuid7.New();
    public required string EventType { get; init; }
    public required int SchemaVersion { get; init; }
    public required string AggregateType { get; init; }
    public required Guid AggregateId { get; init; }
    public long? AggregateVersion { get; init; }
    public Guid? TenantId { get; init; }
    public Guid? BusinessLineId { get; init; }
    public required string ProducerType { get; init; }
    public required Guid ProducerId { get; init; }
    public required string SubjectRefType { get; init; }
    public required string SubjectRefId { get; init; }
    public string? ActorType { get; init; }
    public string? ActorIdType { get; init; }
    public string? ActorId { get; init; }
    public required DateTimeOffset OccurredAt { get; init; }
    public long? DataVersion { get; init; }
    public required string TraceId { get; init; }
    public string? CorrelationId { get; init; }
    public string? CausationId { get; init; }
    public required string DataClassification { get; init; }
    public required string PayloadJson { get; init; }
    public string HeadersJson { get; init; } = "{}";
}

/// <summary>
/// 领域 Outbox 写入端口：必须在调用方当前数据库事务内追加，
/// 与权威事实、本地审计、审计投递 Outbox、幂等结果同事务提交；
/// 事件生成、投递、补偿和重试语义不属于本端口。
/// </summary>
public interface IOutboxWriter
{
    Task AppendAsync(OutboxMessage message, CancellationToken cancellationToken = default);
}
