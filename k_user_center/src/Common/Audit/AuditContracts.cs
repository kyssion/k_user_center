using KUserCenter.Common.Ids;

namespace KUserCenter.Common.Audit;

/// <summary>
/// 本地审计事实（对应 iam.audit_events 不可变追加）：
/// 只允许命令代码 INSERT；before/after 摘要不得包含敏感明文；
/// attributes 白名单与脱敏由命令代码执行。occurred_at 由统一时钟传入。
/// </summary>
public sealed record AuditEntry
{
    public required string Action { get; init; }
    public required string ObjectType { get; init; }
    public Guid? ObjectId { get; init; }
    public required string Outcome { get; init; }
    public string? ReasonCode { get; init; }
    public string? ActorType { get; init; }
    public Guid? ActorId { get; init; }
    public string? SubjectType { get; init; }
    public Guid? SubjectId { get; init; }
    public Guid? TenantId { get; init; }
    public string? BeforeDigest { get; init; }
    public string? AfterDigest { get; init; }
    public Guid? ApprovalCaseId { get; init; }
    public string? TraceId { get; init; }
    public string? AttributesJson { get; init; }
    public required DateTimeOffset OccurredAt { get; init; }
}

/// <summary>
/// 审计写入端口：在调用方当前事务内追加审计事实并返回审计事件 ID；
/// 审计投递 Outbox 复用普通 outbox_events 信封并引用该 audit_event_id，
/// 不另建第二套审计状态机。审计失败必须导致整个命令事务回滚（失败关闭）。
/// </summary>
public interface IAuditWriter
{
    Task<Guid> AppendAsync(AuditEntry entry, CancellationToken cancellationToken = default);
}
