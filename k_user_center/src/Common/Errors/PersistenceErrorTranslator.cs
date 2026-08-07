namespace KUserCenter.Common.Errors;

/// <summary>统一错误映射的约束登记：约束名 → 稳定领域错误码与 HTTP 状态。</summary>
public sealed record ConstraintErrorMapping(string ErrorCode, int HttpStatus);

/// <summary>
/// 持久化故障 → 稳定错误码映射（全局持久化与事务规范 §7）：
/// 唯一冲突按约束名映射且不回显占用主体；Check/NOT NULL 与无法识别的故障
/// 映射 INTERNAL_CONSTRAINT_VIOLATION/INTERNAL_ERROR（internal_only，不对外暴露细节）；
/// 可重试故障与连接不可用映射 DEPENDENCY_UNAVAILABLE 并失败关闭。
/// </summary>
public sealed class PersistenceErrorTranslator
{
    private readonly IReadOnlyDictionary<string, ConstraintErrorMapping> _uniqueConstraintMappings;

    public PersistenceErrorTranslator(IReadOnlyDictionary<string, ConstraintErrorMapping> uniqueConstraintMappings)
    {
        _uniqueConstraintMappings = uniqueConstraintMappings;
    }

    public DomainException Translate(PersistenceFault fault)
    {
        return fault.Kind switch
        {
            PersistenceFaultKind.UniqueViolation => TranslateUnique(fault),
            PersistenceFaultKind.CheckViolation or PersistenceFaultKind.NotNullViolation
                => new DomainException("INTERNAL_CONSTRAINT_VIOLATION", "Constraint violation.", 500),
            PersistenceFaultKind.SerializationFailure or PersistenceFaultKind.DeadlockDetected
            or PersistenceFaultKind.ConnectionUnavailable
                => new DomainException("DEPENDENCY_UNAVAILABLE", "Persistence dependency temporarily unavailable.", 503),
            _ => new DomainException("INTERNAL_ERROR", "Internal error", 500)
        };
    }

    private DomainException TranslateUnique(PersistenceFault fault)
    {
        if (fault.ConstraintName is not null
            && _uniqueConstraintMappings.TryGetValue(fault.ConstraintName, out var mapping))
        {
            return new DomainException(mapping.ErrorCode, "Conflict.", mapping.HttpStatus);
        }

        return new DomainException("INTERNAL_CONSTRAINT_VIOLATION", "Constraint violation.", 500);
    }
}
