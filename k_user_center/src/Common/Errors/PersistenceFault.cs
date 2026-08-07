namespace KUserCenter.Common.Errors;

/// <summary>持久化故障类别：与具体数据库驱动无关的稳定分类。</summary>
public enum PersistenceFaultKind
{
    /// <summary>唯一键被占用（23505）；按约束名映射稳定领域码。</summary>
    UniqueViolation,

    /// <summary>基础 Check 失败（23514）；记录约束名，返回稳定内部错误。</summary>
    CheckViolation,

    /// <summary>NOT NULL 失败（23502）；记录字段名，返回稳定内部错误。</summary>
    NotNullViolation,

    /// <summary>序列化失败（40001）；可自动重试（无外部副作用时）。</summary>
    SerializationFailure,

    /// <summary>死锁（40P01）；可自动重试（无外部副作用时）。</summary>
    DeadlockDetected,

    /// <summary>连接不可用；安全敏感操作失败关闭，不得用陈旧状态继续写入。</summary>
    ConnectionUnavailable,

    /// <summary>无法识别的基础异常。</summary>
    Unknown
}

/// <summary>
/// 持久化故障描述：驱动适配器（Repositories 层）把数据库异常翻译为本分类，
/// Common 层再映射为稳定错误码；禁止在领域层直接捕获驱动异常。
/// </summary>
public sealed record PersistenceFault(
    PersistenceFaultKind Kind,
    string? ConstraintName = null,
    string? ColumnName = null,
    string? SqlState = null)
{
    /// <summary>序列化失败与死锁是唯一允许自动重试的故障（且须无外部副作用）。</summary>
    public bool IsRetryable => Kind is PersistenceFaultKind.SerializationFailure or PersistenceFaultKind.DeadlockDetected;
}
