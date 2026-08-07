namespace KUserCenter.Common.Errors;

/// <summary>
/// 领域异常基类：携带已登记的稳定错误码（见 docs/代码实施/错误码注册表.csv）。
/// Host 错误中间件负责把错误码映射为 HTTP 状态与稳定错误信封；
/// 禁止在领域内直接抛出携带敏感细节的异常。
/// </summary>
public class DomainException : Exception
{
    public DomainException(string errorCode, string message, int httpStatus = 400)
        : base(message)
    {
        ErrorCode = errorCode;
        HttpStatus = httpStatus;
    }

    /// <summary>注册表中登记的稳定错误码，例如 IDEMPOTENCY_KEY_REUSED。</summary>
    public string ErrorCode { get; }

    /// <summary>错误码对应的 HTTP 状态，来源为错误码注册表。</summary>
    public int HttpStatus { get; }
}
