using KUserCenter.Common.Errors;

namespace KUserCenter.Common.Idempotency;

/// <summary>
/// 同幂等键被用于不同规范化请求摘要（409 IDEMPOTENCY_KEY_REUSED，见错误码注册表）。
/// 不回显占用主体与既有请求内容，防枚举。
/// </summary>
public sealed class IdempotencyKeyReusedException : DomainException
{
    public IdempotencyKeyReusedException()
        : base("IDEMPOTENCY_KEY_REUSED", "Idempotency key reused with a different request.", 409)
    {
    }
}
