using KUserCenter.Common.Errors;

namespace KUserCenter.Common.Concurrency;

/// <summary>
/// expected version 不一致（412 VERSION_MISMATCH，见错误码注册表）。
/// CAS 受影响行数为 0 时必须抛出本异常，不得盲目覆盖；
/// 是否重读重试由命令代码按“无外部副作用”条件判断。
/// </summary>
public sealed class VersionMismatchException : DomainException
{
    public VersionMismatchException(string message = "Expected version does not match the current row version.")
        : base("VERSION_MISMATCH", message, 412)
    {
    }
}

/// <summary>
/// 状态转换不合法（409 INVALID_STATE_TRANSITION，见错误码注册表）：
/// CAS 同时匹配状态与 expected version，前态不满足时抛出本异常。
/// </summary>
public sealed class InvalidStateTransitionException : DomainException
{
    public InvalidStateTransitionException(string message = "Current state does not allow this command.")
        : base("INVALID_STATE_TRANSITION", message, 409)
    {
    }
}

/// <summary>
/// CAS 守卫：仓储条件更新（WHERE id=@id AND row_version=@expected 且含合法前态）
/// 返回受影响行数后统一经本守卫映射稳定错误；
/// 更新 SQL 必须显式设置 row_version = row_version + 1, updated_at = CURRENT_TIMESTAMP。
/// </summary>
public static class CasGuard
{
    /// <summary>0 行受影响 → VERSION_MISMATCH；不得静默忽略。</summary>
    public static void EnsureApplied(int affectedRows)
    {
        if (affectedRows <= 0)
        {
            throw new VersionMismatchException();
        }
    }

    /// <summary>
    /// 区分前态与版本的 CAS 结论：条件同时含状态与 expected version 时使用，
    /// 由调用方传入读到的当前状态是否匹配，以便映射准确的稳定错误码。
    /// </summary>
    public static void EnsureApplied(int affectedRows, bool preconditionStateMatched)
    {
        if (affectedRows > 0)
        {
            return;
        }

        throw preconditionStateMatched
            ? new VersionMismatchException()
            : new InvalidStateTransitionException();
    }
}
