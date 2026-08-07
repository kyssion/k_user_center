using KUserCenter.Common.Concurrency;
using Xunit;

namespace KUserCenter.UnitTests;

/// <summary>CAS 守卫：0 行受影响必须映射稳定错误码，不得盲目覆盖。</summary>
public class CasGuardTests
{
    [Fact]
    public void ZeroRows_ThrowsVersionMismatch()
    {
        var ex = Assert.Throws<VersionMismatchException>(() => CasGuard.EnsureApplied(0));

        Assert.Equal("VERSION_MISMATCH", ex.ErrorCode);
        Assert.Equal(412, ex.HttpStatus);
    }

    [Fact]
    public void PositiveRows_DoNotThrow() => CasGuard.EnsureApplied(1);

    [Fact]
    public void ZeroRows_StateMismatch_ThrowsInvalidStateTransition()
    {
        var ex = Assert.Throws<InvalidStateTransitionException>(
            () => CasGuard.EnsureApplied(0, preconditionStateMatched: false));

        Assert.Equal("INVALID_STATE_TRANSITION", ex.ErrorCode);
        Assert.Equal(409, ex.HttpStatus);
    }

    [Fact]
    public void ZeroRows_StateMatched_ThrowsVersionMismatch()
    {
        var ex = Assert.Throws<VersionMismatchException>(
            () => CasGuard.EnsureApplied(0, preconditionStateMatched: true));

        Assert.Equal("VERSION_MISMATCH", ex.ErrorCode);
    }
}
