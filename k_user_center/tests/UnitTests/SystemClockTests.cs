using KUserCenter.Common.Time;
using Xunit;

namespace KUserCenter.UnitTests;

public class SystemClockTests
{
    [Fact]
    public void UtcNow_AlwaysReturnsUtcOffset()
    {
        ISystemClock clock = SystemClock.Instance;

        Assert.Equal(TimeSpan.Zero, clock.UtcNow.Offset);
    }
}
