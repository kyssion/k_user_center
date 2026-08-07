namespace KUserCenter.Common.Time;

/// <summary>默认 UTC 时钟实现，只返回 UTC 时区时间。</summary>
public sealed class SystemClock : ISystemClock
{
    public static readonly SystemClock Instance = new();

    public DateTimeOffset UtcNow => DateTimeOffset.UtcNow;
}
