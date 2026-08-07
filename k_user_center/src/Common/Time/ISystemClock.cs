namespace KUserCenter.Common.Time;

/// <summary>可信时钟抽象：业务代码禁止直接使用系统时钟，统一经此端口获取 UTC 时间。</summary>
public interface ISystemClock
{
    DateTimeOffset UtcNow { get; }
}
