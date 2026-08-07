namespace KUserCenter.Common.Ids;

/// <summary>
/// UUIDv7（RFC 9562）生成入口：所有新建主键使用带时间前缀的 UUIDv7，
/// 保证索引友好与时间有序；禁止使用不可枚举的随机 UUIDv4 作为对外主键。
/// </summary>
public static class Uuid7
{
    public static Guid New() => Guid.CreateVersion7();
}
