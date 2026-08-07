using KUserCenter.Common.Ids;

namespace KUserCenter.Models.Identity.Users;

/// <summary>全局用户主体标识（值对象）：UUIDv7，禁止随机 UUIDv4 与可枚举序号。</summary>
public readonly record struct UserAccountId(Guid Value)
{
    public static UserAccountId New() => new(Uuid7.New());

    public override string ToString() => Value.ToString();
}
