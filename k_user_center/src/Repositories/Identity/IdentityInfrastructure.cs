namespace KUserCenter.Repositories.Identity;

/// <summary>
/// Identity 域数据访问层（阶段 0 骨架）：该域端口适配器与唯一组合入口。
/// SqlSugar Entity 只存在于本层（不等于领域实体）；显式映射 iam Schema。
/// 跨域禁止直接引用本层实现；数据库实跑验证前不落地生产仓储。
/// </summary>
public static class IdentityInfrastructure
{
    /// <summary>域码，与 Models/Services 保持一致。</summary>
    public const string DomainCode = "ID";
}
