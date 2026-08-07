namespace KUserCenter.Services.Identity;

/// <summary>
/// Identity 域业务服务层（阶段 0 骨架）：承载用例编排、权限/作用域入口与事务边界。
/// 命令处理器是事务入口；禁止直接调用 SqlSugar/Npgsql API 或跨域改表。
/// 用例在命令规格卡（绑定需求/权限/事务/事件/测试）批准后才允许落地。
/// </summary>
public static class IdentityApplication
{
    /// <summary>域码，与 Models 保持一致。</summary>
    public const string DomainCode = "ID";
}
