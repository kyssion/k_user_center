namespace KUserCenter.Models.Identity;

/// <summary>
/// Identity 域对外契约边界（阶段 0 骨架）：
/// 命令、查询和事件契约在 Models 层定义，供 Controllers/Services 引用；
/// 禁止出现 Repository、ORM Entity 或内部领域对象。
/// 生产命令必须先在实施追踪矩阵与命令规格卡登记，再进入本层。
/// </summary>
public static class IdentityContracts
{
    /// <summary>域码，用于一域一域码校验。</summary>
    public const string DomainCode = "ID";
}
