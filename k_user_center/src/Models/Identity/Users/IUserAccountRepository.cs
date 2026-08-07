namespace KUserCenter.Models.Identity.Users;

/// <summary>
/// 用户账户仓储端口（阶段 0 骨架）：领域层只定义端口，不依赖 ORM；
/// 适配器只存在于 Repositories 层。真实方法面在命令规格卡批准后扩展。
/// </summary>
public interface IUserAccountRepository
{
    Task<bool> ExistsAsync(UserAccountId id, CancellationToken cancellationToken = default);
}
