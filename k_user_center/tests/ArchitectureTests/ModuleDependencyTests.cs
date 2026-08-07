using NetArchTest.Rules;
using Xunit;

namespace KUserCenter.ArchitectureTests;

/// <summary>
/// 分层依赖测试：按经典分层（Common/Middleware/Models/Services/Repositories）阻断违规依赖。
/// 单程序集布局下按命名空间校验依赖方向（生产源码命名空间，排除测试命名空间）。
/// </summary>
public class ModuleDependencyTests
{
    private static PredicateList ProductionTypes() =>
        Types.InAssembly(typeof(KUserCenter.Common.Time.SystemClock).Assembly)
            .That().ResideInNamespace("KUserCenter")
            .And().DoNotResideInNamespace("KUserCenter.UnitTests")
            .And().DoNotResideInNamespace("KUserCenter.ArchitectureTests")
            .And().DoNotResideInNamespace("KUserCenter.IntegrationTests");

    private static void AssertNoDependency(string scopeNamespace, string dependency, string message)
    {
        var result = ProductionTypes()
            .And().ResideInNamespace(scopeNamespace)
            .Should().NotHaveDependencyOn(dependency)
            .GetResult();
        Assert.True(result.IsSuccessful, message);
    }

    [Fact]
    public void Common_ShouldNotReference_OrmOrWeb()
    {
        AssertNoDependency("KUserCenter.Common", "SqlSugar", "Common 禁止 SqlSugar");
        AssertNoDependency("KUserCenter.Common", "Npgsql", "Common 禁止 Npgsql");
        AssertNoDependency("KUserCenter.Common", "Microsoft.AspNetCore", "Common 禁止 ASP.NET Core");
        AssertNoDependency("KUserCenter.Common", "KUserCenter.Services", "Common 禁止依赖业务层");
        AssertNoDependency("KUserCenter.Common", "KUserCenter.Repositories", "Common 禁止依赖数据访问层");
    }

    [Fact]
    public void Models_ShouldNotReference_SqlSugar() =>
        AssertNoDependency("KUserCenter.Models", "SqlSugar", "Models 不得引用 SqlSugar（禁 ORM Entity）");

    [Fact]
    public void Models_ShouldNotReference_Npgsql() =>
        AssertNoDependency("KUserCenter.Models", "Npgsql", "Models 不得引用 Npgsql");

    [Fact]
    public void Models_ShouldNotReference_AspNetCore() =>
        AssertNoDependency("KUserCenter.Models", "Microsoft.AspNetCore", "Models 不得引用 ASP.NET Core");

    [Fact]
    public void Models_ShouldNotReference_ServicesOrRepositories()
    {
        AssertNoDependency("KUserCenter.Models", "KUserCenter.Services", "Models 不得依赖 Services");
        AssertNoDependency("KUserCenter.Models", "KUserCenter.Repositories", "Models 不得依赖 Repositories（仓储端口在 Models 定义）");
    }

    [Fact]
    public void Services_ShouldNotReference_SqlSugarOrNpgsql()
    {
        AssertNoDependency("KUserCenter.Services", "SqlSugar", "Services 不得引用具体 SqlSugar API");
        AssertNoDependency("KUserCenter.Services", "Npgsql", "Services 不得引用具体 Npgsql API");
    }

    [Fact]
    public void Services_ShouldNotReference_AspNetCoreOrRepositories()
    {
        AssertNoDependency("KUserCenter.Services", "Microsoft.AspNetCore", "Services 不得引用 ASP.NET Core");
        AssertNoDependency("KUserCenter.Services", "KUserCenter.Repositories", "Services 只能经仓储接口访问数据，不得依赖 Repositories 实现");
    }

    [Fact]
    public void Repositories_ShouldNotReference_Services() =>
        AssertNoDependency("KUserCenter.Repositories", "KUserCenter.Services", "Repositories 不得反向依赖 Services");

    [Fact]
    public void Middleware_ShouldOnlyDependOn_Common()
    {
        AssertNoDependency("KUserCenter.Middleware", "SqlSugar", "Middleware 禁止 SqlSugar");
        AssertNoDependency("KUserCenter.Middleware", "KUserCenter.Services", "Middleware 禁止依赖 Services");
        AssertNoDependency("KUserCenter.Middleware", "KUserCenter.Repositories", "Middleware 禁止依赖 Repositories");
    }
}
