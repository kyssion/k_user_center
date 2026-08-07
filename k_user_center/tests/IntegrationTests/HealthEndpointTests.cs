using System.Net;
using Microsoft.AspNetCore.Mvc.Testing;
using Xunit;

namespace KUserCenter.IntegrationTests;

/// <summary>不访问 PostgreSQL 的 Host liveness/readiness 测试（阶段 0 首批）。</summary>
public class HealthEndpointTests : IClassFixture<WebApplicationFactory<Program>>
{
    private readonly WebApplicationFactory<Program> _factory;

    public HealthEndpointTests(WebApplicationFactory<Program> factory)
    {
        // 单程序集布局下 content root 无法由项目名启发式推断，显式指向当前工作目录
        _factory = factory.WithWebHostBuilder(builder => builder.UseContentRoot(Directory.GetCurrentDirectory()));
    }

    [Fact]
    public async Task HealthLive_ReturnsHealthy()
    {
        var client = _factory.CreateClient();

        var response = await client.GetAsync("/health/live");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task HealthReady_ReturnsHealthy_WithoutDatabase()
    {
        var client = _factory.CreateClient();

        var response = await client.GetAsync("/health/ready");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }
}
