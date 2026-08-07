using KUserCenter.Common.Time;
using KUserCenter.Middleware;
using KUserCenter.Repositories;

var builder = WebApplication.CreateBuilder(args);

// 可信时钟：业务代码经 ISystemClock 获取 UTC 时间，禁止直接使用系统时钟
builder.Services.AddSingleton<ISystemClock, SystemClock>();

// 持久化基座：连接串只从环境变量/User Secrets 注入；Host liveness 不依赖 PostgreSQL
builder.Services.AddSqlSugarPersistence(builder.Configuration);

builder.Services.AddHealthChecks();
builder.Services.AddOpenApi();

var app = builder.Build();

app.UseMiddleware<ExceptionHandlingMiddleware>();

if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
}

// 阶段 0 首批健康检查：live 不访问任何依赖；ready 暂为进程级就绪
app.MapHealthChecks("/health/live");
app.MapHealthChecks("/health/ready");

app.Run();

/// <summary>供集成测试（WebApplicationFactory）引用的程序入口标记。</summary>
public partial class Program;
