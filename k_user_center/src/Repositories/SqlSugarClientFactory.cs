using Microsoft.Extensions.Options;
using SqlSugar;

namespace KUserCenter.Repositories;

/// <summary>
/// scoped SqlSugar Client 工厂：每个 HTTP 请求、消息消费或 Worker 命令作用域创建一个 Client；
/// Npgsql 负责物理连接池，同一 Client 不并行执行。显式 PostgreSQL 类型，不依赖自动命名推断。
/// </summary>
public sealed class SqlSugarClientFactory
{
    private readonly SqlSugarPersistenceOptions _options;

    public SqlSugarClientFactory(IOptions<SqlSugarPersistenceOptions> options)
    {
        _options = options.Value;
    }

    public ISqlSugarClient CreateScopedClient()
    {
        if (string.IsNullOrWhiteSpace(_options.ConnectionString))
        {
            throw new InvalidOperationException(
                "PostgreSQL 连接串未配置；只允许从环境变量或 User Secrets 注入。");
        }

        return new SqlSugarClient(new ConnectionConfig
        {
            ConnectionString = _options.ConnectionString,
            DbType = DbType.PostgreSQL,
            IsAutoCloseConnection = true,
            ConfigureExternalServices = new ConfigureExternalServices()
        });
    }
}
