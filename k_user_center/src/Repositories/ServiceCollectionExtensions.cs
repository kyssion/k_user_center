using KUserCenter.Common.Transactions;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using SqlSugar;

namespace KUserCenter.Repositories;

/// <summary>持久化基座注册入口：scoped Client + 事务执行器；禁止 CodeFirst 与运行时 Schema 同步。</summary>
public static class ServiceCollectionExtensions
{
    public static IServiceCollection AddSqlSugarPersistence(this IServiceCollection services, IConfiguration configuration)
    {
        services.AddOptions<SqlSugarPersistenceOptions>()
            .Bind(configuration.GetSection(SqlSugarPersistenceOptions.SectionName));

        services.AddScoped<SqlSugarClientFactory>();
        services.AddScoped<ISqlSugarClient>(sp => sp.GetRequiredService<SqlSugarClientFactory>().CreateScopedClient());
        services.AddScoped<ITransactionExecutor, SqlSugarTransactionExecutor>();

        return services;
    }
}
