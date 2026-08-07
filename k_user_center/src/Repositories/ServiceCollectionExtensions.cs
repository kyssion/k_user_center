using KUserCenter.Common.Audit;
using KUserCenter.Common.Errors;
using KUserCenter.Common.Idempotency;
using KUserCenter.Common.Outbox;
using KUserCenter.Common.Transactions;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using SqlSugar;

namespace KUserCenter.Repositories;

/// <summary>
/// 持久化基座注册入口：scoped Client + 事务执行器 + 幂等/Outbox/审计端口与错误映射；
/// 禁止 CodeFirst 与运行时 Schema 同步。
/// </summary>
public static class ServiceCollectionExtensions
{
    public static IServiceCollection AddSqlSugarPersistence(this IServiceCollection services, IConfiguration configuration)
    {
        services.AddOptions<SqlSugarPersistenceOptions>()
            .Bind(configuration.GetSection(SqlSugarPersistenceOptions.SectionName));

        services.AddScoped<SqlSugarClientFactory>();
        services.AddScoped<ISqlSugarClient>(sp => sp.GetRequiredService<SqlSugarClientFactory>().CreateScopedClient());
        services.AddScoped<ITransactionExecutor, SqlSugarTransactionExecutor>();

        // 唯一冲突按约束名映射稳定领域码；未登记约束回落 INTERNAL_CONSTRAINT_VIOLATION。
        services.AddSingleton(new PersistenceErrorTranslator(
            new Dictionary<string, ConstraintErrorMapping>
            {
                ["uq_idempotency_caller_key"] = new("IDEMPOTENCY_KEY_REUSED", 409),
                ["uq_operations_caller_key"] = new("IDEMPOTENCY_KEY_REUSED", 409)
            }));

        services.AddScoped<IIdempotencyStore, SqlSugarIdempotencyStore>();
        services.AddScoped<IOutboxWriter, SqlSugarOutboxWriter>();
        services.AddScoped<IAuditWriter, SqlSugarAuditWriter>();
        services.AddScoped<TransactionalCommandRunner>();

        return services;
    }
}
