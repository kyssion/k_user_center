namespace KUserCenter.Repositories;

/// <summary>
/// SqlSugar/Npgsql 持久化配置。连接串只允许从环境变量或 User Secrets 注入，
/// 禁止写入仓库文件；Schema 与 Migration 权威在 database/postgresql，此处不做任何自动建表。
/// </summary>
public sealed class SqlSugarPersistenceOptions
{
    public const string SectionName = "Persistence:SqlSugar";

    /// <summary>PostgreSQL 连接串（仅环境变量/User Secrets 注入）。</summary>
    public string ConnectionString { get; init; } = string.Empty;

    /// <summary>显式映射的业务 Schema，默认 iam。</summary>
    public string Schema { get; init; } = "iam";

    /// <summary>SQL 日志默认关闭；开启时只记录模板、耗时和参数数量，不记录参数值。</summary>
    public bool EnableSqlLogging { get; init; }
}
