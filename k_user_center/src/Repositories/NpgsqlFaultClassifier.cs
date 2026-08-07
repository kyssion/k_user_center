using KUserCenter.Common.Errors;
using Npgsql;

namespace KUserCenter.Repositories;

/// <summary>
/// Npgsql 异常 → 持久化故障分类（驱动翻译层）：
/// 领域层只见 <see cref="PersistenceFault"/> 与稳定错误码，不直接捕获驱动异常。
/// SQLSTATE 语义依据 PostgreSQL 错误码：23505/23514/23502/40001/40P01。
/// </summary>
public static class NpgsqlFaultClassifier
{
    public static PersistenceFault Classify(Exception exception)
    {
        if (exception is PostgresException postgres)
        {
            return postgres.SqlState switch
            {
                PostgresErrorCodes.UniqueViolation => new PersistenceFault(
                    PersistenceFaultKind.UniqueViolation, postgres.ConstraintName, SqlState: postgres.SqlState),
                PostgresErrorCodes.CheckViolation => new PersistenceFault(
                    PersistenceFaultKind.CheckViolation, postgres.ConstraintName, SqlState: postgres.SqlState),
                PostgresErrorCodes.NotNullViolation => new PersistenceFault(
                    PersistenceFaultKind.NotNullViolation, ColumnName: postgres.ColumnName, SqlState: postgres.SqlState),
                PostgresErrorCodes.SerializationFailure => new PersistenceFault(
                    PersistenceFaultKind.SerializationFailure, SqlState: postgres.SqlState),
                PostgresErrorCodes.DeadlockDetected => new PersistenceFault(
                    PersistenceFaultKind.DeadlockDetected, SqlState: postgres.SqlState),
                _ => new PersistenceFault(PersistenceFaultKind.Unknown, SqlState: postgres.SqlState)
            };
        }

        if (exception is NpgsqlException { InnerException: IOException or TimeoutException })
        {
            return new PersistenceFault(PersistenceFaultKind.ConnectionUnavailable);
        }

        return new PersistenceFault(PersistenceFaultKind.Unknown);
    }
}
