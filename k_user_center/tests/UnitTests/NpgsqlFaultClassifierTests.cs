using KUserCenter.Common.Errors;
using KUserCenter.Repositories;
using Npgsql;
using Xunit;

namespace KUserCenter.UnitTests;

/// <summary>Npgsql 驱动异常 → 持久化故障分类（SQLSTATE 语义：23505/23514/23502/40001/40P01）。</summary>
public class NpgsqlFaultClassifierTests
{
    private static PostgresException NewPostgresException(
        string sqlState,
        string? constraintName = null,
        string? columnName = null) =>
        new("database error", "ERROR", "ERROR", sqlState,
            columnName: columnName,
            constraintName: constraintName);

    [Fact]
    public void UniqueViolation_ClassifiedWithConstraintName()
    {
        var fault = NpgsqlFaultClassifier.Classify(
            NewPostgresException(PostgresErrorCodes.UniqueViolation, constraintName: "uq_idempotency_caller_key"));

        Assert.Equal(PersistenceFaultKind.UniqueViolation, fault.Kind);
        Assert.Equal("uq_idempotency_caller_key", fault.ConstraintName);
        Assert.Equal(PostgresErrorCodes.UniqueViolation, fault.SqlState);
    }

    [Fact]
    public void CheckViolation_ClassifiedWithConstraintName()
    {
        var fault = NpgsqlFaultClassifier.Classify(
            NewPostgresException(PostgresErrorCodes.CheckViolation, constraintName: "ck_probe"));

        Assert.Equal(PersistenceFaultKind.CheckViolation, fault.Kind);
        Assert.Equal("ck_probe", fault.ConstraintName);
    }

    [Fact]
    public void NotNullViolation_ClassifiedWithColumnName()
    {
        var fault = NpgsqlFaultClassifier.Classify(
            NewPostgresException(PostgresErrorCodes.NotNullViolation, columnName: "event_type"));

        Assert.Equal(PersistenceFaultKind.NotNullViolation, fault.Kind);
        Assert.Equal("event_type", fault.ColumnName);
        Assert.Null(fault.ConstraintName);
    }

    [Theory]
    [InlineData(PostgresErrorCodes.SerializationFailure, PersistenceFaultKind.SerializationFailure)]
    [InlineData(PostgresErrorCodes.DeadlockDetected, PersistenceFaultKind.DeadlockDetected)]
    public void TransientFailures_AreClassifiedRetryable(string sqlState, PersistenceFaultKind expected)
    {
        var fault = NpgsqlFaultClassifier.Classify(NewPostgresException(sqlState));

        Assert.Equal(expected, fault.Kind);
        Assert.True(fault.IsRetryable);
    }

    [Fact]
    public void UnknownSqlState_ClassifiedUnknown()
    {
        var fault = NpgsqlFaultClassifier.Classify(NewPostgresException("99999"));

        Assert.Equal(PersistenceFaultKind.Unknown, fault.Kind);
        Assert.Equal("99999", fault.SqlState);
        Assert.False(fault.IsRetryable);
    }

    [Fact]
    public void ConnectionFailure_IOWrapped_ClassifiedConnectionUnavailable()
    {
        var fault = NpgsqlFaultClassifier.Classify(
            new TestNpgsqlException("connection reset", new IOException("socket closed")));

        Assert.Equal(PersistenceFaultKind.ConnectionUnavailable, fault.Kind);
    }

    [Fact]
    public void NonDriverException_ClassifiedUnknown()
    {
        var fault = NpgsqlFaultClassifier.Classify(new InvalidOperationException("not a driver fault"));

        Assert.Equal(PersistenceFaultKind.Unknown, fault.Kind);
    }

    private sealed class TestNpgsqlException(string message, Exception innerException)
        : NpgsqlException(message, innerException);
}
