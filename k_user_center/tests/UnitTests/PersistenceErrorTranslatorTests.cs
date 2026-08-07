using KUserCenter.Common.Errors;
using Xunit;

namespace KUserCenter.UnitTests;

/// <summary>持久化故障 → 稳定错误码映射（错误码均来自注册表）。</summary>
public class PersistenceErrorTranslatorTests
{
    private static PersistenceErrorTranslator NewTranslator() => new(
        new Dictionary<string, ConstraintErrorMapping>
        {
            ["uq_idempotency_caller_key"] = new("IDEMPOTENCY_KEY_REUSED", 409)
        });

    [Fact]
    public void UniqueViolation_KnownConstraint_MapsRegisteredDomainCode()
    {
        var ex = NewTranslator().Translate(new PersistenceFault(
            PersistenceFaultKind.UniqueViolation, "uq_idempotency_caller_key"));

        Assert.Equal("IDEMPOTENCY_KEY_REUSED", ex.ErrorCode);
        Assert.Equal(409, ex.HttpStatus);
    }

    [Fact]
    public void UniqueViolation_UnknownConstraint_MapsInternalConstraintViolation()
    {
        var ex = NewTranslator().Translate(new PersistenceFault(
            PersistenceFaultKind.UniqueViolation, "uq_unknown"));

        Assert.Equal("INTERNAL_CONSTRAINT_VIOLATION", ex.ErrorCode);
        Assert.Equal(500, ex.HttpStatus);
    }

    [Theory]
    [InlineData(PersistenceFaultKind.CheckViolation)]
    [InlineData(PersistenceFaultKind.NotNullViolation)]
    public void RowShapeViolation_MapsInternalConstraintViolation(PersistenceFaultKind kind)
    {
        var ex = NewTranslator().Translate(new PersistenceFault(kind));

        Assert.Equal("INTERNAL_CONSTRAINT_VIOLATION", ex.ErrorCode);
    }

    [Theory]
    [InlineData(PersistenceFaultKind.SerializationFailure)]
    [InlineData(PersistenceFaultKind.DeadlockDetected)]
    [InlineData(PersistenceFaultKind.ConnectionUnavailable)]
    public void TransientAndAvailabilityFaults_FailClosedWithDependencyUnavailable(PersistenceFaultKind kind)
    {
        var fault = new PersistenceFault(kind);
        var ex = NewTranslator().Translate(fault);

        Assert.Equal("DEPENDENCY_UNAVAILABLE", ex.ErrorCode);
        Assert.Equal(503, ex.HttpStatus);
        Assert.True(fault.IsRetryable || kind == PersistenceFaultKind.ConnectionUnavailable);
    }

    [Fact]
    public void UnknownFault_MapsInternalError()
    {
        var ex = NewTranslator().Translate(new PersistenceFault(PersistenceFaultKind.Unknown));

        Assert.Equal("INTERNAL_ERROR", ex.ErrorCode);
        Assert.Equal(500, ex.HttpStatus);
    }

    [Fact]
    public void OnlySerializationAndDeadlock_AreAutoRetryable()
    {
        Assert.True(new PersistenceFault(PersistenceFaultKind.SerializationFailure).IsRetryable);
        Assert.True(new PersistenceFault(PersistenceFaultKind.DeadlockDetected).IsRetryable);
        Assert.False(new PersistenceFault(PersistenceFaultKind.UniqueViolation).IsRetryable);
        Assert.False(new PersistenceFault(PersistenceFaultKind.ConnectionUnavailable).IsRetryable);
    }
}
