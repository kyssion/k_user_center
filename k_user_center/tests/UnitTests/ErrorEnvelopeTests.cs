using KUserCenter.Common.Errors;
using Xunit;

namespace KUserCenter.UnitTests;

public class ErrorEnvelopeTests
{
    [Fact]
    public void Envelope_ExposesOnlyStableFields()
    {
        var envelope = new ErrorEnvelope("INTERNAL_ERROR", "Internal error");

        Assert.Equal("INTERNAL_ERROR", envelope.Code);
        Assert.Equal("Internal error", envelope.Message);
        Assert.Null(envelope.TraceId);
    }

    [Fact]
    public void Envelope_AllowsOptionalTraceId()
    {
        var envelope = new ErrorEnvelope("INVALID_REQUEST", "bad request", "trace-1");

        Assert.Equal("trace-1", envelope.TraceId);
    }
}
