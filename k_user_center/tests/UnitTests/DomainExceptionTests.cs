using KUserCenter.Common.Errors;
using Xunit;

namespace KUserCenter.UnitTests;

public class DomainExceptionTests
{
    [Fact]
    public void Constructor_CarriesErrorCodeAndStatus()
    {
        var ex = new DomainException("IDEMPOTENCY_KEY_REUSED", "conflict", 409);

        Assert.Equal("IDEMPOTENCY_KEY_REUSED", ex.ErrorCode);
        Assert.Equal(409, ex.HttpStatus);
        Assert.Equal("conflict", ex.Message);
    }

    [Fact]
    public void Constructor_DefaultsToBadRequest()
    {
        var ex = new DomainException("INVALID_REQUEST", "bad request");

        Assert.Equal(400, ex.HttpStatus);
    }
}
