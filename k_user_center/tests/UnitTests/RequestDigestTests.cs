using KUserCenter.Common.Idempotency;
using Xunit;

namespace KUserCenter.UnitTests;

/// <summary>规范化请求摘要：char(64) 小写十六进制、确定性、空输入拒绝。</summary>
public class RequestDigestTests
{
    [Fact]
    public void ComputeSha256Hex_Returns64CharLowercaseHex()
    {
        var digest = RequestDigest.ComputeSha256Hex("{\"name\":\"a\"}");

        Assert.Equal(64, digest.Length);
        Assert.Matches("^[0-9a-f]{64}$", digest);
    }

    [Fact]
    public void ComputeSha256Hex_IsDeterministic()
    {
        Assert.Equal(
            RequestDigest.ComputeSha256Hex("{\"name\":\"a\"}"),
            RequestDigest.ComputeSha256Hex("{\"name\":\"a\"}"));
    }

    [Fact]
    public void ComputeSha256Hex_DifferentInputs_ProduceDifferentDigests()
    {
        Assert.NotEqual(
            RequestDigest.ComputeSha256Hex("{\"name\":\"a\"}"),
            RequestDigest.ComputeSha256Hex("{\"name\":\"b\"}"));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void ComputeSha256Hex_EmptyInput_Throws(string? input) =>
        Assert.ThrowsAny<ArgumentException>(() => RequestDigest.ComputeSha256Hex(input!));
}
