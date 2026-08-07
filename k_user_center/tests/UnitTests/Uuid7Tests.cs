using KUserCenter.Common.Ids;
using Xunit;

namespace KUserCenter.UnitTests;

public class Uuid7Tests
{
    [Fact]
    public void New_ReturnsVersion7Guid()
    {
        var id = Uuid7.New();

        Assert.Equal(7, id.Version);
    }

    [Fact]
    public void New_UsesRfc9562Variant()
    {
        var id = Uuid7.New();

        // RFC 9562 variant：字节 8 最高两位为 10
        Span<byte> bytes = stackalloc byte[16];
        id.TryWriteBytes(bytes, bigEndian: true, out _);
        Assert.Equal(0b10, bytes[8] >> 6);
    }

    [Fact]
    public void New_GeneratesUniqueValues()
    {
        var ids = new HashSet<Guid>();
        for (var i = 0; i < 10_000; i++)
        {
            Assert.True(ids.Add(Uuid7.New()), "duplicate UUIDv7 detected");
        }
    }

    [Fact]
    public void New_TimestampPrefixApproximatesCurrentTime()
    {
        var before = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        var id = Uuid7.New();
        var after = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

        Span<byte> bytes = stackalloc byte[16];
        id.TryWriteBytes(bytes, bigEndian: true, out _);
        long timestamp = (long)bytes[0] << 40 | (long)bytes[1] << 32 | (long)bytes[2] << 24
            | (long)bytes[3] << 16 | (long)bytes[4] << 8 | bytes[5];

        Assert.InRange(timestamp, before, after);
    }
}
