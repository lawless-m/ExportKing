using System.Buffers.Binary;
using ExportKing.Protocol;
using Xunit;

namespace ExportKing.Tests.Protocol;

public class WalkerTests
{
    [Fact]
    public void WalksThreeUnits()
    {
        // 3 units: [4 bytes "wxyz"], [2 bytes "ab"], [0 bytes ""]
        var buf = new List<byte>();
        AppendLength(buf, 4);
        buf.AddRange("wxyz"u8.ToArray());
        AppendLength(buf, 2);
        buf.AddRange("ab"u8.ToArray());
        AppendLength(buf, 0);

        var w = new Walker(buf.ToArray());

        var u1 = w.NextUnit();
        Assert.NotNull(u1);
        Assert.Equal("wxyz"u8.ToArray(), u1!.Value.ToArray());

        var u2 = w.NextUnit();
        Assert.NotNull(u2);
        Assert.Equal("ab"u8.ToArray(), u2!.Value.ToArray());

        var u3 = w.NextUnit();
        Assert.NotNull(u3);
        Assert.Equal(Array.Empty<byte>(), u3!.Value.ToArray());

        Assert.Null(w.NextUnit());
    }

    [Fact]
    public void ErrorsOnOverrun()
    {
        // Length says 10 but only 2 bytes follow.
        var buf = new List<byte>();
        AppendLength(buf, 10);
        buf.AddRange("ab"u8.ToArray());

        var w = new Walker(buf.ToArray());
        Assert.Throws<IOException>(() => w.NextUnit());
    }

    [Fact]
    public void EmptyBufReturnsNull()
    {
        var w = new Walker(Array.Empty<byte>());
        Assert.Null(w.NextUnit());
    }

    [Fact]
    public void StartsAtOffset()
    {
        var buf = new List<byte> { 0xAA, 0xBB, 0xCC };
        AppendLength(buf, 3);
        buf.AddRange("foo"u8.ToArray());

        var w = new Walker(buf.ToArray(), start: 3);
        var unit = w.NextUnit();
        Assert.NotNull(unit);
        Assert.Equal("foo"u8.ToArray(), unit!.Value.ToArray());
    }

    [Fact]
    public void NextNReadsExactlyN()
    {
        var buf = new List<byte>();
        AppendLength(buf, 1);
        buf.Add(0xAA);
        AppendLength(buf, 1);
        buf.Add(0xBB);
        AppendLength(buf, 1);
        buf.Add(0xCC);

        var w = new Walker(buf.ToArray());
        var units = w.NextN(2);
        Assert.Equal(2, units.Count);
        Assert.Equal(new byte[] { 0xAA }, units[0].ToArray());
        Assert.Equal(new byte[] { 0xBB }, units[1].ToArray());
    }

    [Fact]
    public void NextNThrowsIfFewerUnitsAvailable()
    {
        var buf = new List<byte>();
        AppendLength(buf, 1);
        buf.Add(0xAA);

        var w = new Walker(buf.ToArray());
        Assert.Throws<IOException>(() => w.NextN(3));
    }

    [Fact]
    public void SeekRewindsForReplay()
    {
        var buf = new List<byte>();
        AppendLength(buf, 2);
        buf.AddRange(new byte[] { 0xAA, 0xBB });
        AppendLength(buf, 2);
        buf.AddRange(new byte[] { 0xCC, 0xDD });

        var w = new Walker(buf.ToArray());
        int saved = w.Position;
        var first = w.NextUnit()!.Value.ToArray();
        Assert.Equal(new byte[] { 0xAA, 0xBB }, first);

        w.Seek(saved);
        var firstAgain = w.NextUnit()!.Value.ToArray();
        Assert.Equal(first, firstAgain);
    }

    [Fact]
    public void HugeLengthPrefixThrowsIOException()
    {
        // A length >= 2^31 must surface as IOException (malformed wire), not
        // slip past the overrun check via a negative int cast.
        var buf = new List<byte>();
        AppendLength(buf, 0xFFFFFFFF);
        buf.AddRange(new byte[] { 0x01, 0x02 });

        var w = new Walker(buf.ToArray());
        Assert.Throws<IOException>(() => w.NextUnit());
    }

    private static void AppendLength(List<byte> buf, uint length)
    {
        Span<byte> tmp = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32LittleEndian(tmp, length);
        buf.AddRange(tmp.ToArray());
    }
}
