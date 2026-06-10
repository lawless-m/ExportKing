using ExportKing.Protocol;
using Xunit;

namespace ExportKing.Tests.Protocol;

public class TextTests
{
    [Fact]
    public void AsciiPassesThrough()
    {
        Assert.Equal("PLAIN ascii 123", DbisamText.Decode("PLAIN ascii 123"u8));
    }

    [Fact]
    public void Cp1252HighBytesDecode()
    {
        // £ (0xA3) and é (0xE9) are Latin-1 identity; ™ (0x99) and € (0x80)
        // are in the bespoke 0x80–0x9F block. None survive an ASCII decode.
        var bytes = new byte[] { 0xA3, 0x35, 0x20, 0xE9, 0x99, 0x80 };
        Assert.Equal("£5 é™€", DbisamText.Decode(bytes));
    }

    [Fact]
    public void ValidUtf8IsKeptAsUtf8()
    {
        // "£" as UTF-8 (C2 A3) must stay one char, not become "Â£" via CP1252.
        var bytes = new byte[] { 0xC2, 0xA3 };
        Assert.Equal("£", DbisamText.Decode(bytes));
    }

    [Fact]
    public void EncodeRoundTripsCp1252()
    {
        var bytes = DbisamText.Encode("£5 é™€");
        Assert.Equal(new byte[] { 0xA3, 0x35, 0x20, 0xE9, 0x99, 0x80 }, bytes);
        Assert.Equal("£5 é™€", DbisamText.Decode(bytes));
    }

    [Fact]
    public void EncodeReplacesOutOfPageCharsWithQuestionMark()
    {
        Assert.Equal((byte)'?', DbisamText.Encode("→")[0]);
    }
}
