using ExportKing.Protocol;
using Xunit;

namespace ExportKing.Tests.Protocol;

public class OpenBlobMatchesCaptureTest
{
    /// <summary>
    /// Byte-for-byte equality with the captured DBSYS OpenBlob request from
    /// Derek/dbisam-capture-memo.pcapng (msg #9). Inputs:
    ///   cursor_handle=1, col_ord=5, PK="00715677478444" (14 chars),
    ///   row MD5 = a28d18e639eea2fb750cdb26613cca3a, pkFieldWidth=14.
    /// </summary>
    [Fact]
    public void MatchesDbsysCaptureBytesExactly()
    {
        var md5 = Convert.FromHexString("a28d18e639eea2fb750cdb26613cca3a");
        var pk = "00715677478444"u8.ToArray();

        var got = Messages.BuildOpenBlob(
            cursorHandle: 1, colOrdinal: 5, rowMd5: md5, primaryKey: pk, pkFieldWidth: 14);
        // Captured body bytes, verbatim from Derek/dbisam-capture-memo.pcapng msg #9.
        var expected = Convert.FromHexString(
            "00800259000000" +                                                 // header (7)
            "0400000001000000" +                                               // Pack(4) cursor=1
            "020000000200" +                                                   // Pack(2) tag=02 00
            "38000000" +                                                       // Pack(56) length prefix
            "000500000005000000a28d18e639eea2fb750cdb26613cca3a" +             // slot[0..25]: 00 + col x2 + MD5
            "0130303731353637373437383434" +                                   // slot[25..39]: 01 + 13 chars PK
            "3400000001050000000500000000000000" +                             // slot[39..56]: last PK byte + trailer
            "000100000001010000000001000000" +                                 // inner trailer (15 bytes)
            "0000010000");                                                     // outer trailer (5 bytes)

        Assert.Equal(expected.Length, got.Length);
        Assert.Equal(Convert.ToHexString(expected), Convert.ToHexString(got));
    }
}
