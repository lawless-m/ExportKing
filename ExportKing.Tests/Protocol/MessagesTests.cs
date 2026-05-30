using System.Buffers.Binary;
using System.Text;
using ExportKing.Protocol;
using Xunit;

namespace ExportKing.Tests.Protocol;

public class MessagesTests
{
    [Fact]
    public void MsgBuilderHeaderHasFlagReqcodeAndInnerLen()
    {
        // Empty body: header only (no Pack units). inner_len = 0.
        var body = new MsgBuilder(0x1234).Finish();
        Assert.Equal(7, body.Length);
        Assert.Equal(0x00, body[0]);
        Assert.Equal(0x34, body[1]); // reqcode LE byte 0
        Assert.Equal(0x12, body[2]); // reqcode LE byte 1
        Assert.Equal((uint)0, BinaryPrimitives.ReadUInt32LittleEndian(body.AsSpan(3, 4)));
    }

    [Fact]
    public void MsgBuilderPackAppendsLengthPrefixedUnit()
    {
        var body = new MsgBuilder(0x0000)
            .Pack(new byte[] { 0xDE, 0xAD })
            .Pack(new byte[] { 0xBE, 0xEF, 0xCA, 0xFE })
            .Finish();

        // Header (7) + 4+2 unit + 4+4 unit = 21
        Assert.Equal(21, body.Length);

        // inner_len = 14 (everything after the 7-byte header)
        Assert.Equal((uint)14, BinaryPrimitives.ReadUInt32LittleEndian(body.AsSpan(3, 4)));

        // Unit 1: length=2 at offset 7, payload at 11
        Assert.Equal((uint)2, BinaryPrimitives.ReadUInt32LittleEndian(body.AsSpan(7, 4)));
        Assert.Equal(new byte[] { 0xDE, 0xAD }, body[11..13]);

        // Unit 2: length=4 at offset 13, payload at 17
        Assert.Equal((uint)4, BinaryPrimitives.ReadUInt32LittleEndian(body.AsSpan(13, 4)));
        Assert.Equal(new byte[] { 0xBE, 0xEF, 0xCA, 0xFE }, body[17..21]);
    }

    [Fact]
    public void BuildConnectMatchesProtocolLayout()
    {
        // Per §6g: u64 version, u8 compression flag, AnsiString hostname, u32 nonce,
        // followed by 4 trailing zero bytes.
        var body = Messages.BuildConnect("RIVSEM048692", 0xE5A21BE8);

        // Header
        Assert.Equal(0x00, body[0]);
        Assert.Equal((ushort)0x0000, BinaryPrimitives.ReadUInt16LittleEndian(body.AsSpan(1, 2)));

        uint innerLen = BinaryPrimitives.ReadUInt32LittleEndian(body.AsSpan(3, 4));

        // 4 Pack units:
        //   u64 version = 0xAB7C
        var off = 7;
        Assert.Equal((uint)8, BinaryPrimitives.ReadUInt32LittleEndian(body.AsSpan(off, 4))); off += 4;
        Assert.Equal((ulong)0xAB7C, BinaryPrimitives.ReadUInt64LittleEndian(body.AsSpan(off, 8))); off += 8;

        //   u8 compression flag = 0
        Assert.Equal((uint)1, BinaryPrimitives.ReadUInt32LittleEndian(body.AsSpan(off, 4))); off += 4;
        Assert.Equal((byte)0, body[off]); off += 1;

        //   AnsiString hostname
        var hostBytes = "RIVSEM048692"u8.ToArray();
        Assert.Equal((uint)hostBytes.Length, BinaryPrimitives.ReadUInt32LittleEndian(body.AsSpan(off, 4))); off += 4;
        Assert.Equal(hostBytes, body[off..(off + hostBytes.Length)]); off += hostBytes.Length;

        //   u32 nonce
        Assert.Equal((uint)4, BinaryPrimitives.ReadUInt32LittleEndian(body.AsSpan(off, 4))); off += 4;
        Assert.Equal((uint)0xE5A21BE8, BinaryPrimitives.ReadUInt32LittleEndian(body.AsSpan(off, 4))); off += 4;

        // inner_len should cover all 4 Pack units, not the trailing 4 zero bytes.
        Assert.Equal((uint)(off - 7), innerLen);

        // 4 trailing zero bytes of outer padding
        Assert.Equal(off + 4, body.Length);
        Assert.Equal(new byte[] { 0, 0, 0, 0 }, body[off..]);
    }

    [Fact]
    public void BuildLoginWrapsCiphertextWithDoubleLengthPrefix()
    {
        // Use the 24-byte ciphertext from the §5 worked example to verify
        // the exact byte layout the server expects.
        var ct = new byte[]
        {
            0x57, 0x25, 0x56, 0x8E, 0x56, 0x01, 0xB0, 0x58,
            0xD1, 0x7E, 0xE1, 0x77, 0x20, 0xB6, 0x95, 0x24,
            0x78, 0x1F, 0x5A, 0x02, 0x17, 0xF2, 0x43, 0x90,
        };
        var body = Messages.BuildLogin(ct);

        // Total: 7 header + 12 inner-prefix + 24 ct + 1 tail = 44
        Assert.Equal(44, body.Length);

        // Header: flag 00, reqcode 0014
        Assert.Equal(0x00, body[0]);
        Assert.Equal((ushort)0x0014, BinaryPrimitives.ReadUInt16LittleEndian(body.AsSpan(1, 2)));

        // inner_len = 12 + 24 = 36
        Assert.Equal((uint)36, BinaryPrimitives.ReadUInt32LittleEndian(body.AsSpan(3, 4)));

        // First inner Pack-style length = 4 (Delphi pack-of-int prefix)
        Assert.Equal((uint)4, BinaryPrimitives.ReadUInt32LittleEndian(body.AsSpan(7, 4)));

        // Buffer length, then max length, both = ct.Length
        Assert.Equal((uint)24, BinaryPrimitives.ReadUInt32LittleEndian(body.AsSpan(11, 4)));
        Assert.Equal((uint)24, BinaryPrimitives.ReadUInt32LittleEndian(body.AsSpan(15, 4)));

        // Ciphertext at offset 19
        Assert.Equal(ct, body[19..43]);

        // Single trailing zero
        Assert.Equal(0x00, body[^1]);
    }

    [Fact]
    public void BuildCatalogAttachMatchesPyodbcCapture()
    {
        // Expected NISAINT_CS layout, byte-by-byte from the Rust reference.
        var body = Messages.BuildCatalogAttach("NISAINT_CS");
        var name = "NISAINT_CS"u8.ToArray();

        // Header: flag 00, reqcode 003C
        Assert.Equal(0x00, body[0]);
        Assert.Equal((ushort)0x003C, BinaryPrimitives.ReadUInt16LittleEndian(body.AsSpan(1, 2)));

        // inner_len = 4 (name_len) + name.Length + 5 (trailer)
        uint innerLen = (uint)(4 + name.Length + 5);
        Assert.Equal(innerLen, BinaryPrimitives.ReadUInt32LittleEndian(body.AsSpan(3, 4)));

        // name_len, then name bytes
        Assert.Equal((uint)name.Length, BinaryPrimitives.ReadUInt32LittleEndian(body.AsSpan(7, 4)));
        Assert.Equal(name, body[11..(11 + name.Length)]);

        // 5-byte trailer: 01 00 00 00 00
        Assert.Equal(new byte[] { 0x01, 0x00, 0x00, 0x00, 0x00 }, body[(11 + name.Length)..(16 + name.Length)]);

        // 2 outer trailing bytes: 64 00
        Assert.Equal(new byte[] { 0x64, 0x00 }, body[^2..]);

        // Total length sanity
        Assert.Equal(3 + 4 + innerLen + 2, (uint)body.Length);
    }

    [Fact]
    public void SessionSetupConstantsAreUntouched()
    {
        // The C[2]/C[3]/Post constants are replayed verbatim. This test
        // pins them so an accidental edit gets caught immediately.
        Assert.Equal(44, Messages.SessionSetupC2.Length);
        Assert.Equal(12, Messages.SessionSetupC3.Length);
        Assert.Equal(20, Messages.SessionSetupPost.Length);

        // Spot-check signature bytes:
        Assert.Equal(0x28, Messages.SessionSetupC2[1]); // reqcode 0x0028 lo
        Assert.Equal(0x84, Messages.SessionSetupC3[1]); // reqcode 0x0384 lo
        Assert.Equal(0x16, Messages.SessionSetupPost[1]); // reqcode 0x0316 lo
        Assert.Equal("INT_C"u8.ToArray(), Messages.SessionSetupPost[^5..]);
    }
}
