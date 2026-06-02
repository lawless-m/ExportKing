using ExportKing.Protocol;
using Xunit;

namespace ExportKing.Tests.Protocol;

/// <summary>
/// Unit tests for the blob slot/bookmark/response codec. Mirror the Rust
/// reference's <c>exportmaster/blob.rs</c> tests so the two ports assert
/// byte-identical wire shapes — the README's stated correctness contract
/// ("when the C# port and the Rust port disagree on bytes, the C# port is
/// wrong").
/// </summary>
public class BlobTests
{
    [Fact]
    public void BuildSlot_MatchesCapturedWire()
    {
        // Verified against Derek/dbisam-capture-memo.pcapng: for the NIINGRED
        // row with NIEAN="0071567747844" (13 chars in a 14-byte column) at
        // PhysicalRecordNumber=5, the wire slot is the 56-byte sequence below.
        const uint phys = 5;
        var md5 = Convert.FromHexString("a28d18e639eea2fb750cdb26613cca3a");
        // 14-byte PK column: 13 ASCII chars + 1 zero pad.
        var pkField = new byte[14];
        "0071567747844"u8.CopyTo(pkField);

        var slot = Blob.BuildSlot(phys, md5, pkField, 56);

        var expected = Convert.FromHexString(
            "00" + "05000000" + "05000000" +                       // [0..9]  flag + phys x2
            "a28d18e639eea2fb750cdb26613cca3a" +                   // [9..25] MD5
            "01" + "30303731353637373437383434" + "00" +          // [25..40] 01 + 13 PK chars + pad
            "0000" +                                               // [40..42] middle pad
            "01" + "05000000" + "05000000" +                       // [42..51] marker + phys x2
            "0000000000");                                         // [51..56] trailer pad

        Assert.Equal(56, slot.Length);
        Assert.Equal(Convert.ToHexString(expected), Convert.ToHexString(slot));
    }

    [Fact]
    public void BuildSlot_RejectsTooSmall()
    {
        var md5 = new byte[16];
        var pk = new byte[14];
        // 9 header + 16 MD5 + 1 + 14 PK + 14 trailer = 54. So 53 is too small.
        Assert.Throws<ArgumentException>(() => Blob.BuildSlot(1, md5, pk, 53));
        _ = Blob.BuildSlot(1, md5, pk, 54); // 54 is exactly enough
    }

    [Fact]
    public void PhysicalRecordNumber_From22ByteNiingredBookmark()
    {
        // NIEAN="0071567747844" row's 22-byte cursor bookmark carries
        // phys=5 at the trailing 4 bytes (80 00 00 05, high-bit-flagged BE).
        var bookmark = Convert.FromHexString(
            "0130303731353637373437383434000000" + // [0..17]
            "01" +                                  // [17]
            "80000005");                            // [18..22] high-bit BE = 5
        Assert.Equal(22, bookmark.Length);
        Assert.Equal(5u, Blob.PhysicalRecordNumberFromBookmark(bookmark));
    }

    [Fact]
    public void PhysicalRecordNumber_From17ByteCustomerBookmark()
    {
        // CUSTOMER's 11-byte PK (CODE column max=11) produces a 17-byte
        // bookmark: 1 flag + 11 PK + 1 marker + 4 phys, no middle pad.
        // Live-captured from rivsem04 against `SELECT CODE, NOTES FROM
        // CUSTOMER` where the first row has CODE="1" and phys=1.
        //
        // Regression: the old code hardcoded offset 18..22 and returned 0
        // here, silently breaking every blob fetch on short-PK tables via
        // the batched-cursor path.
        // Bytes: 01 (PK flag) 31 (CODE="1") 00*10 (PK pad to 11) 01 (marker) 80 00 00 01 (phys=1)
        var bookmark = Convert.FromHexString("0131000000000000000000000180000001");
        Assert.Equal(17, bookmark.Length);
        Assert.Equal(1u, Blob.PhysicalRecordNumberFromBookmark(bookmark));
    }

    [Fact]
    public void PhysicalRecordNumber_HandlesLargeValues()
    {
        var bookmark = new byte[22];
        // PhysicalRecordNumber = 100000 = 0x000186A0; BE in trailing 4
        // bytes (last byte's high bit is the flag).
        bookmark[18] = 0x80;
        bookmark[19] = 0x01;
        bookmark[20] = 0x86;
        bookmark[21] = 0xA0;
        Assert.Equal(100_000u, Blob.PhysicalRecordNumberFromBookmark(bookmark));
    }

    [Fact]
    public void PhysicalRecordNumber_ShortBookmarkReturnsZero()
    {
        // Bookmark shorter than 4 bytes can't carry phys.
        Assert.Equal(0u, Blob.PhysicalRecordNumberFromBookmark(new byte[3]));
        Assert.Equal(0u, Blob.PhysicalRecordNumberFromBookmark(ReadOnlySpan<byte>.Empty));
    }

    [Fact]
    public void ParseResponse_DecodesPayloadAndActualSlotLength()
    {
        var body = new List<byte>();
        body.AddRange(new byte[] { 0x00, 0x80, 0x02, 0, 0, 0, 0 }); // 7-byte header
        PackUnit(body, new byte[56]);                                // slot echo (actual = 56)
        PackUnit(body, BitConverter.GetBytes(12u));                  // <u32 12>
        PackUnit(body, "Hello world!"u8.ToArray());                  // payload

        var outcome = Blob.ParseOpenBlobResponse(body.ToArray());
        Assert.NotNull(outcome);
        Assert.Equal("Hello world!"u8.ToArray(), outcome!.Payload);
        Assert.Equal(56, outcome.ActualSlotLength);
    }

    [Fact]
    public void ParseResponse_SurfacesMismatchedSlotEcho()
    {
        // Server echoes a wider slot (72) than the caller sent — payload is
        // empty; caller must rebuild at 72 and retry. Parse itself succeeds.
        var body = new List<byte>();
        body.AddRange(new byte[] { 0x00, 0x80, 0x02, 0, 0, 0, 0 });
        PackUnit(body, new byte[72]);
        PackUnit(body, BitConverter.GetBytes(0u));
        PackUnit(body, Array.Empty<byte>());

        var outcome = Blob.ParseOpenBlobResponse(body.ToArray());
        Assert.NotNull(outcome);
        Assert.Equal(72, outcome!.ActualSlotLength);
        Assert.Empty(outcome.Payload);
    }

    [Fact]
    public void ParseResponse_NullOnSizeMismatch()
    {
        var body = new List<byte>();
        body.AddRange(new byte[] { 0x00, 0x80, 0x02, 0, 0, 0, 0 });
        PackUnit(body, new byte[56]);
        PackUnit(body, BitConverter.GetBytes(20u)); // declares 20 bytes
        PackUnit(body, "short"u8.ToArray());        // but only 5 follow
        Assert.Null(Blob.ParseOpenBlobResponse(body.ToArray()));
    }

    [Fact]
    public void BuildOpenBlob_HasSixPackUnits_FieldOrdAndSlotDistinct()
    {
        // The blob column ordinal travels in its own unit; the slot carries
        // the physical record number — they are NOT the same value. Build a
        // request and walk it back to prove the structure.
        var slot = Blob.BuildSlot(5, new byte[16], new byte[14], 56);
        var body = Messages.BuildOpenBlob(cursorHandle: 1, fieldOrd: 2, slot: slot);

        var w = new Walker(body, Response.PackStreamOffset);
        var cursor = w.NextUnit()!.Value;
        var fieldOrd = w.NextUnit()!.Value;
        var slotEcho = w.NextUnit()!.Value;
        var forceReread = w.NextUnit()!.Value;
        var isPhysical = w.NextUnit()!.Value;
        var trailing = w.NextUnit()!.Value;
        Assert.Null(w.NextUnit()); // exactly six units

        Assert.Equal(1u, System.Buffers.Binary.BinaryPrimitives.ReadUInt32LittleEndian(cursor.Span));
        Assert.Equal(2, fieldOrd.Length);
        Assert.Equal(2, System.Buffers.Binary.BinaryPrimitives.ReadUInt16LittleEndian(fieldOrd.Span));
        Assert.Equal(56, slotEcho.Length);
        Assert.Equal(new byte[] { 0 }, forceReread.ToArray());
        Assert.Equal(new byte[] { 0 }, isPhysical.ToArray());
        Assert.Equal(new byte[] { 0 }, trailing.ToArray());
    }

    private static void PackUnit(List<byte> buf, byte[] payload)
    {
        buf.AddRange(BitConverter.GetBytes((uint)payload.Length));
        buf.AddRange(payload);
    }
}
