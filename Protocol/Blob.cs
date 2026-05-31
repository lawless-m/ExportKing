using System.Buffers.Binary;

namespace ExportKing.Protocol;

/// <summary>
/// Memo / blob fetch — reqcode 0x0280. See protocol §6a. Ported from the
/// MrsFlow Rust reference (<c>exportmaster/blob.rs</c>), which is the working
/// oracle: it fetches blob content live against the same <c>dbsrvr.exe</c>.
///
/// Blob columns (sub-type 3, max_size 8) carry only an 8-byte handle on the
/// row; the content is fetched in a separate round-trip when the application
/// reads the field. One 0x0280 per (cursor, field, row) tuple returns the
/// whole payload — the server never paginates remote blob reads regardless
/// of size.
///
/// The slot the server expects is built from the row's <em>physical record
/// number</em> (recovered from the cursor's per-row bookmark), the 16-byte
/// row MD5, and the primary-key column bytes — NOT from the blob column's
/// ordinal. Conflating the two was the original ExportKing bug that produced
/// server error 0x3A9A.
/// </summary>
public static class Blob
{
    /// <summary>
    /// Build the physical-record bookmark slot for a 0x0280 OpenBlob request.
    /// Layout reverse-engineered from a verified dbsys.exe capture
    /// (<c>Derek/dbisam-capture-memo.pcapng</c>, reqcode 0x0280):
    /// <code>
    /// Pos 0        0x00 (record-active flag)
    /// Pos 1..5     u32 LE PhysicalRecordNumber
    /// Pos 5..9     u32 LE PhysicalRecordNumber (repeated)
    /// Pos 9..25    16-byte row MD5 (= record bytes [9..25])
    /// Pos 25       0x01 (PK column null flag)
    /// Pos 26..     PK column raw bytes (1 byte * pk_field_width)
    /// (middle)     zero padding
    /// Pos L-14     0x01 (second null flag / bookmark marker)
    /// Pos L-13..   u32 LE PhysicalRecordNumber
    /// Pos L-9..    u32 LE PhysicalRecordNumber
    /// Pos L-5..    5 bytes 0x00 (trailing pad)
    /// </code>
    /// <paramref name="slotLength"/> is mode-dependent: 56 for natural-PK
    /// cursors on short-PK tables; 72 for WHERE-filtered / materialised
    /// cursors. When unknown up front, send 56 and rebuild at the length the
    /// server echoes back (see <see cref="BlobFetchOutcome.ActualSlotLength"/>).
    /// </summary>
    public static byte[] BuildSlot(
        uint physicalRecordNumber,
        ReadOnlySpan<byte> rowMd5,
        ReadOnlySpan<byte> pkField,
        int slotLength)
    {
        if (rowMd5.Length != 16)
            throw new ArgumentException("rowMd5 must be 16 bytes", nameof(rowMd5));

        const int trailerLen = 14; // 0x01 + 4 + 4 + 5
        const int headerLen = 9;   // 0x00 + 4 + 4
        const int md5Len = 16;
        int pkBlockLen = 1 + pkField.Length; // null flag + PK column bytes
        int used = headerLen + md5Len + pkBlockLen + trailerLen;
        if (used > slotLength)
        {
            throw new ArgumentException(
                $"Exportmaster: slotLength={slotLength} too small for layout with " +
                $"{pkField.Length}-byte PK field (needs {used})", nameof(slotLength));
        }

        var slot = new byte[slotLength];
        // Header.
        slot[0] = 0x00;
        BinaryPrimitives.WriteUInt32LittleEndian(slot.AsSpan(1, 4), physicalRecordNumber);
        BinaryPrimitives.WriteUInt32LittleEndian(slot.AsSpan(5, 4), physicalRecordNumber);
        // MD5.
        rowMd5.CopyTo(slot.AsSpan(9, 16));
        // PK column.
        slot[25] = 0x01;
        pkField.CopyTo(slot.AsSpan(26, pkField.Length));
        // (middle padding is already zero)
        // Trailer.
        int t = slotLength - trailerLen;
        slot[t] = 0x01;
        BinaryPrimitives.WriteUInt32LittleEndian(slot.AsSpan(t + 1, 4), physicalRecordNumber);
        BinaryPrimitives.WriteUInt32LittleEndian(slot.AsSpan(t + 5, 4), physicalRecordNumber);
        // Last 5 bytes already zero.
        return slot;
    }

    /// <summary>
    /// Extract <c>PhysicalRecordNumber</c> from a 22-byte cursor bookmark unit.
    /// The position is encoded at offset 18 as
    /// <c>&lt;u8 with high bit set&gt;&lt;3 bytes BE value&gt;</c> — the §3
    /// "high-bit-tagged integer" form. Strip the high bit and read the 4 bytes
    /// big-endian.
    ///
    /// Returns 0 if the bookmark is too short or malformed (typical
    /// non-natural-PK cursors don't carry a usable position here).
    /// </summary>
    public static uint PhysicalRecordNumberFromBookmark(ReadOnlySpan<byte> bookmark)
    {
        if (bookmark.Length < 22) return 0;
        byte b0 = (byte)(bookmark[18] & 0x7F);
        return BinaryPrimitives.ReadUInt32BigEndian(stackalloc byte[] { b0, bookmark[19], bookmark[20], bookmark[21] });
    }

    /// <summary>
    /// Outcome of one 0x0280 round-trip: the payload bytes plus the server's
    /// actual slot_length (echoed back as the first response unit). When the
    /// echo length differs from what the request sent, the server expected a
    /// different slot width and the payload is empty/garbage — rebuild the
    /// slot at <see cref="ActualSlotLength"/> and retry. Cache the value for
    /// subsequent fetches in the same query.
    /// </summary>
    public sealed class BlobFetchOutcome
    {
        public required byte[] Payload { get; init; }
        public required int ActualSlotLength { get; init; }

        /// <summary>
        /// The slot bytes the server echoed back — NOT identical to the slot
        /// the request sent. The server tags a few trailing bytes (typically
        /// <c>01 fe ff ff ff</c> where the request had <c>01 &lt;u32 phys&gt;</c>)
        /// as an "open in cache" marker. A <c>0x028A</c> FreeBlob must present
        /// these exact bytes or the server can't find the buffer to free —
        /// pass this verbatim to <see cref="Messages.BuildFreeBlob"/>.
        /// </summary>
        public required byte[] SlotEcho { get; init; }
    }

    /// <summary>
    /// Parse a 0x0280 response body. Per §6a the body after the 7-byte header
    /// is 3 Pack units:
    /// <list type="number">
    ///   <item>Slot echo — the server's expected slot_length, independent of
    ///         what the request sent</item>
    ///   <item><c>&lt;u32 blob_size&gt;</c> (4 bytes)</item>
    ///   <item><c>&lt;blob_size bytes&gt;</c> — the payload</item>
    /// </list>
    /// Returns null if the body is an error response (doesn't carry the
    /// expected 3-unit shape) rather than throwing — the caller treats a null
    /// as "no blob payload".
    /// </summary>
    public static BlobFetchOutcome? ParseOpenBlobResponse(byte[] body)
    {
        if (body.Length < Response.PackStreamOffset) return null;
        var w = new Walker(body, Response.PackStreamOffset);

        ReadOnlyMemory<byte>? slotEcho, sizeUnit, payload;
        try
        {
            slotEcho = w.NextUnit();
            if (slotEcho is null) return null;
            int actualSlotLength = slotEcho.Value.Length;
            var slotEchoBytes = slotEcho.Value.ToArray();

            sizeUnit = w.NextUnit();
            if (sizeUnit is null || sizeUnit.Value.Length != 4) return null;
            int blobSize = (int)BinaryPrimitives.ReadUInt32LittleEndian(sizeUnit.Value.Span);

            payload = w.NextUnit();
            if (payload is null || payload.Value.Length != blobSize) return null;

            return new BlobFetchOutcome
            {
                Payload = payload.Value.ToArray(),
                ActualSlotLength = actualSlotLength,
                SlotEcho = slotEchoBytes,
            };
        }
        catch (IOException)
        {
            return null;
        }
    }
}
