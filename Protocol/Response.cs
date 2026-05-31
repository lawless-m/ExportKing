using System.Buffers.Binary;

namespace ExportKing.Protocol;

/// <summary>
/// Cursor-info: the 10-field structure the server writes after each
/// query/fetch (TServerThread.PackCursorInfo, RVA 0x49810, per
/// <c>../../Derek/DBISAM-PROTOCOL.md</c> §6d). Each field is one
/// <c>[u32 LE length][payload]</c> Pack unit.
///
/// Only <see cref="Bookmark"/> and the record counts are used in practice;
/// other fields are surfaced for completeness.
/// </summary>
public sealed class CursorInfo
{
    public required uint RecordNumber { get; init; }
    public required uint PhysicalRecordNumber { get; init; }
    public required uint RecordCount { get; init; }
    public required uint PhysicalRecordsUsed { get; init; }
    public required uint LastAutoIncId { get; init; }
    /// <summary>
    /// 8 raw bytes — TDateTime double, days since 1899-12-30. Callers that
    /// care decode it themselves via <see cref="System.DateTime.FromOADate"/>.
    /// </summary>
    public required byte[] LastUpdated { get; init; }
    public required uint TotalRecordCount { get; init; }
    /// <summary>
    /// THE opaque cursor position. Echo these bytes verbatim into the next
    /// fetch's bookmark slot to advance through any cursor mode.
    /// </summary>
    public required byte[] Bookmark { get; init; }
    public required byte Flag60E { get; init; }
    public required byte Flag60D { get; init; }
    /// <summary>Walker position immediately past the last cursor-info unit.</summary>
    public required int EndOffset { get; init; }

    /// <summary>
    /// Read the 10 cursor-info units starting at <paramref name="walker"/>'s
    /// current position. Advances the walker past them.
    /// </summary>
    public static CursorInfo Read(Walker walker)
    {
        var units = walker.NextN(10);
        return new CursorInfo
        {
            RecordNumber = U32Le(units[0], "RecordNumber"),
            PhysicalRecordNumber = U32Le(units[1], "PhysicalRecordNumber"),
            RecordCount = U32Le(units[2], "RecordCount"),
            PhysicalRecordsUsed = U32Le(units[3], "PhysicalRecordsUsed"),
            LastAutoIncId = U32Le(units[4], "LastAutoIncID"),
            LastUpdated = Fixed8(units[5], "LastUpdated"),
            TotalRecordCount = U32Le(units[6], "TotalRecordCount"),
            Bookmark = units[7].ToArray(),
            Flag60E = OneByte(units[8], "flag_60E"),
            Flag60D = OneByte(units[9], "flag_60D"),
            EndOffset = walker.Position,
        };
    }

    private static uint U32Le(ReadOnlyMemory<byte> buf, string name)
    {
        if (buf.Length != 4)
            throw new IOException($"Exportmaster: cursor-info field {name} expected 4 bytes, got {buf.Length}");
        return BinaryPrimitives.ReadUInt32LittleEndian(buf.Span);
    }

    private static byte[] Fixed8(ReadOnlyMemory<byte> buf, string name)
    {
        if (buf.Length != 8)
            throw new IOException($"Exportmaster: cursor-info field {name} expected 8 bytes, got {buf.Length}");
        return buf.ToArray();
    }

    private static byte OneByte(ReadOnlyMemory<byte> buf, string name)
    {
        if (buf.Length != 1)
            throw new IOException($"Exportmaster: cursor-info field {name} expected 1 byte, got {buf.Length}");
        return buf.Span[0];
    }
}

/// <summary>
/// One server "batch" within a response: a result code, the cursor info,
/// and zero-or-more row records (as offset/length slices into the response body).
/// </summary>
public sealed class CursorBatch
{
    public required ushort ResultCode { get; init; }
    public required CursorInfo CursorInfo { get; init; }
    /// <summary>
    /// Offset/length pairs into the original response body — each is one
    /// on-disk record (header + column data). Empty if result code wasn't OK.
    /// </summary>
    public required List<(int Offset, int Length)> Rows { get; init; }

    /// <summary>
    /// Per-row physical-record bookmarks, one per entry in <see cref="Rows"/>
    /// (offset/length into the same response body). Used by blob fetch to
    /// recover each row's <c>PhysicalRecordNumber</c> via
    /// <see cref="Blob.PhysicalRecordNumberFromBookmark"/>. Empty when the
    /// server didn't send a bookmark buffer (single-row replies) — callers
    /// that don't need bookmarks ignore it.
    /// </summary>
    public List<(int Offset, int Length)> Bookmarks { get; init; } = new();
}

/// <summary>
/// Decoder for cursor-response bodies per protocol §6c–§6f. Mirrors MrsFlow
/// <c>response.rs</c>.
///
/// Body layout (after framing has stripped the GUID+total_len envelope):
/// <code>
/// +0   u8        header flag (always 0x00)
/// +1   u16 LE    reqcode
/// +3   u32 LE    body_len (informational; not strictly verified)
/// +7              Pack stream begins here:
///     [u32 length=2][u16 LE result_code]   OK=0x0000, end-of-cursor=0x2202
///     10 cursor-info Pack units (see CursorInfo)
///     [row record Pack units] each [u32 length=record_size][record bytes]
///     ...repeats per server batch
/// </code>
/// </summary>
public static class Response
{
    public const ushort ResultOk = 0x0000;
    public const ushort ResultNotReady = 0x0003;
    public const ushort ResultEndOfCursor = 0x2202;

    /// <summary>
    /// Reqcode the server emits in its body header when responding with a
    /// "not ready, poll again" status. Not in the client→server dispatch
    /// table — it's a server-pushed status marker.
    /// </summary>
    public const ushort PollingSentinelReqcode = 0x2C14;

    /// <summary>
    /// Offset where the Pack stream begins (after the 7-byte body header).
    /// </summary>
    public const int PackStreamOffset = 7;

    /// <summary>Read the body header's reqcode (u16 LE at offset 1).</summary>
    public static ushort BodyReqcode(ReadOnlySpan<byte> body)
    {
        if (body.Length < 3) return 0;
        return BinaryPrimitives.ReadUInt16LittleEndian(body.Slice(1, 2));
    }

    /// <summary>
    /// Parse a <c>ReadFirstRecordBlock</c> / <c>ReadNextRecordBlock</c>
    /// response (reqcode 0x050A / 0x04F6). Layout decoded empirically from
    /// live captures:
    /// <code>
    /// [u32 length=2][u16 LE result_code]     OK=0x0000, last batch=0x2202
    /// 10 cursor-info Pack units
    /// [u32 length=4][u32 LE row_count]
    /// [u32 length=N × record_size][concatenated row bytes — no inner framing]
    /// [u32 length=N × bookmark_size][concatenated bookmarks — ignored]
    /// </code>
    /// Per the EoC convention, the last batch carries
    /// <c>result_code = 0x2202</c> AND may still contain rows — caller
    /// harvests rows regardless of result_code, then exits on EoC.
    /// </summary>
    public static CursorBatch? ReadRecordBlockBatch(Walker walker, int expectedRecordSize)
    {
        var rcUnit = walker.NextUnit();
        if (rcUnit is null) return null;
        if (rcUnit.Value.Length != 2)
            throw new IOException(
                $"Exportmaster: ReadRecordBlock: expected 2-byte result code, got {rcUnit.Value.Length}");
        ushort resultCode = BinaryPrimitives.ReadUInt16LittleEndian(rcUnit.Value.Span);
        var cursorInfo = CursorInfo.Read(walker);

        var rows = new List<(int Offset, int Length)>();
        var bookmarks = new List<(int Offset, int Length)>();
        var countUnit = walker.NextUnit();
        if (countUnit is not null && countUnit.Value.Length == 4)
        {
            int rowCount = (int)BinaryPrimitives.ReadUInt32LittleEndian(countUnit.Value.Span);
            int rowBufStart = walker.Position; // position of the length prefix
            var rowBuf = walker.NextUnit();
            if (rowBuf is not null && rowCount > 0 && rowBuf.Value.Length % rowCount == 0)
            {
                int actualRecordSize = rowBuf.Value.Length / rowCount;
                int lo = Math.Max(0, expectedRecordSize - 32);
                int hi = expectedRecordSize + 32;
                if (actualRecordSize >= lo && actualRecordSize <= hi)
                {
                    // rowBuf payload starts 4 bytes after rowBufStart (past
                    // its own length prefix). We carry payload-buffer
                    // absolute offsets so callers can slice the original body.
                    int payloadStart = rowBufStart + 4;
                    for (int i = 0; i < rowCount; i++)
                    {
                        rows.Add((payloadStart + i * actualRecordSize, actualRecordSize));
                    }
                }

                // Bookmark buffer: per-row physical-record bookmarks,
                // concatenated. Slice them the same way as rows so blob
                // fetch can recover each row's PhysicalRecordNumber. The
                // per-row width is bookmark_buf.Length / rowCount.
                int bmBufStart = walker.Position;
                var bmBuf = walker.NextUnit();
                if (bmBuf is not null && rowCount > 0 && bmBuf.Value.Length % rowCount == 0)
                {
                    int perRow = bmBuf.Value.Length / rowCount;
                    int bmPayloadStart = bmBufStart + 4;
                    for (int i = 0; i < rowCount; i++)
                    {
                        bookmarks.Add((bmPayloadStart + i * perRow, perRow));
                    }
                }
            }
        }

        return new CursorBatch
        {
            ResultCode = resultCode,
            CursorInfo = cursorInfo,
            Rows = rows,
            Bookmarks = bookmarks,
        };
    }

    /// <summary>
    /// Parse a single-row response shape (used by ExecuteStatement and the
    /// Receive poll loop) — cursor-info + zero or more Pack units that are
    /// each one record of length ≈ <paramref name="expectedRecordSize"/>.
    /// </summary>
    public static CursorBatch? ReadBatch(Walker walker, int expectedRecordSize)
    {
        var rcUnit = walker.NextUnit();
        if (rcUnit is null) return null;
        if (rcUnit.Value.Length != 2)
            throw new IOException(
                $"Exportmaster: expected 2-byte result code, got {rcUnit.Value.Length}");
        ushort resultCode = BinaryPrimitives.ReadUInt16LittleEndian(rcUnit.Value.Span);
        var cursorInfo = CursorInfo.Read(walker);

        var rows = new List<(int Offset, int Length)>();
        int? lockedSize = null;
        if (resultCode == ResultOk)
        {
            while (true)
            {
                int saved = walker.Position;
                var unit = walker.NextUnit();
                if (unit is null) break;

                int len = unit.Value.Length;
                bool matches;
                if (lockedSize is int s)
                {
                    matches = len == s;
                }
                else
                {
                    int lo = Math.Max(0, expectedRecordSize - 2);
                    int hi = expectedRecordSize + 2;
                    if (len >= lo && len <= hi)
                    {
                        lockedSize = len;
                        matches = true;
                    }
                    else
                    {
                        matches = false;
                    }
                }
                if (matches)
                {
                    // Payload starts 4 bytes past the saved length-prefix position.
                    rows.Add((saved + 4, len));
                }
                else
                {
                    walker.Seek(saved);
                    break;
                }
            }
        }

        return new CursorBatch
        {
            ResultCode = resultCode,
            CursorInfo = cursorInfo,
            Rows = rows,
        };
    }
}
