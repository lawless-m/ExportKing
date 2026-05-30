using System.Buffers.Binary;
using System.Text;

namespace ExportKing.Protocol;

/// <summary>
/// DBISAM field type codes, mapped from the per-column <c>sub</c> byte at
/// +0xA7 in each 772-byte schema block. Protocol §6b is the source of truth.
/// Three of these (Blob, Integer, Float) are refined by auxiliary bytes at
/// +0xA8 or +0x250 within the same block — see <see cref="ColumnExtensions.ResolveFieldType"/>.
/// </summary>
public enum FieldType
{
    /// <summary>sub=0 — calculated/derived; no storage. Skipped during row decode.</summary>
    Calculated,
    /// <summary>sub=1 — ftString. ASCII chars, null-padded to decl.</summary>
    String,
    /// <summary>sub=2 — ftDate. 4-byte LE u32, days since 0001-01-01.</summary>
    Date,
    /// <summary>sub=3 + +0xA8=0x00 — ftBlob (binary). 8-byte handle → §6a fetch.</summary>
    Blob,
    /// <summary>sub=3 + +0xA8=0x16 — ftMemo (text). Same handle, decoded as text.</summary>
    Memo,
    /// <summary>sub=3 + +0xA8=0x1A — ftGraphic (image bytes).</summary>
    Graphic,
    /// <summary>sub=4 — ftBoolean. 2-byte LE WordBool (FFFF=true, 0000=false).</summary>
    Boolean,
    /// <summary>sub=5 — ftSmallint. 2-byte LE signed int.</summary>
    Smallint,
    /// <summary>sub=6 + +0xA8=0x00 — ftInteger. 4-byte LE signed int.</summary>
    Integer,
    /// <summary>sub=6 + +0xA8=0x1D — ftAutoInc. 4-byte LE auto-increment.</summary>
    AutoInc,
    /// <summary>sub=7 + +0x250=0x0A — ftCurrency. 8-byte LE Int64 / 10000.</summary>
    Currency,
    /// <summary>sub=7 + +0x250=0x00 — ftFloat. 8-byte LE IEEE 754 binary64.</summary>
    Float,
    /// <summary>sub=9 — ftBytes. N raw bytes (fixed-length binary).</summary>
    Bytes,
    /// <summary>sub=10 — ftTime. 4-byte LE u32, milliseconds since midnight.</summary>
    Time,
    /// <summary>sub=11 — ftDateTime. 8-byte LE binary64, Delphi TDateTime.</summary>
    DateTime,
    /// <summary>sub=15 — ftVarBytes. Up to N bytes, length-prefixed.</summary>
    VarBytes,
    /// <summary>sub=18 — ftLargeint. 8-byte LE signed int.</summary>
    Largeint,
    /// <summary>Anything we haven't seen — row decode fails with the raw bytes for diagnosis.</summary>
    Unknown,
}

/// <summary>
/// A parsed column descriptor.
/// </summary>
public sealed class Column
{
    /// <summary>1-based ordinal in the result set.</summary>
    public required ushort Ord { get; init; }
    /// <summary>Column name (ASCII, exactly namelen bytes from the schema block).</summary>
    public required string Name { get; init; }
    /// <summary>Resolved field type — for Unknown, see <see cref="SubRaw"/>/<see cref="ByteA8"/>/<see cref="Byte250"/>.</summary>
    public required FieldType FieldType { get; init; }
    /// <summary>Declared length (for ftString = max chars; 0 for fixed-size types).</summary>
    public required byte Decl { get; init; }
    /// <summary>On-disk storage width in bytes (for ftString = decl+1 incl. length byte).</summary>
    public required byte Max { get; init; }
    /// <summary>
    /// Byte offset of this field within the on-disk record (after the
    /// header). Field's null-flag byte lives at this offset; value bytes
    /// start at offset+1.
    /// </summary>
    public required ushort RowOffset { get; init; }
    /// <summary>Raw <c>sub</c> byte at +0xA7 — preserved for diagnostics when <see cref="FieldType"/> is <see cref="FieldType.Unknown"/>.</summary>
    public byte SubRaw { get; init; }
    public byte ByteA8 { get; init; }
    public byte Byte250 { get; init; }
}

internal static class ColumnExtensions
{
    public static FieldType ResolveFieldType(byte sub, byte byteA8, byte byte250) => (sub, byteA8, byte250) switch
    {
        (0, _, _) => FieldType.Calculated,
        (1, _, _) => FieldType.String,
        (2, _, _) => FieldType.Date,
        (3, 0x00, _) => FieldType.Blob,
        (3, 0x16, _) => FieldType.Memo,
        (3, 0x1A, _) => FieldType.Graphic,
        (4, _, _) => FieldType.Boolean,
        (5, _, _) => FieldType.Smallint,
        (6, 0x1D, _) => FieldType.AutoInc,
        (6, _, _) => FieldType.Integer,
        (7, _, 0x0A) => FieldType.Currency,
        (7, _, _) => FieldType.Float,
        (9, _, _) => FieldType.Bytes,
        (10, _, _) => FieldType.Time,
        (11, _, _) => FieldType.DateTime,
        (15, _, _) => FieldType.VarBytes,
        (18, _, _) => FieldType.Largeint,
        _ => FieldType.Unknown,
    };
}

/// <summary>
/// Schema parser — decodes the 772-byte column-block region of a SELECT
/// response into typed <see cref="Column"/> descriptors. See protocol §4 + §6b.
/// Mirrors MrsFlow <c>schema.rs</c>.
/// </summary>
public static class Schema
{
    /// <summary>Width of one column-descriptor block in the schema region.</summary>
    public const int SchemaBlockStride = 772;

    /// <summary>Marker bytes at the start of every block: <c>03 00 00</c>.</summary>
    private static readonly byte[] BlockMarker = { 0x03, 0x00, 0x00 };

    /// <summary>
    /// Parse all column descriptors from the schema region of a SELECT
    /// response. Returns the columns and the byte offset just past the last
    /// block (caller uses this to locate row data).
    /// </summary>
    public static (List<Column> Columns, int EndOffset) Parse(ReadOnlySpan<byte> serverPayload)
    {
        int first = FindFirstBlockStart(serverPayload);
        var columns = new List<Column>();
        int off = first;
        ushort expectedOrd = 1;
        while (off + SchemaBlockStride <= serverPayload.Length)
        {
            var col = ParseOneBlock(serverPayload.Slice(off, SchemaBlockStride));
            if (col is null) break;
            if (col.Ord != expectedOrd) break;
            columns.Add(col);
            expectedOrd++;
            off += SchemaBlockStride;
        }
        if (columns.Count == 0)
        {
            throw new IOException("Exportmaster: schema parser found no columns");
        }
        return (columns, off);
    }

    /// <summary>
    /// Find the first column block. Looks for <c>03 00 00 01 00</c> — the
    /// block marker followed by ordinal=1 (LE u16) and a non-zero namelen.
    /// </summary>
    private static int FindFirstBlockStart(ReadOnlySpan<byte> payload)
    {
        ReadOnlySpan<byte> needle = stackalloc byte[] { 0x03, 0x00, 0x00, 0x01, 0x00 };
        for (int i = 0; i + 6 <= payload.Length; i++)
        {
            if (payload.Slice(i, 5).SequenceEqual(needle) && payload[i + 5] > 0)
            {
                return i;
            }
        }
        throw new IOException("Exportmaster: no schema block marker found in response");
    }

    /// <summary>
    /// Parse one 772-byte block. Returns <c>null</c> if the leading marker
    /// doesn't match (signals "no more blocks here").
    /// </summary>
    private static Column? ParseOneBlock(ReadOnlySpan<byte> block)
    {
        if (block.Length < SchemaBlockStride) return null;
        if (!block[..3].SequenceEqual(BlockMarker)) return null;

        ushort ord = BinaryPrimitives.ReadUInt16LittleEndian(block.Slice(3, 2));
        int namelen = block[5];
        if (namelen == 0 || 6 + namelen > block.Length) return null;

        var name = Encoding.ASCII.GetString(block.Slice(6, namelen));

        // 12-byte column descriptor at +0xA7. Layout per protocol §4:
        //   +0  sub          ftType code
        //   +2  decl         declared length
        //   +5  max          on-disk storage width
        //   +8  row_offset   u16 LE
        var meta = block.Slice(0xA7, 12);
        byte sub = meta[0];
        byte decl = meta[2];
        byte max = meta[5];
        ushort rowOffset = BinaryPrimitives.ReadUInt16LittleEndian(meta.Slice(8, 2));
        byte byteA8 = block[0xA8];
        byte byte250 = block[0x250];

        return new Column
        {
            Ord = ord,
            Name = name,
            FieldType = ColumnExtensions.ResolveFieldType(sub, byteA8, byte250),
            Decl = decl,
            Max = max,
            RowOffset = rowOffset,
            SubRaw = sub,
            ByteA8 = byteA8,
            Byte250 = byte250,
        };
    }
}
