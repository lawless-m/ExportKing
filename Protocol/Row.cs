using System.Buffers.Binary;
using System.Text;

namespace ExportKing.Protocol;

/// <summary>
/// Row decoder — turns one record's bytes into per-column CLR values per
/// the ftType sub-code from protocol §6b.
///
/// On-disk row layout (protocol §4):
/// <code>
/// +0    9 bytes    header (8-byte LE TDateTime at +1..+8, byte +0 = type/flag)
/// +9    16 bytes   MD5 hash of record[25..end]
/// +25   N bytes    field data, walked via schema.RowOffset / schema.Max
/// </code>
/// Per-field format:
/// <code>
/// +0    1 byte     null-indicator: 0x00 = NULL, 0x01 = not null
/// +1    max bytes  value data, format depends on FieldType (§6b)
/// </code>
/// </summary>
public static class Row
{
    /// <summary>Header bytes preceding the record proper.</summary>
    public const int RecordHeaderLen = 25;

    /// <summary>
    /// Decode one record into per-column values, one per schema column.
    /// <paramref name="fullRecord"/> covers the full on-disk record — the
    /// 25-byte header followed by the column-data region. The schema's
    /// <c>RowOffset</c> values are in on-disk coordinates (counting from
    /// the start of the header), so we use them directly as indices into
    /// <paramref name="fullRecord"/>.
    /// </summary>
    public static object?[] DecodeRecord(ReadOnlySpan<byte> fullRecord, IReadOnlyList<Column> columns)
    {
        if (columns.Count == 0) return Array.Empty<object?>();
        var cells = new object?[columns.Count];
        for (int i = 0; i < columns.Count; i++)
        {
            var c = columns[i];
            int nullPos = c.RowOffset;
            int valueStart = nullPos + 1;
            if (nullPos >= fullRecord.Length)
            {
                throw new IOException(
                    $"Exportmaster: row truncated; column {c.Name} (null at {nullPos}) past end (len {fullRecord.Length})");
            }
            byte nullFlag = fullRecord[nullPos];
            if (nullFlag == 0)
            {
                cells[i] = null;
                continue;
            }
            if (nullFlag != 1)
            {
                throw new IOException(
                    $"Exportmaster: bad null-indicator 0x{nullFlag:X2} for column {c.Name} at offset {nullPos}");
            }
            int valueLen = c.Max;
            int avail = fullRecord.Length - valueStart;
            if (valueLen > avail)
            {
                throw new IOException(
                    $"Exportmaster: row truncated within column {c.Name}: need {valueLen} bytes, have {avail}");
            }
            cells[i] = DecodeField(c, fullRecord.Slice(valueStart, valueLen));
        }
        return cells;
    }

    /// <summary>
    /// Extract the 16-byte MD5 hash stored at offset +9..+24 of the on-disk
    /// record header. Required as the first 16 bytes of the slot content
    /// for blob/memo fetches (protocol §6a).
    /// </summary>
    public static byte[] ExtractRecordHash(ReadOnlySpan<byte> fullRecord)
    {
        if (fullRecord.Length < 25)
            throw new IOException($"Exportmaster: record too short to contain hash (len {fullRecord.Length})");
        return fullRecord.Slice(9, 16).ToArray();
    }

    private static object? DecodeField(Column col, ReadOnlySpan<byte> bytes)
    {
        switch (col.FieldType)
        {
            case FieldType.Calculated:
                return null; // no storage
            case FieldType.String:
            {
                // Null-terminated within max bytes; trim at first 0x00.
                // Decoded UTF-8-if-valid, else Windows-1252 — the corpus
                // contains CP1252 bytes (£, é, ™) that ASCII would corrupt.
                int end = bytes.IndexOf((byte)0);
                if (end < 0) end = bytes.Length;
                return DbisamText.Decode(bytes[..end]);
            }
            case FieldType.Date:
            {
                // 4-byte LE u32, days since 0001-01-01 (proleptic Gregorian).
                uint days = BinaryPrimitives.ReadUInt32LittleEndian(bytes);
                try
                {
                    return new DateOnly(1, 1, 1).AddDays(checked((int)days));
                }
                catch (ArgumentOutOfRangeException) { return null; }
                catch (OverflowException) { return null; }
            }
            case FieldType.DateTime:
            {
                // 8-byte LE binary64, Delphi TDateTime (days since 1899-12-30).
                // Out-of-range / NaN / sentinel values surface as null rather
                // than throwing — wide tables contain "0000-00-00" garbage
                // rows whose payload is uninitialised memory.
                double serial = BinaryPrimitives.ReadDoubleLittleEndian(bytes);
                if (!double.IsFinite(serial)) return null;
                try
                {
                    return DateTime.FromOADate(serial);
                }
                catch (ArgumentException) { return null; }
            }
            case FieldType.Time:
            {
                // 4-byte LE u32, milliseconds since midnight.
                uint ms = BinaryPrimitives.ReadUInt32LittleEndian(bytes);
                if (ms >= 24 * 60 * 60 * 1000u) return null;
                return TimeOnly.FromTimeSpan(TimeSpan.FromMilliseconds(ms));
            }
            case FieldType.Integer:
            case FieldType.AutoInc:
                return BinaryPrimitives.ReadInt32LittleEndian(bytes);
            case FieldType.Smallint:
                return (int)BinaryPrimitives.ReadInt16LittleEndian(bytes);
            case FieldType.Largeint:
                return BinaryPrimitives.ReadInt64LittleEndian(bytes);
            case FieldType.Boolean:
            {
                // 2-byte WordBool: FFFF = true, 0000 = false. Anything else
                // → true (Delphi convention treats nonzero as true).
                ushort v = BinaryPrimitives.ReadUInt16LittleEndian(bytes);
                return v != 0;
            }
            case FieldType.Float:
                return BinaryPrimitives.ReadDoubleLittleEndian(bytes);
            case FieldType.Currency:
            {
                // 8-byte LE Int64 scaled by 10_000 (4 decimal places).
                long raw = BinaryPrimitives.ReadInt64LittleEndian(bytes);
                return raw / 10_000.0m;
            }
            case FieldType.Blob:
            case FieldType.Memo:
            case FieldType.Graphic:
            {
                // 8-byte server-side blob handle. v1 surfaces as raw bytes;
                // a future commit can add §6a fetch.
                return bytes[..8].ToArray();
            }
            case FieldType.Bytes:
            case FieldType.VarBytes:
                return bytes.ToArray();
            default:
                throw new IOException(
                    $"Exportmaster: unsupported field type for column {col.Name} " +
                    $"(sub={col.SubRaw} +A8=0x{col.ByteA8:X2} +250=0x{col.Byte250:X2})");
        }
    }
}
