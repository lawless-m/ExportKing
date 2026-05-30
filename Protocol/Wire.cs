using System.Buffers.Binary;

namespace ExportKing.Protocol;

/// <summary>
/// Wire-strict walker for the universal <c>&lt;u32 LE length&gt;&lt;payload&gt;</c>
/// framing rule documented in <c>../../Derek/DBISAM-PROTOCOL.md</c> §6c and
/// confirmed by disassembly of <c>TDataSession.Unpack</c> (RVA 0x07752C).
///
/// Every unit on the wire is <c>&lt;u32 LE length&gt;&lt;length bytes&gt;</c>.
/// Higher-level structures (cursor info, row data, field definitions) are
/// sequences of these units; their semantics depend on message type + order,
/// but the framing is uniform. This walker is the one place that interprets
/// that framing — every caller goes through it instead of scanning bytes
/// ad-hoc.
/// </summary>
public sealed class Walker
{
    private readonly ReadOnlyMemory<byte> _buf;
    private int _pos;

    public Walker(ReadOnlyMemory<byte> buf, int start = 0)
    {
        _buf = buf;
        _pos = start;
    }

    public int Position => _pos;

    public ReadOnlyMemory<byte> Buffer => _buf;

    /// <summary>Rewind to a previously recorded position.</summary>
    public void Seek(int pos) => _pos = pos;

    /// <summary>
    /// Read the next <c>&lt;u32 LE length&gt;&lt;payload&gt;</c> unit. Returns
    /// <c>null</c> if the buffer is exhausted cleanly. Throws
    /// <see cref="IOException"/> if a length prefix points past the end
    /// of the buffer (malformed wire).
    /// </summary>
    public ReadOnlyMemory<byte>? NextUnit()
    {
        if (_pos >= _buf.Length) return null;
        if (_pos + 4 > _buf.Length)
        {
            throw new IOException(
                $"Exportmaster: wire walker ran past end at {_pos} " +
                $"(need 4-byte length, have {_buf.Length - _pos})");
        }
        int length = (int)BinaryPrimitives.ReadUInt32LittleEndian(_buf.Span.Slice(_pos, 4));
        int start = _pos + 4;
        int end = start + length;
        if (end > _buf.Length)
        {
            throw new IOException(
                $"Exportmaster: wire walker length {length} at pos {_pos} " +
                $"would overrun (buf len {_buf.Length})");
        }
        _pos = end;
        return _buf.Slice(start, length);
    }

    /// <summary>
    /// Read N consecutive units. Throws if any unit is missing before the
    /// buffer is exhausted.
    /// </summary>
    public List<ReadOnlyMemory<byte>> NextN(int n)
    {
        var output = new List<ReadOnlyMemory<byte>>(n);
        for (int i = 0; i < n; i++)
        {
            var unit = NextUnit();
            if (unit is null)
            {
                throw new IOException(
                    $"Exportmaster: wire walker expected {n} units, got {i} before exhaustion");
            }
            output.Add(unit.Value);
        }
        return output;
    }
}
