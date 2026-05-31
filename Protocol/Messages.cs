using System.Buffers;
using System.Buffers.Binary;
using System.Text;

namespace ExportKing.Protocol;

/// <summary>
/// Reqcode constants for the DBISAM wire protocol. The full server dispatch
/// table has 147 entries; only the subset ExportKing actually uses (SELECT
/// flow + handshake + cleanup) is named here.
/// </summary>
public static class Reqcode
{
    public const ushort Connect = 0x0000;
    public const ushort Login = 0x0014;
    public const ushort SessionParams = 0x0028;
    public const ushort RemoveAllRemoteMemoryTables = 0x0029;
    public const ushort OpenDataDir = 0x003C;
    public const ushort CloseDataDir = 0x0046;

    public const ushort OpenCursor = 0x0096;
    public const ushort CloseCursor = 0x00A0;
    public const ushort ResetCursor = 0x00AA;
    public const ushort SetIndexName = 0x00B4;
    public const ushort SetToBegin = 0x00BE;
    public const ushort SetToEnd = 0x00C8;
    public const ushort GetCurrentRecord = 0x00E6;
    public const ushort GetNextRecord = 0x00FA;
    public const ushort GetPriorRecord = 0x0104;
    public const ushort SetToBookmark = 0x0154;

    public const ushort OpenBlob = 0x0280;
    public const ushort FreeBlob = 0x028A;
    public const ushort FreeAllBlobs = 0x0294;

    public const ushort Receive = 0x030C;
    public const ushort DataDirCtor = 0x0316;
    public const ushort PrepareStatement = 0x0320;
    public const ushort ExecuteStatement = 0x032A;
    public const ushort ResetStatement = 0x0334;

    public const ushort ReadNextRecordBlock = 0x04F6;
    public const ushort ReadPriorRecordBlock = 0x0500;
    public const ushort ReadFirstRecordBlock = 0x050A;
    public const ushort ReadLastRecordBlock = 0x0514;
}

/// <summary>
/// Builder for a client request body. Writes the 7-byte header
/// <c>[flag=0][reqcode:u16 LE][inner_len:u32 LE]</c> then a sequence of
/// Pack units (<c>[u32 LE length][payload]</c>), then patches the inner_len
/// based on the total bytes written. See <c>../../Derek/DBISAM-PROTOCOL.md</c>
/// §6c (universal Pack framing) and msg.rs in the Rust reference.
/// </summary>
public sealed class MsgBuilder
{
    private readonly ArrayBufferWriter<byte> _buf = new(64);
    private readonly int _innerStart;

    public MsgBuilder(ushort reqcode)
    {
        Span<byte> header = stackalloc byte[7];
        header[0] = 0x00;
        BinaryPrimitives.WriteUInt16LittleEndian(header.Slice(1, 2), reqcode);
        // header[3..7] = inner_len placeholder, patched in Finish().
        _buf.Write(header);
        _innerStart = _buf.WrittenCount;
    }

    /// <summary>Push one <c>[u32 LE length][payload]</c> Pack unit.</summary>
    public MsgBuilder Pack(ReadOnlySpan<byte> payload)
    {
        Span<byte> len = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32LittleEndian(len, (uint)payload.Length);
        _buf.Write(len);
        _buf.Write(payload);
        return this;
    }

    public MsgBuilder PackU64(ulong v)
    {
        Span<byte> tmp = stackalloc byte[8];
        BinaryPrimitives.WriteUInt64LittleEndian(tmp, v);
        return Pack(tmp);
    }

    public MsgBuilder PackU32(uint v)
    {
        Span<byte> tmp = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32LittleEndian(tmp, v);
        return Pack(tmp);
    }

    public MsgBuilder PackU8(byte v)
    {
        Span<byte> tmp = stackalloc byte[1];
        tmp[0] = v;
        return Pack(tmp);
    }

    public byte[] Finish()
    {
        var arr = _buf.WrittenSpan.ToArray();
        uint innerLen = (uint)(arr.Length - _innerStart);
        BinaryPrimitives.WriteUInt32LittleEndian(arr.AsSpan(3, 4), innerLen);
        return arr;
    }
}

/// <summary>
/// Concrete request-body builders for the SELECT-only flow. Each method
/// returns the body bytes ready to hand to <see cref="Framing.SendRecv"/>.
/// </summary>
public static class Messages
{
    /// <summary>
    /// Build the Connect handshake body (reqcode 0x0000, very first message
    /// after TCP connect). Per protocol §6g, 4 Pack fields:
    /// <list type="number">
    ///   <item>u64 client version (0xAB7C, stable for DBISAM 4.39)</item>
    ///   <item>u8 RemoteCompression flag (always 0 — we never use it)</item>
    ///   <item>AnsiString hostname (server doesn't validate strictly)</item>
    ///   <item>u32 session nonce (server stores but doesn't echo)</item>
    /// </list>
    /// Followed by 4 trailing zero bytes (padding).
    /// </summary>
    public static byte[] BuildConnect(string hostname, uint nonce)
    {
        var m = new MsgBuilder(Reqcode.Connect);
        m.PackU64(0xAB7C);
        m.PackU8(0);
        m.Pack(Encoding.ASCII.GetBytes(hostname));
        m.PackU32(nonce);
        var body = m.Finish();
        var padded = new byte[body.Length + 4];
        body.CopyTo(padded, 0);
        return padded;
    }

    /// <summary>
    /// Wrap a Blowfish-CBC login ciphertext (from <see cref="Crypto.EncryptLogin"/>)
    /// in the LOGIN message body. Reqcode 0x14, double-length prefix (Delphi
    /// <c>TStringField</c> convention: declared size then actual size), single
    /// trailing zero. Protocol §5.
    /// </summary>
    public static byte[] BuildLogin(ReadOnlySpan<byte> ciphertext)
    {
        // inner: [u32 LE = 4][u32 LE ct_len][u32 LE ct_max_len][ciphertext]
        // total: 7-byte header + inner + 1 trailing zero
        uint innerLen = (uint)(4 + 4 + 4 + ciphertext.Length);
        var body = new byte[3 + 4 + innerLen + 1];
        body[0] = 0x00;
        body[1] = 0x14;
        body[2] = 0x00;
        BinaryPrimitives.WriteUInt32LittleEndian(body.AsSpan(3, 4), innerLen);
        BinaryPrimitives.WriteUInt32LittleEndian(body.AsSpan(7, 4), 4);
        BinaryPrimitives.WriteUInt32LittleEndian(body.AsSpan(11, 4), (uint)ciphertext.Length);
        BinaryPrimitives.WriteUInt32LittleEndian(body.AsSpan(15, 4), (uint)ciphertext.Length);
        ciphertext.CopyTo(body.AsSpan(19, ciphertext.Length));
        // body[^1] is already 0 (new byte[]).
        return body;
    }

    /// <summary>
    /// Build the catalog-attach message body (reqcode 0x003C). Decoded from
    /// an uncompressed <c>pyodbc.connect(DSN=Exportmaster)</c> capture; verified
    /// byte-identical to a replay of <c>NISAINT_CS</c>. Layout:
    /// <code>
    ///   [flag 00][reqcode 003C LE][inner_len LE u32]
    ///   inner: [u32 LE name_len][catalog name][01 00 00 00 00]
    ///   trailing [64 00]
    /// </code>
    /// </summary>
    public static byte[] BuildCatalogAttach(string catalog)
    {
        var name = Encoding.ASCII.GetBytes(catalog);
        int innerLen = 4 + name.Length + 5;
        var body = new byte[3 + 4 + innerLen + 2];
        body[0] = 0x00;
        body[1] = 0x3C;
        body[2] = 0x00;
        BinaryPrimitives.WriteUInt32LittleEndian(body.AsSpan(3, 4), (uint)innerLen);
        BinaryPrimitives.WriteUInt32LittleEndian(body.AsSpan(7, 4), (uint)name.Length);
        name.CopyTo(body, 11);
        body[11 + name.Length] = 0x01;
        // body[12+name.Length .. 16+name.Length] already 0
        body[^2] = 0x64;
        // body[^1] already 0
        return body;
    }

    /// <summary>
    /// C[2] — 44-byte session-setup body sent immediately after login.
    /// Reqcode 0x0028 (SessionParams). Replayed verbatim from capture;
    /// internal field meanings not fully decoded but the server accepts it.
    /// </summary>
    public static readonly byte[] SessionSetupC2 =
    {
        0x00, 0x28, 0x00, 0x20, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
        0x00, 0x01, 0x00, 0x00, 0x00, 0x0F, 0x02, 0x00, 0x00, 0x00, 0x64, 0x00, 0x01, 0x00, 0x00, 0x00,
        0x01, 0x02, 0x00, 0x00, 0x00, 0x14, 0x00, 0x17, 0xF2, 0x43, 0x90, 0x00,
    };

    /// <summary>
    /// C[3] — 12-byte session-setup body sent after C[2], before catalog
    /// attach. Reqcode 0x0384. Replayed verbatim.
    /// </summary>
    public static readonly byte[] SessionSetupC3 =
    {
        0x00, 0x84, 0x03, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
    };

    /// <summary>
    /// C[5] — 20-byte trailing session-setup body, sent after catalog attach.
    /// Reqcode 0x0316. The trailing <c>49 4E 54 5F 43</c> ("INT_C") appears
    /// in every session capture; meaning not decoded, but the server accepts
    /// the literal bytes.
    /// </summary>
    public static readonly byte[] SessionSetupPost =
    {
        0x00, 0x16, 0x03, 0x08, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x49,
        0x4E, 0x54, 0x5F, 0x43,
    };

    // ---- SELECT / cursor flow ----

    /// <summary>
    /// Build the SELECT query body. Reqcode 0x0320 (PrepareStatement). The
    /// SQL is sent CRLF-terminated, twice-length-prefixed (Delphi
    /// <c>TStringField</c> convention). Inner pre/trail and outer trail are
    /// captured verbatim from the PoC and stable across all observed queries
    /// (matches MrsFlow <c>build_query_body</c>).
    /// </summary>
    public static byte[] BuildQuery(string sql)
    {
        var sqlBytes = Encoding.ASCII.GetBytes(sql + "\r\n");
        uint n = (uint)sqlBytes.Length;

        ReadOnlySpan<byte> innerPre = stackalloc byte[]
        {
            0x04, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00,
        };
        ReadOnlySpan<byte> innerTrail = stackalloc byte[]
        {
            0x01, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0x04, 0x00, 0x00,
            0x00, 0x01, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
        };
        ReadOnlySpan<byte> outerTrail = stackalloc byte[] { 0x00, 0x00, 0x00, 0x00, 0x00 };

        uint innerLen = (uint)(innerPre.Length + 8 + sqlBytes.Length + innerTrail.Length);
        var body = new byte[3 + 4 + innerLen + outerTrail.Length];
        body[0] = 0x00;
        body[1] = 0x20;
        body[2] = 0x03;
        BinaryPrimitives.WriteUInt32LittleEndian(body.AsSpan(3, 4), innerLen);
        int off = 7;
        innerPre.CopyTo(body.AsSpan(off, innerPre.Length)); off += innerPre.Length;
        BinaryPrimitives.WriteUInt32LittleEndian(body.AsSpan(off, 4), n); off += 4;
        BinaryPrimitives.WriteUInt32LittleEndian(body.AsSpan(off, 4), n); off += 4;
        sqlBytes.CopyTo(body, off); off += sqlBytes.Length;
        innerTrail.CopyTo(body.AsSpan(off, innerTrail.Length)); off += innerTrail.Length;
        outerTrail.CopyTo(body.AsSpan(off, outerTrail.Length));
        return body;
    }

    /// <summary>
    /// ExecuteStatement (reqcode 0x032A) — result-cursor flavour. Inner +23
    /// byte is 0x01 = "produces a result cursor" (SELECT). See
    /// DBISAM-PROTOCOL.md §7h.
    /// </summary>
    public static byte[] BuildExecuteStatement(uint cursorHandle)
    {
        return new MsgBuilder(Reqcode.ExecuteStatement)
            .PackU32(cursorHandle)
            .Pack(stackalloc byte[] { 0x00, 0x00 })
            .PackU8(0x00)
            .PackU8(0x01) // produces-cursor = true
            .PackU8(0x00)
            .PackU8(0x00)
            .Finish();
    }

    /// <summary>
    /// Receive (reqcode 0x030C). Polled during initial result-set transfer
    /// while the server is still materialising the cursor. Body is a single
    /// <c>[u32 len=1][0x00]</c> unit.
    /// </summary>
    public static byte[] BuildReceive()
        => new MsgBuilder(Reqcode.Receive).PackU8(0x00).Finish();

    /// <summary>
    /// SetToBegin (reqcode 0x00BE). Positions the cursor at the first row
    /// before the first ReadFirstRecordBlock.
    /// </summary>
    public static byte[] BuildSetToBegin(uint cursorHandle)
        => new MsgBuilder(Reqcode.SetToBegin).PackU32(cursorHandle).Finish();

    /// <summary>
    /// GetNextRecord (reqcode 0x00FA). Advances the cursor and returns up to
    /// <paramref name="counter"/> rows, each as
    /// <c>[u16 result_code][10 cursor-info units][slot]</c> where the slot is
    /// the row in physical-record-bookmark form (usable directly as the
    /// <c>0x0280</c> OpenBlob slot). This is the streaming blob-fetch driver —
    /// it lets the server advance through and free materialised rows as we go,
    /// avoiding the <c>0x2303</c> the batched path hits at scale. The
    /// <paramref name="bookmark"/> is echoed from the previous response's
    /// cursor-info (seed it from SetToBegin's response).
    /// Body: <c>cursor_handle u32 | bookmark | u8 0 | u8 0 | counter u32</c>.
    /// </summary>
    public static byte[] BuildGetNextRecord(uint cursorHandle, ReadOnlySpan<byte> bookmark, uint counter)
        => new MsgBuilder(Reqcode.GetNextRecord)
            .PackU32(cursorHandle)
            .Pack(bookmark)
            .PackU8(0x00)
            .PackU8(0x00)
            .PackU32(counter)
            .Finish();

    /// <summary>
    /// ReadFirstRecordBlock (reqcode 0x050A). Batched "position-at-start +
    /// read N records" — one round-trip returns up to <paramref name="maxRecords"/> rows.
    /// Body: <c>[cursor_handle u32][max_records u32]</c>.
    /// </summary>
    public static byte[] BuildReadFirstRecordBlock(uint cursorHandle, uint maxRecords)
    {
        return new MsgBuilder(Reqcode.ReadFirstRecordBlock)
            .PackU32(cursorHandle)
            .PackU32(maxRecords)
            .Finish();
    }

    /// <summary>
    /// ReadNextRecordBlock (reqcode 0x04F6). Batched "continue from current
    /// cursor position, read up to N more rows". Same body shape as
    /// ReadFirstRecordBlock. The cursor's position is tracked server-side.
    /// </summary>
    public static byte[] BuildReadNextRecordBlock(uint cursorHandle, uint maxRecords)
    {
        return new MsgBuilder(Reqcode.ReadNextRecordBlock)
            .PackU32(cursorHandle)
            .PackU32(maxRecords)
            .Finish();
    }

    /// <summary>
    /// CloseCursor (reqcode 0x00A0). Releases the server-side cursor and its
    /// backing temp table from a SELECT materialisation.
    /// </summary>
    public static byte[] BuildCloseCursor(uint cursorHandle)
        => new MsgBuilder(Reqcode.CloseCursor).PackU32(cursorHandle).Finish();

    /// <summary>
    /// ResetStatement (reqcode 0x0334). Finalises a statement after execution.
    /// Sent as part of the post-SELECT cleanup chain.
    /// </summary>
    public static byte[] BuildResetStatement(uint cursorHandle)
        => new MsgBuilder(Reqcode.ResetStatement).PackU32(cursorHandle).Finish();

    /// <summary>
    /// RemoveAllRemoteMemoryTables (reqcode 0x0029). Bulk-releases every
    /// server-side temp table backing materialised SELECT results in this
    /// session — empty inner body, just the reqcode. Required after every
    /// SELECT to keep <c>TDataTable.UseCount</c> from accumulating on the
    /// source table (see <c>KNOWN_BUGS.md</c> B3, fixed).
    /// </summary>
    public static byte[] BuildRemoveAllRemoteMemoryTables()
        => new MsgBuilder(Reqcode.RemoveAllRemoteMemoryTables).Finish();

    /// <summary>
    /// OpenBlob / blob-read (reqcode 0x0280). Fetches the actual content of a
    /// memo/blob/graphic column whose row data only carried an 8-byte handle.
    /// See protocol §6a. Ported from the working Rust reference
    /// (<c>exportmaster/msg.rs::build_open_blob</c>).
    ///
    /// Request layout (6 Pack units after the standard 7-byte header):
    /// <code>
    /// Pack [u32 cursor_handle]
    /// Pack [u16 field_ord]        1-based column ordinal of the blob field (2 bytes LE)
    /// Pack [slot]                 the row's physical-record bookmark — build via Blob.BuildSlot
    /// Pack [u8 force_reread]      0 = allow the server's cached buffer
    /// Pack [u8 is_physical]       0 = GetField path (vs GetPhysicalField)
    /// Pack [u8 0]                 vestigial; the official client always sends it
    /// </code>
    ///
    /// Note the slot carries the row's <em>physical record number</em>, not
    /// the column ordinal — those are distinct, and conflating them was the
    /// original 0x3A9A bug. The column ordinal travels only in the
    /// <paramref name="fieldOrd"/> unit.
    /// </summary>
    public static byte[] BuildOpenBlob(
        uint cursorHandle,
        ushort fieldOrd,
        ReadOnlySpan<byte> slot,
        byte forceReread = 0,
        byte isPhysical = 0)
    {
        Span<byte> fieldOrdBytes = stackalloc byte[2];
        BinaryPrimitives.WriteUInt16LittleEndian(fieldOrdBytes, fieldOrd);
        return new MsgBuilder(Reqcode.OpenBlob)
            .PackU32(cursorHandle)
            .Pack(fieldOrdBytes)
            .Pack(slot)
            .PackU8(forceReread)
            .PackU8(isPhysical)
            .PackU8(0)
            .Finish();
    }

    /// <summary>
    /// FreeBlob (reqcode 0x028A). Releases the server-side blob buffer after
    /// an OpenBlob read. 4 Pack units: <c>cursor_handle u32 | field_ord u16 |
    /// slot | u8 flag</c>. The <paramref name="slot"/> MUST be the
    /// <see cref="Blob.BlobFetchOutcome.SlotEcho"/> the server returned from
    /// OpenBlob — not the request slot. The server tags a few trailing slot
    /// bytes as an "open in cache" marker; FreeBlob has to present those exact
    /// bytes or the buffer is never found and the per-cursor blob cache fills
    /// up, eventually corrupting OpenBlob responses (<c>0x2303</c>).
    /// </summary>
    public static byte[] BuildFreeBlob(uint cursorHandle, ushort fieldOrd, ReadOnlySpan<byte> slot, byte flag = 0)
    {
        Span<byte> fieldOrdBytes = stackalloc byte[2];
        BinaryPrimitives.WriteUInt16LittleEndian(fieldOrdBytes, fieldOrd);
        return new MsgBuilder(Reqcode.FreeBlob)
            .PackU32(cursorHandle)
            .Pack(fieldOrdBytes)
            .Pack(slot)
            .PackU8(flag)
            .Finish();
    }

    /// <summary>
    /// FreeAllBlobs (reqcode 0x0294). Bulk-evicts every blob buffer in the
    /// cursor's blob cache. The per-cursor cache is capacity-bounded (~640
    /// entries observed) and <see cref="BuildFreeBlob"/> only decrements
    /// use-count without forcing eviction; periodic FreeAllBlobs keeps a bulk
    /// extract from filling the cache. Body: <c>cursor_handle u32 | u8 flag</c>.
    /// The streaming path doesn't need it (the cursor advance frees rows), but
    /// it's here for the batched path and parity with the reference.
    /// </summary>
    public static byte[] BuildFreeAllBlobs(uint cursorHandle, byte flag = 0)
        => new MsgBuilder(Reqcode.FreeAllBlobs).PackU32(cursorHandle).PackU8(flag).Finish();
}
