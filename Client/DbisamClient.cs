using System.Net.Sockets;
using System.Text;
using ExportKing.Protocol;

namespace ExportKing.Client;

/// <summary>
/// Options for opening a DBISAM session.
/// </summary>
public sealed class ConnectOptions
{
    public required string Host { get; init; }
    public int Port { get; init; } = 12005;
    public required string User { get; init; }
    public required string Password { get; init; }
    public string EncryptPassword { get; init; } = "elevatesoft";
    /// <summary>DBISAM catalog name attached during session setup.</summary>
    public string Catalog { get; init; } = "NISAINT_CS";
    /// <summary>Rows per ReadFirstRecordBlock / ReadNextRecordBlock call.</summary>
    public uint BatchSize { get; init; } = 5000;
    /// <summary>Hostname-suffix string sent in the Connect handshake (server doesn't validate strictly).</summary>
    public string ConnectHostname { get; init; } = "RIVSEM048692";
    /// <summary>Session nonce sent in the Connect handshake (server stores but doesn't echo).</summary>
    public uint ConnectNonce { get; init; } = 0xE5A21BE8;
}

/// <summary>
/// Result of a SELECT query: column descriptors plus the materialised rows
/// as <c>object?[]</c> (one entry per column, CLR-natural types).
/// </summary>
public sealed class QueryResult
{
    public required IReadOnlyList<Column> Columns { get; init; }
    public required IReadOnlyList<object?[]> Rows { get; init; }
    /// <summary>
    /// One 16-byte MD5 hash per row, in the same order as <see cref="Rows"/>.
    /// Forms part of the blob-fetch slot (see <see cref="Blob.BuildSlot"/>);
    /// surfaced here for callers that materialise blobs manually rather than
    /// via <c>Query(materializeBlobs: true)</c>.
    /// </summary>
    public required IReadOnlyList<byte[]> RowHashes { get; init; }
}

/// <summary>
/// An open, logged-in DBISAM session. One <see cref="DbisamClient"/> per
/// query for now (matches the Rust reference and the existing
/// <c>OdbcConnection</c> lifecycle).
/// </summary>
public sealed class DbisamClient : IDisposable
{
    private readonly TcpClient _client;
    private readonly NetworkStream _stream;
    private readonly ConnectOptions _opts;
    private bool _disposed;

    private DbisamClient(TcpClient client, NetworkStream stream, ConnectOptions opts)
    {
        _client = client;
        _stream = stream;
        _opts = opts;
    }

    /// <summary>The underlying network stream. Internal — used by tests that need to drive the protocol manually.</summary>
    internal Stream Stream => _stream;

    /// <summary>
    /// Open a TCP connection, run the Connect+Login+session-setup handshake,
    /// and return a ready-for-queries client.
    /// </summary>
    public static DbisamClient ConnectAndLogin(ConnectOptions opts)
    {
        var tcp = Framing.Connect(opts.Host, opts.Port);
        try
        {
            var stream = tcp.GetStream();

            // Connect.
            var connectBody = Messages.BuildConnect(opts.ConnectHostname, opts.ConnectNonce);
            _ = Framing.SendRecv(stream, connectBody);

            // Login. The server signals a rejected login by echoing the
            // DBISAM error code (e.g. 0x2C17) as the body reqcode — fail
            // here rather than as a baffling schema error on the first query.
            var ct = Crypto.EncryptLogin(
                Encoding.ASCII.GetBytes(opts.User),
                Encoding.ASCII.GetBytes(opts.Password),
                Encoding.ASCII.GetBytes(opts.EncryptPassword));
            var loginResp = Framing.SendRecv(stream, Messages.BuildLogin(ct));
            if (Response.TryGetServerError(loginResp, out var loginCode, out _))
            {
                throw new IOException(
                    $"Exportmaster: login failed for user '{opts.User}' (server code 0x{loginCode:X4})");
            }

            // Session setup.
            _ = Framing.SendRecv(stream, Messages.SessionSetupC2);
            _ = Framing.SendRecv(stream, Messages.SessionSetupC3);
            var attachResp = Framing.SendRecv(stream, Messages.BuildCatalogAttach(opts.Catalog));
            if (Response.TryGetServerError(attachResp, out var attachCode, out var attachDetail))
            {
                throw new IOException(
                    $"Exportmaster: catalog attach failed: '{(attachDetail.Length > 0 ? attachDetail : opts.Catalog)}' " +
                    $"(server code 0x{attachCode:X4})");
            }
            _ = Framing.SendRecv(stream, Messages.SessionSetupPost);

            return new DbisamClient(tcp, stream, opts);
        }
        catch
        {
            // Failed logins are routine; don't leak the socket to the finalizer.
            tcp.Dispose();
            throw;
        }
    }

    /// <summary>
    /// Issue a SELECT and return the raw schema-bearing first response.
    /// Use for debugging when <see cref="Query"/> fails to parse.
    /// </summary>
    public byte[] QueryRaw(string sql)
        => Framing.SendRecv(_stream, Messages.BuildQuery(sql));

    /// <summary>
    /// Run a SELECT and return the full materialised result. The cleanup
    /// chain (CloseCursor → ResetStatement → RemoveAllRemoteMemoryTables)
    /// runs unconditionally so a subsequent query on the same session works.
    ///
    /// When <paramref name="materializeBlobs"/> is true and the result has any
    /// memo/blob/graphic column, the query streams via <c>GetNextRecord</c>
    /// (0x00FA) and resolves each non-zero handle inline (OpenBlob + FreeBlob
    /// per row) — Memo cells become <see cref="string"/>, Blob/Graphic cells
    /// become <see cref="byte"/>[]. Streaming (rather than the batched
    /// ReadRecordBlock path) is required at scale: the batched path
    /// materialises every row up front and the server returns <c>0x2303</c>
    /// once the OpenBlob count climbs past a few hundred. Non-blob queries use
    /// the faster batched path unchanged.
    /// </summary>
    public QueryResult Query(string sql, bool materializeBlobs = false, int targetRows = int.MaxValue)
    {
        var schemaResp = QueryRaw(sql);
        List<Column> columns;
        var rows = new List<object?[]>();
        var rowHashes = new List<byte[]>();
        // The statement is prepared server-side once QueryRaw returns, so the
        // cleanup chain in the finally must also cover a schema-parse failure
        // — otherwise the orphaned statement leaks on the server.
        try
        {
            try
            {
                columns = Schema.Parse(schemaResp).Columns;
            }
            catch (IOException ex)
            {
                if (Response.TryGetServerError(schemaResp, out var code, out var detail))
                {
                    throw new IOException(
                        $"Exportmaster: server rejected the statement (code 0x{code:X4}" +
                        $"{(detail.Length > 0 ? $": '{detail}'" : "")})", ex);
                }
                var head = schemaResp.AsSpan(0, Math.Min(256, schemaResp.Length));
                throw new IOException(
                    $"{ex.Message} (response: {schemaResp.Length} bytes, " +
                    $"reqcode=0x{Response.BodyReqcode(schemaResp):X4}, " +
                    $"first {head.Length} bytes: {Convert.ToHexString(head)})", ex);
            }

            bool hasBlobs = materializeBlobs && columns.Any(c =>
                c.FieldType is FieldType.Blob or FieldType.Memo or FieldType.Graphic);

            if (hasBlobs)
            {
                DriveStreamingWithBlobs(columns, targetRows, rows, rowHashes);
            }
            else
            {
                Cursor.DriveCursor(_stream, columns, targetRows, _opts.BatchSize, (fullRecord, _) =>
                {
                    rows.Add(Row.DecodeRecord(fullRecord, columns));
                    rowHashes.Add(Row.ExtractRecordHash(fullRecord));
                });
            }
        }
        finally
        {
            try { _ = Framing.SendRecv(_stream, Messages.BuildCloseCursor(Cursor.CursorHandle)); } catch { }
            try { _ = Framing.SendRecv(_stream, Messages.BuildResetStatement(Cursor.CursorHandle)); } catch { }
            try { _ = Framing.SendRecv(_stream, Messages.BuildRemoveAllRemoteMemoryTables()); } catch { }
        }

        return new QueryResult { Columns = columns, Rows = rows, RowHashes = rowHashes };
    }

    /// <summary>
    /// Stream rows via <c>GetNextRecord</c> (0x00FA), resolving blob columns
    /// inline. Mirrors the Rust reference's <c>query_to_table_streaming</c>.
    /// Each GetNextRecord response packs multiple rows, each as
    /// <c>[u16 result_code][10 cursor-info units][slot]</c>; the slot is the
    /// row in physical-record-bookmark form, usable directly as the OpenBlob
    /// slot (so no phys reconstruction is needed). The last row's bookmark
    /// seeds the next GetNextRecord; the loop ends on result_code 0x2202.
    ///
    /// Assumes <see cref="QueryRaw"/> already prepared the statement.
    /// </summary>
    private void DriveStreamingWithBlobs(
        IReadOnlyList<Column> columns, int targetRows,
        List<object?[]> rows, List<byte[]> rowHashes)
    {
        bool debug = Environment.GetEnvironmentVariable("EM_BLOB_DEBUG") is not null;
        int firstOff = columns[0].RowOffset;
        int colEndOffset = Cursor.ComputeRecordSize(columns);
        const uint handle = Cursor.CursorHandle;

        // Phase 1: ExecuteStatement + Receive poll until the cursor materialises.
        var resp = Framing.SendRecv(_stream, Messages.BuildExecuteStatement(handle));
        for (int polls = 0; IsNotReady(resp); polls++)
        {
            if (polls >= Cursor.MaxReceivePolls)
                throw new IOException($"Exportmaster: cursor still 'not ready' after {polls} Receive polls");
            resp = Framing.SendRecv(_stream, Messages.BuildReceive());
        }

        // Phase 2: SetToBegin. Its response carries the first row's bookmark in
        // cursor-info — and, unlike GetNextRecord, has NO leading result-code
        // unit, so the 10 cursor-info units start at PackStreamOffset.
        var setBeginResp = Framing.SendRecv(_stream, Messages.BuildSetToBegin(handle));
        byte[] nextBookmark = CursorInfo.Read(new Walker(setBeginResp, Response.PackStreamOffset)).Bookmark;

        // Phase 3: GetNextRecord loop.
        uint requestBatch = Math.Clamp(_opts.BatchSize, 1u, 50u); // ODBC uses ~50
        while (rows.Count < targetRows)
        {
            var body = Messages.BuildGetNextRecord(handle, nextBookmark, requestBatch);
            var batchResp = Framing.SendRecv(_stream, body);
            var walker = new Walker(batchResp, Response.PackStreamOffset);
            bool gotEoc = false;
            int rowsInBatch = 0;

            while (rows.Count < targetRows)
            {
                // A GetNextRecord response can end with a trailing partial
                // unit; like the reference, break on any read error or clean
                // exhaustion (the next GetNextRecord starts a fresh response).
                ReadOnlyMemory<byte>? rcUnit, slotUnit;
                CursorInfo cursorInfo;
                try
                {
                    rcUnit = walker.NextUnit();
                    if (rcUnit is null || rcUnit.Value.Length != 2) break;
                    ushort resultCode = System.Buffers.Binary.BinaryPrimitives.ReadUInt16LittleEndian(rcUnit.Value.Span);
                    if (resultCode == Response.ResultEndOfCursor) { gotEoc = true; break; }
                    if (resultCode != Response.ResultOk) break;

                    cursorInfo = CursorInfo.Read(walker);
                    slotUnit = walker.NextUnit();
                }
                catch (IOException) { break; }
                if (slotUnit is null || slotUnit.Value.Length < colEndOffset) break;
                var slot = slotUnit.Value.ToArray();

                var cells = Row.DecodeRecord(slot, columns);
                for (int i = 0; i < columns.Count; i++)
                {
                    var ft = columns[i].FieldType;
                    if (ft is not (FieldType.Blob or FieldType.Memo or FieldType.Graphic)) continue;
                    if (cells[i] is not byte[] h || h.Length != 8 || h.All(b => b == 0)) { cells[i] = null; continue; }

                    var fieldOrd = (ushort)(i + 1);
                    var outcome = FetchBlob(fieldOrd, slot);
                    if (debug)
                    {
                        Console.Error.WriteLine(
                            $"[em-blob] row={rows.Count} col={i} field_ord={fieldOrd} " +
                            $"-> payload={outcome?.Payload.Length.ToString() ?? "null"} " +
                            $"server_slot_len={outcome?.ActualSlotLength.ToString() ?? "null"}");
                    }
                    if (outcome is null)
                    {
                        throw new IOException(
                            $"Exportmaster: OpenBlob returned no payload for row {rows.Count} " +
                            $"col {i} (field_ord={fieldOrd}) — likely a server error reqcode (e.g. 0x2303/0x3A9A).");
                    }
                    // Free the server-side buffer using the ECHOED slot bytes,
                    // or the per-cursor blob cache fills and OpenBlob starts
                    // returning 0x2303.
                    try { _ = Framing.SendRecv(_stream, Messages.BuildFreeBlob(handle, fieldOrd, outcome.SlotEcho)); }
                    catch (Exception e)
                    {
                        if (debug) Console.Error.WriteLine($"[em-blob] FreeBlob row={rows.Count} col={i} FAIL: {e.Message}");
                    }

                    cells[i] = ft == FieldType.Memo ? DbisamText.Decode(outcome.Payload) : outcome.Payload;
                }

                rows.Add(cells);
                rowHashes.Add(Row.ExtractRecordHash(slot));
                nextBookmark = cursorInfo.Bookmark;
                rowsInBatch++;
            }

            if (gotEoc) break;
            if (rowsInBatch == 0)
            {
                throw new IOException(
                    "Exportmaster: GetNextRecord delivered no rows and no end-of-cursor " +
                    "— refusing to return a silently truncated result set");
            }
        }
    }

    /// <summary>
    /// True if a response is the "cursor not ready, poll again" status — either
    /// the body-header polling sentinel or an inner <c>RESULT_NOT_READY</c>.
    /// </summary>
    private static bool IsNotReady(byte[] body)
    {
        if (Response.BodyReqcode(body) == Response.PollingSentinelReqcode) return true;
        int p = Response.PackStreamOffset;
        if (body.Length < p + 6) return false;
        if (System.Buffers.Binary.BinaryPrimitives.ReadUInt32LittleEndian(body.AsSpan(p, 4)) != 2) return false;
        return System.Buffers.Binary.BinaryPrimitives.ReadUInt16LittleEndian(body.AsSpan(p + 4, 2)) == Response.ResultNotReady;
    }

    /// <summary>
    /// Fetch the content of one memo/blob/graphic column for one row. Sends an
    /// <c>OpenBlob (0x0280)</c> request and parses the 3-unit response.
    /// <paramref name="fieldOrd"/> is the blob column's 1-based ordinal (see
    /// <see cref="Column.Ord"/>); <paramref name="slot"/> is the row's
    /// physical-record bookmark from <see cref="Blob.BuildSlot"/>.
    ///
    /// Returns the parsed outcome (payload + the server's expected slot
    /// length), or null if the response wasn't a recognisable blob reply
    /// (server returned an error reqcode).
    /// </summary>
    public Blob.BlobFetchOutcome? FetchBlob(ushort fieldOrd, ReadOnlySpan<byte> slot)
    {
        var req = Messages.BuildOpenBlob(Cursor.CursorHandle, fieldOrd, slot);
        var resp = Framing.SendRecv(_stream, req);
        return Blob.ParseOpenBlobResponse(resp);
    }

    /// <summary>
    /// Like <see cref="FetchBlob"/> but returns the full raw response bytes —
    /// used for debugging when the parsed outcome comes back null.
    /// </summary>
    internal byte[] FetchBlobRaw(ushort fieldOrd, ReadOnlySpan<byte> slot)
    {
        var req = Messages.BuildOpenBlob(Cursor.CursorHandle, fieldOrd, slot);
        return Framing.SendRecv(_stream, req);
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        try { _stream.Dispose(); } catch { }
        try { _client.Dispose(); } catch { }
    }
}
