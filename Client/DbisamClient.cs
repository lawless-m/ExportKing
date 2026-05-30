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
    /// Required as input to <see cref="DbisamClient.FetchBlob"/> — the hash
    /// disambiguates which row's blob to fetch on the server.
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
        var stream = tcp.GetStream();

        // Connect.
        var connectBody = Messages.BuildConnect(opts.ConnectHostname, opts.ConnectNonce);
        _ = Framing.SendRecv(stream, connectBody);

        // Login.
        var ct = Crypto.EncryptLogin(
            Encoding.ASCII.GetBytes(opts.User),
            Encoding.ASCII.GetBytes(opts.Password),
            Encoding.ASCII.GetBytes(opts.EncryptPassword));
        _ = Framing.SendRecv(stream, Messages.BuildLogin(ct));

        // Session setup.
        _ = Framing.SendRecv(stream, Messages.SessionSetupC2);
        _ = Framing.SendRecv(stream, Messages.SessionSetupC3);
        _ = Framing.SendRecv(stream, Messages.BuildCatalogAttach(opts.Catalog));
        _ = Framing.SendRecv(stream, Messages.SessionSetupPost);

        return new DbisamClient(tcp, stream, opts);
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
    /// When <paramref name="materializeBlobs"/> is true, each memo/blob/graphic
    /// column with a non-zero handle is fetched inline before cleanup — Memo
    /// cells become <see cref="string"/>, Blob/Graphic cells become <see cref="byte"/>[].
    /// Blob fetch requires an open cursor (server-side), so it has to happen
    /// before the CloseCursor in the cleanup chain.
    /// </summary>
    public QueryResult Query(string sql, bool materializeBlobs = false, int targetRows = int.MaxValue)
    {
        if (materializeBlobs)
        {
            // Blob fetch is implemented at the byte level (BuildOpenBlob
            // matches the DBSYS capture exactly — see OpenBlobMatchesCaptureTest)
            // but the surrounding cursor preamble needed to make the server
            // accept it (and accept GetNextRecord on the same cursor) hasn't
            // been pinned down yet. See PLAN.md phase 9 for the open work.
            throw new NotImplementedException(
                "materializeBlobs=true is not yet wired end-to-end. The OpenBlob " +
                "request bytes are correct but the surrounding cursor state isn't. " +
                "See PLAN.md and FetchBlob_DbsysSequence_Probe in the integration tests.");
        }

        var schemaResp = QueryRaw(sql);
        List<Column> columns;
        try
        {
            columns = Schema.Parse(schemaResp).Columns;
        }
        catch (IOException ex)
        {
            var head = schemaResp.AsSpan(0, Math.Min(256, schemaResp.Length));
            throw new IOException(
                $"{ex.Message} (response: {schemaResp.Length} bytes, " +
                $"reqcode=0x{Response.BodyReqcode(schemaResp):X4}, " +
                $"first {head.Length} bytes: {Convert.ToHexString(head)})", ex);
        }

        var rows = new List<object?[]>();
        var rowHashes = new List<byte[]>();
        try
        {
            Cursor.DriveCursor(_stream, columns, targetRows, _opts.BatchSize, fullRecord =>
            {
                var cells = Row.DecodeRecord(fullRecord, columns);
                var hash = Row.ExtractRecordHash(fullRecord);
                if (materializeBlobs)
                {
                    MaterializeBlobsInPlace(cells, columns, hash);
                }
                rows.Add(cells);
                rowHashes.Add(hash);
            });
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
    /// Replace each blob/memo cell's 8-byte handle with the actual content.
    /// Assumes the first column is the PK (DBISAM convention per §6a impl note).
    /// </summary>
    private void MaterializeBlobsInPlace(object?[] cells, IReadOnlyList<Column> columns, byte[] hash)
    {
        if (cells.Length == 0 || cells[0] is not string pkStr) return;
        var pkBytes = Encoding.ASCII.GetBytes(pkStr);
        for (int i = 0; i < columns.Count; i++)
        {
            if (cells[i] is not byte[] handle || handle.Length != 8 || handle.All(b => b == 0)) continue;
            var ft = columns[i].FieldType;
            if (ft != FieldType.Memo && ft != FieldType.Blob && ft != FieldType.Graphic) continue;

            var blob = FetchBlob((uint)columns[i].Ord, hash, pkBytes);
            if (blob is null) continue;

            cells[i] = ft == FieldType.Memo ? Encoding.ASCII.GetString(blob) : (object)blob;
        }
    }

    /// <summary>
    /// Fetch the actual content of a memo/blob/graphic column for one row.
    /// Sends an <c>OpenBlob (0x0280)</c> request and parses the payload out
    /// of the response. Caller supplies the column ordinal (1-based — see
    /// <see cref="Column.Ord"/>), the row's MD5 hash (from
    /// <see cref="Row.ExtractRecordHash"/> or <see cref="QueryResult.RowHashes"/>),
    /// and the row's PK bytes (typically the first column's value).
    ///
    /// Returns the blob bytes, or null if the response didn't contain a
    /// recognisable blob payload (server returned an error reqcode).
    /// </summary>
    public byte[]? FetchBlob(uint colOrdinal, ReadOnlySpan<byte> rowMd5, ReadOnlySpan<byte> primaryKey)
    {
        var req = Messages.BuildOpenBlob(Cursor.CursorHandle, colOrdinal, rowMd5, primaryKey);
        var resp = Framing.SendRecv(_stream, req);
        return ExtractBlobPayload(resp);
    }

    /// <summary>
    /// Like <see cref="FetchBlob"/> but also returns the full raw response
    /// bytes — used for debugging when the parsed payload comes back null.
    /// </summary>
    internal byte[] FetchBlobRaw(uint colOrdinal, ReadOnlySpan<byte> rowMd5, ReadOnlySpan<byte> primaryKey)
    {
        var req = Messages.BuildOpenBlob(Cursor.CursorHandle, colOrdinal, rowMd5, primaryKey);
        return Framing.SendRecv(_stream, req);
    }

    /// <summary>The same request the client would send for the given blob handle. Exposed for debugging.</summary>
    internal static byte[] DebugBuildOpenBlob(uint colOrdinal, ReadOnlySpan<byte> rowMd5, ReadOnlySpan<byte> pk)
        => Messages.BuildOpenBlob(Cursor.CursorHandle, colOrdinal, rowMd5, pk);

    /// <summary>
    /// Walk the body's Pack stream and find the largest unit whose first
    /// 4 bytes look like a Delphi double-length prefix ([u32 actual][u32 max]
    /// where actual == max). Per protocol §6a: "somewhere in the body the
    /// blob payload appears as Delphi-style length-prefixed".
    /// </summary>
    private static byte[]? ExtractBlobPayload(byte[] body)
    {
        if (body.Length < Response.PackStreamOffset) return null;
        // Error reqcodes: 0x2EAD (SQL parse), 0x2B02/0x2B05 (DDL/exec), etc.
        // We can't enumerate them all; if no blob unit found, return null.
        var walker = new Walker(body, Response.PackStreamOffset);
        byte[]? best = null;
        while (true)
        {
            ReadOnlyMemory<byte>? unit;
            try { unit = walker.NextUnit(); } catch (IOException) { break; }
            if (unit is null) break;
            var u = unit.Value;
            // A blob unit's first 8 bytes are [u32 actual_len][u32 max_len]
            // with actual_len == max_len. Total unit size = 8 + actual_len.
            if (u.Length >= 8)
            {
                uint actual = System.Buffers.Binary.BinaryPrimitives.ReadUInt32LittleEndian(u.Span.Slice(0, 4));
                uint max = System.Buffers.Binary.BinaryPrimitives.ReadUInt32LittleEndian(u.Span.Slice(4, 4));
                if (actual == max && actual > 0 && 8 + actual == u.Length)
                {
                    var content = u.Span.Slice(8, (int)actual).ToArray();
                    if (best is null || content.Length > best.Length) best = content;
                }
            }
        }
        return best;
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        try { _stream.Dispose(); } catch { }
        try { _client.Dispose(); } catch { }
    }
}
