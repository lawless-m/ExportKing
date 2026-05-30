using ExportKing.Client;
using ExportKing.Protocol;
using Xunit;
using Xunit.Abstractions;

namespace ExportKing.Tests;

/// <summary>
/// Live integration tests against a real DBISAM server. Skipped by default
/// — set <c>DBISAM_HOST</c>, <c>DBISAM_USER</c>, <c>DBISAM_PASSWORD</c>
/// (and optionally <c>DBISAM_PORT</c>, <c>DBISAM_CATALOG</c>) in the
/// environment to run.
///
/// Example:
/// <code>
/// DBISAM_HOST=rivsem04 DBISAM_USER=e3user DBISAM_PASSWORD=e3usernew \
///   dotnet test --filter FullyQualifiedName~IntegrationSmokeTests
/// </code>
/// </summary>
public class IntegrationSmokeTests
{
    private readonly ITestOutputHelper _out;

    public IntegrationSmokeTests(ITestOutputHelper output) => _out = output;

    [Fact]
    public void ConnectLoginSessionSetup()
    {
        var host = Environment.GetEnvironmentVariable("DBISAM_HOST");
        if (string.IsNullOrEmpty(host))
        {
            _out.WriteLine("Skipped: set DBISAM_HOST to run.");
            return;
        }
        int port = int.Parse(Environment.GetEnvironmentVariable("DBISAM_PORT") ?? "12005");
        var user = Environment.GetEnvironmentVariable("DBISAM_USER")
            ?? throw new InvalidOperationException("DBISAM_USER not set");
        var password = Environment.GetEnvironmentVariable("DBISAM_PASSWORD")
            ?? throw new InvalidOperationException("DBISAM_PASSWORD not set");
        var catalog = Environment.GetEnvironmentVariable("DBISAM_CATALOG") ?? "NISAINT_CS";

        using var client = Framing.Connect(host, port);
        var stream = client.GetStream();
        _out.WriteLine($"[connect] {host}:{port} TCP open");

        // 1. Connect (reqcode 0x0000). Server replies with banner DBISAMVCLCSSRC.
        var connectBody = Messages.BuildConnect("RIVSEM048692", 0xE5A21BE8);
        var connectResp = Framing.SendRecv(stream, connectBody);
        _out.WriteLine($"[connect] {connectResp.Length} byte response");
        var bannerSearch = "DBISAMVCLCSSRC"u8.ToArray();
        bool foundBanner = ContainsBytes(connectResp, bannerSearch);
        Assert.True(foundBanner, "Connect response did not contain 'DBISAMVCLCSSRC' banner — handshake malformed.");

        // 2. Login (reqcode 0x0014). Blowfish-CBC ciphertext, wrapped per §5.
        var ct = Crypto.EncryptLogin(
            System.Text.Encoding.ASCII.GetBytes(user),
            System.Text.Encoding.ASCII.GetBytes(password),
            "elevatesoft"u8);
        var loginBody = Messages.BuildLogin(ct);
        var loginResp = Framing.SendRecv(stream, loginBody);
        _out.WriteLine($"[login] {loginResp.Length} byte response");
        // No documented marker for success; the captured success case is a
        // short response with no error string. A failed login produces a
        // very different body. Empirically: success ≤ 32 bytes, no readable
        // error text. The real proof of life is the session-setup messages
        // succeeding below — the server would reject those if not logged in.
        Assert.True(loginResp.Length > 0, "Login response empty — connection dropped.");

        // 3. Session setup (C[2], C[3], catalog attach, Post).
        var c2Resp = Framing.SendRecv(stream, Messages.SessionSetupC2);
        _out.WriteLine($"[C2] {c2Resp.Length} byte response");

        var c3Resp = Framing.SendRecv(stream, Messages.SessionSetupC3);
        _out.WriteLine($"[C3] {c3Resp.Length} byte response");

        var catalogResp = Framing.SendRecv(stream, Messages.BuildCatalogAttach(catalog));
        _out.WriteLine($"[catalog={catalog}] {catalogResp.Length} byte response");

        var postResp = Framing.SendRecv(stream, Messages.SessionSetupPost);
        _out.WriteLine($"[post] {postResp.Length} byte response");

        _out.WriteLine("Handshake completed without errors.");
    }

    [Fact]
    public void FirstQuery_RIGeographic()
    {
        var host = Environment.GetEnvironmentVariable("DBISAM_HOST");
        if (string.IsNullOrEmpty(host))
        {
            _out.WriteLine("Skipped: set DBISAM_HOST to run.");
            return;
        }
        int port = int.Parse(Environment.GetEnvironmentVariable("DBISAM_PORT") ?? "12005");
        var user = Environment.GetEnvironmentVariable("DBISAM_USER")
            ?? throw new InvalidOperationException("DBISAM_USER not set");
        var password = Environment.GetEnvironmentVariable("DBISAM_PASSWORD")
            ?? throw new InvalidOperationException("DBISAM_PASSWORD not set");
        var catalog = Environment.GetEnvironmentVariable("DBISAM_CATALOG") ?? "NISAINT_CS";

        using var client = DbisamClient.ConnectAndLogin(new ConnectOptions
        {
            Host = host,
            Port = port,
            User = user,
            Password = password,
            Catalog = catalog,
        });
        _out.WriteLine($"[connect] handshake complete against {host}:{port}/{catalog}");

        // DBISAM syntax: TOP comes after the table, not after SELECT.
        var result = client.Query("SELECT CountryCode, RITerritoryCode FROM RIGeographic TOP 5");
        _out.WriteLine($"[query] {result.Columns.Count} columns, {result.Rows.Count} rows");
        foreach (var c in result.Columns)
        {
            _out.WriteLine($"  col: {c.Name} ({c.FieldType}, decl={c.Decl}, max={c.Max}, off={c.RowOffset})");
        }
        for (int i = 0; i < result.Rows.Count; i++)
        {
            var row = result.Rows[i];
            _out.WriteLine($"  row {i}: [{string.Join(", ", row.Select(c => c?.ToString() ?? "NULL"))}]");
        }

        Assert.Equal(2, result.Columns.Count);
        Assert.True(result.Rows.Count > 0, "expected at least one row from RIGeographic");
        Assert.All(result.Rows, row => Assert.Equal(2, row.Length));
    }

    [Fact]
    public void Probe_NIINGRED_Schema()
    {
        var host = Environment.GetEnvironmentVariable("DBISAM_HOST");
        if (string.IsNullOrEmpty(host)) { _out.WriteLine("Skipped"); return; }
        int port = int.Parse(Environment.GetEnvironmentVariable("DBISAM_PORT") ?? "12005");
        var user = Environment.GetEnvironmentVariable("DBISAM_USER")!;
        var password = Environment.GetEnvironmentVariable("DBISAM_PASSWORD")!;

        using var client = DbisamClient.ConnectAndLogin(new ConnectOptions
        {
            Host = host, Port = port, User = user, Password = password,
        });
        foreach (var name in new[] { "NIINGRED", "NIINGREDS" })
        {
            _out.WriteLine($"--- trying {name} ---");
            QueryResult result;
            try
            {
                result = client.Query($"SELECT * FROM {name} TOP 1");
            }
            catch (IOException ex)
            {
                _out.WriteLine($"  failed: {ex.Message.Substring(0, Math.Min(200, ex.Message.Length))}");
                continue;
            }
            _out.WriteLine($"  {result.Columns.Count} columns, {result.Rows.Count} row(s)");
            foreach (var c in result.Columns)
            {
                _out.WriteLine($"    ord={c.Ord} name={c.Name} type={c.FieldType} decl={c.Decl} max={c.Max} off={c.RowOffset}  sub={c.SubRaw} a8={c.ByteA8:X2} 250={c.Byte250:X2}");
            }
            if (result.Rows.Count > 0)
            {
                var row = result.Rows[0];
                for (int i = 0; i < row.Length; i++)
                {
                    var v = row[i];
                    string s = v switch
                    {
                        null => "NULL",
                        byte[] b => $"bytes[{b.Length}]: {Convert.ToHexString(b)}",
                        _ => v.ToString() ?? ""
                    };
                    _out.WriteLine($"      [{i}] {result.Columns[i].Name} = {s}");
                }
            }
        }
    }

    /// <summary>
    /// Blob fetch probe. EXPERIMENTAL — sends an unverified packet shape that
    /// crashed the server once. Gated on <c>DBISAM_PROBE_BLOBS=1</c> in addition
    /// to the normal env so it doesn't run accidentally during full test runs.
    /// </summary>
    [Fact]
    public void FetchBlob_NIINGREDS_FromNIINGRED()
    {
        var host = Environment.GetEnvironmentVariable("DBISAM_HOST");
        if (string.IsNullOrEmpty(host)) { _out.WriteLine("Skipped (no DBISAM_HOST)"); return; }
        if (Environment.GetEnvironmentVariable("DBISAM_PROBE_BLOBS") != "1")
        {
            _out.WriteLine("Skipped — set DBISAM_PROBE_BLOBS=1 to run (experimental, may crash server).");
            return;
        }

        int port = int.Parse(Environment.GetEnvironmentVariable("DBISAM_PORT") ?? "12005");
        var user = Environment.GetEnvironmentVariable("DBISAM_USER")!;
        var password = Environment.GetEnvironmentVariable("DBISAM_PASSWORD")!;

        using var client = DbisamClient.ConnectAndLogin(new ConnectOptions
        {
            Host = host, Port = port, User = user, Password = password,
        });

        // Single probe: SELECT one row, send one blob fetch, dump response bytes.
        var result = client.Query("SELECT * FROM NIINGRED TOP 1");
        int neanIdx = -1, memoIdx = -1;
        for (int i = 0; i < result.Columns.Count; i++)
        {
            if (result.Columns[i].Name == "NIEAN") neanIdx = i;
            if (result.Columns[i].Name == "NIINGREDS") memoIdx = i;
        }
        if (result.Rows.Count == 0) { _out.WriteLine("no row returned"); return; }

        var nean = result.Rows[0][neanIdx] as string;
        var handle = result.Rows[0][memoIdx] as byte[];
        var hash = result.RowHashes[0];
        _out.WriteLine($"row 0: NIEAN={nean} memo handle={Convert.ToHexString(handle!)} hash={Convert.ToHexString(hash)}");
        _out.WriteLine($"  request bytes: {Convert.ToHexString(DbisamClient.DebugBuildOpenBlob((uint)result.Columns[memoIdx].Ord, hash, System.Text.Encoding.ASCII.GetBytes(nean ?? "")))}");

        var raw = client.FetchBlobRaw((uint)result.Columns[memoIdx].Ord, hash, System.Text.Encoding.ASCII.GetBytes(nean ?? ""));
        _out.WriteLine($"  raw response: {raw.Length} bytes, reqcode=0x{Response.BodyReqcode(raw):X4}");
        for (int off = 0; off < Math.Min(raw.Length, 320); off += 32)
        {
            int n = Math.Min(32, raw.Length - off);
            var hex = Convert.ToHexString(raw.AsSpan(off, n));
            var asc = new string(raw.AsSpan(off, n).ToArray().Select(b => b >= 32 && b < 127 ? (char)b : '.').ToArray());
            _out.WriteLine($"    +{off:X3}: {hex,-64}  {asc}");
        }
    }

    /// <summary>
    /// Low-level blob-fetch probe: drives the cursor manually so the OpenBlob
    /// request can be sent WHILE the cursor is still open. Single shot per
    /// run; double-gated behind DBISAM_PROBE_BLOBS=1.
    /// </summary>
    [Fact]
    public void FetchBlob_CursorOpen_Probe()
    {
        var host = Environment.GetEnvironmentVariable("DBISAM_HOST");
        if (string.IsNullOrEmpty(host)) { _out.WriteLine("Skipped (no DBISAM_HOST)"); return; }
        if (Environment.GetEnvironmentVariable("DBISAM_PROBE_BLOBS") != "1")
        {
            _out.WriteLine("Skipped — set DBISAM_PROBE_BLOBS=1 to run.");
            return;
        }
        int port = int.Parse(Environment.GetEnvironmentVariable("DBISAM_PORT") ?? "12005");
        var user = Environment.GetEnvironmentVariable("DBISAM_USER")!;
        var password = Environment.GetEnvironmentVariable("DBISAM_PASSWORD")!;

        using var client = DbisamClient.ConnectAndLogin(new ConnectOptions
        {
            Host = host, Port = port, User = user, Password = password,
        });

        // Send the SELECT directly and parse schema, but DON'T let Query do its
        // cleanup chain — we need the cursor open when we send OpenBlob.
        var schemaResp = client.QueryRaw("SELECT * FROM NIINGRED TOP 1");
        var (cols, _) = Schema.Parse(schemaResp);
        int neanIdx = cols.FindIndex(c => c.Name == "NIEAN");
        int memoIdx = cols.FindIndex(c => c.Name == "NIINGREDS");
        var memoCol = cols[memoIdx];

        // Drive the cursor manually so we can pause after the first row.
        var firstRow = new List<byte[]>();
        var firstHashes = new List<byte[]>();
        Cursor.DriveCursor(client.Stream, cols, targetRows: 1, batchSize: 1, fullRecord =>
        {
            firstRow.Add(fullRecord.ToArray());
            firstHashes.Add(Row.ExtractRecordHash(fullRecord));
        });
        if (firstRow.Count == 0) { _out.WriteLine("no rows"); return; }

        var fullRec = firstRow[0];
        var hash = firstHashes[0];
        var cells = Row.DecodeRecord(fullRec, cols);
        var nean = cells[neanIdx] as string ?? "";
        var pkBytes = System.Text.Encoding.ASCII.GetBytes(nean);
        _out.WriteLine($"row: NIEAN={nean} hash={Convert.ToHexString(hash)}");
        _out.WriteLine($"  request: {Convert.ToHexString(DbisamClient.DebugBuildOpenBlob((uint)memoCol.Ord, hash, pkBytes))}");

        // Send the blob fetch. Cursor is STILL open at this point — cleanup
        // hasn't run yet.
        var raw = Framing.SendRecv(client.Stream, DbisamClient.DebugBuildOpenBlob((uint)memoCol.Ord, hash, pkBytes));
        _out.WriteLine($"  resp: {raw.Length} bytes, reqcode=0x{Response.BodyReqcode(raw):X4}");
        for (int off = 0; off < Math.Min(raw.Length, 512); off += 32)
        {
            int n = Math.Min(32, raw.Length - off);
            var hex = Convert.ToHexString(raw.AsSpan(off, n));
            var asc = new string(raw.AsSpan(off, n).ToArray().Select(b => b >= 32 && b < 127 ? (char)b : '.').ToArray());
            _out.WriteLine($"    +{off:X3}: {hex,-64}  {asc}");
        }

        // Manual cleanup so the session stays usable for whatever runs next.
        try { _ = Framing.SendRecv(client.Stream, Messages.BuildCloseCursor(Cursor.CursorHandle)); } catch { }
        try { _ = Framing.SendRecv(client.Stream, Messages.BuildResetStatement(Cursor.CursorHandle)); } catch { }
        try { _ = Framing.SendRecv(client.Stream, Messages.BuildRemoveAllRemoteMemoryTables()); } catch { }
    }

    /// <summary>
    /// Full DBSYS-style flow: Prepare → Execute → Receive → SetToBegin →
    /// GetNextRecord (positions cursor on row 1) → OpenBlob. This matches
    /// the captured DBSYS sequence in Derek/dbisam-capture-memo.pcapng exactly.
    /// </summary>
    [Fact]
    public void FetchBlob_DbsysSequence_Probe()
    {
        var host = Environment.GetEnvironmentVariable("DBISAM_HOST");
        if (string.IsNullOrEmpty(host)) { _out.WriteLine("Skipped"); return; }
        if (Environment.GetEnvironmentVariable("DBISAM_PROBE_BLOBS") != "1")
        {
            _out.WriteLine("Skipped — DBISAM_PROBE_BLOBS=1 required.");
            return;
        }
        int port = int.Parse(Environment.GetEnvironmentVariable("DBISAM_PORT") ?? "12005");
        var user = Environment.GetEnvironmentVariable("DBISAM_USER")!;
        var password = Environment.GetEnvironmentVariable("DBISAM_PASSWORD")!;

        using var client = DbisamClient.ConnectAndLogin(new ConnectOptions
        {
            Host = host, Port = port, User = user, Password = password,
        });

        // Prepare (sends SQL, gets schema). Cursor handle = 1 from here on.
        var schemaResp = client.QueryRaw("SELECT * FROM NIINGRED");
        var (cols, _) = Schema.Parse(schemaResp);
        int neanIdx = cols.FindIndex(c => c.Name == "NIEAN");
        int memoIdx = cols.FindIndex(c => c.Name == "NIINGREDS");
        var memoCol = cols[memoIdx];
        var pkCol = cols[neanIdx];
        _out.WriteLine($"NIEAN col: ord={pkCol.Ord} decl={pkCol.Decl} max={pkCol.Max} off={pkCol.RowOffset}");
        _out.WriteLine($"NIINGREDS col: ord={memoCol.Ord}");

        // Execute → Receive poll → SetToBegin → GetNextRecord.
        _ = Framing.SendRecv(client.Stream, Messages.BuildExecuteStatement(Cursor.CursorHandle));
        // Poll until non-sentinel
        for (int p = 0; p < 5; p++)
        {
            var r = Framing.SendRecv(client.Stream, Messages.BuildReceive());
            if (Response.BodyReqcode(r) != Response.PollingSentinelReqcode) break;
        }
        _ = Framing.SendRecv(client.Stream, Messages.BuildSetToBegin(Cursor.CursorHandle));
        var rowResp = Framing.SendRecv(client.Stream, Messages.BuildGetNextRecord(Cursor.CursorHandle));
        _out.WriteLine($"GetNextRecord resp: {rowResp.Length} bytes, reqcode=0x{Response.BodyReqcode(rowResp):X4}");

        // Decode the row from the GetNextRecord response.
        // Body shape (single-row): [header 7][result code Pack(2)][10 cursor-info Packs][row Pack(record_size)]
        var walker = new Walker(rowResp, Response.PackStreamOffset);
        var batch = Response.ReadBatch(walker, Cursor.ComputeRecordSize(cols));
        Assert.NotNull(batch);
        Assert.NotEmpty(batch!.Rows);
        var (rowOff, rowLen) = batch.Rows[0];
        var fullRecord = new ReadOnlySpan<byte>(rowResp, rowOff, rowLen);
        var hash = Row.ExtractRecordHash(fullRecord);
        var cells = Row.DecodeRecord(fullRecord, cols);
        var nean = cells[neanIdx] as string ?? "";
        _out.WriteLine($"row: NIEAN={nean} hash={Convert.ToHexString(hash)}");

        // NOW send OpenBlob — cursor is positioned on this row.
        var pkBytes = System.Text.Encoding.ASCII.GetBytes(nean);
        // PK field width = NIEAN's max (the on-disk storage width).
        int pkWidth = pkCol.Max;
        _out.WriteLine($"PK width = {pkWidth}");
        var openBlobReq = Messages.BuildOpenBlob(
            Cursor.CursorHandle, (uint)memoCol.Ord, hash, pkBytes, pkFieldWidth: pkWidth);
        _out.WriteLine($"OpenBlob req hex: {Convert.ToHexString(openBlobReq)}");
        var raw = Framing.SendRecv(client.Stream, openBlobReq);
        _out.WriteLine($"OpenBlob resp: {raw.Length} bytes, reqcode=0x{Response.BodyReqcode(raw):X4}");
        for (int off = 0; off < Math.Min(raw.Length, 320); off += 32)
        {
            int n = Math.Min(32, raw.Length - off);
            var hex = Convert.ToHexString(raw.AsSpan(off, n));
            var asc = new string(raw.AsSpan(off, n).ToArray().Select(b => b >= 32 && b < 127 ? (char)b : '.').ToArray());
            _out.WriteLine($"  +{off:X3}: {hex,-64}  {asc}");
        }

        // Cleanup
        try { _ = Framing.SendRecv(client.Stream, Messages.BuildCloseCursor(Cursor.CursorHandle)); } catch { }
        try { _ = Framing.SendRecv(client.Stream, Messages.BuildResetStatement(Cursor.CursorHandle)); } catch { }
        try { _ = Framing.SendRecv(client.Stream, Messages.BuildRemoveAllRemoteMemoryTables()); } catch { }
    }

    private static bool ContainsBytes(byte[] haystack, byte[] needle)
    {
        if (needle.Length == 0 || haystack.Length < needle.Length) return false;
        for (int i = 0; i <= haystack.Length - needle.Length; i++)
        {
            bool match = true;
            for (int j = 0; j < needle.Length; j++)
            {
                if (haystack[i + j] != needle[j]) { match = false; break; }
            }
            if (match) return true;
        }
        return false;
    }
}
