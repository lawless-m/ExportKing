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
    /// End-to-end blob materialisation against the live server — the real
    /// thing the port enables. Runs <c>SELECT * FROM NIINGRED</c> with
    /// <c>materializeBlobs:true</c> and asserts the NIINGREDS memo column
    /// comes back as actual text rather than an 8-byte handle.
    ///
    /// Double-gated behind <c>DBISAM_PROBE_BLOBS=1</c> because a malformed
    /// OpenBlob crashed <c>dbsrvr.exe</c> once during development. The slot
    /// now mirrors the working Rust reference, so this should be safe — but
    /// the gate stays until it's run clean a few times.
    /// </summary>
    [Fact]
    public void FetchBlob_NIINGRED_Materialized()
    {
        var host = Environment.GetEnvironmentVariable("DBISAM_HOST");
        if (string.IsNullOrEmpty(host)) { _out.WriteLine("Skipped (no DBISAM_HOST)"); return; }
        if (Environment.GetEnvironmentVariable("DBISAM_PROBE_BLOBS") != "1")
        {
            _out.WriteLine("Skipped — set DBISAM_PROBE_BLOBS=1 to run (touches the blob path).");
            return;
        }

        int port = int.Parse(Environment.GetEnvironmentVariable("DBISAM_PORT") ?? "12005");
        var user = Environment.GetEnvironmentVariable("DBISAM_USER")!;
        var password = Environment.GetEnvironmentVariable("DBISAM_PASSWORD")!;

        // One DbisamClient per query, per the class's documented lifecycle.
        ConnectOptions Opts() => new() { Host = host, Port = port, User = user, Password = password };

        // Part 1 — wide / multi-blob case. `SELECT *` used to return empty
        // payloads (the batched path's bookmark-stride bug); the GetNextRecord
        // streaming path resolves it. Oracle ground truth for TOP 5:
        // NIINGREDS lengths 280, 257, 235, 393, 88.
        using var clientWide = DbisamClient.ConnectAndLogin(Opts());
        var wide = clientWide.Query("SELECT * FROM NIINGRED TOP 5", materializeBlobs: true);
        int wNean = IndexOf(wide.Columns, "NIEAN"), wMemo = IndexOf(wide.Columns, "NIINGREDS");
        Assert.True(wMemo >= 0, "NIINGREDS not found in SELECT * schema");
        var expectedLens = new[] { 280, 257, 235, 393, 88 };
        for (int i = 0; i < wide.Rows.Count; i++)
        {
            var memo = wide.Rows[i][wMemo];
            Assert.False(memo is byte[], $"row {i}: NIINGREDS still an unresolved handle on SELECT *");
            var s = memo as string;
            var preview = s is { Length: > 80 } ? s[..80] + "…" : s;
            _out.WriteLine($"[*] row {i}: NIEAN={wide.Rows[i][wNean]} memo({s?.Length.ToString() ?? "null"})=\"{preview}\"");
            if (i < expectedLens.Length)
                Assert.Equal(expectedLens[i], s!.Length); // byte-for-byte parity with the Rust oracle
        }

        // Part 2 — scale. The batched path returned 0x2303 after ~644 blob
        // fetches; streaming advances the cursor so the server frees rows as
        // it goes. Oracle ground truth: TOP 700 → 700 rows, 575 with a memo.
        using var clientScale = DbisamClient.ConnectAndLogin(Opts());
        var scale = clientScale.Query("SELECT NIEAN, NIINGREDS FROM NIINGRED TOP 700", materializeBlobs: true);
        int sMemo = IndexOf(scale.Columns, "NIINGREDS");
        int withMemo = scale.Rows.Count(r => r[sMemo] is string);
        Assert.False(scale.Rows.Any(r => r[sMemo] is byte[]), "a memo came back as an unresolved handle past the 644 mark");
        _out.WriteLine($"[scale] {scale.Rows.Count} rows, {withMemo} with memo (no 0x2303)");
        Assert.Equal(700, scale.Rows.Count);
        Assert.Equal(575, withMemo); // matches the oracle exactly

        static int IndexOf(IReadOnlyList<Column> cols, string name)
        {
            for (int i = 0; i < cols.Count; i++) if (cols[i].Name == name) return i;
            return -1;
        }
    }

    /// <summary>
    /// Timed full-table extract: <c>SELECT * FROM NIINGRED</c> with blob
    /// materialisation, no TOP. Prints elapsed time, row/throughput stats and
    /// a sample of rows (first 3 + last 2, all columns) so the output can be
    /// eyeballed for correctness. Gated behind <c>DBISAM_PROBE_BLOBS=1</c>
    /// (and <c>DBISAM_FULL_EXTRACT=1</c> so it doesn't run in normal passes —
    /// it can take a while and pulls the whole table).
    /// </summary>
    [Fact]
    public void SelectStar_NIINGRED_FullExtract_Timed()
    {
        var host = Environment.GetEnvironmentVariable("DBISAM_HOST");
        if (string.IsNullOrEmpty(host)) { _out.WriteLine("Skipped (no DBISAM_HOST)"); return; }
        if (Environment.GetEnvironmentVariable("DBISAM_PROBE_BLOBS") != "1"
            || Environment.GetEnvironmentVariable("DBISAM_FULL_EXTRACT") != "1")
        {
            _out.WriteLine("Skipped — set DBISAM_PROBE_BLOBS=1 and DBISAM_FULL_EXTRACT=1 to run.");
            return;
        }
        int port = int.Parse(Environment.GetEnvironmentVariable("DBISAM_PORT") ?? "12005");
        var user = Environment.GetEnvironmentVariable("DBISAM_USER")!;
        var password = Environment.GetEnvironmentVariable("DBISAM_PASSWORD")!;

        using var client = DbisamClient.ConnectAndLogin(new ConnectOptions
        {
            Host = host, Port = port, User = user, Password = password,
        });

        var sw = System.Diagnostics.Stopwatch.StartNew();
        var result = client.Query("SELECT * FROM NIINGRED", materializeBlobs: true);
        sw.Stop();

        int n = result.Rows.Count;
        double secs = sw.Elapsed.TotalSeconds;
        _out.WriteLine($"SELECT * FROM NIINGRED — {n} rows × {result.Columns.Count} cols in " +
                       $"{secs:F2}s ({(secs > 0 ? n / secs : 0):F0} rows/s)");
        _out.WriteLine($"columns: {string.Join(", ", result.Columns.Select(c => $"{c.Name}:{c.FieldType}"))}");

        void DumpRow(int i)
        {
            var row = result.Rows[i];
            _out.WriteLine($"--- row {i} ---");
            for (int c = 0; c < row.Length; c++)
            {
                var v = row[c];
                string s = v switch
                {
                    null => "NULL",
                    string str => str.Length > 100 ? $"\"{str[..100]}…\" ({str.Length} chars)" : $"\"{str}\"",
                    byte[] b => $"bytes[{b.Length}]: {Convert.ToHexString(b.AsSpan(0, Math.Min(16, b.Length)))}{(b.Length > 16 ? "…" : "")}",
                    _ => v.ToString() ?? ""
                };
                _out.WriteLine($"    {result.Columns[c].Name} = {s}");
            }
        }

        for (int i = 0; i < Math.Min(3, n); i++) DumpRow(i);
        if (n > 5) { _out.WriteLine("    …"); DumpRow(n - 2); DumpRow(n - 1); }

        // Sanity: every memo/blob cell is materialised (string or byte[]), not
        // an 8-byte handle left behind.
        int memoIdx = -1;
        for (int i = 0; i < result.Columns.Count; i++)
            if (result.Columns[i].Name == "NIINGREDS") memoIdx = i;
        if (memoIdx >= 0)
        {
            int unresolved = result.Rows.Count(r => r[memoIdx] is byte[] b && b.Length == 8);
            _out.WriteLine($"NIINGREDS: {result.Rows.Count(r => r[memoIdx] is string)} text, " +
                           $"{result.Rows.Count(r => r[memoIdx] is null)} null, {unresolved} unresolved");
            Assert.Equal(0, unresolved);
        }
        Assert.True(n > 0, "expected rows from NIINGRED");
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
