using System.Data.Common;
using ExportKing.Client;

namespace ExportKing.Data;

/// <summary>
/// Strongly-typed connection-string builder for <see cref="DbisamConnection"/>.
/// Recognised keys (case-insensitive): <c>Host</c>, <c>Port</c>,
/// <c>User Id</c>, <c>Password</c>, <c>Catalog</c>, <c>Batch Size</c>,
/// <c>Materialize Blobs</c>. No <c>Compression</c> key — LAN-only deployment
/// never wants it.
/// </summary>
public sealed class DbisamConnectionStringBuilder : DbConnectionStringBuilder
{
    public DbisamConnectionStringBuilder() { }

    public DbisamConnectionStringBuilder(string connectionString)
    {
        ConnectionString = connectionString;
    }

    public string Host
    {
        get => GetString("Host", "");
        set => this["Host"] = value;
    }

    public int Port
    {
        get => GetInt("Port", 12005);
        set => this["Port"] = value;
    }

    /// <summary>Stored under the <c>User Id</c> key (ODBC/ADO.NET convention).</summary>
    public string UserId
    {
        get => GetString("User Id", "");
        set => this["User Id"] = value;
    }

    public string Password
    {
        get => GetString("Password", "");
        set => this["Password"] = value;
    }

    public string Catalog
    {
        get => GetString("Catalog", "NISAINT_CS");
        set => this["Catalog"] = value;
    }

    /// <summary>Rows per ReadFirstRecordBlock / GetNextRecord call.</summary>
    public uint BatchSize
    {
        get => (uint)GetInt("Batch Size", 5000);
        set => this["Batch Size"] = value;
    }

    /// <summary>
    /// When true (default), memo/blob/graphic columns are fetched inline and
    /// surface as <see cref="string"/> / <see cref="byte"/>[] — matching what
    /// the old ODBC driver returned. Set false to leave the raw 8-byte handles
    /// in place (much faster for wide tables you don't read the blobs from).
    /// </summary>
    public bool MaterializeBlobs
    {
        get => GetBool("Materialize Blobs", true);
        set => this["Materialize Blobs"] = value;
    }

    /// <summary>Project the typed properties onto the lower-level
    /// <see cref="ConnectOptions"/> the client consumes.</summary>
    public ConnectOptions ToConnectOptions() => new()
    {
        Host = Host,
        Port = Port,
        User = UserId,
        Password = Password,
        Catalog = Catalog,
        BatchSize = BatchSize,
    };

    private string GetString(string key, string fallback)
        => TryGetValue(key, out var v) && v is not null ? v.ToString() ?? fallback : fallback;

    private int GetInt(string key, int fallback)
        => TryGetValue(key, out var v) && v is not null && int.TryParse(v.ToString(), out var i) ? i : fallback;

    private bool GetBool(string key, bool fallback)
        => TryGetValue(key, out var v) && v is not null && bool.TryParse(v.ToString(), out var b) ? b : fallback;
}
