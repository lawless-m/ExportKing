using System.Data;
using System.Data.Common;
using System.Diagnostics.CodeAnalysis;
using ExportKing.Client;

namespace ExportKing.Data;

/// <summary>
/// ADO.NET connection over the native DBISAM protocol. Drop-in for
/// <c>OdbcConnection</c> against Exportmaster:
/// <code>
/// using var conn = new DbisamConnection("Host=rivsem04;User Id=…;Password=…;Catalog=NISAINT_CS");
/// using var cmd  = new DbisamCommand("SELECT CountryCode FROM RIGeographic", conn);
/// conn.Open();
/// using var reader = cmd.ExecuteReader();
/// while (reader.Read()) { … reader["CountryCode"] … }
/// </code>
///
/// Lifecycle note: one logical session per connection. Because the protocol
/// is one-cursor-per-session, prefer one connection per query (especially when
/// materialising blobs — a streaming blob query leaves the session positioned
/// such that a follow-up query on the same connection can desync). This
/// matches both the Rust reference and the old <c>OdbcConnection</c> usage.
/// </summary>
public sealed class DbisamConnection : DbConnection
{
    private DbisamConnectionStringBuilder _builder = new();
    private string _connectionString = "";
    private DbisamClient? _client;
    private bool _clientUsed;
    private ConnectionState _state = ConnectionState.Closed;

    public DbisamConnection() { }

    public DbisamConnection(string connectionString)
    {
        ConnectionString = connectionString;
    }

    [AllowNull]
    public override string ConnectionString
    {
        get => _connectionString;
        set
        {
            _connectionString = value ?? "";
            _builder = new DbisamConnectionStringBuilder(_connectionString);
        }
    }

    public override string Database => _builder.Catalog;
    public override string DataSource => _builder.Host;
    public override string ServerVersion => "";
    public override ConnectionState State => _state;

    /// <summary>
    /// Acquire a client with a clean session for one query. The protocol is
    /// one-cursor-per-session and sequential queries on a single session can
    /// desync, so each command after the first gets a fresh login. The common
    /// case (one query per connection) re-uses the <see cref="Open"/> client
    /// and never re-logs-in.
    /// </summary>
    internal DbisamClient AcquireClient()
    {
        if (_state != ConnectionState.Open || _client is null)
            throw new InvalidOperationException("The connection is not open.");
        if (_clientUsed)
        {
            _client.Dispose();
            _client = DbisamClient.ConnectAndLogin(_builder.ToConnectOptions());
        }
        _clientUsed = true;
        return _client;
    }

    /// <summary>Default blob-materialisation for commands that don't override it.</summary>
    internal bool MaterializeBlobsDefault => _builder.MaterializeBlobs;

    public override void Open()
    {
        if (_state == ConnectionState.Open) return;
        if (string.IsNullOrEmpty(_builder.Host))
            throw new InvalidOperationException("DBISAM: 'Host' is required in the connection string.");
        _state = ConnectionState.Connecting;
        try
        {
            _client = DbisamClient.ConnectAndLogin(_builder.ToConnectOptions());
            _clientUsed = false;
            _state = ConnectionState.Open;
        }
        catch
        {
            _state = ConnectionState.Closed;
            throw;
        }
    }

    public override void Close()
    {
        try { _client?.Dispose(); }
        finally
        {
            _client = null;
            _state = ConnectionState.Closed;
        }
    }

    public override void ChangeDatabase(string databaseName) =>
        throw new NotSupportedException(
            "DBISAM: ChangeDatabase is not supported; set 'Catalog' in the connection string and reopen.");

    protected override DbTransaction BeginDbTransaction(IsolationLevel isolationLevel) =>
        throw new NotSupportedException("DBISAM: transactions are not supported (reads only).");

    protected override DbCommand CreateDbCommand() => new DbisamCommand { Connection = this };

    protected override void Dispose(bool disposing)
    {
        if (disposing) Close();
        base.Dispose(disposing);
    }
}
