using System.Data;
using System.Data.Common;
using System.Diagnostics.CodeAnalysis;

namespace ExportKing.Data;

/// <summary>
/// ADO.NET command over the native DBISAM protocol. Only <c>SELECT</c> via
/// <see cref="DbCommand.ExecuteReader()"/> is supported; writes go through
/// Exportmaster's XML-RPC API, not this library.
/// </summary>
public sealed class DbisamCommand : DbCommand
{
    private readonly DbisamParameterCollection _parameters = new();

    public DbisamCommand() { }

    public DbisamCommand(string commandText) => CommandText = commandText;

    public DbisamCommand(string commandText, DbisamConnection connection)
    {
        CommandText = commandText;
        Connection = connection;
    }

    [AllowNull]
    public override string CommandText { get; set; } = "";
    /// <summary>Accepted for API compatibility but not enforced — the
    /// underlying stream uses a fixed 30s read/write timeout.</summary>
    public override int CommandTimeout { get; set; }
    public override CommandType CommandType { get; set; } = CommandType.Text;
    public override bool DesignTimeVisible { get; set; }
    public override UpdateRowSource UpdatedRowSource { get; set; } = UpdateRowSource.None;

    /// <summary>
    /// Override blob materialisation for this command. When null (default) the
    /// connection's <c>Materialize Blobs</c> setting applies.
    /// </summary>
    public bool? MaterializeBlobs { get; set; }

    protected override DbConnection? DbConnection { get; set; }
    protected override DbParameterCollection DbParameterCollection => _parameters;
    protected override DbTransaction? DbTransaction { get; set; }

    public override void Cancel() { }
    public override void Prepare() { }

    public override int ExecuteNonQuery() =>
        throw new NotSupportedException(
            "DBISAM ExportKing: only SELECT via ExecuteReader is supported; " +
            "writes go through Exportmaster's XML-RPC API.");

    /// <summary>Convenience: runs the SELECT and returns the first column of
    /// the first row (or null). Handy for <c>SELECT COUNT(*)</c>-style probes.</summary>
    public override object? ExecuteScalar()
    {
        using var reader = ExecuteReader();
        return reader.Read() && reader.FieldCount > 0 ? reader.GetValue(0) : null;
    }

    protected override DbParameter CreateDbParameter() =>
        throw new NotSupportedException("DBISAM ExportKing: parameterised queries are not supported in this cut.");

    protected override DbDataReader ExecuteDbDataReader(CommandBehavior behavior)
    {
        if (DbConnection is not DbisamConnection conn)
            throw new InvalidOperationException(
                "DbisamCommand.Connection must be set to an open DbisamConnection.");
        if (conn.State != ConnectionState.Open)
            throw new InvalidOperationException("The connection is not open.");
        if (string.IsNullOrWhiteSpace(CommandText))
            throw new InvalidOperationException("CommandText is empty.");

        int targetRows = behavior.HasFlag(CommandBehavior.SingleRow) ? 1
            : behavior.HasFlag(CommandBehavior.SchemaOnly) ? 0
            : int.MaxValue;
        bool materialize = MaterializeBlobs ?? conn.MaterializeBlobsDefault;

        var result = conn.AcquireClient().Query(CommandText, materialize, targetRows);
        var closeOnDispose = behavior.HasFlag(CommandBehavior.CloseConnection) ? conn : null;
        return new DbisamDataReader(result, materialize, closeOnDispose);
    }
}
