using System.Collections;
using System.Data;
using System.Data.Common;
using ExportKing.Client;
using ExportKing.Protocol;

namespace ExportKing.Data;

/// <summary>
/// Forward-only reader over a materialised <see cref="QueryResult"/>. Backs
/// <see cref="DbisamCommand.ExecuteReader()"/>; the result set is already in
/// memory, so this is a thin cursor over <see cref="QueryResult.Rows"/>.
/// </summary>
public sealed class DbisamDataReader : DbDataReader
{
    private readonly QueryResult _result;
    private readonly bool _blobsMaterialized;
    private DbisamConnection? _closeOnDispose;
    private int _row = -1;
    private bool _closed;

    internal DbisamDataReader(QueryResult result, bool blobsMaterialized, DbisamConnection? closeOnDispose)
    {
        _result = result;
        _blobsMaterialized = blobsMaterialized;
        _closeOnDispose = closeOnDispose;
    }

    public override int FieldCount => _result.Columns.Count;
    public override bool HasRows => _result.Rows.Count > 0;
    public override bool IsClosed => _closed;
    public override int RecordsAffected => -1;
    public override int Depth => 0;

    public override bool Read()
    {
        if (_closed || _row >= _result.Rows.Count) return false;
        _row++;
        return _row < _result.Rows.Count;
    }

    public override bool NextResult() => false;

    public override string GetName(int ordinal) => _result.Columns[ordinal].Name;

    public override int GetOrdinal(string name)
    {
        for (int i = 0; i < _result.Columns.Count; i++)
            if (string.Equals(_result.Columns[i].Name, name, StringComparison.OrdinalIgnoreCase))
                return i;
        throw new IndexOutOfRangeException($"No column named '{name}'.");
    }

    public override Type GetFieldType(int ordinal) => ClrType(_result.Columns[ordinal].FieldType, _blobsMaterialized);
    public override string GetDataTypeName(int ordinal) => _result.Columns[ordinal].FieldType.ToString();

    public override object this[int ordinal] => GetValue(ordinal);
    public override object this[string name] => GetValue(GetOrdinal(name));

    public override object GetValue(int ordinal)
    {
        EnsureRow();
        return _result.Rows[_row][ordinal] ?? DBNull.Value;
    }

    public override int GetValues(object[] values)
    {
        EnsureRow();
        int n = Math.Min(values.Length, FieldCount);
        for (int i = 0; i < n; i++) values[i] = _result.Rows[_row][i] ?? DBNull.Value;
        return n;
    }

    public override bool IsDBNull(int ordinal)
    {
        EnsureRow();
        return _result.Rows[_row][ordinal] is null;
    }

    public override bool GetBoolean(int ordinal) => (bool)Raw(ordinal);
    public override byte GetByte(int ordinal) => (byte)Raw(ordinal);
    public override char GetChar(int ordinal) => (char)Raw(ordinal);
    public override decimal GetDecimal(int ordinal) => Convert.ToDecimal(Raw(ordinal));
    public override double GetDouble(int ordinal) => Convert.ToDouble(Raw(ordinal));
    public override float GetFloat(int ordinal) => Convert.ToSingle(Raw(ordinal));
    public override Guid GetGuid(int ordinal) => (Guid)Raw(ordinal);
    public override short GetInt16(int ordinal) => Convert.ToInt16(Raw(ordinal));
    public override int GetInt32(int ordinal) => Convert.ToInt32(Raw(ordinal));
    public override long GetInt64(int ordinal) => Convert.ToInt64(Raw(ordinal));
    public override string GetString(int ordinal) => (string)Raw(ordinal);

    public override DateTime GetDateTime(int ordinal) => Raw(ordinal) switch
    {
        DateTime dt => dt,
        DateOnly d => d.ToDateTime(TimeOnly.MinValue),
        _ => (DateTime)Raw(ordinal),
    };

    public override long GetBytes(int ordinal, long dataOffset, byte[]? buffer, int bufferOffset, int length)
    {
        ThrowIfUnresolvedBlob(ordinal);
        var data = (byte[])Raw(ordinal);
        if (buffer is null) return data.Length;
        long available = data.Length - dataOffset;
        if (available <= 0) return 0;
        int n = (int)Math.Min(length, available);
        Array.Copy(data, dataOffset, buffer, bufferOffset, n);
        return n;
    }

    public override long GetChars(int ordinal, long dataOffset, char[]? buffer, int bufferOffset, int length)
    {
        ThrowIfUnresolvedBlob(ordinal);
        var s = (string)Raw(ordinal);
        if (buffer is null) return s.Length;
        long available = s.Length - dataOffset;
        if (available <= 0) return 0;
        int n = (int)Math.Min(length, available);
        s.CopyTo((int)dataOffset, buffer, bufferOffset, n);
        return n;
    }

    public override IEnumerator GetEnumerator() => new DbEnumerator(this, closeReader: false);

    public override DataTable GetSchemaTable()
    {
        var table = new DataTable("SchemaTable");
        table.Columns.Add(SchemaTableColumn.ColumnName, typeof(string));
        table.Columns.Add(SchemaTableColumn.ColumnOrdinal, typeof(int));
        table.Columns.Add(SchemaTableColumn.ColumnSize, typeof(int));
        table.Columns.Add(SchemaTableColumn.DataType, typeof(Type));
        table.Columns.Add(SchemaTableColumn.AllowDBNull, typeof(bool));
        table.Columns.Add(SchemaTableColumn.ProviderType, typeof(int));
        for (int i = 0; i < _result.Columns.Count; i++)
        {
            var c = _result.Columns[i];
            var row = table.NewRow();
            row[SchemaTableColumn.ColumnName] = c.Name;
            row[SchemaTableColumn.ColumnOrdinal] = i;
            // For strings Decl is the declared character length; Max is the
            // on-disk width (decl + length byte). Other types declare 0.
            row[SchemaTableColumn.ColumnSize] = c.FieldType == FieldType.String ? c.Decl : (int)c.Max;
            row[SchemaTableColumn.DataType] = ClrType(c.FieldType, _blobsMaterialized);
            row[SchemaTableColumn.AllowDBNull] = true;
            row[SchemaTableColumn.ProviderType] = (int)c.FieldType;
            table.Rows.Add(row);
        }
        return table;
    }

    public override void Close()
    {
        if (_closed) return;
        _closed = true;
        var conn = _closeOnDispose;
        _closeOnDispose = null;
        conn?.Close();
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing) Close();
        base.Dispose(disposing);
    }

    /// <summary>
    /// With <c>Materialize Blobs=false</c>, blob cells hold the server's
    /// 8-byte handle, not content — returning those bytes from a content
    /// getter would be silent garbage.
    /// </summary>
    private void ThrowIfUnresolvedBlob(int ordinal)
    {
        if (!_blobsMaterialized && _result.Columns[ordinal].FieldType
                is FieldType.Blob or FieldType.Memo or FieldType.Graphic)
        {
            throw new InvalidOperationException(
                $"Column '{GetName(ordinal)}' holds an unresolved blob handle — " +
                "open with 'Materialize Blobs=true' to fetch content.");
        }
    }

    /// <summary>Current cell, non-null, for the typed getters (throws on NULL
    /// like the ODBC driver did).</summary>
    private object Raw(int ordinal)
    {
        EnsureRow();
        return _result.Rows[_row][ordinal]
            ?? throw new InvalidCastException($"Column '{GetName(ordinal)}' is NULL.");
    }

    private void EnsureRow()
    {
        if (_closed) throw new InvalidOperationException("The reader is closed.");
        if (_row < 0) throw new InvalidOperationException("Call Read() before accessing fields.");
        if (_row >= _result.Rows.Count) throw new InvalidOperationException("No current row.");
    }

    internal static Type ClrType(FieldType ft, bool blobsMaterialized) => ft switch
    {
        FieldType.String => typeof(string),
        FieldType.Date => typeof(DateOnly),
        FieldType.Time => typeof(TimeOnly),
        FieldType.DateTime => typeof(DateTime),
        FieldType.Integer or FieldType.AutoInc or FieldType.Smallint => typeof(int),
        FieldType.Largeint => typeof(long),
        FieldType.Boolean => typeof(bool),
        FieldType.Float => typeof(double),
        FieldType.Currency => typeof(decimal),
        FieldType.Bytes or FieldType.VarBytes or FieldType.Blob or FieldType.Graphic => typeof(byte[]),
        FieldType.Memo => blobsMaterialized ? typeof(string) : typeof(byte[]),
        _ => typeof(object),
    };
}
