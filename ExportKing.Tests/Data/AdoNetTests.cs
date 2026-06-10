using System.Data;
using ExportKing.Client;
using ExportKing.Data;
using ExportKing.Protocol;
using Xunit;

namespace ExportKing.Tests.Data;

/// <summary>
/// Offline unit tests for the ADO.NET surface — connection-string parsing and
/// the data reader over a synthetic <see cref="QueryResult"/>. No server.
/// </summary>
public class AdoNetTests
{
    [Fact]
    public void ConnectionStringBuilder_ParsesTypedKeys()
    {
        var b = new DbisamConnectionStringBuilder(
            "Host=rivsem04;Port=12005;User Id=e3user;Password=secret;Catalog=NISAINT_CS;Batch Size=2000;Materialize Blobs=false");
        Assert.Equal("rivsem04", b.Host);
        Assert.Equal(12005, b.Port);
        Assert.Equal("e3user", b.UserId);
        Assert.Equal("secret", b.Password);
        Assert.Equal("NISAINT_CS", b.Catalog);
        Assert.Equal(2000u, b.BatchSize);
        Assert.False(b.MaterializeBlobs);

        var opts = b.ToConnectOptions();
        Assert.Equal("rivsem04", opts.Host);
        Assert.Equal("e3user", opts.User);
        Assert.Equal(2000u, opts.BatchSize);
    }

    [Fact]
    public void ConnectionStringBuilder_AppliesDefaults()
    {
        var b = new DbisamConnectionStringBuilder("Host=h;User Id=u;Password=p");
        Assert.Equal(12005, b.Port);
        Assert.Equal("NISAINT_CS", b.Catalog);
        Assert.Equal(5000u, b.BatchSize);
        Assert.True(b.MaterializeBlobs); // ODBC parity: memos materialise by default
    }

    [Fact]
    public void DataReader_IteratesRowsAndTypesColumns()
    {
        var result = SampleResult();
        using var r = new DbisamDataReader(result, blobsMaterialized: true, closeOnDispose: null);

        Assert.Equal(3, r.FieldCount);
        Assert.True(r.HasRows);
        Assert.False(r.NextResult());
        Assert.Equal(typeof(string), r.GetFieldType(r.GetOrdinal("Code")));
        Assert.Equal(typeof(int), r.GetFieldType(r.GetOrdinal("Qty")));

        Assert.True(r.Read());
        Assert.Equal("AD", r.GetString(0));
        Assert.Equal("AD", (string)r["Code"]);          // indexer by name
        Assert.Equal("AD", (string)r["code"]);          // case-insensitive
        Assert.Equal(42, r.GetInt32(r.GetOrdinal("Qty")));
        Assert.False(r.IsDBNull(0));

        Assert.True(r.Read());
        Assert.Equal("AE", r.GetString(0));
        Assert.True(r.IsDBNull(r.GetOrdinal("Note")));   // null cell
        Assert.Equal(DBNull.Value, r["Note"]);

        Assert.False(r.Read());                          // exhausted
    }

    [Fact]
    public void DataReader_NullThrowsOnTypedGetter()
    {
        var result = SampleResult();
        using var r = new DbisamDataReader(result, blobsMaterialized: true, closeOnDispose: null);
        r.Read();
        r.Read(); // second row has Note = null
        Assert.Throws<InvalidCastException>(() => r.GetString(r.GetOrdinal("Note")));
    }

    [Fact]
    public void DataReader_GetOrdinalRejectsUnknownColumn()
    {
        using var r = new DbisamDataReader(SampleResult(), blobsMaterialized: true, closeOnDispose: null);
        Assert.Throws<IndexOutOfRangeException>(() => r.GetOrdinal("Nope"));
    }

    [Fact]
    public void ConnectionStringBuilder_ThrowsOnUnparseableValues()
    {
        // Silent fallback masked typos — worst case 'Materialize Blobs=0'
        // (ODBC spelling) quietly meant true. Now 0/1/yes/no parse and
        // anything else throws.
        Assert.False(new DbisamConnectionStringBuilder("Host=h;Materialize Blobs=0").MaterializeBlobs);
        Assert.False(new DbisamConnectionStringBuilder("Host=h;Materialize Blobs=no").MaterializeBlobs);
        Assert.True(new DbisamConnectionStringBuilder("Host=h;Materialize Blobs=1").MaterializeBlobs);
        Assert.True(new DbisamConnectionStringBuilder("Host=h;Materialize Blobs=yes").MaterializeBlobs);

        Assert.Throws<ArgumentException>(
            () => new DbisamConnectionStringBuilder("Host=h;Materialize Blobs=maybe").MaterializeBlobs);
        Assert.Throws<ArgumentException>(
            () => new DbisamConnectionStringBuilder("Host=h;Port=abc").Port);
        Assert.Throws<ArgumentException>(
            () => new DbisamConnectionStringBuilder("Host=h;Port=0").Port);
        Assert.Throws<ArgumentException>(
            () => new DbisamConnectionStringBuilder("Host=h;Batch Size=-1").BatchSize);
    }

    [Fact]
    public void DataReader_GetDecimalConvertsFloatCells()
    {
        var columns = new List<Column>
        {
            new() { Ord = 1, Name = "Price", FieldType = FieldType.Float, Decl = 0, Max = 8, RowOffset = 25 },
        };
        var result = new QueryResult
        {
            Columns = columns,
            Rows = new List<object?[]> { new object?[] { 1.25d } },
            RowHashes = new List<byte[]> { new byte[16] },
        };
        using var r = new DbisamDataReader(result, blobsMaterialized: true, closeOnDispose: null);
        r.Read();
        Assert.Equal(1.25m, r.GetDecimal(0));
    }

    [Fact]
    public void DataReader_GetBytesRejectsUnresolvedBlobHandle()
    {
        var columns = new List<Column>
        {
            new() { Ord = 1, Name = "Notes", FieldType = FieldType.Memo, Decl = 0, Max = 8, RowOffset = 25 },
        };
        var result = new QueryResult
        {
            Columns = columns,
            Rows = new List<object?[]> { new object?[] { new byte[8] { 1, 2, 3, 4, 5, 6, 7, 8 } } },
            RowHashes = new List<byte[]> { new byte[16] },
        };
        using var r = new DbisamDataReader(result, blobsMaterialized: false, closeOnDispose: null);
        r.Read();
        var ex = Assert.Throws<InvalidOperationException>(() => r.GetBytes(0, 0, new byte[8], 0, 8));
        Assert.Contains("Materialize Blobs", ex.Message);
    }

    private static QueryResult SampleResult()
    {
        var columns = new List<Column>
        {
            new() { Ord = 1, Name = "Code", FieldType = FieldType.String, Decl = 2, Max = 3, RowOffset = 25 },
            new() { Ord = 2, Name = "Qty",  FieldType = FieldType.Integer, Decl = 0, Max = 4, RowOffset = 29 },
            new() { Ord = 3, Name = "Note", FieldType = FieldType.String, Decl = 10, Max = 11, RowOffset = 34 },
        };
        var rows = new List<object?[]>
        {
            new object?[] { "AD", 42, "hi" },
            new object?[] { "AE", 7, null },
        };
        var hashes = new List<byte[]> { new byte[16], new byte[16] };
        return new QueryResult { Columns = columns, Rows = rows, RowHashes = hashes };
    }
}
