using System.Buffers.Binary;
using ExportKing.Protocol;
using Xunit;

namespace ExportKing.Tests.Protocol;

public class ResponseTests
{
    private const int RecordSize = 10;

    /// <summary>
    /// Build the Pack-stream portion of a ReadRecordBlock batch: result code,
    /// 10 cursor-info units, row count, then an optional row buffer.
    /// </summary>
    private static byte[] BuildBatch(ushort resultCode, int rowCount, byte[]? rowBuf)
    {
        using var ms = new MemoryStream();
        void Unit(byte[] payload)
        {
            Span<byte> len = stackalloc byte[4];
            BinaryPrimitives.WriteUInt32LittleEndian(len, (uint)payload.Length);
            ms.Write(len);
            ms.Write(payload);
        }
        byte[] U32(uint v)
        {
            var b = new byte[4];
            BinaryPrimitives.WriteUInt32LittleEndian(b, v);
            return b;
        }

        Unit(new byte[] { (byte)resultCode, (byte)(resultCode >> 8) });
        // Cursor info: 5 × u32, 8-byte LastUpdated, u32, bookmark, 2 × flag byte.
        Unit(U32(1)); Unit(U32(1)); Unit(U32((uint)rowCount)); Unit(U32((uint)rowCount));
        Unit(U32(0)); Unit(new byte[8]); Unit(U32((uint)rowCount));
        Unit(new byte[] { 0xAA, 0xBB }); Unit(new byte[] { 0 }); Unit(new byte[] { 0 });
        Unit(U32((uint)rowCount));
        if (rowBuf is not null) Unit(rowBuf);
        return ms.ToArray();
    }

    [Fact]
    public void ReadRecordBlockBatchSlicesDeclaredRows()
    {
        var body = BuildBatch(Response.ResultOk, 2, new byte[2 * RecordSize]);
        var batch = Response.ReadRecordBlockBatch(new Walker(body), RecordSize);

        Assert.NotNull(batch);
        Assert.Equal(Response.ResultOk, batch!.ResultCode);
        Assert.Equal(2, batch.Rows.Count);
        Assert.All(batch.Rows, r => Assert.Equal(RecordSize, r.Length));
    }

    [Fact]
    public void ReadRecordBlockBatchThrowsWhenRowBufferNotDivisible()
    {
        // 3 declared rows but a 25-byte buffer — silently dropping the rows
        // would truncate the result set.
        var body = BuildBatch(Response.ResultOk, 3, new byte[25]);
        var ex = Assert.Throws<IOException>(
            () => Response.ReadRecordBlockBatch(new Walker(body), RecordSize));
        Assert.Contains("not divisible", ex.Message);
    }

    [Fact]
    public void ReadRecordBlockBatchThrowsWhenRecordSizeOutsideTolerance()
    {
        // Rows slice evenly but at 100 bytes each, far from the schema's 10.
        var body = BuildBatch(Response.ResultOk, 2, new byte[200]);
        var ex = Assert.Throws<IOException>(
            () => Response.ReadRecordBlockBatch(new Walker(body), RecordSize));
        Assert.Contains("outside expected", ex.Message);
    }

    [Fact]
    public void ReadRecordBlockBatchThrowsWhenRowBufferMissing()
    {
        var body = BuildBatch(Response.ResultOk, 2, rowBuf: null);
        var ex = Assert.Throws<IOException>(
            () => Response.ReadRecordBlockBatch(new Walker(body), RecordSize));
        Assert.Contains("no row buffer", ex.Message);
    }

    // Real error bodies captured from dbsrvr.exe on rivsem04 (2026-06-10).
    private const string WrongCatalogHex =
        "001E2C3F000000000000000F0000004E4F5F535543485F434154414C4F4700000000000000000000" +
        "000000000000000000000000000004000000000000000400000000000000000000000000";
    private const string WrongPasswordHex = "00172C000000000400000003";

    [Fact]
    public void TryGetServerErrorExtractsCodeAndDetail()
    {
        var body = Convert.FromHexString(WrongCatalogHex);
        Assert.True(Response.TryGetServerError(body, out var code, out var detail));
        Assert.Equal(0x2C1E, code);
        Assert.Equal("NO_SUCH_CATALOG", detail);
    }

    [Fact]
    public void TryGetServerErrorToleratesTruncatedBody()
    {
        // The wrong-password reply ends mid-unit; the code alone comes back.
        var body = Convert.FromHexString(WrongPasswordHex);
        Assert.True(Response.TryGetServerError(body, out var code, out var detail));
        Assert.Equal(0x2C17, code);
        Assert.Equal("", detail);
    }

    [Fact]
    public void TryGetServerErrorIgnoresSuccessAndSentinel()
    {
        var success = new byte[] { 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00 };
        Assert.False(Response.TryGetServerError(success, out _, out _));

        var sentinel = new byte[] { 0x00, 0x14, 0x2C, 0x00, 0x00, 0x00, 0x00 };
        Assert.False(Response.TryGetServerError(sentinel, out _, out _));
    }

    [Fact]
    public void ReadRecordBlockBatchAcceptsZeroRows()
    {
        var body = BuildBatch(Response.ResultEndOfCursor, 0, new byte[0]);
        var batch = Response.ReadRecordBlockBatch(new Walker(body), RecordSize);

        Assert.NotNull(batch);
        Assert.Equal(Response.ResultEndOfCursor, batch!.ResultCode);
        Assert.Empty(batch.Rows);
    }
}
