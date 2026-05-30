using System.Buffers.Binary;
using ExportKing.Protocol;
using Xunit;

namespace ExportKing.Tests.Protocol;

public class SchemaTests
{
    [Fact]
    public void ParsesOneStringBlock()
    {
        // Synthesise a 772-byte block with: ord=1, name="CODE", sub=1 (String),
        // decl=30, max=31, row_offset=25.
        var block = new byte[Schema.SchemaBlockStride];
        block[0] = 0x03; block[1] = 0x00; block[2] = 0x00; // marker
        BinaryPrimitives.WriteUInt16LittleEndian(block.AsSpan(3, 2), 1); // ord
        block[5] = 4; // namelen
        "CODE"u8.CopyTo(block.AsSpan(6, 4));
        // 12-byte descriptor at +0xA7
        block[0xA7] = 1;           // sub = String
        block[0xA7 + 2] = 30;      // decl
        block[0xA7 + 5] = 31;      // max
        BinaryPrimitives.WriteUInt16LittleEndian(block.AsSpan(0xA7 + 8, 2), 25); // row_offset

        // Surround with a small prefix so FindFirstBlockStart has to skip past it.
        var payload = new byte[64 + Schema.SchemaBlockStride];
        block.CopyTo(payload, 64);

        var (cols, endOff) = Schema.Parse(payload);
        Assert.Single(cols);
        Assert.Equal(1, cols[0].Ord);
        Assert.Equal("CODE", cols[0].Name);
        Assert.Equal(FieldType.String, cols[0].FieldType);
        Assert.Equal(30, cols[0].Decl);
        Assert.Equal(31, cols[0].Max);
        Assert.Equal(25, cols[0].RowOffset);
        Assert.Equal(64 + Schema.SchemaBlockStride, endOff);
    }

    [Fact]
    public void StopsAtFirstNonSequentialOrdinal()
    {
        // Block 1 (ord=1), then garbage that doesn't match block marker.
        var payload = new byte[Schema.SchemaBlockStride * 2];
        // Block 1
        payload[0] = 0x03; payload[1] = 0x00; payload[2] = 0x00;
        BinaryPrimitives.WriteUInt16LittleEndian(payload.AsSpan(3, 2), 1);
        payload[5] = 3;
        "FOO"u8.CopyTo(payload.AsSpan(6, 3));
        payload[0xA7] = 1;
        // Block 2: marker missing → ParseOneBlock returns null, loop exits.
        payload[Schema.SchemaBlockStride] = 0xFF;

        var (cols, _) = Schema.Parse(payload);
        Assert.Single(cols);
        Assert.Equal("FOO", cols[0].Name);
    }

    [Fact]
    public void ThrowsWhenNoBlockFound()
    {
        var ex = Assert.Throws<IOException>(() => Schema.Parse(new byte[1000]));
        Assert.Contains("no schema block marker", ex.Message);
    }

    [Theory]
    [InlineData(0, 0x00, 0x00, FieldType.Calculated)]
    [InlineData(1, 0x00, 0x00, FieldType.String)]
    [InlineData(2, 0x00, 0x00, FieldType.Date)]
    [InlineData(3, 0x00, 0x00, FieldType.Blob)]
    [InlineData(3, 0x16, 0x00, FieldType.Memo)]
    [InlineData(3, 0x1A, 0x00, FieldType.Graphic)]
    [InlineData(4, 0x00, 0x00, FieldType.Boolean)]
    [InlineData(5, 0x00, 0x00, FieldType.Smallint)]
    [InlineData(6, 0x00, 0x00, FieldType.Integer)]
    [InlineData(6, 0x1D, 0x00, FieldType.AutoInc)]
    [InlineData(7, 0x00, 0x0A, FieldType.Currency)]
    [InlineData(7, 0x00, 0x00, FieldType.Float)]
    [InlineData(9, 0x00, 0x00, FieldType.Bytes)]
    [InlineData(10, 0x00, 0x00, FieldType.Time)]
    [InlineData(11, 0x00, 0x00, FieldType.DateTime)]
    [InlineData(15, 0x00, 0x00, FieldType.VarBytes)]
    [InlineData(18, 0x00, 0x00, FieldType.Largeint)]
    [InlineData(99, 0x00, 0x00, FieldType.Unknown)]
    public void FieldTypeResolution(int sub, int a8, int b250, FieldType expected)
    {
        Assert.Equal(expected, ColumnExtensions.ResolveFieldType((byte)sub, (byte)a8, (byte)b250));
    }
}
