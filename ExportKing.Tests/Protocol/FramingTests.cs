using System.Buffers.Binary;
using ExportKing.Protocol;
using Xunit;

namespace ExportKing.Tests.Protocol;

public class FramingTests
{
    [Fact]
    public void WrapLayoutMatchesPoc()
    {
        // A 4-byte body should produce a 24-byte packet: GUID + u32(24) + body.
        var body = new byte[] { 0xAA, 0xBB, 0xCC, 0xDD };
        var pkt = Framing.Wrap(body);

        Assert.Equal(24, pkt.Length);
        Assert.Equal(Framing.Guid, pkt[..16]);
        Assert.Equal(new byte[] { 24, 0, 0, 0 }, pkt[16..20]); // u32 LE total_len
        Assert.Equal(body, pkt[20..]);
    }

    [Fact]
    public void WrapPadsToEightByteMultiple()
    {
        // 20 (header) + 5 (body) = 25, aligns up to 32 → 7 bytes of pad.
        var body = new byte[] { 1, 2, 3, 4, 5 };
        var pkt = Framing.Wrap(body);

        Assert.Equal(32, pkt.Length);
        Assert.Equal(Framing.Guid, pkt[..16]);
        Assert.Equal((uint)32, BinaryPrimitives.ReadUInt32LittleEndian(pkt.AsSpan(16, 4)));
        Assert.Equal(body, pkt[20..25]);
        // Padding bytes after the body are zero.
        Assert.Equal(new byte[] { 0, 0, 0, 0, 0, 0, 0 }, pkt[25..]);
    }

    [Fact]
    public void WrapEmptyBodyProducesAlignedHeader()
    {
        // 20-byte header alone is not a multiple of 8 — pads up to 24.
        var pkt = Framing.Wrap(ReadOnlySpan<byte>.Empty);

        Assert.Equal(24, pkt.Length);
        Assert.Equal((uint)24, BinaryPrimitives.ReadUInt32LittleEndian(pkt.AsSpan(16, 4)));
        Assert.Equal(new byte[] { 0, 0, 0, 0 }, pkt[20..]);
    }

    [Fact]
    public void RecvMsgRoundTripsAWrappedBody()
    {
        var body = new byte[] { 0x10, 0x20, 0x30, 0x40 };
        var pkt = Framing.Wrap(body);

        using var ms = new MemoryStream(pkt);
        var recovered = Framing.RecvMsg(ms);

        // RecvMsg returns the body without the 20-byte envelope.
        // Note: it returns (total_len - 20) bytes, which includes any
        // padding past the original body. For a 4-byte body that aligned
        // to 24 total, that's 4 bytes — no padding inside the body region.
        Assert.Equal(body, recovered);
    }

    [Fact]
    public void RecvMsgRejectsBadGuid()
    {
        var pkt = new byte[24];
        // Wrong GUID (all zeros), valid length.
        BinaryPrimitives.WriteUInt32LittleEndian(pkt.AsSpan(16, 4), 24);

        using var ms = new MemoryStream(pkt);
        var ex = Assert.Throws<IOException>(() => Framing.RecvMsg(ms));
        Assert.Contains("unexpected envelope prefix", ex.Message);
    }

    [Fact]
    public void RecvMsgRejectsTotalLenSmallerThanHeader()
    {
        var pkt = new byte[20];
        Framing.Guid.AsSpan().CopyTo(pkt);
        BinaryPrimitives.WriteUInt32LittleEndian(pkt.AsSpan(16, 4), 8); // < 20

        using var ms = new MemoryStream(pkt);
        var ex = Assert.Throws<IOException>(() => Framing.RecvMsg(ms));
        Assert.Contains("bad total_len", ex.Message);
    }

    [Fact]
    public void RecvMsgRejectsBodyLengthAboveSanityCap()
    {
        // A corrupt/hostile total_len must throw before any allocation, so
        // only the 20-byte header needs to be present.
        var pkt = new byte[20];
        Framing.Guid.AsSpan().CopyTo(pkt);
        BinaryPrimitives.WriteUInt32LittleEndian(pkt.AsSpan(16, 4), (uint)Framing.MaxBodyLen + 21);

        using var ms = new MemoryStream(pkt);
        var ex = Assert.Throws<IOException>(() => Framing.RecvMsg(ms));
        Assert.Contains("sanity cap", ex.Message);
    }

    [Fact]
    public void RecvMsgThrowsOnShortRead()
    {
        // Valid header claiming a 100-byte body, but stream only has 10.
        var pkt = new byte[30];
        Framing.Guid.AsSpan().CopyTo(pkt);
        BinaryPrimitives.WriteUInt32LittleEndian(pkt.AsSpan(16, 4), 120);

        using var ms = new MemoryStream(pkt);
        var ex = Assert.Throws<IOException>(() => Framing.RecvMsg(ms));
        Assert.Contains("connection closed", ex.Message);
    }

    [Fact]
    public void SendRecvRoundTripsAgainstMemoryStream()
    {
        // Use a duplex pipe: the "server" pre-stages a framed reply, the
        // client SendRecvs and reads it back.
        var requestBody = new byte[] { 0xCA, 0xFE };
        var replyBody = new byte[] { 0xBE, 0xEF, 0x01, 0x02 };
        var replyFrame = Framing.Wrap(replyBody);

        // Stream where the server has pre-written its reply.
        using var serverReplies = new MemoryStream();
        serverReplies.Write(replyFrame, 0, replyFrame.Length);
        serverReplies.Position = 0;

        // Duplex stream: SendRecv writes to one side, reads from another.
        // Easiest: use a single MemoryStream and a tee.
        using var combined = new TeeStream(sink: new MemoryStream(), source: serverReplies);
        var got = Framing.SendRecv(combined, requestBody);

        Assert.Equal(replyBody, got);

        // Verify the request was framed correctly on the way out.
        var sent = ((MemoryStream)combined.Sink).ToArray();
        var expectedSent = Framing.Wrap(requestBody);
        Assert.Equal(expectedSent, sent);
    }

    /// <summary>
    /// Read from one stream, write to another. Mimics a TCP socket's
    /// read/write split for tests.
    /// </summary>
    private sealed class TeeStream : Stream
    {
        public Stream Sink { get; }
        public Stream Source { get; }

        public TeeStream(Stream sink, Stream source)
        {
            Sink = sink;
            Source = source;
        }

        public override bool CanRead => true;
        public override bool CanWrite => true;
        public override bool CanSeek => false;
        public override long Length => throw new NotSupportedException();
        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override int Read(byte[] buffer, int offset, int count) => Source.Read(buffer, offset, count);
        public override void Write(byte[] buffer, int offset, int count) => Sink.Write(buffer, offset, count);
        public override void Flush() => Sink.Flush();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
    }
}
