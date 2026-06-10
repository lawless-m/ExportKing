using System.Buffers.Binary;
using System.Net.Sockets;

namespace ExportKing.Protocol;

/// <summary>
/// TCP framing for the DBISAM wire protocol. Every message on the wire is:
/// <c>[16-byte session GUID][u32 LE total_len][body]</c> where
/// <c>total_len = 20 + len(body)</c>, padded up to an 8-byte multiple.
/// See <c>../../Derek/DBISAM-PROTOCOL.md</c> §2.
///
/// Compression is intentionally not implemented. The Rust reference's
/// measurement on this corpus showed compression slower than plaintext on
/// LAN (8m12s with vs 2m36s without on <c>SELECT * FROM ANALYSIS</c>) and
/// every consuming RocsMiddleware service runs on the same LAN as the
/// DBISAM server, so compression has no use case here.
/// </summary>
public static class Framing
{
    /// <summary>
    /// 16-byte session GUID copied verbatim from PoC captures. Hypothesis: a
    /// client-runtime constant baked into <c>dbsys.exe</c>. If a real DBISAM
    /// server ever rejects it during cross-host testing, we'd need to
    /// negotiate it.
    /// </summary>
    /// <summary>
    /// Sanity cap on the server-supplied body length. A legitimate response
    /// is a few MB at most (batch_size rows × record width, or one blob
    /// payload); the bound only exists so a corrupt or hostile length field
    /// can't make us allocate unbounded memory.
    /// </summary>
    public const int MaxBodyLen = 256 * 1024 * 1024;

    public static readonly byte[] Guid =
    {
        0x8A, 0xBE, 0x8E, 0x59, 0x23, 0x64, 0xCB, 0x40,
        0x3D, 0x71, 0xD2, 0xE3, 0xBC, 0x64, 0xD0, 0x01,
    };

    /// <summary>
    /// Wrap a body in the standard framing envelope: GUID + u32 LE total_len.
    /// Per <c>ANSWERS-TO-DEREK-4.md</c>: total_size is aligned to 8 bytes
    /// (<c>BlockOffset(size, 8) = (size + 7) &amp; ~7</c>). Uncompressed
    /// bodies in our captures all happened to land on 8-byte boundaries
    /// naturally; we pad with zeros up to the next multiple of 8 and report
    /// the padded size in <c>total_len</c>.
    /// </summary>
    public static byte[] Wrap(ReadOnlySpan<byte> body)
    {
        int rawTotal = 20 + body.Length;
        int alignedTotal = (rawTotal + 7) & ~7;
        var pkt = new byte[alignedTotal];
        Guid.AsSpan().CopyTo(pkt);
        BinaryPrimitives.WriteUInt32LittleEndian(pkt.AsSpan(16, 4), (uint)alignedTotal);
        body.CopyTo(pkt.AsSpan(20, body.Length));
        // Tail padding bytes are already zero (new byte[]).
        return pkt;
    }

    /// <summary>
    /// Send a framed message and receive one framed reply. Returns the body
    /// (without the 20-byte envelope). Safe to call repeatedly on the same
    /// stream — DBISAM is strictly request/response.
    /// </summary>
    public static byte[] SendRecv(Stream stream, ReadOnlySpan<byte> body)
    {
        var pkt = Wrap(body);
        stream.Write(pkt, 0, pkt.Length);
        return RecvMsg(stream);
    }

    /// <summary>
    /// Receive one full framed message. Reads exactly 20 bytes for the
    /// header, validates the GUID, then reads <c>total_len - 20</c> bytes
    /// for the body. Returns the body.
    /// </summary>
    public static byte[] RecvMsg(Stream stream)
    {
        var head = new byte[20];
        ReadExact(stream, head);
        if (!head.AsSpan(0, 16).SequenceEqual(Guid))
        {
            throw new IOException(
                $"Exportmaster: unexpected envelope prefix: {Convert.ToHexString(head.AsSpan(0, 16))}");
        }
        int total = (int)BinaryPrimitives.ReadUInt32LittleEndian(head.AsSpan(16, 4));
        if (total < 20)
        {
            throw new IOException($"Exportmaster: bad total_len in header: {total}");
        }
        if (total - 20 > MaxBodyLen)
        {
            throw new IOException(
                $"Exportmaster: body length {total - 20} exceeds sanity cap {MaxBodyLen}");
        }
        var body = new byte[total - 20];
        ReadExact(stream, body);
        return body;
    }

    private static void ReadExact(Stream stream, byte[] buf)
    {
        int got = 0;
        while (got < buf.Length)
        {
            int n = stream.Read(buf, got, buf.Length - got);
            if (n == 0)
            {
                throw new IOException(
                    $"Exportmaster: connection closed (got {got} of {buf.Length})");
            }
            got += n;
        }
    }

    /// <summary>
    /// Open a TCP connection with sensible timeouts. Defaults match the Rust
    /// reference (10s connect, 30s read/write). Returns a <see cref="TcpClient"/>
    /// — call <c>GetStream()</c> for the I/O stream. Caller owns disposal.
    /// </summary>
    public static TcpClient Connect(string host, int port)
    {
        var client = new TcpClient();
        var connectTask = client.ConnectAsync(host, port);
        bool completed;
        try
        {
            completed = connectTask.Wait(TimeSpan.FromSeconds(10));
        }
        catch (AggregateException ex) when (ex.InnerException is { } inner)
        {
            // Surface the SocketException itself, not Wait()'s wrapper.
            client.Close();
            throw inner;
        }
        if (!completed)
        {
            client.Close();
            throw new IOException($"Exportmaster: connect {host}:{port}: timeout");
        }
        var stream = client.GetStream();
        stream.ReadTimeout = 30_000;
        stream.WriteTimeout = 30_000;
        return client;
    }
}
