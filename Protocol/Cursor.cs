namespace ExportKing.Protocol;

/// <summary>
/// Cursor driver: the post-PrepareStatement message sequence for a SELECT.
/// Per Derek's disassembly (ANSWERS-TO-DEREK-2.md), the flow is:
/// <code>
/// 0x032A ExecuteStatement       ← kicks off cursor execution
/// 0x030C Receive (LOOP)         ← poll until server signals "ready"
/// 0x00BE SetToBegin             ← position at row 1
/// 0x050A ReadFirstRecordBlock   ← batched read, N rows per round-trip
/// 0x04F6 ReadNextRecordBlock    ← repeat until end-of-cursor
/// 0x00A0 CloseCursor            ← cleanup (caller handles)
/// </code>
/// </summary>
public static class Cursor
{
    /// <summary>Per-session cursor handle. Always 1 (one cursor per session).</summary>
    public const uint CursorHandle = 1;

    /// <summary>Max Receive-poll iterations before giving up.</summary>
    private const int MaxReceivePolls = 100;

    /// <summary>
    /// Total on-disk record width per protocol §6c: <c>row_offset</c> of
    /// the last column + that column's <c>max</c> bytes + 1 for its null-flag.
    /// </summary>
    public static int ComputeRecordSize(IReadOnlyList<Column> columns)
    {
        var last = columns[^1];
        return last.RowOffset + last.Max + 1;
    }

    /// <summary>
    /// Drive a SELECT cursor to completion. For each row, calls
    /// <paramref name="onRow"/> with the column-data slice (already sliced
    /// past the 25-byte on-disk header — ready to pass to
    /// <see cref="Row.DecodeRecord"/>). Returns the number of rows delivered.
    ///
    /// Stops when a response carries <c>RESULT_END_OF_CURSOR (0x2202)</c>,
    /// or after <paramref name="targetRows"/> rows, or after a safety bound.
    /// </summary>
    public static int DriveCursor(
        Stream stream,
        IReadOnlyList<Column> columns,
        int targetRows,
        uint batchSize,
        RowHandler onRow)
    {
        int recordSize = ComputeRecordSize(columns);
        int rowsSeen = 0;

        // Phase 1: ExecuteStatement.
        var resp = Framing.SendRecv(stream, Messages.BuildExecuteStatement(CursorHandle));
        if (ProcessBody(resp, ReplyKind.SingleRow)) return rowsSeen;

        // Phase 2: Receive poll loop.
        int pollCount = 0;
        while (true)
        {
            resp = Framing.SendRecv(stream, Messages.BuildReceive());
            bool isSentinel = Response.BodyReqcode(resp) == Response.PollingSentinelReqcode;
            bool isNotReadyInner = IsNotReadyInner(resp);
            if (ProcessBody(resp, ReplyKind.SingleRow)) return rowsSeen;
            if (!isSentinel && !isNotReadyInner) break;
            pollCount++;
            if (pollCount >= MaxReceivePolls)
            {
                throw new IOException(
                    $"Exportmaster: cursor still 'not ready' after {MaxReceivePolls} Receive polls");
            }
        }

        // Phase 2.5: SetToBegin.
        resp = Framing.SendRecv(stream, Messages.BuildSetToBegin(CursorHandle));
        if (ProcessBody(resp, ReplyKind.SingleRow)) return rowsSeen;

        // Phase 3: ReadFirstRecordBlock.
        uint firstN = (uint)Math.Max(1, Math.Min(targetRows, (int)batchSize));
        resp = Framing.SendRecv(stream, Messages.BuildReadFirstRecordBlock(CursorHandle, firstN));
        if (ProcessBody(resp, ReplyKind.RecordBlock)) return rowsSeen;

        // Phase 4: ReadNextRecordBlock loop. Runs until end-of-cursor or
        // targetRows. A "not ready" status gets a bounded retry (the server
        // can stall mid-read); any other batch that delivers no rows and no
        // EoC is a protocol error — continuing would either spin forever or
        // silently truncate the result set.
        int notReadyPolls = 0;
        while (rowsSeen < targetRows)
        {
            int before = rowsSeen;
            int remaining = targetRows - rowsSeen;
            uint n = (uint)Math.Max(1, Math.Min(remaining, (int)batchSize));
            resp = Framing.SendRecv(stream, Messages.BuildReadNextRecordBlock(CursorHandle, n));
            if (ProcessBody(resp, ReplyKind.RecordBlock)) break;
            if (rowsSeen > before)
            {
                notReadyPolls = 0;
                continue;
            }
            bool notReady = Response.BodyReqcode(resp) == Response.PollingSentinelReqcode
                || IsNotReadyInner(resp);
            if (notReady)
            {
                if (++notReadyPolls >= MaxReceivePolls)
                {
                    throw new IOException(
                        $"Exportmaster: cursor still 'not ready' after {MaxReceivePolls} ReadNextRecordBlock polls");
                }
                continue;
            }
            throw new IOException(
                "Exportmaster: ReadNextRecordBlock delivered no rows and no end-of-cursor " +
                "— refusing to return a silently truncated result set");
        }

        return rowsSeen;

        // ---- local helpers ----

        bool ProcessBody(byte[] body, ReplyKind kind)
        {
            if (body.Length < Response.PackStreamOffset + 6) return false;
            if (Response.BodyReqcode(body) == Response.PollingSentinelReqcode) return false;

            var walker = new Walker(body, Response.PackStreamOffset);
            while (true)
            {
                CursorBatch? batch;
                if (kind == ReplyKind.SingleRow)
                {
                    // ExecuteStatement / Receive / SetToBegin replies are
                    // heterogeneous (status shapes, not-ready inners with no
                    // cursor-info); a body that isn't batch-shaped is expected
                    // and simply carries no rows.
                    try
                    {
                        batch = Response.ReadBatch(walker, recordSize);
                    }
                    catch (IOException)
                    {
                        return false;
                    }
                }
                else
                {
                    // ReadRecordBlock replies have exactly one shape. A
                    // malformed one is a protocol error, not end-of-cursor —
                    // swallowing it here would silently truncate the result
                    // set. Only clean exhaustion (null) means no more batches.
                    batch = Response.ReadRecordBlockBatch(walker, recordSize);
                }
                if (batch is null) return false;

                for (int i = 0; i < batch.Rows.Count; i++)
                {
                    if (rowsSeen >= targetRows) return true;
                    var (offset, length) = batch.Rows[i];
                    // Pass the full record (header + column data). Row.DecodeRecord
                    // slices off the header internally; downstream blob-fetch needs
                    // the 16-byte MD5 from the header (bytes 9..25).
                    var fullRow = new ReadOnlySpan<byte>(body, offset, length);
                    // Per-row physical-record bookmark (empty for single-row
                    // replies); blob fetch reads PhysicalRecordNumber from it.
                    ReadOnlySpan<byte> bookmark = i < batch.Bookmarks.Count
                        ? new ReadOnlySpan<byte>(body, batch.Bookmarks[i].Offset, batch.Bookmarks[i].Length)
                        : default;
                    onRow(fullRow, bookmark);
                    rowsSeen++;
                }
                if (batch.ResultCode != Response.ResultOk) return true;
                if (IsExhausted(body, walker.Position)) return false;
            }
        }

        // The framing envelope reports the 8-byte-aligned total, so a body
        // can carry up to 7 zero bytes of tail padding after the last batch.
        static bool IsExhausted(byte[] body, int pos)
        {
            if (pos >= body.Length) return true;
            if (body.Length - pos > 7) return false;
            for (int i = pos; i < body.Length; i++)
            {
                if (body[i] != 0) return false;
            }
            return true;
        }

        static bool IsNotReadyInner(byte[] body)
        {
            int packStart = Response.PackStreamOffset;
            if (body.Length < packStart + 6) return false;
            uint len = System.Buffers.Binary.BinaryPrimitives.ReadUInt32LittleEndian(
                body.AsSpan(packStart, 4));
            if (len != 2) return false;
            ushort rc = System.Buffers.Binary.BinaryPrimitives.ReadUInt16LittleEndian(
                body.AsSpan(packStart + 4, 2));
            return rc == Response.ResultNotReady;
        }
    }

    private enum ReplyKind { SingleRow, RecordBlock }
}

/// <summary>
/// Callback invoked once per row. <paramref name="fullRecord"/> covers the
/// full on-disk record (header + column data); use
/// <see cref="Row.DecodeRecord"/> to decode and
/// <see cref="Row.ExtractRecordHash"/> for the row's MD5 (needed for blob
/// fetch). <paramref name="bookmark"/> is the row's physical-record bookmark
/// (empty for single-row replies) — pass it to
/// <see cref="Blob.PhysicalRecordNumberFromBookmark"/> to recover the
/// PhysicalRecordNumber a blob fetch needs. Both spans are valid only for
/// the call duration.
/// </summary>
public delegate void RowHandler(ReadOnlySpan<byte> fullRecord, ReadOnlySpan<byte> bookmark);
