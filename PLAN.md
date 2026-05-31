# ExportKing — Implementation Plan

Staged port from the Rust reference (`../MrsFlow/mrsflow-cli/src/exportmaster/`)
with SELECT-only scope. Each phase is independently verifiable before moving on.

See `README.md` for project intent and scope.

## File mapping

| Rust source | C# target | Rust LoC |
|---|---|---:|
| `framing.rs` | `Protocol/Framing.cs` | 264 |
| `wire.rs` | `Protocol/Wire.cs` | 144 |
| `crypto.rs` | `Protocol/Crypto.cs` | 88 |
| `msg.rs` | `Protocol/Messages.cs` | 410 |
| `response.rs` | `Protocol/Response.cs` | 211 |
| `schema.rs` | `Protocol/Schema.cs` | 256 |
| `cursor.rs` + `cursor_info.rs` | `Protocol/Cursor.cs` | 413 |
| `row.rs` | `Protocol/Row.cs` | 403 |
| `client.rs` (SELECT subset only) | `Client/Client.cs` | ~400 of 780 |
| — | `Data/DbisamConnection.cs` | new |
| — | `Data/DbisamCommand.cs` | new |
| — | `Data/DbisamDataReader.cs` | new |
| — | `Data/DbisamConnectionStringBuilder.cs` | new |

**Skipped (out of scope):** `blob.rs` (memo path — reassess if a real query
needs it), the `execute_dml` half of `client.rs`, the DML/DDL dispatch in
`mod.rs`.

## Phases

### 1. Scaffold ✅
- [x] `ExportKing.csproj` (net9.0, BouncyCastle.Cryptography,
      Microsoft.Extensions.Logging.Abstractions)
- [x] Directory skeleton — `Protocol/`, `Client/`, `Data/`, `Tests/`
- [x] Builds clean (`dotnet build`, 0 warnings)

### 2. Wire foundation ✅ (live-capture replay deferred)
- [x] Port `Framing.cs` — 20-byte GUID+length envelope. Sync `Stream`-based
      I/O (DBISAM is strict request/response — no Pipelines ceremony).
      Compression intentionally **not** ported; LAN-only deployment means
      it's never wanted.
- [x] Port `Wire.cs` — `Walker` for `<u32 LE length><payload>` units.
- [x] **Verified:** 15 xUnit tests pass — wrap layout, 8-byte alignment,
      GUID validation, bad headers, short reads, SendRecv duplex round-trip;
      Walker tests cover the 4 Rust cases plus `NextN` and `Seek` rewind.
- [ ] **Deferred:** replay-decode the first message from
      `dbisam-capture-2.pcapng`. The `.pcapng` and `tshark` are only on the
      Windows capture host; revisit once a byte fixture is extracted.
      Live differential testing in phase 3 will cover the same surface.

### 3. Crypto + login ✅
- [x] Port `Crypto.cs` — Blowfish-CBC via BouncyCastle `BlowfishEngine`;
      key = `MD5("elevatesoft")`. Offline-verified against §5 worked example
      (`e3user`/`e3usernew`/`elevatesoft` → exact 24 ciphertext bytes).
- [x] Implement Connect (`0x0000`) + Login (`0x0014`) per
      `../Derek/DBISAM-PROTOCOL.md` §5, §6g. Also ported `BuildCatalogAttach`
      and the verbatim `SessionSetupC2/C3/Post` constants — the full
      handshake chain.
- [x] **Verified live against `rivsem04:12005`:** Connect → 60-byte response
      containing `DBISAMVCLCSSRC` banner; Login → 12-byte success response;
      C[2], C[3], catalog-attach (NISAINT_CS), Post all accepted. Run with
      `DBISAM_HOST=rivsem04 DBISAM_USER=… DBISAM_PASSWORD=… dotnet test
      --filter IntegrationSmokeTests`.
- [ ] **Deferred:** byte-compare login handshake against Rust client. Live
      success against the same server is strong evidence — the byte-diff
      would only matter if Rust and C# both work but disagree on bytes,
      which can't happen if both successfully authenticate the same user.

### 4. Schema + messages ✅
- [x] Reqcode constants and `MsgBuilder` Pack-stream helper (in `Messages.cs`)
- [x] Appended `BuildQuery`, `BuildExecuteStatement`, `BuildReceive`,
      `BuildSetToBegin`, `BuildReadFirstRecordBlock`,
      `BuildReadNextRecordBlock`, `BuildCloseCursor`, `BuildResetStatement`,
      `BuildRemoveAllRemoteMemoryTables`.
- [x] Ported `Response.cs` — `CursorInfo`, `CursorBatch`, `ReadBatch`
      (single-row), `ReadRecordBlockBatch` (batched).
- [x] Ported `Schema.cs` — 772-byte column-block parser producing
      `List<Column>`, full FieldType resolution table.
- [x] **Verified live:** `SELECT CountryCode, RITerritoryCode FROM
      RIGeographic TOP 5` parses cleanly into 2 String columns with
      `row_offset=25,29`.

### 5. Cursor + row decode ✅
- [x] Ported `Cursor.cs` — `DriveCursor` with full ExecuteStatement →
      Receive-poll → SetToBegin → ReadFirstRecordBlock →
      ReadNextRecordBlock loop. `RowHandler` callback delegate so the
      caller gets row bytes without per-row allocation.
- [x] Ported `Row.cs` — `ftType` → CLR type per §6b. Uses `DateOnly`,
      `TimeOnly`, `DateTime.FromOADate`, `BinaryPrimitives` for the
      respective decodings.
- [x] **Cleanup chain wired into `DbisamClient.Query`** —
      `CloseCursor (0x00A0)` → `ResetStatement (0x0334)` →
      `RemoveAllRemoteMemoryTables (0x0029)` runs in a `try/finally` so
      cleanup happens even on partial-read errors.
- [x] **Verified live:** `RIGeographic TOP 5` returns 5 rows with the
      correct CountryCode→RITerritoryCode pairs (AD→IB, AE→ME, …).
- [ ] **Deferred:** row-for-row diff against Rust output. Strong live
      evidence in place; full byte-diff is bigger machinery than
      worthwhile right now.

### 6. ADO.NET surface ✅
- [x] `DbisamConnection : DbConnection` — `Open`/`Close`/`State`/
      `ConnectionString`; `CreateDbCommand` → `DbisamCommand`;
      `BeginDbTransaction` and `ChangeDatabase` throw `NotSupportedException`.
      Hands out a clean session per query via `AcquireClient()` (the protocol
      is one-cursor-per-session; sequential queries on one session desync, so
      the first query re-uses `Open`'s login and later ones reconnect).
- [x] `DbisamCommand : DbCommand` — `ExecuteDbDataReader` only; `ExecuteNonQuery`
      throws `NotSupportedException` (writes go through the XML-RPC API);
      empty parameter collection. `ExecuteScalar` **works** (first cell) — a
      deliberate deviation from the original "throw" plan, since it's a read
      and helps `SELECT COUNT(*)` drop-ins. `MaterializeBlobs` (bool?)
      overrides the connection's `Materialize Blobs` default per command.
- [x] `DbisamDataReader : DbDataReader` — `Read`, `GetFieldValue<T>` (via base),
      typed getters, `GetName`, `GetOrdinal` (case-insensitive), `FieldCount`,
      `this[name]`, `this[i]`, `GetSchemaTable`, `GetBytes`/`GetChars`;
      `NextResult` returns false. Nulls surface as `DBNull.Value` (ODBC parity).
- [x] `DbisamConnectionStringBuilder : DbConnectionStringBuilder` — typed
      Host, Port, User Id, Password, Catalog, Batch Size, Materialize Blobs
      (no Compression — LAN-only, never wanted).
- [x] **Verified:** offline `AdoNetTests` (builder parse + reader) and live
      `AdoNet_RIGeographic_DropIn` (DbisamConnection + DbisamCommand + reader,
      `reader["CountryCode"]`, ExecuteScalar, ExecuteNonQuery throws).

### 7+8. Consumer migration — out of scope for this phase
Per user direction, RocsMiddleware migration is **not** part of this round
of work. The ExportKing library is ready to consume; the per-service
swap (`OdbcConnection`/`OdbcCommand` → `DbisamConnection`/`DbisamCommand`
or the lower-level `DbisamClient`) can happen as a separate task in
`RocsMiddleware`. Affected services (per `grep -rln "exportmaster\|dbisam"
../RocsMiddleware/**.cs`): `X3CustomerPull`, `CustomerIndexer`,
`KeycloakUpdater`, `InvoiceExtractor`, `DLLTest`, `RocsTests`. `EMUpdater`
stays on its XML-RPC path.

### 9. Blob / memo fetch — ✅ working (ported from the Rust oracle)

**Root cause of the old `0x3A9A` (the preamble hypothesis was wrong):**
there is **no** missing `ResetStatement + BeginDML` preamble and no
single-row scrolling. Blob fetch runs on the *same already-open batched
cursor* (handle 1), after the row scan, before `CloseCursor`. The actual
bug was the **slot contents**: the old `BuildOpenBlob` packed the blob
column's *ordinal* into the slot's repeated 4-byte field, where the server
expects the row's **physical record number**. The old capture test only
ever passed because that one capture row's physical number (5) happened to
equal the `colOrdinal` (5) it was fed; the row's real blob ordinal is 2
(the `02 00` "tag", which is actually `field_ord`).

**The working path — `GetNextRecord` streaming (mirrors MrsFlow
`query_to_table_streaming`).** An earlier batched approach
(`ReadFirstRecordBlock` + deferred `OpenBlob` per handle) materialised
correctly for small explicit-column queries but had two faults that the
oracle hit too: `SELECT *` on wide cursors returned empty payloads (the
per-row bookmark stride is 39 bytes there, not 22, so the phys-at-offset-18
extraction read garbage), and at scale the server returned `0x2303` after
~644 OpenBlobs against the up-front-materialised set. Both are gone with
streaming, which is now the path `Query(materializeBlobs: true)` uses:

- `DbisamClient.DriveStreamingWithBlobs`: ExecuteStatement → Receive-poll →
  SetToBegin (its response seeds the first bookmark) → loop
  `GetNextRecord(handle, bookmark, ~50)`. Each response packs rows as
  `[u16 result_code][10 cursor-info units][slot]`; the **slot is the row in
  physical-record-bookmark form**, so it's both decoded for columns
  (`Row.DecodeRecord(slot)`) *and* passed verbatim to `0x0280` — no phys
  reconstruction, which is why the 22-vs-39 stride problem disappears. The
  last row's cursor-info bookmark seeds the next `GetNextRecord`; the loop
  ends on `result_code = 0x2202`.
- Per blob handle: `0x0280` OpenBlob then `0x028A` FreeBlob using
  **`BlobFetchOutcome.SlotEcho`** (the server-modified slot bytes — e.g.
  `01 fe ff ff ff`). Freeing with the request slot instead of the echo
  leaves buffers un-freed and the per-cursor blob cache fills → `0x2303`.
- `Messages.BuildOpenBlob(cursorHandle, fieldOrd, slot)` is 6 clean Pack
  units (`field_ord` is its own unit, distinct from the slot's phys).
  `Blob.ParseOpenBlobResponse` reads the 3-unit reply (slot echo,
  `<u32 size>`, payload) and surfaces the echo for FreeBlob.

`Blob.BuildSlot` / `PhysicalRecordNumberFromBookmark` and the per-row
bookmark plumbing in `Response.cs`/`Cursor.cs` remain (unit-tested, mirror
the oracle), but the streaming path doesn't need them — they're there for
the legacy batched route and the codec tests.

**Verified live against rivsem04** (`FetchBlob_NIINGRED_Materialized`),
byte-for-byte against the Rust oracle:
- `SELECT NIEAN, NIINGREDS FROM NIINGRED TOP 5` and `SELECT * … TOP 5` —
  payloads 280/257/235/393/88, real ingredient text.
- `SELECT NIEAN, NIINGREDS … TOP 700` — 700 rows, 575 with a memo, no
  `0x2303`. Set `EM_BLOB_DEBUG=1` for per-row tracing.

**Lifecycle:** one `DbisamClient` per query. Reusing a client for a second
query after a streaming blob query desyncs the session (the streaming
teardown differs from the batched cursor's). Open a fresh client per query —
matches the oracle (one connection per query) and the `OdbcConnection` model.

**Risk note:** an early malformed `BuildOpenBlob` crashed `dbsrvr.exe`
once. The byte-perfect shape has been stable across many runs (incl. the
700-row extract); the end-to-end test stays double-gated (`DBISAM_HOST` +
`DBISAM_PROBE_BLOBS=1`).

## Test environment

- **Server:** `rivsem04:12005`
- **Catalog:** `NISAINT_CS`
- **Credentials:** read from environment variables `DBISAM_USER` and
      `DBISAM_PASSWORD`. **Do not commit credentials.** The current
      development credentials are in the project-local Claude memory at
      `~/.claude/projects/-nonreplicated-Git-ExportKing/memory/` (reference
      type — not in git).

## Build

```
dotnet build
dotnet build -c Release
```

ExportKing is its own repo; it does not inherit RocsMiddleware's
`Directory.Build.props` (which pins `RuntimeIdentifier=win-x64` and forces
common service packages). Library output goes to the standard
`bin/{Debug,Release}/net9.0/`. Consumers reference it via `<ProjectReference>`.

## Status

Phase 1 complete. See task list (`TaskList` in the harness) for IDs `#4`–`#10`
matching phases 2–8 above.
