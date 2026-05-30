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

### 6. ADO.NET surface
- [ ] `DbisamConnection : DbConnection` — `Open`/`Close`/`State`/
      `ConnectionString`; `CreateDbCommand` → `DbisamCommand`;
      `BeginDbTransaction` and `ChangeDatabase` throw `NotSupportedException`
- [ ] `DbisamCommand : DbCommand` — `ExecuteDbDataReader` only; `ExecuteNonQuery`
      and `ExecuteScalar` throw `NotSupportedException`; empty parameter
      collection
- [ ] `DbisamDataReader : DbDataReader` — `Read`, `GetFieldValue<T>`, `GetName`,
      `GetOrdinal`, `FieldCount`, `this[name]`, `this[i]`, `GetSchemaTable`;
      `NextResult` returns false
- [ ] `DbisamConnectionStringBuilder : DbConnectionStringBuilder` — typed
      properties for Host, Port, User Id, Password, Catalog, Batch Size
      (no Compression — LAN-only, never wanted)
- [ ] **Verify:** replicate `ExportMasterService.GetTerritoryMap` using
      `DbisamConnection`; result matches ODBC version exactly

### 7+8. Consumer migration — out of scope for this phase
Per user direction, RocsMiddleware migration is **not** part of this round
of work. The ExportKing library is ready to consume; the per-service
swap (`OdbcConnection`/`OdbcCommand` → `DbisamConnection`/`DbisamCommand`
or the lower-level `DbisamClient`) can happen as a separate task in
`RocsMiddleware`. Affected services (per `grep -rln "exportmaster\|dbisam"
../RocsMiddleware/**.cs`): `X3CustomerPull`, `CustomerIndexer`,
`KeycloakUpdater`, `InvoiceExtractor`, `DLLTest`, `RocsTests`. `EMUpdater`
stays on its XML-RPC path.

### 9. Blob / memo fetch — deferred (cursor preamble unresolved)

**What works:**
- `Messages.BuildOpenBlob` produces bytes that are **byte-for-byte
  identical** to a real DBSYS `0x0280` request (verified offline by
  `OpenBlobMatchesCaptureTest` against `Derek/dbisam-capture-memo.pcapng`
  msg #9).
- Slot structure decoded from the capture: leading `00`, col_ord packed
  4× (twice early, twice in trailer), 16-byte row MD5, `0x01` not-null,
  14-byte PK area null-padded to the column's `max` width, then constant
  16 bytes of trailer including col_ord twice more.
- Outer message has 3 Pack units (cursor_handle, `02 00` tag, slot) plus
  a constant 15-byte inner trailer and 5-byte outer trailer.

**What doesn't work yet:**
- Live `0x0280` against rivsem04 returns server error reqcode `0x3A9A`
  regardless of cursor state (open or closed) or PK width.
- `GetNextRecord (0x00FA)` on the same cursor handle (1) returns the
  same `0x3A9A` — so this is a broader cursor-state problem, not blob
  specific. Likely missing the DBSYS preamble:
  `ResetStatement (0x0334) + BeginDML (0x0316)` before `Prepare`, and
  possibly single-row scrolling mode rather than batched
  `ReadFirstRecordBlock`.
- A second capture using ExportKing's own SQL (not the DBSYS grid flow)
  is the most direct way to pin this down.

**Risk:** an early variant of `BuildOpenBlob` crashed `dbsrvr.exe` (the
listener stopped accepting until manual restart). Server has been stable
under the byte-perfect shape and the GetNextRecord experiment. Probes are
double-gated (`DBISAM_HOST` + `DBISAM_PROBE_BLOBS=1`).

**Resume from:**
- `IntegrationSmokeTests.FetchBlob_DbsysSequence_Probe` — closest to the
  DBSYS sequence; needs adding `ResetStatement`+`BeginDML` preamble and
  iterating.
- `Protocol/OpenBlobMatchesCaptureTest` — proves the bytes; don't break it.
- Development will move to `rivsem04` so captures can be taken alongside
  the C# code changes (the only way to learn the right preamble).

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
