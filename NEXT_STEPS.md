# Next Steps

When you (or future-Claude) come back to this, here's exactly where to pick up.

Read this *before* `PLAN.md`. `PLAN.md` is the staged history; this is the
actionable to-do list.

---

## 1. Move development to rivsem04 (do this first if doing blob work)

Why: Wireshark/tshark must be on the same host as `dbsrvr.exe` to capture
the loopback traffic. The blob-fetch work specifically needs new captures
of ExportKing's own SQL going through.

```powershell
# On rivsem04:
git clone git@github.com:lawless-m/ExportKing.git
cd ExportKing
dotnet test    # 51 unit tests should pass
```

Then to run live tests:
```powershell
$env:DBISAM_HOST = "rivsem04"
$env:DBISAM_USER = "e3user"
$env:DBISAM_PASSWORD = "e3usernew"
dotnet test --filter "FullyQualifiedName~IntegrationSmokeTests"
```

To capture while iterating:
```powershell
& "C:\Program Files\Wireshark\tshark.exe" `
    -i 5 -f "tcp portrange 12000-12010" -w cap.pcapng
# Run your code, Ctrl+C tshark, inspect with `tshark -r cap.pcapng -q -z follow,tcp,raw,0`
```
(Interface 5 is the Npcap loopback adapter — verify with `tshark -D`.)

---

## 2. Blob/memo fetch — ✅ DONE (was the unfinished thing)

Ported from the Rust oracle (the `GetNextRecord` streaming approach) and
**verified live on rivsem04**: `Query(materializeBlobs: true)` returns real
memo/blob content (Memo → `string`, Blob/Graphic → `byte[]`) — including
`SELECT *` on wide tables and a 700-row run (no `0x2303` at scale). The old
`0x3A9A` was never a cursor preamble; it was the slot packing the *column
ordinal* where the server wants the row's *physical record number*. The
`SELECT *`/scale faults the first cut had are solved by streaming, which
takes each row's slot straight from `GetNextRecord` and frees buffers with
the server's echoed slot bytes. See `PLAN.md` §9 for the full write-up.

```powershell
$env:DBISAM_HOST="rivsem04"; $env:DBISAM_USER="e3user"; $env:DBISAM_PASSWORD="e3usernew"
$env:DBISAM_PROBE_BLOBS="1"; $env:EM_BLOB_DEBUG="1"   # EM_BLOB_DEBUG optional, per-row trace
dotnet test --filter "FullyQualifiedName~FetchBlob_NIINGRED_Materialized"
```

**Lifecycle constraint:** one `DbisamClient` per query — reusing a client
for a second query after a streaming blob query desyncs the session. Open a
fresh client per query (matches the oracle and `OdbcConnection`).

**Safety note (still matters):** a malformed OpenBlob crashed `dbsrvr.exe`
once. Blob probes stay double-gated behind `DBISAM_PROBE_BLOBS=1`; after an
experimental variant, check `Test-NetConnection rivsem04 -Port 12005`
before the next one.

---

## 3. ADO.NET surface (task #8 in `TaskList`)

This unlocks drop-in replacement for `OdbcConnection` in RocsMiddleware.
Currently consumers would have to use `DbisamClient.Query` directly,
which works but loses Dapper/`DbDataReader` ecosystem compatibility.

Implement in `Data/`:
- `DbisamConnection : DbConnection`
- `DbisamCommand : DbCommand` (only `ExecuteDbDataReader` works; others throw)
- `DbisamDataReader : DbDataReader`
- `DbisamConnectionStringBuilder : DbConnectionStringBuilder`

See `PLAN.md` §6 for the full method-by-method checklist.

---

## 4. Migrate RocsMiddleware consumers (after #3)

Search-replace `OdbcConnection`/`OdbcCommand` → `DbisamConnection`/
`DbisamCommand` in these files (per `grep -rln "exportmaster\|dbisam"`):

- `X3CustomerPull/Services/ExportMasterService.cs` — start here, it's the simplest
- `CustomerIndexer`
- `KeycloakUpdater`
- `InvoiceExtractor` (only the Exportmaster path; `PostgresService.cs` is unrelated)
- `DLLTest`
- `RocsTests`

Leave `EMUpdater` alone — it's on the XML-RPC path, out of scope.

---

## Reference

- Protocol spec: `../Derek/DBISAM-PROTOCOL.md` (cite by §)
- Rust impl (working SELECT, no blob): `../MrsFlow/mrsflow-cli/src/exportmaster/`
- ODBC bug catalogue (the "why this exists"): `../MrsFlow/KNOWN_BUGS.md` §B1
- Memory: `~/.claude/projects/-nonreplicated-Git-ExportKing/memory/` —
  contains dev server creds (off-repo), DBISAM SQL dialect quirks,
  the "don't crash the server with experimental packets" lesson.

---

**One-line summary:** Blob fetch ✅ (streaming, incl. `SELECT *` and at
scale) → build ADO.NET surface → migrate RocsMiddleware consumers.
