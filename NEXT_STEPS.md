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

## 2. Finish blob/memo fetch (the unfinished thing)

**State:** `Messages.BuildOpenBlob` produces bytes that are byte-for-byte
identical to a real DBSYS `0x0280` request — see
`ExportKing.Tests/Protocol/OpenBlobMatchesCaptureTest.cs`. But the live
server returns error `0x3A9A`. The same error fires on `GetNextRecord`,
so the issue is **cursor state preamble**, not the OpenBlob bytes.

**Hypothesis:** DBSYS sends `ResetStatement (0x0334) + BeginDML (0x0316)`
*before* `PrepareStatement`, and uses single-row scrolling (`GetNextRecord`
0x00FA / `GetPriorRecord` 0x0104 / `SetToBookmark` 0x0154) instead of our
batched `ReadFirstRecordBlock`. We don't do either.

**Resume from:**
- `ExportKing.Tests/IntegrationSmokeTests.cs::FetchBlob_DbsysSequence_Probe`
  — closest existing experiment.
- Capture DBSYS on rivsem04 doing the **same SQL** you want ExportKing to
  serve (not the grid flow that's in `dbisam-capture-memo.pcapng`).
- Diff the captured C→S sequence against what ExportKing sends, fill in
  the missing preamble messages.

**Safety note (matters):** A malformed OpenBlob crashed `dbsrvr.exe` once.
Restart was needed. All blob probe tests are double-gated behind
`DBISAM_PROBE_BLOBS=1`; keep that gate. After each experimental run, probe
the server with `Test-NetConnection rivsem04 -Port 12005` (or the Linux
equivalent) before sending another variant.

**When it works:** flip `materializeBlobs:true` in `DbisamClient.Query`
from `throw new NotImplementedException(…)` to actually doing the fetch
loop. The hook is already there in `MaterializeBlobsInPlace`.

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

**One-line summary:** Move dev to rivsem04 → finish blob fetch by replaying
the DBSYS preamble → build ADO.NET surface → migrate RocsMiddleware
consumers.
