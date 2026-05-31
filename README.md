# ExportKing

> **Picking this up?** Read [`NEXT_STEPS.md`](NEXT_STEPS.md) first — it's the
> actionable to-do list. `PLAN.md` is the staged history.

Native-protocol DBISAM client for .NET 9. Talks directly to `dbsrvr.exe` over
TCP, bypassing the broken DBISAM ODBC driver. The initial consumer is
`RocsMiddleware`, replacing every Windows-only `OdbcConnection`-against-
Exportmaster call site there.

## Why this exists

The DBISAM ODBC driver shipped by Elevate Software has four compounding bugs in
its bulk fetch path that cause **silent row loss**, plus it's Windows-only.
Both are deal-breakers for the services that read from Exportmaster:

1. **Silent data loss in bulk fetch.** Verified in MrsFlow against this exact
   server: `Sub Sub Category` returns 26,163 rows via columnar fetch vs 51,823
   rows via row-at-a-time — the driver's internal cursor jumps past entire
   batches it failed to fill. The four underlying defects are catalogued in
   `../MrsFlow/KNOWN_BUGS.md` §B1 (broken SQLLEN indicators, lying
   `SQL_ATTR_ROWS_FETCHED_PTR`, lying `SQL_ATTR_ROW_STATUS_PTR`, partial-fill
   with skipped rows). The only safe ODBC code path is row-at-a-time, which
   takes minutes-to-hours on wide tables (`Ingredients Table`: 53 minutes).

2. **Windows-only.** Every consuming service is currently pinned to a Windows
   host because of the native ODBC DLL.

This library fixes both by speaking DBISAM's TCP protocol directly:

- Cross-platform — sockets in BCL, Blowfish via BouncyCastle, no native DLL
- Correct — uses the protocol's native batched row blocks; no silent row loss
- Drop-in for existing `OdbcConnection` consumers via `System.Data.Common`

## Scope

**In:**
- `SELECT` queries
- Connect + login + session setup + cursor fetch + cleanup
- Memo/blob/graphic column content — `Query(materializeBlobs: true)` streams
  rows via `GetNextRecord` and resolves each handle inline (`0x0280` OpenBlob
  + `0x028A` FreeBlob per row); Memo → `string`, Blob/Graphic → `byte[]`.
  Works on wide / multi-blob tables and at scale (no `0x2303` past ~644
  fetches). Verified live against the Rust oracle — identical payload bytes
  and row counts, including `SELECT *` and a 700-row run.
- ADO.NET surface: `DbisamConnection`, `DbisamCommand`, `DbisamDataReader`,
  `DbisamConnectionStringBuilder`
- Linux and Windows

**Out (explicit non-goals):**
- DML (`INSERT`/`UPDATE`/`DELETE`) — RocsMiddleware writes go through
  Exportmaster's XML-RPC API (`EMUpdater`), not this library
- DDL
- Transactions
- Connection pooling
- Parameterised queries (initial cut — add if a consumer needs them)
- Reusing one `DbisamClient` for multiple sequential queries — the lifecycle
  is one client per query (matches the Rust oracle and the old
  `OdbcConnection` usage). Open a fresh client per query.

## Drop-in usage

```csharp
// Before:
using var conn = new OdbcConnection("DSN=Exportmaster");
using var cmd  = new OdbcCommand("SELECT CountryCode, RITerritoryCode FROM RIGeographic", conn);

// After:
using var conn = new DbisamConnection("Host=rivsem04;Port=12005;User Id=...;Password=...;Catalog=NISAINT_CS");
using var cmd  = new DbisamCommand("SELECT CountryCode, RITerritoryCode FROM RIGeographic", conn);

// Identical from here:
conn.Open();
using var reader = cmd.ExecuteReader();
while (reader.Read())
{
    var code = reader["CountryCode"]?.ToString()?.Trim() ?? "";
    // ...
}
```

Because both types derive from `System.Data.Common.DbConnection` / `DbCommand`
/ `DbDataReader`, indexer access (`reader["..."]`), `GetString` /
`GetFieldValue<T>`, `IDbConnection` interface compliance, and Dapper extension
methods all work unchanged.

The class names stay `Dbisam*` rather than `ExportKing*` — they name the
protocol, which is the useful thing for a future reader to know. `ExportKing`
is just the project name; the wire speaks DBISAM.

## References

- **Protocol spec:** `../Derek/DBISAM-PROTOCOL.md` — 1,566-line
  reverse-engineering notes from packet captures of `dbsys.exe` ↔ `dbsrvr.exe`
  plus binary disassembly of the server. Section numbers cited in code
  comments resolve here.
- **Python reference client:** `../Derek/dbisam_client.py` — first end-to-end
  implementation, used during protocol decoding.
- **Rust reference implementation:** `../MrsFlow/mrsflow-cli/src/exportmaster/` —
  3,242 LoC, production. Used by MrsFlow (Power Query engine) for all
  Exportmaster reads. **This is the working oracle: when the C# port and the
  Rust port disagree on bytes-over-the-wire, the C# port is wrong.**
- **ODBC defect catalogue:** `../MrsFlow/KNOWN_BUGS.md` §B1, §B2 — the case
  for replacing ODBC.

## Validation

The protocol has no published spec; it's reverse-engineered. Correctness is
established by agreement with the Rust reference, not by reasoning from a
standard.

- **Differential testing:** run the same SQL through Rust and C# against the
  same `dbsrvr.exe`, byte-compare outbound packets, row-compare result sets.
  Disagreement = bug in one or the other.
- **Replay testing:** decode the captured `pcapng` files from the Derek repo,
  assert message trees match hand-checked fixtures. Catches codec drift
  without needing a live server.

## Layout

```
ExportKing/
  ExportKing.csproj
  README.md
  PLAN.md
  Protocol/        wire-level concerns, no I/O coupling
    Framing.cs     TCP envelope (20-byte GUID prefix + length)
    Wire.cs        Pack/Unpack primitives
    Crypto.cs      Blowfish-CBC (BouncyCastle)
    Messages.cs    reqcode constants, message records
    Response.cs    response envelope parsing
    Schema.cs      772-byte column-block parser
    Cursor.cs      cursor advance / fetch-block loop
    Row.cs         ftType → CLR type decoding
  Client/
    Client.cs      connect + login + query state machine
  Data/            ADO.NET surface
    DbisamConnection.cs
    DbisamCommand.cs
    DbisamDataReader.cs
    DbisamConnectionStringBuilder.cs
  Tests/           replay fixtures + differential tests
```

See `PLAN.md` for the staged implementation order and current status.
