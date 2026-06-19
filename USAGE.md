# Using ExportKing from another .NET service

A consumer's quickstart. If you only need to **read** from Exportmaster, this is everything —
you do not need to understand the protocol.

> The **`Catalog` is the DBISAM logical alias**. For the Nisa International data it is
> **`NISAINT_CS`** — verified against the live server (653 tables; see
> `../MrsFlow/mrsflow-cli/examples/em_smoke.rs`) and the builder's default.

## 1. Reference it

ExportKing is not on NuGet — add a project reference:

```xml
<ProjectReference Include="..\..\..\ExportKing\ExportKing.csproj" />
```

## 2. Connection string

`DbisamConnection` parses the same ADO.NET-style keys as the builder
(`DbisamConnectionStringBuilder`):

| Key | Meaning | Default |
|-----|---------|---------|
| `Host` | machine running `dbsrvr.exe` | (required) |
| `Port` | DBISAM TCP port | `12005` |
| `User Id` | login user | (required) |
| `Password` | login password | (required) |
| `Catalog` | **DBISAM logical alias** (see warning above) | `NISAINT_CS` |
| `Batch Size` | rows per fetch block | `5000` |
| `Materialize Blobs` | fetch memo/blob/graphic inline as `string`/`byte[]` | `true` |

For Exportmaster on RIVSEM01 (verified working in production via SuperSub):

```
Host=RIVSEM01;Port=12005;User Id=...;Password=...;Catalog=NISAINT_CS
```

Never hard-code the login — pull it from the KeePass store (`../Keepass-access-libs`,
`KdbxCredentials`).

## 3. Read

Drop-in for any old `OdbcConnection` against Exportmaster — `DbisamConnection`/`DbisamCommand`/
`DbisamDataReader` derive from `System.Data.Common`, so indexers, `GetFieldValue<T>`, and Dapper
all work:

```csharp
using ExportKing.Data;

var csb = new DbisamConnectionStringBuilder
{
    Host = "RIVSEM01", Port = 12005,
    UserId = user, Password = password,
    Catalog = "NISAINT_CS",
};

using var conn = new DbisamConnection(csb.ConnectionString);
conn.Open();
using var cmd = conn.CreateCommand();
cmd.CommandText = "SELECT code, desc1, uf_ibarcode FROM Product WHERE code IN ('1042751','1042753')";
using var reader = cmd.ExecuteReader();
while (reader.Read())
{
    string code = reader["code"]?.ToString()?.Trim() ?? "";
    // DBISAM CHAR columns are space-padded — trim string fields.
}
```

## 4. Write (DML)

`INSERT`/`UPDATE`/`DELETE` run through `ExecuteNonQuery()`, which returns rows affected. There are
no parameters — build the SQL with inline literals and single-quote-escape any string values.
`../Rupert` is the worked example (it checks what already exists, then inserts on one reused
connection):

```csharp
static string Esc(string s) => s.Replace("'", "''");

using var ins = new DbisamCommand(
    $"INSERT INTO PSATTRIB (SATAGTYPE, SACODE, SATAG) VALUES ({tagType}, '{Esc(code)}', '{Esc(flag)}')",
    conn);
int inserted = ins.ExecuteNonQuery();
```

See `../Rupert/backend/src/Rupert.Cgi/Program.cs` for the full check-then-insert flow.

## 5. Things to know

- **No parameterised queries.** Inline literals only, single-quote escaped — as in the read and
  write examples above.
- **One query per low-level session.** The ADO.NET `DbisamConnection` hides this — it runs the
  first query on the `Open()` session and silently reconnects for each later command, so multiple
  commands per connection are fine. (The raw `DbisamClient` is one-query-per-session.)
- **Trim strings.** Fixed-width CHAR columns come back space-padded.
- Correctness is established by agreement with the Rust oracle in `../MrsFlow`, not a published
  spec — if results look wrong, diff against it.
