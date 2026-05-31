using System.Collections;
using System.Data.Common;

namespace ExportKing.Data;

/// <summary>
/// Always-empty parameter collection. ExportKing's initial cut doesn't support
/// parameterised queries (Exportmaster reads are simple SELECTs), so any
/// attempt to add a parameter throws. Present so <see cref="DbisamCommand"/>
/// satisfies the <see cref="DbCommand"/> contract.
/// </summary>
internal sealed class DbisamParameterCollection : DbParameterCollection
{
    private static readonly object _syncRoot = new();

    public override int Count => 0;
    public override object SyncRoot => _syncRoot;

    public override int Add(object value) => throw NotSupported();
    public override void AddRange(Array values) => throw NotSupported();
    public override void Clear() { }
    public override bool Contains(object value) => false;
    public override bool Contains(string value) => false;
    public override void CopyTo(Array array, int index) { }
    public override IEnumerator GetEnumerator() => Array.Empty<DbParameter>().GetEnumerator();
    public override int IndexOf(object value) => -1;
    public override int IndexOf(string parameterName) => -1;
    public override void Insert(int index, object value) => throw NotSupported();
    public override void Remove(object value) => throw NotSupported();
    public override void RemoveAt(int index) => throw NotSupported();
    public override void RemoveAt(string parameterName) => throw NotSupported();
    protected override DbParameter GetParameter(int index) => throw new IndexOutOfRangeException();
    protected override DbParameter GetParameter(string parameterName) => throw new IndexOutOfRangeException();
    protected override void SetParameter(int index, DbParameter value) => throw NotSupported();
    protected override void SetParameter(string parameterName, DbParameter value) => throw NotSupported();

    private static NotSupportedException NotSupported() =>
        new("DBISAM ExportKing: parameterised queries are not supported in this cut.");
}
