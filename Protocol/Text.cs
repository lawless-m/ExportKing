using System.Text;

namespace ExportKing.Protocol;

/// <summary>
/// DBISAM text codec. Exportmaster stores AnsiString data in Windows-1252
/// (Delphi on Windows), so bytes ≥ 0x80 are real characters — £, é, ™ —
/// not noise. Decoding tries strict UTF-8 first (preserves data that is
/// already UTF-8, and pure ASCII passes through unchanged), then falls back
/// to Windows-1252. Port of MrsFlow's <c>decode_dbisam_text</c>
/// (mrsflow-core/src/eval/value.rs), same as Delilah's
/// <c>src/protocol/text.cpp</c>.
///
/// Hand-rolled rather than <c>Encoding.GetEncoding(1252)</c> because code
/// pages aren't bundled with .NET Core — this avoids a package dependency
/// and a process-wide <c>Encoding.RegisterProvider</c> side effect.
/// </summary>
public static class DbisamText
{
    private static readonly UTF8Encoding StrictUtf8 = new(
        encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true);

    /// <summary>
    /// Windows-1252 0x80–0x9F → Unicode. 0x00–0x7F and 0xA0–0xFF are
    /// identity (match Latin-1); only this range is bespoke. The five
    /// undefined slots (0x81, 0x8D, 0x8F, 0x90, 0x9D) map to themselves,
    /// matching the reference implementations.
    /// </summary>
    private static readonly char[] Cp1252High =
    {
        '€', '\u0081', '‚', 'ƒ', '„', '…', '†', '‡',
        'ˆ', '‰', 'Š', '‹', 'Œ', '\u008D', 'Ž', '\u008F',
        '\u0090', '‘', '’', '“', '”', '•', '–', '—',
        '˜', '™', 'š', '›', 'œ', '\u009D', 'ž', 'Ÿ',
    };

    /// <summary>Decode server bytes: valid UTF-8 as UTF-8, else Windows-1252.</summary>
    public static string Decode(ReadOnlySpan<byte> bytes)
    {
        try
        {
            return StrictUtf8.GetString(bytes);
        }
        catch (DecoderFallbackException)
        {
            var chars = new char[bytes.Length];
            for (int i = 0; i < bytes.Length; i++)
            {
                byte b = bytes[i];
                chars[i] = b is >= 0x80 and < 0xA0 ? Cp1252High[b - 0x80] : (char)b;
            }
            return new string(chars);
        }
    }

    /// <summary>
    /// Encode a string as Windows-1252 for the wire (SQL text). Characters
    /// outside the code page become '?', matching classic ANSI behaviour.
    /// </summary>
    public static byte[] Encode(string s)
    {
        var bytes = new byte[s.Length];
        for (int i = 0; i < s.Length; i++)
        {
            char c = s[i];
            if (c <= 'ÿ')
            {
                bytes[i] = (byte)c;
                continue;
            }
            int high = Array.IndexOf(Cp1252High, c);
            bytes[i] = high >= 0 ? (byte)(0x80 + high) : (byte)'?';
        }
        return bytes;
    }
}
