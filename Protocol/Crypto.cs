using System.Security.Cryptography;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;

namespace ExportKing.Protocol;

/// <summary>
/// DBISAM login crypto: Blowfish-CBC with IV=0 and key=MD5(encrypt_password).
/// Recovered from <c>dbsys.exe</c> BPL disassembly + dictionary attack against
/// captured login bytes — see <c>../../Derek/DBISAM-PROTOCOL.md</c> §5.
///
/// The MD5 usage here is dictated by the protocol, not a security choice —
/// DBISAM clients (DFM <c>RemoteEncryptionPassword</c>) all derive the
/// Blowfish key this way. Cannot be substituted.
/// </summary>
public static class Crypto
{
    /// <summary>
    /// Encrypt a DBISAM login plaintext.
    ///
    /// Plaintext format:
    /// <c>[u8 ulen][username][u8 plen][password]</c>, zero-padded to a
    /// multiple of 8 bytes (Blowfish block size). Returns the ciphertext
    /// exactly as written to the wire — same length as the padded plaintext.
    /// </summary>
    public static byte[] EncryptLogin(
        ReadOnlySpan<byte> username,
        ReadOnlySpan<byte> password,
        ReadOnlySpan<byte> encryptPassword)
    {
        // Lengths are single-byte prefixes in the plaintext; anything longer
        // would truncate silently and log in as the wrong user.
        if (username.Length > 255 || password.Length > 255)
        {
            throw new ArgumentException(
                "Exportmaster: username/password longer than 255 bytes cannot be length-prefixed");
        }
        int rawLen = 2 + username.Length + password.Length;
        int pad = (8 - (rawLen % 8)) % 8;
        int paddedLen = rawLen + pad;

        var pt = new byte[paddedLen];
        pt[0] = (byte)username.Length;
        username.CopyTo(pt.AsSpan(1, username.Length));
        pt[1 + username.Length] = (byte)password.Length;
        password.CopyTo(pt.AsSpan(2 + username.Length, password.Length));
        // Tail padding bytes are already zero.

        // Key = MD5(encrypt_password) — 16 bytes. Protocol-mandated, not a choice.
        var key = MD5.HashData(encryptPassword);
        var iv = new byte[8];

        var engine = new BlowfishEngine();
        var cipher = new CbcBlockCipher(engine);
        cipher.Init(forEncryption: true, new ParametersWithIV(new KeyParameter(key), iv));

        var output = new byte[paddedLen];
        for (int i = 0; i < paddedLen; i += 8)
        {
            cipher.ProcessBlock(pt, i, output, i);
        }
        return output;
    }
}
