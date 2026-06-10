using System.Security.Cryptography;
using System.Text;
using ExportKing.Protocol;
using Xunit;

namespace ExportKing.Tests.Protocol;

public class CryptoTests
{
    /// <summary>
    /// Worked example from DBISAM-PROTOCOL.md §5: user `e3user`, password
    /// `e3usernew`, encrypt password `elevatesoft`. The ciphertext below is
    /// the captured bytes from a real dbsys.exe login session and is the
    /// gold-standard correctness check for the crypto port — if these 24
    /// bytes don't match, the login will fail at the server.
    /// </summary>
    [Fact]
    public void LoginCiphertextMatchesDocWorkedExample()
    {
        var ct = Crypto.EncryptLogin(
            "e3user"u8,
            "e3usernew"u8,
            "elevatesoft"u8);

        var expected = new byte[]
        {
            0x57, 0x25, 0x56, 0x8E, 0x56, 0x01, 0xB0, 0x58,
            0xD1, 0x7E, 0xE1, 0x77, 0x20, 0xB6, 0x95, 0x24,
            0x78, 0x1F, 0x5A, 0x02, 0x17, 0xF2, 0x43, 0x90,
        };

        Assert.Equal(expected, ct);
    }

    [Fact]
    public void KeyIsMd5OfEncryptPassword()
    {
        // Sanity-check that MD5("elevatesoft") matches the digest the BPL
        // disassembly recovered. If this fails, .NET's MD5 has somehow
        // diverged — it hasn't, but the assertion documents the value.
        var digest = MD5.HashData("elevatesoft"u8);
        var expected = new byte[]
        {
            0xCE, 0x85, 0x01, 0xAA, 0xC5, 0x39, 0xB4, 0xBD,
            0x4C, 0x54, 0x32, 0x7E, 0x41, 0xD9, 0x75, 0xB0,
        };
        Assert.Equal(expected, digest);
    }

    [Fact]
    public void PlaintextZeroPadsToBlockBoundary()
    {
        // 17-byte plaintext (1 + 6 + 1 + 9) must pad to 24 (next multiple of 8).
        // Verified indirectly: the ciphertext is the same length as the
        // padded plaintext, and the worked example produces 24 bytes for a
        // 17-byte raw plaintext.
        var ct = Crypto.EncryptLogin("e3user"u8, "e3usernew"u8, "elevatesoft"u8);
        Assert.Equal(24, ct.Length);
    }

    [Fact]
    public void RejectsCredentialsLongerThan255Bytes()
    {
        // The plaintext length prefixes are single bytes — a longer value
        // would truncate silently and log in as the wrong user.
        var overlong = new byte[256];
        Array.Fill(overlong, (byte)'a');

        Assert.Throws<ArgumentException>(
            () => Crypto.EncryptLogin(overlong, "pass"u8.ToArray(), "elevatesoft"u8.ToArray()));
        Assert.Throws<ArgumentException>(
            () => Crypto.EncryptLogin("user"u8.ToArray(), overlong, "elevatesoft"u8.ToArray()));
    }

    [Fact]
    public void DifferentPasswordsProduceDifferentCiphertext()
    {
        var a = Crypto.EncryptLogin("user"u8, "passA"u8, "elevatesoft"u8);
        var b = Crypto.EncryptLogin("user"u8, "passB"u8, "elevatesoft"u8);
        Assert.NotEqual(a, b);
    }
}
