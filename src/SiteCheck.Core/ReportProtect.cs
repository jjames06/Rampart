using System.Security.Cryptography;
using System.Text;

namespace SiteCheck.Core;

/// <summary>
/// Optional at-rest protection for a saved report on Windows.
/// Uses DPAPI for the current Windows user. The executable is not encrypted:
/// GPLv3 desktop source stays public, and packing the EXE does not hide it.
/// </summary>
public static class ReportProtect
{
    public const string Header = "RAMPART-DPAPI-1";
    private static readonly byte[] Entropy = Encoding.UTF8.GetBytes("operation-locked-in-rampart/1.9.0");

    public static bool WindowsUserProtectAvailable => OperatingSystem.IsWindows();

    public static bool LooksProtected(string text) =>
        text.StartsWith(Header + "\n", StringComparison.Ordinal)
        || text.StartsWith(Header + "\r\n", StringComparison.Ordinal);

    public static string ProtectForCurrentWindowsUser(string plaintext)
    {
        if (!OperatingSystem.IsWindows())
            throw new PlatformNotSupportedException("Windows user protection is only available on Windows.");
        var bytes = Encoding.UTF8.GetBytes(plaintext);
        var sealedBytes = ProtectedData.Protect(bytes, Entropy, DataProtectionScope.CurrentUser);
        return Header + "\n" + Convert.ToBase64String(sealedBytes);
    }

    public static string UnprotectForCurrentWindowsUser(string stored)
    {
        if (!LooksProtected(stored)) return stored;
        if (!OperatingSystem.IsWindows())
            throw new PlatformNotSupportedException("This file can only be opened by the Windows user who saved it.");
        var nl = stored.StartsWith(Header + "\r\n", StringComparison.Ordinal) ? 2 : 1;
        var b64 = stored[(Header.Length + nl)..].Trim();
        var sealedBytes = Convert.FromBase64String(b64);
        var plain = ProtectedData.Unprotect(sealedBytes, Entropy, DataProtectionScope.CurrentUser);
        return Encoding.UTF8.GetString(plain);
    }
}
