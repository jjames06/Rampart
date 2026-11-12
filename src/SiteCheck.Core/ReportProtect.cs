// CODEMAP FILE: src/SiteCheck.Core/ReportProtect.cs
// Product: Rampart (oli-site-check) — read-only public-surface hostname checker, public pin 1.9.0
// Role: Optional Windows DPAPI wrap of a saved report (CurrentUser). No-op on Linux/macOS/mobile.
// Called by: WPF save checkbox. Avalonia no-op off Windows.
// Calls: ProtectedData (System.Security.Cryptography.ProtectedData).
// Invariants: This is not product encryption and not a substitute for TLS. Do not pack the GPLv3 EXE inside an encrypted blob.
// Sisters: Bastion (bastion-hardening) hardens the local Windows PC. bastion-web is the public storefront and hosts /rampart plus the GitHub asset redirect. oli-web-kits client brochures should already 404 the probe paths this checker GETs.
// Map: docs/CODEMAP.md — read that file first for the run/load graph.

using System.Security.Cryptography;
using System.Text;

namespace SiteCheck.Core;

/// <summary>
/// See docs/CODEMAP.md.
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
