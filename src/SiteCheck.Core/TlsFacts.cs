// CODEMAP FILE: src/SiteCheck.Core/TlsFacts.cs
// Product: Rampart (oli-site-check) — read-only public-surface hostname checker, public pin 1.9.0
// Role: Human labels for SslProtocols and leaf-certificate observations (expiry window, SAN vs hostname).
// Called by: Checker.ReadCertificateAsync path.
// Calls: Models.Finding.
// Invariants: The leaf is recorded even when Windows does not fully trust the chain, so a custom-CA origin still reports. TLS 1.0/1.1 is Attention.
// Sisters: Bastion (bastion-hardening) hardens the local Windows PC. bastion-web is the public storefront and hosts /rampart plus the GitHub asset redirect. oli-web-kits client brochures should already 404 the probe paths this checker GETs.
// Map: docs/CODEMAP.md — read that file first for the run/load graph.

namespace SiteCheck.Core;

/// <summary>
/// See docs/CODEMAP.md.
/// TLS observations from the negotiated cipher suite name. Testable without a socket.
/// </summary>
public static class TlsFacts
{
    public static bool CipherLacksForwardSecrecy(string? cipher)
    {
        if (string.IsNullOrWhiteSpace(cipher)) return false;
        var c = cipher.Replace('-', '_');
        return c.Contains("RSA_WITH", StringComparison.OrdinalIgnoreCase)
            && !c.Contains("DHE", StringComparison.OrdinalIgnoreCase)
            && !c.Contains("ECDHE", StringComparison.OrdinalIgnoreCase)
            && !c.Contains("ECDHE_RSA", StringComparison.OrdinalIgnoreCase);
    }

    public static bool CipherUsesLegacyBulk(string? cipher)
    {
        if (string.IsNullOrWhiteSpace(cipher)) return false;
        var c = cipher.Replace('-', '_');
        return c.Contains("_CBC_", StringComparison.OrdinalIgnoreCase)
            || c.Contains("RC4", StringComparison.OrdinalIgnoreCase)
            || c.Contains("3DES", StringComparison.OrdinalIgnoreCase)
            || c.Contains("DES_CBC", StringComparison.OrdinalIgnoreCase)
            || c.Contains("NULL", StringComparison.OrdinalIgnoreCase);
    }

    public static bool RsaKeyIsWeak(string? algorithm, int? bits) =>
        algorithm != null
        && algorithm.Equals("RSA", StringComparison.OrdinalIgnoreCase)
        && bits is > 0 and < 2048;
}
