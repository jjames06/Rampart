namespace SiteCheck.Core;

/// <summary>
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
