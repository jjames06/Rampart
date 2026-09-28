namespace SiteCheck.Core;

/// <summary>
/// Header observations that must stay testable without opening a socket.
/// </summary>
public static class HeaderFacts
{
    public static bool CookieMissingRequiredFlags(string setCookie) =>
        setCookie.IndexOf("HttpOnly", StringComparison.OrdinalIgnoreCase) < 0
        || setCookie.IndexOf("Secure", StringComparison.OrdinalIgnoreCase) < 0;

    public static Finding CookieFinding(IReadOnlyList<string> cookies)
    {
        var list = cookies.Where(c => !string.IsNullOrWhiteSpace(c)).ToArray();
        if (list.Length == 0)
        {
            return new Finding(
                "Cookie flags",
                FindingState.Present,
                "No Set-Cookie header on the homepage response.",
                "Read each Set-Cookie value on HTTPS HEAD / and GET / as a separate cookie, not as a comma-joined string.",
                "Cookies set on other paths are not shown.");
        }

        var weak = list.Where(CookieMissingRequiredFlags).ToArray();
        if (weak.Length == 0)
        {
            return new Finding(
                "Cookie flags",
                FindingState.Present,
                list.Length == 1
                    ? "The Set-Cookie header on this response included HttpOnly and Secure."
                    : $"All {list.Length} Set-Cookie headers on this response included HttpOnly and Secure.",
                "Read each Set-Cookie value on HTTPS HEAD / and GET / as a separate cookie. Flags are searched as whole-header substrings.",
                "This does not prove every cookie on the site is safe. Treat it as a hint and confirm in the browser developer tools.");
        }

        return new Finding(
            "Cookie flags",
            FindingState.NotFound,
            weak.Length == 1
                ? "A Set-Cookie header was present without both HttpOnly and Secure on this response."
                : $"{weak.Length} of {list.Length} Set-Cookie headers on this response were missing HttpOnly or Secure.",
            "Read each Set-Cookie value on HTTPS HEAD / and GET / as a separate cookie. Expires dates contain commas, so cookies are not split on commas.",
            "This is a hint from the homepage response. Confirm flags in the browser developer tools.");
    }

    /// <summary>
    /// True when HSTS is present but tells the browser to forget HTTPS (max-age is zero or negative).
    /// </summary>
    public static bool HstsDisablesHttps(string value)
    {
        foreach (var part in value.Split(';'))
        {
            var p = part.Trim();
            if (!p.StartsWith("max-age", StringComparison.OrdinalIgnoreCase)) continue;
            var eq = p.IndexOf('=');
            if (eq < 0) continue;
            var raw = p[(eq + 1)..].Trim().Trim('"');
            if (long.TryParse(raw, out var n) && n <= 0) return true;
        }
        return false;
    }

    public static bool CspAllowsUnsafeInline(string value) =>
        value.Contains("unsafe-inline", StringComparison.OrdinalIgnoreCase);

    public static bool DmarcIsMonitorOnly(string record)
    {
        foreach (var part in record.Split(';'))
        {
            var p = part.Trim();
            if (!p.StartsWith("p=", StringComparison.OrdinalIgnoreCase)) continue;
            var policy = p[2..].Trim();
            return policy.Equals("none", StringComparison.OrdinalIgnoreCase);
        }
        return false;
    }
}
