using System.Globalization;
using System.Text.RegularExpressions;

namespace SiteCheck.Core;

/// <summary>
/// Public DNS hostnames only. No IP literals, ports, or home-network suffixes.
/// International names are converted to ASCII (punycode) before checks run.
/// </summary>
public static class Hostname
{
    private static readonly IdnMapping Idn = new();

    private static readonly Regex Label = new(
        "^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)$",
        RegexOptions.CultureInvariant | RegexOptions.Compiled);

    private static readonly string[] BlockedSuffixes =
    {
        ".local", ".localhost", ".internal", ".intranet", ".lan", ".home", ".corp", ".localdomain"
    };

    public static string? Parse(string raw)
    {
        if (string.IsNullOrWhiteSpace(raw) || raw.Length > 253) return null;
        var s = raw.Trim().ToLowerInvariant();
        if (s.StartsWith("http://", StringComparison.Ordinal) || s.StartsWith("https://", StringComparison.Ordinal))
        {
            s = s[(s.IndexOf("://", StringComparison.Ordinal) + 3)..];
        }
        var slash = s.IndexOf('/');
        if (slash >= 0) s = s[..slash];
        var at = s.LastIndexOf('@');
        if (at >= 0) s = s[(at + 1)..];
        if (s.Contains(':')) return null;
        s = s.TrimEnd('.');
        if (!s.Contains('.')) return null;
        if (s.Any(c => c > 127))
        {
            try
            {
                s = Idn.GetAscii(s).ToLowerInvariant();
            }
            catch (ArgumentException)
            {
                return null;
            }
        }
        if (Regex.IsMatch(s, @"^\d+\.\d+\.\d+\.\d+$")) return null;
        if (s.StartsWith('[') || s.Contains('%')) return null;
        foreach (var suffix in BlockedSuffixes)
        {
            if (s == suffix[1..] || s.EndsWith(suffix, StringComparison.Ordinal)) return null;
        }
        if (s == "localhost") return null;
        var labels = s.Split('.');
        if (labels.Length is < 2 or > 10) return null;
        if (labels.Any(lab => !Label.IsMatch(lab))) return null;
        return s;
    }

    /// <summary>
    /// True for names we will send to DNS: a parsed hostname, or _dmarc. plus a parsed apex.
    /// </summary>
    public static bool IsSafeDnsName(string name)
    {
        if (string.IsNullOrWhiteSpace(name) || name.Length > 253) return false;
        if (name.StartsWith("_dmarc.", StringComparison.OrdinalIgnoreCase))
            return Parse(name[7..]) != null;
        return Parse(name) != null;
    }

    public static IReadOnlyList<string> SpfLookupNames(string hostname)
    {
        var names = new List<string> { hostname };
        if (hostname.StartsWith("www.", StringComparison.Ordinal) && hostname.Split('.').Length > 2)
        {
            names.Add(hostname[4..]);
        }
        return names;
    }

    public static bool CertificateCoversHost(string hostname, IEnumerable<string> names)
    {
        var h = hostname.ToLowerInvariant();
        foreach (var raw in names)
        {
            var n = raw.Trim().ToLowerInvariant();
            if (n == h) return true;
            if (n.StartsWith("*.", StringComparison.Ordinal)
                && h.EndsWith(n[1..], StringComparison.Ordinal)
                && h.Split('.').Length == n.Split('.').Length)
            {
                return true;
            }
        }
        return false;
    }
}
