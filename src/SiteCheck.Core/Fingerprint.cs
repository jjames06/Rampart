using System.Text.RegularExpressions;

namespace SiteCheck.Core;

/// <summary>
/// Public-surface fingerprints from headers and a capped homepage body only.
/// Does not fetch plugin files, admin paths, or version.php.
/// </summary>
public static class Fingerprint
{
    private static readonly Regex Generator = new(
        @"<meta[^>]+name\s*=\s*[""']generator[""'][^>]+content\s*=\s*[""']([^""']+)[""']",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.Compiled);

    private static readonly Regex GeneratorAlt = new(
        @"<meta[^>]+content\s*=\s*[""']([^""']+)[""'][^>]+name\s*=\s*[""']generator[""']",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.Compiled);

    private static readonly Regex WpPlugin = new(
        @"/wp-content/plugins/([a-z0-9_-]+)/",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.Compiled);

    private static readonly Regex Jquery = new(
        @"jquery(?:[.-]|/)+([0-9]+\.[0-9]+(?:\.[0-9]+)?)",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.Compiled);

    public static IReadOnlyList<StackHint> FromPublicSurface(
        IReadOnlyDictionary<string, string> headers,
        string? html)
    {
        var hints = new List<StackHint>();
        AddHeaderProduct(hints, headers, "X-Powered-By");
        AddHeaderProduct(hints, headers, "Server");

        if (headers.TryGetValue("x-vercel-id", out _) || headers.TryGetValue("x-vercel-cache", out _))
        {
            hints.Add(new StackHint("Vercel", null, "Vercel response headers were present."));
        }
        if (headers.TryGetValue("cf-ray", out _) || headers.TryGetValue("cf-cache-status", out _))
        {
            hints.Add(new StackHint("Cloudflare", null, "Cloudflare response headers were present."));
        }

        if (!string.IsNullOrEmpty(html))
        {
            foreach (Match m in Generator.Matches(html)) AddGenerator(hints, m.Groups[1].Value);
            foreach (Match m in GeneratorAlt.Matches(html)) AddGenerator(hints, m.Groups[1].Value);
            var jq = Jquery.Match(html);
            if (jq.Success)
            {
                hints.Add(new StackHint("jQuery", jq.Groups[1].Value, "A script URL on the homepage named this jQuery version."));
            }
        }

        return hints
            .GroupBy(h => h.Product + "|" + (h.Version ?? ""), StringComparer.OrdinalIgnoreCase)
            .Select(g => g.First())
            .ToArray();
    }

    public static IReadOnlyList<string> WordPressPluginSlugs(string? html)
    {
        if (string.IsNullOrEmpty(html)) return Array.Empty<string>();
        return WpPlugin.Matches(html)
            .Select(m => m.Groups[1].Value.ToLowerInvariant())
            .Distinct()
            .OrderBy(s => s)
            .Take(20)
            .ToArray();
    }

    private static void AddHeaderProduct(List<StackHint> hints, IReadOnlyDictionary<string, string> headers, string header)
    {
        if (!headers.TryGetValue(header, out var value) || string.IsNullOrWhiteSpace(value)) return;
        var v = value.Trim();
        if (v.StartsWith("Next.js", StringComparison.OrdinalIgnoreCase))
        {
            hints.Add(new StackHint("Next.js", VersionAfter(v, "Next.js"), $"Header {header}: {Trim(v)}"));
            return;
        }
        if (v.StartsWith("PHP/", StringComparison.OrdinalIgnoreCase) || v.Contains("PHP/", StringComparison.OrdinalIgnoreCase))
        {
            var php = Regex.Match(v, @"PHP/([0-9]+\.[0-9]+(?:\.[0-9]+)?)", RegexOptions.IgnoreCase);
            hints.Add(new StackHint("PHP", php.Success ? php.Groups[1].Value : null, $"Header {header}: {Trim(v)}"));
            return;
        }
        if (v.Contains("IIS", StringComparison.OrdinalIgnoreCase))
        {
            hints.Add(new StackHint("IIS", null, $"Header {header}: {Trim(v)}"));
            return;
        }
        if (v.Contains("nginx", StringComparison.OrdinalIgnoreCase))
        {
            hints.Add(new StackHint("nginx", null, $"Header {header}: {Trim(v)}"));
        }
    }

    private static void AddGenerator(List<StackHint> hints, string content)
    {
        var c = content.Trim();
        var wp = Regex.Match(c, @"WordPress\s+([0-9]+\.[0-9]+(?:\.[0-9]+)?)", RegexOptions.IgnoreCase);
        if (wp.Success)
        {
            hints.Add(new StackHint("WordPress", wp.Groups[1].Value, "HTML meta generator on the homepage."));
            return;
        }
        hints.Add(new StackHint(Trim(c), null, "HTML meta generator on the homepage."));
    }

    private static string? VersionAfter(string raw, string prefix)
    {
        var rest = raw[prefix.Length..].Trim().TrimStart('/');
        var m = Regex.Match(rest, @"^[0-9]+\.[0-9]+(?:\.[0-9]+)?");
        return m.Success ? m.Value : null;
    }

    private static string Trim(string s) => s.Length > 80 ? s[..80] : s;
}
