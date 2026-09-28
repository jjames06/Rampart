// CODEMAP FILE: src/SiteCheck.Core/Fingerprint.cs
// Product: Rampart (oli-site-check) — read-only public-surface hostname checker, public pin 1.9.0
// Role: Product/version from Server/X-Powered-By/generator meta/script comments. Feeds AdvisoryDb. Plugin slugs are not versions.
// Called by: Checker after headers + HTML.
// Calls: StackHint records.
// Invariants: No advertised version means no CVE match. Do not download wp-content/plugins to guess versions.
// Sisters: Bastion (bastion-hardening) hardens the local Windows PC. bastion-web is the public storefront and hosts /rampart plus the GitHub asset redirect. oli-web-kits client brochures should already 404 the probe paths this checker GETs.
// Map: docs/CODEMAP.md — read that file first for the run/load graph.

using System.Text.RegularExpressions;

namespace SiteCheck.Core;

/// <summary>
/// See docs/CODEMAP.md.
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
        AddEdgeFromHeaders(hints, headers);

        if (!string.IsNullOrEmpty(html))
        {
            foreach (Match m in Generator.Matches(html)) AddGenerator(hints, m.Groups[1].Value);
            foreach (Match m in GeneratorAlt.Matches(html)) AddGenerator(hints, m.Groups[1].Value);
            AddHtmlStack(hints, html);
            hints.AddRange(AdvisoryDb.DetectFromHtml(html));
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
        var nginx = Regex.Match(v, @"nginx/([0-9]+\.[0-9]+(?:\.[0-9]+)?)", RegexOptions.IgnoreCase);
        if (nginx.Success)
        {
            hints.Add(new StackHint("nginx", nginx.Groups[1].Value, $"Header {header}: {Trim(v)}"));
            return;
        }
        if (v.Contains("nginx", StringComparison.OrdinalIgnoreCase))
        {
            hints.Add(new StackHint("nginx", null, $"Header {header}: {Trim(v)}"));
            return;
        }
        var apache = Regex.Match(v, @"Apache/([0-9]+\.[0-9]+(?:\.[0-9]+)?)", RegexOptions.IgnoreCase);
        if (apache.Success)
        {
            hints.Add(new StackHint("Apache HTTP Server", apache.Groups[1].Value, $"Header {header}: {Trim(v)}"));
        }
    }

    private static void AddEdgeFromHeaders(List<StackHint> hints, IReadOnlyDictionary<string, string> headers)
    {
        void Edge(string product, string header)
        {
            if (headers.TryGetValue(header, out _) && hints.All(h => !h.Product.Equals(product, StringComparison.OrdinalIgnoreCase)))
                hints.Add(new StackHint(product, null, "Response header " + header + " was present."));
        }

        Edge("Amazon CloudFront", "x-amz-cf-id");
        Edge("Amazon CloudFront", "x-amz-cf-pop");
        Edge("Azure Front Door", "x-azure-ref");
        Edge("Netlify", "x-nf-request-id");
        Edge("Shopify", "x-shopify-stage");
        Edge("Shopify", "x-shopid");
        Edge("Sucuri", "x-sucuri-id");
        Edge("Akamai", "x-akamai-transformed");
        Edge("Fastly", "x-fastly-request-id");
        Edge("GitHub Pages", "x-github-request-id");
        Edge("Fly.io", "fly-request-id");
        if (headers.TryGetValue("server", out var server)
            && server.Contains("GitHub.com", StringComparison.OrdinalIgnoreCase)
            && hints.All(h => !h.Product.Equals("GitHub Pages", StringComparison.OrdinalIgnoreCase)))
        {
            hints.Add(new StackHint("GitHub Pages", null, "Server header named GitHub.com."));
        }
    }

    private static void AddHtmlStack(List<StackHint> hints, string html)
    {
        if ((html.Contains("/_next/static", StringComparison.Ordinal)
             || html.Contains("__NEXT_DATA__", StringComparison.Ordinal))
            && hints.All(h => !h.Product.Equals("Next.js", StringComparison.OrdinalIgnoreCase)))
        {
            hints.Add(new StackHint("Next.js", null, "Homepage HTML named /_next/static or __NEXT_DATA__."));
        }
        if ((html.Contains("/wp-content/", StringComparison.OrdinalIgnoreCase)
             || html.Contains("/wp-includes/", StringComparison.OrdinalIgnoreCase))
            && hints.All(h => !h.Product.Equals("WordPress", StringComparison.OrdinalIgnoreCase)))
        {
            hints.Add(new StackHint("WordPress", null, "Homepage HTML named /wp-content/ or /wp-includes/."));
        }
        if (html.Contains("cdn.shopify.com", StringComparison.OrdinalIgnoreCase)
            && hints.All(h => !h.Product.Equals("Shopify", StringComparison.OrdinalIgnoreCase)))
        {
            hints.Add(new StackHint("Shopify", null, "Homepage HTML named cdn.shopify.com."));
        }
        if (html.Contains("squarespace.com", StringComparison.OrdinalIgnoreCase)
            && hints.All(h => !h.Product.Equals("Squarespace", StringComparison.OrdinalIgnoreCase)))
        {
            hints.Add(new StackHint("Squarespace", null, "Homepage HTML named squarespace.com."));
        }
        if (html.Contains("static.wixstatic.com", StringComparison.OrdinalIgnoreCase)
            && hints.All(h => !h.Product.Equals("Wix", StringComparison.OrdinalIgnoreCase)))
        {
            hints.Add(new StackHint("Wix", null, "Homepage HTML named static.wixstatic.com."));
        }
        if ((html.Contains("PeopleSoft", StringComparison.OrdinalIgnoreCase)
             || html.Contains("PSIGW", StringComparison.OrdinalIgnoreCase))
            && hints.All(h => !h.Product.Equals("Oracle PeopleSoft", StringComparison.OrdinalIgnoreCase)))
        {
            var ver = Regex.Match(html, @"PeopleTools\s+([0-9]+\.[0-9]+(?:\.[0-9]+)?)", RegexOptions.IgnoreCase);
            hints.Add(new StackHint(
                "Oracle PeopleSoft",
                ver.Success ? ver.Groups[1].Value : null,
                "Homepage HTML named PeopleSoft."));
        }
        foreach (var product in EnterpriseSurface.Products)
        {
            if (hints.Any(h => h.Product.Equals(product.Title, StringComparison.OrdinalIgnoreCase)))
                continue;
            if (!product.HtmlNeedles.Any(n => html.Contains(n, StringComparison.OrdinalIgnoreCase)))
                continue;
            hints.Add(new StackHint(product.Title, null, "Homepage HTML named " + product.Title + "."));
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
