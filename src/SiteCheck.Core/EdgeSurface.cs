namespace SiteCheck.Core;

/// <summary>
/// Classifies the public edge from nameservers, response headers, and homepage HTML.
/// Does not log in to Cloudflare, Vercel, or any other dashboard.
/// </summary>
public static class EdgeSurface
{
    public static bool HasCloudflareNameservers(string? nsRecord) =>
        !string.IsNullOrWhiteSpace(nsRecord)
        && nsRecord.Contains("ns.cloudflare.com", StringComparison.OrdinalIgnoreCase);

    public static bool HasCloudflareRay(IReadOnlyDictionary<string, string> headers) =>
        headers.Keys.Any(k =>
            k.Equals("cf-ray", StringComparison.OrdinalIgnoreCase)
            || k.Equals("cf-cache-status", StringComparison.OrdinalIgnoreCase));

    public static bool HasVercel(IReadOnlyDictionary<string, string> headers) =>
        headers.Keys.Any(k =>
            k.Equals("x-vercel-id", StringComparison.OrdinalIgnoreCase)
            || k.Equals("x-vercel-cache", StringComparison.OrdinalIgnoreCase));

    public static string? OtherCdnName(IReadOnlyList<StackHint> stack)
    {
        foreach (var name in new[]
        {
            "Amazon CloudFront", "Azure Front Door", "Fastly", "Akamai",
            "Sucuri", "Netlify", "Fly.io"
        })
        {
            if (stack.Any(s => s.Product.Equals(name, StringComparison.OrdinalIgnoreCase)))
                return name;
        }
        return null;
    }

    public static EdgeProfile Classify(
        string? nsRecord,
        IReadOnlyDictionary<string, string> headers,
        IReadOnlyList<StackHint> stack)
    {
        var cfNs = HasCloudflareNameservers(nsRecord);
        var cfRay = HasCloudflareRay(headers);
        var vercel = HasVercel(headers) || stack.Any(s => s.Product.Equals("Vercel", StringComparison.OrdinalIgnoreCase));
        var other = OtherCdnName(stack);

        if (cfRay)
        {
            return new EdgeProfile(EdgeKind.CloudflareProxied, "Cloudflare", cfNs, true, vercel);
        }
        if (cfNs)
        {
            return new EdgeProfile(EdgeKind.CloudflareDnsOnly, "Cloudflare DNS", true, false, vercel);
        }
        if (other != null)
        {
            return new EdgeProfile(EdgeKind.OtherCdn, other, false, false, vercel);
        }
        if (vercel)
        {
            return new EdgeProfile(EdgeKind.VercelOnly, "Vercel", false, false, true);
        }
        return new EdgeProfile(EdgeKind.Origin, "Origin", false, false, false);
    }

    public static Finding PublicEdgeFinding(EdgeProfile edge) => edge.Kind switch
    {
        EdgeKind.CloudflareProxied => new Finding(
            "Public edge",
            FindingState.Present,
            "HTTPS responses include Cloudflare headers (cf-ray or cf-cache-status)"
                + (edge.CloudflareNameservers ? ", and the apex nameservers are Cloudflare." : ".")
                + (edge.VercelOrigin ? " Vercel headers are also present, which is expected when Vercel is the origin behind Cloudflare." : ""),
            "Read NS on the apex and Cloudflare or Vercel headers on HTTPS HEAD / and GET /.",
            "This program does not log in to Cloudflare. Orange-cloud versus grey-cloud is inferred from public headers."),
        EdgeKind.CloudflareDnsOnly => new Finding(
            "Public edge",
            FindingState.Attention,
            "Apex nameservers are Cloudflare, but HTTPS responses have no cf-ray. DNS is on Cloudflare and the orange cloud (proxy) is likely off.",
            "Read NS on the apex and Cloudflare headers on HTTPS HEAD / and GET /.",
            "Grey-cloud DNS still uses Cloudflare for records. It does not put WAF, bot, or DDoS protection in front of HTTPS."),
        EdgeKind.VercelOnly => new Finding(
            "Public edge",
            FindingState.Attention,
            "Vercel headers are present and Cloudflare is not in front. The browser is talking to Vercel as the public edge.",
            "Read Vercel and Cloudflare headers on HTTPS HEAD / and GET /, and NS on the apex.",
            "Vercel is a working origin. A CDN such as Cloudflare in front is optional extra protection, not proof the site is unsafe."),
        EdgeKind.OtherCdn => new Finding(
            "Public edge",
            FindingState.Present,
            "This hostname is already behind " + edge.Provider + ". Cloudflare was not required for this run.",
            "Read CDN response headers on HTTPS HEAD / and GET /.",
            "This program does not rank CDNs. Keep the edge you already operate unless you have a reason to move."),
        _ => new Finding(
            "Public edge",
            FindingState.Attention,
            "No CDN or reverse-proxy headers were advertised. The browser appears to be talking to the origin or host directly.",
            "Read NS on the apex and common CDN headers on HTTPS HEAD / and GET /.",
            "A missing CDN is not a breach. Many small sites publish from the host. A public website that faces the Internet usually benefits from an edge such as Cloudflare.")
    };

    public static IEnumerable<Finding> CloudflareSurface(
        string? html,
        IReadOnlyDictionary<string, string> headers,
        EdgeProfile edge)
    {
        if (edge.Kind != EdgeKind.CloudflareProxied)
            yield break;

        if (!string.IsNullOrEmpty(html))
        {
            if (html.Contains("email-decode.min.js", StringComparison.OrdinalIgnoreCase))
            {
                yield return new Finding(
                    "Cloudflare email obfuscation",
                    FindingState.Attention,
                    "The homepage loads Cloudflare email-decode.min.js. Email Address Obfuscation injects a script that a strict Content-Security-Policy will block.",
                    "Search the capped GET / HTML for email-decode.min.js.",
                    "This is a Cloudflare dashboard setting, not a next.config.ts header. Turning it off is the usual fix when CSP is already tight.");
            }
            else
            {
                yield return new Finding(
                    "Cloudflare email obfuscation",
                    FindingState.Present,
                    "The homepage does not load email-decode.min.js.",
                    "Search the capped GET / HTML for email-decode.min.js.",
                    "The setting can still be on for other paths. This check is the homepage only.");
            }

            if (html.Contains("static.cloudflareinsights.com", StringComparison.OrdinalIgnoreCase)
                || html.Contains("beacon.min.js", StringComparison.OrdinalIgnoreCase))
            {
                yield return new Finding(
                    "Cloudflare Web Analytics",
                    FindingState.Attention,
                    "The homepage loads Cloudflare Web Analytics (beacon.min.js). That injects a third-party script and often fights a tight CSP.",
                    "Search the capped GET / HTML for static.cloudflareinsights.com or beacon.min.js.",
                    "Disable Real User Measurements in Cloudflare Web Analytics if first-party analytics already cover this site.");
            }

            if (html.Contains("rocket-loader.min.js", StringComparison.OrdinalIgnoreCase)
                || html.Contains("data-cf-settings", StringComparison.OrdinalIgnoreCase))
            {
                yield return new Finding(
                    "Cloudflare Rocket Loader",
                    FindingState.Attention,
                    "The homepage shows Cloudflare Rocket Loader. It rewrites scripts and can break a modern Next.js or CSP site.",
                    "Search the capped GET / HTML for rocket-loader.min.js or data-cf-settings.",
                    "Turn Rocket Loader off in Cloudflare Speed settings for an App Router site.");
            }
        }

        if (headers.TryGetValue("cf-cache-status", out var cache)
            && cache.Equals("HIT", StringComparison.OrdinalIgnoreCase))
        {
            yield return new Finding(
                "Cloudflare HTML cache",
                FindingState.Attention,
                "cf-cache-status is HIT on the homepage HTML. Cached HTML can serve a stale deploy after you publish.",
                "Read cf-cache-status on HTTPS GET /.",
                "Bypass cache for HTML document routes. Cache /_next/static/ and brand assets. This is not a WAF finding.");
        }
    }
}
