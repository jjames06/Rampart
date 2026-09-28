using System.Text.RegularExpressions;

namespace SiteCheck.Core;

/// <summary>
/// Read-only observations from the capped homepage HTML.
/// Looks only at markup already fetched for GET /. Does not download scripts.
/// </summary>
public static class HtmlSurface
{
    private static readonly Regex HttpResource = new(
        @"(?:src|href)\s*=\s*[""'](http://[^""']+)[""']",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.Compiled);

    private static readonly Regex ExternalScript = new(
        @"<script[^>]+src\s*=\s*[""'](https://[^""']+)[""'][^>]*>",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.Compiled);

    public static Finding MixedContent(string? html)
    {
        if (string.IsNullOrEmpty(html))
        {
            return new Finding(
                "Mixed content",
                FindingState.Incomplete,
                "The homepage body was not read, so mixed http:// resources were not checked.",
                "Search the capped GET / HTML for src= or href= values that start with http://.",
                "Scripts loaded after the first 256 KB are not shown.");
        }

        var hits = HttpResource.Matches(html)
            .Select(m => m.Groups[1].Value)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Take(8)
            .ToArray();
        if (hits.Length == 0)
        {
            return new Finding(
                "Mixed content",
                FindingState.Present,
                "No http:// script or link URLs were found in the homepage HTML.",
                "Search the capped GET / HTML for src= or href= values that start with http://.",
                "Inline CSS url() values and resources loaded by later JavaScript are not shown.");
        }

        return new Finding(
            "Mixed content",
            FindingState.Attention,
            "The homepage HTML named http:// resources: " + string.Join(", ", hits) + ".",
            "Search the capped GET / HTML for src= or href= values that start with http://.",
            "Browsers may block these on an HTTPS page. This is not a scan of every subresource.");
    }

    public static Finding SubresourceIntegrity(string? html)
    {
        if (string.IsNullOrEmpty(html))
        {
            return new Finding(
                "Subresource Integrity",
                FindingState.Incomplete,
                "The homepage body was not read, so script integrity attributes were not checked.",
                "Read script src=https:// tags in the capped GET / HTML.",
                "Only the homepage markup is examined.");
        }

        var scripts = ExternalScript.Matches(html).Cast<Match>().ToArray();
        if (scripts.Length == 0)
        {
            return new Finding(
                "Subresource Integrity",
                FindingState.Present,
                "No https:// script URLs were found on the homepage.",
                "Read script tags with an https src in the capped GET / HTML.",
                "Bundled same-origin scripts often have no src=https:// URL. That is expected on Next.js.");
        }

        var missing = scripts.Where(m =>
                m.Value.IndexOf("integrity=", StringComparison.OrdinalIgnoreCase) < 0)
            .Select(m => m.Groups[1].Value)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Take(8)
            .ToArray();
        if (missing.Length == 0)
        {
            return new Finding(
                "Subresource Integrity",
                FindingState.Present,
                "External https:// scripts on the homepage included an integrity attribute.",
                "Read script tags with an https src in the capped GET / HTML.",
                "Integrity on the homepage does not prove every later request is covered.");
        }

        return new Finding(
            "Subresource Integrity",
            FindingState.NotFound,
            "External scripts without integrity: " + string.Join(", ", missing) + ".",
            "Read script tags with an https src in the capped GET / HTML.",
            "Same-origin bundles (for example /_next/static) often omit integrity. Prefer fixing third-party CDNs first.");
    }
}
