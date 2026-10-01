// CODEMAP FILE: src/SiteCheck.Core/AdvertisedMatch.cs
// Product: Rampart (oli-site-check) — read-only public-surface hostname checker, public pin 1.9.0
// Role: Shared false-positive guards for enterprise portal cards. A 2xx/3xx on an allowlisted path is not enough; the response must look like that product. Marketing HTML that names the product is not advertisement.
// Called by: PeopleSoftSurface, EnterpriseSurface.
// Calls: FileHit.
// Invariants: GET/HEAD only. Next.js brochure shells (__NEXT_DATA__) are not portals. Trailing-slash redirects of the same path are not portals.
// Sisters: Bastion (bastion-hardening) hardens the local Windows PC. bastion-web is the public storefront and hosts /rampart plus the GitHub asset redirect.
// Map: docs/CODEMAP.md — read that file first for the run/load graph.

namespace SiteCheck.Core;

/// <summary>
/// See docs/CODEMAP.md.
/// Distinguishes a live portal from a brochure that writes about that portal.
/// </summary>
public static class AdvertisedMatch
{
    public static bool ContainsAny(string? text, IEnumerable<string> needles)
    {
        if (string.IsNullOrEmpty(text)) return false;
        foreach (var n in needles)
        {
            if (n.Length == 0) continue;
            if (text.Contains(n, StringComparison.OrdinalIgnoreCase)) return true;
        }
        return false;
    }

    public static bool IsGenericWebAppShell(string? body) =>
        ContainsAny(body, ["__NEXT_DATA__", "/_next/static/"]);

    public static bool IsSamePathRedirect(string requestPath, string? location)
    {
        if (string.IsNullOrWhiteSpace(location)) return false;
        if (!Uri.TryCreate(location, UriKind.RelativeOrAbsolute, out var uri)) return false;
        var locPath = uri.IsAbsoluteUri ? uri.AbsolutePath : location.Split('?', '#')[0];
        var a = TrimSlash(requestPath);
        var b = TrimSlash(locPath);
        var query = uri.IsAbsoluteUri ? uri.Query : (location.Contains('?', StringComparison.Ordinal) ? location[location.IndexOf('?', StringComparison.Ordinal)..] : "");
        return a.Equals(b, StringComparison.OrdinalIgnoreCase) && string.IsNullOrEmpty(query);
    }

    public static bool PathLooksLike(FileHit hit, IEnumerable<string> needles)
    {
        if (hit.Status is not (>= 200 and < 400)) return false;
        var list = needles as string[] ?? needles.ToArray();
        if (ContainsAny(hit.Body, list))
        {
            if (IsGenericWebAppShell(hit.Body)) return false;
            return true;
        }
        if (IsSamePathRedirect(hit.Path, hit.Location)) return false;
        return ContainsAny(hit.Location, list);
    }

    private static string TrimSlash(string path)
    {
        var t = path.TrimEnd('/');
        return t.Length == 0 ? "/" : t;
    }
}
