namespace SiteCheck.Core;

/// <summary>
/// Small, sourced catalogue. Only versions we can defend. Not a full NVD mirror.
/// Matching is version-range comparison, not exploit traffic.
/// </summary>
public static class CveCatalog
{
    public sealed record Entry(
        string Product,
        string Id,
        string Summary,
        string SourceUrl,
        Func<string?, bool> Matches);

    private static int[] Parts(string v) =>
        v.Split('.').Select(p => int.TryParse(p, out var n) ? n : 0).ToArray();

    private static int Cmp(string a, string b)
    {
        var pa = Parts(a);
        var pb = Parts(b);
        var len = Math.Max(pa.Length, pb.Length);
        for (var i = 0; i < len; i++)
        {
            var x = i < pa.Length ? pa[i] : 0;
            var y = i < pb.Length ? pb[i] : 0;
            if (x != y) return x.CompareTo(y);
        }
        return 0;
    }

    private static bool InRange(string? version, string minInclusive, string maxExclusive) =>
        version != null && Cmp(version, minInclusive) >= 0 && Cmp(version, maxExclusive) < 0;

    private static bool Below(string? version, string maxExclusive) =>
        version != null && Cmp(version, maxExclusive) < 0;

    public static readonly IReadOnlyList<Entry> Entries = new[]
    {
        new Entry(
            "Next.js",
            "GHSA-vcvr-r3jv-pc5j",
            "Next.js 16.2.0 through 16.3.5 Node ImageResponse can lead to remote code execution when untrusted input is rendered. 15.x is not in that RCE range. Floor is 16.3.6.",
            "https://github.com/vercel/next.js/security/advisories/GHSA-vcvr-r3jv-pc5j",
            v => InRange(v, "16.2.0", "16.3.6")),
        new Entry(
            "PHP",
            "PHP-EOL",
            "PHP 5 and 7.x are past end of life. Public CVE volume on those lines is large. Move to a currently supported PHP 8 release from php.net.",
            "https://www.php.net/supported-versions.php",
            v => v != null && (v.StartsWith("5.", StringComparison.Ordinal) || Below(v, "8.0.0"))),
        new Entry(
            "jQuery",
            "jquery-1-2",
            "jQuery 1.x and 2.x have a long public XSS CVE history. Current maintained 3.x releases are listed on jquery.com.",
            "https://jquery.com/download/",
            v => v != null && (v.StartsWith("1.", StringComparison.Ordinal) || v.StartsWith("2.", StringComparison.Ordinal))),
    };

    public static IReadOnlyList<(Entry Entry, StackHint Hint)> Match(IEnumerable<StackHint> stack)
    {
        var hits = new List<(Entry, StackHint)>();
        foreach (var hint in stack)
        {
            foreach (var entry in Entries)
            {
                if (!string.Equals(entry.Product, hint.Product, StringComparison.OrdinalIgnoreCase)) continue;
                if (entry.Matches(hint.Version)) hits.Add((entry, hint));
            }
        }
        return hits;
    }
}
