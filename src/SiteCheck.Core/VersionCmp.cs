// CODEMAP FILE: src/SiteCheck.Core/VersionCmp.cs
// Product: Rampart (oli-site-check) — read-only public-surface hostname checker, public pin 1.9.0
// Role: Dotted version compare for advisory ranges (including x wildcards from Retire.js).
// Called by: AdvisoryDb.
// Calls: None.
// Invariants: Unknown junk versions do not match. Do not SemVer-coerce 'latest'.
// Sisters: Bastion (bastion-hardening) hardens the local Windows PC. bastion-web is the public storefront and hosts /rampart plus the GitHub asset redirect. oli-web-kits client brochures should already 404 the probe paths this checker GETs.
// Map: docs/CODEMAP.md — read that file first for the run/load graph.

namespace SiteCheck.Core;

/// <summary>
/// See docs/CODEMAP.md.
/// Numeric dotted-version compare used for advisory ranges. Pre-release suffixes
/// on a segment are ignored (1.9.0b1 compares as 1.9.0).
/// </summary>
public static class VersionCmp
{
    public static int Compare(string a, string b)
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

    public static bool Satisfies(string version, string op, string bound)
    {
        var c = Compare(version, bound);
        return op switch
        {
            ">=" => c >= 0,
            ">" => c > 0,
            "<=" => c <= 0,
            "<" => c < 0,
            "=" => c == 0,
            _ => false
        };
    }

    public static bool InRetireRange(string version, string? atOrAbove, string? below)
    {
        if (atOrAbove is null && below is null) return false;
        if (atOrAbove != null && Compare(version, atOrAbove) < 0) return false;
        if (below != null && Compare(version, below) >= 0) return false;
        return true;
    }

    private static int[] Parts(string v)
    {
        var bits = v.Split('.', StringSplitOptions.RemoveEmptyEntries);
        var n = new int[bits.Length];
        for (var i = 0; i < bits.Length; i++)
        {
            var s = bits[i];
            var len = 0;
            while (len < s.Length && char.IsDigit(s[len])) len++;
            n[i] = len == 0 ? 0 : int.TryParse(s[..len], out var p) ? p : 0;
        }
        return n;
    }
}
