// CODEMAP FILE: src/SiteCheck.Core/PeopleSoftSurface.cs
// Product: Rampart (oli-site-check) — read-only public-surface hostname checker, public pin 1.9.0
// Role: GET-only detection of public PeopleSoft portal paths (/psp/, /psc/, /ps/, /PSIGW/, /PSEMHUB/) plus PSJSESSIONID. Names CVE-2026-35273 as a patch prompt, not RCE proof.
// Called by: Checker. Tests in PeopleSoftSurfaceTests.
// Calls: Shared ProbeNamedPathsAsync.
// Invariants: No WAF-bypass, no PeopleTools RCE payload, no POST. Attention if the hostname advertises PeopleSoft. Present if those paths are absent. WAF-only is not the patch.
// Sisters: Bastion (bastion-hardening) hardens the local Windows PC. bastion-web is the public storefront and hosts /rampart plus the GitHub asset redirect. oli-web-kits client brochures should already 404 the probe paths this checker GETs.
// Map: docs/CODEMAP.md — read that file first for the run/load graph.

namespace SiteCheck.Core;

/// <summary>
/// See docs/CODEMAP.md.
/// Read-only public-surface hint that Oracle PeopleSoft is internet-facing.
/// GET allowlist only. No POST, no WAF-bypass encoding, no exploit payload.
/// A match is a prompt to confirm Oracle's Critical Patch Update, not proof of RCE.
/// </summary>
public static class PeopleSoftSurface
{
    public static readonly string[] Paths =
    {
        "/psp/",
        "/psc/",
        "/ps/",
        "/PSIGW/",
        "/PSEMHUB/"
    };

    /// <summary>
    /// Runtime portal chrome. The word "PeopleSoft" on a brochure or docs page is not evidence.
    /// </summary>
    public static readonly string[] EvidenceNeedles =
    {
        "PORTAL_HOMEPAGE",
        "ICType",
        "psCHROME",
        "cmd=login",
        "cmd=start",
        "PSJSESSIONID"
    };

    public static Finding Summary(IReadOnlyList<FileHit> hits, string? homepageHtml, IReadOnlyList<string> cookies)
    {
        _ = homepageHtml;
        var live = hits
            .Where(h => Paths.Contains(h.Path, StringComparer.Ordinal) && AdvertisedMatch.PathLooksLike(h, EvidenceNeedles))
            .Select(h => h.Path + " HTTP " + h.Status)
            .Take(8)
            .ToArray();
        var cookieHint = cookies.Any(c => c.StartsWith("PSJSESSIONID", StringComparison.OrdinalIgnoreCase));

        if (live.Length == 0 && !cookieHint)
        {
            return new Finding(
                "Oracle PeopleSoft",
                FindingState.Present,
                "No common public PeopleSoft portal paths answered with PeopleSoft portal chrome, and no PSJSESSIONID cookie was present.",
                "GET allowlisted PeopleSoft paths on the same public address, redirects disabled. Cookies were also read. Copy that names PeopleSoft on a brochure is ignored.",
                "A renamed portal URL is not found this way. Absence is not clearance for other Oracle products.");
        }

        var bits = new List<string>();
        if (live.Length > 0) bits.Add("Paths: " + string.Join("; ", live));
        if (cookieHint) bits.Add("A PeopleSoft session cookie name was present.");
        return new Finding(
            "Oracle PeopleSoft",
            FindingState.Attention,
            "This hostname advertised internet-facing Oracle PeopleSoft. " + string.Join(" ", bits)
                + " CISA lists CVE-2026-35273 as known exploited against PeopleTools 8.61 and 8.62. Confirm the Oracle Critical Patch Update is installed. A WAF rule alone is not the patch.",
            "GET allowlisted PeopleSoft paths. No POST and no exploit payload. Version is taken only if the public surface named it.",
            "This is not proof the host is unpatched and not proof of access. Rampart does not send exploit traffic.");
    }
}
