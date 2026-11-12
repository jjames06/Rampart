// CODEMAP FILE: tests/SiteCheck.Tests/PeopleSoftSurfaceTests.cs
// Product: Rampart (oli-site-check) — read-only public-surface hostname checker, public pin 1.9.0
// Role: Locks PeopleSoft path list and CVE-2026-35273 prompt-only wording (not RCE proof).
// Called by: dotnet test.
// Calls: PeopleSoftSurface.
// Invariants: No exploit assertions. WAF-only is not the patch.
// Sisters: Bastion (bastion-hardening) hardens the local Windows PC. bastion-web is the public storefront and hosts /rampart plus the GitHub asset redirect. oli-web-kits client brochures should already 404 the probe paths this checker GETs.
// Map: docs/CODEMAP.md — read that file first for the run/load graph.

using SiteCheck.Core;

namespace SiteCheck.Tests;

public class PeopleSoftSurfaceTests
{
    [Fact]
    public void Brochure_without_peoplesoft_is_present()
    {
        var hits = PeopleSoftSurface.Paths.Select(p => new FileHit(p, 404, "not found")).ToArray();
        var f = PeopleSoftSurface.Summary(hits, "<html><body>North Shore IT</body></html>", Array.Empty<string>());
        Assert.Equal(FindingState.Present, f.State);
    }

    [Fact]
    public void Public_portal_is_attention_without_exploit_claim()
    {
        var hits = new[] { new FileHit("/psp/", 302, "", "https://hr.example.edu/psp/ps/?cmd=login") };
        var f = PeopleSoftSurface.Summary(hits, "", Array.Empty<string>());
        Assert.Equal(FindingState.Attention, f.State);
        Assert.Contains("CVE-2026-35273", f.Observation);
        Assert.Contains("does not send exploit", f.Caveat, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Session_cookie_is_attention()
    {
        var hits = PeopleSoftSurface.Paths.Select(p => new FileHit(p, 404, "")).ToArray();
        var f = PeopleSoftSurface.Summary(hits, "<title>Oracle PeopleSoft</title>", new[] { "PSJSESSIONID=abc" });
        Assert.Equal(FindingState.Attention, f.State);
    }

    [Fact]
    public void Brochure_copy_and_next_shell_are_present()
    {
        const string copy = """
            <html><body>__NEXT_DATA__ Rampart GETs /psp/ and names PeopleSoft CVE-2026-35273
            and FortiGate. PeopleTools 8.61 is in the docs.</body></html>
            """;
        var hits = PeopleSoftSurface.Paths.Select(p => new FileHit(p, 200, copy)).ToArray();
        var f = PeopleSoftSurface.Summary(hits, copy, Array.Empty<string>());
        Assert.Equal(FindingState.Present, f.State);
    }

    [Fact]
    public void Empty_redirect_of_the_same_path_is_present()
    {
        var hits = new[] { new FileHit("/psp/", 308, "", "https://www.example.com/psp") };
        var f = PeopleSoftSurface.Summary(hits, "<html>PeopleSoft</html>", Array.Empty<string>());
        Assert.Equal(FindingState.Present, f.State);
    }
}
