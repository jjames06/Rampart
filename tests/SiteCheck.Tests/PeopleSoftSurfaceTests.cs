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
        var hits = new[] { new FileHit("/psp/", 302, "") };
        var f = PeopleSoftSurface.Summary(hits, "", Array.Empty<string>());
        Assert.Equal(FindingState.Attention, f.State);
        Assert.Contains("CVE-2026-35273", f.Observation);
        Assert.Contains("does not send exploit", f.Caveat, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Homepage_name_is_attention()
    {
        var hits = PeopleSoftSurface.Paths.Select(p => new FileHit(p, 404, "")).ToArray();
        var f = PeopleSoftSurface.Summary(hits, "<title>Oracle PeopleSoft</title>", new[] { "PSJSESSIONID=abc" });
        Assert.Equal(FindingState.Attention, f.State);
    }
}
