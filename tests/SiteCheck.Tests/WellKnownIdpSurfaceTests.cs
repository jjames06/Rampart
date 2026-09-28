// CODEMAP FILE: tests/SiteCheck.Tests/WellKnownIdpSurfaceTests.cs
// Product: Rampart (oli-site-check)
// Role: Locks OpenID metadata Attention-only and http issuer wording.
// Map: docs/CODEMAP.md

using SiteCheck.Core;

namespace SiteCheck.Tests;

public class WellKnownIdpSurfaceTests
{
    [Fact]
    public void Brochure_404_is_silent()
    {
        var hits = WellKnownIdpSurface.Paths.Select(p => new FileHit(p, 404, "not found")).ToArray();
        Assert.Empty(WellKnownIdpSurface.Findings(hits));
    }

    [Fact]
    public void Json_issuer_is_attention_without_token_claim()
    {
        var hits = new[]
        {
            new FileHit("/.well-known/openid-configuration", 200, "{\"issuer\":\"https://auth.example.com\"}")
        };
        var f = Assert.Single(WellKnownIdpSurface.Findings(hits));
        Assert.Equal("OpenID Provider", f.Title);
        Assert.Equal(FindingState.Attention, f.State);
        Assert.Contains("does not", f.Caveat, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("No token request", f.Method, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Http_issuer_is_called_out()
    {
        var hits = new[]
        {
            new FileHit("/.well-known/openid-configuration", 200, "{\"issuer\": \"http://auth.example.com\"}")
        };
        var f = Assert.Single(WellKnownIdpSurface.Findings(hits));
        Assert.Contains("http://", f.Observation, StringComparison.Ordinal);
    }
}
