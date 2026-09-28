// CODEMAP FILE: tests/SiteCheck.Tests/HtmlSurfaceTests.cs
// Product: Rampart (oli-site-check) — read-only public-surface hostname checker, public pin 1.9.0
// Role: Locks mixed-content / SRI / tabnabbing / form-action observations on capped HTML.
// Called by: dotnet test.
// Calls: HtmlSurface.
// Invariants: Does not fetch linked scripts.
// Sisters: Bastion (bastion-hardening) hardens the local Windows PC. bastion-web is the public storefront and hosts /rampart plus the GitHub asset redirect. oli-web-kits client brochures should already 404 the probe paths this checker GETs.
// Map: docs/CODEMAP.md — read that file first for the run/load graph.

using SiteCheck.Core;

namespace SiteCheck.Tests;

public class HtmlSurfaceTests
{
    [Fact]
    public void Mixed_content_flags_http_script()
    {
        var f = HtmlSurface.MixedContent("""<script src="http://cdn.example.com/a.js"></script>""");
        Assert.Equal(FindingState.Attention, f.State);
    }

    [Fact]
    public void Mixed_content_clean_on_https_only()
    {
        var f = HtmlSurface.MixedContent("""<script src="https://cdn.example.com/a.js"></script>""");
        Assert.Equal(FindingState.Present, f.State);
    }

    [Fact]
    public void Sri_missing_on_third_party_script()
    {
        var f = HtmlSurface.SubresourceIntegrity("""<script src="https://cdn.example.com/a.js"></script>""");
        Assert.Equal(FindingState.NotFound, f.State);
    }

    [Fact]
    public void Sri_present_when_integrity_attribute_exists()
    {
        var f = HtmlSurface.SubresourceIntegrity("""<script src="https://cdn.example.com/a.js" integrity="sha384-abc"></script>""");
        Assert.Equal(FindingState.Present, f.State);
    }

    [Fact]
    public void Tabnabbing_flags_blank_without_noopener()
    {
        var risky = HtmlSurface.Tabnabbing("""<a href="https://example.com" target="_blank">x</a>""");
        Assert.Equal(FindingState.Attention, risky.State);
        var safe = HtmlSurface.Tabnabbing("""<a href="https://example.com" target="_blank" rel="noopener noreferrer">x</a>""");
        Assert.Equal(FindingState.Present, safe.State);
    }

    [Fact]
    public void Insecure_form_action_is_attention()
    {
        var f = HtmlSurface.InsecureForms("""<form action="http://example.com/login" method="post">""");
        Assert.Equal(FindingState.Attention, f.State);
        var ok = HtmlSurface.InsecureForms("""<form action="/login" method="post">""");
        Assert.Equal(FindingState.Present, ok.State);
    }

    [Fact]
    public void Http_canonical_is_attention()
    {
        var f = HtmlSurface.HttpCanonical("""<link rel="canonical" href="http://example.com/">""");
        Assert.Equal(FindingState.Attention, f.State);
        var ok = HtmlSurface.HttpCanonical("""<link rel="canonical" href="https://example.com/">""");
        Assert.Equal(FindingState.Present, ok.State);
    }
}
