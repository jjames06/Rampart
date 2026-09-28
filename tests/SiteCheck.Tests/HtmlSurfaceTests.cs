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
