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
}
