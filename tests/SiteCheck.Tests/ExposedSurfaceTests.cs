using SiteCheck.Core;

namespace SiteCheck.Tests;

public class ExposedSurfaceTests
{
    [Fact]
    public void Env_file_body_is_leaked()
    {
        var hit = new FileHit("/.env", 200, "APP_KEY=secret\n");
        Assert.True(ExposedSurface.LooksLeaked(hit));
        var f = ExposedSurface.Summary(new[] { hit });
        Assert.Equal(FindingState.Attention, f.State);
    }

    [Fact]
    public void Html_404_page_is_not_leaked()
    {
        var html = "<html>" + new string('x', 500) + "</html>";
        var hit = new FileHit("/.env", 200, html);
        Assert.False(ExposedSurface.LooksLeaked(hit));
        var f = ExposedSurface.Summary(new[] { hit });
        Assert.Equal(FindingState.Present, f.State);
    }

    [Fact]
    public void Missing_files_are_present()
    {
        var hits = ExposedSurface.Paths.Select(p => new FileHit(p, 404, "not found")).ToArray();
        var f = ExposedSurface.Summary(hits);
        Assert.Equal(FindingState.Present, f.State);
    }

    [Fact]
    public void Www_sibling_is_apex()
    {
        Assert.Equal("example.com", HostPair.Sibling("www.example.com"));
        Assert.Equal("www.example.com", HostPair.Sibling("example.com"));
    }

    [Fact]
    public void Http_location_on_sibling_is_attention()
    {
        var f = HostPair.Summary("www.example.com", "example.com", 301, "http://example.com/", true);
        Assert.Equal(FindingState.Attention, f.State);
    }

    [Fact]
    public void Hsts_includeSubDomains_helper()
    {
        Assert.True(HeaderFacts.HstsHasIncludeSubDomains("max-age=63072000; includeSubDomains"));
        Assert.False(HeaderFacts.HstsHasIncludeSubDomains("max-age=63072000"));
    }

    [Fact]
    public void Control_characters_are_not_hostnames()
    {
        Assert.Null(Hostname.Parse("example.com\r\nHost: evil.test"));
        Assert.Null(Hostname.Parse("example.com?x=1"));
        Assert.Equal("example.com", Hostname.Parse("https://example.com/../../../"));
    }
}
