using SiteCheck.Core;

namespace SiteCheck.Tests;

public class HeaderFactsTests
{
    [Fact]
    public void Cookie_with_expires_comma_is_one_cookie()
    {
        var finding = HeaderFacts.CookieFinding(new[]
        {
            "session=abc; Expires=Wed, 21 Oct 2026 07:28:00 GMT; HttpOnly; Secure; SameSite=Lax; Path=/"
        });
        Assert.Equal(FindingState.Present, finding.State);
    }

    [Fact]
    public void Cookie_missing_httponly_is_not_found()
    {
        var finding = HeaderFacts.CookieFinding(new[] { "session=abc; Secure; Path=/" });
        Assert.Equal(FindingState.NotFound, finding.State);
    }

    [Fact]
    public void Empty_cookies_are_present()
    {
        var finding = HeaderFacts.CookieFinding(Array.Empty<string>());
        Assert.Equal(FindingState.Present, finding.State);
    }

    [Theory]
    [InlineData("max-age=0", true)]
    [InlineData("max-age=0; includeSubDomains", true)]
    [InlineData("max-age=63072000; includeSubDomains; preload", false)]
    public void Hsts_zero_max_age(string value, bool disables)
    {
        Assert.Equal(disables, HeaderFacts.HstsDisablesHttps(value));
    }

    [Fact]
    public void Csp_unsafe_inline_is_detected()
    {
        Assert.True(HeaderFacts.CspAllowsUnsafeInline("default-src 'self'; script-src 'unsafe-inline'"));
        Assert.False(HeaderFacts.CspAllowsUnsafeInline("default-src 'self'"));
    }

    [Fact]
    public void Dmarc_p_none_is_monitor_only()
    {
        Assert.True(HeaderFacts.DmarcIsMonitorOnly("v=DMARC1; p=none; rua=mailto:a@example.com"));
        Assert.False(HeaderFacts.DmarcIsMonitorOnly("v=DMARC1; p=quarantine"));
        Assert.False(HeaderFacts.DmarcIsMonitorOnly("v=DMARC1; p=reject"));
    }
}
