using SiteCheck.Core;

namespace SiteCheck.Tests;

public class HostnameTests
{
    [Theory]
    [InlineData("example.com", "example.com")]
    [InlineData("HTTPS://WWW.Example.COM/path", "www.example.com")]
    public void Parse_accepts_public_hostnames(string raw, string expected)
    {
        Assert.Equal(expected, Hostname.Parse(raw));
    }

    [Theory]
    [InlineData("127.0.0.1")]
    [InlineData("localhost")]
    [InlineData("router.local")]
    [InlineData("http://192.168.1.1")]
    [InlineData("example.com:443")]
    [InlineData("not a host")]
    [InlineData("")]
    public void Parse_rejects_private_and_invalid(string raw)
    {
        Assert.Null(Hostname.Parse(raw));
    }

    [Fact]
    public void Parse_converts_international_names_to_punycode()
    {
        var parsed = Hostname.Parse("https://münchen.de/path");
        Assert.Equal("xn--mnchen-3ya.de", parsed);
    }

    [Fact]
    public void Parse_strips_userinfo_and_never_keeps_a_password()
    {
        Assert.Equal("example.com", Hostname.Parse("https://user@example.com/login"));
        Assert.Equal("example.com", Hostname.Parse("https://user:pass@example.com/login"));
    }

    [Fact]
    public void Spf_names_include_parent_for_www()
    {
        Assert.Equal(new[] { "www.example.com", "example.com" }, Hostname.SpfLookupNames("www.example.com"));
        Assert.Equal(new[] { "example.com" }, Hostname.SpfLookupNames("example.com"));
    }

    [Fact]
    public void Safe_dns_names_allow_dmarc_and_reject_injection()
    {
        Assert.True(Hostname.IsSafeDnsName("example.com"));
        Assert.True(Hostname.IsSafeDnsName("_dmarc.example.com"));
        Assert.False(Hostname.IsSafeDnsName("example.com; calc.exe"));
        Assert.False(Hostname.IsSafeDnsName("-type=TXT evil.com"));
    }

    [Fact]
    public void Certificate_covers_host_or_single_label_wildcard()
    {
        Assert.True(Hostname.CertificateCoversHost("www.example.com", new[] { "www.example.com" }));
        Assert.True(Hostname.CertificateCoversHost("www.example.com", new[] { "*.example.com" }));
        Assert.False(Hostname.CertificateCoversHost("example.com", new[] { "*.example.com" }));
        Assert.False(Hostname.CertificateCoversHost("a.b.example.com", new[] { "*.example.com" }));
    }
}
