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
    public void Parse_rejects_private_and_invalid(string raw)
    {
        Assert.Null(Hostname.Parse(raw));
    }

    [Fact]
    public void Spf_names_include_parent_for_www()
    {
        Assert.Equal(new[] { "www.example.com", "example.com" }, Hostname.SpfLookupNames("www.example.com"));
        Assert.Equal(new[] { "example.com" }, Hostname.SpfLookupNames("example.com"));
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
