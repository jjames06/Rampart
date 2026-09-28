// CODEMAP FILE: tests/SiteCheck.Tests/HostnameTests.cs
// Product: Rampart (oli-site-check) — read-only public-surface hostname checker, public pin 1.9.0
// Role: Locks accept/reject table: public DNS names in, IPs/localhost/home suffixes/ports out.
// Called by: dotnet test.
// Calls: Hostname.Parse.
// Invariants: Mirror of bastion-web src/lib/site-check/hostname.ts policy.
// Sisters: Bastion (bastion-hardening) hardens the local Windows PC. bastion-web is the public storefront and hosts /rampart plus the GitHub asset redirect. oli-web-kits client brochures should already 404 the probe paths this checker GETs.
// Map: docs/CODEMAP.md — read that file first for the run/load graph.

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
        Assert.True(Hostname.IsSafeDnsName("default._domainkey.example.com"));
        Assert.True(Hostname.IsSafeDnsName("_mta-sts.example.com"));
        Assert.True(Hostname.IsSafeDnsName("default._bimi.example.com"));
        Assert.True(Hostname.IsSafeDnsName("_smtp._tls.example.com"));
        Assert.False(Hostname.IsSafeDnsName("example.com; calc.exe"));
        Assert.False(Hostname.IsSafeDnsName("-type=TXT evil.com"));
        Assert.False(Hostname.IsSafeDnsName("evil._domainkey.localhost"));
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
