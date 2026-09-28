using System.Net;
using SiteCheck.Core;

namespace SiteCheck.Tests;

public class PrivateIpTests
{
    [Theory]
    [InlineData("127.0.0.1")]
    [InlineData("10.0.0.5")]
    [InlineData("192.168.0.1")]
    [InlineData("169.254.169.254")]
    [InlineData("172.16.0.1")]
    [InlineData("100.64.0.1")]
    [InlineData("192.0.2.1")]
    [InlineData("198.51.100.1")]
    [InlineData("203.0.113.1")]
    [InlineData("224.0.0.1")]
    [InlineData("::1")]
    [InlineData("fe80::1")]
    [InlineData("fc00::1")]
    [InlineData("fd12:3456:789a::1")]
    [InlineData("2001:db8::1")]
    [InlineData("100::1")]
    [InlineData("64:ff9b::10.0.0.1")]
    [InlineData("64:ff9b:1::1")]
    [InlineData("2002:c0a8:0001::1")]
    [InlineData("::ffff:192.168.1.1")]
    public void Blocks_private_and_loopback(string ip)
    {
        Assert.True(PrivateIp.IsBlocked(IPAddress.Parse(ip)));
    }

    [Theory]
    [InlineData("8.8.8.8")]
    [InlineData("1.1.1.1")]
    [InlineData("2001:4860:4860::8888")]
    [InlineData("64:ff9b::8.8.8.8")]
    [InlineData("2002:0808:0808::1")]
    public void Allows_public_addresses(string ip)
    {
        Assert.False(PrivateIp.IsBlocked(IPAddress.Parse(ip)));
    }
}
