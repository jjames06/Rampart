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
    [InlineData("::1")]
    public void Blocks_private_and_loopback(string ip)
    {
        Assert.True(PrivateIp.IsBlocked(IPAddress.Parse(ip)));
    }

    [Theory]
    [InlineData("8.8.8.8")]
    [InlineData("1.1.1.1")]
    public void Allows_public_v4(string ip)
    {
        Assert.False(PrivateIp.IsBlocked(IPAddress.Parse(ip)));
    }
}
