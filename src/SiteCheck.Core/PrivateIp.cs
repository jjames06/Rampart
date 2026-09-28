using System.Net;
using System.Net.Sockets;

namespace SiteCheck.Core;

/// <summary>
/// Addresses this tool must never contact: loopback, RFC1918, link-local, CGNAT, documentation, multicast.
/// </summary>
public static class PrivateIp
{
    public static bool IsBlocked(IPAddress ip)
    {
        if (ip.IsIPv4MappedToIPv6) ip = ip.MapToIPv4();
        if (IPAddress.IsLoopback(ip)) return true;
        if (ip.Equals(IPAddress.Any) || ip.Equals(IPAddress.IPv6Any) || ip.Equals(IPAddress.None)) return true;

        if (ip.AddressFamily == AddressFamily.InterNetwork)
        {
            var b = ip.GetAddressBytes();
            var a = b[0];
            var c = b[1];
            var d = b[2];
            if (a is 0 or 10 or 127) return true;
            if (a == 169 && c == 254) return true;
            if (a == 172 && c is >= 16 and <= 31) return true;
            if (a == 192 && c == 168) return true;
            if (a == 100 && c is >= 64 and <= 127) return true;
            if (a == 192 && c == 0 && d is 0 or 2) return true;
            if (a == 198 && c is 18 or 19) return true;
            if (a == 198 && c == 51 && d == 100) return true;
            if (a == 203 && c == 0 && d == 113) return true;
            if (a >= 224) return true;
            return false;
        }

        if (ip.AddressFamily == AddressFamily.InterNetworkV6)
        {
            if (ip.IsIPv6LinkLocal || ip.IsIPv6Multicast || ip.IsIPv6SiteLocal) return true;
            if (ip.IsIPv6UniqueLocal) return true;
            var bytes = ip.GetAddressBytes();
            if (bytes.All(x => x == 0)) return true;
            return false;
        }

        return true;
    }

    public static bool IsBlocked(string text) =>
        IPAddress.TryParse(text, out var ip) && IsBlocked(ip);
}
