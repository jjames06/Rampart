using System.Net;
using System.Net.Sockets;

namespace SiteCheck.Core;

/// <summary>
/// Addresses this tool must never contact: loopback, RFC1918, link-local, CGNAT,
/// documentation, multicast, discard, unique-local, and IPv4 embedded in NAT64 or 6to4.
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
            var second = b[1];
            var third = b[2];
            if (a is 0 or 10 or 127) return true;
            if (a == 169 && second == 254) return true;
            if (a == 172 && second is >= 16 and <= 31) return true;
            if (a == 192 && second == 168) return true;
            if (a == 100 && second is >= 64 and <= 127) return true;
            if (a == 192 && second == 0 && third is 0 or 2) return true;
            if (a == 198 && second is 18 or 19) return true;
            if (a == 198 && second == 51 && third == 100) return true;
            if (a == 203 && second == 0 && third == 113) return true;
            if (a >= 224) return true;
            return false;
        }

        if (ip.AddressFamily == AddressFamily.InterNetworkV6)
        {
            if (ip.IsIPv6LinkLocal || ip.IsIPv6Multicast || ip.IsIPv6SiteLocal) return true;
            if (ip.IsIPv6UniqueLocal) return true;
            var bytes = ip.GetAddressBytes();
            if (bytes.All(x => x == 0)) return true;

            // 2001:db8::/32 documentation
            if (bytes[0] == 0x20 && bytes[1] == 0x01 && bytes[2] == 0x0d && bytes[3] == 0xb8) return true;

            // 100::/64 discard prefix
            if (bytes[0] == 0x01 && bytes[1] == 0x00 && PrefixZero(bytes, 2, 6)) return true;

            // 64:ff9b:1::/48 local-use NAT64 (meant for a translator on this network)
            if (bytes[0] == 0x00 && bytes[1] == 0x64 && bytes[2] == 0xff && bytes[3] == 0x9b
                && bytes[4] == 0x00 && bytes[5] == 0x01)
            {
                return true;
            }

            // 64:ff9b::/96 well-known NAT64: last 32 bits are IPv4
            if (bytes[0] == 0x00 && bytes[1] == 0x64 && bytes[2] == 0xff && bytes[3] == 0x9b
                && PrefixZero(bytes, 4, 8))
            {
                return IsBlocked(new IPAddress(bytes[12..16]));
            }

            // 2002::/16 6to4: next 32 bits are IPv4
            if (bytes[0] == 0x20 && bytes[1] == 0x02)
            {
                return IsBlocked(new IPAddress(new[] { bytes[2], bytes[3], bytes[4], bytes[5] }));
            }

            // Deprecated IPv4-compatible ::a.b.c.d (96-bit prefix of zeros)
            if (PrefixZero(bytes, 0, 12))
            {
                return IsBlocked(new IPAddress(bytes[12..16]));
            }

            return false;
        }

        return true;
    }

    public static bool IsBlocked(string text) =>
        IPAddress.TryParse(text, out var ip) && IsBlocked(ip);

    private static bool PrefixZero(byte[] bytes, int start, int length)
    {
        for (var i = 0; i < length; i++)
        {
            if (bytes[start + i] != 0) return false;
        }
        return true;
    }
}
