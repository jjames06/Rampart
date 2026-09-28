namespace SiteCheck.Core;

public enum CheckScope
{
    Standard,
    AuthorizedAssessment
}

/// <summary>
/// Lawful-use copy. This is product wording, not legal advice.
/// Sources: Criminal Code (Canada) s. 342.1 and s. 342.2 (Justice Laws website,
/// current to 2026-09-03); Burp Suite Community licence clause requiring
/// authorisation from system owners; Canadian commentary that unsolicited
/// penetration testing may be an offence under s. 342.1.
/// </summary>
public static class LawfulUse
{
    public const string OwnerAttestation =
        "I operate this hostname, or I have written permission from the person who operates it, to run this program against it.";

    public const string RefusalAttestation =
        "I will not use this program against any hostname I do not operate and for which I do not have written permission. Operation Locked In does not authorize, condone, or accept that use. I understand that using a computer system fraudulently and without colour of right can be a criminal offence in Canada under Criminal Code section 342.1, and that similar laws apply in other countries. This screen is not legal advice.";

    public static string ScopeName(CheckScope scope) => scope switch
    {
        CheckScope.AuthorizedAssessment => "Authorized public-surface assessment",
        _ => "Standard public-surface check"
    };

    public static IReadOnlyList<string> MethodsUsed(CheckScope scope)
    {
        var list = new List<string>
        {
            "Resolve public A and AAAA records for the typed hostname",
            "TLS 1.2 or 1.3 handshake on port 443 to a public address, with this hostname as SNI",
            "HTTPS HEAD / and GET / (body capped) with redirects disabled",
            "HTTP HEAD / on port 80 to the same public address",
            "DNS TXT for SPF and DMARC on parsed names only",
            "DNS MX and NS on the apex",
            "Compare advertised product versions with the local advisory catalogue",
            "Read the homepage HTML for mixed http:// resources, form actions, canonical URLs, target=_blank links, and integrity attributes on https:// scripts",
            "Record the negotiated TLS protocol, cipher suite, ALPN, and leaf public-key size",
            "Classify the public edge from apex NS and CDN response headers (Cloudflare, Vercel, and similar)",
            "GET common public sign-in paths on the same address (no passwords, no extra ports, redirects off)"
        };
        if (scope == CheckScope.AuthorizedAssessment)
        {
            list.Add("HTTPS GET /.well-known/security.txt, /robots.txt, and /.well-known/change-password on the typed hostname (RFC public files, body capped)");
            list.Add("HTTPS GET /.well-known/mta-sts.txt on mta-sts. plus the apex (RFC 8461 policy host, public addresses only)");
            list.Add("DNS CAA on the hostname and, when the name starts with www, on the apex");
            list.Add("DNS TXT on common DKIM selectors at _domainkey plus the apex");
            list.Add("DNS DS and DNSKEY on the apex (presence only; the chain is not walked to the root)");
            list.Add("DNS TXT for MTA-STS, BIMI, and SMTP TLS reporting on parsed names only");
        }
        return list;
    }

    public static IReadOnlyList<string> MethodsRefused() =>
    [
        "Exploit payloads, proof-of-concept attack traffic, or password guessing",
        "Port scanning beyond 443 and a single HEAD on 80",
        "Following redirects, crawling, or requesting wp-admin, xmlrpc.php, version.php, or plugin zip files",
        "Contacting private, loopback, link-local, CGNAT, or similar blocked addresses",
        "Uploading the report, or sending advertised versions to NVD, GitHub, or Cloudflare"
    ];

    public static AuthorizationRecord Record(CheckScope scope, DateTimeOffset acceptedAt) =>
        new(
            acceptedAt,
            ScopeName(scope),
            new[] { OwnerAttestation, RefusalAttestation },
            MethodsUsed(scope),
            MethodsRefused());
}

public sealed record AuthorizationRecord(
    DateTimeOffset AcceptedAtUtc,
    string ScopeName,
    IReadOnlyList<string> Attestations,
    IReadOnlyList<string> MethodsUsed,
    IReadOnlyList<string> MethodsRefused);
