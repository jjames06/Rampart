// CODEMAP FILE: src/SiteCheck.Core/DnsTxt.cs
// Product: Rampart (oli-site-check) — read-only public-surface hostname checker, public pin 1.9.0
// Role: SPF, DMARC, MX, NS, CAA, DNSSEC DS/RRSIG via DnsClient (UDP/TCP 53 to public resolvers).
// Called by: Checker parallel with HTTPS.
// Calls: DnsClient NuGet (Apache-2.0).
// Invariants: Authorized scope may add extra RFC records. Do not AXFR. CAA how-to on kits is letsencrypt.org + pki.goog.
// Sisters: Bastion (bastion-hardening) hardens the local Windows PC. bastion-web is the public storefront and hosts /rampart plus the GitHub asset redirect. oli-web-kits client brochures should already 404 the probe paths this checker GETs.
// Map: docs/CODEMAP.md — read that file first for the run/load graph.

using DnsClient;

namespace SiteCheck.Core;

/// <summary>
/// See docs/CODEMAP.md.
/// TXT lookups through the system resolver via DnsClient. Names must pass IsSafeDnsName.
/// </summary>
public static class DnsTxt
{
    private static readonly LookupClient Client = new(new LookupClientOptions
    {
        Timeout = TimeSpan.FromMilliseconds(4000),
        Retries = 1,
        UseCache = true,
        ThrowDnsErrors = false
    });

    public static async Task<IReadOnlyList<string>> QueryAsync(string name, CancellationToken cancellationToken)
    {
        if (!Hostname.IsSafeDnsName(name)) return Array.Empty<string>();
        try
        {
            var result = await Client.QueryAsync(name, QueryType.TXT, cancellationToken: cancellationToken);
            return result.Answers.TxtRecords()
                .Select(r => string.Concat(r.Text))
                .Where(s => !string.IsNullOrWhiteSpace(s))
                .ToArray();
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception)
        {
            return Array.Empty<string>();
        }
    }

    public static async Task<IReadOnlyList<string>> QueryMxAsync(string name, CancellationToken cancellationToken)
    {
        if (!Hostname.IsSafeDnsName(name)) return Array.Empty<string>();
        try
        {
            var result = await Client.QueryAsync(name, QueryType.MX, cancellationToken: cancellationToken);
            return result.Answers.MxRecords()
                .OrderBy(r => r.Preference)
                .Select(r => $"{r.Preference} {r.Exchange}")
                .ToArray();
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception)
        {
            return Array.Empty<string>();
        }
    }

    public static async Task<IReadOnlyList<string>> QueryDsAsync(string name, CancellationToken cancellationToken)
    {
        if (!Hostname.IsSafeDnsName(name)) return Array.Empty<string>();
        try
        {
            var result = await Client.QueryAsync(name, QueryType.DS, cancellationToken: cancellationToken);
            return result.Answers
                .Select(a => a.ToString())
                .Where(s => !string.IsNullOrWhiteSpace(s))
                .ToArray();
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception)
        {
            return Array.Empty<string>();
        }
    }

    public static async Task<IReadOnlyList<string>> QueryNsAsync(string name, CancellationToken cancellationToken)
    {
        if (!Hostname.IsSafeDnsName(name)) return Array.Empty<string>();
        try
        {
            var result = await Client.QueryAsync(name, QueryType.NS, cancellationToken: cancellationToken);
            return result.Answers.NsRecords()
                .Select(r => r.NSDName.ToString().TrimEnd('.'))
                .Where(s => !string.IsNullOrWhiteSpace(s))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .OrderBy(s => s, StringComparer.OrdinalIgnoreCase)
                .ToArray();
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception)
        {
            return Array.Empty<string>();
        }
    }

    public static async Task<IReadOnlyList<string>> QueryDnsKeyAsync(string name, CancellationToken cancellationToken)
    {
        if (!Hostname.IsSafeDnsName(name)) return Array.Empty<string>();
        try
        {
            var result = await Client.QueryAsync(name, QueryType.DNSKEY, cancellationToken: cancellationToken);
            return result.Answers
                .Select(a => a.ToString())
                .Where(s => !string.IsNullOrWhiteSpace(s))
                .ToArray();
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception)
        {
            return Array.Empty<string>();
        }
    }

    public static async Task<IReadOnlyList<string>> QueryCaaAsync(string name, CancellationToken cancellationToken)
    {
        if (!Hostname.IsSafeDnsName(name)) return Array.Empty<string>();
        try
        {
            var result = await Client.QueryAsync(name, QueryType.CAA, cancellationToken: cancellationToken);
            return result.Answers
                .Select(a => a.ToString())
                .Where(s => !string.IsNullOrWhiteSpace(s) && s.Contains("CAA", StringComparison.OrdinalIgnoreCase))
                .ToArray();
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception)
        {
            return Array.Empty<string>();
        }
    }
}
