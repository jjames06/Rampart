using DnsClient;

namespace SiteCheck.Core;

/// <summary>
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

    public static async Task<IReadOnlyList<string>> QueryCaaAsync(string name, CancellationToken cancellationToken)
    {
        if (!Hostname.IsSafeDnsName(name)) return Array.Empty<string>();
        try
        {
            var result = await Client.QueryAsync(name, QueryType.CAA, cancellationToken: cancellationToken);
            return result.Answers
                .CaaRecords()
                .Select(r => $"{r.Flags} {r.Tag} {r.Value}".Trim())
                .Where(s => s.Length > 0)
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
