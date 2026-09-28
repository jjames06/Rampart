using System.Net;
using System.Net.Http;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace SiteCheck.Core;

/// <summary>
/// Read-only checks against a public hostname the operator confirmed they may test.
/// Never follows redirects. Never contacts blocked addresses. Never sends a request body.
/// </summary>
public static class Checker
{
    public const int TimeoutMs = 4500;
    public const string UserAgent = "operation-locked-in-site-check/1.0";

    private static readonly string[] HeaderNames =
    {
        "Strict-Transport-Security",
        "Content-Security-Policy",
        "X-Content-Type-Options",
        "X-Frame-Options",
        "Referrer-Policy",
        "Permissions-Policy"
    };

    public static async Task<CheckReport> RunAsync(string rawHost, CancellationToken cancellationToken = default)
    {
        var hostname = Hostname.Parse(rawHost)
            ?? throw new CheckException("Use a public hostname such as example.com. Do not enter an IP address, localhost, or a home network name.");

        using var timeout = new CancellationTokenSource(TimeoutMs);
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, timeout.Token);

        var publicIps = await ResolvePublicAsync(hostname, linked.Token);
        if (publicIps.Count == 0)
        {
            throw new CheckException("That hostname has no public Internet address, or it only points at a private address. This program does not contact private networks.");
        }

        var ip = publicIps[0];
        var certTask = ReadCertificateAsync(hostname, ip, linked.Token);
        var httpTask = ProbeHttpsAsync(hostname, ip, linked.Token);
        var spfTask = LookupSpfAsync(hostname, linked.Token);
        await Task.WhenAll(certTask, httpTask, spfTask);

        var cert = await certTask;
        var http = await httpTask;
        var spf = await spfTask;

        var findings = new List<Finding>
        {
            HttpsFinding(http),
            CertificateFinding(hostname, cert),
        };
        findings.AddRange(HeaderFindings(http));
        findings.Add(SpfFinding(spf));

        return new CheckReport(
            hostname,
            DateTimeOffset.UtcNow,
            publicIps.Select(a => a.ToString()).ToArray(),
            findings,
            new[]
            {
                "This is a short read-only check, not a penetration test and not a guarantee.",
                "It contacts only public addresses for the hostname you typed, and only after you confirm permission.",
                "It does not follow redirects, crawl pages, guess logins, or send exploit traffic.",
                "Present or not found describes what this program observed. It does not mean the site is safe or unsafe.",
                "Unauthorized access to a computer system is an offence in Canada (Criminal Code s. 342.1) and similar laws elsewhere. Check only hostnames you operate or have written permission to check.",
                "Paid website work still begins after a written quote."
            });
    }

    private static async Task<IReadOnlyList<IPAddress>> ResolvePublicAsync(string hostname, CancellationToken ct)
    {
        IPAddress[] all;
        try
        {
            all = await Dns.GetHostAddressesAsync(hostname, ct);
        }
        catch (Exception)
        {
            return Array.Empty<IPAddress>();
        }
        return all.Where(a => !PrivateIp.IsBlocked(a)).Distinct().ToArray();
    }

    private sealed record CertResult(
        DateTimeOffset? NotAfter,
        IReadOnlyList<string> Names,
        string? Issuer,
        bool Trusted,
        string? Error);

    private static async Task<CertResult> ReadCertificateAsync(string hostname, IPAddress ip, CancellationToken ct)
    {
        try
        {
            using var tcp = new TcpClient(ip.AddressFamily);
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(TimeoutMs);
            await tcp.ConnectAsync(ip, 443, cts.Token);
            await using var stream = tcp.GetStream();
            var trustErrors = SslPolicyErrors.None;
            await using var ssl = new SslStream(stream, false, (_, _, _, errors) =>
            {
                trustErrors = errors;
                return true;
            });
            await ssl.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
            {
                TargetHost = hostname,
                EnabledSslProtocols = System.Security.Authentication.SslProtocols.Tls12 | System.Security.Authentication.SslProtocols.Tls13
            }, cts.Token);

            if (ssl.RemoteCertificate is null)
            {
                return new CertResult(null, Array.Empty<string>(), null, false, "No certificate was presented.");
            }

            using var cert = new X509Certificate2(ssl.RemoteCertificate);
            var names = ReadDnsNames(cert);
            var issuer = cert.GetNameInfo(X509NameType.SimpleName, true);
            if (string.IsNullOrWhiteSpace(issuer)) issuer = cert.Issuer;
            return new CertResult(
                new DateTimeOffset(DateTime.SpecifyKind(cert.NotAfter, DateTimeKind.Local)).ToUniversalTime(),
                names,
                issuer,
                trustErrors == SslPolicyErrors.None,
                null);
        }
        catch (Exception ex) when (ex is SocketException or AuthenticationException or IOException or OperationCanceledException)
        {
            return new CertResult(null, Array.Empty<string>(), null, false, "The TLS handshake did not complete.");
        }
    }

    private static IReadOnlyList<string> ReadDnsNames(X509Certificate2 cert)
    {
        var names = new List<string>();
        var cn = cert.GetNameInfo(X509NameType.DnsName, false);
        if (!string.IsNullOrWhiteSpace(cn)) names.Add(cn.ToLowerInvariant());
        foreach (var ext in cert.Extensions)
        {
            if (ext is X509SubjectAlternativeNameExtension san)
            {
                foreach (var dns in san.EnumerateDnsNames())
                {
                    names.Add(dns.ToLowerInvariant());
                }
            }
        }
        return names.Distinct().ToArray();
    }

    private sealed record HttpResult(int? Status, IReadOnlyDictionary<string, string> Headers, string Note);

    private static async Task<HttpResult> ProbeHttpsAsync(string hostname, IPAddress ip, CancellationToken ct)
    {
        try
        {
            using var handler = new SocketsHttpHandler
            {
                AllowAutoRedirect = false,
                ConnectTimeout = TimeSpan.FromMilliseconds(TimeoutMs),
                SslOptions =
                {
                    TargetHost = hostname,
                    RemoteCertificateValidationCallback = (_, _, _, _) => true
                },
                ConnectCallback = async (context, token) =>
                {
                    var socket = new Socket(ip.AddressFamily, SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
                    try
                    {
                        await socket.ConnectAsync(ip, 443, token);
                        return new NetworkStream(socket, ownsSocket: true);
                    }
                    catch
                    {
                        socket.Dispose();
                        throw;
                    }
                }
            };
            using var client = new HttpClient(handler) { Timeout = TimeSpan.FromMilliseconds(TimeoutMs) };
            using var request = new HttpRequestMessage(HttpMethod.Head, $"https://{hostname}/");
            request.Headers.TryAddWithoutValidation("User-Agent", UserAgent);
            request.Headers.TryAddWithoutValidation("Accept", "text/html,application/xhtml+xml");
            request.Headers.Host = hostname;
            using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, ct);
            var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            foreach (var h in response.Headers)
            {
                headers[h.Key] = string.Join(", ", h.Value);
            }
            foreach (var h in response.Content.Headers)
            {
                headers[h.Key] = string.Join(", ", h.Value);
            }
            var status = (int)response.StatusCode;
            var note = status is >= 300 and < 400
                ? $"HTTPS answered with a redirect ({status}). This program does not follow redirects."
                : "The hostname answered on HTTPS at the first public address.";
            return new HttpResult(status, headers, note);
        }
        catch (Exception)
        {
            return new HttpResult(null, new Dictionary<string, string>(), "HTTPS did not complete within the time limit.");
        }
    }

    private sealed record SpfResult(IReadOnlyList<string> Names, string? Record);

    private static async Task<SpfResult> LookupSpfAsync(string hostname, CancellationToken ct)
    {
        var names = Hostname.SpfLookupNames(hostname);
        foreach (var name in names)
        {
            ct.ThrowIfCancellationRequested();
            var txt = await QueryTxtAsync(name, ct);
            var spf = txt.FirstOrDefault(r => r.StartsWith("v=spf1", StringComparison.OrdinalIgnoreCase));
            if (spf != null) return new SpfResult(names, spf.Length > 240 ? spf[..240] : spf);
        }
        return new SpfResult(names, null);
    }

    private static Task<IReadOnlyList<string>> QueryTxtAsync(string name, CancellationToken ct) =>
        Task.Run(() =>
        {
            try
            {
                return QueryTxtWindows(name);
            }
            catch
            {
                return (IReadOnlyList<string>)Array.Empty<string>();
            }
        }, ct);

    /// <summary>
    /// TXT via nslookup on Windows so we do not take a third-party DNS package.
    /// Parsed only for lines that look like TXT data. Empty on failure.
    /// </summary>
    private static IReadOnlyList<string> QueryTxtWindows(string name)
    {
        var psi = new System.Diagnostics.ProcessStartInfo
        {
            FileName = "nslookup",
            Arguments = $"-type=TXT {name}",
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };
        using var proc = System.Diagnostics.Process.Start(psi);
        if (proc is null) return Array.Empty<string>();
        var output = proc.StandardOutput.ReadToEnd();
        proc.WaitForExit(TimeoutMs);
        var records = new List<string>();
        foreach (var line in output.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries))
        {
            var trimmed = line.Trim();
            if (!trimmed.Contains("text =", StringComparison.OrdinalIgnoreCase) && !trimmed.Contains("\"v=spf1", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }
            var quoted = ExtractQuoted(trimmed);
            if (!string.IsNullOrWhiteSpace(quoted)) records.Add(quoted);
        }
        return records;
    }

    private static string ExtractQuoted(string line)
    {
        var sb = new StringBuilder();
        var inQuote = false;
        foreach (var ch in line)
        {
            if (ch == '"')
            {
                inQuote = !inQuote;
                continue;
            }
            if (inQuote) sb.Append(ch);
        }
        return sb.ToString().Trim();
    }

    private static Finding HttpsFinding(HttpResult http)
    {
        var ok = http.Status is >= 100 and < 500;
        return new Finding(
            "HTTPS",
            ok ? FindingState.Present : FindingState.Incomplete,
            ok ? http.Note + (http.Status is null ? "" : $" HTTP status {http.Status}.") : http.Note,
            "Opened a TLS connection to the first public address on port 443, then sent HTTP HEAD / with no request body and no redirect following.",
            "A response on HTTPS does not mean the site is well configured or that other ports and paths are safe.");
    }

    private static Finding CertificateFinding(string hostname, CertResult cert)
    {
        if (cert.NotAfter is null)
        {
            return new Finding(
                "Certificate",
                FindingState.Incomplete,
                cert.Error ?? "No certificate could be read.",
                "Completed a TLS handshake to the first public address using this hostname as SNI, then read the leaf certificate.",
                "A failed handshake can be a timeout, a firewall, or a name mismatch. This program does not retry other addresses.");
        }

        var days = (int)Math.Floor((cert.NotAfter.Value - DateTimeOffset.UtcNow).TotalDays);
        var covers = Hostname.CertificateCoversHost(hostname, cert.Names);
        var present = days >= 0 && covers;
        var obs = new StringBuilder();
        obs.Append(days >= 0 ? $"{days} day{(days == 1 ? "" : "s")} remaining (UTC {cert.NotAfter.Value:yyyy-MM-dd})." : $"Expired {Math.Abs(days)} day{(Math.Abs(days) == 1 ? "" : "s")} ago.");
        if (!string.IsNullOrWhiteSpace(cert.Issuer)) obs.Append($" Issuer: {cert.Issuer}.");
        obs.Append(covers ? " The certificate names this hostname." : " The certificate does not clearly name this hostname.");
        obs.Append(cert.Trusted ? " Windows trusted the certification path." : " Windows did not fully trust the certification path.");
        return new Finding(
            "Certificate",
            present ? FindingState.Present : FindingState.NotFound,
            obs.ToString(),
            "Read NotAfter and subject alternative names from the leaf certificate presented in the TLS handshake. Trust used the Windows certificate store. Days remaining are whole UTC days.",
            "A named, unexpired certificate does not prove every subdomain or mail server is covered, and it does not prove the operator of the site is who they claim.");
    }

    private static IEnumerable<Finding> HeaderFindings(HttpResult http)
    {
        var csp = http.Headers.TryGetValue("Content-Security-Policy", out var cspVal) ? cspVal : "";
        foreach (var name in HeaderNames)
        {
            var present = http.Headers.ContainsKey(name);
            if (name == "X-Frame-Options" && csp.Contains("frame-ancestors", StringComparison.OrdinalIgnoreCase))
            {
                present = true;
            }
            var hint = name switch
            {
                "Strict-Transport-Security" => "Tells browsers to keep using HTTPS.",
                "Content-Security-Policy" => "Limits scripts, frames, and other sources.",
                "X-Content-Type-Options" => "Stops the browser guessing file types.",
                "X-Frame-Options" => "Clickjacking control. CSP frame-ancestors can cover this too.",
                "Referrer-Policy" => "Limits what other sites see in the Referer header.",
                "Permissions-Policy" => "Turns off camera, microphone, and similar features.",
                _ => name
            };
            yield return new Finding(
                name,
                http.Status is null ? FindingState.Incomplete : present ? FindingState.Present : FindingState.NotFound,
                http.Status is null
                    ? "Headers were not read because HTTPS did not complete."
                    : present
                        ? $"{name} is present. {hint}"
                        : $"{name} was not present on HEAD /. {hint}",
                "Read response headers from HTTP HEAD / on HTTPS. Names are compared without regard to case. Redirects are not followed, so headers on a later URL are not included.",
                "A missing header is a fact about this response, not proof of a breach. Extra headers on other paths are not shown.");
        }
    }

    private static Finding SpfFinding(SpfResult spf)
    {
        if (spf.Record is null)
        {
            return new Finding(
                "SPF",
                FindingState.NotFound,
                $"No v=spf1 TXT record was found on {string.Join(" or ", spf.Names)}.",
                "Asked Windows DNS for TXT records on the hostname and, when the name starts with www, on the parent name. Only records that begin with v=spf1 are counted.",
                "The absence of SPF is not proof that mail is forged. DKIM and DMARC are not checked.");
        }
        return new Finding(
            "SPF",
            FindingState.Present,
            $"An SPF record is published on one of: {string.Join(", ", spf.Names)}.",
            "Asked Windows DNS for TXT records on the hostname and, when the name starts with www, on the parent name. Only records that begin with v=spf1 are counted.",
            "Publishing SPF does not prove mail will pass, and this program does not evaluate include: chains or DMARC.");
    }
}
