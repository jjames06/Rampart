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
    public const int TimeoutMs = 8000;
    public const int MaxTlsAttempts = 3;
    public const int MaxBodyBytes = 256 * 1024;
    public const string UserAgent = "operation-locked-in-site-check/1.2";

    private static readonly string[] HeaderNames =
    {
        "Strict-Transport-Security",
        "Content-Security-Policy",
        "X-Content-Type-Options",
        "X-Frame-Options",
        "Referrer-Policy",
        "Permissions-Policy"
    };

    public static async Task<CheckReport> RunAsync(
        string rawHost,
        IProgress<string>? progress = null,
        CancellationToken cancellationToken = default)
    {
        var hostname = Hostname.Parse(rawHost)
            ?? throw new CheckException("Use a public hostname such as example.com. Do not enter an IP address, localhost, or a home network name.");

        progress?.Report("Resolving public Internet addresses.");
        var publicIps = await ResolvePublicAsync(hostname, cancellationToken);
        if (publicIps.Count == 0)
        {
            throw new CheckException("That hostname has no public Internet address, or it only points at a private address. This program does not contact private networks.");
        }

        var orderedIps = publicIps
            .OrderBy(a => a.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork ? 0 : 1)
            .ToArray();

        progress?.Report("Opening TLS on a public address.");
        IPAddress? workingIp = null;
        CertResult cert = new(null, Array.Empty<string>(), null, false, null, "The TLS handshake did not complete.");
        foreach (var candidate in orderedIps.Take(MaxTlsAttempts))
        {
            cancellationToken.ThrowIfCancellationRequested();
            var attempt = await ReadCertificateAsync(hostname, candidate, cancellationToken);
            if (attempt.NotAfter != null || attempt.TlsProtocol != null)
            {
                workingIp = candidate;
                cert = attempt;
                break;
            }
        }
        var ip = workingIp ?? orderedIps[0];

        progress?.Report("Reading HTTPS headers, the homepage, mail records, and HTTP on port 80.");
        var httpTask = ProbeHttpsAsync(hostname, ip, cancellationToken);
        var pageTask = ReadHomepageAsync(hostname, ip, cancellationToken);
        var spfTask = LookupSpfAsync(hostname, cancellationToken);
        var dmarcTask = LookupDmarcAsync(hostname, cancellationToken);
        var http80Task = ProbeHttpPort80Async(hostname, ip, cancellationToken);
        await Task.WhenAll(httpTask, pageTask, spfTask, dmarcTask, http80Task);

        var http = await httpTask;
        var page = await pageTask;
        var spf = await spfTask;
        var dmarc = await dmarcTask;
        var http80 = await http80Task;

        var headers = MergeHeaders(http.Headers, page.Headers);
        var stack = Fingerprint.FromPublicSurface(headers, page.Body);
        var plugins = Fingerprint.WordPressPluginSlugs(page.Body);

        var findings = new List<Finding>
        {
            HttpsFinding(http),
            CertificateFinding(hostname, cert),
            TlsFinding(cert),
            HttpRedirectFinding(http80),
        };
        findings.AddRange(HeaderFindings(http.Status ?? page.Status, headers));
        var cookies = (http.Cookies ?? Array.Empty<string>()).Concat(page.Cookies ?? Array.Empty<string>()).ToArray();
        findings.Add(HeaderFacts.CookieFinding(cookies));
        findings.Add(ServerDisclosureFinding(headers));
        findings.Add(SpfFinding(spf));
        findings.Add(DmarcFinding(dmarc));
        findings.AddRange(CveFindings(stack));
        if (plugins.Count > 0)
        {
            findings.Add(new Finding(
                "Plugins",
                FindingState.Attention,
                "Homepage URLs named these WordPress plugin directories: " + string.Join(", ", plugins) + ".",
                "Read script and link URLs from the first 256 KB of GET /. Plugin files were not downloaded.",
                "A path on the homepage is not proof the plugin is vulnerable. It is only evidence it is linked."));
        }

        var certDays = cert.NotAfter is null
            ? (int?)null
            : (int)Math.Floor((cert.NotAfter.Value - DateTimeOffset.UtcNow).TotalDays);

        var next = Advice.Build(
            hostname,
            findings,
            stack,
            plugins,
            certDays,
            cert.TlsProtocol,
            http80.Status,
            http80.Location);

        return new CheckReport(
            hostname,
            DateTimeOffset.UtcNow,
            publicIps.Select(a => a.ToString()).ToArray(),
            findings,
            next,
            stack,
            new[]
            {
                "This is a short read-only check of public HTTPS, DNS, and the homepage. It is not a red-team engagement, not a crawl, and not a guarantee.",
                "It contacts only public addresses for the hostname you typed, and only after you confirm permission.",
                "It does not follow redirects, guess logins, brute-force plugins, or send exploit traffic.",
                "CVE matches use a small sourced catalogue against versions this host advertised. Absence of a match is not clearance.",
                "Unauthorized access to a computer system is an offence in Canada (Criminal Code s. 342.1) and similar laws elsewhere.",
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
        string? TlsProtocol,
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
                return new CertResult(null, Array.Empty<string>(), null, false, ssl.SslProtocol.ToString(), "No certificate was presented.");
            }

            using var cert = new X509Certificate2(ssl.RemoteCertificate);
            var names = ReadDnsNames(cert);
            var issuer = cert.GetNameInfo(X509NameType.SimpleName, true);
            if (string.IsNullOrWhiteSpace(issuer)) issuer = cert.Issuer;
            var notAfter = cert.NotAfter.Kind == DateTimeKind.Unspecified
                ? new DateTimeOffset(DateTime.SpecifyKind(cert.NotAfter, DateTimeKind.Local))
                : new DateTimeOffset(cert.NotAfter);
            return new CertResult(
                notAfter.ToUniversalTime(),
                names,
                issuer,
                trustErrors == SslPolicyErrors.None,
                ssl.SslProtocol.ToString(),
                null);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex) when (ex is SocketException or AuthenticationException or IOException or OperationCanceledException)
        {
            return new CertResult(null, Array.Empty<string>(), null, false, null, "The TLS handshake did not complete.");
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

    private sealed record HttpResult(
        int? Status,
        IReadOnlyDictionary<string, string> Headers,
        string Note,
        string? Body = null,
        string? Location = null,
        IReadOnlyList<string>? Cookies = null);

    private static Dictionary<string, string> MergeHeaders(
        IReadOnlyDictionary<string, string> a,
        IReadOnlyDictionary<string, string> b)
    {
        var d = new Dictionary<string, string>(a, StringComparer.OrdinalIgnoreCase);
        foreach (var kv in b)
        {
            if (!d.ContainsKey(kv.Key)) d[kv.Key] = kv.Value;
        }
        return d;
    }

    private static SocketsHttpHandler PinnedHandler(string hostname, IPAddress ip, int port) =>
        new()
        {
            AllowAutoRedirect = false,
            AutomaticDecompression = DecompressionMethods.All,
            ConnectTimeout = TimeSpan.FromMilliseconds(TimeoutMs),
            SslOptions =
            {
                TargetHost = hostname,
                RemoteCertificateValidationCallback = (_, _, _, _) => true
            },
            ConnectCallback = async (_, token) =>
            {
                var socket = new Socket(ip.AddressFamily, SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
                try
                {
                    await socket.ConnectAsync(ip, port, token);
                    return new NetworkStream(socket, ownsSocket: true);
                }
                catch
                {
                    socket.Dispose();
                    throw;
                }
            }
        };

    private static async Task<HttpResult> ProbeHttpsAsync(string hostname, IPAddress ip, CancellationToken ct)
    {
        try
        {
            using var handler = PinnedHandler(hostname, ip, 443);
            using var client = new HttpClient(handler) { Timeout = TimeSpan.FromMilliseconds(TimeoutMs) };
            using var request = new HttpRequestMessage(HttpMethod.Head, $"https://{hostname}/");
            request.Headers.TryAddWithoutValidation("User-Agent", UserAgent);
            request.Headers.TryAddWithoutValidation("Accept", "text/html,application/xhtml+xml");
            request.Headers.Host = hostname;
            using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, ct);
            var (headers, cookies) = ReadHeaders(response);
            var status = (int)response.StatusCode;
            var note = status is >= 300 and < 400
                ? $"HTTPS answered with a redirect ({status}). This program does not follow redirects."
                : "The hostname answered on HTTPS at a public address.";
            headers.TryGetValue("location", out var loc);
            return new HttpResult(status, headers, note, Location: loc, Cookies: cookies);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception)
        {
            return new HttpResult(null, new Dictionary<string, string>(), "HTTPS did not complete within the time limit.");
        }
    }

    private static async Task<HttpResult> ReadHomepageAsync(string hostname, IPAddress ip, CancellationToken ct)
    {
        try
        {
            using var handler = PinnedHandler(hostname, ip, 443);
            using var client = new HttpClient(handler) { Timeout = TimeSpan.FromMilliseconds(TimeoutMs) };
            using var request = new HttpRequestMessage(HttpMethod.Get, $"https://{hostname}/");
            request.Headers.TryAddWithoutValidation("User-Agent", UserAgent);
            request.Headers.TryAddWithoutValidation("Accept", "text/html,application/xhtml+xml");
            request.Headers.Host = hostname;
            using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, ct);
            var (headers, cookies) = ReadHeaders(response);
            var body = await ReadCappedBodyAsync(response, MaxBodyBytes, ct);
            return new HttpResult((int)response.StatusCode, headers, "Read the homepage body.", body, Cookies: cookies);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception)
        {
            return new HttpResult(null, new Dictionary<string, string>(), "Homepage GET did not complete.");
        }
    }

    private static async Task<HttpResult> ProbeHttpPort80Async(string hostname, IPAddress ip, CancellationToken ct)
    {
        try
        {
            using var handler = new SocketsHttpHandler
            {
                AllowAutoRedirect = false,
                AutomaticDecompression = DecompressionMethods.All,
                ConnectTimeout = TimeSpan.FromMilliseconds(TimeoutMs),
                ConnectCallback = async (_, token) =>
                {
                    var socket = new Socket(ip.AddressFamily, SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
                    try
                    {
                        await socket.ConnectAsync(ip, 80, token);
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
            using var request = new HttpRequestMessage(HttpMethod.Head, $"http://{hostname}/");
            request.Headers.TryAddWithoutValidation("User-Agent", UserAgent);
            request.Headers.Host = hostname;
            using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, ct);
            var (headers, _) = ReadHeaders(response);
            headers.TryGetValue("location", out var loc);
            return new HttpResult((int)response.StatusCode, headers, "Port 80 answered.", Location: loc);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception)
        {
            return new HttpResult(null, new Dictionary<string, string>(), "Port 80 did not answer. That can be correct if the host only speaks HTTPS.");
        }
    }

    private static (Dictionary<string, string> Headers, string[] Cookies) ReadHeaders(HttpResponseMessage response)
    {
        var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var cookies = new List<string>();
        foreach (var h in response.Headers)
        {
            if (h.Key.Equals("Set-Cookie", StringComparison.OrdinalIgnoreCase))
            {
                cookies.AddRange(h.Value);
                continue;
            }
            headers[h.Key] = string.Join(", ", h.Value);
        }
        foreach (var h in response.Content.Headers)
            headers[h.Key] = string.Join(", ", h.Value);
        return (headers, cookies.ToArray());
    }

    private static async Task<string> ReadCappedBodyAsync(HttpResponseMessage response, int cap, CancellationToken ct)
    {
        await using var stream = await response.Content.ReadAsStreamAsync(ct);
        var buffer = new byte[cap];
        var read = 0;
        while (read < cap)
        {
            var n = await stream.ReadAsync(buffer.AsMemory(read, cap - read), ct);
            if (n == 0) break;
            read += n;
        }
        return Encoding.UTF8.GetString(buffer, 0, read);
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

    private static async Task<SpfResult> LookupDmarcAsync(string hostname, CancellationToken ct)
    {
        var apex = hostname.StartsWith("www.", StringComparison.Ordinal) && hostname.Split('.').Length > 2
            ? hostname[4..]
            : hostname;
        var name = "_dmarc." + apex;
        var txt = await QueryTxtAsync(name, ct);
        var rec = txt.FirstOrDefault(r => r.StartsWith("v=DMARC1", StringComparison.OrdinalIgnoreCase));
        return new SpfResult(new[] { name }, rec is null ? null : rec.Length > 240 ? rec[..240] : rec);
    }

    private static Task<IReadOnlyList<string>> QueryTxtAsync(string name, CancellationToken ct) =>
        DnsTxt.QueryAsync(name, ct);

    private static Finding HttpsFinding(HttpResult http)
    {
        var ok = http.Status is >= 100 and < 500;
        return new Finding(
            "HTTPS",
            ok ? FindingState.Present : FindingState.Incomplete,
            ok ? http.Note + (http.Status is null ? "" : $" HTTP status {http.Status}.") : http.Note,
            "Opened a TLS connection to a public address on port 443 (IPv4 first, then at most two further addresses if needed), then sent HTTP HEAD / with no request body and no redirect following.",
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
                "Completed a TLS handshake to a public address using this hostname as SNI, then read the leaf certificate. IPv4 is tried before IPv6. Up to three public addresses are tried.",
                "A failed handshake can be a timeout, a firewall, or a name mismatch.");
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

    private static IEnumerable<Finding> HeaderFindings(int? status, IReadOnlyDictionary<string, string> headers)
    {
        var csp = headers.TryGetValue("Content-Security-Policy", out var cspVal) ? cspVal : "";
        foreach (var name in HeaderNames)
        {
            var present = headers.ContainsKey(name);
            if (name == "X-Frame-Options" && csp.Contains("frame-ancestors", StringComparison.OrdinalIgnoreCase))
            {
                present = true;
            }
            var hstsDisabled = name == "Strict-Transport-Security"
                && present
                && HeaderFacts.HstsDisablesHttps(headers[name]);
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
            var state = status is null
                ? FindingState.Incomplete
                : hstsDisabled
                    ? FindingState.Attention
                    : present
                        ? FindingState.Present
                        : FindingState.NotFound;
            var observation = status is null
                ? "Headers were not read because HTTPS did not complete."
                : hstsDisabled
                    ? $"{name} is present with max-age at or below zero, which tells browsers to forget HTTPS. {hint}"
                    : present
                        ? $"{name} is present. {hint}"
                        : $"{name} was not present on HEAD / or GET /. {hint}";
            yield return new Finding(
                name,
                state,
                observation,
                "Read response headers from HTTPS HEAD / and GET /. Names are compared without regard to case. Redirects are not followed. Compressed bodies are decompressed before HTML is read.",
                "A missing header is a fact about this response, not proof of a breach. Extra headers on other paths are not shown.");
        }
    }

    private static Finding TlsFinding(CertResult cert)
    {
        if (string.IsNullOrEmpty(cert.TlsProtocol))
        {
            return new Finding(
                "TLS",
                FindingState.Incomplete,
                "No TLS protocol was recorded.",
                "Read SslStream.SslProtocol after AuthenticateAsClient with TLS 1.2 and 1.3 offered.",
                "The client offered only TLS 1.2 and 1.3. An old-only server may fail the handshake instead of negotiating TLS 1.0.");
        }
        var old = cert.TlsProtocol is "Tls" or "Tls11" or "Ssl2" or "Ssl3";
        return new Finding(
            "TLS",
            old ? FindingState.Attention : FindingState.Present,
            $"The handshake used {cert.TlsProtocol}.",
            "Read SslStream.SslProtocol after AuthenticateAsClient. The client offered TLS 1.2 and 1.3 only.",
            "This is the version used for this one connection, not a scan of every cipher.");
    }

    private static Finding HttpRedirectFinding(HttpResult http80)
    {
        if (http80.Status is null)
        {
            return new Finding(
                "HTTP",
                FindingState.Present,
                http80.Note,
                "Opened the same public address on port 80 and sent HEAD /. No other ports were tried.",
                "A closed port 80 is common. It does not prove HTTPS is forced from every client.");
        }
        var toHttps = http80.Location != null && http80.Location.StartsWith("https://", StringComparison.OrdinalIgnoreCase);
        var state = toHttps ? FindingState.Present : FindingState.NotFound;
        return new Finding(
            "HTTP",
            state,
            toHttps
                ? $"Port 80 redirected to HTTPS ({http80.Status})."
                : $"Port 80 answered with status {http80.Status}" + (http80.Location is null ? "." : $" and Location {http80.Location}."),
            "Opened the same public address on port 80 and sent HEAD /. Redirects were not followed.",
            "This is not a full HTTP site crawl.");
    }

    private static Finding ServerDisclosureFinding(IReadOnlyDictionary<string, string> headers)
    {
        headers.TryGetValue("Server", out var server);
        headers.TryGetValue("X-Powered-By", out var powered);
        if (string.IsNullOrEmpty(server) && string.IsNullOrEmpty(powered))
        {
            return new Finding(
                "Server disclosure",
                FindingState.Present,
                "No Server or X-Powered-By header on this response.",
                "Read Server and X-Powered-By on HTTPS HEAD / and GET /.",
                "Other headers can still name a framework.");
        }
        var bits = new List<string>();
        if (!string.IsNullOrEmpty(server)) bits.Add("Server=" + server);
        if (!string.IsNullOrEmpty(powered)) bits.Add("X-Powered-By=" + powered);
        return new Finding(
            "Server disclosure",
            FindingState.Attention,
            "This response names the stack: " + string.Join("; ", bits) + ".",
            "Read Server and X-Powered-By on HTTPS HEAD / and GET /.",
            "Removing a header is hygiene. It does not hide a vulnerable version by itself.");
    }

    private static IEnumerable<Finding> CveFindings(IReadOnlyList<StackHint> stack)
    {
        var hits = CveCatalog.Match(stack);
        if (hits.Count == 0)
        {
            yield return new Finding(
                "Known CVEs (advertised versions)",
                FindingState.Present,
                stack.Count == 0
                    ? "The homepage and headers did not advertise a product version this catalogue knows."
                    : "Advertised versions did not match the small sourced catalogue in this program.",
                "Compared advertised versions from headers and homepage HTML with a local catalogue (Next.js ImageResponse RCE range, PHP end of life, jQuery 1.x/2.x). No plugin files were downloaded. NVD was not scraped live.",
                "A clean result is not clearance. The catalogue is short on purpose so we do not invent matches.");
            yield break;
        }
        foreach (var (entry, hint) in hits)
        {
            yield return new Finding(
                entry.Id,
                FindingState.Attention,
                $"{entry.Product} {hint.Version} matches {entry.Id}. {entry.Summary}",
                $"Version {hint.Version} was taken from: {hint.Evidence}. Matched locally against {entry.SourceUrl}.",
                "A catalogue match is a prompt to upgrade. It is not proof that this host is exploitable, and this program does not send exploit traffic.");
        }
    }

    private static Finding DmarcFinding(SpfResult dmarc)
    {
        if (dmarc.Record is null)
        {
            return new Finding(
                "DMARC",
                FindingState.NotFound,
                $"No v=DMARC1 TXT record was found on {string.Join(" or ", dmarc.Names)}.",
                "Requested TXT through the system DNS resolver (DnsClient) on _dmarc. plus the apex name. Only a parsed hostname is queried.",
                "Missing DMARC is not proof that mail is forged. Publish SPF first.");
        }
        var monitor = HeaderFacts.DmarcIsMonitorOnly(dmarc.Record);
        return new Finding(
            "DMARC",
            monitor ? FindingState.Attention : FindingState.Present,
            monitor
                ? "A DMARC record is published with p=none (monitor only) on " + string.Join(", ", dmarc.Names) + "."
                : "A DMARC record is published on " + string.Join(", ", dmarc.Names) + ".",
            "Requested TXT through the system DNS resolver (DnsClient) on _dmarc. plus the apex name. Only a parsed hostname is queried.",
            "This program does not evaluate rua mailboxes or forensic reporting.");
    }

    private static Finding SpfFinding(SpfResult spf)
    {
        if (spf.Record is null)
        {
            return new Finding(
                "SPF",
                FindingState.NotFound,
                $"No v=spf1 TXT record was found on {string.Join(" or ", spf.Names)}.",
                "Requested TXT through the system DNS resolver (DnsClient) on the hostname and, when the name starts with www, on the parent name. Only records that begin with v=spf1 are counted. Only parsed hostnames are queried.",
                "The absence of SPF is not proof that mail is forged. DKIM is not checked here.");
        }
        return new Finding(
            "SPF",
            FindingState.Present,
            $"An SPF record is published on one of: {string.Join(", ", spf.Names)}.",
            "Requested TXT through the system DNS resolver (DnsClient) on the hostname and, when the name starts with www, on the parent name. Only records that begin with v=spf1 are counted. Only parsed hostnames are queried.",
            "Publishing SPF does not prove mail will pass, and this program does not evaluate include: chains.");
    }
}
