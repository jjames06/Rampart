using System.Net;
using System.Net.Http;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace SiteCheck.Core;

/// <summary>
/// Read-only checks against a public hostname the operator confirmed they may test.
/// Never follows redirects. Never contacts blocked addresses. Never sends a request body.
/// Never sends exploit traffic. Extra RFC public files run only in Authorized assessment.
/// </summary>
public static class Checker
{
    public const int TimeoutMs = 8000;
    public const int MaxTlsAttempts = 3;
    public const int MaxBodyBytes = 256 * 1024;
    public const string UserAgent = "operation-locked-in-rampart/1.9.0";

    private static readonly string[] HeaderNames =
    {
        "Strict-Transport-Security",
        "Content-Security-Policy",
        "X-Content-Type-Options",
        "X-Frame-Options",
        "Referrer-Policy",
        "Permissions-Policy",
        "Cross-Origin-Opener-Policy",
        "Cross-Origin-Resource-Policy",
        "Cross-Origin-Embedder-Policy"
    };

    private static readonly HashSet<string> PublicPaths = new(StringComparer.Ordinal)
    {
        "/.well-known/security.txt",
        "/robots.txt",
        "/.well-known/mta-sts.txt",
        "/.well-known/change-password"
    };

    public static async Task<CheckReport> RunAsync(
        string rawHost,
        IProgress<string>? progress = null,
        CancellationToken cancellationToken = default,
        CheckScope scope = CheckScope.Standard)
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
        CertResult cert = new(null, Array.Empty<string>(), null, false, null, "The TLS handshake did not complete.", null, null, null, null, null);
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

        progress?.Report("Reading HTTPS headers, the homepage, mail records, nameservers, and HTTP on port 80.");
        var httpTask = ProbeHttpsAsync(hostname, ip, cancellationToken);
        var pageTask = ReadHomepageAsync(hostname, ip, cancellationToken);
        var spfTask = LookupSpfAsync(hostname, cancellationToken);
        var dmarcTask = LookupDmarcAsync(hostname, cancellationToken);
        var mxTask = LookupMxAsync(hostname, cancellationToken);
        var nsTask = LookupNsAsync(hostname, cancellationToken);
        var http80Task = ProbeHttpPort80Async(hostname, ip, cancellationToken);
        await Task.WhenAll(httpTask, pageTask, spfTask, dmarcTask, mxTask, nsTask, http80Task);

        var http = await httpTask;
        var page = await pageTask;
        var spf = await spfTask;
        var dmarc = await dmarcTask;
        var mx = await mxTask;
        var ns = await nsTask;
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
        findings.Add(CorsFinding(headers));
        findings.Add(XssProtectionFinding(headers));
        findings.Add(AddressFamilyFinding(publicIps, ip));
        findings.Add(HomepageTypeFinding(page));
        findings.Add(SpfFinding(spf));
        findings.Add(DmarcFinding(dmarc));
        findings.Add(MxFinding(mx));
        findings.Add(NsFinding(ns));
        var edge = EdgeSurface.Classify(ns.Record, headers, stack);
        findings.Add(EdgeSurface.PublicEdgeFinding(edge));
        findings.AddRange(EdgeSurface.CloudflareSurface(page.Body, headers, edge));
        findings.AddRange(CveFindings(stack));
        findings.Add(HtmlSurface.MixedContent(page.Body));
        findings.Add(HtmlSurface.SubresourceIntegrity(page.Body));
        findings.Add(HtmlSurface.Tabnabbing(page.Body));
        findings.Add(HtmlSurface.InsecureForms(page.Body));
        findings.Add(HtmlSurface.HttpCanonical(page.Body));
        progress?.Report("Reading common public sign-in, admin, and private-file paths.");
        var loginHits = await ProbeLoginPathsAsync(hostname, ip, cancellationToken);
        findings.Add(LoginSurface.Summary(loginHits));
        findings.Add(LoginSurface.AdminSummary(loginHits));
        findings.AddRange(LoginSurface.Issues(loginHits));
        var exposedHits = await ProbeExposedPathsAsync(hostname, ip, cancellationToken);
        findings.Add(ExposedSurface.Summary(exposedHits));
        findings.Add(await ProbeHostPairAsync(hostname, cancellationToken));
        if (scope == CheckScope.AuthorizedAssessment)
        {
            progress?.Report("Reading RFC public files and extra DNS (CAA, DKIM, MTA-STS, BIMI, TLS-RPT, DNSSEC).");
            var secTask = ReadPublicPathAsync(hostname, ip, "/.well-known/security.txt", 16 * 1024, cancellationToken);
            var robotsTask = ReadPublicPathAsync(hostname, ip, "/robots.txt", 16 * 1024, cancellationToken);
            var mtaFileTask = ReadMtaStsPolicyAsync(hostname, cancellationToken);
            var changeTask = ReadPublicPathAsync(hostname, ip, "/.well-known/change-password", 4 * 1024, cancellationToken);
            var caaTask = LookupCaaAsync(hostname, cancellationToken);
            var dkimTask = LookupDkimAsync(hostname, cancellationToken);
            var dnssecTask = LookupDnssecAsync(hostname, cancellationToken);
            var mtaDnsTask = LookupMtaStsDnsAsync(hostname, cancellationToken);
            var bimiTask = LookupBimiAsync(hostname, cancellationToken);
            var tlsRptTask = LookupTlsRptAsync(hostname, cancellationToken);
            await Task.WhenAll(secTask, robotsTask, mtaFileTask, changeTask, caaTask, dkimTask, dnssecTask, mtaDnsTask, bimiTask, tlsRptTask);
            findings.Add(PublicFileFinding("security.txt", await secTask, "RFC 9116 contact file at /.well-known/security.txt."));
            findings.Add(PublicFileFinding("robots.txt", await robotsTask, "Public robots.txt on the same address."));
            findings.Add(MtaStsFileFinding(await mtaFileTask));
            findings.Add(ChangePasswordFinding(await changeTask));
            findings.Add(CaaFinding(await caaTask));
            findings.Add(DkimFinding(await dkimTask));
            findings.Add(await dnssecTask);
            findings.Add(MtaStsDnsFinding(await mtaDnsTask));
            findings.Add(BimiFinding(await bimiTask));
            findings.Add(TlsRptFinding(await tlsRptTask));
        }
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
            http80.Location,
            edge);

        var limits = new List<string>
        {
            "This is a read-only public-surface check of a hostname you attested you may test. It is not a penetration test, not an exploit kit, and not a guarantee.",
            "Industry red-team work includes attempting to exploit. This program does not send exploit traffic, guess passwords, or crawl.",
            "It contacts only public addresses for the hostname you typed, and only after both permission boxes are ticked.",
            "CVE matches use the local catalogue against versions this host advertised. Absence of a match is not clearance.",
            "Unauthorized use of a computer system can be an offence in Canada (Criminal Code section 342.1). Operation Locked In does not authorize use without the operator's permission.",
            "This program is not legal advice. Paid website work still begins after a written quote."
        };
        return new CheckReport(
            hostname,
            DateTimeOffset.UtcNow,
            publicIps.Select(a => a.ToString()).ToArray(),
            findings,
            next,
            stack,
            limits,
            LawfulUse.Record(scope, DateTimeOffset.UtcNow));
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
        string? Error,
        string? Cipher,
        string? Alpn,
        string? KeyAlgorithm,
        int? KeySize,
        string? SignatureAlgorithm);

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
                return new CertResult(null, Array.Empty<string>(), null, false, ssl.SslProtocol.ToString(), "No certificate was presented.",
                    ssl.NegotiatedCipherSuite.ToString(), AlpnName(ssl), null, null, null);
            }

            using var cert = new X509Certificate2(ssl.RemoteCertificate);
            var names = ReadDnsNames(cert);
            var issuer = cert.GetNameInfo(X509NameType.SimpleName, true);
            if (string.IsNullOrWhiteSpace(issuer)) issuer = cert.Issuer;
            var notAfter = cert.NotAfter.Kind == DateTimeKind.Unspecified
                ? new DateTimeOffset(DateTime.SpecifyKind(cert.NotAfter, DateTimeKind.Local))
                : new DateTimeOffset(cert.NotAfter);
            var (keyAlg, keySize) = ReadPublicKey(cert);
            return new CertResult(
                notAfter.ToUniversalTime(),
                names,
                issuer,
                trustErrors == SslPolicyErrors.None,
                ssl.SslProtocol.ToString(),
                null,
                ssl.NegotiatedCipherSuite.ToString(),
                AlpnName(ssl),
                keyAlg,
                keySize,
                cert.SignatureAlgorithm.FriendlyName ?? cert.SignatureAlgorithm.Value);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex) when (ex is SocketException or AuthenticationException or IOException or OperationCanceledException)
        {
            return new CertResult(null, Array.Empty<string>(), null, false, null, "The TLS handshake did not complete.", null, null, null, null, null);
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

    private static string? AlpnName(SslStream ssl)
    {
        var p = ssl.NegotiatedApplicationProtocol;
        if (p == default) return null;
        var s = p.ToString();
        return string.IsNullOrWhiteSpace(s) ? null : s;
    }

    private static (string? Algorithm, int? Bits) ReadPublicKey(X509Certificate2 cert)
    {
        try
        {
            using var rsa = cert.GetRSAPublicKey();
            if (rsa != null) return ("RSA", rsa.KeySize);
        }
        catch (CryptographicException)
        {
            // Fall through to ECDSA.
        }
        try
        {
            using var ecdsa = cert.GetECDsaPublicKey();
            if (ecdsa != null) return ("ECDSA", ecdsa.KeySize);
        }
        catch (CryptographicException)
        {
            // Unknown key type.
        }
        return (null, null);
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

    private static async Task<HttpResult> ReadMtaStsPolicyAsync(string hostname, CancellationToken ct)
    {
        var policyHost = "mta-sts." + Hostname.Apex(hostname);
        if (Hostname.Parse(policyHost) is null)
        {
            return new HttpResult(null, new Dictionary<string, string>(), "The MTA-STS policy hostname could not be parsed.");
        }
        var ips = await ResolvePublicAsync(policyHost, ct);
        if (ips.Count == 0)
        {
            return new HttpResult(404, new Dictionary<string, string>(), "The mta-sts subdomain has no public address.");
        }
        var policyIp = ips
            .OrderBy(a => a.AddressFamily == AddressFamily.InterNetwork ? 0 : 1)
            .First();
        return await ReadPublicPathAsync(policyHost, policyIp, "/.well-known/mta-sts.txt", 16 * 1024, ct);
    }

    private static async Task<HttpResult> ReadPublicPathAsync(
        string hostname, IPAddress ip, string path, int cap, CancellationToken ct)
    {
        if (!PublicPaths.Contains(path))
            return new HttpResult(null, new Dictionary<string, string>(), "That path is not in the allowlist.");
        try
        {
            using var handler = PinnedHandler(hostname, ip, 443);
            using var client = new HttpClient(handler) { Timeout = TimeSpan.FromMilliseconds(TimeoutMs) };
            using var request = new HttpRequestMessage(HttpMethod.Get, $"https://{hostname}{path}");
            request.Headers.TryAddWithoutValidation("User-Agent", UserAgent);
            request.Headers.Host = hostname;
            using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, ct);
            var (headers, _) = ReadHeaders(response);
            var body = await ReadCappedBodyAsync(response, cap, ct);
            return new HttpResult((int)response.StatusCode, headers, "Read " + path, body);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception)
        {
            return new HttpResult(null, new Dictionary<string, string>(), path + " did not complete.");
        }
    }

    private static async Task<IReadOnlyList<LoginHit>> ProbeLoginPathsAsync(
        string hostname, IPAddress ip, CancellationToken ct)
    {
        using var handler = PinnedHandler(hostname, ip, 443);
        using var client = new HttpClient(handler) { Timeout = TimeSpan.FromMilliseconds(TimeoutMs) };
        var tasks = LoginSurface.Paths.Select(async path =>
        {
            try
            {
                using var request = new HttpRequestMessage(HttpMethod.Get, $"https://{hostname}{path}");
                request.Headers.TryAddWithoutValidation("User-Agent", UserAgent);
                request.Headers.Host = hostname;
                using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, ct);
                var (headers, cookies) = ReadHeaders(response);
                headers.TryGetValue("location", out var loc);
                var body = await ReadCappedBodyAsync(response, 64 * 1024, ct);
                return new LoginHit(path, (int)response.StatusCode, loc, body, headers, cookies);
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception)
            {
                return new LoginHit(path, null, null, null, new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase), Array.Empty<string>());
            }
        });
        return await Task.WhenAll(tasks);
    }

    private static async Task<IReadOnlyList<FileHit>> ProbeExposedPathsAsync(
        string hostname, IPAddress ip, CancellationToken ct)
    {
        using var handler = PinnedHandler(hostname, ip, 443);
        using var client = new HttpClient(handler) { Timeout = TimeSpan.FromMilliseconds(TimeoutMs) };
        var tasks = ExposedSurface.Paths.Select(async path =>
        {
            try
            {
                using var request = new HttpRequestMessage(HttpMethod.Get, $"https://{hostname}{path}");
                request.Headers.TryAddWithoutValidation("User-Agent", UserAgent);
                request.Headers.Host = hostname;
                using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, ct);
                var body = await ReadCappedBodyAsync(response, 8 * 1024, ct);
                return new FileHit(path, (int)response.StatusCode, body);
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception)
            {
                return new FileHit(path, null, null);
            }
        });
        return await Task.WhenAll(tasks);
    }

    private static async Task<Finding> ProbeHostPairAsync(string hostname, CancellationToken ct)
    {
        var sibling = HostPair.Sibling(hostname);
        if (sibling is null) return HostPair.Summary(hostname, null, null, null, false);
        var ips = await ResolvePublicAsync(sibling, ct);
        if (ips.Count == 0) return HostPair.Summary(hostname, sibling, null, null, false);
        var ip = ips.OrderBy(a => a.AddressFamily == AddressFamily.InterNetwork ? 0 : 1).First();
        try
        {
            using var handler = PinnedHandler(sibling, ip, 443);
            using var client = new HttpClient(handler) { Timeout = TimeSpan.FromMilliseconds(TimeoutMs) };
            using var request = new HttpRequestMessage(HttpMethod.Head, $"https://{sibling}/");
            request.Headers.TryAddWithoutValidation("User-Agent", UserAgent);
            request.Headers.Host = sibling;
            using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, ct);
            var (headers, _) = ReadHeaders(response);
            headers.TryGetValue("location", out var loc);
            return HostPair.Summary(hostname, sibling, (int)response.StatusCode, loc, true);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception)
        {
            return HostPair.Summary(hostname, sibling, null, null, true);
        }
    }

    private static async Task<SpfResult> LookupCaaAsync(string hostname, CancellationToken ct)
    {
        var names = Hostname.SpfLookupNames(hostname);
        var found = new List<string>();
        foreach (var name in names)
        {
            ct.ThrowIfCancellationRequested();
            var recs = await DnsTxt.QueryCaaAsync(name, ct);
            if (recs.Count > 0) found.AddRange(recs.Take(4));
        }
        return new SpfResult(names, found.Count == 0 ? null : string.Join("; ", found.Take(8)));
    }

    private static async Task<SpfResult> LookupDkimAsync(string hostname, CancellationToken ct)
    {
        var apex = Hostname.Apex(hostname);
        var names = new[]
        {
            "default._domainkey." + apex,
            "google._domainkey." + apex,
            "selector1._domainkey." + apex,
            "selector2._domainkey." + apex,
            "k1._domainkey." + apex,
            "s1._domainkey." + apex,
            "s2._domainkey." + apex,
            "mail._domainkey." + apex,
            "dkim._domainkey." + apex,
            "smtp._domainkey." + apex
        };
        var tasks = names.Select(async name =>
        {
            var txt = await QueryTxtAsync(name, ct);
            return txt.Any(r => r.Contains("v=DKIM1", StringComparison.OrdinalIgnoreCase) || r.Contains("p=", StringComparison.OrdinalIgnoreCase))
                ? name
                : null;
        });
        var results = await Task.WhenAll(tasks);
        var found = results.Where(n => n != null).Cast<string>().ToArray();
        return new SpfResult(names, found.Length == 0 ? null : string.Join(", ", found));
    }

    private static Finding PublicFileFinding(string title, HttpResult result, string method)
    {
        var ok = result.Status is >= 200 and < 300 && !string.IsNullOrWhiteSpace(result.Body);
        if (result.Status is null)
        {
            return new Finding(title, FindingState.Incomplete, result.Note, method,
                "A timeout is not proof the file is missing.");
        }
        return new Finding(
            title,
            ok ? FindingState.Present : FindingState.NotFound,
            ok ? $"{title} answered HTTP {result.Status} on this public address." : $"{title} was not a successful document (HTTP {result.Status}).",
            method,
            "This is a public RFC or convention file. Its absence is hygiene, not a breach.");
    }

    private static async Task<Finding> LookupDnssecAsync(string hostname, CancellationToken ct)
    {
        var apex = Hostname.Apex(hostname);
        var dsTask = DnsTxt.QueryDsAsync(apex, ct);
        var keyTask = DnsTxt.QueryDnsKeyAsync(apex, ct);
        await Task.WhenAll(dsTask, keyTask);
        var ds = await dsTask;
        var keys = await keyTask;
        if (ds.Count == 0 && keys.Count == 0)
        {
            return new Finding(
                "DNSSEC",
                FindingState.NotFound,
                "No DS or DNSKEY record was found on the apex. The parent zone may not have a Delegation Signer for this name.",
                "Asked the system resolver for DS and DNSKEY on the apex name.",
                "A missing DS record is common. It does not mean DNS is forged. Enabling DNSSEC is a registrar and DNS-host task.");
        }
        if (ds.Count == 0)
        {
            return new Finding(
                "DNSSEC",
                FindingState.Attention,
                "A DNSKEY is published on the apex (" + keys.Count + " answer(s)), but no DS record was found at the parent. The chain is incomplete until the registrar publishes DS.",
                "Asked the system resolver for DS and DNSKEY on the apex name.",
                "Presence of DNSKEY without DS usually means DNSSEC was turned on at the DNS host but not at the registrar.");
        }
        return new Finding(
            "DNSSEC",
            FindingState.Present,
            "A DS record is published on the apex (" + ds.Count + " answer(s))"
                + (keys.Count > 0 ? " and DNSKEY is present (" + keys.Count + " answer(s))." : "."),
            "Asked the system resolver for DS and DNSKEY on the apex name.",
            "Presence of DS is not a full chain validation. This program does not walk the DNSSEC chain to the root.");
    }

    private static Finding CaaFinding(SpfResult caa)
    {
        if (caa.Record is null)
        {
            return new Finding(
                "CAA",
                FindingState.NotFound,
                "No CAA record was found on " + string.Join(" or ", caa.Names) + ".",
                "Asked the system resolver for CAA on the typed hostname.",
                "Missing CAA does not mean a certificate was issued wrongly. It means this name does not restrict which CAs may issue.");
        }
        return new Finding(
            "CAA",
            FindingState.Present,
            "CAA is published: " + caa.Record,
            "Asked the system resolver for CAA on the typed hostname.",
            "This program does not evaluate issuewild or iodef mailboxes.");
    }

    private static Finding DkimFinding(SpfResult dkim)
    {
        if (dkim.Record is null)
        {
            return new Finding(
                "DKIM",
                FindingState.NotFound,
                "No DKIM TXT was found on the common selectors " + string.Join(", ", dkim.Names) + ".",
                "Requested TXT on common selectors (default, google, selector1, selector2, k1, s1, s2, mail, dkim, smtp) under _domainkey plus the apex. Only parsed names are queried.",
                "Many hosts use a different selector. Absence here is not proof DKIM is unpublished.");
        }
        return new Finding(
            "DKIM",
            FindingState.Present,
            "A DKIM-like TXT record was found on: " + dkim.Record + ".",
            "Requested TXT on common selectors (default, google, selector1, selector2, k1, s1, s2, mail, dkim, smtp) under _domainkey plus the apex. Only parsed names are queried.",
            "This program does not validate signatures or rotate keys.");
    }

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
        var weakKey = string.Equals(cert.KeyAlgorithm, "RSA", StringComparison.OrdinalIgnoreCase)
            && cert.KeySize is int rsaBits && rsaBits < 2048;
        var state = days < 0 || !covers
            ? FindingState.NotFound
            : weakKey
                ? FindingState.Attention
                : FindingState.Present;
        var obs = new StringBuilder();
        obs.Append(days >= 0 ? $"{days} day{(days == 1 ? "" : "s")} remaining (UTC {cert.NotAfter.Value:yyyy-MM-dd})." : $"Expired {Math.Abs(days)} day{(Math.Abs(days) == 1 ? "" : "s")} ago.");
        if (!string.IsNullOrWhiteSpace(cert.Issuer)) obs.Append($" Issuer: {cert.Issuer}.");
        if (!string.IsNullOrWhiteSpace(cert.KeyAlgorithm))
        {
            obs.Append($" Leaf key: {cert.KeyAlgorithm}");
            if (cert.KeySize is int bits) obs.Append($" {bits} bits");
            obs.Append('.');
        }
        if (weakKey) obs.Append(" The RSA leaf key is shorter than 2048 bits.");
        obs.Append(covers ? " The certificate names this hostname." : " The certificate does not clearly name this hostname.");
        obs.Append(cert.Trusted ? " Windows trusted the certification path." : " Windows did not fully trust the certification path.");
        return new Finding(
            "Certificate",
            state,
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
            var hstsShort = name == "Strict-Transport-Security"
                && present
                && !hstsDisabled
                && HeaderFacts.HstsMaxAgeIsShort(headers[name]);
            var hstsNoSub = name == "Strict-Transport-Security"
                && present
                && !hstsDisabled
                && !hstsShort
                && !HeaderFacts.HstsHasIncludeSubDomains(headers[name]);
            var cspUnsafe = name == "Content-Security-Policy"
                && present
                && HeaderFacts.CspAllowsUnsafeInline(headers[name]);
            var hint = name switch
            {
                "Strict-Transport-Security" => "Tells browsers to keep using HTTPS.",
                "Content-Security-Policy" => "Limits scripts, frames, and other sources.",
                "X-Content-Type-Options" => "Stops the browser guessing file types.",
                "X-Frame-Options" => "Clickjacking control. CSP frame-ancestors can cover this too.",
                "Referrer-Policy" => "Limits what other sites see in the Referer header.",
                "Permissions-Policy" => "Turns off camera, microphone, and similar features.",
                "Cross-Origin-Opener-Policy" => "Isolates the browsing context from cross-origin popups.",
                "Cross-Origin-Resource-Policy" => "Limits which other origins can load this response as a resource.",
                "Cross-Origin-Embedder-Policy" => "Required together with COOP for a cross-origin isolated context (SharedArrayBuffer). Many brochure sites do not need it.",
                _ => name
            };
            var state = status is null
                ? FindingState.Incomplete
                : hstsDisabled || hstsShort || hstsNoSub || cspUnsafe
                    ? FindingState.Attention
                    : present
                        ? FindingState.Present
                        : FindingState.NotFound;
            var observation = status is null
                ? "Headers were not read because HTTPS did not complete."
                : hstsDisabled
                    ? $"{name} is present with max-age at or below zero, which tells browsers to forget HTTPS. {hint}"
                    : hstsShort
                        ? $"{name} is present with max-age {HeaderFacts.HstsMaxAge(headers[name])} seconds, which is shorter than 180 days. {hint}"
                        : hstsNoSub
                            ? $"{name} is present without includeSubDomains. Child names will not inherit this policy. {hint}"
                            : cspUnsafe
                                ? $"{name} is present. script-src includes unsafe-inline. {hint}"
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
        var weakCipher = TlsFacts.CipherLacksForwardSecrecy(cert.Cipher) || TlsFacts.CipherUsesLegacyBulk(cert.Cipher);
        var weakKey = TlsFacts.RsaKeyIsWeak(cert.KeyAlgorithm, cert.KeySize);
        var attention = old || weakCipher || weakKey;
        var obs = new StringBuilder();
        obs.Append($"The handshake used {cert.TlsProtocol}.");
        if (!string.IsNullOrWhiteSpace(cert.Cipher)) obs.Append($" Cipher: {cert.Cipher}.");
        if (!string.IsNullOrWhiteSpace(cert.Alpn)) obs.Append($" ALPN: {cert.Alpn}.");
        if (!string.IsNullOrWhiteSpace(cert.KeyAlgorithm))
        {
            obs.Append($" Leaf key: {cert.KeyAlgorithm}");
            if (cert.KeySize is int bits) obs.Append($" {bits} bits");
            obs.Append('.');
        }
        if (!string.IsNullOrWhiteSpace(cert.SignatureAlgorithm)) obs.Append($" Signature: {cert.SignatureAlgorithm}.");
        if (weakCipher) obs.Append(" The cipher is CBC, RC4, 3DES, or RSA key-exchange without forward secrecy.");
        if (weakKey) obs.Append(" The RSA public key is shorter than 2048 bits.");
        return new Finding(
            "TLS",
            attention ? FindingState.Attention : FindingState.Present,
            obs.ToString(),
            "Read SslStream.SslProtocol, NegotiatedCipherSuite, and NegotiatedApplicationProtocol after AuthenticateAsClient. The leaf public key size was read from the certificate. The client offered TLS 1.2 and 1.3 only.",
            "This is the version and cipher used for this one connection. It is not a scan of every cipher the server still offers.");
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
        var cloudflareOnly =
            string.IsNullOrEmpty(powered)
            && server != null
            && server.Equals("cloudflare", StringComparison.OrdinalIgnoreCase);
        if (cloudflareOnly)
        {
            return new Finding(
                "Server disclosure",
                FindingState.Present,
                "Server is cloudflare. That is expected when Cloudflare is the public edge. It is not a version string.",
                "Read Server and X-Powered-By on HTTPS HEAD / and GET /.",
                "Hiding Server on Cloudflare is a Transform Rule at the edge. next.config.ts cannot remove it.");
        }
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
                $"Compared advertised versions from headers and homepage HTML with a local catalogue of {AdvisoryDb.ProductCount} products and {AdvisoryDb.AdvisoryCount} advisories (built {AdvisoryDb.Built}). JavaScript matches use Retire.js ranges on homepage URLs. Next.js matches use GitHub Advisory ranges. PHP end of life is included. Plugin files were not downloaded. NVD was not queried live.",
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
        var open = HeaderFacts.SpfAllIsPermissive(spf.Record);
        return new Finding(
            "SPF",
            open ? FindingState.Attention : FindingState.Present,
            open
                ? "An SPF record is published, but the all mechanism is +all, all, or ?all, which permits or does not restrict unexpected senders: " + spf.Record + "."
                : $"An SPF record is published on one of: {string.Join(", ", spf.Names)}.",
            "Requested TXT through the system DNS resolver (DnsClient) on the hostname and, when the name starts with www, on the parent name. Only records that begin with v=spf1 are counted. Only parsed hostnames are queried.",
            "Publishing SPF does not prove mail will pass, and this program does not evaluate include: chains.");
    }

    private static async Task<SpfResult> LookupMxAsync(string hostname, CancellationToken ct)
    {
        var apex = Hostname.Apex(hostname);
        var recs = await DnsTxt.QueryMxAsync(apex, ct);
        return new SpfResult(new[] { apex }, recs.Count == 0 ? null : string.Join("; ", recs.Take(8)));
    }

    private static async Task<SpfResult> LookupNsAsync(string hostname, CancellationToken ct)
    {
        var apex = Hostname.Apex(hostname);
        var recs = await DnsTxt.QueryNsAsync(apex, ct);
        return new SpfResult(new[] { apex }, recs.Count == 0 ? null : string.Join(", ", recs.Take(8)));
    }

    private static Finding MxFinding(SpfResult mx)
    {
        if (mx.Record is null)
        {
            return new Finding(
                "MX",
                FindingState.NotFound,
                "No MX record was found on " + string.Join(" or ", mx.Names) + ".",
                "Asked the system resolver for MX on the apex name.",
                "Some hosts accept mail on the A record instead. Absence of MX is not proof that mail cannot be delivered. A null MX (preference 0 and a dot) is a published refusal to accept mail.");
        }
        var nullMx = mx.Record.Contains(" 0 .", StringComparison.Ordinal) || mx.Record.TrimEnd().EndsWith(" 0 .", StringComparison.Ordinal);
        return new Finding(
            "MX",
            FindingState.Present,
            (nullMx ? "A null MX is published (this name does not accept mail): " : "MX is published: ") + mx.Record,
            "Asked the system resolver for MX on the apex name. Preference and exchange are recorded. The mail server itself is not contacted.",
            "This program does not open port 25, 465, or 587, and it does not send mail.");
    }

    private static Finding NsFinding(SpfResult ns)
    {
        if (ns.Record is null)
        {
            return new Finding(
                "Nameservers",
                FindingState.Incomplete,
                "No NS record was returned for " + string.Join(" or ", ns.Names) + ".",
                "Asked the system resolver for NS on the apex name.",
                "A resolver can omit NS from the answer section. That is not proof the zone has no nameservers.");
        }
        return new Finding(
            "Nameservers",
            FindingState.Present,
            "Apex nameservers: " + ns.Record + ".",
            "Asked the system resolver for NS on the apex name.",
            "This is who currently answers DNS for the zone, not a registrar transfer check.");
    }

    private static Finding AddressFamilyFinding(IReadOnlyList<IPAddress> publicIps, IPAddress working)
    {
        var v4 = publicIps.Any(a => a.AddressFamily == AddressFamily.InterNetwork);
        var v6 = publicIps.Any(a => a.AddressFamily == AddressFamily.InterNetworkV6);
        var used = working.AddressFamily == AddressFamily.InterNetwork ? "IPv4" : "IPv6";
        var obs = v4 && v6
            ? $"Public addresses include IPv4 and IPv6. This run used {used} ({working}) for HTTPS."
            : v4
                ? $"Public addresses are IPv4 only. This run used {working}."
                : $"Public addresses are IPv6 only. This run used {working}.";
        return new Finding(
            "Address family",
            FindingState.Present,
            obs,
            "Resolved A and AAAA, dropped blocked addresses, then opened TLS on IPv4 first.",
            "IPv4-only is common for small sites. This is not a dual-stack compliance audit.");
    }

    private static Finding HomepageTypeFinding(HttpResult page)
    {
        if (page.Status is null)
        {
            return new Finding(
                "Homepage",
                FindingState.Incomplete,
                "GET / did not complete, so the homepage type was not recorded.",
                "Read Content-Type and the capped body length from GET /.",
                "A timeout is not proof the homepage is missing.");
        }
        page.Headers.TryGetValue("Content-Type", out var type);
        var bytes = page.Body?.Length ?? 0;
        var typeText = string.IsNullOrWhiteSpace(type) ? "no Content-Type header" : type;
        return new Finding(
            "Homepage",
            FindingState.Present,
            $"GET / answered HTTP {page.Status} with {typeText}. {bytes} character(s) of the body were kept (cap {MaxBodyBytes}).",
            "Read Content-Type and a capped UTF-8 body from GET / with redirects disabled.",
            "A 3xx status is recorded and not followed. Later paths are not fetched.");
    }

    private static Finding CorsFinding(IReadOnlyDictionary<string, string> headers)
    {
        headers.TryGetValue("Access-Control-Allow-Origin", out var acao);
        if (string.IsNullOrWhiteSpace(acao))
        {
            return new Finding(
                "CORS",
                FindingState.Present,
                "No Access-Control-Allow-Origin header on this response.",
                "Read Access-Control-Allow-Origin on HTTPS HEAD / and GET /.",
                "APIs on other paths can still send CORS headers. This check is the homepage only.");
        }
        if (HeaderFacts.CorsAllowsAnyOrigin(acao))
        {
            return new Finding(
                "CORS",
                FindingState.Attention,
                "Access-Control-Allow-Origin is * on the homepage response.",
                "Read Access-Control-Allow-Origin on HTTPS HEAD / and GET /.",
                "A public brochure page can use *. Treat this as a prompt to confirm no authenticated API lives on the same origin with the same header.");
        }
        return new Finding(
            "CORS",
            FindingState.Present,
            "Access-Control-Allow-Origin is set to a specific origin: " + acao + ".",
            "Read Access-Control-Allow-Origin on HTTPS HEAD / and GET /.",
            "This is not a full CORS preflight test. OPTIONS is not sent.");
    }

    private static Finding XssProtectionFinding(IReadOnlyDictionary<string, string> headers)
    {
        headers.TryGetValue("X-XSS-Protection", out var xss);
        if (string.IsNullOrWhiteSpace(xss))
        {
            return new Finding(
                "X-XSS-Protection",
                FindingState.Present,
                "No X-XSS-Protection header. Modern browsers ignore this header; omitting it is correct.",
                "Read X-XSS-Protection on HTTPS HEAD / and GET /.",
                "Do not add this header to new sites. Use Content-Security-Policy instead.");
        }
        if (HeaderFacts.XssProtectionIsLegacyEnabled(xss))
        {
            return new Finding(
                "X-XSS-Protection",
                FindingState.Attention,
                "X-XSS-Protection is present with a non-zero value (" + xss + "). Old Internet Explorer XSS filters can introduce XSS. Prefer omitting the header or setting it to 0.",
                "Read X-XSS-Protection on HTTPS HEAD / and GET /.",
                "Current Chrome, Firefox, and Edge ignore this header.");
        }
        return new Finding(
            "X-XSS-Protection",
            FindingState.Present,
            "X-XSS-Protection is present and disabled (" + xss + ").",
            "Read X-XSS-Protection on HTTPS HEAD / and GET /.",
            "Omitting the header entirely is also correct.");
    }

    private static Finding MtaStsFileFinding(HttpResult result)
    {
        var ok = result.Status is >= 200 and < 300
            && result.Body != null
            && result.Body.Contains("STSv1", StringComparison.OrdinalIgnoreCase);
        if (result.Status is null)
        {
            return new Finding("MTA-STS policy", FindingState.Incomplete, result.Note,
                "GET /.well-known/mta-sts.txt on the same public address.",
                "A timeout is not proof the file is missing.");
        }
        return new Finding(
            "MTA-STS policy",
            ok ? FindingState.Present : FindingState.NotFound,
            ok
                ? "mta-sts.txt answered HTTP " + result.Status + " and named STSv1."
                : (string.IsNullOrWhiteSpace(result.Note)
                    ? "mta-sts.txt was not a successful STSv1 policy (HTTP " + result.Status + ")."
                    : result.Note),
            "Resolved mta-sts. plus the apex, then GET /.well-known/mta-sts.txt on that public hostname (RFC 8461), body capped, no redirect.",
            "MTA-STS is for inbound SMTP on the apex. It does not replace SPF, DKIM, or DMARC. The policy host is a subdomain of the attested apex, not a third-party name.");
    }

    private static Finding ChangePasswordFinding(HttpResult result)
    {
        if (result.Status is null)
        {
            return new Finding("change-password", FindingState.Incomplete, result.Note,
                "GET /.well-known/change-password on the same public address.",
                "A timeout is not proof the well-known URL is missing.");
        }
        var ok = result.Status is >= 200 and < 400;
        return new Finding(
            "change-password",
            ok ? FindingState.Present : FindingState.NotFound,
            ok
                ? "change-password answered HTTP " + result.Status + ". Browsers can send a person to this URL to update a saved password."
                : "change-password was not found (HTTP " + result.Status + ").",
            "GET /.well-known/change-password on the same public address. Redirects are not followed; a 3xx still counts as a published pointer.",
            "This well-known URL is useful when the site has accounts. A marketing site without logins can omit it.");
    }

    private static Finding MtaStsDnsFinding(SpfResult rec)
    {
        if (rec.Record is null)
        {
            return new Finding(
                "MTA-STS DNS",
                FindingState.NotFound,
                "No MTA-STS TXT was found on " + string.Join(" or ", rec.Names) + ".",
                "Requested TXT on _mta-sts. plus the apex. Only parsed names are queried.",
                "MTA-STS needs both this TXT record and /.well-known/mta-sts.txt. Many small hosts omit both.");
        }
        return new Finding(
            "MTA-STS DNS",
            FindingState.Present,
            "MTA-STS TXT is published: " + rec.Record,
            "Requested TXT on _mta-sts. plus the apex.",
            "This program does not contact inbound MX over TLS to verify the policy.");
    }

    private static Finding BimiFinding(SpfResult rec)
    {
        if (rec.Record is null)
        {
            return new Finding(
                "BIMI",
                FindingState.NotFound,
                "No BIMI TXT was found on " + string.Join(" or ", rec.Names) + ".",
                "Requested TXT on default._bimi. plus the apex. Only parsed names are queried.",
                "BIMI is a brand-indicator for mailbox providers. It is optional. DMARC at quarantine or reject is usually required first.");
        }
        return new Finding(
            "BIMI",
            FindingState.Present,
            "BIMI TXT is published: " + rec.Record,
            "Requested TXT on default._bimi. plus the apex.",
            "This program does not fetch the SVG logo or validate a VMC certificate.");
    }

    private static Finding TlsRptFinding(SpfResult rec)
    {
        if (rec.Record is null)
        {
            return new Finding(
                "TLS-RPT",
                FindingState.NotFound,
                "No SMTP TLS reporting TXT was found on " + string.Join(" or ", rec.Names) + ".",
                "Requested TXT on _smtp._tls. plus the apex. Only parsed names are queried.",
                "TLS-RPT is a mailbox for reports about failed SMTP TLS. It is optional and pairs with MTA-STS.");
        }
        return new Finding(
            "TLS-RPT",
            FindingState.Present,
            "TLS-RPT is published: " + rec.Record,
            "Requested TXT on _smtp._tls. plus the apex.",
            "This program does not send a test report to the rua mailbox.");
    }

    private static async Task<SpfResult> LookupMtaStsDnsAsync(string hostname, CancellationToken ct)
    {
        var name = "_mta-sts." + Hostname.Apex(hostname);
        var txt = await QueryTxtAsync(name, ct);
        var rec = txt.FirstOrDefault(r => r.Contains("STSv1", StringComparison.OrdinalIgnoreCase));
        return new SpfResult(new[] { name }, rec is null ? null : rec.Length > 240 ? rec[..240] : rec);
    }

    private static async Task<SpfResult> LookupBimiAsync(string hostname, CancellationToken ct)
    {
        var name = "default._bimi." + Hostname.Apex(hostname);
        var txt = await QueryTxtAsync(name, ct);
        var rec = txt.FirstOrDefault(r => r.Contains("v=BIMI1", StringComparison.OrdinalIgnoreCase) || r.Contains("l=", StringComparison.OrdinalIgnoreCase));
        return new SpfResult(new[] { name }, rec is null ? null : rec.Length > 240 ? rec[..240] : rec);
    }

    private static async Task<SpfResult> LookupTlsRptAsync(string hostname, CancellationToken ct)
    {
        var name = "_smtp._tls." + Hostname.Apex(hostname);
        var txt = await QueryTxtAsync(name, ct);
        var rec = txt.FirstOrDefault(r => r.Contains("TLSRPT", StringComparison.OrdinalIgnoreCase));
        return new SpfResult(new[] { name }, rec is null ? null : rec.Length > 240 ? rec[..240] : rec);
    }
}
