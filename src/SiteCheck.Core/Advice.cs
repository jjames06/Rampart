namespace SiteCheck.Core;

/// <summary>
/// Next steps only for what this run actually observed.
/// </summary>
public static class Advice
{
    public static IReadOnlyList<NextStep> Build(
        string hostname,
        IReadOnlyList<Finding> findings,
        IReadOnlyList<StackHint> stack,
        IReadOnlyList<string> pluginSlugs,
        int? certificateDays,
        string? tlsProtocol,
        int? http80Status,
        string? http80Location)
    {
        var steps = new List<NextStep>();
        var next = stack.Any(s => s.Product.Equals("Next.js", StringComparison.OrdinalIgnoreCase));
        var wordpress = stack.Any(s => s.Product.Equals("WordPress", StringComparison.OrdinalIgnoreCase));
        var cloudflare = stack.Any(s => s.Product.Equals("Cloudflare", StringComparison.OrdinalIgnoreCase));
        var vercel = stack.Any(s => s.Product.Equals("Vercel", StringComparison.OrdinalIgnoreCase));

        void Missing(string title, string generic, string? nextJs = null, string? wp = null)
        {
            var f = findings.FirstOrDefault(x => x.Title.Equals(title, StringComparison.OrdinalIgnoreCase));
            if (f is null || f.State == FindingState.Present) return;
            // Incomplete header reads mean HTTPS did not finish. Do not invent a header fix list on top of that.
            if (f.State == FindingState.Incomplete && title != "HTTPS") return;
            var body = generic;
            if (next && nextJs != null) body = nextJs;
            else if (wordpress && wp != null) body = wp;
            else if (vercel) body += " On Vercel this is usually a header in next.config or the project Security Headers settings.";
            else if (cloudflare) body += " In Cloudflare: Rules, then Transform or HTTP Header Modification, or the SSL/TLS overview for HTTPS redirects.";
            steps.Add(new NextStep($"Fix {title}", body, title));
        }

        Missing(
            "HTTPS",
            "The hostname did not complete HTTPS on the first public address. Confirm DNS points at the intended host, port 443 is open, and the certificate is installed. This program does not change firewall rules for you.");

        var cert = findings.FirstOrDefault(x => x.Title == "Certificate");
        if (cert != null)
        {
            if (cert.State != FindingState.Present)
            {
                steps.Add(new NextStep(
                    "Replace or correct the certificate",
                    "Issue a certificate that includes this exact hostname (and www if you use it). Let's Encrypt via your host or Caddy/nginx is common. Wait for DNS to match the host before requesting the certificate.",
                    "Certificate"));
            }
            else if (certificateDays is >= 0 and < 21)
            {
                steps.Add(new NextStep(
                    "Renew the certificate soon",
                    $"About {certificateDays} days remain. Turn on automatic renewal at the host or ACME client. Do not wait until the week it expires.",
                    "Certificate"));
            }
            else if (certificateDays is >= 21 and < 45)
            {
                steps.Add(new NextStep(
                    "Confirm automatic certificate renewal",
                    $"About {certificateDays} days remain. Check that the host or ACME client has been renewing successfully.",
                    "Certificate"));
            }
        }

        Missing(
            "Strict-Transport-Security",
            "Add Strict-Transport-Security on HTTPS responses, for example max-age=63072000; includeSubDomains; preload, only after HTTPS works for every name you use.",
            "In next.config.ts headers(), set Strict-Transport-Security to max-age=63072000; includeSubDomains; preload after HTTPS is correct for every hostname.",
            "In WordPress, set HSTS at the host or CDN, not in a random plugin unless you already trust that plugin. Confirm HTTPS works on wp-admin first.");

        Missing(
            "Content-Security-Policy",
            "Add a Content-Security-Policy that allowlists your own scripts and disallows unexpected frames. Start in Report-Only if you need to watch console errors.",
            "Keep using the shared CSP builder. Do not add 'unsafe-eval' in production. Avoid new third-party script hosts unless you re-review the policy.",
            "A security plugin can emit CSP, but a wrong policy will break the admin. Test on a copy of the site first.");

        Missing(
            "X-Content-Type-Options",
            "Send X-Content-Type-Options: nosniff on all responses.");

        Missing(
            "X-Frame-Options",
            "Send X-Frame-Options: DENY or a CSP frame-ancestors 'none' unless you intentionally embed this site.");

        Missing(
            "Referrer-Policy",
            "Send Referrer-Policy: strict-origin-when-cross-origin or stricter.");

        Missing(
            "Permissions-Policy",
            "Send Permissions-Policy disabling camera, microphone, geolocation, and payment unless a page truly needs them.");

        Missing(
            "Cross-Origin-Opener-Policy",
            "Send Cross-Origin-Opener-Policy: same-origin unless a page must be opened as a cross-origin popup.");

        Missing(
            "Cross-Origin-Resource-Policy",
            "Send Cross-Origin-Resource-Policy: same-origin or same-site unless you intentionally serve this response to other origins.");

        Missing(
            "SPF",
            $"At the DNS host for {hostname}, add a TXT record on the mail name (often the apex) starting with v=spf1 that lists only the services that send mail for you, and end with -all or ~all. Confirm the exact name with your mail provider.",
            null,
            "If WordPress sends mail through the host or a provider such as a transactional API, that provider must appear in the SPF record. Do not copy someone else's SPF.");

        var dmarc = findings.FirstOrDefault(x => x.Title == "DMARC");
        if (dmarc is { State: FindingState.NotFound })
        {
            steps.Add(new NextStep(
                "Publish DMARC after SPF is in place",
                "Add a TXT record on _dmarc. followed by the apex, for example v=DMARC1; p=none; rua=mailto:your-mailbox, then move to quarantine once reports look right. Do not start with p=reject until you have read a week of reports.",
                "DMARC"));
        }
        else if (dmarc is { State: FindingState.Attention })
        {
            steps.Add(new NextStep(
                "Move DMARC off monitor-only when reports look right",
                "This hostname publishes DMARC with p=none. After a week of rua reports with no unexpected sources, raise the policy to quarantine, then reject. Do not jump to p=reject on the first day.",
                "DMARC"));
        }

        if (http80Status is >= 200 and < 300 && string.IsNullOrEmpty(http80Location))
        {
            steps.Add(new NextStep(
                "Redirect HTTP to HTTPS",
                "Port 80 answered without sending you to HTTPS. At the host or CDN, redirect all http requests to https on the same hostname.",
                "HTTP"));
        }
        else if (http80Status is >= 300 and < 400 && !string.IsNullOrEmpty(http80Location) &&
                 !http80Location.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
        {
            steps.Add(new NextStep(
                "Point the HTTP redirect at HTTPS",
                $"Port 80 redirected to {http80Location}. Change that target to https://{hostname}/.",
                "HTTP"));
        }

        if (tlsProtocol is "Tls" or "Tls11" or "Ssl3")
        {
            steps.Add(new NextStep(
                "Turn off old TLS",
                "This handshake used an old TLS version. In the host or CDN SSL settings, allow TLS 1.2 and 1.3 only.",
                "TLS"));
        }

        if (findings.Any(f => f.Title == "Cookie flags" && f.State != FindingState.Present))
        {
            steps.Add(new NextStep(
                "Set cookie flags",
                "For cookies that authenticate a person, set HttpOnly, Secure, and SameSite=Lax or Strict. Session cookies should not be readable by page scripts.",
                "Cookie flags"));
        }

        if (findings.Any(f => f.Title == "Server disclosure" && f.State == FindingState.Attention))
        {
            steps.Add(new NextStep(
                "Stop advertising the stack on every response",
                next
                    ? "Set poweredByHeader: false in next.config.ts so Next.js is not named on every response."
                    : "Remove or genericize Server and X-Powered-By if you do not need them for debugging. They help an attacker choose a catalogue.",
                "Server disclosure"));
        }

        var cveHits = CveCatalog.Match(stack);
        foreach (var (entry, hint) in cveHits.Take(12))
        {
            steps.Add(new NextStep(
                $"Review {entry.Id} for {entry.Product} {hint.Version}",
                $"{entry.Summary} Evidence: {hint.Evidence} Read {entry.SourceUrl} and upgrade before you treat this as closed.",
                entry.Id));
        }
        if (cveHits.Count > 12)
        {
            steps.Add(new NextStep(
                $"Review the remaining {cveHits.Count - 12} catalogue matches",
                "The findings list has every match from this run. Upgrade the advertised library or framework, then run Site Check again. The catalogue is local; this program did not query NVD live.",
                "Known CVEs (advertised versions)"));
        }

        var wp = stack.FirstOrDefault(s => s.Product.Equals("WordPress", StringComparison.OrdinalIgnoreCase));
        if (wp?.Version != null)
        {
            steps.Add(new NextStep(
                "Confirm WordPress and plugins are current",
                $"The homepage advertised WordPress {wp.Version}. Compare that number with wordpress.org/download. Update WordPress, themes, and plugins from the dashboard. Remove the generator meta so the version is not public. This program did not log in to wp-admin and did not download plugin files.",
                "WordPress"));
        }
        if (pluginSlugs.Count > 0)
        {
            steps.Add(new NextStep(
                "Review plugins linked from the homepage",
                "These plugin directory names appeared in homepage URLs: " + string.Join(", ", pluginSlugs) +
                ". Confirm each is still maintained. Delete unused plugins. This is not a CVE proof for those plugins; it is only what the homepage linked.",
                "Plugins"));
        }

        return steps;
    }
}
