namespace SiteCheck.Core;

/// <summary>
/// Next steps only for what this run actually observed.
/// Wording follows the advertised stack (Next.js, WordPress, Vercel, Cloudflare)
/// so a fix is written for that environment, not a generic lab.
/// Incomplete header reads do not invent header chores when HTTPS never finished.
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
        string? http80Location,
        EdgeProfile? edge = null)
    {
        var steps = new List<NextStep>();
        var next = stack.Any(s => s.Product.Equals("Next.js", StringComparison.OrdinalIgnoreCase));
        var wordpress = stack.Any(s => s.Product.Equals("WordPress", StringComparison.OrdinalIgnoreCase));
        var cloudflare = stack.Any(s => s.Product.Equals("Cloudflare", StringComparison.OrdinalIgnoreCase));
        var vercel = stack.Any(s => s.Product.Equals("Vercel", StringComparison.OrdinalIgnoreCase));
        edge ??= new EdgeProfile(EdgeKind.Origin, "Origin", false, false, vercel);
        if (edge.Kind is EdgeKind.CloudflareProxied or EdgeKind.CloudflareDnsOnly)
            cloudflare = true;

        string HeaderEnv() =>
            next ? "Next.js" : wordpress ? "WordPress" : vercel ? "Vercel" : cloudflare ? "Cloudflare" : "This hostname";

        void MissingHeader(string title, string generic, string? nextJs = null, string? wp = null)
        {
            var f = findings.FirstOrDefault(x => x.Title.Equals(title, StringComparison.OrdinalIgnoreCase));
            if (f is null || f.State == FindingState.Present) return;
            if (f.State == FindingState.Incomplete && title != "HTTPS") return;
            var body = generic;
            if (next && nextJs != null) body = nextJs;
            else if (wordpress && wp != null) body = wp;
            else if (title.StartsWith("Cloudflare", StringComparison.OrdinalIgnoreCase))
            {
                // Cloudflare dashboard settings are not Vercel headers.
            }
            else if (vercel) body += " On Vercel this is usually a header in next.config.ts or the project Security Headers settings.";
            else if (cloudflare) body += " In Cloudflare: Rules, then Transform or HTTP Header Modification, or the SSL/TLS overview for HTTPS redirects.";
            steps.Add(new NextStep($"Fix {title}", body, title, HeaderEnv()));
        }

        void MissingDns(string title, string generic, string? cloudflareDns = null)
        {
            var f = findings.FirstOrDefault(x => x.Title.Equals(title, StringComparison.OrdinalIgnoreCase));
            if (f is null || f.State == FindingState.Present) return;
            if (f.State is FindingState.Incomplete or FindingState.Attention) return;
            var body = generic;
            if (cloudflare && cloudflareDns != null) body = cloudflareDns;
            else if (cloudflare)
                body += " Add this at the DNS host (Cloudflare DNS if the orange cloud is on). It is not an HTTP header and it does not go in next.config.ts.";
            steps.Add(new NextStep($"Fix {title}", body, title, "DNS host"));
        }

        var edgeStep = FixGuides.PublicEdgeStep(hostname, edge, vercel, next);
        if (edgeStep != null
            && findings.Any(f => f.Title == "Public edge" && f.State != FindingState.Present))
        {
            steps.Add(edgeStep);
        }

        MissingHeader(
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

        MissingHeader(
            "Strict-Transport-Security",
            "Add Strict-Transport-Security on HTTPS responses, for example max-age=63072000; includeSubDomains; preload, only after HTTPS works for every name you use.",
            "In next.config.ts headers(), set Strict-Transport-Security to max-age=63072000; includeSubDomains; preload after HTTPS is correct for every hostname.",
            "In WordPress, set HSTS at the host or CDN, not in a random plugin unless you already trust that plugin. Confirm HTTPS works on wp-admin first.");

        var csp = findings.FirstOrDefault(x => x.Title == "Content-Security-Policy");
        if (csp is { State: FindingState.Attention })
        {
            steps.Add(new NextStep(
                "Tighten Content-Security-Policy",
                next
                    ? "CSP is already present. script-src includes unsafe-inline, which Next.js App Router still needs unless middleware issues a per-request nonce. Do not remove unsafe-inline until a nonce is wired. Keep unsafe-eval off in production. style-src unsafe-inline is separate and is still common."
                    : "CSP is already present. script-src includes unsafe-inline. Move inline scripts to files, or issue a nonce, before you drop that token. style-src unsafe-inline is a separate question.",
                "Content-Security-Policy",
                next ? "Next.js" : HeaderEnv()));
        }
        else
        {
            MissingHeader(
                "Content-Security-Policy",
                "Add a Content-Security-Policy that allowlists your own scripts and disallows unexpected frames. Start in Report-Only if you need to watch console errors.",
                "Keep using the shared CSP builder. Do not add 'unsafe-eval' in production. Avoid new third-party script hosts unless you re-review the policy.",
                "A security plugin can emit CSP, but a wrong policy will break the admin. Test on a copy of the site first.");
        }

        MissingHeader(
            "X-Content-Type-Options",
            "Send X-Content-Type-Options: nosniff on all responses.");

        MissingHeader(
            "X-Frame-Options",
            "Send X-Frame-Options: DENY or a CSP frame-ancestors 'none' unless you intentionally embed this site.");

        MissingHeader(
            "Referrer-Policy",
            "Send Referrer-Policy: strict-origin-when-cross-origin or stricter.");

        MissingHeader(
            "Permissions-Policy",
            "Send Permissions-Policy disabling camera, microphone, geolocation, and payment unless a page truly needs them.");

        MissingHeader(
            "Cross-Origin-Opener-Policy",
            "Send Cross-Origin-Opener-Policy: same-origin unless a page must be opened as a cross-origin popup.");

        MissingHeader(
            "Cross-Origin-Resource-Policy",
            "Send Cross-Origin-Resource-Policy: same-origin or same-site unless you intentionally serve this response to other origins.");

        var coop = findings.FirstOrDefault(x => x.Title == "Cross-Origin-Opener-Policy");
        var coep = findings.FirstOrDefault(x => x.Title == "Cross-Origin-Embedder-Policy");
        if (coop is { State: FindingState.Present } && coep is { State: FindingState.NotFound })
        {
            steps.Add(new NextStep(
                "Add Cross-Origin-Embedder-Policy only if you need isolation",
                "COOP is already present. COEP (credentialless or require-corp) is the second header for a cross-origin isolated context.",
                "Cross-Origin-Embedder-Policy",
                HeaderEnv(),
                Optional: true,
                WhenTo: "Do this when this origin uses SharedArrayBuffer, high-resolution timers, or other APIs that require a cross-origin isolated context. Operation Locked In brochure sites use credentialless so Vercel Insights and fonts keep loading.",
                WhenNot: "Skip require-corp on a marketing site with third-party scripts or embeds. Skip entirely if you do not need those APIs. Rampart cannot see whether your JavaScript uses SharedArrayBuffer."));
        }

        MissingHeader(
            "Mixed content",
            "Serve every script, stylesheet, and image over HTTPS. Replace http:// URLs in the homepage with https:// or relative paths.",
            "In Next.js, keep next/image and public assets on HTTPS. Search the repo for http:// in layout and MDX.",
            "In WordPress, run a search-replace of the site URL to https and clear the cache.");

        MissingHeader(
            "Subresource Integrity",
            "Add integrity (and crossorigin) on third-party script tags, or host the script yourself. Same-origin bundles can skip this.",
            "Prefer bundling third-party code through next.config instead of a public CDN script tag.",
            "In WordPress, dequeue unused CDN scripts and host needed libraries from the theme with integrity hashes.");

        MissingHeader(
            "Tabnabbing",
            "On every target=_blank link, set rel=\"noopener noreferrer\" so the opened page cannot rewrite window.opener.",
            "In Next.js, <a target=\"_blank\"> should include rel=\"noopener noreferrer\". next/link passes rel through.",
            "In WordPress, theme and plugin markup that opens a new tab needs rel=\"noopener noreferrer\".");

        MissingHeader(
            "Sign-in form",
            "A public sign-in page posted a form to http://. Change that action to https:// or a relative path so passwords stay on TLS.");

        MissingHeader(
            "Sign-in redirect",
            "A public sign-in path redirected to http://. Change Location to https:// on the same hostname.");

        MissingHeader(
            "Form action",
            "Change every form action that starts with http:// to https:// or a relative path so the submission stays on TLS.",
            "Search the App Router and any client forms for action=\"http://\".",
            "In WordPress, set the site URL to https and re-save permalinks so form plugins inherit HTTPS.");

        MissingHeader(
            "Canonical URL",
            "Change the homepage rel=canonical href from http:// to https:// on the same hostname.");

        if (findings.Any(f => f.Title == "CORS" && f.State == FindingState.Attention))
        {
            steps.Add(new NextStep(
                "Confirm Access-Control-Allow-Origin on this origin",
                "The homepage sends Access-Control-Allow-Origin: *. That is acceptable for a public brochure page. If this origin also hosts an authenticated API, restrict the header to the exact front-end origin instead of *.",
                "CORS",
                HeaderEnv()));
        }

        if (findings.Any(f => f.Title == "X-XSS-Protection" && f.State == FindingState.Attention))
        {
            steps.Add(new NextStep(
                "Remove or disable X-XSS-Protection",
                "Set X-XSS-Protection to 0 or omit it. Current browsers ignore it, and a non-zero value can introduce XSS in old Internet Explorer.",
                "X-XSS-Protection",
                HeaderEnv()));
        }

        MissingDns(
            "DNSSEC",
            "If your registrar and DNS host support DNSSEC, enable it on the apex and publish DS at the parent. Confirm with the DNS host's own checker after it propagates. This is not an HTTP header and it does not go in next.config.ts.",
            "In Cloudflare: DNS, then Settings, then enable DNSSEC. Copy the DS record Cloudflare shows and add it at the registrar (the place that holds the domain, not Vercel). next.config.ts cannot enable DNSSEC.");

        MissingHeader(
            "security.txt",
            "Publish a security.txt file at https://your-host/.well-known/security.txt with a Contact: mailto line so researchers can reach you. See RFC 9116.",
            "Add public/.well-known/security.txt in the Next.js app with a Contact: mailto line, then deploy.",
            "A static file at /.well-known/security.txt is enough. A plugin is not required.");

        MissingDns(
            "CAA",
            "At the DNS host, add CAA records that list only the certificate authorities you use, for example issue \"letsencrypt.org\". This is a DNS record, not an HTTP header.",
            "In Cloudflare: DNS, then Records, then add CAA. For this stack (Vercel origin, Cloudflare edge) allow Let's Encrypt and Google Trust so both can issue: issue \"letsencrypt.org\" and issue \"pki.goog\", plus the same names with issuewild. Do not put CAA in next.config.ts.");

        MissingDns(
            "DKIM",
            "If this hostname sends mail, publish DKIM at the selector your mail provider specifies. This program asked default, google, selector1, selector2, k1, s1, s2, mail, dkim, and smtp.");

        MissingDns(
            "MX",
            "If this hostname should receive mail, add MX records at the DNS host pointing at your mail provider. If it must not receive mail, publish a null MX (preference 0, exchange \".\") so other servers know not to deliver.",
            "In Cloudflare: DNS, then Records, then MX. If the name should not receive mail, add a null MX (0 .). This is not an HTTP header.");

        if (findings.Any(f => f.Title == "MX" && f.State == FindingState.Present))
        {
            MissingDns(
                "MTA-STS DNS",
                "This apex publishes MX, so inbound mail is expected. Publish a TXT record on _mta-sts. plus the apex (v=STSv1; id=...) and a policy file at https://mta-sts.your-apex/.well-known/mta-sts.txt after MX TLS is correct.",
                "In Cloudflare: DNS, then Records, then TXT on _mta-sts. Use v=STSv1; id=a-unique-id. Serve the policy file on the mta-sts subdomain, not from next.config.ts.");

            MissingHeader(
                "MTA-STS policy",
                "Publish https://mta-sts.your-apex/.well-known/mta-sts.txt with version: STSv1, mode: testing then enforce, and mx: lines that match your MX hosts. Point the mta-sts subdomain at a host that can serve that file over HTTPS.",
                "The policy file must be served on the mta-sts subdomain of the apex (RFC 8461), not on www and not from next.config.ts headers.",
                "Serve the policy on the mta-sts subdomain of the apex. A plugin on www is the wrong place.");

            MissingDns(
                "TLS-RPT",
                "Add a TXT record on _smtp._tls. plus the apex, for example v=TLSRPTv1; rua=mailto:your-mailbox, so providers can report failed SMTP TLS.",
                "In Cloudflare: DNS, then Records, then TXT on _smtp._tls. Example: v=TLSRPTv1; rua=mailto:you@your-domain. This is not an HTTP header.");

            MissingDns(
                "BIMI",
                "BIMI is a brand logo in supporting inboxes. It needs DMARC at quarantine or reject, an SVG Tiny logo on HTTPS, and a TXT record on default._bimi. plus the apex. A Verified Mark Certificate is optional and costly.");
        }

        MissingHeader(
            "change-password",
            "If this hostname has accounts, publish https://your-host/.well-known/change-password that redirects to your password-change page (RFC 8615). A site without logins can omit this.",
            "Add a rewrite from /.well-known/change-password to your account password page in next.config.ts.",
            "Point /.well-known/change-password at the account password screen, or omit it if there are no accounts.");

        var spf = findings.FirstOrDefault(x => x.Title == "SPF");
        if (spf is { State: FindingState.Attention })
        {
            steps.Add(new NextStep(
                "Tighten the SPF all mechanism",
                "The published SPF record uses +all, all, or ?all, which does not restrict unexpected senders. After you have listed every legitimate include:, end the record with ~all (soft fail) or -all (fail). Do not use +all on a production name.",
                "SPF",
                "DNS host"));
        }
        else
        {
            var spfBody =
                $"At the DNS host for {hostname}, add a TXT record on the mail name (often the apex) starting with v=spf1 that lists only the services that send mail for you, and end with -all or ~all. Confirm the exact name with your mail provider.";
            if (wordpress)
                spfBody += " If WordPress sends mail through the host or a provider, that provider must appear in the SPF record.";
            MissingDns(
                "SPF",
                spfBody,
                "In Cloudflare: DNS, then Records, then TXT on the mail name (often @). List only the services that send mail for you. This is not an HTTP header.");
        }

        var dmarc = findings.FirstOrDefault(x => x.Title == "DMARC");
        if (dmarc is { State: FindingState.NotFound })
        {
            steps.Add(new NextStep(
                "Publish DMARC after SPF is in place",
                "Add a TXT record on _dmarc. followed by the apex, for example v=DMARC1; p=none; rua=mailto:your-mailbox, then move to quarantine once reports look right. Do not start with p=reject until you have read a week of reports.",
                "DMARC",
                "DNS host"));
        }
        else if (dmarc is { State: FindingState.Attention })
        {
            steps.Add(new NextStep(
                "Move DMARC off monitor-only when reports look right",
                "This hostname publishes DMARC with p=none. After a week of rua reports with no unexpected sources, raise the policy to quarantine, then reject. Do not jump to p=reject on the first day.",
                "DMARC",
                "DNS host"));
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

        var tls = findings.FirstOrDefault(x => x.Title == "TLS");
        if (tlsProtocol is "Tls" or "Tls11" or "Ssl3")
        {
            steps.Add(new NextStep(
                "Turn off old TLS",
                "This handshake used an old TLS version. In the host or CDN SSL settings, allow TLS 1.2 and 1.3 only.",
                "TLS"));
        }
        else if (tls is { State: FindingState.Attention })
        {
            steps.Add(new NextStep(
                "Prefer modern TLS ciphers",
                "This handshake used a cipher without forward secrecy, a CBC/RC4/3DES suite, or an RSA key shorter than 2048 bits. In the host or CDN SSL settings, prefer TLS 1.3, or TLS 1.2 with ECDHE and AES-GCM or ChaCha20. Issue a new certificate if the RSA key is under 2048 bits.",
                "TLS",
                cloudflare ? "Cloudflare" : HeaderEnv()));
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
                entry.Id,
                entry.Product));
        }
        if (cveHits.Count > 12)
        {
            steps.Add(new NextStep(
                $"Review the remaining {cveHits.Count - 12} catalogue matches",
                "The findings list has every match from this run. Upgrade the advertised library or framework, then run Rampart again. The catalogue is local; this program did not query NVD live.",
                "Known CVEs (advertised versions)"));
        }

        var wp = stack.FirstOrDefault(s => s.Product.Equals("WordPress", StringComparison.OrdinalIgnoreCase));
        if (wp?.Version != null)
        {
            steps.Add(new NextStep(
                "Confirm WordPress and plugins are current",
                $"The homepage advertised WordPress {wp.Version}. Compare that number with wordpress.org/download. Update WordPress, themes, and plugins from the dashboard. Remove the generator meta so the version is not public. This program did not log in to wp-admin and did not download plugin files.",
                "WordPress",
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

        MissingHeader(
            "Cloudflare email obfuscation",
            "Turn Email Address Obfuscation off in Cloudflare Security Settings. The injected email-decode.min.js script fights a tight Content-Security-Policy.");

        MissingHeader(
            "Cloudflare Web Analytics",
            "Disable Cloudflare Real User Measurements if this site already has first-party analytics. The beacon script is a third-party inject.");

        MissingHeader(
            "Cloudflare Rocket Loader",
            "Turn Rocket Loader off in Cloudflare Speed settings. It rewrites scripts and can break Next.js App Router.");

        MissingHeader(
            "Cloudflare HTML cache",
            "Bypass Cloudflare cache for HTML document routes. Cache fingerprinted static files only, then purge after a deploy.");

        return FixGuides.WithLines(steps, hostname, edge, next, wordpress, vercel, cloudflare);
    }
}
