// CODEMAP FILE: src/SiteCheck.Core/FixGuides.cs
// Product: Rampart (oli-site-check) — read-only public-surface hostname checker, public pin 1.9.0
// Role: Copyable how-to lines and when-to/when-not notes. Ensure() attaches a panel to every non-Present finding so Admin Not-found still explains itself.
// Called by: Checker after Advice.Build. All three UIs render NextStep.Lines via FindingGuide.
// Calls: EdgeProfile, hostname, stack booleans.
// Invariants: How-to follows the advertised stack. Never tell a kit operator to create /account/sign-in. Never send Cloudflare steps to a Vercel-only origin.
// Sisters: Bastion (bastion-hardening) hardens the local Windows PC. bastion-web is the public storefront and hosts /rampart plus the GitHub asset redirect. oli-web-kits client brochures should already 404 the probe paths this checker GETs.
// Map: docs/CODEMAP.md — read that file first for the run/load graph.

namespace SiteCheck.Core;

/// <summary>
/// See docs/CODEMAP.md.
/// Full-sentence, copyable how-to lines for a finding that needs work.
/// Wording follows the advertised edge (Cloudflare, Vercel, origin) so the
/// operator is not sent to the wrong dashboard.
/// </summary>
public static class FixGuides
{
    public static IReadOnlyList<NextStep> WithLines(
        IReadOnlyList<NextStep> steps,
        string hostname,
        EdgeProfile edge,
        bool nextJs,
        bool wordpress,
        bool vercel,
        bool cloudflare)
    {
        return steps.Select(s =>
        {
            var lines = s.Lines is { Count: > 0 } ? s.Lines : For(s.Related, hostname, edge, nextJs, wordpress, vercel, cloudflare);
            var note = Note(s.Related);
            if ((lines is null || lines.Count == 0) && note is null) return s;
            return s with
            {
                Lines = lines is { Count: > 0 } ? lines : s.Lines,
                Optional = s.Optional || note != null,
                WhenTo = s.WhenTo ?? note?.WhenTo,
                WhenNot = s.WhenNot ?? note?.WhenNot
            };
        }).ToArray();
    }

    /// <summary>
/// See docs/CODEMAP.md.
    /// Every finding that is not a clean Present gets a How to fix this panel:
    /// full sentences, when-to / when-not, and copyable lines.
    /// </summary>
    public static IReadOnlyList<NextStep> Ensure(
        IReadOnlyList<Finding> findings,
        IReadOnlyList<NextStep> steps,
        string hostname,
        EdgeProfile edge,
        bool nextJs,
        bool wordpress,
        bool vercel,
        bool cloudflare)
    {
        var filled = WithLines(steps, hostname, edge, nextJs, wordpress, vercel, cloudflare).ToList();
        foreach (var f in findings)
        {
            if (f.State == FindingState.Present) continue;
            var already = filled.Any(s => s.Related.Equals(f.Title, StringComparison.OrdinalIgnoreCase));
            if (!already && f.State == FindingState.NotFound && !CoreHygieneNotFound(f.Title)) continue;
            if (!already && OptionalUntilAdvised(f.Title)) continue;
            var existing = filled.FirstOrDefault(s => s.Related.Equals(f.Title, StringComparison.OrdinalIgnoreCase));
            IReadOnlyList<FixLine>? lines;
            if (f.State == FindingState.Incomplete)
            {
                lines = Fallback(f, hostname, nextJs, wordpress);
            }
            else
            {
                lines = existing?.Lines is { Count: > 0 }
                    ? existing.Lines
                    : For(f.Title, hostname, edge, nextJs, wordpress, vercel, cloudflare);
                if (lines is null || lines.Count == 0)
                    lines = Fallback(f, hostname, nextJs, wordpress);
            }
            var note = Note(f.Title);
            if (existing is null)
            {
                filled.Add(new NextStep(
                    HowToTitle(f),
                    HowToBody(f),
                    f.Title,
                    nextJs ? "Next.js" : wordpress ? "WordPress" : vercel ? "Vercel" : cloudflare ? "Cloudflare" : "This hostname",
                    lines,
                    WhenTo: note?.WhenTo,
                    WhenNot: note?.WhenNot));
            }
            else
            {
                var i = filled.IndexOf(existing);
                filled[i] = existing with
                {
                    Lines = lines,
                    WhenTo = existing.WhenTo ?? note?.WhenTo,
                    WhenNot = existing.WhenNot ?? note?.WhenNot
                };
            }
        }
        return filled;
    }

    /// <summary>
/// See docs/CODEMAP.md.
    /// NotFound cards that always need a how-to. Optional headers and brochure
    /// sign-in gaps stay observations unless Advice already added a step.
    /// </summary>
    private static bool CoreHygieneNotFound(string title) => title is
        "HTTPS" or
        "Certificate" or
        "Admin pages" or
        "HTTP" or
        "Strict-Transport-Security" or
        "Content-Security-Policy" or
        "X-Content-Type-Options" or
        "X-Frame-Options" or
        "Referrer-Policy" or
        "Cookie flags" or
        "SPF" or
        "DMARC" or
        "Private files" or
        "Oracle PeopleSoft" or
        "WWW and apex" or
        "security.txt";

    private static bool OptionalUntilAdvised(string title) => title is
        "Cross-Origin-Embedder-Policy" or
        "MTA-STS DNS" or
        "MTA-STS policy" or
        "TLS-RPT" or
        "BIMI" or
        "change-password";

    private static string HowToTitle(Finding f) => f.State switch
    {
        FindingState.Incomplete => "Finish the check for " + f.Title,
        FindingState.NotFound => "Publish or confirm " + f.Title,
        _ => "Address " + f.Title
    };

    private static string HowToBody(Finding f) =>
        "The card above is the observation from this run. The lines below are the steps for this hostname only. Copy one line at a time. Do not paste passwords into Rampart.";

    private static IReadOnlyList<FixLine> Fallback(Finding f, string hostname, bool nextJs, bool wordpress)
    {
        var lines = new List<FixLine>
        {
            L("Read the observation on this card first. It is what this run actually saw on " + hostname + "."),
            L("Confirm in a private browser window:", "https://" + hostname + "/")
        };
        if (f.Title.StartsWith("CVE-", StringComparison.OrdinalIgnoreCase))
        {
            lines.Add(L("Look up the advisory, then upgrade the advertised product or stop publishing that version in HTML and headers."));
            lines.Add(L("National Vulnerability Database entry:", "https://nvd.nist.gov/vuln/detail/" + f.Title));
            lines.Add(L("This program does not send exploit traffic. A catalogue match is a prompt to upgrade, not proof the host is exploitable."));
            return lines;
        }
        if (f.State == FindingState.Incomplete)
        {
            lines.Add(L("The network step did not finish. Confirm the hostname is public, that this computer can reach port 443, and that a firewall is not blocking Rampart."));
            lines.Add(L("Run the check again after the host answers. A timeout is not proof the control is missing."));
            return lines;
        }
        if (nextJs)
            lines.Add(L("If this is a Next.js app, prefer a change in next.config.ts, middleware, or DNS over a random plugin."));
        if (wordpress)
            lines.Add(L("If this is WordPress, prefer the host or CDN over an untrusted security plugin. Test wp-admin after you change headers."));
        lines.Add(L("When the change is live, run Rampart again on " + hostname + " and confirm this card moves to Present."));
        return lines;
    }

    public static NextStep? PublicEdgeStep(string hostname, EdgeProfile edge, bool vercel, bool nextJs)
    {
        var apex = Hostname.Apex(hostname);
        if (edge.Kind is EdgeKind.CloudflareProxied or EdgeKind.OtherCdn)
            return null;

        if (edge.Kind == EdgeKind.CloudflareDnsOnly)
        {
            return new NextStep(
                "Turn on the Cloudflare proxy after Full (strict) TLS",
                "Cloudflare already holds DNS for this name, and the orange cloud is likely off. Put Full (strict) in place, then proxy www (and the apex if you use it) so WAF and HTTPS enforcement sit in front of the origin.",
                "Public edge",
                "Cloudflare",
                new[]
                {
                    L("Open the Cloudflare dashboard and select the zone for " + apex + ".", "https://dash.cloudflare.com/"),
                    L("Open SSL/TLS, then Overview. Set encryption mode to Full (strict). The origin must already present a valid certificate for this hostname."),
                    L("Open SSL/TLS, then Edge Certificates. Turn Always Use HTTPS on. Set minimum TLS version to 1.2."),
                    L("Open DNS, then Records. For the www name, set the proxy status to Proxied (orange cloud). Do the same for the apex if Cloudflare can proxy it."),
                    L("Wait one or two minutes, then open https://" + hostname + "/ and confirm the site loads. Rampart should then report a cf-ray header."),
                    L("Leave Vercel (or your host) attached as the origin. Do not change the public site URL while you do this.")
                });
        }

        var originNote = vercel || nextJs
            ? "This hostname already has a working origin (Vercel or Next.js). Cloudflare sits in front. The origin stays where it is."
            : "Cloudflare is the usual first edge for a public website. The free plan is enough to start. Bunny, Fastly, or Amazon CloudFront are alternatives if you already have a reason to use them.";

        return new NextStep(
            "Put a CDN edge in front of this hostname",
            originNote + " Rampart cannot log in to Cloudflare. The steps below are the public-surface path for a Vercel origin behind grey-cloud DNS.",
            "Public edge",
            vercel || nextJs ? "Cloudflare in front of Vercel" : "Cloudflare",
            new[]
            {
                L("Create a Cloudflare account and add the site " + apex + ". The free plan is enough to start.", "https://dash.cloudflare.com/"),
                L("When Cloudflare lists DNS records, keep mail and TXT records. Point www at your current origin (for Vercel that is often cname.vercel-dns.com). Leave the proxy grey (DNS only) until nameservers are Active."),
                L("At the registrar, replace the nameservers with the two Cloudflare nameservers shown in the dashboard. Wait until the zone status is Active."),
                L("Set SSL/TLS encryption mode to Full (strict). Turn Always Use HTTPS on. Set minimum TLS version to 1.2."),
                L("When the zone is Active and Full (strict) is set, turn the orange cloud on for www (and the apex if you use it)."),
                L("Confirm https://" + hostname + "/ loads, then run Rampart again. A cf-ray header means the proxy is in front."),
                L("If you prefer not to use Cloudflare, Bunny, Fastly, or Amazon CloudFront can sit in front of the same origin. Keep one public edge, not two competing proxies.")
            });
    }

    private static (string WhenTo, string WhenNot)? Note(string related) => related switch
    {
        "Cross-Origin-Embedder-Policy" => (
            "Do this when this origin uses SharedArrayBuffer or other APIs that need a cross-origin isolated context.",
            "Skip on a typical brochure site. Rampart cannot see whether your JavaScript uses those APIs. require-corp will break third-party scripts that omit CORP."),
        "BIMI" => (
            "Do this when DMARC is already quarantine or reject and you want a brand logo in supporting inboxes.",
            "Skip if you have no square SVG logo, if DMARC is still p=none, or if you will not buy a Verified Mark Certificate for Gmail."),
        "MTA-STS DNS" or "MTA-STS policy" => (
            "Do this when this domain receives mail (MX is published) and you want senders to use TLS for SMTP.",
            "Skip if the name does not receive mail."),
        "TLS-RPT" => (
            "Do this with MTA-STS so providers can mail you SMTP TLS failure reports.",
            "Skip if you do not receive mail or do not want extra report messages."),
        "change-password" => (
            "Do this when people can sign in on this hostname.",
            "Skip on a brochure site with no accounts. A 404 is then correct."),
        "Admin pages" => (
            "Do this when /wp-admin/ or /admin showed a dashboard to a signed-out GET, or when you intended WordPress and those paths are missing.",
            "Skip adding WordPress admin on a Next.js or brochure hostname. A 403 or 404 on /wp-admin/ and /admin is then the healthy public surface."),
        "Sign-in pages" => (
            "Do this when people can sign in on this hostname and none of the common login paths answered.",
            "Skip on a brochure site with no accounts. Missing /login is then correct."),
        _ => null
    };

    private static IReadOnlyList<FixLine> For(
        string related,
        string hostname,
        EdgeProfile edge,
        bool nextJs,
        bool wordpress,
        bool vercel,
        bool cloudflare)
    {
        var apex = Hostname.Apex(hostname);
        var cf = cloudflare || edge.Kind is EdgeKind.CloudflareProxied or EdgeKind.CloudflareDnsOnly;
        var headerPlace = nextJs
            ? "In the Next.js app, set this in next.config.ts headers()."
            : wordpress
                ? "Set this at the host, CDN, or a security plugin you already trust. Test on a copy of the site first."
                : vercel
                    ? "On Vercel this is usually a header in next.config.ts or the project Security Headers settings."
                    : cf
                        ? "In Cloudflare: Rules, then Transform Rules, then Modify Response Header, or the SSL/TLS overview for HTTPS."
                        : "Set this on the HTTPS responses from this hostname.";

        return related switch
        {
            "CAA" => cf
                ? new[]
                {
                    L("CAA is a DNS record. It does not go in next.config.ts and it is not a Vercel header."),
                    L("Open Cloudflare, then DNS, then Records, then Add record. Type is CAA. Name is @. Flags is 0. TTL is Auto.", "https://dash.cloudflare.com/"),
                    L("The Tag dropdown says Only allow specific hostnames for ordinary certificates (issue), and Only allow wildcards for wildcard certificates (issuewild)."),
                    L("Record 1: Tag Only allow specific hostnames. CA domain name:", "letsencrypt.org"),
                    L("Record 2: Tag Only allow specific hostnames. CA domain name:", "pki.goog"),
                    L("Record 3: Tag Only allow wildcards. CA domain name:", "letsencrypt.org"),
                    L("Record 4: Tag Only allow wildcards. CA domain name:", "pki.goog"),
                    L("Save after each record. Wait a minute, then run Rampart again on " + hostname + ".")
                }
                : new[]
                {
                    L("At the DNS host for " + apex + ", add CAA records that list only the certificate authorities you use."),
                    L("A typical Let's Encrypt line is:", "0 issue \"letsencrypt.org\""),
                    L("If a CDN issues its own certificates, add that CA as well (for Cloudflare Universal SSL, pki.goog)."),
                    L("CAA is a DNS record. It does not go in the web server config as an HTTP header.")
                },
            "DNSSEC" => cf
                ? new[]
                {
                    L("DNSSEC is enabled at the DNS host and at the registrar. It does not go in next.config.ts."),
                    L("In Cloudflare: DNS, then Settings, then DNSSEC, then Enable DNSSEC. Copy Key Tag, Algorithm, Digest Type, and Digest.", "https://dash.cloudflare.com/"),
                    L("This domain is registered at GoDaddy and uses Cloudflare nameservers. In GoDaddy do not use the one-click DNSSEC toggle. That toggle is for GoDaddy nameservers."),
                    L("In GoDaddy: Domain Portfolio, then " + apex + ", then DNS, then DS Records, then Add.", "https://dcc.godaddy.com/"),
                    L("Paste Cloudflare Key Tag into Key Tag, Algorithm 13 (ECDSA Curve P-256 with SHA-256 if that is how the menu is labelled), Digest Type 2, and the full Digest hex string. Save."),
                    L("Wait until Cloudflare DNSSEC shows Active, then run Rampart again. Rampart checks for DS and DNSKEY; it does not walk the chain to the root.")
                }
                : new[]
                {
                    L("If your registrar and DNS host support DNSSEC, enable it on the apex " + apex + "."),
                    L("Publish the DS record at the parent (the registrar). Confirm with the DNS host's own checker after it propagates."),
                    L("This is not an HTTP header.")
                },
            "Strict-Transport-Security" => nextJs
                ? new[]
                {
                    L(headerPlace),
                    L("Set Strict-Transport-Security only after HTTPS works for every name you use.", "max-age=63072000; includeSubDomains; preload"),
                    L("If Cloudflare is in front, also turn HSTS on under SSL/TLS, then Edge Certificates, with a max-age of at least 12 months, so the edge does not replace a strong header with a weaker one.")
                }
                : new[]
                {
                    L(headerPlace),
                    L("Send this header on HTTPS responses:", "Strict-Transport-Security: max-age=63072000; includeSubDomains; preload"),
                    L("Turn it on only after every hostname you use already works on HTTPS.")
                },
            "Content-Security-Policy" => nextJs
                ? new[]
                {
                    L("Do not add 'unsafe-eval' in production."),
                    L("Production script-src should use a per-request nonce from middleware (createCspNonce, x-nonce, NextResponse.next request headers) instead of 'unsafe-inline'."),
                    L("Do not also send CSP from next.config.ts. A static header cannot carry a nonce, and two policies AND-combine."),
                    L("In Cloudflare Managed Transforms, leave Add security headers Off. That feature can fight this CSP."),
                    L("If Email Address Obfuscation or Web Analytics injects scripts, turn those Cloudflare features off instead of widening CSP.")
                }
                : new[]
                {
                    L(headerPlace),
                    L("Add a Content-Security-Policy that allowlists your own scripts and disallows unexpected frames. Start in Report-Only if you need to watch console errors.")
                },
            "SPF" => new[]
            {
                L("At the DNS host for " + hostname + ", add a TXT record on the mail name (often the apex) that starts with v=spf1."),
                L("List only the services that send mail for you, then end with ~all or -all. Do not use +all on a production name."),
                L(cf
                    ? "In Cloudflare: DNS, then Records, then TXT on @ (or the mail name). This is not an HTTP header."
                    : "This is a DNS TXT record, not an HTTP header.")
            },
            "DMARC" => new[]
            {
                L("Publish SPF first, then add a TXT record on _dmarc." + apex + "."),
                L("Start in monitor mode, then raise the policy after you have read a week of reports.", "v=DMARC1; p=none; rua=mailto:you@" + apex),
                L("When reports look right, move p=none to p=quarantine, then p=reject. Do not jump to p=reject on the first day."),
                L(cf ? "In Cloudflare: DNS, then Records, then TXT on _dmarc." : "Add this at the DNS host. It is not an HTTP header.")
            },
            "MX" => new[]
            {
                L("If " + apex + " should receive mail, add MX records at the DNS host pointing at your mail provider."),
                L("If this name must not receive mail, publish a null MX so other servers know not to deliver.", "0 ."),
                L(cf ? "In Cloudflare: DNS, then Records, then MX. This is not an HTTP header." : "Add MX at the DNS host. Rampart does not open port 25.")
            },
            "HTTP" => new[]
            {
                L("Port 80 answered without sending the browser to HTTPS."),
                L(cf
                    ? "In Cloudflare: SSL/TLS, then Edge Certificates, then Always Use HTTPS: On."
                    : headerPlace + " Redirect every http request to https on the same hostname.")
            },
            "Cookie flags" => new[]
            {
                L("For cookies that authenticate a person, set HttpOnly, Secure, and SameSite=Lax or Strict."),
                L("Session cookies should not be readable by page scripts."),
                L("Confirm the flags in the browser developer tools after you deploy. If this hostname has accounts, session cookies should use HttpOnly, Secure, and SameSite=Lax or Strict.")
            },
            "security.txt" => new[]
            {
                L("Publish a contact file at this URL so researchers can reach you.", "https://" + hostname + "/.well-known/security.txt"),
                L("A minimum file is one Contact line.", "Contact: mailto:security@" + apex),
                L(nextJs
                    ? "Add public/.well-known/security.txt in the Next.js app, then deploy."
                    : "A static file at /.well-known/security.txt is enough. A plugin is not required.")
            },
            "Tabnabbing" => new[]
            {
                L("On every link that opens a new tab, set rel to noopener and noreferrer.", "rel=\"noopener noreferrer\""),
                L(nextJs
                    ? "In Next.js, a target=_blank link should include that rel. next/link passes rel through."
                    : "Search the theme or templates for target=_blank and add the rel attribute on the same tag.")
            },
            "Form action" => new[]
            {
                L("Change every form action that starts with http:// to https:// or a relative path."),
                L("Search the site files for action=\"http://\" and replace those URLs.")
            },
            "Canonical URL" => new[]
            {
                L("Change the homepage rel=canonical href from http:// to https:// on the same hostname."),
                L("Search for rel=\"canonical\" and confirm the href starts with https://.")
            },
            "Cloudflare email obfuscation" => new[]
            {
                L("Open the Cloudflare dashboard for " + apex + ".", "https://dash.cloudflare.com/"),
                L("Open Security, then Settings. Find Email Address Obfuscation and set it Off."),
                L("If you cannot see it, use the dashboard search box and type Email Address Obfuscation."),
                L("Do not widen Content-Security-Policy to allow email-decode.min.js. Turning the feature off is the fix.")
            },
            "Cloudflare Web Analytics" => new[]
            {
                L("Open Cloudflare Web Analytics.", "https://dash.cloudflare.com/?to=/:account/web-analytics"),
                L("On this zone, choose Manage site, then set Real User Measurements to Disable, then Update."),
                L("If this site already has first-party analytics, leave the Cloudflare beacon off.")
            },
            "Cloudflare Rocket Loader" => new[]
            {
                L("Open Cloudflare, then Speed, then Optimization. Turn Rocket Loader Off."),
                L("Rocket Loader rewrites scripts and is a poor fit for Next.js App Router.")
            },
            "Cloudflare HTML cache" => new[]
            {
                L("Open Cloudflare, then Caching, then Cache Rules."),
                L("Bypass cache when the URI Path starts with /api/."),
                L("Do not force Cache Everything on HTML document routes. Cache /_next/static/ and /brand/ only."),
                L("After a deploy, Purge Everything if a visitor still sees old HTML.")
            },
            "X-Content-Type-Options" => new[]
            {
                L(headerPlace),
                L("Send this header on all responses:", "X-Content-Type-Options: nosniff")
            },
            "X-Frame-Options" => new[]
            {
                L(headerPlace),
                L("Send this header, or set CSP frame-ancestors to none:", "X-Frame-Options: DENY")
            },
            "Referrer-Policy" => new[]
            {
                L(headerPlace),
                L("Send this header:", "Referrer-Policy: strict-origin-when-cross-origin")
            },
            "Permissions-Policy" => new[]
            {
                L(headerPlace),
                L("Disable camera, microphone, geolocation, and payment unless a page truly needs them.", "camera=(), microphone=(), geolocation=(), payment=()")
            },
            "Cross-Origin-Embedder-Policy" => nextJs
                ? new[]
                {
                    L("When to do this: you need SharedArrayBuffer or a cross-origin isolated page. Use credentialless if third-party scripts must still load."),
                    L("When not to: a brochure site with no such APIs. require-corp will break embeds that do not send Cross-Origin-Resource-Policy."),
                    L("In next.config.ts headers(), add:", "Cross-Origin-Embedder-Policy: credentialless"),
                    L("Keep Cross-Origin-Opener-Policy: same-origin. Deploy, then open the homepage and confirm scripts still load."),
                    L("Rampart cannot see your JavaScript. If the homepage goes blank, remove the header and re-deploy.")
                }
                : new[]
                {
                    L("When to do this: you need SharedArrayBuffer or similar isolation."),
                    L("When not to: ordinary brochure or WordPress sites with ads, fonts, or embeds from other hosts."),
                    L("Send this header on HTTPS responses:", "Cross-Origin-Embedder-Policy: credentialless")
                },
            "MTA-STS DNS" => new[]
            {
                L("When to do this: this domain receives mail (MX is published) and you want senders to use TLS on SMTP."),
                L("When not to: the name does not receive mail, or you only send (SPF/DKIM) and never inbox."),
                L("Open Cloudflare, zone for " + apex + ", DNS, then Records, then Add record.", "https://dash.cloudflare.com/"),
                L("Type TXT. Name _mta-sts. Proxy DNS only (grey cloud). TTL Auto. Content:", "v=STSv1; id=20260928"),
                L("Save. You also need the policy file on https://mta-sts." + apex + "/.well-known/mta-sts.txt (see MTA-STS policy).")
            },
            "MTA-STS policy" => new[]
            {
                L("When to do this: MX is published and _mta-sts TXT already exists."),
                L("When not to: no inbound mail, or you are not ready to serve HTTPS on the mta-sts subdomain."),
                L("In the Next.js app add public/.well-known/mta-sts.txt with:", "version: STSv1\nmode: testing\nmx: your-mx-host\nmax_age: 86400"),
                L("Replace your-mx-host with the MX target Rampart listed (for Outlook that is often NAME-com.mail.protection.outlook.com)."),
                L("In Vercel: Settings, then Domains, then add:", "mta-sts." + apex),
                L("In Cloudflare: DNS, Records, Add record. Type CNAME. Name mta-sts. Target cname.vercel-dns.com. Proxy orange or grey. TTL Auto."),
                L("Wait until https://mta-sts." + apex + "/.well-known/mta-sts.txt loads. Start with mode testing. After a week with no mail loss, change testing to enforce and raise the id= on the TXT record.")
            },
            "TLS-RPT" => new[]
            {
                L("When to do this: you turned on MTA-STS and want a mailbox for SMTP TLS failure reports."),
                L("When not to: no inbound mail, or you do not want extra report mail at Info@."),
                L("Cloudflare: DNS, Records, Add record. Type TXT. Name _smtp._tls. Proxy DNS only. Content:", "v=TLSRPTv1; rua=mailto:Info@" + apex)
            },
            "BIMI" => new[]
            {
                L("When to do this: DMARC is already p=quarantine or p=reject, you have a square SVG logo, and you want that logo in supporting inboxes (Yahoo, some others). Gmail usually also wants a paid Verified Mark Certificate."),
                L("When not to: DMARC is p=none, you have no SVG logo, or you do not care about inbox logos. Rampart cannot see whether a VMC exists."),
                L("Put an SVG Tiny 1.2 square logo on HTTPS with no scripts. Example path:", "https://" + hostname + "/brand/bimi.svg"),
                L("Cloudflare: DNS, Records, Add record. Type TXT. Name default._bimi. Proxy DNS only. Content:", "v=BIMI1; l=https://" + hostname + "/brand/bimi.svg"),
                L("Do not orange-cloud this TXT. A VMC (a=https://...) is optional and usually several hundred dollars per year.")
            },
            "Sign-in form" => new[]
            {
                L("When to do this: a public login page posts to http://. That sends passwords without TLS."),
                L("When not to: the form already posts to https:// or to a relative path such as /api/auth/sign-in."),
                L("Search the sign-in template for action=\"http://\" and change it to https:// or a relative path."),
                L("Open the public sign-in page this hostname actually uses. Keep the form action relative or https."),
                L("In WordPress, set the site URL to https and re-save permalinks.", "https://example.com/wp-admin/options-general.php")
            },
            "Sign-in redirect" => new[]
            {
                L("When to do this: GET on a login path returned Location: http://..."),
                L("When not to: Location already starts with https:// on the same hostname."),
                L("Change that redirect to https:// on the same hostname. In Next.js that is often next.config.ts redirects()."),
                L("If you use Next.js redirects, send leftover /login URLs to the sign-in path this hostname already publishes."),
                L("In Cloudflare, SSL/TLS, Edge Certificates, Always Use HTTPS should already catch http:// hops.", "https://dash.cloudflare.com/")
            },
            "Sign-in mixed content" => new[]
            {
                L("When to do this: the sign-in HTML named an http:// script, stylesheet, or image."),
                L("When not to: every src and href on that page is https:// or relative."),
                L("Replace those http:// URLs with https:// or with a path that starts with /."),
                L("In Next.js, search the account route and the root layout for http://. Keep next/image and public assets on HTTPS.")
            },
            "Sign-in framing" => new[]
            {
                L("When to do this: a public sign-in page answered 200 without X-Frame-Options and without CSP frame-ancestors."),
                L("When not to: that route already sends X-Frame-Options: DENY or CSP frame-ancestors 'none' (or a short allowlist you intend)."),
                L("Add this header on account and sign-in routes:", "X-Frame-Options: DENY"),
                L("And keep this in Content-Security-Policy:", "frame-ancestors 'none'"),
                L("In next.config.ts headers(), return those fields for /account/:path* as well as for / . Homepage headers do not automatically cover a different route unless the matcher includes it."),
                L("Copyable Next.js matcher example:", "source: '/account/:path*'\nheaders: [\n  { key: 'X-Frame-Options', value: 'DENY' },\n  { key: 'Cache-Control', value: 'no-store' }\n]"),
                L("In WordPress, set the header at the host or CDN for /wp-login.php and /wp-admin/. A security plugin can do this; test wp-admin after you change it.")
            },
            "Sign-in cookies" => new[]
            {
                L("When to do this: GET on a sign-in path already set a cookie without HttpOnly or Secure."),
                L("When not to: no Set-Cookie was sent on GET. Many apps only set the session cookie after a successful POST, which Rampart does not send."),
                L("Every session cookie needs these flags:", "HttpOnly; Secure; SameSite=Lax"),
                L("In Better Auth (Next.js), keep cookies httpOnly, use Secure in production, and sameSite: \"lax\". On HTTPS, a __Host- prefix is the usual production name."),
                L("Copyable Better Auth cookie flags:", "advanced: {\n  useSecureCookies: true,\n  cookiePrefix: \"__Host-oli\"\n}"),
                L("In WordPress, confirm FORCE_SSL_ADMIN is true so auth cookies are Secure.", "define('FORCE_SSL_ADMIN', true);")
            },
            "Sign-in cache" => new[]
            {
                L("When to do this: a sign-in HTML response sent Cache-Control: public without no-store."),
                L("When not to: the route already sends no-store, no-cache, or private."),
                L("Send this on sign-in and account HTML:", "Cache-Control: no-store"),
                L("In next.config.ts headers() for /account/:path* add Cache-Control: no-store. Dynamic App Router pages should already be uncached; this makes it explicit."),
                L("In Cloudflare, skip cache for those paths: Cache Rules, then Bypass cache when URI Path starts with /account or /wp-login.php.", "https://dash.cloudflare.com/")
            },
            "Admin pages" => new[]
            {
                L("When to do this: /wp-admin/ or /admin answered 200 with dashboard markup to a signed-out GET, or you intended this hostname to be WordPress and those paths are missing."),
                L("When not to: this is a Next.js or brochure site with no WordPress. Then /wp-admin/ and /admin should not exist. A 403 or 404 is the healthy public surface."),
                L("Confirm /wp-admin/ in a private browser window while signed out.", "https://" + hostname + "/wp-admin/"),
                L("Confirm /admin the same way.", "https://" + hostname + "/admin"),
                L("If you see a dashboard while signed out, put a login redirect in front of it, or restrict the path at the host or CDN."),
                L("If you do not run WordPress, keep probes from reaching an application. In Next.js middleware, return 404 for those paths."),
                L("Copyable Next.js guard:", "if (path === \"/admin\" || path.startsWith(\"/admin/\") || path.includes(\"/wp-admin\")) {\n  return new NextResponse(null, { status: 404 });\n}"),
                L("Optional Cloudflare WAF custom rule:", "(http.request.uri.path contains \"/wp-admin\") or (http.request.uri.path eq \"/admin\") then Block"),
                L("Cloudflare dashboard:", "https://dash.cloudflare.com/"),
                L("Do not type passwords into Rampart. This program never submits a login form.")
            },
            "Sign-in pages" => new[]
            {
                L("When to do this: this hostname advertised WordPress or another account product, and none of the common public login paths answered."),
                L("When not to: this is a brochure hostname with no public accounts. Missing /login is then correct."),
                L("If people sign in here, publish one stable HTTPS sign-in URL and keep it on this hostname.", "https://" + hostname + "/"),
                L(wordpress
                    ? "WordPress usually uses /wp-login.php. Restore that path or the custom login you already chose."
                    : "Use the login URL this product already documents. Do not invent a path from another site."),
                L("A custom login URL outside the allowlist is not found by this check. That is not proof there are no accounts.")
            },
            "HTTPS" => new[]
            {
                L("When to do this: this run did not complete HTTPS on a public address."),
                L("When not to: you already load https://" + hostname + "/ in a browser from this network."),
                L("Confirm DNS for " + hostname + " points at the intended host, and that port 443 is open."),
                L("Issue a certificate that names this hostname. Let's Encrypt is the usual free path.", "https://letsencrypt.org/getting-started/"),
                L("On Vercel, attach the domain in Project Settings, then Domains, and wait until the certificate is Issued.", "https://vercel.com/dashboard"),
                L("This program does not change firewall rules for you.")
            },
            "Certificate" => new[]
            {
                L("When to do this: the certificate is missing, does not name this hostname, or is near expiry."),
                L("When not to: the browser padlock already names " + hostname + " and automatic renewal is confirmed."),
                L("Issue a certificate that includes this exact hostname, and www if you use it."),
                L("Let's Encrypt via the host or Caddy/nginx is common. Wait for DNS to match before you request the certificate.", "https://letsencrypt.org/getting-started/"),
                L("On Vercel, open Domains and confirm the certificate status is Issued.", "https://vercel.com/dashboard")
            },
            "Mixed content" => new[]
            {
                L("When to do this: the homepage HTML named an http:// script, stylesheet, or image."),
                L("When not to: every src and href on the homepage is https:// or a relative path."),
                L("Replace those http:// URLs with https:// or with a path that starts with /."),
                L("In Next.js, search the App Router and public assets for http://. Keep next/image on HTTPS.")
            },
            "Subresource Integrity" => new[]
            {
                L("When to do this: a third-party https:// script on the homepage has no integrity attribute."),
                L("When not to: the scripts are same-origin bundles such as /_next/static. Those often omit integrity on purpose."),
                L("For a third-party CDN script, add integrity and crossorigin=\"anonymous\" on the script tag."),
                L("Example:", "<script src=\"https://cdn.example/lib.js\" integrity=\"sha384-...\" crossorigin=\"anonymous\"></script>")
            },
            "DKIM" => new[]
            {
                L("When to do this: this domain sends mail and no DKIM TXT was found on common selector names."),
                L("When not to: the name never sends mail."),
                L("At the mail host, enable DKIM and publish the TXT record they give you (often selector._domainkey." + Hostname.Apex(hostname) + ")."),
                L("In Cloudflare, add that TXT with the proxy grey (DNS only).", "https://dash.cloudflare.com/"),
                L("Rampart only probes a short list of selector names. A custom selector can still be valid.")
            },
            "robots.txt" => new[]
            {
                L("When to do this: you want crawlers to have a public robots.txt on this hostname."),
                L("When not to: you are happy with the default crawler behaviour. A missing file is hygiene, not a breach."),
                L("Publish a UTF-8 file at this URL.", "https://" + hostname + "/robots.txt"),
                L("A minimum file is:", "User-agent: *\nAllow: /"),
                L(nextJs ? "In Next.js, add public/robots.txt or app/robots.ts, then deploy." : "A static file at /robots.txt is enough.")
            },
            "Plugins" => new[]
            {
                L("When to do this: the homepage linked WordPress plugin directories."),
                L("When not to: you are not on WordPress, or those paths are leftover strings in CSS."),
                L("In wp-admin, open Plugins, delete anything you do not use, and update what remains."),
                L("A folder name on the homepage is not a CVE match. Rampart does not download plugin files.")
            },
            "Server disclosure" => new[]
            {
                L("When to do this: Server or X-Powered-By names a versioned stack you do not want public."),
                L("When not to: Server is only cloudflare. That is expected on an orange-cloud hostname and next.config.ts cannot remove it."),
                L("Turn off X-Powered-By in the app. In Next.js, poweredByHeader: false in next.config.ts."),
                L("Copyable next.config.ts:", "poweredByHeader: false"),
                L("Do not fight Cloudflare for the Server header. Transform Rules refuse Remove on Server.")
            },
            "Cross-Origin-Opener-Policy" => new[]
            {
                L("When to do this: you want this origin isolated from cross-origin popups."),
                L("When not to: a page must be opened as a cross-origin popup and share window.opener."),
                L(headerPlace),
                L("Send this header:", "Cross-Origin-Opener-Policy: same-origin")
            },
            "Cross-Origin-Resource-Policy" => new[]
            {
                L("When to do this: other origins should not load this response as a resource unless you intend it."),
                L("When not to: you intentionally embed this response on another origin."),
                L(headerPlace),
                L("Send this header:", "Cross-Origin-Resource-Policy: same-origin")
            },
            "Nameservers" => new[]
            {
                L("When to do this: NS lookup failed and you need to confirm who answers DNS for the zone."),
                L("When not to: a resolver omitted NS from the answer section. That is not proof the zone has no nameservers."),
                L("At the registrar, confirm the nameserver hostnames match the DNS host you intend."),
                L("If the zone should be on Cloudflare, the nameservers look like ada.ns.cloudflare.com.", "https://dash.cloudflare.com/")
            },
            "Known CVEs (advertised versions)" => new[]
            {
                L("When to do this: this card listed a catalogue match for an advertised version."),
                L("When not to: the card says advertised versions did not match. That is not clearance."),
                L("Upgrade the named product, or stop publishing the version in HTML generators and headers."),
                L("This program does not send exploit traffic.")
            },
            "Oracle PeopleSoft" => new[]
            {
                L("When to do this: this hostname advertised a public PeopleSoft portal or cookie. That is an internet-facing HR or campus system."),
                L("When not to: those paths 404 and the homepage does not name PeopleSoft. Then this card should be Present."),
                L("Install Oracle's Critical Patch Update that covers CVE-2026-35273 for PeopleTools 8.61 and 8.62. A firewall or WAF rule that only blocks one request shape is not the patch."),
                L("Oracle security alerts:", "https://www.oracle.com/security-alerts/"),
                L("CISA Known Exploited Vulnerabilities catalogue:", "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"),
                L("Take the portal off the public internet if it does not need to be there. Rampart does not send exploit traffic and cannot see whether the CPU is installed.")
            },
            "Private files" => new[]
            {
                L("When to do this: a path such as /.env or /.git/HEAD answered 200 with a short non-HTML body."),
                L("When not to: those paths 404 or 403, or they return a normal HTML 404 page."),
                L("Remove the file from the public document root. Rotate any secret that was in it."),
                L(vercel || nextJs
                    ? "Do not put .env in the public folder. Keep secrets in the host environment."
                    : "Keep secrets off the document root. A .env file belongs only on the server, not under the website folder."),
                L("Confirm /.env in a private window.", "https://" + hostname + "/.env"),
                L("Confirm /.git/HEAD the same way.", "https://" + hostname + "/.git/HEAD")
            },
            "WWW and apex" => new[]
            {
                L("When to do this: the sibling www or apex name redirected to http://, or HTTPS on that name failed while you use both names."),
                L("When not to: you only publish one name, or the sibling already redirects to https://" + hostname + "/."),
                L("In DNS, publish the sibling only if you intend people to type it."),
                L("On Vercel, attach both names and let the platform issue certificates.", "https://vercel.com/dashboard"),
                L("In Cloudflare, orange-cloud both names and set HTTPS to Full (strict).", "https://dash.cloudflare.com/")
            },
            "Homepage" => new[]
            {
                L("When to do this: GET / did not complete, so the homepage type was not recorded."),
                L("When not to: the homepage already answers in a browser."),
                L("Confirm https://" + hostname + "/ loads, then run Rampart again.", "https://" + hostname + "/")
            },
            "Address family" => new[]
            {
                L("When to do this: you intended dual-stack and only IPv4 or only IPv6 was published."),
                L("When not to: IPv4-only is common for a small site and is not a breach."),
                L("At the DNS host, add AAAA only if the origin actually answers on IPv6.")
            },
            "change-password" => new[]
            {
                L("When to do this: people can sign in on this hostname. Password managers use /.well-known/change-password to jump to the change-password screen."),
                L("When not to: a brochure site with no accounts. A 404 is then correct."),
                L("In next.config.ts redirects(), add a temporary (permanent: false) redirect:", "/.well-known/change-password -> /account/profile"),
                L("The destination must be the page where a signed-in person changes their password. Deploy, then open:", "https://" + hostname + "/.well-known/change-password")
            },
            "TLS" => new[]
            {
                L(cf
                    ? "In Cloudflare: SSL/TLS, then Edge Certificates. Set minimum TLS version to 1.2. Prefer TLS 1.3."
                    : "In the host or CDN SSL settings, allow TLS 1.2 and 1.3 only. Prefer ECDHE with AES-GCM or ChaCha20.")
            },
            _ => Array.Empty<FixLine>() // Ensure() fills a fallback when For() has no named guide.
        };
    }

    private static FixLine L(string text, string? copy = null) => new(text, copy);
}
