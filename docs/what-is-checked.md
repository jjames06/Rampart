# What is checked, and how

Every observation in Site Check is paired with a method and a caveat. If a method cannot run, the state is **Could not complete**, not **Not found**. Next steps are generated only from findings that are not **Present**, with one exception: incomplete header reads (because HTTPS never finished) do not invent a list of header fixes on top of the HTTPS failure.

## Addresses

The hostname is parsed to a DNS name. IP literals, localhost, ports, and home-network suffixes are refused. International names are converted to ASCII (punycode). Userinfo in a pasted URL is discarded and never sent.

Windows then resolves A and AAAA records. Loopback, RFC 1918, link-local, CGNAT (100.64.0.0/10), documentation prefixes, multicast, IPv6 unique-local, the IPv6 discard prefix, local-use NAT64, and IPv4 that is only reachable by embedding it in well-known NAT64 or 6to4 are dropped. Remaining addresses are treated as public Internet addresses. IPv4 is tried before IPv6 for the TLS handshake. Up to three public addresses are tried if the first handshake does not complete.

The program never connects to an address that failed that filter. HTTP and TLS are pinned to the chosen address so a later DNS change cannot redirect the socket onto a private network.

## HTTPS and the homepage

A TLS connection is opened to the working public address on port 443, using the typed hostname as SNI. The client offers TLS 1.2 and TLS 1.3 only. The leaf certificate is read from that handshake. Trust is evaluated against the Windows certificate store; the connection still records the certificate if trust fails, and the report says so.

HTTP HEAD `/` is sent on that same address with no body and with redirects disabled. HTTP GET `/` is sent the same way. Compressed responses (gzip, deflate, Brotli) are decompressed before HTML is read, so fingerprints are taken from real markup. The body is truncated at 256 kilobytes. No other path is requested.

Port 80 receives a single HEAD `/` on the same public address, only to see whether HTTP redirects to HTTPS.

An **Authorized public-surface assessment** also requests `/.well-known/security.txt`, `/robots.txt`, and `/.well-known/change-password` on the typed hostname (capped, no redirect), plus `/.well-known/mta-sts.txt` on the RFC 8461 policy host `mta-sts.` plus the apex. It asks DNS for CAA on the hostname and apex, TXT on common DKIM selectors under `_domainkey`, DS and DNSKEY on the apex, MTA-STS (`_mta-sts.`), BIMI (`default._bimi.`), and SMTP TLS reporting (`_smtp._tls.`). Those names must still pass `IsSafeDnsName`. The `mta-sts` subdomain is resolved and contacted only if it has a public address.

## Mail records

TXT records are requested through the system DNS resolver (DnsClient) for the hostname and, when the name starts with `www`, for the parent. Only records that begin with `v=spf1` count as SPF. An SPF `all` mechanism of `+all`, `all`, or `?all` is **Needs attention**. DMARC is requested on `_dmarc.` plus the apex. Only `v=DMARC1` counts. Include chains are not evaluated. A DMARC record with `p=none` is reported as **Needs attention** (monitor-only), not as a finished policy.

MX and NS are requested on the apex. The mail server itself is not contacted. A null MX (preference 0 and a dot) is recorded as a published refusal to accept mail.

DNS names passed to the resolver are a parsed hostname, `_dmarc.` plus a parsed apex, `_mta-sts.` plus a parsed apex, `_smtp._tls.` plus a parsed apex, or a selector under `_domainkey` or `_bimi` plus a parsed apex. Arbitrary strings are not sent.

## TLS details

The handshake records the protocol, the negotiated cipher suite, ALPN, and the leaf public-key algorithm and size. TLS 1.0/1.1, CBC/RC4/3DES, RSA key-exchange without forward secrecy, and RSA keys shorter than 2048 bits are **Needs attention**. This is the suite used for this one connection, not a scan of every suite the server still offers.

## Headers and cookies

The program looks for Strict-Transport-Security, Content-Security-Policy, X-Content-Type-Options, X-Frame-Options (or CSP `frame-ancestors`), Referrer-Policy, Permissions-Policy, Cross-Origin-Opener-Policy, Cross-Origin-Resource-Policy, and Cross-Origin-Embedder-Policy. HSTS with `max-age` at or below zero, or shorter than 180 days, is **Needs attention**. Access-Control-Allow-Origin `*` on the homepage is **Needs attention**. A non-zero X-XSS-Protection value is **Needs attention**; omitting that header is correct.

Each `Set-Cookie` value is read as its own cookie. Expires dates contain commas, so cookies are never split on commas. HttpOnly and Secure are the required flags on this check. Cookies on other paths are not shown.

Homepage HTML is also searched for mixed `http://` resources, third-party scripts without integrity, `target=_blank` without `rel=noopener`, forms that post to `http://`, and an `http://` canonical URL.

## Fingerprints and CVEs

Product names and versions are taken only from:

- `Server` and `X-Powered-By`
- Vercel or Cloudflare headers if present
- HTML `meta name="generator"`
- jQuery version strings in homepage script URLs
- WordPress plugin directory names already present in homepage URLs

Plugin files, `readme.html`, and `wp-admin` are not fetched.

CVE matching uses the embedded file `data/advisories.json` (Retire.js JavaScript ranges, GitHub Advisory ranges for Next.js, and PHP end of life). See `docs/cve-catalogue.md`. Homepage script URLs are compared with Retire.js extractors. Plugin files are not downloaded. NVD is not queried live.

A match is a prompt to upgrade. It is not proof of exploitability. Absence of a match is not clearance.

## Next steps

`Advice.Build` emits a step only when the related finding is not **Present**, or when certificate days are under 45, or when HTTP on port 80 does not redirect to HTTPS, or when the catalogue matched, or when DMARC is monitor-only. WordPress and Next.js wording is chosen only if that stack was advertised on this run. Incomplete header findings do not generate header fixes; they wait until HTTPS works.
