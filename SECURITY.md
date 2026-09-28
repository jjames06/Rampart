# Security policy

Rampart is a read-only checker for a hostname the operator confirms they may test.

## What the program is allowed to do

- Resolve public A and AAAA records for a parsed hostname (international names converted to ASCII)
- Open TLS 1.2 or 1.3 to a public address on port 443, with that hostname as SNI, IPv4 first, at most three addresses
- Send HTTP HEAD `/` and one GET `/` (body capped at 256 kilobytes, compressed bodies decompressed) with redirects disabled
- Send HTTP HEAD `/` on port 80 to the same public address
- GET a short allowlist of common public account, sign-in, and admin URLs on that same address (body capped at 64 kilobytes, no passwords, redirects off)
- GET a short allowlist of private-file paths (`/.env`, `/.git/HEAD`, `/wp-config.php`, `/phpinfo.php`, `/server-status`) with the body capped at 8 kilobytes
- GET a short allowlist of public Oracle PeopleSoft portal paths (`/psp/`, `/psc/`, `/ps/`, `/PSIGW/`, `/PSEMHUB/`) with GET only and no exploit payload
- HEAD `/` on the www or apex sibling when that name has a public address
- Request TXT records for that hostname, its www parent, and `_dmarc.` plus the apex, only after `Hostname.IsSafeDnsName` accepts the name

## What the program must not do

- Contact loopback, RFC 1918, link-local, CGNAT, documentation, multicast, unique-local, discard, local-use NAT64, or IPv4 that is only reachable by embedding it in well-known NAT64 or 6to4
- Follow redirects
- Request plugin zip files, xmlrpc.php, or version.php
- Crawl, follow redirects, or POST credentials
- Guess passwords or send exploit traffic
- Upload reports
- Scrape the National Vulnerability Database live

Sockets are pinned to the resolved public address so a later DNS change cannot send the HTTP client onto a private network. TXT names cannot be used to inject resolver arguments; DnsClient is given a parsed name, not a shell string.

Unauthorized use of a computer system can be an offence in Canada (Criminal Code section 342.1) and under similar laws elsewhere. See `docs/lawful-use.md`. Operation Locked In does not authorize use without the operator's permission. This program does not send exploit traffic.

## Reporting a problem in this program

Open a private GitHub issue on `jjames06/oli-site-check` or email Info@operationlockedin.com. Describe the hostname class (not a live exploit) and what you expected. Do not attach exploit proof-of-concept traffic.

## Keeping the CVE catalogue current

See `docs/cve-catalogue.md`. Rebuild `data/advisories.json` with `node tools\build-advisories.mjs`, run tests, and ship a new private release. Matching stays local. This program does not call Cloudflare Radar, NVD, or GitHub at run time.
