# Security policy

Site Check is a read-only checker for a hostname the operator confirms they may test.

## What the program is allowed to do

- Resolve public A and AAAA records for a parsed hostname (international names converted to ASCII)
- Open TLS 1.2 or 1.3 to a public address on port 443, with that hostname as SNI, IPv4 first, at most three addresses
- Send HTTP HEAD `/` and one GET `/` (body capped at 256 kilobytes, compressed bodies decompressed) with redirects disabled
- Send HTTP HEAD `/` on port 80 to the same public address
- Request TXT records for that hostname, its www parent, and `_dmarc.` plus the apex, only after `Hostname.IsSafeDnsName` accepts the name

## What the program must not do

- Contact loopback, RFC 1918, link-local, CGNAT, documentation, multicast, unique-local, discard, local-use NAT64, or IPv4 that is only reachable by embedding it in well-known NAT64 or 6to4
- Follow redirects
- Request `wp-admin`, plugin zip files, or version.php
- Guess passwords or send exploit traffic
- Upload reports
- Scrape the National Vulnerability Database live

Sockets are pinned to the resolved public address so a later DNS change cannot send the HTTP client onto a private network. TXT names cannot be used to inject resolver arguments; DnsClient is given a parsed name, not a shell string.

Unauthorized use of a computer system can be an offence in Canada (Criminal Code section 342.1) and under similar laws elsewhere.

## Reporting a problem in this program

Open a private GitHub issue on `jjames06/oli-site-check` or email Info@operationlockedin.com. Describe the hostname class (not a live exploit) and what you expected. Do not attach exploit proof-of-concept traffic.

## Keeping the CVE catalogue current

See `docs/cve-catalogue.md`. Add only sourced version ranges for products this program already fingerprints. Ship a new private release after tests pass. This is ongoing work. New CVEs will be added as they apply; absence of a match is not clearance.
