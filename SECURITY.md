# Security and lawful use

Site Check only looks at a hostname the operator types after confirming permission.

It must not be used to probe systems you do not operate. That can be an offence in Canada (Criminal Code s. 342.1) and under similar laws elsewhere.

The program:

- refuses IP literals, localhost, and home-network names
- refuses to connect after DNS if the address is private, loopback, link-local, CGNAT, or documentation space
- sends HTTP HEAD `/` and one GET `/` (body capped at 256 KB) with no other paths
- does not follow redirects
- does not crawl, brute-force plugins, hit wp-admin, or send exploit traffic
- CVE notes use a small sourced local catalogue against versions the host advertised, not live exploit probes
- does not store reports unless you copy or save them

Report suspected issues in this repository. Do not attach proof-of-concept attack traffic.
