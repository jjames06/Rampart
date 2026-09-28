# Lawful use of Rampart

This page is product wording for Rampart, a Windows program from Jesse Mosier-Bowers, operating as Operation Locked In in Courtice, Ontario. **It is not legal advice.** If you need advice about a specific engagement, speak to a lawyer licensed in the place where the system lives.

Rampart exists to help a person **protect a public website they operate**, or a public website for which they have **written permission**. Operation Locked In does not authorize, condone, or accept any other use.

## What this program is

Rampart is a **read-only public-surface assessment**. After you attest permission, it resolves public Internet addresses, reads TLS, requests a small set of public HTTPS paths, and asks DNS for mail and certificate-authority records. It then lists only the next steps that apply to what that run found.

Every run also GETs a short allowlist of common public account, sign-in, and admin URLs on the same hostname (for example `/account/sign-in` and `/wp-login.php`). Redirects are not followed. Passwords are never sent. That is how Rampart notices a login form that posts to `http://`, a login page that can be framed, or an admin URL that looks like an open dashboard.

The **Authorized public-surface assessment** option adds RFC public files (`/.well-known/security.txt`, `/robots.txt`, `/.well-known/change-password`) on the typed hostname, the MTA-STS policy file on `mta-sts.` plus the apex, and extra DNS (CAA, DKIM selectors, DNSSEC, MTA-STS, BIMI, TLS-RPT). Those files are published for the public to read. The program still does not crawl, follow redirects, or send a request body.

## What this program is not

A professional red-team engagement includes attempting to exploit, to see whether a control actually fails. Rampart does **not** do that work. Shipping exploit payloads would be dishonest for a defender's hygiene tool, and it would move the program toward a device designed primarily for unauthorized use, which Canadian criminal law treats separately (Criminal Code section 342.2).

This program does not:

- send exploit traffic or proof-of-concept attack payloads
- guess passwords or brute-force logins
- scan ports other than 443 and a single HEAD on 80
- follow redirects or crawl the site
- post credentials, guess passwords, or brute-force a login form
- request `xmlrpc.php`, `version.php`, or plugin zip files
- contact private or home-network addresses
- upload your report

A quiet report is not a certificate that the site is safe. Paid website work from Operation Locked In still begins after a written quote.

## Authorization you must have

You may run Rampart only if **one** of these is true:

1. You operate the hostname (you are the registrant, the hosting customer, or the person who controls DNS and HTTPS for that name).
2. You have **written permission** from that operator, with a scope that covers this kind of read-only check.

Verbal "go ahead" from a stranger on the internet is not enough. A bug-bounty program is permission only inside that program's published scope and rules.

Ticking the boxes in the program records **your** attestation. It is not a licence from Operation Locked In to test other people's systems. Operation Locked In does not authorize, condone, or accept use against a hostname without the operator's permission.

## Canadian criminal law (plain language)

The official text is [Criminal Code section 342.1](https://laws-lois.justice.gc.ca/eng/acts/C-46/section-342.1.html) (Justice Laws website, current to 3 September 2026 at the time of writing). In summary, it is an offence to obtain a computer service **fraudulently and without colour of right**. Colour of right is an honest belief in a legal right to do the act. Written permission from the operator is how a defender or an authorized tester shows that belief.

Canadian commentary used in professional cybercrime surveys states that **unsolicited penetration testing** (exploiting a system without the owner's permission to find weaknesses) may be an offence under section 342.1.

Section 342.2 concerns making or distributing a device that is designed or adapted **primarily** to commit an offence under 342.1 or mischief in relation to data, knowing it is intended for that use. Rampart is designed as a defender's authorized assessment tool. That design choice is deliberate.

This summary is not a complete statement of the law and is not legal advice.

## Similar laws elsewhere

Other countries have unauthorized-access offences (for example, the United States Computer Fraud and Abuse Act, 18 U.S.C. § 1030, and the United Kingdom Computer Misuse Act 1990). If the hostname, the operator, or you are outside Ontario, those laws may apply as well. Obtain permission that is valid in the relevant place before you run the program.

## How professional tools word the same duty

PortSwigger's Burp Suite Community licence requires the licensee **to obtain all necessary authorisations from system owners prior to using the Software**. Rampart uses the same idea in its own words: written permission from the operator, or you are the operator.

Cloudflare's published scan policy for customers testing their own zones likewise limits scans to identifying the presence of weaknesses **without attempting to actively exploit**. Rampart follows that line even though it is not a Cloudflare product.

## How the program records permission

Both boxes must be ticked before a check will run:

1. You operate the hostname, or you have written permission from the person who operates it.
2. You will not use the program against a hostname you are not authorized to check, and you understand that unauthorized use can be a criminal offence.

The saved report repeats those attestations, the time in UTC, the scope name, the methods used, and the methods refused. Keep the written permission (email, letter, or contract clause) with that report. The tick boxes do not replace that document.

## If you are hiring Operation Locked In

Please call or email. I will confirm what the work will cost before I begin. An authorized assessment with Rampart can sit inside a quoted website or IT job. It does not replace a scoped penetration test. If you need intrusive testing, that is a separate written engagement with a defined scope, and it is not this executable.
