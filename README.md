# Site Check

Operation Locked In. A Windows program that reports what a **public hostname you operate** presents on HTTPS, its certificate, selected headers, SPF and DMARC, what the homepage advertises, and sourced CVE matches for those advertised versions. Next steps are listed only for what this run found.

It is not a penetration test. It is not a crawl. It does not contact private or home-network addresses.

## What it checks

| Observation | How it is gathered | What it does not mean |
|---|---|---|
| HTTPS answers | TLS to the first public address on port 443, then HTTP HEAD `/`. Redirects are not followed. | Other ports and paths are safe. |
| Certificate days and names | Leaf certificate from that handshake. Days are whole UTC days. Trust uses the Windows store. | The operator of the site is who they claim. Every subdomain is covered. |
| Selected headers | Response headers on that HEAD `/`. | Headers on other URLs. A missing header is not a breach. |
| SPF | Windows DNS TXT on the hostname, and the parent if the name starts with `www`. Only `v=spf1` counts. | Mail will pass. DKIM and DMARC are not checked. |

## Permission

Check only hostnames you operate or have written permission to check. Unauthorized use of a computer is an offence in Canada (Criminal Code s. 342.1) and similar laws elsewhere.

## Run

Build a single-file 64-bit Windows executable (no extra runtime install):

```
powershell -NoProfile -File tools\publish.ps1
```

The EXE is written to `dist\SiteCheck.exe`. Tick the permission box, enter a hostname such as `www.operationlockedin.com`, then check.

## Limits

- Public DNS hostnames only. No IP literals, localhost, or `.local` names.
- After DNS, private, loopback, link-local, and documentation addresses are refused.
- Time limit is 4.5 seconds per step.
- Results stay on this computer unless you copy or save the report.

## Licence

GNU General Public License version 3. See `LICENSE`.
