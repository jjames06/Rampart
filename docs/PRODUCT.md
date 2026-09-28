# Honest assessment of Rampart 1.9.0

This is a product judgment, not marketing. Jesse asked for a final pass that says what the program actually is.

## What it is

Rampart is a **permissioned, read-only public-surface checker** for one hostname you operate, or for which you have written permission. After two consent boxes it resolves public DNS, opens TLS on port 443, reads a small allowlist of HTTPS paths, asks DNS for mail records, and prints findings with method, caveat, and copyable how-to for **this** hostname.

The Windows EXE is the finished public product. Linux and macOS zips are testing copies. iPhone and Android source exists and is not in stores.

## What it does well

- Lawful framing is in the UI, the saved report, and `docs/lawful-use.md`. Dual attestations. Criminal Code s. 342.1 named. Not legal advice.
- Invariants hold: GET/HEAD only, redirects off, sockets pinned to a remaining public IP, private ranges refused, no POST, no exploit payloads.
- How-to follows the advertised stack (Next.js, WordPress, Vercel, Cloudflare, or this hostname). Brochure hosts are not told to invent `/account/sign-in`.
- Every non-Present finding can open How to fix this. Admin that is correctly absent still explains itself.
- Local CVE catalogue (Retire.js + GitHub Advisory ranges + PHP EOL). Runtime does not query NVD.
- Internet-facing enterprise portals (PeopleSoft always; SharePoint, NetScaler, FortiGate, and peers only when advertised) name CISA Known Exploited CVEs as a **patch prompt**, not RCE proof.
- Three shells share `SiteCheck.Core`, so a card cannot exist on Windows only.

## What it is not

It is not Nessus, Qualys, Burp, or a pentest. It does not crawl, does not follow redirects, does not prove a host is unpatched, and does not replace Cloudflare, Microsoft 365, or a registrar. A quiet report is not a certificate.

Compared with commercial scanners it is **narrow and professionally finished in that lane**, not feature-rich across every protocol.

## Limits that stay on purpose

| Limit | Why it stays |
|---|---|
| Unsigned `Rampart.exe` (SmartScreen) | Authenticode costs money or SignPath (they refuse this class of tool). |
| No live NVD / CISA fetch | Would send advertised versions off-box. Catalogue is rebuilt at release. |
| No extra ports, no POST | Canadian Criminal Code s. 342.2 design choice. Defender hygiene, not an exploit kit. |
| No ToolPane / `wls-wsat` / `fgt_lang` probes | Those paths are how past exploits were sent. Presence of `/_layouts/15/start.aspx` is enough to prompt the patch. |
| Mobile not in stores | Source is ready. Submit is a separate operator job (`docs/stores/SUBMIT.md`). |
| Wiki remote | GitHub needs a first wiki page in the UI before `tools/publish-wiki.ps1` can sync. |
| Cannot prove RCE | A KEV name on an advertised portal is a prompt to confirm the vendor patch. |

## Final pass (this document's generation)

Unexpected parser or network faults in Core become **Could not complete** or a friendly `CheckException`. They do not take the window down. Phone, Linux/macOS, and Windows share the same Core, the same scopes, and the same consent strings.

Private-file GET now includes `.env.local`, `composer.json`, and `package.json`. HTML 200s are not treated as leaked secrets. OpenID Discovery is reported only when advertised. The local catalogue treats PHP 8.1 as end of life and names WordPress CVE-2026-87902 when a generator version is in range.

Authorization `MethodsUsed` / `MethodsRefused` name those methods, plus the exploit paths that are never requested. Saved reports stay honest.

Docs: this file, `what-is-checked.md`, `lawful-use.md`, `KNOWN-ISSUES.md`.

Site: `/rampart` lists every check group in the same order as the handbook, including enterprise portals, without a wall of scanner jargon.

No version bump. Public pin remains **1.9.0**.
