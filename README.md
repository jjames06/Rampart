# Rampart

**Read-only public-surface assessment of a hostname you operate**

Version **1.9.0**

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](LICENSE)
[![.NET 8](https://img.shields.io/badge/.NET-8.0-512BD4)](#run-a-release-build)

<p align="center">
  <a href="https://www.operationlockedin.com/rampart"><strong>Official site</strong></a> ·
  <a href="https://www.operationlockedin.com/rampart/download"><strong>Download</strong></a> ·
  <a href="docs/how-to-use.md"><strong>How to use</strong></a> ·
  <a href="docs/wiki/Home.md"><strong>Handbook</strong></a> ·
  <a href="https://github.com/jjames06/oli-site-check/releases/latest"><strong>Latest release</strong></a> ·
  <a href="https://github.com/jjames06/oli-site-check/issues"><strong>Issues</strong></a> ·
  <a href="SECURITY.md"><strong>Security</strong></a>
</p>

Rampart is a program from Jesse Mosier-Bowers, operating as Operation Locked In in Courtice, Ontario. **Bastion** hardens a Windows PC you administer. **Rampart** inspects a public hostname you operate.

The **recommended download is the Windows desktop program** (`Rampart.exe`). Testing copies for Linux and macOS are on the same GitHub release. The iPhone and Android copies are ready. They still need to be submitted to the App Store and Google Play.

It reports what that hostname presents on HTTPS: certificate and TLS, security headers, cookies, homepage markup, public edge (Cloudflare and similar), mail records, common public sign-in and admin paths, paths that should not publish private files, the www and apex pair, advertised versions against a **local** CVE catalogue, and internet-facing enterprise portals (SharePoint, NetScaler, FortiGate, PeopleSoft, and peers) when those products are advertised. After the run it lists **only the next steps that apply to that hostname**, with copyable how-to lines. If an enterprise portal is on the public internet it names the CISA Known Exploited CVE as a patch to confirm. It does not send exploit traffic.

It is not a penetration test, not a red-team engagement, and not a guarantee. Paid website work still begins after a written quote.

**Further reading in this repo**

| Document | Topic |
|----------|--------|
| [docs/CODEMAP.md](docs/CODEMAP.md) | File-by-file map. Start here if you did not write this code. Every source file has a matching header. |
| [docs/PRODUCT.md](docs/PRODUCT.md) | Honest product judgment: what 1.9.0 is, what it will not become |
| [Official site](https://www.operationlockedin.com/rampart) | Product home and download |
| [docs/how-to-use.md](docs/how-to-use.md) | Permission boxes, states, How to fix this |
| [docs/what-is-checked.md](docs/what-is-checked.md) | Every check and how it was gathered |
| [docs/lawful-use.md](docs/lawful-use.md) | Written permission, Criminal Code s. 342.1 |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Core plus Windows, Linux/macOS, and phone shells |
| [docs/KNOWN-ISSUES.md](docs/KNOWN-ISSUES.md) | SmartScreen, wiki, testing zips, stores |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Issues and pull requests |
| [SECURITY.md](SECURITY.md) | What the program may contact, how to report a defect |
| [docs/encryption.md](docs/encryption.md) | Licence versus TLS versus optional Windows report protection |

## Licence

Desktop copies (Windows, and the Linux and macOS testing zips) are GNU GPLv3. The full legal text is in [`LICENSE`](LICENSE). When iPhone and Android applications are listed on the App Store and Google Play, those store binaries will carry an additional Apache License 2.0 grant in [`LICENSE.MOBILE`](LICENSE.MOBILE). The source stays available under GPLv3 as well.

Copyright and third-party attribution are in [`NOTICE`](NOTICE). DnsClient and Retire.js data remain Apache License 2.0; GitHub Advisory ranges for Next.js, React, Vue, Nuxt, jQuery, Bootstrap, and WordPress core are CC BY 4.0. See [`THIRD-PARTY.md`](THIRD-PARTY.md). Why those licences were chosen: [`docs/licence.md`](docs/licence.md).

There is no warranty. The window footer and **Licence and warranty** state that in the program itself.

## Lawful use

Check only hostnames you operate or for which you have written permission. Unauthorized use of a computer system can be an offence in Canada (Criminal Code section 342.1) and under similar laws elsewhere.

## Start here

- Lawful use: [docs/lawful-use.md](docs/lawful-use.md)
- Tutorial: [docs/how-to-use.md](docs/how-to-use.md)
- What is checked, and how: [docs/what-is-checked.md](docs/what-is-checked.md)
- Privacy: [docs/privacy.md](docs/privacy.md)
- CVE catalogue: [docs/cve-catalogue.md](docs/cve-catalogue.md)
- Building the executable: [docs/building.md](docs/building.md)
- Licence: [docs/licence.md](docs/licence.md)
- Extra-desktop testing copies and store work: [docs/stores/SUBMIT.md](docs/stores/SUBMIT.md)
- Security policy: [SECURITY.md](SECURITY.md)

## Run a release build

The GitHub release contains `Rampart.exe` (Windows), testing zips for Linux and macOS, and `LICENSE`, `NOTICE`, and `THIRD-PARTY.md`. On Windows, double-click the executable. If Microsoft Defender SmartScreen shows **Windows protected your PC**, that is an unsigned-publisher warning, not a malware finding. Choose **More info**, then **Run anyway**, for a copy from this repository. Then tick the permission box, enter a hostname such as `www.example.com`, and choose **Check this hostname** or press Enter. Choose **Stop this check** or press Escape if you need to cancel.

To build from source on 64-bit Windows with the .NET 8 SDK:

```
dotnet test tests\SiteCheck.Tests\SiteCheck.Tests.csproj -c Release
dotnet publish src\SiteCheck.App\SiteCheck.App.csproj -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true -p:PublishTrimmed=false -p:EnableCompressionInSingleFile=true -o dist
```

`tools\publish.ps1` runs the tests, publishes, names the file `Rampart.exe`, Authenticode-signs it when a certificate is present, writes SHA256SUMS, and copies the licence files beside it. SmartScreen notes: [docs/signing.md](docs/signing.md).

## What this program will not do

It will not crawl every URL, follow redirects, post credentials, download plugin zip files, guess passwords, or send exploit traffic. It GETs a short allowlist of common public sign-in, admin, and private-file paths. It will not contact private or home-network addresses. A quiet report is not clearance.

## Version

This tree is Rampart 1.9.0. The User-Agent is `operation-locked-in-rampart/1.9.0`. Findings are grouped (needs attention first). Next steps name the stack they were written for. Lawful use: [docs/lawful-use.md](docs/lawful-use.md). Rebuild the local catalogue with `node tools\build-advisories.mjs` before a release that should pick up new Retire.js or GitHub Advisory ranges.
