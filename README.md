# Rampart

A rampart is the defensive wall of a fortress. **Bastion** hardens a Windows PC you administer. **Rampart** inspects a public hostname you operate.

Rampart is a program from Jesse Mosier-Bowers, operating as Operation Locked In in Courtice, Ontario. The **recommended download is the Windows desktop program** (`Rampart.exe`). Testing copies for Linux and macOS are on the same GitHub release. The iPhone and Android copies are ready. They still need to be submitted to the App Store and Google Play. It reports what a **public hostname you operate** presents on HTTPS, what its certificate says, which security headers are present, whether SPF and DMARC exist, what the homepage and common public sign-in paths present, and whether advertised versions match a **local** CVE catalogue (Retire.js JavaScript ranges plus GitHub Advisory ranges for Next.js, rebuilt at each release). After the run, it lists **only the next steps that apply to that hostname**, with copyable how-to lines.

It is not a penetration test, not a red-team engagement, and not a guarantee. Paid website work still begins after a written quote.

## Licence

Desktop copies (Windows, and the Linux and macOS testing zips) are GNU GPLv3. The full legal text is in [`LICENSE`](LICENSE). When iPhone and Android applications are listed on the App Store and Google Play, those store binaries will carry an additional Apache License 2.0 grant in [`LICENSE.MOBILE`](LICENSE.MOBILE). The source stays available under GPLv3 as well.

Copyright and third-party attribution are in [`NOTICE`](NOTICE). DnsClient and Retire.js data remain Apache License 2.0; GitHub Advisory ranges for Next.js are CC BY 4.0. See [`THIRD-PARTY.md`](THIRD-PARTY.md). Why those licences were chosen: [`docs/licence.md`](docs/licence.md).

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

The GitHub release contains `Rampart.exe` (Windows), testing zips for Linux and macOS, and `LICENSE`, `NOTICE`, and `THIRD-PARTY.md`. On Windows, double-click the executable, tick the permission box, enter a hostname such as `www.example.com`, then choose **Check this hostname** or press Enter. Choose **Stop this check** or press Escape if you need to cancel.

To build from source on 64-bit Windows with the .NET 8 SDK:

```
dotnet test tests\SiteCheck.Tests\SiteCheck.Tests.csproj -c Release
dotnet publish src\SiteCheck.App\SiteCheck.App.csproj -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true -p:PublishTrimmed=false -p:EnableCompressionInSingleFile=true -o dist
```

`tools\publish.ps1` runs the tests, publishes, names the file `Rampart.exe`, and copies the licence files beside it.

## What this program will not do

It will not crawl every URL, follow redirects, post credentials, download plugin zip files, guess passwords, or send exploit traffic. It GETs a short allowlist of common public sign-in and admin URLs. It will not contact private or home-network addresses. A quiet report is not clearance.

## Version

This tree is Rampart 1.9.0. The User-Agent is `operation-locked-in-rampart/1.9.0`. Findings are grouped (needs attention first). Next steps name the stack they were written for. Lawful use: [docs/lawful-use.md](docs/lawful-use.md). Rebuild the local catalogue with `node tools\build-advisories.mjs` before a release that should pick up new Retire.js or GitHub Advisory ranges.
