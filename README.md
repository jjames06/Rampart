# Barbican

A barbican is the outer gatehouse of a fortress: the place that inspects the public approach before anyone reaches the keep. **Bastion** hardens a Windows PC you administer. **Barbican** inspects a public hostname you operate.

Barbican is a Windows program from Jesse Mosier-Bowers, operating as Operation Locked In in Courtice, Ontario. It reports what a **public hostname you operate** presents on HTTPS, what its certificate says, which security headers are present, whether SPF and DMARC exist, what the homepage advertises, and whether those advertised versions match a **local** CVE catalogue (Retire.js JavaScript ranges plus GitHub Advisory ranges for Next.js, rebuilt at each release). After the run, it lists **only the next steps that apply to that hostname**.

It is not a penetration test, not a red-team engagement, and not a guarantee. Paid website work still begins after a written quote.

## Licence

GNU General Public License version 3, or any later version. The full legal text is in [`LICENSE`](LICENSE). Copyright and third-party attribution are in [`NOTICE`](NOTICE). DnsClient and Retire.js data remain Apache License 2.0; GitHub Advisory ranges for Next.js are CC BY 4.0. See [`THIRD-PARTY.md`](THIRD-PARTY.md). Why GPLv3 was chosen: [`docs/licence.md`](docs/licence.md).

GPLv3 matches Bastion: this is free software you can run, study, and share under the same copyleft. It is not a paid SKU.

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
- Security policy: [SECURITY.md](SECURITY.md)

## Run a release build

The GitHub release contains `Barbican.exe` together with `LICENSE`, `NOTICE`, and `THIRD-PARTY.md`. Double-click the executable, tick the permission box, enter a hostname such as `www.example.com`, then choose **Check this hostname** or press Enter. Choose **Stop this check** or press Escape if you need to cancel.

To build from source on 64-bit Windows with the .NET 8 SDK:

```
dotnet test tests\SiteCheck.Tests\SiteCheck.Tests.csproj -c Release
dotnet publish src\SiteCheck.App\SiteCheck.App.csproj -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true -p:PublishTrimmed=false -p:EnableCompressionInSingleFile=true -o dist
```

`tools\publish.ps1` runs the tests, publishes, names the file `SiteCheck.exe`, and copies the licence files beside it.

## What this program will not do

It will not crawl every URL, follow redirects, open administrative paths, download plugin files, guess passwords, or send exploit traffic. It will not contact private or home-network addresses. A quiet report is not clearance.

## Version

This tree is Barbican 1.7.1. The User-Agent is `operation-locked-in-barbican/1.7.1`. Findings are grouped (needs attention first). Next steps name the stack they were written for. Lawful use: [docs/lawful-use.md](docs/lawful-use.md). Rebuild the local catalogue with `node tools\build-advisories.mjs` before a release that should pick up new Retire.js or GitHub Advisory ranges.
