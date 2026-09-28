# Rampart code map

Read this first if you did not write this code. Every first-party source file starts with a `CODEMAP FILE:` header: **Role**, **Called by**, **Calls**, **Invariants**, and how this repo sits next to Bastion and the practice site.

Generated JSON (`data/advisories.json`) and `bin/`/`obj/`/`dist/` are not commented. Rebuild the catalogue; do not hand-edit it.

## What the program is

Rampart is a **read-only** public-surface checker. After two permission boxes, it talks to **one public hostname** on DNS, TCP 443, and one HEAD on port 80. It never POSTs, never follows redirects, never contacts private addresses, never sends exploit traffic.

**Bastion** hardens the PC you administer. **Rampart** inspects a hostname you operate. The practice site (`bastion-web`) is the public storefront that links both downloads. Kits (`oli-web-kits`) are client brochures that should already pass Rampart's origin probes (`blocked-paths.ts` 404s `/.env`, `/.git/HEAD`, `/admin`, and friends).

Public version pin: **1.9.0**. User-Agent: `operation-locked-in-rampart/1.9.0`. Catalogue rebuilds replace the v1.9.0 asset; do not bump the number unless you intend a numbered release.

## Solution layout

```
SiteCheck.Core     shared checker (this is the product)
SiteCheck.App      Windows WPF  → Rampart.exe          (recommended download)
SiteCheck.Desktop  Avalonia     → Linux/macOS testing zips
SiteCheck.Maui     MAUI         → iPhone/Android (ready to submit, not in stores yet)
```

All three shells call `Checker.RunAsync` then `FindingGuide` so a card cannot exist on Windows only. Desktop licence is GNU GPLv3. Store binaries add Apache-2.0 (`LICENSE.MOBILE`).

## Run graph (one check)

1. UI (`MainWindow` / `MainPage`) requires both consent checkboxes (strings from `LawfulUse`).
2. `Hostname.Parse` rejects IPs, localhost, home suffixes, control characters.
3. `PrivateIp` filters resolved A/AAAA. `Checker` pins sockets to a remaining public address.
4. TLS handshake (`ReadCertificateAsync`) records the leaf even if Windows does not fully trust it.
5. Parallel: HTTPS HEAD/GET `/`, homepage body (256 KB cap), SPF/DMARC/MX/NS/CAA, port 80 HEAD.
6. `Fingerprint` + `AdvisoryDb` (embedded `data/advisories.json`, built by `tools/build-advisories.mjs`).
7. Allowlisted GETs: sign-in, admin, private files, PeopleSoft portal paths, other CISA-KEV enterprise portal paths (SharePoint, NetScaler, FortiGate, and peers), www/apex HEAD.
8. Authorized scope adds RFC files and extra DNS.
9. `Advice.Build` + `FixGuides.Ensure` attach how-to **only** for work that applies to this stack.
10. UI groups by `FindingState`. Save may DPAPI-protect on Windows (`ReportProtect`).

`FindingState.Present` includes "correctly absent" (no `/admin` on a brochure). `Incomplete` is neither all-clear nor a confirmed gap. PeopleSoft names CVE-2026-35273 as a **patch prompt**, not RCE proof.

## How to read a file

Open any `.cs` / `.xaml` / tool. The top of the file answers: what is this, who calls it, what it may call, what you must not break. Type-level `/// <summary>` comments (where they exist) go deeper. Tests name the invariant they lock.

## File index

| File | Role |
|------|------|
| `src/SiteCheck.App/App.xaml` | WPF Application resources: Operation Locked In navy/teal/amber palette. StartupUri MainWindow.xaml. |
| `src/SiteCheck.App/App.xaml.cs` | WPF Application subclass. DispatcherUnhandledException so a failed check does not vanish the window. |
| `src/SiteCheck.App/AssemblyInfo.cs` | WPF ThemeInfo: generic dictionary in this assembly, no theme-specific dictionaries. |
| `src/SiteCheck.App/MainWindow.xaml` | Windows desktop layout: consent boxes, hostname, scope, findings grouped by FindingState, How to fix this expander, save/copy. |
| `src/SiteCheck.App/MainWindow.xaml.cs` | Windows WPF shell for Rampart.exe. Consent → Checker.RunAsync → FindingGuide → ReportProtect on save. |
| `src/SiteCheck.App/ResponsiveCardPanel.cs` | Wrap panel for finding cards so the window reflows instead of a single tall stack. |
| `src/SiteCheck.App/SiteCheck.App.csproj` | WinExe net8.0-windows WPF. Version properties pinned 1.9.0. Embeds LICENSE and lawful-use.md. ApplicationManifest + icon. |
| `src/SiteCheck.App/app.manifest` | Win32 application manifest (dpiAwareness, requestedExecutionLevel asinvoker). Rampart does not require admin. |
| `src/SiteCheck.Core/Advice.cs` | Decide which findings get a NextStep. Incomplete HTTPS does not invent header chores. Wording follows advertised stack (Next.js, WordPress, Vercel, Cloudflare). |
| `src/SiteCheck.Core/AdvisoryDb.cs` | Load embedded data/advisories.json and match advertised product versions against ranges. |
| `src/SiteCheck.Core/Checker.cs` | Orchestrator for one permissioned run. Parse host, resolve public A/AAAA, pin sockets, TLS leaf, parallel HEAD/GET and DNS, fingerprint, catalogue match, allowlisted extra GETs, then Advice + FixGuides. |
| `src/SiteCheck.Core/CveCatalog.cs` | Thin facade over AdvisoryDb so call sites read as 'catalogue' not 'json file'. |
| `src/SiteCheck.Core/DnsTxt.cs` | SPF, DMARC, MX, NS, CAA, DNSSEC DS/RRSIG via DnsClient (UDP/TCP 53 to public resolvers). |
| `src/SiteCheck.Core/EdgeSurface.cs` | Classify Cloudflare (NS vs proxied/CF-Ray) vs Vercel vs origin vs other CDN. FixGuides uses this so how-to names the right dashboard. |
| `src/SiteCheck.Core/ExposedSurface.cs` | Allowlisted GET of paths that should 404: /.env, /.git/HEAD, phpinfo, wp-config, server-status, etc. Kits bake these 404s in @oli/site-kit blocked-paths. |
| `src/SiteCheck.Core/FindingGuide.cs` | Single place for 'does this card show How to fix this'. All shells must call this so a copy change cannot land on Windows only. |
| `src/SiteCheck.Core/Fingerprint.cs` | Product/version from Server/X-Powered-By/generator meta/script comments. Feeds AdvisoryDb. Plugin slugs are not versions. |
| `src/SiteCheck.Core/FixGuides.cs` | Copyable how-to lines and when-to/when-not notes. Ensure() attaches a panel to every non-Present finding so Admin Not-found still explains itself. |
| `src/SiteCheck.Core/HeaderFacts.cs` | Parse HSTS, CSP, cookies, CORS, X-Frame-Options and friends from response headers into Findings. |
| `src/SiteCheck.Core/HostPair.cs` | HEAD www vs apex so a split (one live, one parking, mismatched cert) is visible. |
| `src/SiteCheck.Core/Hostname.cs` | Parse operator input into a DNS hostname. Strips scheme/path, lowercases, rejects IPs, localhost, home suffixes, ports, control characters. |
| `src/SiteCheck.Core/HtmlSurface.cs` | Homepage HTML (capped) for mixed content, missing SRI on third-party scripts, target=_blank without rel, form action, canonical host. |
| `src/SiteCheck.Core/LawfulUse.cs` | Consent checkbox strings and CheckScope names shown in every shell. Criminal Code s. 342.1 / 342.2 framing lives in docs/lawful-use.md; this file is UI copy only. |
| `src/SiteCheck.Core/LoginSurface.cs` | Allowlisted GET of common public sign-in and admin paths. Brochure sites without /admin are Present (correctly absent), not Attention. |
| `src/SiteCheck.Core/Models.cs` | Shared types for one run: FindingState, Finding, FixLine, NextStep, EdgeProfile, StackHint, CheckReport, authorization record. |
| `src/SiteCheck.Core/PeopleSoftSurface.cs` | GET-only detection of public PeopleSoft portal paths (/psp/, /psc/, /ps/, /PSIGW/, /PSEMHUB/) plus PSJSESSIONID. Names CVE-2026-35273 as a patch prompt, not RCE proof. |
| `src/SiteCheck.Core/EnterpriseSurface.cs` | Table of other internet-facing enterprise portals. Attention cards only when advertised. CISA KEV CVE as patch prompt. |
| `src/SiteCheck.Core/PrivateIp.cs` | Classify resolved addresses: RFC1918, loopback, link-local, CGNAT 100.64/10, NAT64, 6to4, unique-local, documentation ranges. |
| `src/SiteCheck.Core/ReportJson.cs` | Machine-readable sibling of ReportText for operators who archive JSON. |
| `src/SiteCheck.Core/ReportProtect.cs` | Optional Windows DPAPI wrap of a saved report (CurrentUser). No-op on Linux/macOS/mobile. |
| `src/SiteCheck.Core/ReportText.cs` | UTF-8 plaintext report for clipboard and Save. Includes findings, next steps, limits, authorization. |
| `src/SiteCheck.Core/SiteCheck.Core.csproj` | Shared class library. net8.0, DnsClient, ProtectedData, embedded advisories.json. |
| `src/SiteCheck.Core/TlsFacts.cs` | Human labels for SslProtocols and leaf-certificate observations (expiry window, SAN vs hostname). |
| `src/SiteCheck.Core/VersionCmp.cs` | Dotted version compare for advisory ranges (including x wildcards from Retire.js). |
| `src/SiteCheck.Desktop/App.axaml` | Avalonia application XAML. Linux/macOS testing zips. Same palette intent as WPF App.xaml. |
| `src/SiteCheck.Desktop/App.axaml.cs` | Avalonia application host. Creates MainWindow. |
| `src/SiteCheck.Desktop/MainWindow.axaml` | Avalonia layout mirroring WPF: consent, findings, how-to, save. |
| `src/SiteCheck.Desktop/MainWindow.axaml.cs` | Avalonia code-behind. Same Core call graph as WPF. |
| `src/SiteCheck.Desktop/Program.cs` | Avalonia process entry. [STAThread] required on Windows if this project is ever run there. |
| `src/SiteCheck.Desktop/ResponsiveCardPanel.cs` | Avalonia wrap panel sibling of the WPF ResponsiveCardPanel. |
| `src/SiteCheck.Desktop/SiteCheck.Desktop.csproj` | Avalonia desktop csproj. Publishes linux-x64, osx-x64, osx-arm64 zips via tools/publish.ps1. |
| `src/SiteCheck.Desktop/app.manifest` | Win32 application manifest (dpiAwareness, requestedExecutionLevel asinvoker). Rampart does not require admin. |
| `src/SiteCheck.Maui/App.xaml` | MAUI Application XAML. Navigation chrome only. |
| `src/SiteCheck.Maui/App.xaml.cs` | MAUI Application. Sets MainPage. |
| `src/SiteCheck.Maui/MainPage.xaml` | Phone layout: consent, hostname, findings, how-to, share. |
| `src/SiteCheck.Maui/MainPage.xaml.cs` | MAUI shell. Same Core as WPF. Share sheet instead of Win32 SaveFileDialog. |
| `src/SiteCheck.Maui/MauiProgram.cs` | MAUI host builder. Fonts and the single MainPage. |
| `src/SiteCheck.Maui/Platforms/Android/MainActivity.cs` | Android launcher activity. Required MAUI host; no extra logic. |
| `src/SiteCheck.Maui/Platforms/Android/MainApplication.cs` | Android Application subclass. Boots MauiProgram. |
| `src/SiteCheck.Maui/Platforms/iOS/AppDelegate.cs` | iOS app delegate. Boots MauiProgram. Store licence is LICENSE.MOBILE. |
| `src/SiteCheck.Maui/Platforms/iOS/Program.cs` | iOS process entry (UIApplication.Main). |
| `src/SiteCheck.Maui/SiteCheck.Maui.csproj` | MAUI csproj for iOS/Android. Additional Apache-2.0 for store distribution. |
| `tests/SiteCheck.Tests/AdviceTests.cs` | Locks Advice: no header chores on Incomplete HTTPS; stack-specific next steps; Present admin is not a chore. |
| `tests/SiteCheck.Tests/AdvisoryTests.cs` | Locks catalogue matching: version in range hits, unknown product misses, plugin slug is not a version. |
| `tests/SiteCheck.Tests/EdgeSurfaceTests.cs` | Locks Cloudflare NS vs CF-Ray vs Vercel vs origin classification. |
| `tests/SiteCheck.Tests/ExposedSurfaceTests.cs` | Locks private-file path allowlist and 200-vs-404 interpretation. |
| `tests/SiteCheck.Tests/HeaderFactsTests.cs` | Locks HSTS/CSP/cookie parsers including includeSubDomains observation. |
| `tests/SiteCheck.Tests/HostnameTests.cs` | Locks accept/reject table: public DNS names in, IPs/localhost/home suffixes/ports out. |
| `tests/SiteCheck.Tests/HtmlSurfaceTests.cs` | Locks mixed-content / SRI / tabnabbing / form-action observations on capped HTML. |
| `tests/SiteCheck.Tests/LoginSurfaceTests.cs` | Locks sign-in/admin allowlist and Present-when-absent for brochure sites. |
| `tests/SiteCheck.Tests/PeopleSoftSurfaceTests.cs` | Locks PeopleSoft path list and CVE-2026-35273 prompt-only wording (not RCE proof). |
| `tests/SiteCheck.Tests/EnterpriseSurfaceTests.cs` | Locks brochure silence, SharePoint/NetScaler/Magento prompts, and omitted exploit paths. |
| `tests/SiteCheck.Tests/PrivateIpTests.cs` | Locks RFC1918/CGNAT/ULA/etc. classification. |
| `tests/SiteCheck.Tests/ReportProtectTests.cs` | Locks DPAPI round-trip on Windows and no-op/skip elsewhere. |
| `tests/SiteCheck.Tests/ReportTextTests.cs` | Locks plaintext report sections: hostname, findings, limits, authorization. |
| `tests/SiteCheck.Tests/SiteCheck.Tests.csproj` | xUnit test project referencing Core. No network to live origins in CI. |
| `tests/SiteCheck.Tests/TlsFactsTests.cs` | Locks protocol labels and expiry-window copy. |
| `tools/build-advisories.mjs` | Release-time builder for data/advisories.json from Retire.js jsrepository.json and GitHub Advisory npm packages (next, react, vue, …). |
| `tools/publish-wiki.ps1` | Push docs/wiki/* to the GitHub wiki remote. |
| `tools/publish.ps1` | Publish Rampart.exe + linux/osx zips into dist/, SHA256SUMS, copy docs. Does not bump 1.9.0. |
| `tools/sign-windows.ps1` | Optional Azure Artifact Signing of Rampart.exe. Needs az login + RAMPART_SIGNING_* env. See docs/signing.md. |

## Config and data that are not in the table

| Path | Why it has no CODEMAP header |
|------|------------------------------|
| `data/advisories.json` | Generated. Run `node tools/build-advisories.mjs`. |
| `dist/` | Publish output. |
| `SiteCheck.sln` | Solution wrapper; projects above are the map. |

## Licence

Desktop: GNU GPLv3. Store binaries: additional Apache-2.0 (`LICENSE.MOBILE`). DnsClient and Retire.js data: Apache-2.0. GitHub Advisory ranges: CC BY 4.0. Do not query Cloudflare Radar (CC BY-NC vs GPLv3).
