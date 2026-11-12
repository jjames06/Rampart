# Building Rampart

Install the 64-bit .NET 10.0 SDK and the .NET 8 runtime. `global.json` selects SDK 10.0.100 or any later 10.0 release. Avalonia 12.1.3 generates the desktop window with a source generator built against Roslyn 4.14.0.0. The .NET 10.0 SDK ships Roslyn 5.0 or newer, so the generator runs. The projects stay on net8.0, and the .NET 10 SDK compiles that target. Running the tests and `SiteCheck.Desktop` uses the .NET 8 runtime.

A `Microsoft.Net.Compilers.Toolset` package can swap in a newer compiler for one project. `global.json` covers the desktop program, the tests, and CI, and the `dotnet` host stops with an SDK message when the installed compiler is older than the generators require. The .NET 9 SDK is out of support. The pin stays on the .NET 10.0 line, which is the supported SDK that meets the compiler requirement.

The **recommended public ship** is the Windows WPF EXE. The same SDK publishes testing copies of the Avalonia UI for Linux and macOS. Those zips go on the GitHub release with `TESTING.txt` and the GPLv3 files. iOS and Android need the .NET MAUI workload and a Mac for iOS. The iPhone and Android copies are ready. They still need to be submitted to the App Store and Google Play.

Rebuild the local CVE catalogue (needs network once per release):

```
node tools\build-advisories.mjs
```

Then from the repository root:

```
dotnet test tests\SiteCheck.Tests\SiteCheck.Tests.csproj -c Release
dotnet publish src\SiteCheck.App\SiteCheck.App.csproj -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true -p:PublishTrimmed=false -p:EnableCompressionInSingleFile=true -o dist
```

`tools\publish.ps1` runs both commands, names the result `Rampart.exe`, and copies `LICENSE`, `NOTICE`, `THIRD-PARTY.md`, and `docs/how-to-use.md` into `dist` so an object-code copy is accompanied by the licence text GPLv3 requires.

The executable is self-contained. The person who runs it does not install the .NET runtime. The program requests no administrative elevation (`asInvoker`). Per-monitor DPI awareness is set in the application manifest.

Do not enable `PublishTrimmed`. Trimming has broken WPF resource lookup on this project before. Compression of the single file stays on so the download stays a reasonable size. SmartScreen is about Authenticode, not that flag.

After the EXE is named `Rampart.exe`, `tools\sign-windows.ps1` Authenticode-signs it when `RAMPART_SIGN_PFX` or a Code Signing certificate is present. Keep the product version at 1.9.1 when you only add a signature. Full notes: [signing.md](signing.md).

## User interfaces

`SiteCheck.Core` owns findings and How to fix this. `FindingGuide` decides which cards show the panel. Apply UI card changes to all three shells:

- `src/SiteCheck.App` (Windows WPF, `Rampart.exe`)
- `src/SiteCheck.Desktop` (Avalonia Linux and macOS testing zips)
- `src/SiteCheck.Maui` (iPhone and Android)

Saved reports go through `ReportText.Format`, so they pick up the same How to fix this lines.

## Linux and macOS

```
dotnet publish src\SiteCheck.Desktop\SiteCheck.Desktop.csproj -c Release -r linux-x64 --self-contained true -o dist\linux-x64
dotnet publish src\SiteCheck.Desktop\SiteCheck.Desktop.csproj -c Release -r osx-x64 --self-contained true -o dist\osx-x64
dotnet publish src\SiteCheck.Desktop\SiteCheck.Desktop.csproj -c Release -r osx-arm64 --self-contained true -o dist\osx-arm64
```

`tools\publish.ps1` also writes those folders. Zip each folder with `LICENSE`, `NOTICE`, `THIRD-PARTY.md`, `LICENSE.MOBILE`, `how-to-use.md`, `lawful-use.md`, and `TESTING.txt`, then attach `Rampart-linux-x64.zip`, `Rampart-osx-arm64.zip`, and `Rampart-osx-x64.zip` to the v1.9.1 release. Notarize macOS copies with a Developer ID before you treat them as a finished Mac distribution. Store steps: [stores/SUBMIT.md](stores/SUBMIT.md).

## Tests

Unit tests cover hostname parsing (including international names and userinfo stripping), private-address refusal (including NAT64 and 6to4 embeddings), cookie flag reading that does not split on Expires commas, HSTS `max-age=0` and short max-age, DMARC `p=none`, SPF `+all`, TLS cipher helpers, homepage tabnabbing and http forms, advice that does not invent header fixes when HTTPS never finished, fingerprints (including Next.js from `/_next/static`), and the CVE catalogue.

```
dotnet test tests\SiteCheck.Tests\SiteCheck.Tests.csproj -c Release
```

## Signing

The grey **Windows protected your PC** box is Microsoft Defender SmartScreen (unrecognized publisher), not a Defender malware finding. A Defender scan of `Rampart.exe` reports no threats. The public 1.9.1 EXE was `NotSigned`.

Sign with an OV/EV Authenticode certificate or Microsoft Trusted Signing, then replace the v1.9.1 `Rampart.exe` asset. Until that certificate is on this PC, `tools\sign-windows.ps1` warns and the handbook still says **More info**, then **Run anyway**. See [signing.md](signing.md).
