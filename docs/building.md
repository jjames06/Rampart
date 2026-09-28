# Building Rampart

You need the .NET 8 SDK (64-bit). The **recommended public ship** is the Windows WPF EXE. The same SDK publishes testing copies of the Avalonia UI for Linux and macOS. Those zips go on the GitHub release with `TESTING.txt` and the GPLv3 files. iOS and Android need the .NET MAUI workload and a Mac for iOS. The iPhone and Android copies are ready. They still need to be submitted to the App Store and Google Play.

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

Do not enable `PublishTrimmed`. Trimming has broken WPF resource lookup on this project before. Compression of the single file is on.

## Linux and macOS

```
dotnet publish src\SiteCheck.Desktop\SiteCheck.Desktop.csproj -c Release -r linux-x64 --self-contained true -o dist\linux-x64
dotnet publish src\SiteCheck.Desktop\SiteCheck.Desktop.csproj -c Release -r osx-x64 --self-contained true -o dist\osx-x64
dotnet publish src\SiteCheck.Desktop\SiteCheck.Desktop.csproj -c Release -r osx-arm64 --self-contained true -o dist\osx-arm64
```

`tools\publish.ps1` also writes those folders. Zip each folder with `LICENSE`, `NOTICE`, `THIRD-PARTY.md`, `LICENSE.MOBILE`, `how-to-use.md`, `lawful-use.md`, and `TESTING.txt`, then attach `Rampart-linux-x64.zip`, `Rampart-osx-arm64.zip`, and `Rampart-osx-x64.zip` to the v1.9.0 release. Notarize macOS copies with a Developer ID before you treat them as a finished Mac distribution. Store steps: [stores/SUBMIT.md](stores/SUBMIT.md).

## Tests

Unit tests cover hostname parsing (including international names and userinfo stripping), private-address refusal (including NAT64 and 6to4 embeddings), cookie flag reading that does not split on Expires commas, HSTS `max-age=0` and short max-age, DMARC `p=none`, SPF `+all`, TLS cipher helpers, homepage tabnabbing and http forms, advice that does not invent header fixes when HTTPS never finished, fingerprints (including Next.js from `/_next/static`), and the CVE catalogue.

```
dotnet test tests\SiteCheck.Tests\SiteCheck.Tests.csproj -c Release
```

## Signing

Release builds are not Authenticode-signed yet. Windows SmartScreen may warn. The operator handbook explains **More info**, then **Run anyway**, for copies that came from the public repository.
